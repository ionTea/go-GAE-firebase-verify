package go-GAE-firebase-verify

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/net/context"
	"google.golang.org/appengine/urlfetch"
)

const (
	clientCertURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
)

func VerifyFirebaseToken(idToken string, googleProjectID string, ctx context.Context) (string, error) {
	keys, err := fetchPublicKeys(ctx)

	if err != nil {
		return "", err
	}

	parsedToken, err := jwt.Parse(idToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		kid := token.Header["kid"]

		if keys[kid.(string)] == nil {
			return "", fmt.Errorf("Invalid key ID: %v", kid)
		}

		certPEM := string(*keys[kid.(string)])
		certPEM = strings.Replace(certPEM, "\\n", "\n", -1)
		certPEM = strings.Replace(certPEM, "\"", "", -1)
		block, _ := pem.Decode([]byte(certPEM))
		var cert *x509.Certificate
		cert, _ = x509.ParseCertificate(block.Bytes)
		rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)

		return rsaPublicKey, nil
	})

	if err != nil {
		return "", err
	}

	claims := parsedToken.Claims.(jwt.MapClaims)

	errMessage := ""

	if claims["aud"].(string) != googleProjectID {
		errMessage = "Firebase Auth ID token has incorrect 'aud' claim: " + claims["aud"].(string)
	} else if claims["iss"].(string) != "https://securetoken.google.com/"+googleProjectID {
		errMessage = "Firebase Auth ID token has incorrect 'iss' claim"
	} else if claims["sub"].(string) == "" || len(claims["sub"].(string)) > 128 {
		errMessage = "Firebase Auth ID token has invalid 'sub' claim"
	}

	if errMessage != "" {
		return "", errors.New(errMessage)
	}

	return string(claims["sub"].(string)), nil
}

func fetchPublicKeys(ctx context.Context) (map[string]*json.RawMessage, error) {
	client := urlfetch.Client(ctx)
	resp, err := client.Get(clientCertURL)

	if err != nil {
		return nil, err
	}

	var objmap map[string]*json.RawMessage
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&objmap)

	return objmap, err
}
