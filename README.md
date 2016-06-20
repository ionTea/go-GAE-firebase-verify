# go-GAE-firebase-verify
Verifies Backend Tokens from Firebase in Google App Engine.

## Usage

`VerifyIDToken(idToken string, googleProjectID string, ctx context.Context) (string, error)`

A version of [alternaDev](https://github.com/alternaDev/go-firebase-verify)s' firebase token verifier
adapted to be used in Google Appengine. It is also updated to use jwt-go v3 instead of v2.

