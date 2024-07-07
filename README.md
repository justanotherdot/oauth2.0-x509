# Oauth 2.0 with x509 certificate verification

This is a small demo to both explain the basic flow 
of oauth 2.0, as well as highlighting how to utilize
x509 certificates to sign and verify access tokens. 

## Oauth 2.0 flow

1. A user calls login. 

2. The login calls redirects the caller to the third party. This would be the
   trusted identity provider that. When credentials are correct, the third party
   will send back an authorization token. We elide credential handling for
   brevity.

3. The caller redirects the call to /oauth/exchange.

4. At /oauth/exchange, we take the authorization token ("code") and attempt to
   upgrade this to a access token. If the upgrade succeeds, stuff the access
   token into a secure (HTTPS-only) cookie.
