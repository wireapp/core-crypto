# Wire end to end identity example
Ed25519 - SHA256
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: 🔒 GET /acme/wire/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 HEAD /acme/wire/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: 🔒 POST /acme/wire/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/cb674b050f729eb1/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/47eOxmrLEJR3aJl7X0hpnH4y0rU8uRo2
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/DaugXj4rBw04OfjyWfucICoaOAGGzXFQ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/h9cDMf5pspJgGz6KMEWy1zNCiUrFxUk8
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32926/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32926/acme/wire/new-nonce",
  "newAccount": "https://stepca:32926/acme/wire/new-account",
  "newOrder": "https://stepca:32926/acme/wire/new-order",
  "revokeCert": "https://stepca:32926/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32926/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32926/acme/wire/directory>;rel="index"
replay-nonce: QVBGY0ZhQzFWeEd5UUVaUTdqWjRTcldmYnZ5MTJxWDI
```
```text
QVBGY0ZhQzFWeEd5UUVaUTdqWjRTcldmYnZ5MTJxWDI
```
#### 5. create a new account
```http request
POST https://stepca:32926/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImhLcUl4LWl0LXB3dDZZbm5SeEk5VjVKX2dZb0NET3ZTNFo1YWROZHdwSEEifSwibm9uY2UiOiJRVkJHWTBaaFF6RldlRWQ1VVVWYVVUZHFXalJUY2xkbVluWjVNVEp4V0RJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "bt13p_xHT5noHb9-7kH6uUXdgYtZDiVWKE6Wd_pCkMNlvi1t9I68eA7As9gE-YBqjy1AUHvCThMCEfgpuZPwDg"
}
```
```json
{
  "payload": {
    "contact": [
      "anonymous@anonymous.invalid"
    ],
    "onlyReturnExisting": false,
    "termsOfServiceAgreed": true
  },
  "protected": {
    "alg": "EdDSA",
    "jwk": {
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "hKqIx-it-pwt6YnnRxI9V5J_gYoCDOvS4Z5adNdwpHA"
    },
    "nonce": "QVBGY0ZhQzFWeEd5UUVaUTdqWjRTcldmYnZ5MTJxWDI",
    "typ": "JWT",
    "url": "https://stepca:32926/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32926/acme/wire/directory>;rel="index"
location: https://stepca:32926/acme/wire/account/cAJXsUhF1twqtV34VRwwoNutr6rgYgED
replay-nonce: Q1JNVE5mQUlsMW5vVlo2c3pkVGVMQmdOODhIekhxTkk
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32926/acme/wire/account/cAJXsUhF1twqtV34VRwwoNutr6rgYgED/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32926/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9hY2NvdW50L2NBSlhzVWhGMXR3cXRWMzRWUnd3b051dHI2cmdZZ0VEIiwidHlwIjoiSldUIiwibm9uY2UiOiJRMUpOVkU1bVFVbHNNVzV2VmxvMmMzcGtWR1ZNUW1kT09EaElla2h4VGtrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly8xRVdHMlh0QVJ5cVlNc1owYlJNQl9RIWNiNjc0YjA1MGY3MjllYjFAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIn0ifV0sIm5vdEJlZm9yZSI6IjIwMjQtMDEtMThUMTA6MTE6NDMuNjg4NTUzWiIsIm5vdEFmdGVyIjoiMjAzNC0wMS0xNVQxMDoxMTo0My42ODg1NTNaIn0",
  "signature": "Mm1ZWM07-FYpvJN0P6xSFB9yqETAka5DGT6obqqZn5yv6M-sF0q7rn411pTwylr2Q0a-iNE7e96KYJrvE9oICQ"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://1EWG2XtARyqYMsZ0bRMB_Q!cb674b050f729eb1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2034-01-15T10:11:43.688553Z",
    "notBefore": "2024-01-18T10:11:43.688553Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32926/acme/wire/account/cAJXsUhF1twqtV34VRwwoNutr6rgYgED",
    "nonce": "Q1JNVE5mQUlsMW5vVlo2c3pkVGVMQmdOODhIekhxTkk",
    "typ": "JWT",
    "url": "https://stepca:32926/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32926/acme/wire/directory>;rel="index"
location: https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U
replay-nonce: S3BZZFNJbkZVV1JVbDIxZHE1Wk5tRUpINk50RzVrWkk
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://1EWG2XtARyqYMsZ0bRMB_Q!cb674b050f729eb1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32926/acme/wire/authz/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj"
  ],
  "expires": "2024-01-19T10:11:43Z",
  "notBefore": "2024-01-18T10:11:43.688553Z",
  "notAfter": "2034-01-15T10:11:43.688553Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32926/acme/wire/authz/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9hY2NvdW50L2NBSlhzVWhGMXR3cXRWMzRWUnd3b051dHI2cmdZZ0VEIiwidHlwIjoiSldUIiwibm9uY2UiOiJTM0JaWkZOSmJrWlZWMUpWYkRJeFpIRTFXazV0UlVwSU5rNTBSelZyV2trIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL2F1dGh6L0VpdGRSQThnenh1UkNySGxwcFpKZlFzQjhIanNrbHBqIn0",
  "payload": "",
  "signature": "ZZPYmigFAmnA7LXDDdtUfqWCN2nyNF6GxKnUvkLhveKVlJ5WWg9v-E6OSZw4oqr3TL64etjuDsH3iusPch4SBQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32926/acme/wire/account/cAJXsUhF1twqtV34VRwwoNutr6rgYgED",
    "nonce": "S3BZZFNJbkZVV1JVbDIxZHE1Wk5tRUpINk50RzVrWkk",
    "typ": "JWT",
    "url": "https://stepca:32926/acme/wire/authz/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32926/acme/wire/directory>;rel="index"
location: https://stepca:32926/acme/wire/authz/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj
replay-nonce: TGRyNEs0eVVhT1FWOUhFNE4xNWp1cU9mYnpEbThLb3A
```
```json
{
  "status": "pending",
  "expires": "2024-01-19T10:11:43Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/DaugXj4rBw04OfjyWfucICoaOAGGzXFQ",
      "status": "pending",
      "token": "4xQIED9iPLQo1fkPLBq1znAniwvcVsxQ",
      "target": "http://keycloak:15170/realms/master"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/47eOxmrLEJR3aJl7X0hpnH4y0rU8uRo2",
      "status": "pending",
      "token": "4xQIED9iPLQo1fkPLBq1znAniwvcVsxQ",
      "target": "http://wire.com:16066/clients/cb674b050f729eb1/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://1EWG2XtARyqYMsZ0bRMB_Q!cb674b050f729eb1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:16066/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
a0tGQWRPcEppdjlabldlUFhpYjhaVTBCNW1LWHFmdHM
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiaEtxSXgtaXQtcHd0NllublJ4STlWNUpfZ1lvQ0RPdlM0WjVhZE5kd3BIQSJ9fQ.eyJpYXQiOjE3MDU1NjkxMDMsImV4cCI6MTcwNTU3NjMwMywibmJmIjoxNzA1NTY5MTAzLCJzdWIiOiJ3aXJlYXBwOi8vMUVXRzJYdEFSeXFZTXNaMGJSTUJfUSFjYjY3NGIwNTBmNzI5ZWIxQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL2NoYWxsZW5nZS9FaXRkUkE4Z3p4dVJDckhscHBaSmZRc0I4SGpza2xwai80N2VPeG1yTEVKUjNhSmw3WDBocG5INHkwclU4dVJvMiIsImp0aSI6IjI5OGFhN2Q4LTI0NDEtNDkwOS1hYzc5LTVmYmRhYmRiOWU5YiIsIm5vbmNlIjoiYTB0R1FXUlBjRXBwZGpsYWJsZGxVRmhwWWpoYVZUQkNOVzFMV0hGbWRITSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTYwNjYvY2xpZW50cy9jYjY3NGIwNTBmNzI5ZWIxL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI0eFFJRUQ5aVBMUW8xZmtQTEJxMXpuQW5pd3ZjVnN4USIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.0kXr35pyWkiR6hQe7O0wv_7Ldb3C-zkUpKl8GGdNuxcKnIWNLnL4Lx7qhVZuERRnzHyqW294MYgYV8m2Cf_pBw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiaEtxSXgtaXQtcHd0NllublJ4STlWNUpf
Z1lvQ0RPdlM0WjVhZE5kd3BIQSJ9fQ.eyJpYXQiOjE3MDU1NjkxMDMsImV4cCI6M
TcwNTU3NjMwMywibmJmIjoxNzA1NTY5MTAzLCJzdWIiOiJ3aXJlYXBwOi8vMUVXR
zJYdEFSeXFZTXNaMGJSTUJfUSFjYjY3NGIwNTBmNzI5ZWIxQHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL2NoYWxsZW5nZS9Fa
XRkUkE4Z3p4dVJDckhscHBaSmZRc0I4SGpza2xwai80N2VPeG1yTEVKUjNhSmw3W
DBocG5INHkwclU4dVJvMiIsImp0aSI6IjI5OGFhN2Q4LTI0NDEtNDkwOS1hYzc5L
TVmYmRhYmRiOWU5YiIsIm5vbmNlIjoiYTB0R1FXUlBjRXBwZGpsYWJsZGxVRmhwW
WpoYVZUQkNOVzFMV0hGbWRITSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MTYwNjYvY2xpZW50cy9jYjY3NGIwNTBmNzI5ZWIxL2FjY2Vzcy10b
2tlbiIsImNoYWwiOiI0eFFJRUQ5aVBMUW8xZmtQTEJxMXpuQW5pd3ZjVnN4USIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUifQ.0kXr35pyWkiR6hQe7O0wv_7Ldb3C-zkUpKl8GGdNuxcKnIWNLn
L4Lx7qhVZuERRnzHyqW294MYgYV8m2Cf_pBw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "hKqIx-it-pwt6YnnRxI9V5J_gYoCDOvS4Z5adNdwpHA"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/47eOxmrLEJR3aJl7X0hpnH4y0rU8uRo2",
  "chal": "4xQIED9iPLQo1fkPLBq1znAniwvcVsxQ",
  "exp": 1705576303,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:16066/clients/cb674b050f729eb1/access-token",
  "iat": 1705569103,
  "jti": "298aa7d8-2441-4909-ac79-5fbdabdb9e9b",
  "nbf": 1705569103,
  "nonce": "a0tGQWRPcEppdjlabldlUFhpYjhaVTBCNW1LWHFmdHM",
  "sub": "wireapp://1EWG2XtARyqYMsZ0bRMB_Q!cb674b050f729eb1@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEI0BLLjGvfm+zyI+8D9/zuOBEy7XR53jPEtmUbI5WoM
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhKqIx+it+pwt6YnnRxI9V5J/gYoCDOvS4Z5adNdwpHA=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:16066/clients/cb674b050f729eb1/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pYUV0eFNYZ3RhWFF0Y0hkME5sbHVibEo0U1RsV05VcGZaMWx2UTBSUGRsTTBXalZoWkU1a2QzQklRU0o5ZlEuZXlKcFlYUWlPakUzTURVMU5qa3hNRE1zSW1WNGNDSTZNVGN3TlRVM05qTXdNeXdpYm1KbUlqb3hOekExTlRZNU1UQXpMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZNVVZYUnpKWWRFRlNlWEZaVFhOYU1HSlNUVUpmVVNGallqWTNOR0l3TlRCbU56STVaV0l4UUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekk1TWpZdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOUZhWFJrVWtFNFozcDRkVkpEY2toc2NIQmFTbVpSYzBJNFNHcHphMnh3YWk4ME4yVlBlRzF5VEVWS1VqTmhTbXczV0RCb2NHNUlOSGt3Y2xVNGRWSnZNaUlzSW1wMGFTSTZJakk1T0dGaE4yUTRMVEkwTkRFdE5Ea3dPUzFoWXpjNUxUVm1ZbVJoWW1SaU9XVTVZaUlzSW01dmJtTmxJam9pWVRCMFIxRlhVbEJqUlhCd1pHcHNZV0pzWkd4VlJtaHdXV3BvWVZaVVFrTk9WekZNVjBoR2JXUklUU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRZd05qWXZZMnhwWlc1MGN5OWpZalkzTkdJd05UQm1Oekk1WldJeEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUkwZUZGSlJVUTVhVkJNVVc4eFptdFFURUp4TVhwdVFXNXBkM1pqVm5ONFVTSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpZlEuMGtYcjM1cHlXa2lSNmhRZTdPMHd2XzdMZGIzQy16a1VwS2w4R0dkTnV4Y0tuSVdOTG5MNEx4N3FoVlp1RVJSbnpIeXFXMjk0TVlnWVY4bTJDZl9wQnc
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImZ0WFV3T1ZreUhNVm9tQ0R3MFVUVFhzU09FSG9jS2p2emp3TjNLa29HbDAifX0.eyJpYXQiOjE3MDU1NjkxMDMsImV4cCI6MTcwNTU3MzA2MywibmJmIjoxNzA1NTY5MTAzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTYwNjYvY2xpZW50cy9jYjY3NGIwNTBmNzI5ZWIxL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8xRVdHMlh0QVJ5cVlNc1owYlJNQl9RIWNiNjc0YjA1MGY3MjllYjFAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjkyNi9hY21lL3dpcmUvY2hhbGxlbmdlL0VpdGRSQThnenh1UkNySGxwcFpKZlFzQjhIanNrbHBqLzQ3ZU94bXJMRUpSM2FKbDdYMGhwbkg0eTByVTh1Um8yIiwianRpIjoiOTEzYzQzY2ItNzc3Yy00MGIxLWExYTYtOTY3ZDE5MzFmZGMyIiwibm9uY2UiOiJhMHRHUVdSUGNFcHBkamxhYmxkbFVGaHBZamhhVlRCQ05XMUxXSEZtZEhNIiwiY2hhbCI6IjR4UUlFRDlpUExRbzFma1BMQnExem5Bbml3dmNWc3hRIiwiY25mIjp7ImtpZCI6IkxReWd2YkRiSFpWQTBhZTUtVXJhM1NWeEtnOExLZkM5VW9wX1lDZTZrYkEifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lhRXR4U1hndGFYUXRjSGQwTmxsdWJsSjRTVGxXTlVwZloxbHZRMFJQZGxNMFdqVmhaRTVrZDNCSVFTSjlmUS5leUpwWVhRaU9qRTNNRFUxTmpreE1ETXNJbVY0Y0NJNk1UY3dOVFUzTmpNd015d2libUptSWpveE56QTFOVFk1TVRBekxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dk1VVlhSekpZZEVGU2VYRlpUWE5hTUdKU1RVSmZVU0ZqWWpZM05HSXdOVEJtTnpJNVpXSXhRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STVNall2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5RmFYUmtVa0U0WjNwNGRWSkRja2hzY0hCYVNtWlJjMEk0U0dwemEyeHdhaTgwTjJWUGVHMXlURVZLVWpOaFNtdzNXREJvY0c1SU5Ia3djbFU0ZFZKdk1pSXNJbXAwYVNJNklqSTVPR0ZoTjJRNExUSTBOREV0TkRrd09TMWhZemM1TFRWbVltUmhZbVJpT1dVNVlpSXNJbTV2Ym1ObElqb2lZVEIwUjFGWFVsQmpSWEJ3Wkdwc1lXSnNaR3hWUm1od1dXcG9ZVlpVUWtOT1Z6Rk1WMGhHYldSSVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFl3TmpZdlkyeHBaVzUwY3k5allqWTNOR0l3TlRCbU56STVaV0l4TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTBlRkZKUlVRNWFWQk1VVzh4Wm10UVRFSnhNWHB1UVc1cGQzWmpWbk40VVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS4wa1hyMzVweVdraVI2aFFlN08wd3ZfN0xkYjNDLXprVXBLbDhHR2ROdXhjS25JV05Mbkw0THg3cWhWWnVFUlJuekh5cVcyOTRNWWdZVjhtMkNmX3BCdyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8xRVdHMlh0QVJ5cVlNc1owYlJNQl9RIWNiNjc0YjA1MGY3MjllYjFAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.y2IL_pjcoyNx0TwsWMs83ccIg4qs08e2Jf9TKUJ1gg0__8lBTpUgq4YorGq68VbWuZrO0sVScA8jrpokvkcYDg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImZ0WFV3T1ZreUhNVm9tQ0R3MFVUVFhzU09FSG9jS2p2emp3TjNLa29HbDAifX0.eyJpYXQiOjE3MDU1NjkxMDMsImV4cCI6MTcwNTU3MzA2MywibmJmIjoxNzA1NTY5MTAzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTYwNjYvY2xpZW50cy9jYjY3NGIwNTBmNzI5ZWIxL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8xRVdHMlh0QVJ5cVlNc1owYlJNQl9RIWNiNjc0YjA1MGY3MjllYjFAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjkyNi9hY21lL3dpcmUvY2hhbGxlbmdlL0VpdGRSQThnenh1UkNySGxwcFpKZlFzQjhIanNrbHBqLzQ3ZU94bXJMRUpSM2FKbDdYMGhwbkg0eTByVTh1Um8yIiwianRpIjoiOTEzYzQzY2ItNzc3Yy00MGIxLWExYTYtOTY3ZDE5MzFmZGMyIiwibm9uY2UiOiJhMHRHUVdSUGNFcHBkamxhYmxkbFVGaHBZamhhVlRCQ05XMUxXSEZtZEhNIiwiY2hhbCI6IjR4UUlFRDlpUExRbzFma1BMQnExem5Bbml3dmNWc3hRIiwiY25mIjp7ImtpZCI6IkxReWd2YkRiSFpWQTBhZTUtVXJhM1NWeEtnOExLZkM5VW9wX1lDZTZrYkEifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lhRXR4U1hndGFYUXRjSGQwTmxsdWJsSjRTVGxXTlVwZloxbHZRMFJQZGxNMFdqVmhaRTVrZDNCSVFTSjlmUS5leUpwWVhRaU9qRTNNRFUxTmpreE1ETXNJbVY0Y0NJNk1UY3dOVFUzTmpNd015d2libUptSWpveE56QTFOVFk1TVRBekxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dk1VVlhSekpZZEVGU2VYRlpUWE5hTUdKU1RVSmZVU0ZqWWpZM05HSXdOVEJtTnpJNVpXSXhRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STVNall2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5RmFYUmtVa0U0WjNwNGRWSkRja2hzY0hCYVNtWlJjMEk0U0dwemEyeHdhaTgwTjJWUGVHMXlURVZLVWpOaFNtdzNXREJvY0c1SU5Ia3djbFU0ZFZKdk1pSXNJbXAwYVNJNklqSTVPR0ZoTjJRNExUSTBOREV0TkRrd09TMWhZemM1TFRWbVltUmhZbVJpT1dVNVlpSXNJbTV2Ym1ObElqb2lZVEIwUjFGWFVsQmpSWEJ3Wkdwc1lXSnNaR3hWUm1od1dXcG9ZVlpVUWtOT1Z6Rk1WMGhHYldSSVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFl3TmpZdlkyeHBaVzUwY3k5allqWTNOR0l3TlRCbU56STVaV0l4TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTBlRkZKUlVRNWFWQk1VVzh4Wm10UVRFSnhNWHB1UVc1cGQzWmpWbk40VVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS4wa1hyMzVweVdraVI2aFFlN08wd3ZfN0xkYjNDLXprVXBLbDhHR2ROdXhjS25JV05Mbkw0THg3cWhWWnVFUlJuekh5cVcyOTRNWWdZVjhtMkNmX3BCdyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8xRVdHMlh0QVJ5cVlNc1owYlJNQl9RIWNiNjc0YjA1MGY3MjllYjFAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.y2IL_pjcoyNx0TwsWMs83ccIg4qs08e2Jf9TKUJ1gg0__8lBTpUgq4YorGq68VbWuZrO0sVScA8jrpokvkcYDg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6ImZ0WFV3T1ZreUhNVm9tQ0R3MFVUVFhzU09F
SG9jS2p2emp3TjNLa29HbDAifX0.eyJpYXQiOjE3MDU1NjkxMDMsImV4cCI6MTcw
NTU3MzA2MywibmJmIjoxNzA1NTY5MTAzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MTYwNjYvY2xpZW50cy9jYjY3NGIwNTBmNzI5ZWIxL2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly8xRVdHMlh0QVJ5cVlNc1owYlJNQl9RIWNiNjc0YjA1MGY3
MjllYjFAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjkyNi9hY21l
L3dpcmUvY2hhbGxlbmdlL0VpdGRSQThnenh1UkNySGxwcFpKZlFzQjhIanNrbHBq
LzQ3ZU94bXJMRUpSM2FKbDdYMGhwbkg0eTByVTh1Um8yIiwianRpIjoiOTEzYzQz
Y2ItNzc3Yy00MGIxLWExYTYtOTY3ZDE5MzFmZGMyIiwibm9uY2UiOiJhMHRHUVdS
UGNFcHBkamxhYmxkbFVGaHBZamhhVlRCQ05XMUxXSEZtZEhNIiwiY2hhbCI6IjR4
UUlFRDlpUExRbzFma1BMQnExem5Bbml3dmNWc3hRIiwiY25mIjp7ImtpZCI6IkxR
eWd2YkRiSFpWQTBhZTUtVXJhM1NWeEtnOExLZkM5VW9wX1lDZTZrYkEifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lhRXR4U1hndGFYUXRjSGQwTmxsdWJsSjRTVGxXTlVwZloxbHZRMFJQZGxN
MFdqVmhaRTVrZDNCSVFTSjlmUS5leUpwWVhRaU9qRTNNRFUxTmpreE1ETXNJbVY0
Y0NJNk1UY3dOVFUzTmpNd015d2libUptSWpveE56QTFOVFk1TVRBekxDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dk1VVlhSekpZZEVGU2VYRlpUWE5hTUdKU1RVSmZVU0Zq
WWpZM05HSXdOVEJtTnpJNVpXSXhRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STVNall2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM5RmFYUmtVa0U0WjNwNGRWSkRja2hzY0hCYVNtWlJjMEk0U0dwemEyeHdhaTgw
TjJWUGVHMXlURVZLVWpOaFNtdzNXREJvY0c1SU5Ia3djbFU0ZFZKdk1pSXNJbXAw
YVNJNklqSTVPR0ZoTjJRNExUSTBOREV0TkRrd09TMWhZemM1TFRWbVltUmhZbVJp
T1dVNVlpSXNJbTV2Ym1ObElqb2lZVEIwUjFGWFVsQmpSWEJ3Wkdwc1lXSnNaR3hW
Um1od1dXcG9ZVlpVUWtOT1Z6Rk1WMGhHYldSSVRTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFl3TmpZdlkyeHBaVzUw
Y3k5allqWTNOR0l3TlRCbU56STVaV0l4TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSTBlRkZKUlVRNWFWQk1VVzh4Wm10UVRFSnhNWHB1UVc1cGQzWmpWbk40
VVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS4wa1hyMzVweVdraVI2
aFFlN08wd3ZfN0xkYjNDLXprVXBLbDhHR2ROdXhjS25JV05Mbkw0THg3cWhWWnVF
UlJuekh5cVcyOTRNWWdZVjhtMkNmX3BCdyIsImNsaWVudF9pZCI6IndpcmVhcHA6
Ly8xRVdHMlh0QVJ5cVlNc1owYlJNQl9RIWNiNjc0YjA1MGY3MjllYjFAd2lyZS5j
b20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.y2I
L_pjcoyNx0TwsWMs83ccIg4qs08e2Jf9TKUJ1gg0__8lBTpUgq4YorGq68VbWuZr
O0sVScA8jrpokvkcYDg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "ftXUwOVkyHMVomCDw0UTTXsSOEHocKjvzjwN3KkoGl0"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/47eOxmrLEJR3aJl7X0hpnH4y0rU8uRo2",
  "chal": "4xQIED9iPLQo1fkPLBq1znAniwvcVsxQ",
  "client_id": "wireapp://1EWG2XtARyqYMsZ0bRMB_Q!cb674b050f729eb1@wire.com",
  "cnf": {
    "kid": "LQygvbDbHZVA0ae5-Ura3SVxKg8LKfC9Uop_YCe6kbA"
  },
  "exp": 1705573063,
  "iat": 1705569103,
  "iss": "http://wire.com:16066/clients/cb674b050f729eb1/access-token",
  "jti": "913c43cb-777c-40b1-a1a6-967d1931fdc2",
  "nbf": 1705569103,
  "nonce": "a0tGQWRPcEppdjlabldlUFhpYjhaVTBCNW1LWHFmdHM",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiaEtxSXgtaXQtcHd0NllublJ4STlWNUpfZ1lvQ0RPdlM0WjVhZE5kd3BIQSJ9fQ.eyJpYXQiOjE3MDU1NjkxMDMsImV4cCI6MTcwNTU3NjMwMywibmJmIjoxNzA1NTY5MTAzLCJzdWIiOiJ3aXJlYXBwOi8vMUVXRzJYdEFSeXFZTXNaMGJSTUJfUSFjYjY3NGIwNTBmNzI5ZWIxQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL2NoYWxsZW5nZS9FaXRkUkE4Z3p4dVJDckhscHBaSmZRc0I4SGpza2xwai80N2VPeG1yTEVKUjNhSmw3WDBocG5INHkwclU4dVJvMiIsImp0aSI6IjI5OGFhN2Q4LTI0NDEtNDkwOS1hYzc5LTVmYmRhYmRiOWU5YiIsIm5vbmNlIjoiYTB0R1FXUlBjRXBwZGpsYWJsZGxVRmhwWWpoYVZUQkNOVzFMV0hGbWRITSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTYwNjYvY2xpZW50cy9jYjY3NGIwNTBmNzI5ZWIxL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI0eFFJRUQ5aVBMUW8xZmtQTEJxMXpuQW5pd3ZjVnN4USIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.0kXr35pyWkiR6hQe7O0wv_7Ldb3C-zkUpKl8GGdNuxcKnIWNLnL4Lx7qhVZuERRnzHyqW294MYgYV8m2Cf_pBw",
  "scope": "wire_client_id",
  "sub": "wireapp://1EWG2XtARyqYMsZ0bRMB_Q!cb674b050f729eb1@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPxQOT4z26xJEW8EpyqfuHK+ePwtUF9pDOtVy96CoeTx
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAftXUwOVkyHMVomCDw0UTTXsSOEHocKjvzjwN3KkoGl0=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/47eOxmrLEJR3aJl7X0hpnH4y0rU8uRo2
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9hY2NvdW50L2NBSlhzVWhGMXR3cXRWMzRWUnd3b051dHI2cmdZZ0VEIiwidHlwIjoiSldUIiwibm9uY2UiOiJUR1J5TkVzMGVWVmhUMUZXT1VoRk5FNHhOV3AxY1U5bVlucEViVGhMYjNBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL2NoYWxsZW5nZS9FaXRkUkE4Z3p4dVJDckhscHBaSmZRc0I4SGpza2xwai80N2VPeG1yTEVKUjNhSmw3WDBocG5INHkwclU4dVJvMiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltWjBXRlYzVDFacmVVaE5WbTl0UTBSM01GVlVWRmh6VTA5RlNHOWpTMnAyZW1wM1RqTkxhMjlIYkRBaWZYMC5leUpwWVhRaU9qRTNNRFUxTmpreE1ETXNJbVY0Y0NJNk1UY3dOVFUzTXpBMk15d2libUptSWpveE56QTFOVFk1TVRBekxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRZd05qWXZZMnhwWlc1MGN5OWpZalkzTkdJd05UQm1Oekk1WldJeEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTh4UlZkSE1saDBRVko1Y1ZsTmMxb3dZbEpOUWw5UklXTmlOamMwWWpBMU1HWTNNamxsWWpGQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpreU5pOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMFZwZEdSU1FUaG5lbmgxVWtOeVNHeHdjRnBLWmxGelFqaElhbk5yYkhCcUx6UTNaVTk0YlhKTVJVcFNNMkZLYkRkWU1HaHdia2cwZVRCeVZUaDFVbTh5SWl3aWFuUnBJam9pT1RFell6UXpZMkl0TnpjM1l5MDBNR0l4TFdFeFlUWXRPVFkzWkRFNU16Rm1aR015SWl3aWJtOXVZMlVpT2lKaE1IUkhVVmRTVUdORmNIQmthbXhoWW14a2JGVkdhSEJaYW1oaFZsUkNRMDVYTVV4WFNFWnRaRWhOSWl3aVkyaGhiQ0k2SWpSNFVVbEZSRGxwVUV4UmJ6Rm1hMUJNUW5FeGVtNUJibWwzZG1OV2MzaFJJaXdpWTI1bUlqcDdJbXRwWkNJNklreFJlV2QyWWtSaVNGcFdRVEJoWlRVdFZYSmhNMU5XZUV0bk9FeExaa001Vlc5d1gxbERaVFpyWWtFaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsaFJYUjRVMWhuZEdGWVVYUmpTR1F3VG14c2RXSnNTalJUVkd4WFRsVndabG94YkhaUk1GSlFaR3hOTUZkcVZtaGFSVFZyWkROQ1NWRlRTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5SRlV4VG1wcmVFMUVUWE5KYlZZMFkwTkpOazFVWTNkT1ZGVXpUbXBOZDAxNWQybGliVXB0U1dwdmVFNTZRVEZPVkZrMVRWUkJla3hEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRrMVZWbGhTZWtwWlpFVkdVMlZZUmxwVVdFNWhUVWRLVTFSVlNtWlZVMFpxV1dwWk0wNUhTWGRPVkVKdFRucEpOVnBYU1hoUlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUVk5hbGwyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE01Um1GWVVtdFZhMFUwV2pOd05HUldTa1JqYTJoelkwaENZVk50V2xKak1FazBVMGR3ZW1FeWVIZGhhVGd3VGpKV1VHVkhNWGxVUlZaTFZXcE9hRk50ZHpOWFJFSnZZMGMxU1U1SWEzZGpiRlUwWkZaS2RrMXBTWE5KYlhBd1lWTkpOa2xxU1RWUFIwWm9UakpSTkV4VVNUQk9SRVYwVGtScmQwOVRNV2haZW1NMVRGUldiVmx0VW1oWmJWSnBUMWRWTlZscFNYTkpiVFYyWW0xT2JFbHFiMmxaVkVJd1VqRkdXRlZzUW1wU1dFSjNXa2R3YzFsWFNuTmFSM2hXVW0xb2QxZFhjRzlaVmxwVlVXdE9UMVo2UmsxV01HaEhZbGRTU1ZSVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOVkZsM1RtcFpkbGt5ZUhCYVZ6VXdZM2s1YWxscVdUTk9SMGwzVGxSQ2JVNTZTVFZhVjBsNFRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTVEJsUmtaS1VsVlJOV0ZXUWsxVlZ6aDRXbTEwVVZSRlNuaE5XSEIxVVZjMWNHUXpXbXBXYms0MFZWTkpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsbVVTNHdhMWh5TXpWd2VWZHJhVkkyYUZGbE4wOHdkM1pmTjB4a1lqTkRMWHByVlhCTGJEaEhSMlJPZFhoalMyNUpWMDVNYmt3MFRIZzNjV2hXV25WRlVsSnVla2g1Y1ZjeU9UUk5XV2RaVmpodE1rTm1YM0JDZHlJc0ltTnNhV1Z1ZEY5cFpDSTZJbmRwY21WaGNIQTZMeTh4UlZkSE1saDBRVko1Y1ZsTmMxb3dZbEpOUWw5UklXTmlOamMwWWpBMU1HWTNNamxsWWpGQWQybHlaUzVqYjIwaUxDSmhjR2xmZG1WeWMybHZiaUk2TlN3aWMyTnZjR1VpT2lKM2FYSmxYMk5zYVdWdWRGOXBaQ0o5LnkySUxfcGpjb3lOeDBUd3NXTXM4M2NjSWc0cXMwOGUySmY5VEtVSjFnZzBfXzhsQlRwVWdxNFlvckdxNjhWYld1WnJPMHNWU2NBOGpycG9rdmtjWURnIn0",
  "signature": "49OXOozlCvXw26Cy5BwVWUaM2Pb0Yp3wwnYUjgvqMm2Ng2y_uMLYItzRZFL9C7a0E2iclVT-aG-JPbGVTtAgBw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImZ0WFV3T1ZreUhNVm9tQ0R3MFVUVFhzU09FSG9jS2p2emp3TjNLa29HbDAifX0.eyJpYXQiOjE3MDU1NjkxMDMsImV4cCI6MTcwNTU3MzA2MywibmJmIjoxNzA1NTY5MTAzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTYwNjYvY2xpZW50cy9jYjY3NGIwNTBmNzI5ZWIxL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8xRVdHMlh0QVJ5cVlNc1owYlJNQl9RIWNiNjc0YjA1MGY3MjllYjFAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjkyNi9hY21lL3dpcmUvY2hhbGxlbmdlL0VpdGRSQThnenh1UkNySGxwcFpKZlFzQjhIanNrbHBqLzQ3ZU94bXJMRUpSM2FKbDdYMGhwbkg0eTByVTh1Um8yIiwianRpIjoiOTEzYzQzY2ItNzc3Yy00MGIxLWExYTYtOTY3ZDE5MzFmZGMyIiwibm9uY2UiOiJhMHRHUVdSUGNFcHBkamxhYmxkbFVGaHBZamhhVlRCQ05XMUxXSEZtZEhNIiwiY2hhbCI6IjR4UUlFRDlpUExRbzFma1BMQnExem5Bbml3dmNWc3hRIiwiY25mIjp7ImtpZCI6IkxReWd2YkRiSFpWQTBhZTUtVXJhM1NWeEtnOExLZkM5VW9wX1lDZTZrYkEifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lhRXR4U1hndGFYUXRjSGQwTmxsdWJsSjRTVGxXTlVwZloxbHZRMFJQZGxNMFdqVmhaRTVrZDNCSVFTSjlmUS5leUpwWVhRaU9qRTNNRFUxTmpreE1ETXNJbVY0Y0NJNk1UY3dOVFUzTmpNd015d2libUptSWpveE56QTFOVFk1TVRBekxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dk1VVlhSekpZZEVGU2VYRlpUWE5hTUdKU1RVSmZVU0ZqWWpZM05HSXdOVEJtTnpJNVpXSXhRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STVNall2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5RmFYUmtVa0U0WjNwNGRWSkRja2hzY0hCYVNtWlJjMEk0U0dwemEyeHdhaTgwTjJWUGVHMXlURVZLVWpOaFNtdzNXREJvY0c1SU5Ia3djbFU0ZFZKdk1pSXNJbXAwYVNJNklqSTVPR0ZoTjJRNExUSTBOREV0TkRrd09TMWhZemM1TFRWbVltUmhZbVJpT1dVNVlpSXNJbTV2Ym1ObElqb2lZVEIwUjFGWFVsQmpSWEJ3Wkdwc1lXSnNaR3hWUm1od1dXcG9ZVlpVUWtOT1Z6Rk1WMGhHYldSSVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFl3TmpZdlkyeHBaVzUwY3k5allqWTNOR0l3TlRCbU56STVaV0l4TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTBlRkZKUlVRNWFWQk1VVzh4Wm10UVRFSnhNWHB1UVc1cGQzWmpWbk40VVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS4wa1hyMzVweVdraVI2aFFlN08wd3ZfN0xkYjNDLXprVXBLbDhHR2ROdXhjS25JV05Mbkw0THg3cWhWWnVFUlJuekh5cVcyOTRNWWdZVjhtMkNmX3BCdyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8xRVdHMlh0QVJ5cVlNc1owYlJNQl9RIWNiNjc0YjA1MGY3MjllYjFAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.y2IL_pjcoyNx0TwsWMs83ccIg4qs08e2Jf9TKUJ1gg0__8lBTpUgq4YorGq68VbWuZrO0sVScA8jrpokvkcYDg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32926/acme/wire/account/cAJXsUhF1twqtV34VRwwoNutr6rgYgED",
    "nonce": "TGRyNEs0eVVhT1FWOUhFNE4xNWp1cU9mYnpEbThLb3A",
    "typ": "JWT",
    "url": "https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/47eOxmrLEJR3aJl7X0hpnH4y0rU8uRo2"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32926/acme/wire/directory>;rel="index"
link: <https://stepca:32926/acme/wire/authz/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj>;rel="up"
location: https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/47eOxmrLEJR3aJl7X0hpnH4y0rU8uRo2
replay-nonce: b2ZSQzd0UWZ6V0VWWHpXQkdPOVdTdkNzbXRyYVQ0NmE
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/47eOxmrLEJR3aJl7X0hpnH4y0rU8uRo2",
  "status": "valid",
  "token": "4xQIED9iPLQo1fkPLBq1znAniwvcVsxQ",
  "target": "http://wire.com:16066/clients/cb674b050f729eb1/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=K5Tm__4nHn0W8dpZW_qamJT8EESYsZxv-Bpcfaxmrnk&code_challenge=T7f04WX4wCAhHbeb2FMkUt3Mb2ZOX8otD-LkgK0Uro4
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:15170/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=gRCaED2_GiU0DxUw-KfCqw&code_challenge=T7f04WX4wCAhHbeb2FMkUt3Mb2ZOX8otD-LkgK0Uro4&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A16066%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32926%2Facme%2Fwire%2Fchallenge%2FEitdRA8gzxuRCrHlppZJfQsB8Hjsklpj%2FDaugXj4rBw04OfjyWfucICoaOAGGzXFQ%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%224xQIED9iPLQo1fkPLBq1znAniwvcVsxQ.LQygvbDbHZVA0ae5-Ura3SVxKg8LKfC9Uop_YCe6kbA%22%7D%7D%7D&nonce=ifCeNlJ2PklTFG83XRd8Fg
```

#### 20. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:15170/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=30d91a25-f642-4a00-917b-d7acd6ad6f7b.e4f1d08b-d363-4e1f-af27-8d9f71849f1d.85259f19-7261-4f76-bd41-c355de91bee7&code_verifier=K5Tm__4nHn0W8dpZW_qamJT8EESYsZxv-Bpcfaxmrnk&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A16066%2Fcallback
```
#### 21. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkTjFDelBjZnVlWXFWSUUta0hmMDBFb2lqUmJvMFhIS0tvb3NZY3FkLWpNIn0.eyJleHAiOjE3MDU1NzI3NjMsImlhdCI6MTcwNTU3MjcwMywiYXV0aF90aW1lIjoxNzA1NTcyNzAzLCJqdGkiOiI0ODI3OTAxZC0zMWRjLTQwM2QtYmM3Ni1kYzQ2NjYyOGQxYWMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhMjQzODU5Yy02OWVjLTRlMDYtYTg5ZC1hNDUwYzUyY2FhODkiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJpZkNlTmxKMlBrbFRGRzgzWFJkOEZnIiwic2Vzc2lvbl9zdGF0ZSI6ImU0ZjFkMDhiLWQzNjMtNGUxZi1hZjI3LThkOWY3MTg0OWYxZCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE2MDY2Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiZTRmMWQwOGItZDM2My00ZTFmLWFmMjctOGQ5ZjcxODQ5ZjFkIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.AJZ5in4nrx-yzy0QjYB9QOunaMMIF_PlANVOqbSDZ40UMPfruzbWBvb7CWcqS4h7ltM1KdUXyiGkuFtPr3-XNsv7N-oiYh-b0mou3QnkgQ4jaR-FTSDDr0pbMYx2J8FvRU6t9-WUp-xDluyPOnD0iTP4zQYhz8iabLN0p4O9B0wUGBse5HTeMGs3fkmiZUgm59ga4TDuVHICVUTT7xPZlPaMOKiQ7HUGtUAhb8ehxy0qac1EYR1vKTDJnYOZNY_PrD90pxk_8cuqjntfQQGJ0ryIucPyfFuT-4DMlL0eu4Q6-gm7boBdpQbDfgssJvhgvyl0E6GKzhcqSaguXeCSVA",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkTjFDelBjZnVlWXFWSUUta0hmMDBFb2lqUmJvMFhIS0tvb3NZY3FkLWpNIn0.eyJleHAiOjE3MDU1NzI3NjMsImlhdCI6MTcwNTU3MjcwMywiYXV0aF90aW1lIjoxNzA1NTcyNzAzLCJqdGkiOiJiNmZjOTQwOS1lNDgzLTQxMmUtYjY2Mi0wN2RlNGRkNWM1MjciLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJhMjQzODU5Yy02OWVjLTRlMDYtYTg5ZC1hNDUwYzUyY2FhODkiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6ImlmQ2VObEoyUGtsVEZHODNYUmQ4RmciLCJzZXNzaW9uX3N0YXRlIjoiZTRmMWQwOGItZDM2My00ZTFmLWFmMjctOGQ5ZjcxODQ5ZjFkIiwiYXRfaGFzaCI6IktpTXpQT3RxNGlmU0dqc2s5RlpvaUEiLCJhY3IiOiIxIiwic2lkIjoiZTRmMWQwOGItZDM2My00ZTFmLWFmMjctOGQ5ZjcxODQ5ZjFkIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6IjR4UUlFRDlpUExRbzFma1BMQnExem5Bbml3dmNWc3hRLkxReWd2YkRiSFpWQTBhZTUtVXJhM1NWeEtnOExLZkM5VW9wX1lDZTZrYkEiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9jaGFsbGVuZ2UvRWl0ZFJBOGd6eHVSQ3JIbHBwWkpmUXNCOEhqc2tscGovRGF1Z1hqNHJCdzA0T2ZqeVdmdWNJQ29hT0FHR3pYRlEiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.hnGyK5RoInUaK1QmOBZVAkQVAzB-30ddhCbpa0TxXx5wI2AFmwmB2OQBkchYb2PWqH4O1omXdMr88XFhBRBfkry-mVWBcHh5GjYZP9zrILRM4RtBry014WXrbWB2iMbNm_KN_74RQHPOPzfJGW9GizO-lu1Sa8WakCvLTOjX305OWcX2bRXSiSOW84xztpuIH0y526LbT27gp4fh4yRfG6fpiGO9xOA7oWvlsNAtNCGtpyHINzIbHCcNa3VZtxGt_sko3TPizqi_uiu1stXTRo41oChDJMNVDp8TvaQj6ubJjWpALbStlEu-vYPNFsEWxaqfdedKChX58o0kDRZzsg",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlOWZiNDAzYS0wZDllLTRlMGUtYWNjYS03ZWM4NTMyYjMyMzgifQ.eyJleHAiOjE3MDU1NzQ1MDMsImlhdCI6MTcwNTU3MjcwMywianRpIjoiMzQyN2EyNjAtNmIzOC00ZTA1LTg3ZmEtMzdmYTcyMGE0MmY1IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE1MTcwL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc3RlciIsInN1YiI6ImEyNDM4NTljLTY5ZWMtNGUwNi1hODlkLWE0NTBjNTJjYWE4OSIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJpZkNlTmxKMlBrbFRGRzgzWFJkOEZnIiwic2Vzc2lvbl9zdGF0ZSI6ImU0ZjFkMDhiLWQzNjMtNGUxZi1hZjI3LThkOWY3MTg0OWYxZCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJlNGYxZDA4Yi1kMzYzLTRlMWYtYWYyNy04ZDlmNzE4NDlmMWQifQ.YaDr72e64rPElU2_1CjKqGZus2WJsfxmE_XPTyMN_9E",
  "scope": "openid profile email",
  "session_state": "e4f1d08b-d363-4e1f-af27-8d9f71849f1d",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkTjFDelBjZnVlWXFWSUUta0hmMDBFb2lqUmJvMFhIS0tvb3NZY3FkLWpNIn0.eyJleHAiOjE3MDU1NzI3NjMsImlhdCI6MTcwNTU3MjcwMywiYXV0aF90aW1lIjoxNzA1NTcyNzAzLCJqdGkiOiI0ODI3OTAxZC0zMWRjLTQwM2QtYmM3Ni1kYzQ2NjYyOGQxYWMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJhMjQzODU5Yy02OWVjLTRlMDYtYTg5ZC1hNDUwYzUyY2FhODkiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJpZkNlTmxKMlBrbFRGRzgzWFJkOEZnIiwic2Vzc2lvbl9zdGF0ZSI6ImU0ZjFkMDhiLWQzNjMtNGUxZi1hZjI3LThkOWY3MTg0OWYxZCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE2MDY2Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiZTRmMWQwOGItZDM2My00ZTFmLWFmMjctOGQ5ZjcxODQ5ZjFkIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.AJZ5in4nrx-yzy0QjYB9QOunaMMIF_PlANVOqbSDZ40UMPfruzbWBvb7CWcqS4h7ltM1KdUXyiGkuFtPr3-XNsv7N-oiYh-b0mou3QnkgQ4jaR-FTSDDr0pbMYx2J8FvRU6t9-WUp-xDluyPOnD0iTP4zQYhz8iabLN0p4O9B0wUGBse5HTeMGs3fkmiZUgm59ga4TDuVHICVUTT7xPZlPaMOKiQ7HUGtUAhb8ehxy0qac1EYR1vKTDJnYOZNY_PrD90pxk_8cuqjntfQQGJ0ryIucPyfFuT-4DMlL0eu4Q6-gm7boBdpQbDfgssJvhgvyl0E6GKzhcqSaguXeCSVA)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkTjFDelBjZnVl
WXFWSUUta0hmMDBFb2lqUmJvMFhIS0tvb3NZY3FkLWpNIn0.eyJleHAiOjE3MDU1
NzI3NjMsImlhdCI6MTcwNTU3MjcwMywiYXV0aF90aW1lIjoxNzA1NTcyNzAzLCJq
dGkiOiI0ODI3OTAxZC0zMWRjLTQwM2QtYmM3Ni1kYzQ2NjYyOGQxYWMiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiJhMjQzODU5Yy02OWVjLTRlMDYtYTg5ZC1hNDUwYzUyY2Fh
ODkiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJpZkNl
TmxKMlBrbFRGRzgzWFJkOEZnIiwic2Vzc2lvbl9zdGF0ZSI6ImU0ZjFkMDhiLWQz
NjMtNGUxZi1hZjI3LThkOWY3MTg0OWYxZCIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE2MDY2Il0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxl
IGVtYWlsIiwic2lkIjoiZTRmMWQwOGItZDM2My00ZTFmLWFmMjctOGQ5ZjcxODQ5
ZjFkIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdp
cmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0
aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.AJZ5in4nrx-yzy0QjYB
9QOunaMMIF_PlANVOqbSDZ40UMPfruzbWBvb7CWcqS4h7ltM1KdUXyiGkuFtPr3-
XNsv7N-oiYh-b0mou3QnkgQ4jaR-FTSDDr0pbMYx2J8FvRU6t9-WUp-xDluyPOnD
0iTP4zQYhz8iabLN0p4O9B0wUGBse5HTeMGs3fkmiZUgm59ga4TDuVHICVUTT7xP
ZlPaMOKiQ7HUGtUAhb8ehxy0qac1EYR1vKTDJnYOZNY_PrD90pxk_8cuqjntfQQG
J0ryIucPyfFuT-4DMlL0eu4Q6-gm7boBdpQbDfgssJvhgvyl0E6GKzhcqSaguXeC
SVA
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "dN1CzPcfueYqVIE-kHf00EoijRbo0XHKKoosYcqd-jM",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:16066"
  ],
  "aud": "account",
  "auth_time": 1705572703,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1705572763,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1705572703,
  "iss": "http://keycloak:15170/realms/master",
  "jti": "4827901d-31dc-403d-bc76-dc466628d1ac",
  "name": "Alice Smith",
  "nonce": "ifCeNlJ2PklTFG83XRd8Fg",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "realm_access": {
    "roles": [
      "default-roles-master",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid profile email",
  "session_state": "e4f1d08b-d363-4e1f-af27-8d9f71849f1d",
  "sid": "e4f1d08b-d363-4e1f-af27-8d9f71849f1d",
  "sub": "a243859c-69ec-4e06-a89d-a450c52caa89",
  "typ": "Bearer"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuc9j9f0260CUDzF+DU3R
R0gzhUVHyi2RgLiRNRlwGwgFyHBUAk26l8ednmlVvM2C0dXsLnFzx5y1cEEUB9wq
3KmMjxSqBFmMf5jMtvcXkOVwQOvcXmWpPr9/XmK1IpYWw9zWB7etYVa4cHEeekYJ
Iv6H+qY01R2qQhjJWLe923p6CLEKucfDGLWWuXNwdtwnVwsTAR7M8XIDoJYejNmg
ewpDR4DAGob7uhg5XJx8AnOt7xrFcNyvTsW1Z+5s9iDPDzXrNTSEgCKTwZc3yVIk
X7T5I6n0RRTFJKjmpFWeO84x9sjP59oKWzG2zAmHeTKjOT2KMANwWxMUM/8r9ooB
8QIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlOWZiNDAzYS0wZDllLTRlMGUtYWNjYS03ZWM4NTMyYjMyMzgifQ.eyJleHAiOjE3MDU1NzQ1MDMsImlhdCI6MTcwNTU3MjcwMywianRpIjoiMzQyN2EyNjAtNmIzOC00ZTA1LTg3ZmEtMzdmYTcyMGE0MmY1IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE1MTcwL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc3RlciIsInN1YiI6ImEyNDM4NTljLTY5ZWMtNGUwNi1hODlkLWE0NTBjNTJjYWE4OSIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJpZkNlTmxKMlBrbFRGRzgzWFJkOEZnIiwic2Vzc2lvbl9zdGF0ZSI6ImU0ZjFkMDhiLWQzNjMtNGUxZi1hZjI3LThkOWY3MTg0OWYxZCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJlNGYxZDA4Yi1kMzYzLTRlMWYtYWYyNy04ZDlmNzE4NDlmMWQifQ.YaDr72e64rPElU2_1CjKqGZus2WJsfxmE_XPTyMN_9E)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJlOWZiNDAzYS0w
ZDllLTRlMGUtYWNjYS03ZWM4NTMyYjMyMzgifQ.eyJleHAiOjE3MDU1NzQ1MDMsI
mlhdCI6MTcwNTU3MjcwMywianRpIjoiMzQyN2EyNjAtNmIzOC00ZTA1LTg3ZmEtM
zdmYTcyMGE0MmY1IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE1MTcwL3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc
3RlciIsInN1YiI6ImEyNDM4NTljLTY5ZWMtNGUwNi1hODlkLWE0NTBjNTJjYWE4O
SIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJpZkNlT
mxKMlBrbFRGRzgzWFJkOEZnIiwic2Vzc2lvbl9zdGF0ZSI6ImU0ZjFkMDhiLWQzN
jMtNGUxZi1hZjI3LThkOWY3MTg0OWYxZCIsInNjb3BlIjoib3BlbmlkIHByb2Zpb
GUgZW1haWwiLCJzaWQiOiJlNGYxZDA4Yi1kMzYzLTRlMWYtYWYyNy04ZDlmNzE4N
DlmMWQifQ.YaDr72e64rPElU2_1CjKqGZus2WJsfxmE_XPTyMN_9E
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "e9fb403a-0d9e-4e0e-acca-7ec8532b3238",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:15170/realms/master",
  "azp": "wireapp",
  "exp": 1705574503,
  "iat": 1705572703,
  "iss": "http://keycloak:15170/realms/master",
  "jti": "3427a260-6b38-4e05-87fa-37fa720a42f5",
  "nonce": "ifCeNlJ2PklTFG83XRd8Fg",
  "scope": "openid profile email",
  "session_state": "e4f1d08b-d363-4e1f-af27-8d9f71849f1d",
  "sid": "e4f1d08b-d363-4e1f-af27-8d9f71849f1d",
  "sub": "a243859c-69ec-4e06-a89d-a450c52caa89",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuc9j9f0260CUDzF+DU3R
R0gzhUVHyi2RgLiRNRlwGwgFyHBUAk26l8ednmlVvM2C0dXsLnFzx5y1cEEUB9wq
3KmMjxSqBFmMf5jMtvcXkOVwQOvcXmWpPr9/XmK1IpYWw9zWB7etYVa4cHEeekYJ
Iv6H+qY01R2qQhjJWLe923p6CLEKucfDGLWWuXNwdtwnVwsTAR7M8XIDoJYejNmg
ewpDR4DAGob7uhg5XJx8AnOt7xrFcNyvTsW1Z+5s9iDPDzXrNTSEgCKTwZc3yVIk
X7T5I6n0RRTFJKjmpFWeO84x9sjP59oKWzG2zAmHeTKjOT2KMANwWxMUM/8r9ooB
8QIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 22. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkTjFDelBjZnVlWXFWSUUta0hmMDBFb2lqUmJvMFhIS0tvb3NZY3FkLWpNIn0.eyJleHAiOjE3MDU1NzI3NjMsImlhdCI6MTcwNTU3MjcwMywiYXV0aF90aW1lIjoxNzA1NTcyNzAzLCJqdGkiOiJiNmZjOTQwOS1lNDgzLTQxMmUtYjY2Mi0wN2RlNGRkNWM1MjciLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJhMjQzODU5Yy02OWVjLTRlMDYtYTg5ZC1hNDUwYzUyY2FhODkiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6ImlmQ2VObEoyUGtsVEZHODNYUmQ4RmciLCJzZXNzaW9uX3N0YXRlIjoiZTRmMWQwOGItZDM2My00ZTFmLWFmMjctOGQ5ZjcxODQ5ZjFkIiwiYXRfaGFzaCI6IktpTXpQT3RxNGlmU0dqc2s5RlpvaUEiLCJhY3IiOiIxIiwic2lkIjoiZTRmMWQwOGItZDM2My00ZTFmLWFmMjctOGQ5ZjcxODQ5ZjFkIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6IjR4UUlFRDlpUExRbzFma1BMQnExem5Bbml3dmNWc3hRLkxReWd2YkRiSFpWQTBhZTUtVXJhM1NWeEtnOExLZkM5VW9wX1lDZTZrYkEiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9jaGFsbGVuZ2UvRWl0ZFJBOGd6eHVSQ3JIbHBwWkpmUXNCOEhqc2tscGovRGF1Z1hqNHJCdzA0T2ZqeVdmdWNJQ29hT0FHR3pYRlEiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.hnGyK5RoInUaK1QmOBZVAkQVAzB-30ddhCbpa0TxXx5wI2AFmwmB2OQBkchYb2PWqH4O1omXdMr88XFhBRBfkry-mVWBcHh5GjYZP9zrILRM4RtBry014WXrbWB2iMbNm_KN_74RQHPOPzfJGW9GizO-lu1Sa8WakCvLTOjX305OWcX2bRXSiSOW84xztpuIH0y526LbT27gp4fh4yRfG6fpiGO9xOA7oWvlsNAtNCGtpyHINzIbHCcNa3VZtxGt_sko3TPizqi_uiu1stXTRo41oChDJMNVDp8TvaQj6ubJjWpALbStlEu-vYPNFsEWxaqfdedKChX58o0kDRZzsg)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkTjFDelBjZnVl
WXFWSUUta0hmMDBFb2lqUmJvMFhIS0tvb3NZY3FkLWpNIn0.eyJleHAiOjE3MDU1
NzI3NjMsImlhdCI6MTcwNTU3MjcwMywiYXV0aF90aW1lIjoxNzA1NTcyNzAzLCJq
dGkiOiJiNmZjOTQwOS1lNDgzLTQxMmUtYjY2Mi0wN2RlNGRkNWM1MjciLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiJhMjQzODU5Yy02OWVjLTRlMDYtYTg5ZC1hNDUwYzUyY2Fh
ODkiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6ImlmQ2VObEoy
UGtsVEZHODNYUmQ4RmciLCJzZXNzaW9uX3N0YXRlIjoiZTRmMWQwOGItZDM2My00
ZTFmLWFmMjctOGQ5ZjcxODQ5ZjFkIiwiYXRfaGFzaCI6IktpTXpQT3RxNGlmU0dq
c2s5RlpvaUEiLCJhY3IiOiIxIiwic2lkIjoiZTRmMWQwOGItZDM2My00ZTFmLWFm
MjctOGQ5ZjcxODQ5ZjFkIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBh
bGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6IjR4UUlFRDlpUExRbzFma1BM
QnExem5Bbml3dmNWc3hRLkxReWd2YkRiSFpWQTBhZTUtVXJhM1NWeEtnOExLZkM5
VW9wX1lDZTZrYkEiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2Fj
bWUvd2lyZS9jaGFsbGVuZ2UvRWl0ZFJBOGd6eHVSQ3JIbHBwWkpmUXNCOEhqc2ts
cGovRGF1Z1hqNHJCdzA0T2ZqeVdmdWNJQ29hT0FHR3pYRlEiLCJnaXZlbl9uYW1l
IjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNt
aXRoQHdpcmUuY29tIn0.hnGyK5RoInUaK1QmOBZVAkQVAzB-30ddhCbpa0TxXx5w
I2AFmwmB2OQBkchYb2PWqH4O1omXdMr88XFhBRBfkry-mVWBcHh5GjYZP9zrILRM
4RtBry014WXrbWB2iMbNm_KN_74RQHPOPzfJGW9GizO-lu1Sa8WakCvLTOjX305O
WcX2bRXSiSOW84xztpuIH0y526LbT27gp4fh4yRfG6fpiGO9xOA7oWvlsNAtNCGt
pyHINzIbHCcNa3VZtxGt_sko3TPizqi_uiu1stXTRo41oChDJMNVDp8TvaQj6ubJ
jWpALbStlEu-vYPNFsEWxaqfdedKChX58o0kDRZzsg
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "dN1CzPcfueYqVIE-kHf00EoijRbo0XHKKoosYcqd-jM",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/DaugXj4rBw04OfjyWfucICoaOAGGzXFQ",
  "acr": "1",
  "at_hash": "KiMzPOtq4ifSGjsk9FZoiA",
  "aud": "wireapp",
  "auth_time": 1705572703,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1705572763,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1705572703,
  "iss": "http://keycloak:15170/realms/master",
  "jti": "b6fc9409-e483-412e-b662-07de4dd5c527",
  "keyauth": "4xQIED9iPLQo1fkPLBq1znAniwvcVsxQ.LQygvbDbHZVA0ae5-Ura3SVxKg8LKfC9Uop_YCe6kbA",
  "name": "Alice Smith",
  "nonce": "ifCeNlJ2PklTFG83XRd8Fg",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "session_state": "e4f1d08b-d363-4e1f-af27-8d9f71849f1d",
  "sid": "e4f1d08b-d363-4e1f-af27-8d9f71849f1d",
  "sub": "a243859c-69ec-4e06-a89d-a450c52caa89",
  "typ": "ID"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuc9j9f0260CUDzF+DU3R
R0gzhUVHyi2RgLiRNRlwGwgFyHBUAk26l8ednmlVvM2C0dXsLnFzx5y1cEEUB9wq
3KmMjxSqBFmMf5jMtvcXkOVwQOvcXmWpPr9/XmK1IpYWw9zWB7etYVa4cHEeekYJ
Iv6H+qY01R2qQhjJWLe923p6CLEKucfDGLWWuXNwdtwnVwsTAR7M8XIDoJYejNmg
ewpDR4DAGob7uhg5XJx8AnOt7xrFcNyvTsW1Z+5s9iDPDzXrNTSEgCKTwZc3yVIk
X7T5I6n0RRTFJKjmpFWeO84x9sjP59oKWzG2zAmHeTKjOT2KMANwWxMUM/8r9ooB
8QIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/DaugXj4rBw04OfjyWfucICoaOAGGzXFQ
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9hY2NvdW50L2NBSlhzVWhGMXR3cXRWMzRWUnd3b051dHI2cmdZZ0VEIiwidHlwIjoiSldUIiwibm9uY2UiOiJiMlpTUXpkMFVXWjZWMFZXV0hwWFFrZFBPVmRUZGtOemJYUnlZVlEwTm1FIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL2NoYWxsZW5nZS9FaXRkUkE4Z3p4dVJDckhscHBaSmZRc0I4SGpza2xwai9EYXVnWGo0ckJ3MDRPZmp5V2Z1Y0lDb2FPQUdHelhGUSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSmtUakZEZWxCalpuVmxXWEZXU1VVdGEwaG1NREJGYjJscVVtSnZNRmhJUzB0dmIzTlpZM0ZrTFdwTkluMC5leUpsZUhBaU9qRTNNRFUxTnpJM05qTXNJbWxoZENJNk1UY3dOVFUzTWpjd015d2lZWFYwYUY5MGFXMWxJam94TnpBMU5UY3lOekF6TENKcWRHa2lPaUppTm1aak9UUXdPUzFsTkRnekxUUXhNbVV0WWpZMk1pMHdOMlJsTkdSa05XTTFNamNpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNVFV4TnpBdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSmhNalF6T0RVNVl5MDJPV1ZqTFRSbE1EWXRZVGc1WkMxaE5EVXdZelV5WTJGaE9Ea2lMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJbWxtUTJWT2JFb3lVR3RzVkVaSE9ETllVbVE0Um1jaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaVpUUm1NV1F3T0dJdFpETTJNeTAwWlRGbUxXRm1NamN0T0dRNVpqY3hPRFE1WmpGa0lpd2lZWFJmYUdGemFDSTZJa3RwVFhwUVQzUnhOR2xtVTBkcWMyczVSbHB2YVVFaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaVpUUm1NV1F3T0dJdFpETTJNeTAwWlRGbUxXRm1NamN0T0dRNVpqY3hPRFE1WmpGa0lpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lhMlY1WVhWMGFDSTZJalI0VVVsRlJEbHBVRXhSYnpGbWExQk1RbkV4ZW01QmJtbDNkbU5XYzNoUkxreFJlV2QyWWtSaVNGcFdRVEJoWlRVdFZYSmhNMU5XZUV0bk9FeExaa001Vlc5d1gxbERaVFpyWWtFaUxDSmhZMjFsWDJGMVpDSTZJbWgwZEhCek9pOHZjM1JsY0dOaE9qTXlPVEkyTDJGamJXVXZkMmx5WlM5amFHRnNiR1Z1WjJVdlJXbDBaRkpCT0dkNmVIVlNRM0pJYkhCd1drcG1VWE5DT0VocWMydHNjR292UkdGMVoxaHFOSEpDZHpBMFQyWnFlVmRtZFdOSlEyOWhUMEZIUjNwWVJsRWlMQ0puYVhabGJsOXVZVzFsSWpvaVFXeHBZMlVpTENKbVlXMXBiSGxmYm1GdFpTSTZJbE50YVhSb0lpd2laVzFoYVd3aU9pSmhiR2xqWlhOdGFYUm9RSGRwY21VdVkyOXRJbjAuaG5HeUs1Um9JblVhSzFRbU9CWlZBa1FWQXpCLTMwZGRoQ2JwYTBUeFh4NXdJMkFGbXdtQjJPUUJrY2hZYjJQV3FINE8xb21YZE1yODhYRmhCUkJma3J5LW1WV0JjSGg1R2pZWlA5enJJTFJNNFJ0QnJ5MDE0V1hyYldCMmlNYk5tX0tOXzc0UlFIUE9QemZKR1c5R2l6Ty1sdTFTYThXYWtDdkxUT2pYMzA1T1djWDJiUlhTaVNPVzg0eHp0cHVJSDB5NTI2TGJUMjdncDRmaDR5UmZHNmZwaUdPOXhPQTdvV3Zsc05BdE5DR3RweUhJTnpJYkhDY05hM1ZadHhHdF9za28zVFBpenFpX3VpdTFzdFhUUm80MW9DaERKTU5WRHA4VHZhUWo2dWJKaldwQUxiU3RsRXUtdllQTkZzRVd4YXFmZGVkS0NoWDU4bzBrRFJaenNnIn0",
  "signature": "A7Dw5v4VIMTXM-2EvoRGMEXgVzwyRZ99g-7ip63Xb8tZkwYc6OSJjs5V2usVRs56F4GNKqZEV0Bvo3QTtXnADg"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJkTjFDelBjZnVlWXFWSUUta0hmMDBFb2lqUmJvMFhIS0tvb3NZY3FkLWpNIn0.eyJleHAiOjE3MDU1NzI3NjMsImlhdCI6MTcwNTU3MjcwMywiYXV0aF90aW1lIjoxNzA1NTcyNzAzLCJqdGkiOiJiNmZjOTQwOS1lNDgzLTQxMmUtYjY2Mi0wN2RlNGRkNWM1MjciLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTUxNzAvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJhMjQzODU5Yy02OWVjLTRlMDYtYTg5ZC1hNDUwYzUyY2FhODkiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6ImlmQ2VObEoyUGtsVEZHODNYUmQ4RmciLCJzZXNzaW9uX3N0YXRlIjoiZTRmMWQwOGItZDM2My00ZTFmLWFmMjctOGQ5ZjcxODQ5ZjFkIiwiYXRfaGFzaCI6IktpTXpQT3RxNGlmU0dqc2s5RlpvaUEiLCJhY3IiOiIxIiwic2lkIjoiZTRmMWQwOGItZDM2My00ZTFmLWFmMjctOGQ5ZjcxODQ5ZjFkIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6IjR4UUlFRDlpUExRbzFma1BMQnExem5Bbml3dmNWc3hRLkxReWd2YkRiSFpWQTBhZTUtVXJhM1NWeEtnOExLZkM5VW9wX1lDZTZrYkEiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9jaGFsbGVuZ2UvRWl0ZFJBOGd6eHVSQ3JIbHBwWkpmUXNCOEhqc2tscGovRGF1Z1hqNHJCdzA0T2ZqeVdmdWNJQ29hT0FHR3pYRlEiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.hnGyK5RoInUaK1QmOBZVAkQVAzB-30ddhCbpa0TxXx5wI2AFmwmB2OQBkchYb2PWqH4O1omXdMr88XFhBRBfkry-mVWBcHh5GjYZP9zrILRM4RtBry014WXrbWB2iMbNm_KN_74RQHPOPzfJGW9GizO-lu1Sa8WakCvLTOjX305OWcX2bRXSiSOW84xztpuIH0y526LbT27gp4fh4yRfG6fpiGO9xOA7oWvlsNAtNCGtpyHINzIbHCcNa3VZtxGt_sko3TPizqi_uiu1stXTRo41oChDJMNVDp8TvaQj6ubJjWpALbStlEu-vYPNFsEWxaqfdedKChX58o0kDRZzsg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32926/acme/wire/account/cAJXsUhF1twqtV34VRwwoNutr6rgYgED",
    "nonce": "b2ZSQzd0UWZ6V0VWWHpXQkdPOVdTdkNzbXRyYVQ0NmE",
    "typ": "JWT",
    "url": "https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/DaugXj4rBw04OfjyWfucICoaOAGGzXFQ"
  }
}
```
#### 23. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32926/acme/wire/directory>;rel="index"
link: <https://stepca:32926/acme/wire/authz/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj>;rel="up"
location: https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/DaugXj4rBw04OfjyWfucICoaOAGGzXFQ
replay-nonce: Qnh4NWF6Q0NQRGhMbnN5b1BnTmVjNXJJOVNSVU1wMnY
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32926/acme/wire/challenge/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj/DaugXj4rBw04OfjyWfucICoaOAGGzXFQ",
  "status": "valid",
  "token": "4xQIED9iPLQo1fkPLBq1znAniwvcVsxQ",
  "target": "http://keycloak:15170/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 24. verify the status of the order
```http request
POST https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9hY2NvdW50L2NBSlhzVWhGMXR3cXRWMzRWUnd3b051dHI2cmdZZ0VEIiwidHlwIjoiSldUIiwibm9uY2UiOiJRbmg0TldGNlEwTlFSR2hNYm5ONWIxQm5UbVZqTlhKSk9WTlNWVTF3TW5ZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL29yZGVyL0Iwdk16QXk0MFprV1VYWnZvam1KbXNoVDFUQkZpNjJVIn0",
  "payload": "",
  "signature": "1sn0ISnaWgOZ-18KROhWA241pKjAkf0-oDsRTRg-GjK7-tiiv_3kew8acY3boz7tRSWbQJskvCxwgVPaRxj4Cg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32926/acme/wire/account/cAJXsUhF1twqtV34VRwwoNutr6rgYgED",
    "nonce": "Qnh4NWF6Q0NQRGhMbnN5b1BnTmVjNXJJOVNSVU1wMnY",
    "typ": "JWT",
    "url": "https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U"
  }
}
```
#### 25. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32926/acme/wire/directory>;rel="index"
location: https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U
replay-nonce: am02VmtVZHVBZ2gxaU1aOXhkaHRZRGVZTFpCNFBEZko
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://1EWG2XtARyqYMsZ0bRMB_Q!cb674b050f729eb1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32926/acme/wire/authz/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj"
  ],
  "expires": "2024-01-19T10:11:43Z",
  "notBefore": "2024-01-18T10:11:43.688553Z",
  "notAfter": "2034-01-15T10:11:43.688553Z"
}
```
#### 26. create a CSR and call finalize url
```http request
POST https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9hY2NvdW50L2NBSlhzVWhGMXR3cXRWMzRWUnd3b051dHI2cmdZZ0VEIiwidHlwIjoiSldUIiwibm9uY2UiOiJhbTAyVm10VlpIVkJaMmd4YVUxYU9YaGthSFJaUkdWWlRGcENORkJFWmtvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL29yZGVyL0Iwdk16QXk0MFprV1VYWnZvam1KbXNoVDFUQkZpNjJVL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBSEI3NWY3b0dWUXJDcXlmQ2RJNkhBWEFQQzZuY2lSdC1xcDBDdE5GNFdLNW9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2TVVWWFJ6SllkRUZTZVhGWlRYTmFNR0pTVFVKZlVTRmpZalkzTkdJd05UQm1Oekk1WldJeFFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFCM3V3amw5WVlEb2p4aHJKNlRiS09TcVc0T0I0RTNEekc3YnZHWFFqb0dRTlJnRWlPNnJTb3d3bWRPc291dS1KYmVVY1NYT2RRVGkyV1luR2RRaWZBRiJ9",
  "signature": "yq5hnrcCh-al7prN0gZKmUjtadA8WYuafYCXvRfnle6qeg7rR5TDFHTA8HVnTlCseJIeQrXlXKVBZTJbIAKUCg"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAHB75f7oGVQrCqyfCdI6HAXAPC6nciRt-qp0CtNF4WK5oHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vMUVXRzJYdEFSeXFZTXNaMGJSTUJfUSFjYjY3NGIwNTBmNzI5ZWIxQHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQB3uwjl9YYDojxhrJ6TbKOSqW4OB4E3DzG7bvGXQjoGQNRgEiO6rSowwmdOsouu-JbeUcSXOdQTi2WYnGdQifAF"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32926/acme/wire/account/cAJXsUhF1twqtV34VRwwoNutr6rgYgED",
    "nonce": "am02VmtVZHVBZ2gxaU1aOXhkaHRZRGVZTFpCNFBEZko",
    "typ": "JWT",
    "url": "https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAHB75f7oGVQrCqyfCdI6HAXAPC6nciRt
+qp0CtNF4WK5oHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vMUVXRzJYdEFSeXFZTXNaMGJSTUJfUSFjYjY3NGIwNTBmNzI5ZWIxQHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQB3
uwjl9YYDojxhrJ6TbKOSqW4OB4E3DzG7bvGXQjoGQNRgEiO6rSowwmdOsouu+Jbe
UcSXOdQTi2WYnGdQifAF
-----END CERTIFICATE REQUEST-----

```
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O=wire.com, 2.16.840.1.113730.3.1.241=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    70:7b:e5:fe:e8:19:54:2b:0a:ac:9f:09:d2:3a:1c:
                    05:c0:3c:2e:a7:72:24:6d:fa:aa:74:0a:d3:45:e1:
                    62:b9
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://1EWG2XtARyqYMsZ0bRMB_Q!cb674b050f729eb1@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        77:bb:08:e5:f5:86:03:a2:3c:61:ac:9e:93:6c:a3:92:a9:6e:
        0e:07:81:37:0f:31:bb:6e:f1:97:42:3a:06:40:d4:60:12:23:
        ba:ad:2a:30:c2:67:4e:b2:8b:ae:f8:96:de:51:c4:97:39:d4:
        13:8b:65:98:9c:67:50:89:f0:05

```

#### 27. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32926/acme/wire/directory>;rel="index"
location: https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U
replay-nonce: NzhHYlFCRUF6NDFhNFB1djdOcFkzVXdwOFptZHRQNTQ
```
```json
{
  "certificate": "https://stepca:32926/acme/wire/certificate/h9cDMf5pspJgGz6KMEWy1zNCiUrFxUk8",
  "status": "valid",
  "finalize": "https://stepca:32926/acme/wire/order/B0vMzAy40ZkWUXZvojmJmshT1TBFi62U/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://1EWG2XtARyqYMsZ0bRMB_Q!cb674b050f729eb1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32926/acme/wire/authz/EitdRA8gzxuRCrHlppZJfQsB8Hjsklpj"
  ],
  "expires": "2024-01-19T10:11:43Z",
  "notBefore": "2024-01-18T10:11:43.688553Z",
  "notAfter": "2034-01-15T10:11:43.688553Z"
}
```
#### 28. fetch the certificate
```http request
POST https://stepca:32926/acme/wire/certificate/h9cDMf5pspJgGz6KMEWy1zNCiUrFxUk8
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTI2L2FjbWUvd2lyZS9hY2NvdW50L2NBSlhzVWhGMXR3cXRWMzRWUnd3b051dHI2cmdZZ0VEIiwidHlwIjoiSldUIiwibm9uY2UiOiJOemhIWWxGQ1JVRjZOREZoTkZCMWRqZE9jRmt6Vlhkd09GcHRaSFJRTlRRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjYvYWNtZS93aXJlL2NlcnRpZmljYXRlL2g5Y0RNZjVwc3BKZ0d6NktNRVd5MXpOQ2lVckZ4VWs4In0",
  "payload": "",
  "signature": "PaX8ngrUSsPFADWLIcgNu0c3bLLZ7zUYAk4p9iRFNCsxAF8QJHUTo-Si4VHeOK6Yad9tSCM6Wlh_3JRJuxnJAw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32926/acme/wire/account/cAJXsUhF1twqtV34VRwwoNutr6rgYgED",
    "nonce": "NzhHYlFCRUF6NDFhNFB1djdOcFkzVXdwOFptZHRQNTQ",
    "typ": "JWT",
    "url": "https://stepca:32926/acme/wire/certificate/h9cDMf5pspJgGz6KMEWy1zNCiUrFxUk8"
  }
}
```
#### 29. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32926/acme/wire/directory>;rel="index"
replay-nonce: N2QxNzVIVHNMMlV5YW5FVkVQZWNRZkxsOE1CdDNzTDk
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGTCCAb+gAwIBAgIQRfe54acOe2tiyJW6Q0lD1zAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nNDAxMTgxMDExNDNaFw0zNDAxMTUxMDExNDNaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAHB75f7oGVQrCqyfCdI6\nHAXAPC6nciRt+qp0CtNF4WK5o4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUuCW7WUFDDGV4hem2jhfraMjKkSUwHwYD\nVR0jBBgwFoAUN/hNBhTaVY4AxIVXbwbUuG8cf18waQYDVR0RBGIwYIYgd2lyZWFw\ncDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly8xRVdHMlh0QVJ5\ncVlNc1owYlJNQl9RJTIxY2I2NzRiMDUwZjcyOWViMUB3aXJlLmNvbTAdBgwrBgEE\nAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIgPnEqcasY\n5xeLoTEi4vj5Dd8YxiNEiZOIdAtLFkK1HWECIQDSMwCF7B6m774SnwuQx7ZWPRn4\nBXt/5Q5G9zw/Fx8Hbw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV6gAwIBAgIQcSq8/qjGNSe/lzV6GQdauTAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTE4MTAx\nMTQyWhcNMzQwMTE1MTAxMTQyWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN+R\nBatdvnI+0icNT5QX/URPOPuFR23uOHs3PPCmyzLzntqJXxvK1BBdnPQjddiNzKCp\nORM0R6lEkyKgpoEn0hmjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBQ3+E0GFNpVjgDEhVdvBtS4bxx/XzAfBgNVHSMEGDAW\ngBThS8PItoESdLTaKNmfFOndvEdRcDAKBggqhkjOPQQDAgNIADBFAiBRuD7PBQ4K\nBMygV6xk5RnrI/kQd0QWYJGcJjdgbv6S1gIhAO2lkm/NNy6u57Y4H0HwwOSDEn1o\nup7mrmyWf1X+anWR\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGTCCAb+gAwIBAgIQRfe54acOe2tiyJW6Q0lD1zAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
NDAxMTgxMDExNDNaFw0zNDAxMTUxMDExNDNaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAHB75f7oGVQrCqyfCdI6
HAXAPC6nciRt+qp0CtNF4WK5o4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUuCW7WUFDDGV4hem2jhfraMjKkSUwHwYD
VR0jBBgwFoAUN/hNBhTaVY4AxIVXbwbUuG8cf18waQYDVR0RBGIwYIYgd2lyZWFw
cDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly8xRVdHMlh0QVJ5
cVlNc1owYlJNQl9RJTIxY2I2NzRiMDUwZjcyOWViMUB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIgPnEqcasY
5xeLoTEi4vj5Dd8YxiNEiZOIdAtLFkK1HWECIQDSMwCF7B6m774SnwuQx7ZWPRn4
BXt/5Q5G9zw/Fx8Hbw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            45:f7:b9:e1:a7:0e:7b:6b:62:c8:95:ba:43:49:43:d7
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan 18 10:11:43 2024 GMT
            Not After : Jan 15 10:11:43 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    70:7b:e5:fe:e8:19:54:2b:0a:ac:9f:09:d2:3a:1c:
                    05:c0:3c:2e:a7:72:24:6d:fa:aa:74:0a:d3:45:e1:
                    62:b9
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                B8:25:BB:59:41:43:0C:65:78:85:E9:B6:8E:17:EB:68:C8:CA:91:25
            X509v3 Authority Key Identifier: 
                37:F8:4D:06:14:DA:55:8E:00:C4:85:57:6F:06:D4:B8:6F:1C:7F:5F
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://1EWG2XtARyqYMsZ0bRMB_Q%21cb674b050f729eb1@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:3e:71:2a:71:ab:18:e7:17:8b:a1:31:22:e2:f8:
        f9:0d:df:18:c6:23:44:89:93:88:74:0b:4b:16:42:b5:1d:61:
        02:21:00:d2:33:00:85:ec:1e:a6:ef:be:12:9f:0b:90:c7:b6:
        56:3d:19:f8:05:7b:7f:e5:0e:46:f7:3c:3f:17:1f:07:6f

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQcSq8/qjGNSe/lzV6GQdauTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTE4MTAx
MTQyWhcNMzQwMTE1MTAxMTQyWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABN+R
BatdvnI+0icNT5QX/URPOPuFR23uOHs3PPCmyzLzntqJXxvK1BBdnPQjddiNzKCp
ORM0R6lEkyKgpoEn0hmjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQ3+E0GFNpVjgDEhVdvBtS4bxx/XzAfBgNVHSMEGDAW
gBThS8PItoESdLTaKNmfFOndvEdRcDAKBggqhkjOPQQDAgNIADBFAiBRuD7PBQ4K
BMygV6xk5RnrI/kQd0QWYJGcJjdgbv6S1gIhAO2lkm/NNy6u57Y4H0HwwOSDEn1o
up7mrmyWf1X+anWR
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            71:2a:bc:fe:a8:c6:35:27:bf:97:35:7a:19:07:5a:b9
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 18 10:11:42 2024 GMT
            Not After : Jan 15 10:11:42 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:df:91:05:ab:5d:be:72:3e:d2:27:0d:4f:94:17:
                    fd:44:4f:38:fb:85:47:6d:ee:38:7b:37:3c:f0:a6:
                    cb:32:f3:9e:da:89:5f:1b:ca:d4:10:5d:9c:f4:23:
                    75:d8:8d:cc:a0:a9:39:13:34:47:a9:44:93:22:a0:
                    a6:81:27:d2:19
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                37:F8:4D:06:14:DA:55:8E:00:C4:85:57:6F:06:D4:B8:6F:1C:7F:5F
            X509v3 Authority Key Identifier: 
                E1:4B:C3:C8:B6:81:12:74:B4:DA:28:D9:9F:14:E9:DD:BC:47:51:70
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:51:b8:3e:cf:05:0e:0a:04:cc:a0:57:ac:64:e5:
        19:eb:23:f9:10:77:44:16:60:91:9c:26:37:60:6e:fe:92:d6:
        02:21:00:ed:a5:92:6f:cd:37:2e:ae:e7:b6:38:1f:41:f0:c0:
        e4:83:12:7d:68:ba:9e:e6:ae:6c:96:7f:55:fe:6a:75:91

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIRAO6PbpPv7SeGRKS6xAlYp2UwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExODEw
MTE0MVoXDTM0MDExNTEwMTE0MVowJjENMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMM
d2lyZSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEs8encHd6d5Ls
XNFoBfCeoifKw9K0SiLFPcQSnBMtZNCDJj7QbQt6H3eUQn2uJM9tGp0mGM2ZnsLJ
BVKWWKiM8aNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEw
HQYDVR0OBBYEFOFLw8i2gRJ0tNoo2Z8U6d28R1FwMAoGCCqGSM49BAMCA0gAMEUC
ICXkTEh2T+48C7OmIZoMhC1DbD5RLRu11GJCJfCAmnP4AiEApzvoQeMJLyYNR3Cv
fTBhVNrvnnbUImApDpQr+Cx2slY=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ee:8f:6e:93:ef:ed:27:86:44:a4:ba:c4:09:58:a7:65
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 18 10:11:41 2024 GMT
            Not After : Jan 15 10:11:41 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:b3:c7:a7:70:77:7a:77:92:ec:5c:d1:68:05:f0:
                    9e:a2:27:ca:c3:d2:b4:4a:22:c5:3d:c4:12:9c:13:
                    2d:64:d0:83:26:3e:d0:6d:0b:7a:1f:77:94:42:7d:
                    ae:24:cf:6d:1a:9d:26:18:cd:99:9e:c2:c9:05:52:
                    96:58:a8:8c:f1
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                E1:4B:C3:C8:B6:81:12:74:B4:DA:28:D9:9F:14:E9:DD:BC:47:51:70
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:25:e4:4c:48:76:4f:ee:3c:0b:b3:a6:21:9a:0c:
        84:2d:43:6c:3e:51:2d:1b:b5:d4:62:42:25:f0:80:9a:73:f8:
        02:21:00:a7:3b:e8:41:e3:09:2f:26:0d:47:70:af:7d:30:61:
        54:da:ef:9e:76:d4:22:60:29:0e:94:2b:f8:2c:76:b2:56

```

openssl verify chain ✅
