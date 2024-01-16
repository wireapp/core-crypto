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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/77eb113fbf44df7c/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/1g0mNhefCjrkoiWhB1JpMFtyGPu4yEPE
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/EMBqtxdhuq0ZK67otnOl4n2omKVg7LGP
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/HXO1PE3g3Z2km9mgMdyDAlNefQQqGSG9
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32912/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
vary: Origin
```
```json
{
  "newNonce": "https://stepca:32912/acme/wire/new-nonce",
  "newAccount": "https://stepca:32912/acme/wire/new-account",
  "newOrder": "https://stepca:32912/acme/wire/new-order",
  "revokeCert": "https://stepca:32912/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32912/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32912/acme/wire/directory>;rel="index"
replay-nonce: djRQVUNSWnVlazJUdXBBb1RGbEx5YWdLUkxnenNRdUw
vary: Origin
```
```text
djRQVUNSWnVlazJUdXBBb1RGbEx5YWdLUkxnenNRdUw
```
#### 5. create a new account
```http request
POST https://stepca:32912/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjFMT1BFelNKeWxSdDF3dmJUZV9TSFFDd0hQVEhtQXhwRjJDOWNKVmxTYVUifSwibm9uY2UiOiJkalJRVlVOU1duVmxhekpVZFhCQmIxUkdiRXg1WVdkTFVreG5lbk5SZFV3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "SBV-NTGhXbdGLsOspgNIF9rtx16-asOTTs8XOSaulkl-NkU9UXAW1mUqfAhuc6bft8B4tpY3nPTbxjqAn7ziDw"
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
      "x": "1LOPEzSJylRt1wvbTe_SHQCwHPTHmAxpF2C9cJVlSaU"
    },
    "nonce": "djRQVUNSWnVlazJUdXBBb1RGbEx5YWdLUkxnenNRdUw",
    "typ": "JWT",
    "url": "https://stepca:32912/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32912/acme/wire/directory>;rel="index"
location: https://stepca:32912/acme/wire/account/VNLGGl68WZBz4rAUuQY9EAqzOdL7EAW1
replay-nonce: MW0xSUZpRXJNMHlUbGd1MEdyRm1RSzVKbE9XQjdLWmw
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32912/acme/wire/account/VNLGGl68WZBz4rAUuQY9EAqzOdL7EAW1/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32912/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTEyL2FjbWUvd2lyZS9hY2NvdW50L1ZOTEdHbDY4V1pCejRyQVV1UVk5RUFxek9kTDdFQVcxIiwidHlwIjoiSldUIiwibm9uY2UiOiJNVzB4U1VacFJYSk5NSGxVYkdkMU1FZHlSbTFSU3pWS2JFOVhRamRMV213IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9sQXd6dWdlSlNwS0NOR0tfVlVHd3p3ITc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIn0ifV0sIm5vdEJlZm9yZSI6IjIwMjQtMDEtMTZUMjI6MzU6MjguNDk5NDIzWiIsIm5vdEFmdGVyIjoiMjAzNC0wMS0xM1QyMjozNToyOC40OTk0MjNaIn0",
  "signature": "Hh5X5phmPfKPX8btMdPzhS44LoyRH9eG6tmdMwUovU6gEZp1N0BCXuyXTXKe6KmLu1NddC3MqKDbj3MwWaopDw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://lAwzugeJSpKCNGK_VUGwzw!77eb113fbf44df7c@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2034-01-13T22:35:28.499423Z",
    "notBefore": "2024-01-16T22:35:28.499423Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32912/acme/wire/account/VNLGGl68WZBz4rAUuQY9EAqzOdL7EAW1",
    "nonce": "MW0xSUZpRXJNMHlUbGd1MEdyRm1RSzVKbE9XQjdLWmw",
    "typ": "JWT",
    "url": "https://stepca:32912/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32912/acme/wire/directory>;rel="index"
location: https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq
replay-nonce: M2Y5SHdKQVY5S0hjdURFZWw5Tm1NNDVMdWhoR1Zrekg
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://lAwzugeJSpKCNGK_VUGwzw!77eb113fbf44df7c@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32912/acme/wire/authz/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv"
  ],
  "expires": "2024-01-17T22:35:28Z",
  "notBefore": "2024-01-16T22:35:28.499423Z",
  "notAfter": "2034-01-13T22:35:28.499423Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32912/acme/wire/authz/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTEyL2FjbWUvd2lyZS9hY2NvdW50L1ZOTEdHbDY4V1pCejRyQVV1UVk5RUFxek9kTDdFQVcxIiwidHlwIjoiSldUIiwibm9uY2UiOiJNMlk1U0hkS1FWWTVTMGhqZFVSRlpXdzVUbTFOTkRWTWRXaG9SMVpyZWtnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL2F1dGh6L0F0OTNtZHA0ZHlqcTBnMGF3cnJHZHJSOENjNlF1enV2In0",
  "payload": "",
  "signature": "IqlAdIMUi85PQPlVwSrGJAMcYwAwhRf5Pp8rQftnH9bHqPOhlxO4WS2LGh0NsQxcjPzTXB1sywUgPUKGAv84Bg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32912/acme/wire/account/VNLGGl68WZBz4rAUuQY9EAqzOdL7EAW1",
    "nonce": "M2Y5SHdKQVY5S0hjdURFZWw5Tm1NNDVMdWhoR1Zrekg",
    "typ": "JWT",
    "url": "https://stepca:32912/acme/wire/authz/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32912/acme/wire/directory>;rel="index"
location: https://stepca:32912/acme/wire/authz/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv
replay-nonce: VDlCNmdaYlJpZ2Jxc09VWDBGSTRkQVQ5a3FGcU9pS3g
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2024-01-17T22:35:28Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/EMBqtxdhuq0ZK67otnOl4n2omKVg7LGP",
      "status": "pending",
      "token": "xKdQ4tbsk8Pyh40aLKBm0WyeTlORgx0p",
      "target": "http://keycloak:23132/realms/master"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/1g0mNhefCjrkoiWhB1JpMFtyGPu4yEPE",
      "status": "pending",
      "token": "xKdQ4tbsk8Pyh40aLKBm0WyeTlORgx0p",
      "target": "http://wire.com:24091/clients/77eb113fbf44df7c/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://lAwzugeJSpKCNGK_VUGwzw!77eb113fbf44df7c@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:24091/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
QkYxUUMxaFJvUEdvT21rOWtKOFhzUkU0ZzJlblVKeXU
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMUxPUEV6U0p5bFJ0MXd2YlRlX1NIUUN3SFBUSG1BeHBGMkM5Y0pWbFNhVSJ9fQ.eyJpYXQiOjE3MDU0NDA5MjgsImV4cCI6MTcwNTQ0ODEyOCwibmJmIjoxNzA1NDQwOTI4LCJzdWIiOiJ3aXJlYXBwOi8vbEF3enVnZUpTcEtDTkdLX1ZVR3d6dyE3N2ViMTEzZmJmNDRkZjdjQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL2NoYWxsZW5nZS9BdDkzbWRwNGR5anEwZzBhd3JyR2RyUjhDYzZRdXp1di8xZzBtTmhlZkNqcmtvaVdoQjFKcE1GdHlHUHU0eUVQRSIsImp0aSI6ImRmMGZlMWQ5LTlmMDAtNDcxNC05YWNlLWI4NmViZGI3ODJlMyIsIm5vbmNlIjoiUWtZeFVVTXhhRkp2VUVkdlQyMXJPV3RLT0ZoelVrVTBaekpsYmxWS2VYVSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQwOTEvY2xpZW50cy83N2ViMTEzZmJmNDRkZjdjL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJ4S2RRNHRic2s4UHloNDBhTEtCbTBXeWVUbE9SZ3gwcCIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.o-u_xGEV4VjyIGqGBcQ0TBcPgFSOr-UZNY410NVIejY_DH1Ero6T8DqaFU6X8emwNaLyrLzhKA07JWPczyzxAA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMUxPUEV6U0p5bFJ0MXd2YlRlX1NIUUN3
SFBUSG1BeHBGMkM5Y0pWbFNhVSJ9fQ.eyJpYXQiOjE3MDU0NDA5MjgsImV4cCI6M
TcwNTQ0ODEyOCwibmJmIjoxNzA1NDQwOTI4LCJzdWIiOiJ3aXJlYXBwOi8vbEF3e
nVnZUpTcEtDTkdLX1ZVR3d6dyE3N2ViMTEzZmJmNDRkZjdjQHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL2NoYWxsZW5nZS9Bd
DkzbWRwNGR5anEwZzBhd3JyR2RyUjhDYzZRdXp1di8xZzBtTmhlZkNqcmtvaVdoQ
jFKcE1GdHlHUHU0eUVQRSIsImp0aSI6ImRmMGZlMWQ5LTlmMDAtNDcxNC05YWNlL
WI4NmViZGI3ODJlMyIsIm5vbmNlIjoiUWtZeFVVTXhhRkp2VUVkdlQyMXJPV3RLT
0ZoelVrVTBaekpsYmxWS2VYVSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MjQwOTEvY2xpZW50cy83N2ViMTEzZmJmNDRkZjdjL2FjY2Vzcy10b
2tlbiIsImNoYWwiOiJ4S2RRNHRic2s4UHloNDBhTEtCbTBXeWVUbE9SZ3gwcCIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUifQ.o-u_xGEV4VjyIGqGBcQ0TBcPgFSOr-UZNY410NVIejY_DH1Ero
6T8DqaFU6X8emwNaLyrLzhKA07JWPczyzxAA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "1LOPEzSJylRt1wvbTe_SHQCwHPTHmAxpF2C9cJVlSaU"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/1g0mNhefCjrkoiWhB1JpMFtyGPu4yEPE",
  "chal": "xKdQ4tbsk8Pyh40aLKBm0WyeTlORgx0p",
  "exp": 1705448128,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:24091/clients/77eb113fbf44df7c/access-token",
  "iat": 1705440928,
  "jti": "df0fe1d9-9f00-4714-9ace-b86ebdb782e3",
  "nbf": 1705440928,
  "nonce": "QkYxUUMxaFJvUEdvT21rOWtKOFhzUkU0ZzJlblVKeXU",
  "sub": "wireapp://lAwzugeJSpKCNGK_VUGwzw!77eb113fbf44df7c@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIHb01ucPd1bWOE7oef9cMxB50ydBEM4qkpyudvnrXA4F
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1LOPEzSJylRt1wvbTe/SHQCwHPTHmAxpF2C9cJVlSaU=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:24091/clients/77eb113fbf44df7c/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTVV4UFVFVjZVMHA1YkZKME1YZDJZbFJsWDFOSVVVTjNTRkJVU0cxQmVIQkdNa001WTBwV2JGTmhWU0o5ZlEuZXlKcFlYUWlPakUzTURVME5EQTVNamdzSW1WNGNDSTZNVGN3TlRRME9ERXlPQ3dpYm1KbUlqb3hOekExTkRRd09USTRMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZiRUYzZW5WblpVcFRjRXREVGtkTFgxWlZSM2Q2ZHlFM04yVmlNVEV6Wm1KbU5EUmtaamRqUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekk1TVRJdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOUJkRGt6YldSd05HUjVhbkV3WnpCaGQzSnlSMlJ5VWpoRFl6WlJkWHAxZGk4eFp6QnRUbWhsWmtOcWNtdHZhVmRvUWpGS2NFMUdkSGxIVUhVMGVVVlFSU0lzSW1wMGFTSTZJbVJtTUdabE1XUTVMVGxtTURBdE5EY3hOQzA1WVdObExXSTRObVZpWkdJM09ESmxNeUlzSW01dmJtTmxJam9pVVd0WmVGVlZUWGhoUmtwMlZVVmtkbFF5TVhKUFYzUkxUMFpvZWxWclZUQmFla3BzWW14V1MyVllWU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRd09URXZZMnhwWlc1MGN5ODNOMlZpTVRFelptSm1ORFJrWmpkakwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUo0UzJSUk5IUmljMnM0VUhsb05EQmhURXRDYlRCWGVXVlViRTlTWjNnd2NDSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpZlEuby11X3hHRVY0Vmp5SUdxR0JjUTBUQmNQZ0ZTT3ItVVpOWTQxME5WSWVqWV9ESDFFcm82VDhEcWFGVTZYOGVtd05hTHlyTHpoS0EwN0pXUGN6eXp4QUE
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkJscjNzNHEwdmhoWERJU2NSa0szRHBiVDhNMTVpZC15RENmX1B3dzF0eWcifX0.eyJpYXQiOjE3MDU0NDA5MjgsImV4cCI6MTcwNTQ0NDg4OCwibmJmIjoxNzA1NDQwOTI4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQwOTEvY2xpZW50cy83N2ViMTEzZmJmNDRkZjdjL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9sQXd6dWdlSlNwS0NOR0tfVlVHd3p3ITc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjkxMi9hY21lL3dpcmUvY2hhbGxlbmdlL0F0OTNtZHA0ZHlqcTBnMGF3cnJHZHJSOENjNlF1enV2LzFnMG1OaGVmQ2pya29pV2hCMUpwTUZ0eUdQdTR5RVBFIiwianRpIjoiMTYxMjkxMjgtOWZlNi00ODkwLWIxYzktMjM1OWNmOWUyZmQ1Iiwibm9uY2UiOiJRa1l4VVVNeGFGSnZVRWR2VDIxck9XdEtPRmh6VWtVMFp6SmxibFZLZVhVIiwiY2hhbCI6InhLZFE0dGJzazhQeWg0MGFMS0JtMFd5ZVRsT1JneDBwIiwiY25mIjp7ImtpZCI6ImJuTnNkNDA4NW41RFpVdmljQ0pTeU1fYlhKSjhjNTlvN3Z0LXowc1hqb1UifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNVXhQVUVWNlUwcDViRkowTVhkMllsUmxYMU5JVVVOM1NGQlVTRzFCZUhCR01rTTVZMHBXYkZOaFZTSjlmUS5leUpwWVhRaU9qRTNNRFUwTkRBNU1qZ3NJbVY0Y0NJNk1UY3dOVFEwT0RFeU9Dd2libUptSWpveE56QTFORFF3T1RJNExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmJFRjNlblZuWlVwVGNFdERUa2RMWDFaVlIzZDZkeUUzTjJWaU1URXpabUptTkRSa1pqZGpRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STVNVEl2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5QmREa3piV1J3TkdSNWFuRXdaekJoZDNKeVIyUnlVamhEWXpaUmRYcDFkaTh4WnpCdFRtaGxaa05xY210dmFWZG9RakZLY0UxR2RIbEhVSFUwZVVWUVJTSXNJbXAwYVNJNkltUm1NR1psTVdRNUxUbG1NREF0TkRjeE5DMDVZV05sTFdJNE5tVmlaR0kzT0RKbE15SXNJbTV2Ym1ObElqb2lVV3RaZUZWVlRYaGhSa3AyVlVWa2RsUXlNWEpQVjNSTFQwWm9lbFZyVlRCYWVrcHNZbXhXUzJWWVZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalF3T1RFdlkyeHBaVzUwY3k4M04yVmlNVEV6Wm1KbU5EUmtaamRqTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjRTMlJSTkhSaWMyczRVSGxvTkRCaFRFdENiVEJYZVdWVWJFOVNaM2d3Y0NJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5vLXVfeEdFVjRWanlJR3FHQmNRMFRCY1BnRlNPci1VWk5ZNDEwTlZJZWpZX0RIMUVybzZUOERxYUZVNlg4ZW13TmFMeXJMemhLQTA3SldQY3p5enhBQSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9sQXd6dWdlSlNwS0NOR0tfVlVHd3p3ITc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.f7SSTtZv0hgZprIcEFaTh-z6w-otCpvhq9bXRxE4TdNqsecWCx0o8t3zN54iymzuMlx98EH6BQc8dstSqYuvAA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkJscjNzNHEwdmhoWERJU2NSa0szRHBiVDhNMTVpZC15RENmX1B3dzF0eWcifX0.eyJpYXQiOjE3MDU0NDA5MjgsImV4cCI6MTcwNTQ0NDg4OCwibmJmIjoxNzA1NDQwOTI4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQwOTEvY2xpZW50cy83N2ViMTEzZmJmNDRkZjdjL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9sQXd6dWdlSlNwS0NOR0tfVlVHd3p3ITc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjkxMi9hY21lL3dpcmUvY2hhbGxlbmdlL0F0OTNtZHA0ZHlqcTBnMGF3cnJHZHJSOENjNlF1enV2LzFnMG1OaGVmQ2pya29pV2hCMUpwTUZ0eUdQdTR5RVBFIiwianRpIjoiMTYxMjkxMjgtOWZlNi00ODkwLWIxYzktMjM1OWNmOWUyZmQ1Iiwibm9uY2UiOiJRa1l4VVVNeGFGSnZVRWR2VDIxck9XdEtPRmh6VWtVMFp6SmxibFZLZVhVIiwiY2hhbCI6InhLZFE0dGJzazhQeWg0MGFMS0JtMFd5ZVRsT1JneDBwIiwiY25mIjp7ImtpZCI6ImJuTnNkNDA4NW41RFpVdmljQ0pTeU1fYlhKSjhjNTlvN3Z0LXowc1hqb1UifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNVXhQVUVWNlUwcDViRkowTVhkMllsUmxYMU5JVVVOM1NGQlVTRzFCZUhCR01rTTVZMHBXYkZOaFZTSjlmUS5leUpwWVhRaU9qRTNNRFUwTkRBNU1qZ3NJbVY0Y0NJNk1UY3dOVFEwT0RFeU9Dd2libUptSWpveE56QTFORFF3T1RJNExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmJFRjNlblZuWlVwVGNFdERUa2RMWDFaVlIzZDZkeUUzTjJWaU1URXpabUptTkRSa1pqZGpRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STVNVEl2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5QmREa3piV1J3TkdSNWFuRXdaekJoZDNKeVIyUnlVamhEWXpaUmRYcDFkaTh4WnpCdFRtaGxaa05xY210dmFWZG9RakZLY0UxR2RIbEhVSFUwZVVWUVJTSXNJbXAwYVNJNkltUm1NR1psTVdRNUxUbG1NREF0TkRjeE5DMDVZV05sTFdJNE5tVmlaR0kzT0RKbE15SXNJbTV2Ym1ObElqb2lVV3RaZUZWVlRYaGhSa3AyVlVWa2RsUXlNWEpQVjNSTFQwWm9lbFZyVlRCYWVrcHNZbXhXUzJWWVZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalF3T1RFdlkyeHBaVzUwY3k4M04yVmlNVEV6Wm1KbU5EUmtaamRqTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjRTMlJSTkhSaWMyczRVSGxvTkRCaFRFdENiVEJYZVdWVWJFOVNaM2d3Y0NJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5vLXVfeEdFVjRWanlJR3FHQmNRMFRCY1BnRlNPci1VWk5ZNDEwTlZJZWpZX0RIMUVybzZUOERxYUZVNlg4ZW13TmFMeXJMemhLQTA3SldQY3p5enhBQSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9sQXd6dWdlSlNwS0NOR0tfVlVHd3p3ITc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.f7SSTtZv0hgZprIcEFaTh-z6w-otCpvhq9bXRxE4TdNqsecWCx0o8t3zN54iymzuMlx98EH6BQc8dstSqYuvAA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IkJscjNzNHEwdmhoWERJU2NSa0szRHBiVDhN
MTVpZC15RENmX1B3dzF0eWcifX0.eyJpYXQiOjE3MDU0NDA5MjgsImV4cCI6MTcw
NTQ0NDg4OCwibmJmIjoxNzA1NDQwOTI4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQwOTEvY2xpZW50cy83N2ViMTEzZmJmNDRkZjdjL2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9sQXd6dWdlSlNwS0NOR0tfVlVHd3p3ITc3ZWIxMTNmYmY0
NGRmN2NAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjkxMi9hY21l
L3dpcmUvY2hhbGxlbmdlL0F0OTNtZHA0ZHlqcTBnMGF3cnJHZHJSOENjNlF1enV2
LzFnMG1OaGVmQ2pya29pV2hCMUpwTUZ0eUdQdTR5RVBFIiwianRpIjoiMTYxMjkx
MjgtOWZlNi00ODkwLWIxYzktMjM1OWNmOWUyZmQ1Iiwibm9uY2UiOiJRa1l4VVVN
eGFGSnZVRWR2VDIxck9XdEtPRmh6VWtVMFp6SmxibFZLZVhVIiwiY2hhbCI6InhL
ZFE0dGJzazhQeWg0MGFMS0JtMFd5ZVRsT1JneDBwIiwiY25mIjp7ImtpZCI6ImJu
TnNkNDA4NW41RFpVdmljQ0pTeU1fYlhKSjhjNTlvN3Z0LXowc1hqb1UifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lNVXhQVUVWNlUwcDViRkowTVhkMllsUmxYMU5JVVVOM1NGQlVTRzFCZUhC
R01rTTVZMHBXYkZOaFZTSjlmUS5leUpwWVhRaU9qRTNNRFUwTkRBNU1qZ3NJbVY0
Y0NJNk1UY3dOVFEwT0RFeU9Dd2libUptSWpveE56QTFORFF3T1RJNExDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dmJFRjNlblZuWlVwVGNFdERUa2RMWDFaVlIzZDZkeUUz
TjJWaU1URXpabUptTkRSa1pqZGpRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STVNVEl2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM5QmREa3piV1J3TkdSNWFuRXdaekJoZDNKeVIyUnlVamhEWXpaUmRYcDFkaTh4
WnpCdFRtaGxaa05xY210dmFWZG9RakZLY0UxR2RIbEhVSFUwZVVWUVJTSXNJbXAw
YVNJNkltUm1NR1psTVdRNUxUbG1NREF0TkRjeE5DMDVZV05sTFdJNE5tVmlaR0kz
T0RKbE15SXNJbTV2Ym1ObElqb2lVV3RaZUZWVlRYaGhSa3AyVlVWa2RsUXlNWEpQ
VjNSTFQwWm9lbFZyVlRCYWVrcHNZbXhXUzJWWVZTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalF3T1RFdlkyeHBaVzUw
Y3k4M04yVmlNVEV6Wm1KbU5EUmtaamRqTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSjRTMlJSTkhSaWMyczRVSGxvTkRCaFRFdENiVEJYZVdWVWJFOVNaM2d3
Y0NJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5vLXVfeEdFVjRWanlJ
R3FHQmNRMFRCY1BnRlNPci1VWk5ZNDEwTlZJZWpZX0RIMUVybzZUOERxYUZVNlg4
ZW13TmFMeXJMemhLQTA3SldQY3p5enhBQSIsImNsaWVudF9pZCI6IndpcmVhcHA6
Ly9sQXd6dWdlSlNwS0NOR0tfVlVHd3p3ITc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5j
b20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.f7S
STtZv0hgZprIcEFaTh-z6w-otCpvhq9bXRxE4TdNqsecWCx0o8t3zN54iymzuMlx
98EH6BQc8dstSqYuvAA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "Blr3s4q0vhhXDIScRkK3DpbT8M15id-yDCf_Pww1tyg"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/1g0mNhefCjrkoiWhB1JpMFtyGPu4yEPE",
  "chal": "xKdQ4tbsk8Pyh40aLKBm0WyeTlORgx0p",
  "client_id": "wireapp://lAwzugeJSpKCNGK_VUGwzw!77eb113fbf44df7c@wire.com",
  "cnf": {
    "kid": "bnNsd4085n5DZUvicCJSyM_bXJJ8c59o7vt-z0sXjoU"
  },
  "exp": 1705444888,
  "iat": 1705440928,
  "iss": "http://wire.com:24091/clients/77eb113fbf44df7c/access-token",
  "jti": "16129128-9fe6-4890-b1c9-2359cf9e2fd5",
  "nbf": 1705440928,
  "nonce": "QkYxUUMxaFJvUEdvT21rOWtKOFhzUkU0ZzJlblVKeXU",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMUxPUEV6U0p5bFJ0MXd2YlRlX1NIUUN3SFBUSG1BeHBGMkM5Y0pWbFNhVSJ9fQ.eyJpYXQiOjE3MDU0NDA5MjgsImV4cCI6MTcwNTQ0ODEyOCwibmJmIjoxNzA1NDQwOTI4LCJzdWIiOiJ3aXJlYXBwOi8vbEF3enVnZUpTcEtDTkdLX1ZVR3d6dyE3N2ViMTEzZmJmNDRkZjdjQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL2NoYWxsZW5nZS9BdDkzbWRwNGR5anEwZzBhd3JyR2RyUjhDYzZRdXp1di8xZzBtTmhlZkNqcmtvaVdoQjFKcE1GdHlHUHU0eUVQRSIsImp0aSI6ImRmMGZlMWQ5LTlmMDAtNDcxNC05YWNlLWI4NmViZGI3ODJlMyIsIm5vbmNlIjoiUWtZeFVVTXhhRkp2VUVkdlQyMXJPV3RLT0ZoelVrVTBaekpsYmxWS2VYVSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQwOTEvY2xpZW50cy83N2ViMTEzZmJmNDRkZjdjL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJ4S2RRNHRic2s4UHloNDBhTEtCbTBXeWVUbE9SZ3gwcCIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.o-u_xGEV4VjyIGqGBcQ0TBcPgFSOr-UZNY410NVIejY_DH1Ero6T8DqaFU6X8emwNaLyrLzhKA07JWPczyzxAA",
  "scope": "wire_client_id",
  "sub": "wireapp://lAwzugeJSpKCNGK_VUGwzw!77eb113fbf44df7c@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIMoOxcbHkyzRJlP323kZMj4sc4HKMHnGHz/HBmXSU5Le
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEABlr3s4q0vhhXDIScRkK3DpbT8M15id+yDCf/Pww1tyg=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/1g0mNhefCjrkoiWhB1JpMFtyGPu4yEPE
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTEyL2FjbWUvd2lyZS9hY2NvdW50L1ZOTEdHbDY4V1pCejRyQVV1UVk5RUFxek9kTDdFQVcxIiwidHlwIjoiSldUIiwibm9uY2UiOiJWRGxDTm1kYVlsSnBaMkp4YzA5VldEQkdTVFJrUVZRNWEzRkdjVTlwUzNnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL2NoYWxsZW5nZS9BdDkzbWRwNGR5anEwZzBhd3JyR2RyUjhDYzZRdXp1di8xZzBtTmhlZkNqcmtvaVdoQjFKcE1GdHlHUHU0eUVQRSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrSnNjak56TkhFd2RtaG9XRVJKVTJOU2Ewc3pSSEJpVkRoTk1UVnBaQzE1UkVObVgxQjNkekYwZVdjaWZYMC5leUpwWVhRaU9qRTNNRFUwTkRBNU1qZ3NJbVY0Y0NJNk1UY3dOVFEwTkRnNE9Dd2libUptSWpveE56QTFORFF3T1RJNExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRd09URXZZMnhwWlc1MGN5ODNOMlZpTVRFelptSm1ORFJrWmpkakwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTlzUVhkNmRXZGxTbE53UzBOT1IwdGZWbFZIZDNwM0lUYzNaV0l4TVRObVltWTBOR1JtTjJOQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpreE1pOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMEYwT1ROdFpIQTBaSGxxY1RCbk1HRjNjbkpIWkhKU09FTmpObEYxZW5WMkx6Rm5NRzFPYUdWbVEycHlhMjlwVjJoQ01VcHdUVVowZVVkUWRUUjVSVkJGSWl3aWFuUnBJam9pTVRZeE1qa3hNamd0T1dabE5pMDBPRGt3TFdJeFl6a3RNak0xT1dObU9XVXlabVExSWl3aWJtOXVZMlVpT2lKUmExbDRWVlZOZUdGR1NuWlZSV1IyVkRJeGNrOVhkRXRQUm1oNlZXdFZNRnA2U214aWJGWkxaVmhWSWl3aVkyaGhiQ0k2SW5oTFpGRTBkR0p6YXpoUWVXZzBNR0ZNUzBKdE1GZDVaVlJzVDFKbmVEQndJaXdpWTI1bUlqcDdJbXRwWkNJNkltSnVUbk5rTkRBNE5XNDFSRnBWZG1salEwcFRlVTFmWWxoS1NqaGpOVGx2TjNaMExYb3djMWhxYjFVaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsTlZYaFFWVVZXTmxVd2NEVmlSa293VFZoa01sbHNVbXhZTVU1SlZWVk9NMU5HUWxWVFJ6RkNaVWhDUjAxclRUVlpNSEJYWWtaT2FGWlRTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5SRlV3VGtSQk5VMXFaM05KYlZZMFkwTkpOazFVWTNkT1ZGRXdUMFJGZVU5RGQybGliVXB0U1dwdmVFNTZRVEZPUkZGM1QxUkpORXhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRtSkZSak5sYmxadVdsVndWR05GZEVSVWEyUk1XREZhVmxJelpEWmtlVVV6VGpKV2FVMVVSWHBhYlVwdFRrUlNhMXBxWkdwUlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUVk5WRWwyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE01UW1SRWEzcGlWMUozVGtkU05XRnVSWGRhZWtKb1pETktlVkl5VW5sVmFtaEVXWHBhVW1SWWNERmthVGg0V25wQ2RGUnRhR3hhYTA1eFkyMTBkbUZXWkc5UmFrWkxZMFV4UjJSSWJFaFZTRlV3WlZWV1VWSlRTWE5KYlhBd1lWTkpOa2x0VW0xTlIxcHNUVmRSTlV4VWJHMU5SRUYwVGtSamVFNURNRFZaVjA1c1RGZEpORTV0Vm1sYVIwa3pUMFJLYkUxNVNYTkpiVFYyWW0xT2JFbHFiMmxWVjNSYVpVWldWbFJZYUdoU2EzQXlWbFZXYTJSc1VYbE5XRXBRVmpOU1RGUXdXbTlsYkZaeVZsUkNZV1ZyY0hOWmJYaFhVekpXV1ZaVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxGM1QxUkZkbGt5ZUhCYVZ6VXdZM2s0TTA0eVZtbE5WRVY2V20xS2JVNUVVbXRhYW1ScVRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTalJUTWxKU1RraFNhV015Y3pSVlNHeHZUa1JDYUZSRmRFTmlWRUpZWlZkV1ZXSkZPVk5hTTJkM1kwTkpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsbVVTNXZMWFZmZUVkRlZqUldhbmxKUjNGSFFtTlJNRlJDWTFCblJsTlBjaTFWV2s1Wk5ERXdUbFpKWldwWlgwUklNVVZ5YnpaVU9FUnhZVVpWTmxnNFpXMTNUbUZNZVhKTWVtaExRVEEzU2xkUVkzcDVlbmhCUVNJc0ltTnNhV1Z1ZEY5cFpDSTZJbmRwY21WaGNIQTZMeTlzUVhkNmRXZGxTbE53UzBOT1IwdGZWbFZIZDNwM0lUYzNaV0l4TVRObVltWTBOR1JtTjJOQWQybHlaUzVqYjIwaUxDSmhjR2xmZG1WeWMybHZiaUk2TlN3aWMyTnZjR1VpT2lKM2FYSmxYMk5zYVdWdWRGOXBaQ0o5LmY3U1NUdFp2MGhnWnBySWNFRmFUaC16Nnctb3RDcHZocTliWFJ4RTRUZE5xc2VjV0N4MG84dDN6TjU0aXltenVNbHg5OEVINkJRYzhkc3RTcVl1dkFBIn0",
  "signature": "ipjL9eDLjW1eSmTs6c78zOBN405qcxZPLfVg3FeRP8u8MrEcnWMamVQ7kpMov7y99zKQa72q8ATqW0L9y9b4DQ"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkJscjNzNHEwdmhoWERJU2NSa0szRHBiVDhNMTVpZC15RENmX1B3dzF0eWcifX0.eyJpYXQiOjE3MDU0NDA5MjgsImV4cCI6MTcwNTQ0NDg4OCwibmJmIjoxNzA1NDQwOTI4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQwOTEvY2xpZW50cy83N2ViMTEzZmJmNDRkZjdjL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9sQXd6dWdlSlNwS0NOR0tfVlVHd3p3ITc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjkxMi9hY21lL3dpcmUvY2hhbGxlbmdlL0F0OTNtZHA0ZHlqcTBnMGF3cnJHZHJSOENjNlF1enV2LzFnMG1OaGVmQ2pya29pV2hCMUpwTUZ0eUdQdTR5RVBFIiwianRpIjoiMTYxMjkxMjgtOWZlNi00ODkwLWIxYzktMjM1OWNmOWUyZmQ1Iiwibm9uY2UiOiJRa1l4VVVNeGFGSnZVRWR2VDIxck9XdEtPRmh6VWtVMFp6SmxibFZLZVhVIiwiY2hhbCI6InhLZFE0dGJzazhQeWg0MGFMS0JtMFd5ZVRsT1JneDBwIiwiY25mIjp7ImtpZCI6ImJuTnNkNDA4NW41RFpVdmljQ0pTeU1fYlhKSjhjNTlvN3Z0LXowc1hqb1UifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNVXhQVUVWNlUwcDViRkowTVhkMllsUmxYMU5JVVVOM1NGQlVTRzFCZUhCR01rTTVZMHBXYkZOaFZTSjlmUS5leUpwWVhRaU9qRTNNRFUwTkRBNU1qZ3NJbVY0Y0NJNk1UY3dOVFEwT0RFeU9Dd2libUptSWpveE56QTFORFF3T1RJNExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmJFRjNlblZuWlVwVGNFdERUa2RMWDFaVlIzZDZkeUUzTjJWaU1URXpabUptTkRSa1pqZGpRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STVNVEl2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5QmREa3piV1J3TkdSNWFuRXdaekJoZDNKeVIyUnlVamhEWXpaUmRYcDFkaTh4WnpCdFRtaGxaa05xY210dmFWZG9RakZLY0UxR2RIbEhVSFUwZVVWUVJTSXNJbXAwYVNJNkltUm1NR1psTVdRNUxUbG1NREF0TkRjeE5DMDVZV05sTFdJNE5tVmlaR0kzT0RKbE15SXNJbTV2Ym1ObElqb2lVV3RaZUZWVlRYaGhSa3AyVlVWa2RsUXlNWEpQVjNSTFQwWm9lbFZyVlRCYWVrcHNZbXhXUzJWWVZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalF3T1RFdlkyeHBaVzUwY3k4M04yVmlNVEV6Wm1KbU5EUmtaamRqTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjRTMlJSTkhSaWMyczRVSGxvTkRCaFRFdENiVEJYZVdWVWJFOVNaM2d3Y0NJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5vLXVfeEdFVjRWanlJR3FHQmNRMFRCY1BnRlNPci1VWk5ZNDEwTlZJZWpZX0RIMUVybzZUOERxYUZVNlg4ZW13TmFMeXJMemhLQTA3SldQY3p5enhBQSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9sQXd6dWdlSlNwS0NOR0tfVlVHd3p3ITc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.f7SSTtZv0hgZprIcEFaTh-z6w-otCpvhq9bXRxE4TdNqsecWCx0o8t3zN54iymzuMlx98EH6BQc8dstSqYuvAA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32912/acme/wire/account/VNLGGl68WZBz4rAUuQY9EAqzOdL7EAW1",
    "nonce": "VDlCNmdaYlJpZ2Jxc09VWDBGSTRkQVQ5a3FGcU9pS3g",
    "typ": "JWT",
    "url": "https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/1g0mNhefCjrkoiWhB1JpMFtyGPu4yEPE"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32912/acme/wire/directory>;rel="index"
link: <https://stepca:32912/acme/wire/authz/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv>;rel="up"
location: https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/1g0mNhefCjrkoiWhB1JpMFtyGPu4yEPE
replay-nonce: U0xraU5OSTEyU0JUNVRWektiWHNqNTFIRnpQbzNmNlc
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/1g0mNhefCjrkoiWhB1JpMFtyGPu4yEPE",
  "status": "valid",
  "token": "xKdQ4tbsk8Pyh40aLKBm0WyeTlORgx0p",
  "target": "http://wire.com:24091/clients/77eb113fbf44df7c/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=3rQUgarWIDxJ6ZvhGxBkU3r4-YgLjbvKOVj2qVi5WlA&code_challenge=N5HJsnEDBH-0QekAzjfkWBw2_4QYaMSVUl7XAPnQBVg
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:23132/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=x1YpLrL3ycZkNMvd4gC_Bw&code_challenge=N5HJsnEDBH-0QekAzjfkWBw2_4QYaMSVUl7XAPnQBVg&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A24091%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32912%2Facme%2Fwire%2Fchallenge%2FAt93mdp4dyjq0g0awrrGdrR8Cc6Quzuv%2FEMBqtxdhuq0ZK67otnOl4n2omKVg7LGP%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22xKdQ4tbsk8Pyh40aLKBm0WyeTlORgx0p.bnNsd4085n5DZUvicCJSyM_bXJJ8c59o7vt-z0sXjoU%22%7D%7D%7D&nonce=S_v3m5gE_53nVAwRggfFoA
```

#### 20. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:23132/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=0891b5ac-d624-49fc-9c1e-4c75c98c054a.f375c06c-a3e1-4551-81fa-182dc7afcc58.ac6ad89e-4b25-40de-addb-e698b767ef7b&code_verifier=3rQUgarWIDxJ6ZvhGxBkU3r4-YgLjbvKOVj2qVi5WlA&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A24091%2Fcallback
```
#### 21. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5by1UZzBIbThyaGpPSXpGbkh5ZHJJQVY0RHF4WEZicmJQcW5MRllLdElVIn0.eyJleHAiOjE3MDU0NDQ1ODgsImlhdCI6MTcwNTQ0NDUyOCwiYXV0aF90aW1lIjoxNzA1NDQ0NTI4LCJqdGkiOiJjZTNmNWQyMS01MDM0LTQ3YWQtYTBiOC1kMzg2MGU4NmNkODMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIwYTY5NmViMi1mZGI0LTQ4Y2QtOGUyNC01OWU5MWNiNTdmYTAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJTX3YzbTVnRV81M25WQXdSZ2dmRm9BIiwic2Vzc2lvbl9zdGF0ZSI6ImYzNzVjMDZjLWEzZTEtNDU1MS04MWZhLTE4MmRjN2FmY2M1OCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0MDkxIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgxZmEtMTgyZGM3YWZjYzU4IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.J5D6tqRJ1696yMB-XBK0r3wmSeAFP0GMmkqbgAP4J3tyFE2gsmjA38MhEBM1w6npRA4JnVnZGa-dtWiAQwvxzGDs-VueJvWzBnNWVgoQ5tU2Z75mP4vqI6k8eoe5otJ8PZnmk5GVFsoTCS4VeoBn5UvvRkBfIcnibzJZdqsYOwkbGKxoJNEvcD6gceGWwLbV8dXIGExQQoPshPTfiVBkfS8M9w3-S7Tkb_gaoAsftQl_oUD4iC_hfmEHdfVlWdVx65Ez-V_7I7CFr8_eWxoAmb7T-M-jE-vwL1-jhg11EyQfQuAEPA-8f6VABNDnfmwQwQ4th7h2Sovlb-7bmA3BBQ",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5by1UZzBIbThyaGpPSXpGbkh5ZHJJQVY0RHF4WEZicmJQcW5MRllLdElVIn0.eyJleHAiOjE3MDU0NDQ1ODgsImlhdCI6MTcwNTQ0NDUyOCwiYXV0aF90aW1lIjoxNzA1NDQ0NTI4LCJqdGkiOiIzNjhjYTNjZC1mOTQyLTQ2ZjMtOTJkNi1kMjIwMzU5MDkxNDQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIwYTY5NmViMi1mZGI0LTQ4Y2QtOGUyNC01OWU5MWNiNTdmYTAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IlNfdjNtNWdFXzUzblZBd1JnZ2ZGb0EiLCJzZXNzaW9uX3N0YXRlIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgxZmEtMTgyZGM3YWZjYzU4IiwiYXRfaGFzaCI6Im9Hcnpsc0hucVQ5cU1lejVfN2FjMWciLCJhY3IiOiIxIiwic2lkIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgxZmEtMTgyZGM3YWZjYzU4IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjkxMi9hY21lL3dpcmUvY2hhbGxlbmdlL0F0OTNtZHA0ZHlqcTBnMGF3cnJHZHJSOENjNlF1enV2L0VNQnF0eGRodXEwWks2N290bk9sNG4yb21LVmc3TEdQIiwia2V5YXV0aCI6InhLZFE0dGJzazhQeWg0MGFMS0JtMFd5ZVRsT1JneDBwLmJuTnNkNDA4NW41RFpVdmljQ0pTeU1fYlhKSjhjNTlvN3Z0LXowc1hqb1UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.foGdeSd3wqDxIuJH1seU6azATU_3T7kFPlD3OiuIQuR6BM2IupKCCKGrtRtuSY8ICz-K83O6mmG_iqSAlusKYwqgshvQjXd2vCFNOEbsvdSKHyn3xpqHDY6upstqPRoQ9QdKikEWiSmbqYHfq0I92bi-GjDeXAOaLycUqg5DWJrzRBEt0ORmwQOkCqLQIDoZo7eTJjeVnJVzKe5pkI4kfjzsPuwOwRrIxF78xbsN41-eTQthDFEkR0M_eDx69SxSBpOmRAvO4x0lvHcZ3mBkeblzVjSzk3TYIxp8oPGnOnZWPe1k0t1oQr_kWRNlD_IT5x8mdnW_Vk4as-lvBTLCWw",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhNWE2MzJhNi04ODNlLTQ1NWItYTRjNi0yZjFmOGMzZjc0M2IifQ.eyJleHAiOjE3MDU0NDYzMjgsImlhdCI6MTcwNTQ0NDUyOCwianRpIjoiYWY4NGU3NWItM2Q2ZS00MTE4LTkyNjYtYmY3NmM1YWZlOWEwIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjIzMTMyL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc3RlciIsInN1YiI6IjBhNjk2ZWIyLWZkYjQtNDhjZC04ZTI0LTU5ZTkxY2I1N2ZhMCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJTX3YzbTVnRV81M25WQXdSZ2dmRm9BIiwic2Vzc2lvbl9zdGF0ZSI6ImYzNzVjMDZjLWEzZTEtNDU1MS04MWZhLTE4MmRjN2FmY2M1OCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJmMzc1YzA2Yy1hM2UxLTQ1NTEtODFmYS0xODJkYzdhZmNjNTgifQ.-aKOhKHikFq-8rHwPmCkr0jY-bwjJne_kNVK9jzTU_I",
  "scope": "openid profile email",
  "session_state": "f375c06c-a3e1-4551-81fa-182dc7afcc58",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5by1UZzBIbThyaGpPSXpGbkh5ZHJJQVY0RHF4WEZicmJQcW5MRllLdElVIn0.eyJleHAiOjE3MDU0NDQ1ODgsImlhdCI6MTcwNTQ0NDUyOCwiYXV0aF90aW1lIjoxNzA1NDQ0NTI4LCJqdGkiOiJjZTNmNWQyMS01MDM0LTQ3YWQtYTBiOC1kMzg2MGU4NmNkODMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIwYTY5NmViMi1mZGI0LTQ4Y2QtOGUyNC01OWU5MWNiNTdmYTAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJTX3YzbTVnRV81M25WQXdSZ2dmRm9BIiwic2Vzc2lvbl9zdGF0ZSI6ImYzNzVjMDZjLWEzZTEtNDU1MS04MWZhLTE4MmRjN2FmY2M1OCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0MDkxIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgxZmEtMTgyZGM3YWZjYzU4IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.J5D6tqRJ1696yMB-XBK0r3wmSeAFP0GMmkqbgAP4J3tyFE2gsmjA38MhEBM1w6npRA4JnVnZGa-dtWiAQwvxzGDs-VueJvWzBnNWVgoQ5tU2Z75mP4vqI6k8eoe5otJ8PZnmk5GVFsoTCS4VeoBn5UvvRkBfIcnibzJZdqsYOwkbGKxoJNEvcD6gceGWwLbV8dXIGExQQoPshPTfiVBkfS8M9w3-S7Tkb_gaoAsftQl_oUD4iC_hfmEHdfVlWdVx65Ez-V_7I7CFr8_eWxoAmb7T-M-jE-vwL1-jhg11EyQfQuAEPA-8f6VABNDnfmwQwQ4th7h2Sovlb-7bmA3BBQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5by1UZzBIbThy
aGpPSXpGbkh5ZHJJQVY0RHF4WEZicmJQcW5MRllLdElVIn0.eyJleHAiOjE3MDU0
NDQ1ODgsImlhdCI6MTcwNTQ0NDUyOCwiYXV0aF90aW1lIjoxNzA1NDQ0NTI4LCJq
dGkiOiJjZTNmNWQyMS01MDM0LTQ3YWQtYTBiOC1kMzg2MGU4NmNkODMiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiIwYTY5NmViMi1mZGI0LTQ4Y2QtOGUyNC01OWU5MWNiNTdm
YTAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJTX3Yz
bTVnRV81M25WQXdSZ2dmRm9BIiwic2Vzc2lvbl9zdGF0ZSI6ImYzNzVjMDZjLWEz
ZTEtNDU1MS04MWZhLTE4MmRjN2FmY2M1OCIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0MDkxIl0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxl
IGVtYWlsIiwic2lkIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgxZmEtMTgyZGM3YWZj
YzU4IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdp
cmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0
aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.J5D6tqRJ1696yMB-XBK
0r3wmSeAFP0GMmkqbgAP4J3tyFE2gsmjA38MhEBM1w6npRA4JnVnZGa-dtWiAQwv
xzGDs-VueJvWzBnNWVgoQ5tU2Z75mP4vqI6k8eoe5otJ8PZnmk5GVFsoTCS4VeoB
n5UvvRkBfIcnibzJZdqsYOwkbGKxoJNEvcD6gceGWwLbV8dXIGExQQoPshPTfiVB
kfS8M9w3-S7Tkb_gaoAsftQl_oUD4iC_hfmEHdfVlWdVx65Ez-V_7I7CFr8_eWxo
Amb7T-M-jE-vwL1-jhg11EyQfQuAEPA-8f6VABNDnfmwQwQ4th7h2Sovlb-7bmA3
BBQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "yo-Tg0Hm8rhjOIzFnHydrIAV4DqxXFbrbPqnLFYKtIU",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:24091"
  ],
  "aud": "account",
  "auth_time": 1705444528,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1705444588,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1705444528,
  "iss": "http://keycloak:23132/realms/master",
  "jti": "ce3f5d21-5034-47ad-a0b8-d3860e86cd83",
  "name": "Alice Smith",
  "nonce": "S_v3m5gE_53nVAwRggfFoA",
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
  "session_state": "f375c06c-a3e1-4551-81fa-182dc7afcc58",
  "sid": "f375c06c-a3e1-4551-81fa-182dc7afcc58",
  "sub": "0a696eb2-fdb4-48cd-8e24-59e91cb57fa0",
  "typ": "Bearer"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApq9iRc9Pf0mivV/NVvQ+
RMGfoABUFLhSHZMiTUyo31Obo0lnij22sap0Sg/lgyHsG8h9bO9iEtKlAHWaOXdk
42frFtGtZHx3vdZr0WRr2hQ78Og5hLMuCDr1xnyoutqwOeSPqFzwTRuTk19oICtJ
DUX+uViUb/GI4qtaQgaZaQ/q+RTiWzZMFVKZaXl+TJotzZzulhesuRUz+xYrvXMC
eJgJRRHpO9OtcORwUMb/WauEBV+ghyBwEZyzp4P9O9aPLMVZdp9xphcSAkmkTyiu
c7gwEV9TKOi8+0vHLf7l0oR49+lM+4mifuI5mlJPWA4WxF1xc52B/YChVTCPT1sv
CwIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhNWE2MzJhNi04ODNlLTQ1NWItYTRjNi0yZjFmOGMzZjc0M2IifQ.eyJleHAiOjE3MDU0NDYzMjgsImlhdCI6MTcwNTQ0NDUyOCwianRpIjoiYWY4NGU3NWItM2Q2ZS00MTE4LTkyNjYtYmY3NmM1YWZlOWEwIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjIzMTMyL3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc3RlciIsInN1YiI6IjBhNjk2ZWIyLWZkYjQtNDhjZC04ZTI0LTU5ZTkxY2I1N2ZhMCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJTX3YzbTVnRV81M25WQXdSZ2dmRm9BIiwic2Vzc2lvbl9zdGF0ZSI6ImYzNzVjMDZjLWEzZTEtNDU1MS04MWZhLTE4MmRjN2FmY2M1OCIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiJmMzc1YzA2Yy1hM2UxLTQ1NTEtODFmYS0xODJkYzdhZmNjNTgifQ.-aKOhKHikFq-8rHwPmCkr0jY-bwjJne_kNVK9jzTU_I)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJhNWE2MzJhNi04
ODNlLTQ1NWItYTRjNi0yZjFmOGMzZjc0M2IifQ.eyJleHAiOjE3MDU0NDYzMjgsI
mlhdCI6MTcwNTQ0NDUyOCwianRpIjoiYWY4NGU3NWItM2Q2ZS00MTE4LTkyNjYtY
mY3NmM1YWZlOWEwIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjIzMTMyL3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc
3RlciIsInN1YiI6IjBhNjk2ZWIyLWZkYjQtNDhjZC04ZTI0LTU5ZTkxY2I1N2ZhM
CIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJTX3Yzb
TVnRV81M25WQXdSZ2dmRm9BIiwic2Vzc2lvbl9zdGF0ZSI6ImYzNzVjMDZjLWEzZ
TEtNDU1MS04MWZhLTE4MmRjN2FmY2M1OCIsInNjb3BlIjoib3BlbmlkIHByb2Zpb
GUgZW1haWwiLCJzaWQiOiJmMzc1YzA2Yy1hM2UxLTQ1NTEtODFmYS0xODJkYzdhZ
mNjNTgifQ.-aKOhKHikFq-8rHwPmCkr0jY-bwjJne_kNVK9jzTU_I
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "a5a632a6-883e-455b-a4c6-2f1f8c3f743b",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:23132/realms/master",
  "azp": "wireapp",
  "exp": 1705446328,
  "iat": 1705444528,
  "iss": "http://keycloak:23132/realms/master",
  "jti": "af84e75b-3d6e-4118-9266-bf76c5afe9a0",
  "nonce": "S_v3m5gE_53nVAwRggfFoA",
  "scope": "openid profile email",
  "session_state": "f375c06c-a3e1-4551-81fa-182dc7afcc58",
  "sid": "f375c06c-a3e1-4551-81fa-182dc7afcc58",
  "sub": "0a696eb2-fdb4-48cd-8e24-59e91cb57fa0",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApq9iRc9Pf0mivV/NVvQ+
RMGfoABUFLhSHZMiTUyo31Obo0lnij22sap0Sg/lgyHsG8h9bO9iEtKlAHWaOXdk
42frFtGtZHx3vdZr0WRr2hQ78Og5hLMuCDr1xnyoutqwOeSPqFzwTRuTk19oICtJ
DUX+uViUb/GI4qtaQgaZaQ/q+RTiWzZMFVKZaXl+TJotzZzulhesuRUz+xYrvXMC
eJgJRRHpO9OtcORwUMb/WauEBV+ghyBwEZyzp4P9O9aPLMVZdp9xphcSAkmkTyiu
c7gwEV9TKOi8+0vHLf7l0oR49+lM+4mifuI5mlJPWA4WxF1xc52B/YChVTCPT1sv
CwIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 22. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5by1UZzBIbThyaGpPSXpGbkh5ZHJJQVY0RHF4WEZicmJQcW5MRllLdElVIn0.eyJleHAiOjE3MDU0NDQ1ODgsImlhdCI6MTcwNTQ0NDUyOCwiYXV0aF90aW1lIjoxNzA1NDQ0NTI4LCJqdGkiOiIzNjhjYTNjZC1mOTQyLTQ2ZjMtOTJkNi1kMjIwMzU5MDkxNDQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIwYTY5NmViMi1mZGI0LTQ4Y2QtOGUyNC01OWU5MWNiNTdmYTAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IlNfdjNtNWdFXzUzblZBd1JnZ2ZGb0EiLCJzZXNzaW9uX3N0YXRlIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgxZmEtMTgyZGM3YWZjYzU4IiwiYXRfaGFzaCI6Im9Hcnpsc0hucVQ5cU1lejVfN2FjMWciLCJhY3IiOiIxIiwic2lkIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgxZmEtMTgyZGM3YWZjYzU4IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjkxMi9hY21lL3dpcmUvY2hhbGxlbmdlL0F0OTNtZHA0ZHlqcTBnMGF3cnJHZHJSOENjNlF1enV2L0VNQnF0eGRodXEwWks2N290bk9sNG4yb21LVmc3TEdQIiwia2V5YXV0aCI6InhLZFE0dGJzazhQeWg0MGFMS0JtMFd5ZVRsT1JneDBwLmJuTnNkNDA4NW41RFpVdmljQ0pTeU1fYlhKSjhjNTlvN3Z0LXowc1hqb1UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.foGdeSd3wqDxIuJH1seU6azATU_3T7kFPlD3OiuIQuR6BM2IupKCCKGrtRtuSY8ICz-K83O6mmG_iqSAlusKYwqgshvQjXd2vCFNOEbsvdSKHyn3xpqHDY6upstqPRoQ9QdKikEWiSmbqYHfq0I92bi-GjDeXAOaLycUqg5DWJrzRBEt0ORmwQOkCqLQIDoZo7eTJjeVnJVzKe5pkI4kfjzsPuwOwRrIxF78xbsN41-eTQthDFEkR0M_eDx69SxSBpOmRAvO4x0lvHcZ3mBkeblzVjSzk3TYIxp8oPGnOnZWPe1k0t1oQr_kWRNlD_IT5x8mdnW_Vk4as-lvBTLCWw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5by1UZzBIbThy
aGpPSXpGbkh5ZHJJQVY0RHF4WEZicmJQcW5MRllLdElVIn0.eyJleHAiOjE3MDU0
NDQ1ODgsImlhdCI6MTcwNTQ0NDUyOCwiYXV0aF90aW1lIjoxNzA1NDQ0NTI4LCJq
dGkiOiIzNjhjYTNjZC1mOTQyLTQ2ZjMtOTJkNi1kMjIwMzU5MDkxNDQiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiIwYTY5NmViMi1mZGI0LTQ4Y2QtOGUyNC01OWU5MWNiNTdm
YTAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IlNfdjNtNWdF
XzUzblZBd1JnZ2ZGb0EiLCJzZXNzaW9uX3N0YXRlIjoiZjM3NWMwNmMtYTNlMS00
NTUxLTgxZmEtMTgyZGM3YWZjYzU4IiwiYXRfaGFzaCI6Im9Hcnpsc0hucVQ5cU1l
ejVfN2FjMWciLCJhY3IiOiIxIiwic2lkIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgx
ZmEtMTgyZGM3YWZjYzU4IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBh
bGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9h
dWQiOiJodHRwczovL3N0ZXBjYTozMjkxMi9hY21lL3dpcmUvY2hhbGxlbmdlL0F0
OTNtZHA0ZHlqcTBnMGF3cnJHZHJSOENjNlF1enV2L0VNQnF0eGRodXEwWks2N290
bk9sNG4yb21LVmc3TEdQIiwia2V5YXV0aCI6InhLZFE0dGJzazhQeWg0MGFMS0Jt
MFd5ZVRsT1JneDBwLmJuTnNkNDA4NW41RFpVdmljQ0pTeU1fYlhKSjhjNTlvN3Z0
LXowc1hqb1UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNt
aXRoQHdpcmUuY29tIn0.foGdeSd3wqDxIuJH1seU6azATU_3T7kFPlD3OiuIQuR6
BM2IupKCCKGrtRtuSY8ICz-K83O6mmG_iqSAlusKYwqgshvQjXd2vCFNOEbsvdSK
Hyn3xpqHDY6upstqPRoQ9QdKikEWiSmbqYHfq0I92bi-GjDeXAOaLycUqg5DWJrz
RBEt0ORmwQOkCqLQIDoZo7eTJjeVnJVzKe5pkI4kfjzsPuwOwRrIxF78xbsN41-e
TQthDFEkR0M_eDx69SxSBpOmRAvO4x0lvHcZ3mBkeblzVjSzk3TYIxp8oPGnOnZW
Pe1k0t1oQr_kWRNlD_IT5x8mdnW_Vk4as-lvBTLCWw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "yo-Tg0Hm8rhjOIzFnHydrIAV4DqxXFbrbPqnLFYKtIU",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/EMBqtxdhuq0ZK67otnOl4n2omKVg7LGP",
  "acr": "1",
  "at_hash": "oGrzlsHnqT9qMez5_7ac1g",
  "aud": "wireapp",
  "auth_time": 1705444528,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1705444588,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1705444528,
  "iss": "http://keycloak:23132/realms/master",
  "jti": "368ca3cd-f942-46f3-92d6-d22035909144",
  "keyauth": "xKdQ4tbsk8Pyh40aLKBm0WyeTlORgx0p.bnNsd4085n5DZUvicCJSyM_bXJJ8c59o7vt-z0sXjoU",
  "name": "Alice Smith",
  "nonce": "S_v3m5gE_53nVAwRggfFoA",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "session_state": "f375c06c-a3e1-4551-81fa-182dc7afcc58",
  "sid": "f375c06c-a3e1-4551-81fa-182dc7afcc58",
  "sub": "0a696eb2-fdb4-48cd-8e24-59e91cb57fa0",
  "typ": "ID"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApq9iRc9Pf0mivV/NVvQ+
RMGfoABUFLhSHZMiTUyo31Obo0lnij22sap0Sg/lgyHsG8h9bO9iEtKlAHWaOXdk
42frFtGtZHx3vdZr0WRr2hQ78Og5hLMuCDr1xnyoutqwOeSPqFzwTRuTk19oICtJ
DUX+uViUb/GI4qtaQgaZaQ/q+RTiWzZMFVKZaXl+TJotzZzulhesuRUz+xYrvXMC
eJgJRRHpO9OtcORwUMb/WauEBV+ghyBwEZyzp4P9O9aPLMVZdp9xphcSAkmkTyiu
c7gwEV9TKOi8+0vHLf7l0oR49+lM+4mifuI5mlJPWA4WxF1xc52B/YChVTCPT1sv
CwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/EMBqtxdhuq0ZK67otnOl4n2omKVg7LGP
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTEyL2FjbWUvd2lyZS9hY2NvdW50L1ZOTEdHbDY4V1pCejRyQVV1UVk5RUFxek9kTDdFQVcxIiwidHlwIjoiSldUIiwibm9uY2UiOiJVMHhyYVU1T1NURXlVMEpVTlZSV2VrdGlXSE5xTlRGSVJucFFiek5tTmxjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL2NoYWxsZW5nZS9BdDkzbWRwNGR5anEwZzBhd3JyR2RyUjhDYzZRdXp1di9FTUJxdHhkaHVxMFpLNjdvdG5PbDRuMm9tS1ZnN0xHUCJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSjVieTFVWnpCSWJUaHlhR3BQU1hwR2JraDVaSEpKUVZZMFJIRjRXRVppY21KUWNXNU1SbGxMZEVsVkluMC5leUpsZUhBaU9qRTNNRFUwTkRRMU9EZ3NJbWxoZENJNk1UY3dOVFEwTkRVeU9Dd2lZWFYwYUY5MGFXMWxJam94TnpBMU5EUTBOVEk0TENKcWRHa2lPaUl6TmpoallUTmpaQzFtT1RReUxUUTJaak10T1RKa05pMWtNakl3TXpVNU1Ea3hORFFpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNak14TXpJdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSXdZVFk1Tm1WaU1pMW1aR0kwTFRRNFkyUXRPR1V5TkMwMU9XVTVNV05pTlRkbVlUQWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJbE5mZGpOdE5XZEZYelV6YmxaQmQxSm5aMlpHYjBFaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaVpqTTNOV013Tm1NdFlUTmxNUzAwTlRVeExUZ3habUV0TVRneVpHTTNZV1pqWXpVNElpd2lZWFJmYUdGemFDSTZJbTlIY25wc2MwaHVjVlE1Y1UxbGVqVmZOMkZqTVdjaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaVpqTTNOV013Tm1NdFlUTmxNUzAwTlRVeExUZ3habUV0TVRneVpHTTNZV1pqWXpVNElpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2laMmwyWlc1ZmJtRnRaU0k2SWtGc2FXTmxJaXdpWVdOdFpWOWhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpreE1pOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMEYwT1ROdFpIQTBaSGxxY1RCbk1HRjNjbkpIWkhKU09FTmpObEYxZW5WMkwwVk5RbkYwZUdSb2RYRXdXa3MyTjI5MGJrOXNORzR5YjIxTFZtYzNURWRRSWl3aWEyVjVZWFYwYUNJNkluaExaRkUwZEdKemF6aFFlV2cwTUdGTVMwSnRNRmQ1WlZSc1QxSm5lREJ3TG1KdVRuTmtOREE0Tlc0MVJGcFZkbWxqUTBwVGVVMWZZbGhLU2poak5UbHZOM1owTFhvd2MxaHFiMVVpTENKbVlXMXBiSGxmYm1GdFpTSTZJbE50YVhSb0lpd2laVzFoYVd3aU9pSmhiR2xqWlhOdGFYUm9RSGRwY21VdVkyOXRJbjAuZm9HZGVTZDN3cUR4SXVKSDFzZVU2YXpBVFVfM1Q3a0ZQbEQzT2l1SVF1UjZCTTJJdXBLQ0NLR3J0UnR1U1k4SUN6LUs4M082bW1HX2lxU0FsdXNLWXdxZ3NodlFqWGQydkNGTk9FYnN2ZFNLSHluM3hwcUhEWTZ1cHN0cVBSb1E5UWRLaWtFV2lTbWJxWUhmcTBJOTJiaS1HakRlWEFPYUx5Y1VxZzVEV0pyelJCRXQwT1Jtd1FPa0NxTFFJRG9abzdlVEpqZVZuSlZ6S2U1cGtJNGtmanpzUHV3T3dSckl4Rjc4eGJzTjQxLWVUUXRoREZFa1IwTV9lRHg2OVN4U0JwT21SQXZPNHgwbHZIY1ozbUJrZWJselZqU3prM1RZSXhwOG9QR25PblpXUGUxazB0MW9Rcl9rV1JObERfSVQ1eDhtZG5XX1ZrNGFzLWx2QlRMQ1d3In0",
  "signature": "roo6sZ3FzZ1M14D4gJzPQwJLoCnnqruP9reRqOixOHkN4_fyEafW5e5uPh-MXiuO_qo0M633oT3kbYYvS5LjDQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ5by1UZzBIbThyaGpPSXpGbkh5ZHJJQVY0RHF4WEZicmJQcW5MRllLdElVIn0.eyJleHAiOjE3MDU0NDQ1ODgsImlhdCI6MTcwNTQ0NDUyOCwiYXV0aF90aW1lIjoxNzA1NDQ0NTI4LCJqdGkiOiIzNjhjYTNjZC1mOTQyLTQ2ZjMtOTJkNi1kMjIwMzU5MDkxNDQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjMxMzIvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIwYTY5NmViMi1mZGI0LTQ4Y2QtOGUyNC01OWU5MWNiNTdmYTAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IlNfdjNtNWdFXzUzblZBd1JnZ2ZGb0EiLCJzZXNzaW9uX3N0YXRlIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgxZmEtMTgyZGM3YWZjYzU4IiwiYXRfaGFzaCI6Im9Hcnpsc0hucVQ5cU1lejVfN2FjMWciLCJhY3IiOiIxIiwic2lkIjoiZjM3NWMwNmMtYTNlMS00NTUxLTgxZmEtMTgyZGM3YWZjYzU4IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjkxMi9hY21lL3dpcmUvY2hhbGxlbmdlL0F0OTNtZHA0ZHlqcTBnMGF3cnJHZHJSOENjNlF1enV2L0VNQnF0eGRodXEwWks2N290bk9sNG4yb21LVmc3TEdQIiwia2V5YXV0aCI6InhLZFE0dGJzazhQeWg0MGFMS0JtMFd5ZVRsT1JneDBwLmJuTnNkNDA4NW41RFpVdmljQ0pTeU1fYlhKSjhjNTlvN3Z0LXowc1hqb1UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.foGdeSd3wqDxIuJH1seU6azATU_3T7kFPlD3OiuIQuR6BM2IupKCCKGrtRtuSY8ICz-K83O6mmG_iqSAlusKYwqgshvQjXd2vCFNOEbsvdSKHyn3xpqHDY6upstqPRoQ9QdKikEWiSmbqYHfq0I92bi-GjDeXAOaLycUqg5DWJrzRBEt0ORmwQOkCqLQIDoZo7eTJjeVnJVzKe5pkI4kfjzsPuwOwRrIxF78xbsN41-eTQthDFEkR0M_eDx69SxSBpOmRAvO4x0lvHcZ3mBkeblzVjSzk3TYIxp8oPGnOnZWPe1k0t1oQr_kWRNlD_IT5x8mdnW_Vk4as-lvBTLCWw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32912/acme/wire/account/VNLGGl68WZBz4rAUuQY9EAqzOdL7EAW1",
    "nonce": "U0xraU5OSTEyU0JUNVRWektiWHNqNTFIRnpQbzNmNlc",
    "typ": "JWT",
    "url": "https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/EMBqtxdhuq0ZK67otnOl4n2omKVg7LGP"
  }
}
```
#### 23. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32912/acme/wire/directory>;rel="index"
link: <https://stepca:32912/acme/wire/authz/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv>;rel="up"
location: https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/EMBqtxdhuq0ZK67otnOl4n2omKVg7LGP
replay-nonce: SzllSXFDd1FMSXg4bTNCbXFxSm5lSFkycGU1V2h1aE8
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32912/acme/wire/challenge/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv/EMBqtxdhuq0ZK67otnOl4n2omKVg7LGP",
  "status": "valid",
  "token": "xKdQ4tbsk8Pyh40aLKBm0WyeTlORgx0p",
  "target": "http://keycloak:23132/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 24. verify the status of the order
```http request
POST https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTEyL2FjbWUvd2lyZS9hY2NvdW50L1ZOTEdHbDY4V1pCejRyQVV1UVk5RUFxek9kTDdFQVcxIiwidHlwIjoiSldUIiwibm9uY2UiOiJTemxsU1hGRGQxRk1TWGc0YlROQ2JYRnhTbTVsU0ZreWNHVTFWMmgxYUU4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL29yZGVyLzJoTlZtdzNDd1NGZjBWNlFvdzd4V2JEOFBaS3JjTnpxIn0",
  "payload": "",
  "signature": "EcVBcFwLf4woI1O5BtTh_K3PvOK0nHZ2Epaoc9Dqj3Oe16OjM1afgSLTFxGcVj3NRvM6W2Q_v1MS33cm2EYzCw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32912/acme/wire/account/VNLGGl68WZBz4rAUuQY9EAqzOdL7EAW1",
    "nonce": "SzllSXFDd1FMSXg4bTNCbXFxSm5lSFkycGU1V2h1aE8",
    "typ": "JWT",
    "url": "https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq"
  }
}
```
#### 25. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32912/acme/wire/directory>;rel="index"
location: https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq
replay-nonce: OFIxRXBtU0lWU0tHa3NtaXh5ZUZxeXE1eFo0ZkJYcFU
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://lAwzugeJSpKCNGK_VUGwzw!77eb113fbf44df7c@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32912/acme/wire/authz/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv"
  ],
  "expires": "2024-01-17T22:35:28Z",
  "notBefore": "2024-01-16T22:35:28.499423Z",
  "notAfter": "2034-01-13T22:35:28.499423Z"
}
```
#### 26. create a CSR and call finalize url
```http request
POST https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTEyL2FjbWUvd2lyZS9hY2NvdW50L1ZOTEdHbDY4V1pCejRyQVV1UVk5RUFxek9kTDdFQVcxIiwidHlwIjoiSldUIiwibm9uY2UiOiJPRkl4UlhCdFUwbFdVMHRIYTNOdGFYaDVaVVp4ZVhFMWVGbzBaa0pZY0ZVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL29yZGVyLzJoTlZtdzNDd1NGZjBWNlFvdzd4V2JEOFBaS3JjTnpxL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBSjFiWlhZbndrczhEODNxY2VDNzMxckdURXpubXZyWFMtb2cydlp2TTJ1Nm9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2YkVGM2VuVm5aVXBUY0V0RFRrZExYMVpWUjNkNmR5RTNOMlZpTVRFelptSm1ORFJrWmpkalFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFCaVNVeC1DVVIwOS1KMGJFTC1xZEgtYlo0TmVDcEJVMW1BbkpacktUMlRla2VEREpBeW0xbWVNV0lycEM0S1RXLUUtdXVEbFpxQVY0ZmhMTFJvNUtBSCJ9",
  "signature": "3lo9IV7V5A6sVblatU2ne021_3mscUtcCobLcdQIeKKijtpEbg7R7yNieAXJGMq2B-FfbjDv-6VO2GONRwPDAA"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAJ1bZXYnwks8D83qceC731rGTEznmvrXS-og2vZvM2u6oHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vbEF3enVnZUpTcEtDTkdLX1ZVR3d6dyE3N2ViMTEzZmJmNDRkZjdjQHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQBiSUx-CUR09-J0bEL-qdH-bZ4NeCpBU1mAnJZrKT2TekeDDJAym1meMWIrpC4KTW-E-uuDlZqAV4fhLLRo5KAH"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32912/acme/wire/account/VNLGGl68WZBz4rAUuQY9EAqzOdL7EAW1",
    "nonce": "OFIxRXBtU0lWU0tHa3NtaXh5ZUZxeXE1eFo0ZkJYcFU",
    "typ": "JWT",
    "url": "https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAJ1bZXYnwks8D83qceC731rGTEznmvrX
S+og2vZvM2u6oHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vbEF3enVnZUpTcEtDTkdLX1ZVR3d6dyE3N2ViMTEzZmJmNDRkZjdjQHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQBi
SUx+CUR09+J0bEL+qdH+bZ4NeCpBU1mAnJZrKT2TekeDDJAym1meMWIrpC4KTW+E
+uuDlZqAV4fhLLRo5KAH
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
                    9d:5b:65:76:27:c2:4b:3c:0f:cd:ea:71:e0:bb:df:
                    5a:c6:4c:4c:e7:9a:fa:d7:4b:ea:20:da:f6:6f:33:
                    6b:ba
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://lAwzugeJSpKCNGK_VUGwzw!77eb113fbf44df7c@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        62:49:4c:7e:09:44:74:f7:e2:74:6c:42:fe:a9:d1:fe:6d:9e:
        0d:78:2a:41:53:59:80:9c:96:6b:29:3d:93:7a:47:83:0c:90:
        32:9b:59:9e:31:62:2b:a4:2e:0a:4d:6f:84:fa:eb:83:95:9a:
        80:57:87:e1:2c:b4:68:e4:a0:07

```

#### 27. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32912/acme/wire/directory>;rel="index"
location: https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq
replay-nonce: ZDFsZ21IVG0xQW9hb1Z4UnZmYzhnNVRhTU9OS1BkRnE
vary: Origin
```
```json
{
  "certificate": "https://stepca:32912/acme/wire/certificate/HXO1PE3g3Z2km9mgMdyDAlNefQQqGSG9",
  "status": "valid",
  "finalize": "https://stepca:32912/acme/wire/order/2hNVmw3CwSFf0V6Qow7xWbD8PZKrcNzq/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://lAwzugeJSpKCNGK_VUGwzw!77eb113fbf44df7c@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32912/acme/wire/authz/At93mdp4dyjq0g0awrrGdrR8Cc6Quzuv"
  ],
  "expires": "2024-01-17T22:35:28Z",
  "notBefore": "2024-01-16T22:35:28.499423Z",
  "notAfter": "2034-01-13T22:35:28.499423Z"
}
```
#### 28. fetch the certificate
```http request
POST https://stepca:32912/acme/wire/certificate/HXO1PE3g3Z2km9mgMdyDAlNefQQqGSG9
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTEyL2FjbWUvd2lyZS9hY2NvdW50L1ZOTEdHbDY4V1pCejRyQVV1UVk5RUFxek9kTDdFQVcxIiwidHlwIjoiSldUIiwibm9uY2UiOiJaREZzWjIxSVZHMHhRVzloYjFaNFVuWm1ZemhuTlZSaFRVOU9TMUJrUm5FIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MTIvYWNtZS93aXJlL2NlcnRpZmljYXRlL0hYTzFQRTNnM1oya205bWdNZHlEQWxOZWZRUXFHU0c5In0",
  "payload": "",
  "signature": "t7R2evQrRcAvCAWS-1aBr1B3y37AP7en9cZuiUJzfsNoqEJmBqBZ5bt3x2wBjkqmOPIAOPD2md5DaYZyTRnmDA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32912/acme/wire/account/VNLGGl68WZBz4rAUuQY9EAqzOdL7EAW1",
    "nonce": "ZDFsZ21IVG0xQW9hb1Z4UnZmYzhnNVRhTU9OS1BkRnE",
    "typ": "JWT",
    "url": "https://stepca:32912/acme/wire/certificate/HXO1PE3g3Z2km9mgMdyDAlNefQQqGSG9"
  }
}
```
#### 29. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32912/acme/wire/directory>;rel="index"
replay-nonce: Z3lCUnNQTnZCQ0tqM2R5Nk5jRjdvNG1wTHVHdnNyQ2o
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAcCgAwIBAgIRAIsq56BGaUvLr6+Zf4n1IgAwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMTE2MjIzNTI4WhcNMzQwMTEzMjIzNTI4WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCdW2V2J8JLPA/N6nHg\nu99axkxM55r610vqINr2bzNruqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFMGYSCqvISwyezlcbO+C4oFJ58otMB8G\nA1UdIwQYMBaAFGNpB5T27t3RsPgGTrmYe6pgkKfrMGkGA1UdEQRiMGCGIHdpcmVh\ncHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vbEF3enVnZUpT\ncEtDTkdLX1ZVR3d6dyUyMTc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIASxZ9kF\nDOANnaoANCSOqaQiPrId1U80sWArEPUkVDmgAiEAv6GeNWk21dPqzgER7I14Ggaa\nOrgYnglGZ8mC7LjpwXI=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRALSXua+IBsxyaE5aZb3eBykwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExNjIy\nMzUyNloXDTM0MDExMzIyMzUyNlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATf\nhn+qzYnE56qKXGv87VRN4mQPrjmXyJqXsAlzIczsovFMrNB2ss70dZhowY4ESQEm\n8OiugG0Mh6EayY4ls/Zko2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUY2kHlPbu3dGw+AZOuZh7qmCQp+swHwYDVR0jBBgw\nFoAUAMEivXYReqfHP9rERddhhwnPHHkwCgYIKoZIzj0EAwIDSAAwRQIhAIqAJDPl\nRBoIWjvc9K4VLKerZsdeXh6GdmUQWC+2qFfzAiBdAEXLWo5nx7oBnekia7XEfbpK\nkgd8w/bU8NAlL02qLw==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRAIsq56BGaUvLr6+Zf4n1IgAwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMTE2MjIzNTI4WhcNMzQwMTEzMjIzNTI4WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCdW2V2J8JLPA/N6nHg
u99axkxM55r610vqINr2bzNruqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFMGYSCqvISwyezlcbO+C4oFJ58otMB8G
A1UdIwQYMBaAFGNpB5T27t3RsPgGTrmYe6pgkKfrMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vbEF3enVnZUpT
cEtDTkdLX1ZVR3d6dyUyMTc3ZWIxMTNmYmY0NGRmN2NAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIASxZ9kF
DOANnaoANCSOqaQiPrId1U80sWArEPUkVDmgAiEAv6GeNWk21dPqzgER7I14Ggaa
OrgYnglGZ8mC7LjpwXI=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            8b:2a:e7:a0:46:69:4b:cb:af:af:99:7f:89:f5:22:00
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan 16 22:35:28 2024 GMT
            Not After : Jan 13 22:35:28 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    9d:5b:65:76:27:c2:4b:3c:0f:cd:ea:71:e0:bb:df:
                    5a:c6:4c:4c:e7:9a:fa:d7:4b:ea:20:da:f6:6f:33:
                    6b:ba
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                C1:98:48:2A:AF:21:2C:32:7B:39:5C:6C:EF:82:E2:81:49:E7:CA:2D
            X509v3 Authority Key Identifier: 
                63:69:07:94:F6:EE:DD:D1:B0:F8:06:4E:B9:98:7B:AA:60:90:A7:EB
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://lAwzugeJSpKCNGK_VUGwzw%2177eb113fbf44df7c@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:04:b1:67:d9:05:0c:e0:0d:9d:aa:00:34:24:8e:
        a9:a4:22:3e:b2:1d:d5:4f:34:b1:60:2b:10:f5:24:54:39:a0:
        02:21:00:bf:a1:9e:35:69:36:d5:d3:ea:ce:01:11:ec:8d:78:
        1a:06:9a:3a:b8:18:9e:09:46:67:c9:82:ec:b8:e9:c1:72

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRALSXua+IBsxyaE5aZb3eBykwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExNjIy
MzUyNloXDTM0MDExMzIyMzUyNlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATf
hn+qzYnE56qKXGv87VRN4mQPrjmXyJqXsAlzIczsovFMrNB2ss70dZhowY4ESQEm
8OiugG0Mh6EayY4ls/Zko2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUY2kHlPbu3dGw+AZOuZh7qmCQp+swHwYDVR0jBBgw
FoAUAMEivXYReqfHP9rERddhhwnPHHkwCgYIKoZIzj0EAwIDSAAwRQIhAIqAJDPl
RBoIWjvc9K4VLKerZsdeXh6GdmUQWC+2qFfzAiBdAEXLWo5nx7oBnekia7XEfbpK
kgd8w/bU8NAlL02qLw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            b4:97:b9:af:88:06:cc:72:68:4e:5a:65:bd:de:07:29
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 16 22:35:26 2024 GMT
            Not After : Jan 13 22:35:26 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:df:86:7f:aa:cd:89:c4:e7:aa:8a:5c:6b:fc:ed:
                    54:4d:e2:64:0f:ae:39:97:c8:9a:97:b0:09:73:21:
                    cc:ec:a2:f1:4c:ac:d0:76:b2:ce:f4:75:98:68:c1:
                    8e:04:49:01:26:f0:e8:ae:80:6d:0c:87:a1:1a:c9:
                    8e:25:b3:f6:64
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                63:69:07:94:F6:EE:DD:D1:B0:F8:06:4E:B9:98:7B:AA:60:90:A7:EB
            X509v3 Authority Key Identifier: 
                00:C1:22:BD:76:11:7A:A7:C7:3F:DA:C4:45:D7:61:87:09:CF:1C:79
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:8a:80:24:33:e5:44:1a:08:5a:3b:dc:f4:ae:
        15:2c:a7:ab:66:c7:5e:5e:1e:86:76:65:10:58:2f:b6:a8:57:
        f3:02:20:5d:00:45:cb:5a:8e:67:c7:ba:01:9d:e9:22:6b:b5:
        c4:7d:ba:4a:92:07:7c:c3:f6:d4:f0:d0:25:2f:4d:aa:2f

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATWgAwIBAgIQDui+SBrERqpEEFBZIEO4zjAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTE2MjIz
NTI1WhcNMzQwMTEzMjIzNTI1WjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3
aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASoHdY9ZUdIAv5h
kzJ1dtYqAxc7lLtTpsx23E9VonOIODBR5ieHvfPDVJYzqe0c6C+R0JHLt5D+8dE6
iUc9WSelo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd
BgNVHQ4EFgQUAMEivXYReqfHP9rERddhhwnPHHkwCgYIKoZIzj0EAwIDSQAwRgIh
AM8uRyrYaZ1cddH3frf6X5LFyIRwmQU5kVL+a2V8JdRFAiEAsU+J5l/WIUwepj0Y
WqBJ+nP3uZ2H1gaMrc+Fv1mpx0I=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0e:e8:be:48:1a:c4:46:aa:44:10:50:59:20:43:b8:ce
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 16 22:35:25 2024 GMT
            Not After : Jan 13 22:35:25 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:a8:1d:d6:3d:65:47:48:02:fe:61:93:32:75:76:
                    d6:2a:03:17:3b:94:bb:53:a6:cc:76:dc:4f:55:a2:
                    73:88:38:30:51:e6:27:87:bd:f3:c3:54:96:33:a9:
                    ed:1c:e8:2f:91:d0:91:cb:b7:90:fe:f1:d1:3a:89:
                    47:3d:59:27:a5
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                00:C1:22:BD:76:11:7A:A7:C7:3F:DA:C4:45:D7:61:87:09:CF:1C:79
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:cf:2e:47:2a:d8:69:9d:5c:75:d1:f7:7e:b7:
        fa:5f:92:c5:c8:84:70:99:05:39:91:52:fe:6b:65:7c:25:d4:
        45:02:21:00:b1:4f:89:e6:5f:d6:21:4c:1e:a6:3d:18:5a:a0:
        49:fa:73:f7:b9:9d:87:d6:06:8c:ad:cf:85:bf:59:a9:c7:42

```

openssl verify chain ✅