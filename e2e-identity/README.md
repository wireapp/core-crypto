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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/c1d4519ce580a475/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/v7OXTTRPg7xn2k1EM8ZItqp7uXnamLeu
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/J04SdUogmGSif7EBdFiJKR5zof7Pwamz
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/1N2SXSYR718thgwccKm7U7Ftqq6wb3NL
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32787/acme/wire/directory
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
  "newNonce": "https://stepca:32787/acme/wire/new-nonce",
  "newAccount": "https://stepca:32787/acme/wire/new-account",
  "newOrder": "https://stepca:32787/acme/wire/new-order",
  "revokeCert": "https://stepca:32787/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32787/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32787/acme/wire/directory>;rel="index"
replay-nonce: cDBJUTh6bXhqUnBoSzVnaFhMQmdQZUZEVjZrMGdkZmY
vary: Origin
```
```text
cDBJUTh6bXhqUnBoSzVnaFhMQmdQZUZEVjZrMGdkZmY
```
#### 5. create a new account
```http request
POST https://stepca:32787/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ikxjd3VqVEtDc2ZQZS03WjB0UDRjWV95SllFLXN4dzEzcHA0SHNGLUU5UlUifSwibm9uY2UiOiJjREJKVVRoNmJYaHFVbkJvU3pWbmFGaE1RbWRRWlVaRVZqWnJNR2RrWm1ZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "V8hmJ2DLIj4I5BW1H3suKX8JmccE5bMfM5_LBJABr6e6um_OrEbVzItsVgJlNUSaPj4sx7Buyh3w0JDlOiygDg"
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
      "x": "LcwujTKCsfPe-7Z0tP4cY_yJYE-sxw13pp4HsF-E9RU"
    },
    "nonce": "cDBJUTh6bXhqUnBoSzVnaFhMQmdQZUZEVjZrMGdkZmY",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
location: https://stepca:32787/acme/wire/account/RC1AWVA3UzF7dHQDaEIbP2P2tMCOlzxG
replay-nonce: eWxnM0Vhc3NCQnpUT0hSSEl6eVM1d3l4WnB0U3luVTk
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32787/acme/wire/account/RC1AWVA3UzF7dHQDaEIbP2P2tMCOlzxG/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32787/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L1JDMUFXVkEzVXpGN2RIUURhRUliUDJQMnRNQ09senhHIiwidHlwIjoiSldUIiwibm9uY2UiOiJlV3huTTBWaGMzTkNRbnBVVDBoU1NFbDZlVk0xZDNsNFduQjBVM2x1VlRrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9bEpHWVB6MFpScTJrdmNfWHBkYURsQS9jMWQ0NTE5Y2U1ODBhNDc1QHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0xMi0xNVQwOTozMDoxNy4zMDg0NTZaIiwibm90QWZ0ZXIiOiIyMDMzLTEyLTEyVDA5OjMwOjE3LjMwODQ1NloifQ",
  "signature": "DVrmY0PKT9oedhfxa2GgFJFk2Lv2JyMXzgdRguMKjj51v8QQwYuJXMdixODWx4IlH5eBk-786dR8C9dIkS9hDg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2033-12-12T09:30:17.308456Z",
    "notBefore": "2023-12-15T09:30:17.308456Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/RC1AWVA3UzF7dHQDaEIbP2P2tMCOlzxG",
    "nonce": "eWxnM0Vhc3NCQnpUT0hSSEl6eVM1d3l4WnB0U3luVTk",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
location: https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc
replay-nonce: bXh0Y2lNQ1lLRTZVOUlwRDk3ZWtudHBFdUM5NFBaNFU
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32787/acme/wire/authz/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1"
  ],
  "expires": "2023-12-16T09:30:17Z",
  "notBefore": "2023-12-15T09:30:17.308456Z",
  "notAfter": "2033-12-12T09:30:17.308456Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32787/acme/wire/authz/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L1JDMUFXVkEzVXpGN2RIUURhRUliUDJQMnRNQ09senhHIiwidHlwIjoiSldUIiwibm9uY2UiOiJiWGgwWTJsTlExbExSVFpWT1Vsd1JEazNaV3R1ZEhCRmRVTTVORkJhTkZVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL2F1dGh6LzVoUUlwVWpLRDBSN3lCb2FrMG9FcUlnM1JMMnBMQ3AxIn0",
  "payload": "",
  "signature": "arz28iAx6CgueosZa87GjSs-gLlG_m75cjjuqSA9dfAU1MozP4SK28WkKe_2WuM4dnUMsWLYQyie7XGE8z1ABA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/RC1AWVA3UzF7dHQDaEIbP2P2tMCOlzxG",
    "nonce": "bXh0Y2lNQ1lLRTZVOUlwRDk3ZWtudHBFdUM5NFBaNFU",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/authz/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
location: https://stepca:32787/acme/wire/authz/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1
replay-nonce: cVNySjhvWVpJNHBzREFlNmNrNkNrbUFTQU1BcHZhUWs
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2023-12-16T09:30:17Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/J04SdUogmGSif7EBdFiJKR5zof7Pwamz",
      "status": "pending",
      "token": "zQUJWhbsDMJRa3DqOTx8kqc2Bd9j3G9W",
      "target": "http://dex:22890/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/v7OXTTRPg7xn2k1EM8ZItqp7uXnamLeu",
      "status": "pending",
      "token": "zQUJWhbsDMJRa3DqOTx8kqc2Bd9j3G9W",
      "target": "http://wire.com:22180/clients/c1d4519ce580a475/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:22180/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
S3VjbTVtSUZxbnBhSEwxWnVSek9CUjI3dUp3WUdPdkY
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiTGN3dWpUS0NzZlBlLTdaMHRQNGNZX3lKWUUtc3h3MTNwcDRIc0YtRTlSVSJ9fQ.eyJpYXQiOjE3MDI2MjkwMTcsImV4cCI6MTcwMjYzNjIxNywibmJmIjoxNzAyNjI5MDE3LCJzdWIiOiJpbTp3aXJlYXBwPWxKR1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJlLmNvbSIsImp0aSI6IjFmYzg0NTJlLWZjZWUtNGU1My05NzZkLTJjMjY5MTQwZDQ3ZSIsIm5vbmNlIjoiUzNWamJUVnRTVVp4Ym5CaFNFd3hXblZTZWs5Q1VqSTNkVXAzV1VkUGRrWSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjIxODAvY2xpZW50cy9jMWQ0NTE5Y2U1ODBhNDc1L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJ6UVVKV2hic0RNSlJhM0RxT1R4OGtxYzJCZDlqM0c5VyIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.j2hmMofmXSU3zgcxmPHz5m0lgD4weg55qE0qsLyWqqtxS2qRnUbJm_6rjDrrNZpKHMUKmpcWAmZx-wVUTmxODQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiTGN3dWpUS0NzZlBlLTdaMHRQNGNZX3lK
WUUtc3h3MTNwcDRIc0YtRTlSVSJ9fQ.eyJpYXQiOjE3MDI2MjkwMTcsImV4cCI6M
TcwMjYzNjIxNywibmJmIjoxNzAyNjI5MDE3LCJzdWIiOiJpbTp3aXJlYXBwPWxKR
1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJlLmNvbSIsI
mp0aSI6IjFmYzg0NTJlLWZjZWUtNGU1My05NzZkLTJjMjY5MTQwZDQ3ZSIsIm5vb
mNlIjoiUzNWamJUVnRTVVp4Ym5CaFNFd3hXblZTZWs5Q1VqSTNkVXAzV1VkUGRrW
SIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjIxODAvY2xpZ
W50cy9jMWQ0NTE5Y2U1ODBhNDc1L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJ6UVVKV
2hic0RNSlJhM0RxT1R4OGtxYzJCZDlqM0c5VyIsImhhbmRsZSI6ImltOndpcmVhc
HA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.j2hmMofmX
SU3zgcxmPHz5m0lgD4weg55qE0qsLyWqqtxS2qRnUbJm_6rjDrrNZpKHMUKmpcWA
mZx-wVUTmxODQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "LcwujTKCsfPe-7Z0tP4cY_yJYE-sxw13pp4HsF-E9RU"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "zQUJWhbsDMJRa3DqOTx8kqc2Bd9j3G9W",
  "exp": 1702636217,
  "handle": "im:wireapp=%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:22180/clients/c1d4519ce580a475/access-token",
  "iat": 1702629017,
  "jti": "1fc8452e-fcee-4e53-976d-2c269140d47e",
  "nbf": 1702629017,
  "nonce": "S3VjbTVtSUZxbnBhSEwxWnVSek9CUjI3dUp3WUdPdkY",
  "sub": "im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINk0lbQAp+mBCL4dduRdemqLP2+h62+How2zYQ/rq+PO
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEALcwujTKCsfPe+7Z0tP4cY/yJYE+sxw13pp4HsF+E9RU=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:22180/clients/c1d4519ce580a475/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVEdOM2RXcFVTME56WmxCbExUZGFNSFJRTkdOWlgzbEtXVVV0YzNoM01UTndjRFJJYzBZdFJUbFNWU0o5ZlEuZXlKcFlYUWlPakUzTURJMk1qa3dNVGNzSW1WNGNDSTZNVGN3TWpZek5qSXhOeXdpYm1KbUlqb3hOekF5TmpJNU1ERTNMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQV3hLUjFsUWVqQmFVbkV5YTNaalgxaHdaR0ZFYkVFdll6RmtORFV4T1dObE5UZ3dZVFEzTlVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpGbVl6ZzBOVEpsTFdaalpXVXROR1UxTXkwNU56WmtMVEpqTWpZNU1UUXdaRFEzWlNJc0ltNXZibU5sSWpvaVV6TldhbUpVVm5SVFZWcDRZbTVDYUZORmQzaFhibFpUWldzNVExVnFTVE5rVlhBelYxVmtVR1JyV1NJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qSXhPREF2WTJ4cFpXNTBjeTlqTVdRME5URTVZMlUxT0RCaE5EYzFMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lKNlVWVktWMmhpYzBSTlNsSmhNMFJ4VDFSNE9HdHhZekpDWkRscU0wYzVWeUlzSW1oaGJtUnNaU0k2SW1sdE9uZHBjbVZoY0hBOUpUUXdZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW5SbFlXMGlPaUozYVhKbEluMC5qMmhtTW9mbVhTVTN6Z2N4bVBIejVtMGxnRDR3ZWc1NXFFMHFzTHlXcXF0eFMycVJuVWJKbV82cmpEcnJOWnBLSE1VS21wY1dBbVp4LXdWVVRteE9EUQ
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjNJYzBoM1hUbnVkN3pKYnhrdS00Yk5GTktXOFAtNnYxZHB4czdQLVEzMkkifX0.eyJpYXQiOjE3MDI2MjkwMTcsImV4cCI6MTcwMjYzMjk3NywibmJmIjoxNzAyNjI5MDE3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjIxODAvY2xpZW50cy9jMWQ0NTE5Y2U1ODBhNDc1L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9bEpHWVB6MFpScTJrdmNfWHBkYURsQS9jMWQ0NTE5Y2U1ODBhNDc1QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIyMTgwL2NsaWVudHMvYzFkNDUxOWNlNTgwYTQ3NS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhYTk5ZmUyYy03MTA5LTQ0MzAtYTNmZS0xNGUyNTZjZTk3ZDgiLCJub25jZSI6IlMzVmpiVFZ0U1VaeGJuQmhTRXd4V25WU2VrOUNVakkzZFVwM1dVZFBka1kiLCJjaGFsIjoielFVSldoYnNETUpSYTNEcU9UeDhrcWMyQmQ5ajNHOVciLCJjbmYiOnsia2lkIjoibi0tM2RMV3kxSElZaVZLakFOb2ZKMzREZkItQUZBWlhGdjRCSE5XeVJMdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVRHTjNkV3BVUzBOelpsQmxMVGRhTUhSUU5HTlpYM2xLV1VVdGMzaDNNVE53Y0RSSWMwWXRSVGxTVlNKOWZRLmV5SnBZWFFpT2pFM01ESTJNamt3TVRjc0ltVjRjQ0k2TVRjd01qWXpOakl4Tnl3aWJtSm1Jam94TnpBeU5qSTVNREUzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFd4S1IxbFFlakJhVW5FeWEzWmpYMWh3WkdGRWJFRXZZekZrTkRVeE9XTmxOVGd3WVRRM05VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqRm1ZemcwTlRKbExXWmpaV1V0TkdVMU15MDVOelprTFRKak1qWTVNVFF3WkRRM1pTSXNJbTV2Ym1ObElqb2lVek5XYW1KVVZuUlRWVnA0WW01Q2FGTkZkM2hYYmxaVFpXczVRMVZxU1ROa1ZYQXpWMVZrVUdScldTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakl4T0RBdlkyeHBaVzUwY3k5ak1XUTBOVEU1WTJVMU9EQmhORGMxTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjZVVlZLVjJoaWMwUk5TbEpoTTBSeFQxUjRPR3R4WXpKQ1pEbHFNMGM1VnlJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuajJobU1vZm1YU1UzemdjeG1QSHo1bTBsZ0Q0d2VnNTVxRTBxc0x5V3FxdHhTMnFSblViSm1fNnJqRHJyTlpwS0hNVUttcGNXQW1aeC13VlVUbXhPRFEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPWxKR1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.3CByWjRst89kbGfizm96-szFf5cXBLRtkOdC046Ue4c_dLX-sRfSrYVbjax2aUDdJSOnH8E-Kcj8S_wZhQj3CA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjNJYzBoM1hUbnVkN3pKYnhrdS00Yk5GTktXOFAtNnYxZHB4czdQLVEzMkkifX0.eyJpYXQiOjE3MDI2MjkwMTcsImV4cCI6MTcwMjYzMjk3NywibmJmIjoxNzAyNjI5MDE3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjIxODAvY2xpZW50cy9jMWQ0NTE5Y2U1ODBhNDc1L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9bEpHWVB6MFpScTJrdmNfWHBkYURsQS9jMWQ0NTE5Y2U1ODBhNDc1QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIyMTgwL2NsaWVudHMvYzFkNDUxOWNlNTgwYTQ3NS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhYTk5ZmUyYy03MTA5LTQ0MzAtYTNmZS0xNGUyNTZjZTk3ZDgiLCJub25jZSI6IlMzVmpiVFZ0U1VaeGJuQmhTRXd4V25WU2VrOUNVakkzZFVwM1dVZFBka1kiLCJjaGFsIjoielFVSldoYnNETUpSYTNEcU9UeDhrcWMyQmQ5ajNHOVciLCJjbmYiOnsia2lkIjoibi0tM2RMV3kxSElZaVZLakFOb2ZKMzREZkItQUZBWlhGdjRCSE5XeVJMdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVRHTjNkV3BVUzBOelpsQmxMVGRhTUhSUU5HTlpYM2xLV1VVdGMzaDNNVE53Y0RSSWMwWXRSVGxTVlNKOWZRLmV5SnBZWFFpT2pFM01ESTJNamt3TVRjc0ltVjRjQ0k2TVRjd01qWXpOakl4Tnl3aWJtSm1Jam94TnpBeU5qSTVNREUzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFd4S1IxbFFlakJhVW5FeWEzWmpYMWh3WkdGRWJFRXZZekZrTkRVeE9XTmxOVGd3WVRRM05VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqRm1ZemcwTlRKbExXWmpaV1V0TkdVMU15MDVOelprTFRKak1qWTVNVFF3WkRRM1pTSXNJbTV2Ym1ObElqb2lVek5XYW1KVVZuUlRWVnA0WW01Q2FGTkZkM2hYYmxaVFpXczVRMVZxU1ROa1ZYQXpWMVZrVUdScldTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakl4T0RBdlkyeHBaVzUwY3k5ak1XUTBOVEU1WTJVMU9EQmhORGMxTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjZVVlZLVjJoaWMwUk5TbEpoTTBSeFQxUjRPR3R4WXpKQ1pEbHFNMGM1VnlJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuajJobU1vZm1YU1UzemdjeG1QSHo1bTBsZ0Q0d2VnNTVxRTBxc0x5V3FxdHhTMnFSblViSm1fNnJqRHJyTlpwS0hNVUttcGNXQW1aeC13VlVUbXhPRFEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPWxKR1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.3CByWjRst89kbGfizm96-szFf5cXBLRtkOdC046Ue4c_dLX-sRfSrYVbjax2aUDdJSOnH8E-Kcj8S_wZhQj3CA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IjNJYzBoM1hUbnVkN3pKYnhrdS00Yk5GTktX
OFAtNnYxZHB4czdQLVEzMkkifX0.eyJpYXQiOjE3MDI2MjkwMTcsImV4cCI6MTcw
MjYzMjk3NywibmJmIjoxNzAyNjI5MDE3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjIxODAvY2xpZW50cy9jMWQ0NTE5Y2U1ODBhNDc1L2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9bEpHWVB6MFpScTJrdmNfWHBkYURsQS9jMWQ0NTE5Y2U1
ODBhNDc1QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIyMTgwL2Ns
aWVudHMvYzFkNDUxOWNlNTgwYTQ3NS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhYTk5
ZmUyYy03MTA5LTQ0MzAtYTNmZS0xNGUyNTZjZTk3ZDgiLCJub25jZSI6IlMzVmpi
VFZ0U1VaeGJuQmhTRXd4V25WU2VrOUNVakkzZFVwM1dVZFBka1kiLCJjaGFsIjoi
elFVSldoYnNETUpSYTNEcU9UeDhrcWMyQmQ5ajNHOVciLCJjbmYiOnsia2lkIjoi
bi0tM2RMV3kxSElZaVZLakFOb2ZKMzREZkItQUZBWlhGdjRCSE5XeVJMdyJ9LCJw
cm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJ
aXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lM
Q0o0SWpvaVRHTjNkV3BVUzBOelpsQmxMVGRhTUhSUU5HTlpYM2xLV1VVdGMzaDNN
VE53Y0RSSWMwWXRSVGxTVlNKOWZRLmV5SnBZWFFpT2pFM01ESTJNamt3TVRjc0lt
VjRjQ0k2TVRjd01qWXpOakl4Tnl3aWJtSm1Jam94TnpBeU5qSTVNREUzTENKemRX
SWlPaUpwYlRwM2FYSmxZWEJ3UFd4S1IxbFFlakJhVW5FeWEzWmpYMWh3WkdGRWJF
RXZZekZrTkRVeE9XTmxOVGd3WVRRM05VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklq
Rm1ZemcwTlRKbExXWmpaV1V0TkdVMU15MDVOelprTFRKak1qWTVNVFF3WkRRM1pT
SXNJbTV2Ym1ObElqb2lVek5XYW1KVVZuUlRWVnA0WW01Q2FGTkZkM2hYYmxaVFpX
czVRMVZxU1ROa1ZYQXpWMVZrVUdScldTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RI
VWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakl4T0RBdlkyeHBaVzUwY3k5ak1X
UTBOVEU1WTJVMU9EQmhORGMxTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9p
SjZVVlZLVjJoaWMwUk5TbEpoTTBSeFQxUjRPR3R4WXpKQ1pEbHFNMGM1VnlJc0lt
aGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FY
SmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuajJobU1vZm1YU1UzemdjeG1Q
SHo1bTBsZ0Q0d2VnNTVxRTBxc0x5V3FxdHhTMnFSblViSm1fNnJqRHJyTlpwS0hN
VUttcGNXQW1aeC13VlVUbXhPRFEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPWxK
R1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJlLmNvbSIs
ImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.3CByWjRs
t89kbGfizm96-szFf5cXBLRtkOdC046Ue4c_dLX-sRfSrYVbjax2aUDdJSOnH8E-
Kcj8S_wZhQj3CA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "3Ic0h3XTnud7zJbxku-4bNFNKW8P-6v1dpxs7P-Q32I"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:22180/clients/c1d4519ce580a475/access-token",
  "chal": "zQUJWhbsDMJRa3DqOTx8kqc2Bd9j3G9W",
  "client_id": "im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com",
  "cnf": {
    "kid": "n--3dLWy1HIYiVKjANofJ34DfB-AFAZXFv4BHNWyRLw"
  },
  "exp": 1702632977,
  "iat": 1702629017,
  "iss": "http://wire.com:22180/clients/c1d4519ce580a475/access-token",
  "jti": "aa99fe2c-7109-4430-a3fe-14e256ce97d8",
  "nbf": 1702629017,
  "nonce": "S3VjbTVtSUZxbnBhSEwxWnVSek9CUjI3dUp3WUdPdkY",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiTGN3dWpUS0NzZlBlLTdaMHRQNGNZX3lKWUUtc3h3MTNwcDRIc0YtRTlSVSJ9fQ.eyJpYXQiOjE3MDI2MjkwMTcsImV4cCI6MTcwMjYzNjIxNywibmJmIjoxNzAyNjI5MDE3LCJzdWIiOiJpbTp3aXJlYXBwPWxKR1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJlLmNvbSIsImp0aSI6IjFmYzg0NTJlLWZjZWUtNGU1My05NzZkLTJjMjY5MTQwZDQ3ZSIsIm5vbmNlIjoiUzNWamJUVnRTVVp4Ym5CaFNFd3hXblZTZWs5Q1VqSTNkVXAzV1VkUGRrWSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjIxODAvY2xpZW50cy9jMWQ0NTE5Y2U1ODBhNDc1L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJ6UVVKV2hic0RNSlJhM0RxT1R4OGtxYzJCZDlqM0c5VyIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.j2hmMofmXSU3zgcxmPHz5m0lgD4weg55qE0qsLyWqqtxS2qRnUbJm_6rjDrrNZpKHMUKmpcWAmZx-wVUTmxODQ",
  "scope": "wire_client_id",
  "sub": "im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBafpBF92P0wtEsex0ulbh3VHZZbovWWVjIJ73kyYqih
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA3Ic0h3XTnud7zJbxku+4bNFNKW8P+6v1dpxs7P+Q32I=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/v7OXTTRPg7xn2k1EM8ZItqp7uXnamLeu
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L1JDMUFXVkEzVXpGN2RIUURhRUliUDJQMnRNQ09senhHIiwidHlwIjoiSldUIiwibm9uY2UiOiJjVk55U2podldWcEpOSEJ6UkVGbE5tTnJOa05yYlVGVFFVMUJjSFpoVVdzIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL2NoYWxsZW5nZS81aFFJcFVqS0QwUjd5Qm9hazBvRXFJZzNSTDJwTENwMS92N09YVFRSUGc3eG4yazFFTThaSXRxcDd1WG5hbUxldSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklqTkpZekJvTTFoVWJuVmtOM3BLWW5ocmRTMDBZazVHVGt0WE9GQXRObll4WkhCNGN6ZFFMVkV6TWtraWZYMC5leUpwWVhRaU9qRTNNREkyTWprd01UY3NJbVY0Y0NJNk1UY3dNall6TWprM055d2libUptSWpveE56QXlOakk1TURFM0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJeE9EQXZZMnhwWlc1MGN5OWpNV1EwTlRFNVkyVTFPREJoTkRjMUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5YkVwSFdWQjZNRnBTY1RKcmRtTmZXSEJrWVVSc1FTOWpNV1EwTlRFNVkyVTFPREJoTkRjMVFIZHBjbVV1WTI5dElpd2lZWFZrSWpvaWFIUjBjRG92TDNkcGNtVXVZMjl0T2pJeU1UZ3dMMk5zYVdWdWRITXZZekZrTkRVeE9XTmxOVGd3WVRRM05TOWhZMk5sYzNNdGRHOXJaVzRpTENKcWRHa2lPaUpoWVRrNVptVXlZeTAzTVRBNUxUUTBNekF0WVRObVpTMHhOR1V5TlRaalpUazNaRGdpTENKdWIyNWpaU0k2SWxNelZtcGlWRlowVTFWYWVHSnVRbWhUUlhkNFYyNVdVMlZyT1VOVmFra3paRlZ3TTFkVlpGQmthMWtpTENKamFHRnNJam9pZWxGVlNsZG9Zbk5FVFVwU1lUTkVjVTlVZURocmNXTXlRbVE1YWpOSE9WY2lMQ0pqYm1ZaU9uc2lhMmxrSWpvaWJpMHRNMlJNVjNreFNFbFphVlpMYWtGT2IyWktNelJFWmtJdFFVWkJXbGhHZGpSQ1NFNVhlVkpNZHlKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVZSSFRqTmtWM0JWVXpCT2VscHNRbXhNVkdSaFRVaFNVVTVIVGxwWU0yeExWMVZWZEdNemFETk5WRTUzWTBSU1NXTXdXWFJTVkd4VFZsTktPV1pSTG1WNVNuQlpXRkZwVDJwRk0wMUVTVEpOYW10M1RWUmpjMGx0VmpSalEwazJUVlJqZDAxcVdYcE9ha2w0VG5sM2FXSnRTbTFKYW05NFRucEJlVTVxU1RWTlJFVXpURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGZDRTMUl4YkZGbGFrSmhWVzVGZVdFeldtcFlNV2gzV2tkR1JXSkZSWFpaZWtaclRrUlZlRTlYVG14T1ZHZDNXVlJSTTA1VlFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2xxUm0xWmVtY3dUbFJLYkV4WFdtcGFWMVYwVGtkVk1VMTVNRFZPZWxwclRGUkthazFxV1RWTlZGRjNXa1JSTTFwVFNYTkpiVFYyWW0xT2JFbHFiMmxWZWs1WFlXMUtWVlp1VWxSV1ZuQTBXVzAxUTJGR1RrWmtNMmhZWW14YVZGcFhjelZSTVZaeFUxUk9hMVpZUVhwV01WWnJWVWRTY2xkVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWtsNFQwUkJkbGt5ZUhCYVZ6VXdZM2s1YWsxWFVUQk9WRVUxV1RKVk1VOUVRbWhPUkdNeFRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTalpWVmxaTFZqSm9hV013VWs1VGJFcG9UVEJTZUZReFVqUlBSM1I0V1hwS1ExcEViSEZOTUdNMVZubEpjMGx0YUdoaWJWSnpXbE5KTmtsdGJIUlBibVJ3WTIxV2FHTklRVGxLVkZGM1dWZDRjRmt5Vm1aa01teDVXbFZDTTJGWVNteE1iVTUyWWxOSmMwbHVVbXhaVnpCcFQybEtNMkZZU214SmJqQXVhakpvYlUxdlptMVlVMVV6ZW1kamVHMVFTSG8xYlRCc1owUTBkMlZuTlRWeFJUQnhjMHg1VjNGeGRIaFRNbkZTYmxWaVNtMWZObkpxUkhKeVRscHdTMGhOVlV0dGNHTlhRVzFhZUMxM1ZsVlViWGhQUkZFaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFd4S1IxbFFlakJhVW5FeWEzWmpYMWh3WkdGRWJFRXZZekZrTkRVeE9XTmxOVGd3WVRRM05VQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvMUxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLjNDQnlXalJzdDg5a2JHZml6bTk2LXN6RmY1Y1hCTFJ0a09kQzA0NlVlNGNfZExYLXNSZlNyWVZiamF4MmFVRGRKU09uSDhFLUtjajhTX3daaFFqM0NBIn0",
  "signature": "cDiASpQMUwYRyqZyp0AqG1Rh-qkav1vFDVc5O7t2yOu1GwvBPrOICLACnGKn6cY58MGBungfz6e1T-1Rp9bCCw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjNJYzBoM1hUbnVkN3pKYnhrdS00Yk5GTktXOFAtNnYxZHB4czdQLVEzMkkifX0.eyJpYXQiOjE3MDI2MjkwMTcsImV4cCI6MTcwMjYzMjk3NywibmJmIjoxNzAyNjI5MDE3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjIxODAvY2xpZW50cy9jMWQ0NTE5Y2U1ODBhNDc1L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9bEpHWVB6MFpScTJrdmNfWHBkYURsQS9jMWQ0NTE5Y2U1ODBhNDc1QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIyMTgwL2NsaWVudHMvYzFkNDUxOWNlNTgwYTQ3NS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhYTk5ZmUyYy03MTA5LTQ0MzAtYTNmZS0xNGUyNTZjZTk3ZDgiLCJub25jZSI6IlMzVmpiVFZ0U1VaeGJuQmhTRXd4V25WU2VrOUNVakkzZFVwM1dVZFBka1kiLCJjaGFsIjoielFVSldoYnNETUpSYTNEcU9UeDhrcWMyQmQ5ajNHOVciLCJjbmYiOnsia2lkIjoibi0tM2RMV3kxSElZaVZLakFOb2ZKMzREZkItQUZBWlhGdjRCSE5XeVJMdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVRHTjNkV3BVUzBOelpsQmxMVGRhTUhSUU5HTlpYM2xLV1VVdGMzaDNNVE53Y0RSSWMwWXRSVGxTVlNKOWZRLmV5SnBZWFFpT2pFM01ESTJNamt3TVRjc0ltVjRjQ0k2TVRjd01qWXpOakl4Tnl3aWJtSm1Jam94TnpBeU5qSTVNREUzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFd4S1IxbFFlakJhVW5FeWEzWmpYMWh3WkdGRWJFRXZZekZrTkRVeE9XTmxOVGd3WVRRM05VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqRm1ZemcwTlRKbExXWmpaV1V0TkdVMU15MDVOelprTFRKak1qWTVNVFF3WkRRM1pTSXNJbTV2Ym1ObElqb2lVek5XYW1KVVZuUlRWVnA0WW01Q2FGTkZkM2hYYmxaVFpXczVRMVZxU1ROa1ZYQXpWMVZrVUdScldTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakl4T0RBdlkyeHBaVzUwY3k5ak1XUTBOVEU1WTJVMU9EQmhORGMxTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjZVVlZLVjJoaWMwUk5TbEpoTTBSeFQxUjRPR3R4WXpKQ1pEbHFNMGM1VnlJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuajJobU1vZm1YU1UzemdjeG1QSHo1bTBsZ0Q0d2VnNTVxRTBxc0x5V3FxdHhTMnFSblViSm1fNnJqRHJyTlpwS0hNVUttcGNXQW1aeC13VlVUbXhPRFEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPWxKR1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.3CByWjRst89kbGfizm96-szFf5cXBLRtkOdC046Ue4c_dLX-sRfSrYVbjax2aUDdJSOnH8E-Kcj8S_wZhQj3CA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/RC1AWVA3UzF7dHQDaEIbP2P2tMCOlzxG",
    "nonce": "cVNySjhvWVpJNHBzREFlNmNrNkNrbUFTQU1BcHZhUWs",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/v7OXTTRPg7xn2k1EM8ZItqp7uXnamLeu"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
link: <https://stepca:32787/acme/wire/authz/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1>;rel="up"
location: https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/v7OXTTRPg7xn2k1EM8ZItqp7uXnamLeu
replay-nonce: WElLR21wY1U2ZmZnckJkUFI2VGJmeTVCeWdnQndjb3Q
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/v7OXTTRPg7xn2k1EM8ZItqp7uXnamLeu",
  "status": "valid",
  "token": "zQUJWhbsDMJRa3DqOTx8kqc2Bd9j3G9W",
  "target": "http://wire.com:22180/clients/c1d4519ce580a475/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=0Wln2t3bQSMQBmbNKoMNUhpISSRSXo5DedWG7Gf5mXc&code_challenge=abLPowNrfxkOQQVXjUq4hekH-n3OMj_l0AyvTs4VkTc
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:22890/dex/auth?response_type=code&client_id=wireapp&state=GJFQ49deILGu8k-CUw6Qmg&code_challenge=abLPowNrfxkOQQVXjUq4hekH-n3OMj_l0AyvTs4VkTc&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A22180%2Fcallback&scope=openid+profile&nonce=HMxiX-k_uOKN3cIK3vrgaw
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:22890/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpiRk5tVlZZemNYRlhWSE5LVTJReFUxcFhXVUppVlhONQ==
```
```text
grant_type=authorization_code&code=uc22cd6ghfe77wfre3i5dz2xm&code_verifier=0Wln2t3bQSMQBmbNKoMNUhpISSRSXo5DedWG7Gf5mXc&redirect_uri=http%3A%2F%2Fwire.com%3A22180%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjM5M2JiNGQxZDEyZWVmMzRjZDZlMTlhYzc3MDhiNDljMWViMmNmZTcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyODkwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQV3hLUjFsUWVqQmFVbkV5YTNaalgxaHdaR0ZFYkVFdll6RmtORFV4T1dObE5UZ3dZVFEzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDI3MTkwMTcsImlhdCI6MTcwMjYzMjYxNywibm9uY2UiOiJITXhpWC1rX3VPS04zY0lLM3ZyZ2F3IiwiYXRfaGFzaCI6IkNfa25wUUxXcFlSbXNGSDdXU2x4NFEiLCJuYW1lIjoiaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.UzeabI6hZO00uAlT8eKmc1IKdf3j6p0yr7Oh9nMwbrOdTDB6sDYW4kC4b7gO29l_WOKpIjjJvKgX6RTUZpjnqCoWI-mnuBUN0hhMLjJO9TjRwAuP56vXt3lGRcvsqFGPFZyCN9SHW5uXzZJVKIh5yKVjne82NOHR2UauKqxf0_Ew8ZLeUtydpLnTy-T95OsjFBk63Jh9mAuIcAavoA-jwTaG09TvwiWu_m5GLQxhUbefUxnZdAavSRJLlgicAwR8s8jKX5jN28-iWEHcxP41CRdHMTPDG8I0iovtBQ_uH7ROf2ybHJdW4lRbC2M56rLok4WNe6hsrh9zsKk60Qm4-w",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjM5M2JiNGQxZDEyZWVmMzRjZDZlMTlhYzc3MDhiNDljMWViMmNmZTcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyODkwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQV3hLUjFsUWVqQmFVbkV5YTNaalgxaHdaR0ZFYkVFdll6RmtORFV4T1dObE5UZ3dZVFEzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDI3MTkwMTcsImlhdCI6MTcwMjYzMjYxNywibm9uY2UiOiJITXhpWC1rX3VPS04zY0lLM3ZyZ2F3IiwiYXRfaGFzaCI6IlNCMXFEQS0zdHJuQS1KWTlnSVZFU1EiLCJjX2hhc2giOiJUSlNOQkNTNzRzY05mUnp2cHRWMEtRIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.WR4X7zAvJfSlHiI83YyaxKQGtpSe-qlP6cJk2F8Zvdr_7npdyXM3duluN0cD7rfR3agOeizKHhQ91XzJ85nHqBE2j64Be61qrvMEFP_nmRULg41JAo1jwSMUZKDOdVwgZMxcKMaD4Eq700k_LFdEIoa52okjMCXbFzoUjlSHSu98NaB2FDec1dGQc8plSmRSx7jvvUEdFAInraa8uclYscprgIu0Z5wop22ik-qDfzSVkHoxqMww3mZV9teo8n1H2T_3QkWf4TWgfSbdDUzqCKTOLO198v9ZRXBq1JNriJokH27Sdtq4BCK1dTQtJPC9lIqApZL6WIfdt2IJD9_Fxw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjM5M2JiNGQxZDEyZWVmMzRjZDZlMTlhYzc3MDhiNDljMWViMmNmZTcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyODkwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQV3hLUjFsUWVqQmFVbkV5YTNaalgxaHdaR0ZFYkVFdll6RmtORFV4T1dObE5UZ3dZVFEzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDI3MTkwMTcsImlhdCI6MTcwMjYzMjYxNywibm9uY2UiOiJITXhpWC1rX3VPS04zY0lLM3ZyZ2F3IiwiYXRfaGFzaCI6IlNCMXFEQS0zdHJuQS1KWTlnSVZFU1EiLCJjX2hhc2giOiJUSlNOQkNTNzRzY05mUnp2cHRWMEtRIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.WR4X7zAvJfSlHiI83YyaxKQGtpSe-qlP6cJk2F8Zvdr_7npdyXM3duluN0cD7rfR3agOeizKHhQ91XzJ85nHqBE2j64Be61qrvMEFP_nmRULg41JAo1jwSMUZKDOdVwgZMxcKMaD4Eq700k_LFdEIoa52okjMCXbFzoUjlSHSu98NaB2FDec1dGQc8plSmRSx7jvvUEdFAInraa8uclYscprgIu0Z5wop22ik-qDfzSVkHoxqMww3mZV9teo8n1H2T_3QkWf4TWgfSbdDUzqCKTOLO198v9ZRXBq1JNriJokH27Sdtq4BCK1dTQtJPC9lIqApZL6WIfdt2IJD9_Fxw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjM5M2JiNGQxZDEyZWVmMzRjZDZlMTlhYzc3MDhiNDljMWViMmNmZTcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyODkwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQV3hLUjFsUWVqQmFVbkV5YTNaalgxaHdaR0ZFYkVFdll6RmtORFV4T1dObE5UZ3dZVFEzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDI3MTkwMTcsImlhdCI6MTcwMjYzMjYxNywibm9uY2UiOiJITXhpWC1rX3VPS04zY0lLM3ZyZ2F3IiwiYXRfaGFzaCI6IlNCMXFEQS0zdHJuQS1KWTlnSVZFU1EiLCJjX2hhc2giOiJUSlNOQkNTNzRzY05mUnp2cHRWMEtRIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.WR4X7zAvJfSlHiI83YyaxKQGtpSe-qlP6cJk2F8Zvdr_7npdyXM3duluN0cD7rfR3agOeizKHhQ91XzJ85nHqBE2j64Be61qrvMEFP_nmRULg41JAo1jwSMUZKDOdVwgZMxcKMaD4Eq700k_LFdEIoa52okjMCXbFzoUjlSHSu98NaB2FDec1dGQc8plSmRSx7jvvUEdFAInraa8uclYscprgIu0Z5wop22ik-qDfzSVkHoxqMww3mZV9teo8n1H2T_3QkWf4TWgfSbdDUzqCKTOLO198v9ZRXBq1JNriJokH27Sdtq4BCK1dTQtJPC9lIqApZL6WIfdt2IJD9_Fxw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjM5M2JiNGQxZDEyZWVmMzRjZDZlMTlhYzc3
MDhiNDljMWViMmNmZTcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyODkwL2RleCIsI
nN1YiI6IkNqdHBiVHAzYVhKbFlYQndQV3hLUjFsUWVqQmFVbkV5YTNaalgxaHdaR
0ZFYkVFdll6RmtORFV4T1dObE5UZ3dZVFEzTlVCM2FYSmxMbU52YlJJRWJHUmhjQ
SIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDI3MTkwMTcsImlhdCI6MTcwMjYzM
jYxNywibm9uY2UiOiJITXhpWC1rX3VPS04zY0lLM3ZyZ2F3IiwiYXRfaGFzaCI6I
lNCMXFEQS0zdHJuQS1KWTlnSVZFU1EiLCJjX2hhc2giOiJUSlNOQkNTNzRzY05mU
np2cHRWMEtRIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlL
mNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.WR4X7zAvJ
fSlHiI83YyaxKQGtpSe-qlP6cJk2F8Zvdr_7npdyXM3duluN0cD7rfR3agOeizKH
hQ91XzJ85nHqBE2j64Be61qrvMEFP_nmRULg41JAo1jwSMUZKDOdVwgZMxcKMaD4
Eq700k_LFdEIoa52okjMCXbFzoUjlSHSu98NaB2FDec1dGQc8plSmRSx7jvvUEdF
AInraa8uclYscprgIu0Z5wop22ik-qDfzSVkHoxqMww3mZV9teo8n1H2T_3QkWf4
TWgfSbdDUzqCKTOLO198v9ZRXBq1JNriJokH27Sdtq4BCK1dTQtJPC9lIqApZL6W
Ifdt2IJD9_Fxw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "393bb4d1d12eef34cd6e19ac7708b49c1eb2cfe7"
}
```

```json
{
  "at_hash": "SB1qDA-3trnA-JY9gIVESQ",
  "aud": "wireapp",
  "c_hash": "TJSNBCS74scNfRzvptV0KQ",
  "exp": 1702719017,
  "iat": 1702632617,
  "iss": "http://dex:22890/dex",
  "name": "im:wireapp=%40alice_wire@wire.com",
  "nonce": "HMxiX-k_uOKN3cIK3vrgaw",
  "preferred_username": "Alice Smith",
  "sub": "CjtpbTp3aXJlYXBwPWxKR1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzsLdh8sHWZ4hjt1txmZ7
SMgxYcmPqnzMKhAdXHhyMa5MfVduBXo9rtnAphXoxdtqOM7qW0bb5qTv1tmOjMsM
/Uz7BGk/co+xNoS2hG1B7xPjbxdBqz9U3YKye1mIidRyROjS037p1GNBvMwGxszF
iD2X63QwtBouTjPsz4vvSboB9Y2BGmjUDMNYu1JGJlBYDvZDCmpkovld7Woy/bWq
rySfGJ7RONXPQNvwGndQEqisIwSndGXBRUbEHHj5Gt7aJSmSJEErLnw68z7TbEc1
bpYDrSKMg0QB4WWrP+C95kRnYloia78s4m/tvOr3uwMOmqX/gcIWEubUXh3e0Nka
UwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/J04SdUogmGSif7EBdFiJKR5zof7Pwamz
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L1JDMUFXVkEzVXpGN2RIUURhRUliUDJQMnRNQ09senhHIiwidHlwIjoiSldUIiwibm9uY2UiOiJXRWxMUjIxd1kxVTJabVpuY2tKa1VGSTJWR0ptZVRWQ2VXZG5RbmRqYjNRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL2NoYWxsZW5nZS81aFFJcFVqS0QwUjd5Qm9hazBvRXFJZzNSTDJwTENwMS9KMDRTZFVvZ21HU2lmN0VCZEZpSktSNXpvZjdQd2FteiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJak01TTJKaU5HUXhaREV5WldWbU16UmpaRFpsTVRsaFl6YzNNRGhpTkRsak1XVmlNbU5tWlRjaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSXlPRGt3TDJSbGVDSXNJbk4xWWlJNklrTnFkSEJpVkhBellWaEtiRmxZUW5kUVYzaExVakZzVVdWcVFtRlZia1Y1WVROYWFsZ3hhSGRhUjBaRllrVkZkbGw2Um10T1JGVjRUMWRPYkU1VVozZFpWRkV6VGxWQ00yRllTbXhNYlU1MllsSkpSV0pIVW1oalFTSXNJbUYxWkNJNkluZHBjbVZoY0hBaUxDSmxlSEFpT2pFM01ESTNNVGt3TVRjc0ltbGhkQ0k2TVRjd01qWXpNall4Tnl3aWJtOXVZMlVpT2lKSVRYaHBXQzFyWDNWUFMwNHpZMGxMTTNaeVoyRjNJaXdpWVhSZmFHRnphQ0k2SWxOQ01YRkVRUzB6ZEhKdVFTMUtXVGxuU1ZaRlUxRWlMQ0pqWDJoaGMyZ2lPaUpVU2xOT1FrTlROelJ6WTA1bVVucDJjSFJXTUV0Uklpd2libUZ0WlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJa0ZzYVdObElGTnRhWFJvSW4wLldSNFg3ekF2SmZTbEhpSTgzWXlheEtRR3RwU2UtcWxQNmNKazJGOFp2ZHJfN25wZHlYTTNkdWx1TjBjRDdyZlIzYWdPZWl6S0hoUTkxWHpKODVuSHFCRTJqNjRCZTYxcXJ2TUVGUF9ubVJVTGc0MUpBbzFqd1NNVVpLRE9kVndnWk14Y0tNYUQ0RXE3MDBrX0xGZEVJb2E1Mm9rak1DWGJGem9VamxTSFN1OThOYUIyRkRlYzFkR1FjOHBsU21SU3g3anZ2VUVkRkFJbnJhYTh1Y2xZc2NwcmdJdTBaNXdvcDIyaWstcURmelNWa0hveHFNd3czbVpWOXRlbzhuMUgyVF8zUWtXZjRUV2dmU2JkRFV6cUNLVE9MTzE5OHY5WlJYQnExSk5yaUpva0gyN1NkdHE0QkNLMWRUUXRKUEM5bElxQXBaTDZXSWZkdDJJSkQ5X0Z4dyIsImtleWF1dGgiOiJ6UVVKV2hic0RNSlJhM0RxT1R4OGtxYzJCZDlqM0c5Vy5uLS0zZExXeTFISVlpVktqQU5vZkozNERmQi1BRkFaWEZ2NEJITld5Ukx3In0",
  "signature": "mRO_JMk9TQAOictrdWzzAoMaOD-Et17TMKjYWVhPk9zP14U3wgCzkvBW2d8oQ8Hl_9qe6s6tQRmXggxP84YOBA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjM5M2JiNGQxZDEyZWVmMzRjZDZlMTlhYzc3MDhiNDljMWViMmNmZTcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyODkwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQV3hLUjFsUWVqQmFVbkV5YTNaalgxaHdaR0ZFYkVFdll6RmtORFV4T1dObE5UZ3dZVFEzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDI3MTkwMTcsImlhdCI6MTcwMjYzMjYxNywibm9uY2UiOiJITXhpWC1rX3VPS04zY0lLM3ZyZ2F3IiwiYXRfaGFzaCI6IlNCMXFEQS0zdHJuQS1KWTlnSVZFU1EiLCJjX2hhc2giOiJUSlNOQkNTNzRzY05mUnp2cHRWMEtRIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.WR4X7zAvJfSlHiI83YyaxKQGtpSe-qlP6cJk2F8Zvdr_7npdyXM3duluN0cD7rfR3agOeizKHhQ91XzJ85nHqBE2j64Be61qrvMEFP_nmRULg41JAo1jwSMUZKDOdVwgZMxcKMaD4Eq700k_LFdEIoa52okjMCXbFzoUjlSHSu98NaB2FDec1dGQc8plSmRSx7jvvUEdFAInraa8uclYscprgIu0Z5wop22ik-qDfzSVkHoxqMww3mZV9teo8n1H2T_3QkWf4TWgfSbdDUzqCKTOLO198v9ZRXBq1JNriJokH27Sdtq4BCK1dTQtJPC9lIqApZL6WIfdt2IJD9_Fxw",
    "keyauth": "zQUJWhbsDMJRa3DqOTx8kqc2Bd9j3G9W.n--3dLWy1HIYiVKjANofJ34DfB-AFAZXFv4BHNWyRLw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/RC1AWVA3UzF7dHQDaEIbP2P2tMCOlzxG",
    "nonce": "WElLR21wY1U2ZmZnckJkUFI2VGJmeTVCeWdnQndjb3Q",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/J04SdUogmGSif7EBdFiJKR5zof7Pwamz"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
link: <https://stepca:32787/acme/wire/authz/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1>;rel="up"
location: https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/J04SdUogmGSif7EBdFiJKR5zof7Pwamz
replay-nonce: MW1hYUM5ODNaM0dvT2JKdVU1Q2MzVm5CaTdYaUJOcDU
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32787/acme/wire/challenge/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1/J04SdUogmGSif7EBdFiJKR5zof7Pwamz",
  "status": "valid",
  "token": "zQUJWhbsDMJRa3DqOTx8kqc2Bd9j3G9W",
  "target": "http://dex:22890/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L1JDMUFXVkEzVXpGN2RIUURhRUliUDJQMnRNQ09senhHIiwidHlwIjoiSldUIiwibm9uY2UiOiJNVzFoWVVNNU9ETmFNMGR2VDJKS2RWVTFRMk16Vm01Q2FUZFlhVUpPY0RVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL29yZGVyL0lZdkpOaUpsUUFRNzg5U2dDUUZQSERsRWVaeHNmRnVjIn0",
  "payload": "",
  "signature": "FUhzOq594NFrVXmb5xl0CPnfNKqcQPG81-P1_3UVoA0MKFSDEaYuxC92GVpddvcNKLp1EKFGfl4SMfk1r7OgBA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/RC1AWVA3UzF7dHQDaEIbP2P2tMCOlzxG",
    "nonce": "MW1hYUM5ODNaM0dvT2JKdVU1Q2MzVm5CaTdYaUJOcDU",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
location: https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc
replay-nonce: WXE4YlhZSGhWNzR2bFVIaWk2eGdXTWFPRXZXamtnSHA
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32787/acme/wire/authz/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1"
  ],
  "expires": "2023-12-16T09:30:17Z",
  "notBefore": "2023-12-15T09:30:17.308456Z",
  "notAfter": "2033-12-12T09:30:17.308456Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L1JDMUFXVkEzVXpGN2RIUURhRUliUDJQMnRNQ09senhHIiwidHlwIjoiSldUIiwibm9uY2UiOiJXWEU0WWxoWlNHaFdOelIyYkZWSWFXazJlR2RYVFdGUFJYWlhhbXRuU0hBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL29yZGVyL0lZdkpOaUpsUUFRNzg5U2dDUUZQSERsRWVaeHNmRnVjL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTFRDQjRBSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBQzNNTG8weWdySHozdnUyZExULUhHUDhpV0JQck1jTmQ2YWVCN0JmaFBVVm9Id3dlZ1lKS29aSWh2Y05BUWtPTVcwd2F6QnBCZ05WSFJFRVlqQmdoanRwYlRwM2FYSmxZWEJ3UFd4S1IxbFFlakJhVW5FeWEzWmpYMWh3WkdGRWJFRXZZekZrTkRVeE9XTmxOVGd3WVRRM05VQjNhWEpsTG1OdmJZWWhhVzA2ZDJseVpXRndjRDBsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dE1BVUdBeXRsY0FOQkFCUWl4a0c3OHJ3TGtJYzRMd1docWJhbEJQR2tzQnJuQjB5S0VXamxqU1VPY3BTV2h5UFZ4a0ttbUNVX0xGZ0E0ZnEwOElfREkySlh1amZPT2ZMRnJ3USJ9",
  "signature": "XcVzpN9nnZvio8q30el5vAeOKxEhpX3AQ7_GkOa9HM8TQX9lx2V0GftKQg68dydX6UdHTtgpC-9uwu-OQ15EDg"
}
```
```json
{
  "payload": {
    "csr": "MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAC3MLo0ygrHz3vu2dLT-HGP8iWBPrMcNd6aeB7BfhPUVoHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJlYXBwPWxKR1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJlLmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANBABQixkG78rwLkIc4LwWhqbalBPGksBrnB0yKEWjljSUOcpSWhyPVxkKmmCU_LFgA4fq08I_DI2JXujfOOfLFrwQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/RC1AWVA3UzF7dHQDaEIbP2P2tMCOlzxG",
    "nonce": "WXE4YlhZSGhWNzR2bFVIaWk2eGdXTWFPRXZXamtnSHA",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAC3MLo0ygrHz3vu2dLT+HGP8iWBPrMcN
d6aeB7BfhPUVoHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJl
YXBwPWxKR1lQejBaUnEya3ZjX1hwZGFEbEEvYzFkNDUxOWNlNTgwYTQ3NUB3aXJl
LmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANB
ABQixkG78rwLkIc4LwWhqbalBPGksBrnB0yKEWjljSUOcpSWhyPVxkKmmCU/LFgA
4fq08I/DI2JXujfOOfLFrwQ=
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
                    2d:cc:2e:8d:32:82:b1:f3:de:fb:b6:74:b4:fe:1c:
                    63:fc:89:60:4f:ac:c7:0d:77:a6:9e:07:b0:5f:84:
                    f5:15
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com, URI:im:wireapp=%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        14:22:c6:41:bb:f2:bc:0b:90:87:38:2f:05:a1:a9:b6:a5:04:
        f1:a4:b0:1a:e7:07:4c:8a:11:68:e5:8d:25:0e:72:94:96:87:
        23:d5:c6:42:a6:98:25:3f:2c:58:00:e1:fa:b4:f0:8f:c3:23:
        62:57:ba:37:ce:39:f2:c5:af:04

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
location: https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc
replay-nonce: aThIdGJEcTJPQWRrRzhZMUNjb3RNMTVVM3FJRzl1Q3g
vary: Origin
```
```json
{
  "certificate": "https://stepca:32787/acme/wire/certificate/1N2SXSYR718thgwccKm7U7Ftqq6wb3NL",
  "status": "valid",
  "finalize": "https://stepca:32787/acme/wire/order/IYvJNiJlQAQ789SgCQFPHDlEeZxsfFuc/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32787/acme/wire/authz/5hQIpUjKD0R7yBoak0oEqIg3RL2pLCp1"
  ],
  "expires": "2023-12-16T09:30:17Z",
  "notBefore": "2023-12-15T09:30:17.308456Z",
  "notAfter": "2033-12-12T09:30:17.308456Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32787/acme/wire/certificate/1N2SXSYR718thgwccKm7U7Ftqq6wb3NL
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L1JDMUFXVkEzVXpGN2RIUURhRUliUDJQMnRNQ09senhHIiwidHlwIjoiSldUIiwibm9uY2UiOiJhVGhJZEdKRWNUSlBRV1JyUnpoWk1VTmpiM1JOTVRWVk0zRkpSemwxUTNnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL2NlcnRpZmljYXRlLzFOMlNYU1lSNzE4dGhnd2NjS203VTdGdHFxNndiM05MIn0",
  "payload": "",
  "signature": "GXIdtDKat9oDEyI5AHnNyPwqdyRJO35H6-f08BIlycS_UmxSfmeJqXPoE351rmop-YKh7dgVf2IrFlcUrOv_CA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/RC1AWVA3UzF7dHQDaEIbP2P2tMCOlzxG",
    "nonce": "aThIdGJEcTJPQWRrRzhZMUNjb3RNMTVVM3FJRzl1Q3g",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/certificate/1N2SXSYR718thgwccKm7U7Ftqq6wb3NL"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32787/acme/wire/directory>;rel="index"
replay-nonce: TGtFYzBWemVUbHRpVFdySG1vQXpreTRXbUtoSXczWWg
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAcCgAwIBAgIRAM1DwAWoR286t3UAPQ0mtq0wCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMxMjE1MDkzMDE3WhcNMzMxMjEyMDkzMDE3WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQAtzC6NMoKx8977tnS0\n/hxj/IlgT6zHDXemngewX4T1FaOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFPIRgXjbJELbdD77XaRISRfABGrfMB8G\nA1UdIwQYMBaAFKZzSQhYphnY5TMyuJqMTk4c/HGLMGkGA1UdEQRiMGCGIWltOndp\ncmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY7aW06d2lyZWFwcD1sSkdZUHow\nWlJxMmt2Y19YcGRhRGxBL2MxZDQ1MTljZTU4MGE0NzVAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIFBWBdrV\n8caghfirEwYpHLpSXaasrewTI1MOPe4+8KiRAiEAtzBT99YvAHzMIMFSosub0ViG\nbs5Gl+Ieyo1UGjJs9bE=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV6gAwIBAgIQW2eHq0Wg/Lsl4IoarCUrSjAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMjE1MDkz\nMDE1WhcNMzMxMjEyMDkzMDE1WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDN6\nyJG/lAsh3ykUkwMq25q1z9FV2E2fr5R6nnZt/UO1Z+QcUFZy/bn4N/gbi47lhAEQ\nGs8nMnbtldoRoE3zRWajZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBSmc0kIWKYZ2OUzMriajE5OHPxxizAfBgNVHSMEGDAW\ngBSJHuc7G3bNZ0FNwsoiQh/Rur0znjAKBggqhkjOPQQDAgNIADBFAiBnXwqpTYlN\nYXftDUSzaJ57O5CkhvgVIlKiFQJMN6984wIhAKG7ZDIqGIKL3PUcInFCb5drLyh9\nFB81M8ieOHb4tyGW\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ❌
```
-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRAM1DwAWoR286t3UAPQ0mtq0wCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMxMjE1MDkzMDE3WhcNMzMxMjEyMDkzMDE3WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQAtzC6NMoKx8977tnS0
/hxj/IlgT6zHDXemngewX4T1FaOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFPIRgXjbJELbdD77XaRISRfABGrfMB8G
A1UdIwQYMBaAFKZzSQhYphnY5TMyuJqMTk4c/HGLMGkGA1UdEQRiMGCGIWltOndp
cmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY7aW06d2lyZWFwcD1sSkdZUHow
WlJxMmt2Y19YcGRhRGxBL2MxZDQ1MTljZTU4MGE0NzVAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIFBWBdrV
8caghfirEwYpHLpSXaasrewTI1MOPe4+8KiRAiEAtzBT99YvAHzMIMFSosub0ViG
bs5Gl+Ieyo1UGjJs9bE=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            cd:43:c0:05:a8:47:6f:3a:b7:75:00:3d:0d:26:b6:ad
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Dec 15 09:30:17 2023 GMT
            Not After : Dec 12 09:30:17 2033 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    2d:cc:2e:8d:32:82:b1:f3:de:fb:b6:74:b4:fe:1c:
                    63:fc:89:60:4f:ac:c7:0d:77:a6:9e:07:b0:5f:84:
                    f5:15
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                F2:11:81:78:DB:24:42:DB:74:3E:FB:5D:A4:48:49:17:C0:04:6A:DF
            X509v3 Authority Key Identifier: 
                A6:73:49:08:58:A6:19:D8:E5:33:32:B8:9A:8C:4E:4E:1C:FC:71:8B
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=%40alice_wire@wire.com, URI:im:wireapp=lJGYPz0ZRq2kvc_XpdaDlA/c1d4519ce580a475@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:50:56:05:da:d5:f1:c6:a0:85:f8:ab:13:06:29:
        1c:ba:52:5d:a6:ac:ad:ec:13:23:53:0e:3d:ee:3e:f0:a8:91:
        02:21:00:b7:30:53:f7:d6:2f:00:7c:cc:20:c1:52:a2:cb:9b:
        d1:58:86:6e:ce:46:97:e2:1e:ca:8d:54:1a:32:6c:f5:b1

```

###### Certificate #2
openssl -verify ❌
```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQW2eHq0Wg/Lsl4IoarCUrSjAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMjE1MDkz
MDE1WhcNMzMxMjEyMDkzMDE1WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDN6
yJG/lAsh3ykUkwMq25q1z9FV2E2fr5R6nnZt/UO1Z+QcUFZy/bn4N/gbi47lhAEQ
Gs8nMnbtldoRoE3zRWajZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBSmc0kIWKYZ2OUzMriajE5OHPxxizAfBgNVHSMEGDAW
gBSJHuc7G3bNZ0FNwsoiQh/Rur0znjAKBggqhkjOPQQDAgNIADBFAiBnXwqpTYlN
YXftDUSzaJ57O5CkhvgVIlKiFQJMN6984wIhAKG7ZDIqGIKL3PUcInFCb5drLyh9
FB81M8ieOHb4tyGW
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5b:67:87:ab:45:a0:fc:bb:25:e0:8a:1a:ac:25:2b:4a
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Dec 15 09:30:15 2023 GMT
            Not After : Dec 12 09:30:15 2033 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:33:7a:c8:91:bf:94:0b:21:df:29:14:93:03:2a:
                    db:9a:b5:cf:d1:55:d8:4d:9f:af:94:7a:9e:76:6d:
                    fd:43:b5:67:e4:1c:50:56:72:fd:b9:f8:37:f8:1b:
                    8b:8e:e5:84:01:10:1a:cf:27:32:76:ed:95:da:11:
                    a0:4d:f3:45:66
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                A6:73:49:08:58:A6:19:D8:E5:33:32:B8:9A:8C:4E:4E:1C:FC:71:8B
            X509v3 Authority Key Identifier: 
                89:1E:E7:3B:1B:76:CD:67:41:4D:C2:CA:22:42:1F:D1:BA:BD:33:9E
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:67:5f:0a:a9:4d:89:4d:61:77:ed:0d:44:b3:68:
        9e:7b:3b:90:a4:86:f8:15:22:52:a2:15:02:4c:37:af:7c:e3:
        02:21:00:a1:bb:64:32:2a:18:82:8b:dc:f5:1c:22:71:42:6f:
        97:6b:2f:28:7d:14:1f:35:33:c8:9e:38:76:f8:b7:21:96

```
