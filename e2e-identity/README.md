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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/41ce37f7349bae10/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/KCnv14ObkImIcLvbYhxuoHSAhppnDOwd
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/i6gRxAG0x6PcdxdO7DndWGoReGYlr26S
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/U1w1EfAyZrVZfoBOe47YwDlJCaMwfDHS
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32871/acme/wire/directory
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
  "newNonce": "https://stepca:32871/acme/wire/new-nonce",
  "newAccount": "https://stepca:32871/acme/wire/new-account",
  "newOrder": "https://stepca:32871/acme/wire/new-order",
  "revokeCert": "https://stepca:32871/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32871/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32871/acme/wire/directory>;rel="index"
replay-nonce: Wm5wdU1FcWdwR2txQXU4SjFRT1lGeW1uaFFBVkpoMG4
vary: Origin
```
```text
Wm5wdU1FcWdwR2txQXU4SjFRT1lGeW1uaFFBVkpoMG4
```
#### 5. create a new account
```http request
POST https://stepca:32871/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IldfTHhBSnNDTm9RbXNkcGxxelhwQ3ZIRXlxMHg5eVFQODcxaUlTY1NTUzQifSwibm9uY2UiOiJXbTV3ZFUxRmNXZHdSMnR4UVhVNFNqRlJUMWxHZVcxdWFGRkJWa3BvTUc0IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NzEvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "30BVh367_MLbxFwFHGxzouBwaektKnTI1jBJY1V5fyKEZ6j-XylUZp2lx34VwISW8AjwP_gnrbspWUyqX0WlDw"
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
      "x": "W_LxAJsCNoQmsdplqzXpCvHEyq0x9yQP871iIScSSS4"
    },
    "nonce": "Wm5wdU1FcWdwR2txQXU4SjFRT1lGeW1uaFFBVkpoMG4",
    "typ": "JWT",
    "url": "https://stepca:32871/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32871/acme/wire/directory>;rel="index"
location: https://stepca:32871/acme/wire/account/713xcnRAaXekXeWmfBjDjqMiMtB8arDi
replay-nonce: anhmTURRYVM1S1lKUVJ4SUU5U3A5TkFWZGxka0Z6OHU
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32871/acme/wire/account/713xcnRAaXekXeWmfBjDjqMiMtB8arDi/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32871/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODcxL2FjbWUvd2lyZS9hY2NvdW50LzcxM3hjblJBYVhla1hlV21mQmpEanFNaU10QjhhckRpIiwidHlwIjoiSldUIiwibm9uY2UiOiJhbmhtVFVSUllWTTFTMWxLVVZKNFNVVTVVM0E1VGtGV1pHeGthMFo2T0hVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NzEvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9WWNRb2w5d25UMmFGTkRBdy12ZnZEUS80MWNlMzdmNzM0OWJhZTEwQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMS0wM1QwOTowOTowMi4yNTg1NjVaIiwibm90QWZ0ZXIiOiIyMDMzLTEyLTMxVDA5OjA5OjAyLjI1ODU2NVoifQ",
  "signature": "g3CzigehoCiqt6URf1G2oL6ZLQik0f-FSxayYnStvaOLY1-_QRfsQePM1-wSmdM2NKE4rO3c17zOO6vlMY8hAg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2033-12-31T09:09:02.258565Z",
    "notBefore": "2024-01-03T09:09:02.258565Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32871/acme/wire/account/713xcnRAaXekXeWmfBjDjqMiMtB8arDi",
    "nonce": "anhmTURRYVM1S1lKUVJ4SUU5U3A5TkFWZGxka0Z6OHU",
    "typ": "JWT",
    "url": "https://stepca:32871/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32871/acme/wire/directory>;rel="index"
location: https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O
replay-nonce: T2dLeWFpTlhjbmRVZnJlaGJ6dFlrRG9wdkRWVzhWZXo
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32871/acme/wire/authz/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak"
  ],
  "expires": "2024-01-04T09:09:02Z",
  "notBefore": "2024-01-03T09:09:02.258565Z",
  "notAfter": "2033-12-31T09:09:02.258565Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32871/acme/wire/authz/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODcxL2FjbWUvd2lyZS9hY2NvdW50LzcxM3hjblJBYVhla1hlV21mQmpEanFNaU10QjhhckRpIiwidHlwIjoiSldUIiwibm9uY2UiOiJUMmRMZVdGcFRsaGpibVJWWm5KbGFHSjZkRmxyUkc5d2RrUldWemhXWlhvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NzEvYWNtZS93aXJlL2F1dGh6LzhIRDVlWEhSZG0yNWJWY1dvSm02U2dpeW11UmZkOUFrIn0",
  "payload": "",
  "signature": "PCmjQkf0FOSam_WLabJBXf9pOWGLBcklsNKJQAy9sQNxWe3Lenb1Y7dYlk8knNmrs1Omm7nDBGmFecg0CfcoCg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32871/acme/wire/account/713xcnRAaXekXeWmfBjDjqMiMtB8arDi",
    "nonce": "T2dLeWFpTlhjbmRVZnJlaGJ6dFlrRG9wdkRWVzhWZXo",
    "typ": "JWT",
    "url": "https://stepca:32871/acme/wire/authz/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32871/acme/wire/directory>;rel="index"
location: https://stepca:32871/acme/wire/authz/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak
replay-nonce: Zm9NNmR5TEJWTW1Xd0UzZGVTSzVyZ1IyaFRSNkwzbUI
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2024-01-04T09:09:02Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/i6gRxAG0x6PcdxdO7DndWGoReGYlr26S",
      "status": "pending",
      "token": "2KAKw3bDg6xOy0D71BjVs8U2RLJ7Wjlp",
      "target": "http://dex:22288/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/KCnv14ObkImIcLvbYhxuoHSAhppnDOwd",
      "status": "pending",
      "token": "2KAKw3bDg6xOy0D71BjVs8U2RLJ7Wjlp",
      "target": "http://wire.com:23372/clients/41ce37f7349bae10/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:23372/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
dWFmbVFoYUx0dVdZYnJUc0FZYWdqOHBVMDROQUF5NzA
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiV19MeEFKc0NOb1Ftc2RwbHF6WHBDdkhFeXEweDl5UVA4NzFpSVNjU1NTNCJ9fQ.eyJpYXQiOjE3MDQyNjkzNDIsImV4cCI6MTcwNDI3NjU0MiwibmJmIjoxNzA0MjY5MzQyLCJzdWIiOiJpbTp3aXJlYXBwPVljUW9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJlLmNvbSIsImp0aSI6ImRhMzk3NDVlLTYzNzUtNDAyOS05MThlLTk0YWE2NDRjZjE1NSIsIm5vbmNlIjoiZFdGbWJWRm9ZVXgwZFZkWlluSlVjMEZaWVdkcU9IQlZNRFJPUVVGNU56QSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjMzNzIvY2xpZW50cy80MWNlMzdmNzM0OWJhZTEwL2FjY2Vzcy10b2tlbiIsImNoYWwiOiIyS0FLdzNiRGc2eE95MEQ3MUJqVnM4VTJSTEo3V2pscCIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.0SVBQ-jyReuYSgk_u8g1wLBwyXzLy2H0BHll5NjwaRUycVzUIcUJXRgCGNQi68nSdBRibeI_ECElc50VDJkkBw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiV19MeEFKc0NOb1Ftc2RwbHF6WHBDdkhF
eXEweDl5UVA4NzFpSVNjU1NTNCJ9fQ.eyJpYXQiOjE3MDQyNjkzNDIsImV4cCI6M
TcwNDI3NjU0MiwibmJmIjoxNzA0MjY5MzQyLCJzdWIiOiJpbTp3aXJlYXBwPVljU
W9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJlLmNvbSIsI
mp0aSI6ImRhMzk3NDVlLTYzNzUtNDAyOS05MThlLTk0YWE2NDRjZjE1NSIsIm5vb
mNlIjoiZFdGbWJWRm9ZVXgwZFZkWlluSlVjMEZaWVdkcU9IQlZNRFJPUVVGNU56Q
SIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjMzNzIvY2xpZ
W50cy80MWNlMzdmNzM0OWJhZTEwL2FjY2Vzcy10b2tlbiIsImNoYWwiOiIyS0FLd
zNiRGc2eE95MEQ3MUJqVnM4VTJSTEo3V2pscCIsImhhbmRsZSI6ImltOndpcmVhc
HA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.0SVBQ-jyR
euYSgk_u8g1wLBwyXzLy2H0BHll5NjwaRUycVzUIcUJXRgCGNQi68nSdBRibeI_E
CElc50VDJkkBw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "W_LxAJsCNoQmsdplqzXpCvHEyq0x9yQP871iIScSSS4"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "2KAKw3bDg6xOy0D71BjVs8U2RLJ7Wjlp",
  "exp": 1704276542,
  "handle": "im:wireapp=%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:23372/clients/41ce37f7349bae10/access-token",
  "iat": 1704269342,
  "jti": "da39745e-6375-4029-918e-94aa644cf155",
  "nbf": 1704269342,
  "nonce": "dWFmbVFoYUx0dVdZYnJUc0FZYWdqOHBVMDROQUF5NzA",
  "sub": "im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICTdVj4L2eCg5YyrIr6NoOmg1Y3qWk7KxIkkVSUq6rPg
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAW/LxAJsCNoQmsdplqzXpCvHEyq0x9yQP871iIScSSS4=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:23372/clients/41ce37f7349bae10/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVjE5TWVFRktjME5PYjFGdGMyUndiSEY2V0hCRGRraEZlWEV3ZURsNVVWQTROekZwU1ZOalUxTlROQ0o5ZlEuZXlKcFlYUWlPakUzTURReU5qa3pORElzSW1WNGNDSTZNVGN3TkRJM05qVTBNaXdpYm1KbUlqb3hOekEwTWpZNU16UXlMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVmxqVVc5c09YZHVWREpoUms1RVFYY3RkbVoyUkZFdk5ERmpaVE0zWmpjek5EbGlZV1V4TUVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1SaE16azNORFZsTFRZek56VXROREF5T1MwNU1UaGxMVGswWVdFMk5EUmpaakUxTlNJc0ltNXZibU5sSWpvaVpGZEdiV0pXUm05WlZYZ3daRlprV2xsdVNsVmpNRVphV1Zka2NVOUlRbFpOUkZKUFVWVkdOVTU2UVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qTXpOekl2WTJ4cFpXNTBjeTgwTVdObE16ZG1Oek0wT1dKaFpURXdMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lJeVMwRkxkek5pUkdjMmVFOTVNRVEzTVVKcVZuTTRWVEpTVEVvM1YycHNjQ0lzSW1oaGJtUnNaU0k2SW1sdE9uZHBjbVZoY0hBOUpUUXdZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW5SbFlXMGlPaUozYVhKbEluMC4wU1ZCUS1qeVJldVlTZ2tfdThnMXdMQnd5WHpMeTJIMEJIbGw1Tmp3YVJVeWNWelVJY1VKWFJnQ0dOUWk2OG5TZEJSaWJlSV9FQ0VsYzUwVkRKa2tCdw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImN0RmkxWmozUVRmSmRLemh6NFdlMmdNSl9kMmg5ckNiU3lrQ3g5a3ZDVjAifX0.eyJpYXQiOjE3MDQyNjkzNDIsImV4cCI6MTcwNDI3MzMwMiwibmJmIjoxNzA0MjY5MzQyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjMzNzIvY2xpZW50cy80MWNlMzdmNzM0OWJhZTEwL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9WWNRb2w5d25UMmFGTkRBdy12ZnZEUS80MWNlMzdmNzM0OWJhZTEwQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzMzcyL2NsaWVudHMvNDFjZTM3ZjczNDliYWUxMC9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI4NWRhMzA3YS05ODFiLTQ5MzAtYTY3NC01ZTdlMzAwMmI3Y2EiLCJub25jZSI6ImRXRm1iVkZvWVV4MGRWZFpZbkpVYzBGWllXZHFPSEJWTURST1FVRjVOekEiLCJjaGFsIjoiMktBS3czYkRnNnhPeTBENzFCalZzOFUyUkxKN1dqbHAiLCJjbmYiOnsia2lkIjoiVTdTZHh3aDQyX2Z4SkpFTk5nQnpGTmU5UU9ZQnZ3dndLMlRIcUZoUTVfVSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVYxOU1lRUZLYzBOT2IxRnRjMlJ3YkhGNldIQkRka2hGZVhFd2VEbDVVVkE0TnpGcFNWTmpVMU5UTkNKOWZRLmV5SnBZWFFpT2pFM01EUXlOamt6TkRJc0ltVjRjQ0k2TVRjd05ESTNOalUwTWl3aWJtSm1Jam94TnpBME1qWTVNelF5TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFZsalVXOXNPWGR1VkRKaFJrNUVRWGN0ZG1aMlJGRXZOREZqWlRNM1pqY3pORGxpWVdVeE1FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltUmhNemszTkRWbExUWXpOelV0TkRBeU9TMDVNVGhsTFRrMFlXRTJORFJqWmpFMU5TSXNJbTV2Ym1ObElqb2laRmRHYldKV1JtOVpWWGd3WkZaa1dsbHVTbFZqTUVaYVdWZGtjVTlJUWxaTlJGSlBVVlZHTlU1NlFTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak16TnpJdlkyeHBaVzUwY3k4ME1XTmxNemRtTnpNME9XSmhaVEV3TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSXlTMEZMZHpOaVJHYzJlRTk1TUVRM01VSnFWbk00VlRKU1RFbzNWMnBzY0NJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuMFNWQlEtanlSZXVZU2drX3U4ZzF3TEJ3eVh6THkySDBCSGxsNU5qd2FSVXljVnpVSWNVSlhSZ0NHTlFpNjhuU2RCUmliZUlfRUNFbGM1MFZESmtrQnciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVljUW9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.7gwmRUwugEWIPL9azp9WlYbHoRwqHitOnseYAQuSgc6-S30OKeT--hrGqeD5_owG7wi6PDnfaWSBQeb8ktH7Bg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImN0RmkxWmozUVRmSmRLemh6NFdlMmdNSl9kMmg5ckNiU3lrQ3g5a3ZDVjAifX0.eyJpYXQiOjE3MDQyNjkzNDIsImV4cCI6MTcwNDI3MzMwMiwibmJmIjoxNzA0MjY5MzQyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjMzNzIvY2xpZW50cy80MWNlMzdmNzM0OWJhZTEwL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9WWNRb2w5d25UMmFGTkRBdy12ZnZEUS80MWNlMzdmNzM0OWJhZTEwQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzMzcyL2NsaWVudHMvNDFjZTM3ZjczNDliYWUxMC9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI4NWRhMzA3YS05ODFiLTQ5MzAtYTY3NC01ZTdlMzAwMmI3Y2EiLCJub25jZSI6ImRXRm1iVkZvWVV4MGRWZFpZbkpVYzBGWllXZHFPSEJWTURST1FVRjVOekEiLCJjaGFsIjoiMktBS3czYkRnNnhPeTBENzFCalZzOFUyUkxKN1dqbHAiLCJjbmYiOnsia2lkIjoiVTdTZHh3aDQyX2Z4SkpFTk5nQnpGTmU5UU9ZQnZ3dndLMlRIcUZoUTVfVSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVYxOU1lRUZLYzBOT2IxRnRjMlJ3YkhGNldIQkRka2hGZVhFd2VEbDVVVkE0TnpGcFNWTmpVMU5UTkNKOWZRLmV5SnBZWFFpT2pFM01EUXlOamt6TkRJc0ltVjRjQ0k2TVRjd05ESTNOalUwTWl3aWJtSm1Jam94TnpBME1qWTVNelF5TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFZsalVXOXNPWGR1VkRKaFJrNUVRWGN0ZG1aMlJGRXZOREZqWlRNM1pqY3pORGxpWVdVeE1FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltUmhNemszTkRWbExUWXpOelV0TkRBeU9TMDVNVGhsTFRrMFlXRTJORFJqWmpFMU5TSXNJbTV2Ym1ObElqb2laRmRHYldKV1JtOVpWWGd3WkZaa1dsbHVTbFZqTUVaYVdWZGtjVTlJUWxaTlJGSlBVVlZHTlU1NlFTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak16TnpJdlkyeHBaVzUwY3k4ME1XTmxNemRtTnpNME9XSmhaVEV3TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSXlTMEZMZHpOaVJHYzJlRTk1TUVRM01VSnFWbk00VlRKU1RFbzNWMnBzY0NJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuMFNWQlEtanlSZXVZU2drX3U4ZzF3TEJ3eVh6THkySDBCSGxsNU5qd2FSVXljVnpVSWNVSlhSZ0NHTlFpNjhuU2RCUmliZUlfRUNFbGM1MFZESmtrQnciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVljUW9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.7gwmRUwugEWIPL9azp9WlYbHoRwqHitOnseYAQuSgc6-S30OKeT--hrGqeD5_owG7wi6PDnfaWSBQeb8ktH7Bg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6ImN0RmkxWmozUVRmSmRLemh6NFdlMmdNSl9k
Mmg5ckNiU3lrQ3g5a3ZDVjAifX0.eyJpYXQiOjE3MDQyNjkzNDIsImV4cCI6MTcw
NDI3MzMwMiwibmJmIjoxNzA0MjY5MzQyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjMzNzIvY2xpZW50cy80MWNlMzdmNzM0OWJhZTEwL2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9WWNRb2w5d25UMmFGTkRBdy12ZnZEUS80MWNlMzdmNzM0
OWJhZTEwQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzMzcyL2Ns
aWVudHMvNDFjZTM3ZjczNDliYWUxMC9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI4NWRh
MzA3YS05ODFiLTQ5MzAtYTY3NC01ZTdlMzAwMmI3Y2EiLCJub25jZSI6ImRXRm1i
VkZvWVV4MGRWZFpZbkpVYzBGWllXZHFPSEJWTURST1FVRjVOekEiLCJjaGFsIjoi
MktBS3czYkRnNnhPeTBENzFCalZzOFUyUkxKN1dqbHAiLCJjbmYiOnsia2lkIjoi
VTdTZHh3aDQyX2Z4SkpFTk5nQnpGTmU5UU9ZQnZ3dndLMlRIcUZoUTVfVSJ9LCJw
cm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJ
aXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lM
Q0o0SWpvaVYxOU1lRUZLYzBOT2IxRnRjMlJ3YkhGNldIQkRka2hGZVhFd2VEbDVV
VkE0TnpGcFNWTmpVMU5UTkNKOWZRLmV5SnBZWFFpT2pFM01EUXlOamt6TkRJc0lt
VjRjQ0k2TVRjd05ESTNOalUwTWl3aWJtSm1Jam94TnpBME1qWTVNelF5TENKemRX
SWlPaUpwYlRwM2FYSmxZWEJ3UFZsalVXOXNPWGR1VkRKaFJrNUVRWGN0ZG1aMlJG
RXZOREZqWlRNM1pqY3pORGxpWVdVeE1FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklt
UmhNemszTkRWbExUWXpOelV0TkRBeU9TMDVNVGhsTFRrMFlXRTJORFJqWmpFMU5T
SXNJbTV2Ym1ObElqb2laRmRHYldKV1JtOVpWWGd3WkZaa1dsbHVTbFZqTUVaYVdW
ZGtjVTlJUWxaTlJGSlBVVlZHTlU1NlFTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RI
VWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak16TnpJdlkyeHBaVzUwY3k4ME1X
TmxNemRtTnpNME9XSmhaVEV3TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9p
SXlTMEZMZHpOaVJHYzJlRTk1TUVRM01VSnFWbk00VlRKU1RFbzNWMnBzY0NJc0lt
aGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FY
SmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuMFNWQlEtanlSZXVZU2drX3U4
ZzF3TEJ3eVh6THkySDBCSGxsNU5qd2FSVXljVnpVSWNVSlhSZ0NHTlFpNjhuU2RC
UmliZUlfRUNFbGM1MFZESmtrQnciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVlj
UW9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJlLmNvbSIs
ImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.7gwmRUwu
gEWIPL9azp9WlYbHoRwqHitOnseYAQuSgc6-S30OKeT--hrGqeD5_owG7wi6PDnf
aWSBQeb8ktH7Bg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "ctFi1Zj3QTfJdKzhz4We2gMJ_d2h9rCbSykCx9kvCV0"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:23372/clients/41ce37f7349bae10/access-token",
  "chal": "2KAKw3bDg6xOy0D71BjVs8U2RLJ7Wjlp",
  "client_id": "im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com",
  "cnf": {
    "kid": "U7Sdxwh42_fxJJENNgBzFNe9QOYBvwvwK2THqFhQ5_U"
  },
  "exp": 1704273302,
  "iat": 1704269342,
  "iss": "http://wire.com:23372/clients/41ce37f7349bae10/access-token",
  "jti": "85da307a-981b-4930-a674-5e7e3002b7ca",
  "nbf": 1704269342,
  "nonce": "dWFmbVFoYUx0dVdZYnJUc0FZYWdqOHBVMDROQUF5NzA",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiV19MeEFKc0NOb1Ftc2RwbHF6WHBDdkhFeXEweDl5UVA4NzFpSVNjU1NTNCJ9fQ.eyJpYXQiOjE3MDQyNjkzNDIsImV4cCI6MTcwNDI3NjU0MiwibmJmIjoxNzA0MjY5MzQyLCJzdWIiOiJpbTp3aXJlYXBwPVljUW9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJlLmNvbSIsImp0aSI6ImRhMzk3NDVlLTYzNzUtNDAyOS05MThlLTk0YWE2NDRjZjE1NSIsIm5vbmNlIjoiZFdGbWJWRm9ZVXgwZFZkWlluSlVjMEZaWVdkcU9IQlZNRFJPUVVGNU56QSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjMzNzIvY2xpZW50cy80MWNlMzdmNzM0OWJhZTEwL2FjY2Vzcy10b2tlbiIsImNoYWwiOiIyS0FLdzNiRGc2eE95MEQ3MUJqVnM4VTJSTEo3V2pscCIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.0SVBQ-jyReuYSgk_u8g1wLBwyXzLy2H0BHll5NjwaRUycVzUIcUJXRgCGNQi68nSdBRibeI_ECElc50VDJkkBw",
  "scope": "wire_client_id",
  "sub": "im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIA7Qg1xC8gP1VG2HRwYJ9ARsifowJOW3QlWuOtvWnbyE
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEActFi1Zj3QTfJdKzhz4We2gMJ/d2h9rCbSykCx9kvCV0=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/KCnv14ObkImIcLvbYhxuoHSAhppnDOwd
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODcxL2FjbWUvd2lyZS9hY2NvdW50LzcxM3hjblJBYVhla1hlV21mQmpEanFNaU10QjhhckRpIiwidHlwIjoiSldUIiwibm9uY2UiOiJabTlOTm1SNVRFSldUVzFYZDBVelpHVlRTelZ5WjFJeWFGUlNOa3d6YlVJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NzEvYWNtZS93aXJlL2NoYWxsZW5nZS84SEQ1ZVhIUmRtMjViVmNXb0ptNlNnaXltdVJmZDlBay9LQ252MTRPYmtJbUljTHZiWWh4dW9IU0FocHBuRE93ZCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltTjBSbWt4V21velVWUm1TbVJMZW1oNk5GZGxNbWROU2w5a01tZzVja05pVTNsclEzZzVhM1pEVmpBaWZYMC5leUpwWVhRaU9qRTNNRFF5Tmprek5ESXNJbVY0Y0NJNk1UY3dOREkzTXpNd01pd2libUptSWpveE56QTBNalk1TXpReUxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNek56SXZZMnhwWlc1MGN5ODBNV05sTXpkbU56TTBPV0poWlRFd0wyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5V1dOUmIydzVkMjVVTW1GR1RrUkJkeTEyWm5aRVVTODBNV05sTXpkbU56TTBPV0poWlRFd1FIZHBjbVV1WTI5dElpd2lZWFZrSWpvaWFIUjBjRG92TDNkcGNtVXVZMjl0T2pJek16Y3lMMk5zYVdWdWRITXZOREZqWlRNM1pqY3pORGxpWVdVeE1DOWhZMk5sYzNNdGRHOXJaVzRpTENKcWRHa2lPaUk0TldSaE16QTNZUzA1T0RGaUxUUTVNekF0WVRZM05DMDFaVGRsTXpBd01tSTNZMkVpTENKdWIyNWpaU0k2SW1SWFJtMWlWa1p2V1ZWNE1HUldaRnBaYmtwVll6QkdXbGxYWkhGUFNFSldUVVJTVDFGVlJqVk9la0VpTENKamFHRnNJam9pTWt0QlMzY3pZa1JuTm5oUGVUQkVOekZDYWxaek9GVXlVa3hLTjFkcWJIQWlMQ0pqYm1ZaU9uc2lhMmxrSWpvaVZUZFRaSGgzYURReVgyWjRTa3BGVGs1blFucEdUbVU1VVU5WlFuWjNkbmRMTWxSSWNVWm9VVFZmVlNKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVZZeE9VMWxSVVpMWXpCT1QySXhSblJqTWxKM1lraEdObGRJUWtSa2EyaEdaVmhGZDJWRWJEVlZWa0UwVG5wR2NGTldUbXBWTVU1VVRrTktPV1pSTG1WNVNuQlpXRkZwVDJwRk0wMUVVWGxPYW10NlRrUkpjMGx0VmpSalEwazJUVlJqZDA1RVNUTk9hbFV3VFdsM2FXSnRTbTFKYW05NFRucEJNRTFxV1RWTmVsRjVURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGWnNhbFZYT1hOUFdHUjFWa1JLYUZKck5VVlJXR04wWkcxYU1sSkdSWFpPUkVacVdsUk5NMXBxWTNwT1JHeHBXVmRWZUUxRlFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2x0VW1oTmVtc3pUa1JXYkV4VVdYcE9lbFYwVGtSQmVVOVRNRFZOVkdoc1RGUnJNRmxYUlRKT1JGSnFXbXBGTVU1VFNYTkpiVFYyWW0xT2JFbHFiMmxhUm1SSFlsZEtWMUp0T1ZwV1dHZDNXa1phYTFkc2JIVlRiRlpxVFVWYVlWZFdaR3RqVlRsSlVXeGFUbEpHU2xCVlZsWkhUbFUxTmxGVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWsxNlRucEpkbGt5ZUhCYVZ6VXdZM2s0TUUxWFRteE5lbVJ0VG5wTk1FOVhTbWhhVkVWM1RESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTWGxUTUVaTVpIcE9hVkpIWXpKbFJUazFUVVZSTTAxVlNuRldiazAwVmxSS1UxUkZiek5XTW5CelkwTkpjMGx0YUdoaWJWSnpXbE5KTmtsdGJIUlBibVJ3WTIxV2FHTklRVGxLVkZGM1dWZDRjRmt5Vm1aa01teDVXbFZDTTJGWVNteE1iVTUyWWxOSmMwbHVVbXhaVnpCcFQybEtNMkZZU214SmJqQXVNRk5XUWxFdGFubFNaWFZaVTJkclgzVTRaekYzVEVKM2VWaDZUSGt5U0RCQ1NHeHNOVTVxZDJGU1ZYbGpWbnBWU1dOVlNsaFNaME5IVGxGcE5qaHVVMlJDVW1saVpVbGZSVU5GYkdNMU1GWkVTbXRyUW5jaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFZsalVXOXNPWGR1VkRKaFJrNUVRWGN0ZG1aMlJGRXZOREZqWlRNM1pqY3pORGxpWVdVeE1FQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvMUxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLjdnd21SVXd1Z0VXSVBMOWF6cDlXbFliSG9Sd3FIaXRPbnNlWUFRdVNnYzYtUzMwT0tlVC0taHJHcWVENV9vd0c3d2k2UERuZmFXU0JRZWI4a3RIN0JnIn0",
  "signature": "beuYRE3--_gRmcgsjM13pDemUHmHepUv8rVwNQoE2qNlpyTT2TYo3G4DGJIpHb3hGOB73QCLm-7jzdmGLplqBw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImN0RmkxWmozUVRmSmRLemh6NFdlMmdNSl9kMmg5ckNiU3lrQ3g5a3ZDVjAifX0.eyJpYXQiOjE3MDQyNjkzNDIsImV4cCI6MTcwNDI3MzMwMiwibmJmIjoxNzA0MjY5MzQyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjMzNzIvY2xpZW50cy80MWNlMzdmNzM0OWJhZTEwL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9WWNRb2w5d25UMmFGTkRBdy12ZnZEUS80MWNlMzdmNzM0OWJhZTEwQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzMzcyL2NsaWVudHMvNDFjZTM3ZjczNDliYWUxMC9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI4NWRhMzA3YS05ODFiLTQ5MzAtYTY3NC01ZTdlMzAwMmI3Y2EiLCJub25jZSI6ImRXRm1iVkZvWVV4MGRWZFpZbkpVYzBGWllXZHFPSEJWTURST1FVRjVOekEiLCJjaGFsIjoiMktBS3czYkRnNnhPeTBENzFCalZzOFUyUkxKN1dqbHAiLCJjbmYiOnsia2lkIjoiVTdTZHh3aDQyX2Z4SkpFTk5nQnpGTmU5UU9ZQnZ3dndLMlRIcUZoUTVfVSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVYxOU1lRUZLYzBOT2IxRnRjMlJ3YkhGNldIQkRka2hGZVhFd2VEbDVVVkE0TnpGcFNWTmpVMU5UTkNKOWZRLmV5SnBZWFFpT2pFM01EUXlOamt6TkRJc0ltVjRjQ0k2TVRjd05ESTNOalUwTWl3aWJtSm1Jam94TnpBME1qWTVNelF5TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFZsalVXOXNPWGR1VkRKaFJrNUVRWGN0ZG1aMlJGRXZOREZqWlRNM1pqY3pORGxpWVdVeE1FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltUmhNemszTkRWbExUWXpOelV0TkRBeU9TMDVNVGhsTFRrMFlXRTJORFJqWmpFMU5TSXNJbTV2Ym1ObElqb2laRmRHYldKV1JtOVpWWGd3WkZaa1dsbHVTbFZqTUVaYVdWZGtjVTlJUWxaTlJGSlBVVlZHTlU1NlFTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak16TnpJdlkyeHBaVzUwY3k4ME1XTmxNemRtTnpNME9XSmhaVEV3TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSXlTMEZMZHpOaVJHYzJlRTk1TUVRM01VSnFWbk00VlRKU1RFbzNWMnBzY0NJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuMFNWQlEtanlSZXVZU2drX3U4ZzF3TEJ3eVh6THkySDBCSGxsNU5qd2FSVXljVnpVSWNVSlhSZ0NHTlFpNjhuU2RCUmliZUlfRUNFbGM1MFZESmtrQnciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVljUW9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.7gwmRUwugEWIPL9azp9WlYbHoRwqHitOnseYAQuSgc6-S30OKeT--hrGqeD5_owG7wi6PDnfaWSBQeb8ktH7Bg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32871/acme/wire/account/713xcnRAaXekXeWmfBjDjqMiMtB8arDi",
    "nonce": "Zm9NNmR5TEJWTW1Xd0UzZGVTSzVyZ1IyaFRSNkwzbUI",
    "typ": "JWT",
    "url": "https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/KCnv14ObkImIcLvbYhxuoHSAhppnDOwd"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32871/acme/wire/directory>;rel="index"
link: <https://stepca:32871/acme/wire/authz/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak>;rel="up"
location: https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/KCnv14ObkImIcLvbYhxuoHSAhppnDOwd
replay-nonce: Y0gzQ2lBUmxrQnl0REJNNUx2djBpSVVZcWRicWZEdTc
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/KCnv14ObkImIcLvbYhxuoHSAhppnDOwd",
  "status": "valid",
  "token": "2KAKw3bDg6xOy0D71BjVs8U2RLJ7Wjlp",
  "target": "http://wire.com:23372/clients/41ce37f7349bae10/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=kGv5BNthMPURXxjg-4eiojBJDP9YHmshd0sAOMjq31c&code_challenge=cvB6zYAZW0H1YjddmkmC3YuDGufmqGDWJTCmFu51qrk
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:22288/dex/auth?response_type=code&client_id=wireapp&state=nwy-iJdG-uFYk7exnBGVWA&code_challenge=cvB6zYAZW0H1YjddmkmC3YuDGufmqGDWJTCmFu51qrk&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A23372%2Fcallback&scope=openid+profile&nonce=Q9MRqqnJyufivqDEndJiRA
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:22288/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDphV1Z4T0RjM2NFOHlVVXBMTURCU1dtSmlVRGt6YnpSbA==
```
```text
grant_type=authorization_code&code=p4kfhbtfn2e6oielcsga2m2ll&code_verifier=kGv5BNthMPURXxjg-4eiojBJDP9YHmshd0sAOMjq31c&redirect_uri=http%3A%2F%2Fwire.com%3A23372%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhmNTk4NTRkZWI4M2MxZGY4NzhkNDllOWVkOGIzY2ViMjkzMmEyZmEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyMjg4L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVmxqVVc5c09YZHVWREpoUms1RVFYY3RkbVoyUkZFdk5ERmpaVE0zWmpjek5EbGlZV1V4TUVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQzNTkzNDIsImlhdCI6MTcwNDI3Mjk0Miwibm9uY2UiOiJROU1ScXFuSnl1Zml2cURFbmRKaVJBIiwiYXRfaGFzaCI6Ik8zZmpUOFZlODRzNXZ3YTVXM1VveWciLCJuYW1lIjoiaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.PQ5xKVlJWpiJDNQL_V6kVy6L98EfbkrrhQyQTat50J3DwvuaZn5FMkCNmZgwV-c2XYGFFkDK_fm-MaL0V6j8PoMjAGf4qDgA7ZK2oI_-0Nxh_T1aJ-hPaT8CcfQQuF5vQUsXHkiMkIQgnri65NPag7mmS48xJBrWosnuL9aVhIulHwjkJVCGHpZjUbxN62rFsCxBVu65cbjYbdHE4CWGzj31zJplOUpAxtPbhxjxujZHV9kr0iNajWc4mIjQWyQ6P13T8kK7KK-uyvoIQsZJPGWzh0HgQ1z6omfCib28cSg_fVRMdvspd-yg7DrJOY5SZjmLul1a2VN6m6PjSiuPzQ",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhmNTk4NTRkZWI4M2MxZGY4NzhkNDllOWVkOGIzY2ViMjkzMmEyZmEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyMjg4L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVmxqVVc5c09YZHVWREpoUms1RVFYY3RkbVoyUkZFdk5ERmpaVE0zWmpjek5EbGlZV1V4TUVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQzNTkzNDIsImlhdCI6MTcwNDI3Mjk0Miwibm9uY2UiOiJROU1ScXFuSnl1Zml2cURFbmRKaVJBIiwiYXRfaGFzaCI6IlBhR0ljVTJuSUlCSElzQ1p5Sl9OWlEiLCJjX2hhc2giOiJRQ0xEV1AzeDIyaHBEUmZ1TlVlXzBnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.oQ47EmyQibdsmua-7AMT6wZH_keMkRDc3S-bSN3FB-z9A24Etb5b759rfgZBYrN-b5lx0qqg39NFqu1f-2PJM6DHlcKjrijBzUi0QoWkERjDJcVxKjzzbCFC_4YZGOqHaJlk8D-BeZFwrc8AR25fZi8NWYUJu21pvozBpm5Y_2DIOSddLIEPC-GtomNcz-Rh8tuVvzUbp-_ETQeP9nvRGXWctL_ksRpSJLYS7XcphcSpNQlNQOOOjxnvybDlppH3feF-lMmxm7b1A59kSC3HAyEpk2MH-UvP9zGv7YYD9aCBImwc1apwzxL3Jb5BBQCDYUcTdKaniSQtVQ5dCgKgSw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjhmNTk4NTRkZWI4M2MxZGY4NzhkNDllOWVkOGIzY2ViMjkzMmEyZmEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyMjg4L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVmxqVVc5c09YZHVWREpoUms1RVFYY3RkbVoyUkZFdk5ERmpaVE0zWmpjek5EbGlZV1V4TUVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQzNTkzNDIsImlhdCI6MTcwNDI3Mjk0Miwibm9uY2UiOiJROU1ScXFuSnl1Zml2cURFbmRKaVJBIiwiYXRfaGFzaCI6IlBhR0ljVTJuSUlCSElzQ1p5Sl9OWlEiLCJjX2hhc2giOiJRQ0xEV1AzeDIyaHBEUmZ1TlVlXzBnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.oQ47EmyQibdsmua-7AMT6wZH_keMkRDc3S-bSN3FB-z9A24Etb5b759rfgZBYrN-b5lx0qqg39NFqu1f-2PJM6DHlcKjrijBzUi0QoWkERjDJcVxKjzzbCFC_4YZGOqHaJlk8D-BeZFwrc8AR25fZi8NWYUJu21pvozBpm5Y_2DIOSddLIEPC-GtomNcz-Rh8tuVvzUbp-_ETQeP9nvRGXWctL_ksRpSJLYS7XcphcSpNQlNQOOOjxnvybDlppH3feF-lMmxm7b1A59kSC3HAyEpk2MH-UvP9zGv7YYD9aCBImwc1apwzxL3Jb5BBQCDYUcTdKaniSQtVQ5dCgKgSw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjhmNTk4NTRkZWI4M2MxZGY4NzhkNDllOWVkOGIzY2ViMjkzMmEyZmEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyMjg4L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVmxqVVc5c09YZHVWREpoUms1RVFYY3RkbVoyUkZFdk5ERmpaVE0zWmpjek5EbGlZV1V4TUVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQzNTkzNDIsImlhdCI6MTcwNDI3Mjk0Miwibm9uY2UiOiJROU1ScXFuSnl1Zml2cURFbmRKaVJBIiwiYXRfaGFzaCI6IlBhR0ljVTJuSUlCSElzQ1p5Sl9OWlEiLCJjX2hhc2giOiJRQ0xEV1AzeDIyaHBEUmZ1TlVlXzBnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.oQ47EmyQibdsmua-7AMT6wZH_keMkRDc3S-bSN3FB-z9A24Etb5b759rfgZBYrN-b5lx0qqg39NFqu1f-2PJM6DHlcKjrijBzUi0QoWkERjDJcVxKjzzbCFC_4YZGOqHaJlk8D-BeZFwrc8AR25fZi8NWYUJu21pvozBpm5Y_2DIOSddLIEPC-GtomNcz-Rh8tuVvzUbp-_ETQeP9nvRGXWctL_ksRpSJLYS7XcphcSpNQlNQOOOjxnvybDlppH3feF-lMmxm7b1A59kSC3HAyEpk2MH-UvP9zGv7YYD9aCBImwc1apwzxL3Jb5BBQCDYUcTdKaniSQtVQ5dCgKgSw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjhmNTk4NTRkZWI4M2MxZGY4NzhkNDllOWVk
OGIzY2ViMjkzMmEyZmEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyMjg4L2RleCIsI
nN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVmxqVVc5c09YZHVWREpoUms1RVFYY3Rkb
VoyUkZFdk5ERmpaVE0zWmpjek5EbGlZV1V4TUVCM2FYSmxMbU52YlJJRWJHUmhjQ
SIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQzNTkzNDIsImlhdCI6MTcwNDI3M
jk0Miwibm9uY2UiOiJROU1ScXFuSnl1Zml2cURFbmRKaVJBIiwiYXRfaGFzaCI6I
lBhR0ljVTJuSUlCSElzQ1p5Sl9OWlEiLCJjX2hhc2giOiJRQ0xEV1AzeDIyaHBEU
mZ1TlVlXzBnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlL
mNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.oQ47EmyQi
bdsmua-7AMT6wZH_keMkRDc3S-bSN3FB-z9A24Etb5b759rfgZBYrN-b5lx0qqg3
9NFqu1f-2PJM6DHlcKjrijBzUi0QoWkERjDJcVxKjzzbCFC_4YZGOqHaJlk8D-Be
ZFwrc8AR25fZi8NWYUJu21pvozBpm5Y_2DIOSddLIEPC-GtomNcz-Rh8tuVvzUbp
-_ETQeP9nvRGXWctL_ksRpSJLYS7XcphcSpNQlNQOOOjxnvybDlppH3feF-lMmxm
7b1A59kSC3HAyEpk2MH-UvP9zGv7YYD9aCBImwc1apwzxL3Jb5BBQCDYUcTdKani
SQtVQ5dCgKgSw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "8f59854deb83c1df878d49e9ed8b3ceb2932a2fa"
}
```

```json
{
  "at_hash": "PaGIcU2nIIBHIsCZyJ_NZQ",
  "aud": "wireapp",
  "c_hash": "QCLDWP3x22hpDRfuNUe_0g",
  "exp": 1704359342,
  "iat": 1704272942,
  "iss": "http://dex:22288/dex",
  "name": "im:wireapp=%40alice_wire@wire.com",
  "nonce": "Q9MRqqnJyufivqDEndJiRA",
  "preferred_username": "Alice Smith",
  "sub": "CjtpbTp3aXJlYXBwPVljUW9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtt7Gx+plVrhpp/Pk0AzU
25vpUiH9JQo+WpS793OPiBVWo+ijju6lsbfVtDJHpOd8zdM5SuR1hLqI4SJNP1ya
Koqevmd15zSYLuJAhlSm7g+jODlqvLTlpxiVXMGCJGX0r18znYtSYgbZlC8TQ0sj
prTv9FQiynqVJC8ieR0NxKRjsOhUsEM5QmHKeoFWI6OWsHf24Ki99CcjUuxL6i/N
nXNBweYkbFhADf5Ey1mY8DagKGTQNpht38Q2xSzeRCmaIrExcZ+lgf4TQ7nclTgH
PBs9ip+ERZWlnLqk2otxVIlhQlxS/R/WbR/9rFVhLtvL4oGENvZ+ZtjBJs1n7RTh
WwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/i6gRxAG0x6PcdxdO7DndWGoReGYlr26S
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODcxL2FjbWUvd2lyZS9hY2NvdW50LzcxM3hjblJBYVhla1hlV21mQmpEanFNaU10QjhhckRpIiwidHlwIjoiSldUIiwibm9uY2UiOiJZMGd6UTJsQlVteHJRbmwwUkVKTk5VeDJkakJwU1ZWWmNXUmljV1pFZFRjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NzEvYWNtZS93aXJlL2NoYWxsZW5nZS84SEQ1ZVhIUmRtMjViVmNXb0ptNlNnaXltdVJmZDlBay9pNmdSeEFHMHg2UGNkeGRPN0RuZFdHb1JlR1lscjI2UyJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJamhtTlRrNE5UUmtaV0k0TTJNeFpHWTROemhrTkRsbE9XVmtPR0l6WTJWaU1qa3pNbUV5Wm1FaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSXlNamc0TDJSbGVDSXNJbk4xWWlJNklrTnFkSEJpVkhBellWaEtiRmxZUW5kUVZteHFWVmM1YzA5WVpIVldSRXBvVW1zMVJWRllZM1JrYlZveVVrWkZkazVFUm1wYVZFMHpXbXBqZWs1RWJHbFpWMVY0VFVWQ00yRllTbXhNYlU1MllsSkpSV0pIVW1oalFTSXNJbUYxWkNJNkluZHBjbVZoY0hBaUxDSmxlSEFpT2pFM01EUXpOVGt6TkRJc0ltbGhkQ0k2TVRjd05ESTNNamswTWl3aWJtOXVZMlVpT2lKUk9VMVNjWEZ1U25sMVptbDJjVVJGYm1SS2FWSkJJaXdpWVhSZmFHRnphQ0k2SWxCaFIwbGpWVEp1U1VsQ1NFbHpRMXA1U2w5T1dsRWlMQ0pqWDJoaGMyZ2lPaUpSUTB4RVYxQXplREl5YUhCRVVtWjFUbFZsWHpCbklpd2libUZ0WlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJa0ZzYVdObElGTnRhWFJvSW4wLm9RNDdFbXlRaWJkc211YS03QU1UNndaSF9rZU1rUkRjM1MtYlNOM0ZCLXo5QTI0RXRiNWI3NTlyZmdaQllyTi1iNWx4MHFxZzM5TkZxdTFmLTJQSk02REhsY0tqcmlqQnpVaTBRb1drRVJqREpjVnhLanp6YkNGQ180WVpHT3FIYUpsazhELUJlWkZ3cmM4QVIyNWZaaThOV1lVSnUyMXB2b3pCcG01WV8yRElPU2RkTElFUEMtR3RvbU5jei1SaDh0dVZ2elVicC1fRVRRZVA5bnZSR1hXY3RMX2tzUnBTSkxZUzdYY3BoY1NwTlFsTlFPT09qeG52eWJEbHBwSDNmZUYtbE1teG03YjFBNTlrU0MzSEF5RXBrMk1ILVV2UDl6R3Y3WVlEOWFDQkltd2MxYXB3enhMM0piNUJCUUNEWVVjVGRLYW5pU1F0VlE1ZENnS2dTdyIsImtleWF1dGgiOiIyS0FLdzNiRGc2eE95MEQ3MUJqVnM4VTJSTEo3V2pscC5VN1NkeHdoNDJfZnhKSkVOTmdCekZOZTlRT1lCdnd2d0syVEhxRmhRNV9VIn0",
  "signature": "asfG5CdguUEhOqGO9SYaGd9sFivxdxnu2YpTjeRH0hJnumYmU3E3h6s9tducdbbZXdKCKe4vgKWOYcKssAYMDQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhmNTk4NTRkZWI4M2MxZGY4NzhkNDllOWVkOGIzY2ViMjkzMmEyZmEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyMjg4L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVmxqVVc5c09YZHVWREpoUms1RVFYY3RkbVoyUkZFdk5ERmpaVE0zWmpjek5EbGlZV1V4TUVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQzNTkzNDIsImlhdCI6MTcwNDI3Mjk0Miwibm9uY2UiOiJROU1ScXFuSnl1Zml2cURFbmRKaVJBIiwiYXRfaGFzaCI6IlBhR0ljVTJuSUlCSElzQ1p5Sl9OWlEiLCJjX2hhc2giOiJRQ0xEV1AzeDIyaHBEUmZ1TlVlXzBnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.oQ47EmyQibdsmua-7AMT6wZH_keMkRDc3S-bSN3FB-z9A24Etb5b759rfgZBYrN-b5lx0qqg39NFqu1f-2PJM6DHlcKjrijBzUi0QoWkERjDJcVxKjzzbCFC_4YZGOqHaJlk8D-BeZFwrc8AR25fZi8NWYUJu21pvozBpm5Y_2DIOSddLIEPC-GtomNcz-Rh8tuVvzUbp-_ETQeP9nvRGXWctL_ksRpSJLYS7XcphcSpNQlNQOOOjxnvybDlppH3feF-lMmxm7b1A59kSC3HAyEpk2MH-UvP9zGv7YYD9aCBImwc1apwzxL3Jb5BBQCDYUcTdKaniSQtVQ5dCgKgSw",
    "keyauth": "2KAKw3bDg6xOy0D71BjVs8U2RLJ7Wjlp.U7Sdxwh42_fxJJENNgBzFNe9QOYBvwvwK2THqFhQ5_U"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32871/acme/wire/account/713xcnRAaXekXeWmfBjDjqMiMtB8arDi",
    "nonce": "Y0gzQ2lBUmxrQnl0REJNNUx2djBpSVVZcWRicWZEdTc",
    "typ": "JWT",
    "url": "https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/i6gRxAG0x6PcdxdO7DndWGoReGYlr26S"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32871/acme/wire/directory>;rel="index"
link: <https://stepca:32871/acme/wire/authz/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak>;rel="up"
location: https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/i6gRxAG0x6PcdxdO7DndWGoReGYlr26S
replay-nonce: clhxdldwZWREdWVVUHpyblF5RjhEeFBISXVIM2ZiVm0
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32871/acme/wire/challenge/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak/i6gRxAG0x6PcdxdO7DndWGoReGYlr26S",
  "status": "valid",
  "token": "2KAKw3bDg6xOy0D71BjVs8U2RLJ7Wjlp",
  "target": "http://dex:22288/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODcxL2FjbWUvd2lyZS9hY2NvdW50LzcxM3hjblJBYVhla1hlV21mQmpEanFNaU10QjhhckRpIiwidHlwIjoiSldUIiwibm9uY2UiOiJjbGh4ZGxkd1pXUkVkV1ZWVUhweWJsRjVSamhFZUZCSVNYVklNMlppVm0wIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NzEvYWNtZS93aXJlL29yZGVyL25wa1hxUnNnWTJRTk1PbWpHMFVIRk1weHZkVEZEeTdPIn0",
  "payload": "",
  "signature": "Ekq-Z5C6e8QNzMswFSZKL9zlEd-mwyeJsqkmZFG5LjNJ6F_drT0AFUaMcJu42Qn8vESKcHhAeYT6ppj4kIpWAg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32871/acme/wire/account/713xcnRAaXekXeWmfBjDjqMiMtB8arDi",
    "nonce": "clhxdldwZWREdWVVUHpyblF5RjhEeFBISXVIM2ZiVm0",
    "typ": "JWT",
    "url": "https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32871/acme/wire/directory>;rel="index"
location: https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O
replay-nonce: OVR3Y0R0U2VMRENXaHRZSFhrWnUycDJ2WFdEM1dSeTI
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32871/acme/wire/authz/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak"
  ],
  "expires": "2024-01-04T09:09:02Z",
  "notBefore": "2024-01-03T09:09:02.258565Z",
  "notAfter": "2033-12-31T09:09:02.258565Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODcxL2FjbWUvd2lyZS9hY2NvdW50LzcxM3hjblJBYVhla1hlV21mQmpEanFNaU10QjhhckRpIiwidHlwIjoiSldUIiwibm9uY2UiOiJPVlIzWTBSMFUyVk1SRU5YYUhSWlNGaHJXblV5Y0RKMldGZEVNMWRTZVRJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NzEvYWNtZS93aXJlL29yZGVyL25wa1hxUnNnWTJRTk1PbWpHMFVIRk1weHZkVEZEeTdPL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTFRDQjRBSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBRnZ5OFFDYkFqYUVKckhhWmFzMTZRcnh4TXF0TWZja0RfTzlZaUVuRWtrdW9Id3dlZ1lKS29aSWh2Y05BUWtPTVcwd2F6QnBCZ05WSFJFRVlqQmdoanRwYlRwM2FYSmxZWEJ3UFZsalVXOXNPWGR1VkRKaFJrNUVRWGN0ZG1aMlJGRXZOREZqWlRNM1pqY3pORGxpWVdVeE1FQjNhWEpsTG1OdmJZWWhhVzA2ZDJseVpXRndjRDBsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dE1BVUdBeXRsY0FOQkFHTC1wbC1QSnFGZzNYVzZsdURFa3hkNVllTld6LV9rQUFjVmx0NHk0NmI2UjdRbGJhcUVpN1VLb3BDZVRhM25sZ3dnYXFicFFPSVI2NmlINkU0azZnTSJ9",
  "signature": "W5K4g3fnETNIZdEphU6-kTqCGiHFo9yyZQWSphI_CyiIilQaoaPsDOtwnouPG_fD2kQKWRRMvfg6D5kXbtuyBA"
}
```
```json
{
  "payload": {
    "csr": "MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAFvy8QCbAjaEJrHaZas16QrxxMqtMfckD_O9YiEnEkkuoHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJlYXBwPVljUW9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJlLmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANBAGL-pl-PJqFg3XW6luDEkxd5YeNWz-_kAAcVlt4y46b6R7QlbaqEi7UKopCeTa3nlgwgaqbpQOIR66iH6E4k6gM"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32871/acme/wire/account/713xcnRAaXekXeWmfBjDjqMiMtB8arDi",
    "nonce": "OVR3Y0R0U2VMRENXaHRZSFhrWnUycDJ2WFdEM1dSeTI",
    "typ": "JWT",
    "url": "https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAFvy8QCbAjaEJrHaZas16QrxxMqtMfck
D/O9YiEnEkkuoHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJl
YXBwPVljUW9sOXduVDJhRk5EQXctdmZ2RFEvNDFjZTM3ZjczNDliYWUxMEB3aXJl
LmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANB
AGL+pl+PJqFg3XW6luDEkxd5YeNWz+/kAAcVlt4y46b6R7QlbaqEi7UKopCeTa3n
lgwgaqbpQOIR66iH6E4k6gM=
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
                    5b:f2:f1:00:9b:02:36:84:26:b1:da:65:ab:35:e9:
                    0a:f1:c4:ca:ad:31:f7:24:0f:f3:bd:62:21:27:12:
                    49:2e
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com, URI:im:wireapp=%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        62:fe:a6:5f:8f:26:a1:60:dd:75:ba:96:e0:c4:93:17:79:61:
        e3:56:cf:ef:e4:00:07:15:96:de:32:e3:a6:fa:47:b4:25:6d:
        aa:84:8b:b5:0a:a2:90:9e:4d:ad:e7:96:0c:20:6a:a6:e9:40:
        e2:11:eb:a8:87:e8:4e:24:ea:03

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32871/acme/wire/directory>;rel="index"
location: https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O
replay-nonce: YmxVM1ZZTkQwZzVFeTV3VGEzbTAxM0gzRWxKZkd0SEg
vary: Origin
```
```json
{
  "certificate": "https://stepca:32871/acme/wire/certificate/U1w1EfAyZrVZfoBOe47YwDlJCaMwfDHS",
  "status": "valid",
  "finalize": "https://stepca:32871/acme/wire/order/npkXqRsgY2QNMOmjG0UHFMpxvdTFDy7O/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32871/acme/wire/authz/8HD5eXHRdm25bVcWoJm6SgiymuRfd9Ak"
  ],
  "expires": "2024-01-04T09:09:02Z",
  "notBefore": "2024-01-03T09:09:02.258565Z",
  "notAfter": "2033-12-31T09:09:02.258565Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32871/acme/wire/certificate/U1w1EfAyZrVZfoBOe47YwDlJCaMwfDHS
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODcxL2FjbWUvd2lyZS9hY2NvdW50LzcxM3hjblJBYVhla1hlV21mQmpEanFNaU10QjhhckRpIiwidHlwIjoiSldUIiwibm9uY2UiOiJZbXhWTTFaWlRrUXdaelZGZVRWM1ZHRXpiVEF4TTBnelJXeEtaa2QwU0VnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NzEvYWNtZS93aXJlL2NlcnRpZmljYXRlL1UxdzFFZkF5WnJWWmZvQk9lNDdZd0RsSkNhTXdmREhTIn0",
  "payload": "",
  "signature": "hC8JTmi3lpHu0wCZBB4aqdSRAkQuLFUdDA9hwmx-z0tTR1unf8VXbqXlmlTCrMzTgWbemj4GKMQUEUsHPZQ5BQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32871/acme/wire/account/713xcnRAaXekXeWmfBjDjqMiMtB8arDi",
    "nonce": "YmxVM1ZZTkQwZzVFeTV3VGEzbTAxM0gzRWxKZkd0SEg",
    "typ": "JWT",
    "url": "https://stepca:32871/acme/wire/certificate/U1w1EfAyZrVZfoBOe47YwDlJCaMwfDHS"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32871/acme/wire/directory>;rel="index"
replay-nonce: UWVLbGp3V2J3UGNJQlNHdmRpUkxaNnFNV1k0OER5c3k
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAcCgAwIBAgIRALpe9De7OMn+5X4uh9SsAJIwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMTAzMDkwOTAyWhcNMzMxMjMxMDkwOTAyWjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQBb8vEAmwI2hCax2mWr\nNekK8cTKrTH3JA/zvWIhJxJJLqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFIOQZ6qg6bhM77sxlJp14PE7R3b4MB8G\nA1UdIwQYMBaAFHemXHbCUMF+KEJ8TtElTGvKYKJrMGkGA1UdEQRiMGCGIWltOndp\ncmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY7aW06d2lyZWFwcD1ZY1FvbDl3\nblQyYUZOREF3LXZmdkRRLzQxY2UzN2Y3MzQ5YmFlMTBAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIEimjd3r\n8DNwSJjuF+oVE+yZnGBaBPGpP8R/2OEWDPdcAiEA+BVVD/hfKZvyMw+eFo3kr9rp\nk64t0kL2le7FUrvBfRc=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBujCCAV+gAwIBAgIRAOg54SZmgxHsypO6vRovLFQwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDEwMzA5\nMDkwMFoXDTMzMTIzMTA5MDkwMFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATS\nTN229lDPterdV8ms9s7lebNqEaIbQrTh1of40hkRBth3yox07++jbdMCGPm2Ypj2\n8yt/Miw5Co4NRFrW91uuo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUd6ZcdsJQwX4oQnxO0SVMa8pgomswHwYDVR0jBBgw\nFoAUCA+5qxXG8qYu0sqg3UtNRzBSX1IwCgYIKoZIzj0EAwIDSQAwRgIhAKols5xZ\nTxwHPhAwkr7S6aLmYyLRXX09g3jmUrY0WH31AiEA/oZKY6XT0lUQp5Hwq8s/geDT\n7wSALoaMRh/xxUq26/w=\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRALpe9De7OMn+5X4uh9SsAJIwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMTAzMDkwOTAyWhcNMzMxMjMxMDkwOTAyWjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQBb8vEAmwI2hCax2mWr
NekK8cTKrTH3JA/zvWIhJxJJLqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFIOQZ6qg6bhM77sxlJp14PE7R3b4MB8G
A1UdIwQYMBaAFHemXHbCUMF+KEJ8TtElTGvKYKJrMGkGA1UdEQRiMGCGIWltOndp
cmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY7aW06d2lyZWFwcD1ZY1FvbDl3
blQyYUZOREF3LXZmdkRRLzQxY2UzN2Y3MzQ5YmFlMTBAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIEimjd3r
8DNwSJjuF+oVE+yZnGBaBPGpP8R/2OEWDPdcAiEA+BVVD/hfKZvyMw+eFo3kr9rp
k64t0kL2le7FUrvBfRc=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ba:5e:f4:37:bb:38:c9:fe:e5:7e:2e:87:d4:ac:00:92
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan  3 09:09:02 2024 GMT
            Not After : Dec 31 09:09:02 2033 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    5b:f2:f1:00:9b:02:36:84:26:b1:da:65:ab:35:e9:
                    0a:f1:c4:ca:ad:31:f7:24:0f:f3:bd:62:21:27:12:
                    49:2e
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                83:90:67:AA:A0:E9:B8:4C:EF:BB:31:94:9A:75:E0:F1:3B:47:76:F8
            X509v3 Authority Key Identifier: 
                77:A6:5C:76:C2:50:C1:7E:28:42:7C:4E:D1:25:4C:6B:CA:60:A2:6B
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=%40alice_wire@wire.com, URI:im:wireapp=YcQol9wnT2aFNDAw-vfvDQ/41ce37f7349bae10@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:48:a6:8d:dd:eb:f0:33:70:48:98:ee:17:ea:15:
        13:ec:99:9c:60:5a:04:f1:a9:3f:c4:7f:d8:e1:16:0c:f7:5c:
        02:21:00:f8:15:55:0f:f8:5f:29:9b:f2:33:0f:9e:16:8d:e4:
        af:da:e9:93:ae:2d:d2:42:f6:95:ee:c5:52:bb:c1:7d:17

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBujCCAV+gAwIBAgIRAOg54SZmgxHsypO6vRovLFQwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDEwMzA5
MDkwMFoXDTMzMTIzMTA5MDkwMFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATS
TN229lDPterdV8ms9s7lebNqEaIbQrTh1of40hkRBth3yox07++jbdMCGPm2Ypj2
8yt/Miw5Co4NRFrW91uuo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUd6ZcdsJQwX4oQnxO0SVMa8pgomswHwYDVR0jBBgw
FoAUCA+5qxXG8qYu0sqg3UtNRzBSX1IwCgYIKoZIzj0EAwIDSQAwRgIhAKols5xZ
TxwHPhAwkr7S6aLmYyLRXX09g3jmUrY0WH31AiEA/oZKY6XT0lUQp5Hwq8s/geDT
7wSALoaMRh/xxUq26/w=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            e8:39:e1:26:66:83:11:ec:ca:93:ba:bd:1a:2f:2c:54
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan  3 09:09:00 2024 GMT
            Not After : Dec 31 09:09:00 2033 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:d2:4c:dd:b6:f6:50:cf:b5:ea:dd:57:c9:ac:f6:
                    ce:e5:79:b3:6a:11:a2:1b:42:b4:e1:d6:87:f8:d2:
                    19:11:06:d8:77:ca:8c:74:ef:ef:a3:6d:d3:02:18:
                    f9:b6:62:98:f6:f3:2b:7f:32:2c:39:0a:8e:0d:44:
                    5a:d6:f7:5b:ae
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                77:A6:5C:76:C2:50:C1:7E:28:42:7C:4E:D1:25:4C:6B:CA:60:A2:6B
            X509v3 Authority Key Identifier: 
                08:0F:B9:AB:15:C6:F2:A6:2E:D2:CA:A0:DD:4B:4D:47:30:52:5F:52
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:aa:25:b3:9c:59:4f:1c:07:3e:10:30:92:be:
        d2:e9:a2:e6:63:22:d1:5d:7d:3d:83:78:e6:52:b6:34:58:7d:
        f5:02:21:00:fe:86:4a:63:a5:d3:d2:55:10:a7:91:f0:ab:cb:
        3f:81:e0:d3:ef:04:80:2e:86:8c:46:1f:f1:c5:4a:b6:eb:fc

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBjjCCATWgAwIBAgIQIQmuB+qpqVsxrRoCk5oCUjAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTAzMDkw
ODU5WhcNMzMxMjMxMDkwODU5WjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3
aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASj1zhoQdIfWadZ
ir33OnG1pPmzRBiN0YIw38Mx9zIzBc9J/UUspmGoq5B6eVCUYY76MyYVEy3HD9j/
6YCc4oooo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd
BgNVHQ4EFgQUCA+5qxXG8qYu0sqg3UtNRzBSX1IwCgYIKoZIzj0EAwIDRwAwRAIg
LrFUJOOMSia+kiEmZ3Aa0dT6SJyXB296pEfOF/nAVjwCIGpcVqOcbgLhJ9Tj48iE
V41b8FEvUXPqKNo21TYNtIsz
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            21:09:ae:07:ea:a9:a9:5b:31:ad:1a:02:93:9a:02:52
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan  3 09:08:59 2024 GMT
            Not After : Dec 31 09:08:59 2033 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:a3:d7:38:68:41:d2:1f:59:a7:59:8a:bd:f7:3a:
                    71:b5:a4:f9:b3:44:18:8d:d1:82:30:df:c3:31:f7:
                    32:33:05:cf:49:fd:45:2c:a6:61:a8:ab:90:7a:79:
                    50:94:61:8e:fa:33:26:15:13:2d:c7:0f:d8:ff:e9:
                    80:9c:e2:8a:28
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                08:0F:B9:AB:15:C6:F2:A6:2E:D2:CA:A0:DD:4B:4D:47:30:52:5F:52
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:2e:b1:54:24:e3:8c:4a:26:be:92:21:26:67:70:
        1a:d1:d4:fa:48:9c:97:07:6f:7a:a4:47:ce:17:f9:c0:56:3c:
        02:20:6a:5c:56:a3:9c:6e:02:e1:27:d4:e3:e3:c8:84:57:8d:
        5b:f0:51:2f:51:73:ea:28:da:36:d5:36:0d:b4:8b:33

```

openssl verify chain ✅