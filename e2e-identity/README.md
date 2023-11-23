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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/9ad1bac52999a04a/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/sJHQa965f6n1AEpiYx8mAFVj8Jq7dOCL
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/tKYqHAOd4hlpfQ84bpko2ez4vsXOON16
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/QBn00Pnr9oXNbX3rSEjCyRDuHNDmJ8rF
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32921/acme/wire/directory
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
  "newNonce": "https://stepca:32921/acme/wire/new-nonce",
  "newAccount": "https://stepca:32921/acme/wire/new-account",
  "newOrder": "https://stepca:32921/acme/wire/new-order",
  "revokeCert": "https://stepca:32921/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32921/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32921/acme/wire/directory>;rel="index"
replay-nonce: eUw2eG5jWXRPTGp5bzRFeVN1b2lJb2JXcHRvWnVKb1g
vary: Origin
```
```text
eUw2eG5jWXRPTGp5bzRFeVN1b2lJb2JXcHRvWnVKb1g
```
#### 5. create a new account
```http request
POST https://stepca:32921/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ing3X0sybDd3cGNLMFl6Ym1wek0yQkJHZWRvU1dUR1VzQmJpMUxJdDNhWFUifSwibm9uY2UiOiJlVXcyZUc1aldYUlBUR3A1YnpSRmVWTjFiMmxKYjJKWGNIUnZXblZLYjFnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjEvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "xhheK_2HKnaBtTzdUf3Krgtf-gpGrwYuj_nLHXVqg2aFbKaugIFe1vNsMO_6dtMKo_kJRmWC6GkRJ0umr6WRDA"
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
      "x": "x7_K2l7wpcK0YzbmpzM2BBGedoSWTGUsBbi1LIt3aXU"
    },
    "nonce": "eUw2eG5jWXRPTGp5bzRFeVN1b2lJb2JXcHRvWnVKb1g",
    "typ": "JWT",
    "url": "https://stepca:32921/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32921/acme/wire/directory>;rel="index"
location: https://stepca:32921/acme/wire/account/NiJxQqtQvEEG6Hn5N96XxKoJP4jjo9S9
replay-nonce: MGdLWEFLclk2M2xNRDFFTDFHQ3lZY1VMRGhsQ1RwREE
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32921/acme/wire/account/NiJxQqtQvEEG6Hn5N96XxKoJP4jjo9S9/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32921/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTIxL2FjbWUvd2lyZS9hY2NvdW50L05pSnhRcXRRdkVFRzZIbjVOOTZYeEtvSlA0ampvOVM5IiwidHlwIjoiSldUIiwibm9uY2UiOiJNR2RMV0VGTGNsazJNMnhOUkRGRlRERkhRM2xaWTFWTVJHaHNRMVJ3UkVFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjEvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9QjJTNi16NFpRcW1XT3Q2QmFYSWZmdy85YWQxYmFjNTI5OTlhMDRhQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0xMS0yM1QxNzoxODozNy4zNzI1NThaIiwibm90QWZ0ZXIiOiIyMDMzLTExLTIwVDE3OjE4OjM3LjM3MjU1OFoifQ",
  "signature": "MEcOfb3OIto0Fo7sD0X6hBkszQRzlW4JZMF8iodfGmrASDJSiO6MnIZC1WCGs9jDlDQtDye-AqueG08AiIJ4AA"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2033-11-20T17:18:37.372558Z",
    "notBefore": "2023-11-23T17:18:37.372558Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32921/acme/wire/account/NiJxQqtQvEEG6Hn5N96XxKoJP4jjo9S9",
    "nonce": "MGdLWEFLclk2M2xNRDFFTDFHQ3lZY1VMRGhsQ1RwREE",
    "typ": "JWT",
    "url": "https://stepca:32921/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32921/acme/wire/directory>;rel="index"
location: https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP
replay-nonce: NFhYTEdycVdleUdQZzJIUGc5bERLZzhQTUlSMUZuUXY
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32921/acme/wire/authz/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf"
  ],
  "expires": "2023-11-24T17:18:37Z",
  "notBefore": "2023-11-23T17:18:37.372558Z",
  "notAfter": "2033-11-20T17:18:37.372558Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32921/acme/wire/authz/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTIxL2FjbWUvd2lyZS9hY2NvdW50L05pSnhRcXRRdkVFRzZIbjVOOTZYeEtvSlA0ampvOVM5IiwidHlwIjoiSldUIiwibm9uY2UiOiJORmhZVEVkeWNWZGxlVWRRWnpKSVVHYzViRVJMWnpoUVRVbFNNVVp1VVhZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjEvYWNtZS93aXJlL2F1dGh6L3NWN1NBZEhUZFpUU1ZzclFhd2pOZkpxOWEwaHVlMHFmIn0",
  "payload": "",
  "signature": "Sy658I0PGg5VY9DegYFXWblrXrUgcSxvWPZNcX3Ux5AgIKEEjJbV8izi2_QKR4riMwg8YrSVudbCRoRFSpSWCw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32921/acme/wire/account/NiJxQqtQvEEG6Hn5N96XxKoJP4jjo9S9",
    "nonce": "NFhYTEdycVdleUdQZzJIUGc5bERLZzhQTUlSMUZuUXY",
    "typ": "JWT",
    "url": "https://stepca:32921/acme/wire/authz/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32921/acme/wire/directory>;rel="index"
location: https://stepca:32921/acme/wire/authz/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf
replay-nonce: UVpSZnhKamdENFg5eTMzMzNENllzbG1NRTdXcU5XbUg
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2023-11-24T17:18:37Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/tKYqHAOd4hlpfQ84bpko2ez4vsXOON16",
      "status": "pending",
      "token": "AxwqbS7EaggPYbYkIlt6QuCvnB59K59F",
      "target": "http://dex:19182/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/sJHQa965f6n1AEpiYx8mAFVj8Jq7dOCL",
      "status": "pending",
      "token": "AxwqbS7EaggPYbYkIlt6QuCvnB59K59F",
      "target": "http://wire.com:24519/clients/9ad1bac52999a04a/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:24519/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
c3cxRVpuZ0diNDR3VWdwWHNhbG1Vc3NjbGtTZlUxYnE
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieDdfSzJsN3dwY0swWXpibXB6TTJCQkdlZG9TV1RHVXNCYmkxTEl0M2FYVSJ9fQ.eyJpYXQiOjE3MDA3NTYzMTcsImV4cCI6MTcwMDc2MzUxNywibmJmIjoxNzAwNzU2MzE3LCJzdWIiOiJpbTp3aXJlYXBwPUIyUzYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbSIsImp0aSI6IjE5NmM4ZjY0LWM0OWUtNGQ5OC1hMTViLTQ0NjcxYmI4NTkyZiIsIm5vbmNlIjoiYzNjeFJWcHVaMGRpTkRSM1ZXZHdXSE5oYkcxVmMzTmpiR3RUWmxVeFluRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ1MTkvY2xpZW50cy85YWQxYmFjNTI5OTlhMDRhL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJBeHdxYlM3RWFnZ1BZYllrSWx0NlF1Q3ZuQjU5SzU5RiIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.xK9N9LipNZOgDIW39PyxRn6GzvJx__bEcuP3V_oWBpLBvw7OLcN1DUWWyXJGYHk9k0M5zW8h7AuHjROkEM92Ag)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieDdfSzJsN3dwY0swWXpibXB6TTJCQkdl
ZG9TV1RHVXNCYmkxTEl0M2FYVSJ9fQ.eyJpYXQiOjE3MDA3NTYzMTcsImV4cCI6M
TcwMDc2MzUxNywibmJmIjoxNzAwNzU2MzE3LCJzdWIiOiJpbTp3aXJlYXBwPUIyU
zYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbSIsI
mp0aSI6IjE5NmM4ZjY0LWM0OWUtNGQ5OC1hMTViLTQ0NjcxYmI4NTkyZiIsIm5vb
mNlIjoiYzNjeFJWcHVaMGRpTkRSM1ZXZHdXSE5oYkcxVmMzTmpiR3RUWmxVeFluR
SIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ1MTkvY2xpZ
W50cy85YWQxYmFjNTI5OTlhMDRhL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJBeHdxY
lM3RWFnZ1BZYllrSWx0NlF1Q3ZuQjU5SzU5RiIsImhhbmRsZSI6ImltOndpcmVhc
HA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.xK9N9LipN
ZOgDIW39PyxRn6GzvJx__bEcuP3V_oWBpLBvw7OLcN1DUWWyXJGYHk9k0M5zW8h7
AuHjROkEM92Ag
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "x7_K2l7wpcK0YzbmpzM2BBGedoSWTGUsBbi1LIt3aXU"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "AxwqbS7EaggPYbYkIlt6QuCvnB59K59F",
  "exp": 1700763517,
  "handle": "im:wireapp=%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:24519/clients/9ad1bac52999a04a/access-token",
  "iat": 1700756317,
  "jti": "196c8f64-c49e-4d98-a15b-44671bb8592f",
  "nbf": 1700756317,
  "nonce": "c3cxRVpuZ0diNDR3VWdwWHNhbG1Vc3NjbGtTZlUxYnE",
  "sub": "im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINmgnc4XYjz4IXwNiQDhs7WstR39rLDqPuYn6cXil6ba
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAx7/K2l7wpcK0YzbmpzM2BBGedoSWTGUsBbi1LIt3aXU=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:24519/clients/9ad1bac52999a04a/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZURkZlN6SnNOM2R3WTBzd1dYcGliWEI2VFRKQ1FrZGxaRzlUVjFSSFZYTkNZbWt4VEVsME0yRllWU0o5ZlEuZXlKcFlYUWlPakUzTURBM05UWXpNVGNzSW1WNGNDSTZNVGN3TURjMk16VXhOeXdpYm1KbUlqb3hOekF3TnpVMk16RTNMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVUl5VXpZdGVqUmFVWEZ0VjA5ME5rSmhXRWxtWm5jdk9XRmtNV0poWXpVeU9UazVZVEEwWVVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpFNU5tTTRaalkwTFdNME9XVXROR1E1T0MxaE1UVmlMVFEwTmpjeFltSTROVGt5WmlJc0ltNXZibU5sSWpvaVl6TmplRkpXY0hWYU1HUnBUa1JTTTFaWFpIZFhTRTVvWWtjeFZtTXpUbXBpUjNSVVdteFZlRmx1UlNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qUTFNVGt2WTJ4cFpXNTBjeTg1WVdReFltRmpOVEk1T1RsaE1EUmhMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lKQmVIZHhZbE0zUldGbloxQlpZbGxyU1d4ME5sRjFRM1p1UWpVNVN6VTVSaUlzSW1oaGJtUnNaU0k2SW1sdE9uZHBjbVZoY0hBOUpUUXdZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW5SbFlXMGlPaUozYVhKbEluMC54SzlOOUxpcE5aT2dESVczOVB5eFJuNkd6dkp4X19iRWN1UDNWX29XQnBMQnZ3N09MY04xRFVXV3lYSkdZSGs5azBNNXpXOGg3QXVIalJPa0VNOTJBZw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im5tSjktd3R0dUpXYUVNNHRMaERQUXlTb2lGckNCUFg2cGNyTkFnLTIxT00ifX0.eyJpYXQiOjE3MDA3NTYzMTcsImV4cCI6MTcwMDc2MDI3NywibmJmIjoxNzAwNzU2MzE3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ1MTkvY2xpZW50cy85YWQxYmFjNTI5OTlhMDRhL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9QjJTNi16NFpRcW1XT3Q2QmFYSWZmdy85YWQxYmFjNTI5OTlhMDRhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NTE5L2NsaWVudHMvOWFkMWJhYzUyOTk5YTA0YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiIwYzI3YTg0ZC1lMGFlLTQ1MmYtYjM4MC03ZjM5MjVhNWMzYTIiLCJub25jZSI6ImMzY3hSVnB1WjBkaU5EUjNWV2R3V0hOaGJHMVZjM05qYkd0VFpsVXhZbkUiLCJjaGFsIjoiQXh3cWJTN0VhZ2dQWWJZa0lsdDZRdUN2bkI1OUs1OUYiLCJjbmYiOnsia2lkIjoiekF4WThHdlRxUGdxekNOUmxDUTJiWVhteExyeW5MT19yRU0xalV2TFRmYyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVEZGZTekpzTjNkd1kwc3dXWHBpYlhCNlRUSkNRa2RsWkc5VFYxUkhWWE5DWW1reFRFbDBNMkZZVlNKOWZRLmV5SnBZWFFpT2pFM01EQTNOVFl6TVRjc0ltVjRjQ0k2TVRjd01EYzJNelV4Tnl3aWJtSm1Jam94TnpBd056VTJNekUzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFVJeVV6WXRlalJhVVhGdFYwOTBOa0poV0VsbVpuY3ZPV0ZrTVdKaFl6VXlPVGs1WVRBMFlVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqRTVObU00WmpZMExXTTBPV1V0TkdRNU9DMWhNVFZpTFRRME5qY3hZbUk0TlRreVppSXNJbTV2Ym1ObElqb2lZek5qZUZKV2NIVmFNR1JwVGtSU00xWlhaSGRYU0U1b1lrY3hWbU16VG1waVIzUlVXbXhWZUZsdVJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalExTVRrdlkyeHBaVzUwY3k4NVlXUXhZbUZqTlRJNU9UbGhNRFJoTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSkJlSGR4WWxNM1JXRm5aMUJaWWxsclNXeDBObEYxUTNadVFqVTVTelU1UmlJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAueEs5TjlMaXBOWk9nRElXMzlQeXhSbjZHenZKeF9fYkVjdVAzVl9vV0JwTEJ2dzdPTGNOMURVV1d5WEpHWUhrOWswTTV6VzhoN0F1SGpST2tFTTkyQWciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUIyUzYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.A-xNYKJQLCZPo-c_vkB3NXBDp0XK42Sf0240rip5JmN4oGe56Cp7cB9cKrH0a1Po8X6qBI0OyPe36XR-pE4-Dw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im5tSjktd3R0dUpXYUVNNHRMaERQUXlTb2lGckNCUFg2cGNyTkFnLTIxT00ifX0.eyJpYXQiOjE3MDA3NTYzMTcsImV4cCI6MTcwMDc2MDI3NywibmJmIjoxNzAwNzU2MzE3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ1MTkvY2xpZW50cy85YWQxYmFjNTI5OTlhMDRhL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9QjJTNi16NFpRcW1XT3Q2QmFYSWZmdy85YWQxYmFjNTI5OTlhMDRhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NTE5L2NsaWVudHMvOWFkMWJhYzUyOTk5YTA0YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiIwYzI3YTg0ZC1lMGFlLTQ1MmYtYjM4MC03ZjM5MjVhNWMzYTIiLCJub25jZSI6ImMzY3hSVnB1WjBkaU5EUjNWV2R3V0hOaGJHMVZjM05qYkd0VFpsVXhZbkUiLCJjaGFsIjoiQXh3cWJTN0VhZ2dQWWJZa0lsdDZRdUN2bkI1OUs1OUYiLCJjbmYiOnsia2lkIjoiekF4WThHdlRxUGdxekNOUmxDUTJiWVhteExyeW5MT19yRU0xalV2TFRmYyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVEZGZTekpzTjNkd1kwc3dXWHBpYlhCNlRUSkNRa2RsWkc5VFYxUkhWWE5DWW1reFRFbDBNMkZZVlNKOWZRLmV5SnBZWFFpT2pFM01EQTNOVFl6TVRjc0ltVjRjQ0k2TVRjd01EYzJNelV4Tnl3aWJtSm1Jam94TnpBd056VTJNekUzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFVJeVV6WXRlalJhVVhGdFYwOTBOa0poV0VsbVpuY3ZPV0ZrTVdKaFl6VXlPVGs1WVRBMFlVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqRTVObU00WmpZMExXTTBPV1V0TkdRNU9DMWhNVFZpTFRRME5qY3hZbUk0TlRreVppSXNJbTV2Ym1ObElqb2lZek5qZUZKV2NIVmFNR1JwVGtSU00xWlhaSGRYU0U1b1lrY3hWbU16VG1waVIzUlVXbXhWZUZsdVJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalExTVRrdlkyeHBaVzUwY3k4NVlXUXhZbUZqTlRJNU9UbGhNRFJoTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSkJlSGR4WWxNM1JXRm5aMUJaWWxsclNXeDBObEYxUTNadVFqVTVTelU1UmlJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAueEs5TjlMaXBOWk9nRElXMzlQeXhSbjZHenZKeF9fYkVjdVAzVl9vV0JwTEJ2dzdPTGNOMURVV1d5WEpHWUhrOWswTTV6VzhoN0F1SGpST2tFTTkyQWciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUIyUzYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.A-xNYKJQLCZPo-c_vkB3NXBDp0XK42Sf0240rip5JmN4oGe56Cp7cB9cKrH0a1Po8X6qBI0OyPe36XR-pE4-Dw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6Im5tSjktd3R0dUpXYUVNNHRMaERQUXlTb2lG
ckNCUFg2cGNyTkFnLTIxT00ifX0.eyJpYXQiOjE3MDA3NTYzMTcsImV4cCI6MTcw
MDc2MDI3NywibmJmIjoxNzAwNzU2MzE3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQ1MTkvY2xpZW50cy85YWQxYmFjNTI5OTlhMDRhL2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9QjJTNi16NFpRcW1XT3Q2QmFYSWZmdy85YWQxYmFjNTI5
OTlhMDRhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NTE5L2Ns
aWVudHMvOWFkMWJhYzUyOTk5YTA0YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiIwYzI3
YTg0ZC1lMGFlLTQ1MmYtYjM4MC03ZjM5MjVhNWMzYTIiLCJub25jZSI6ImMzY3hS
VnB1WjBkaU5EUjNWV2R3V0hOaGJHMVZjM05qYkd0VFpsVXhZbkUiLCJjaGFsIjoi
QXh3cWJTN0VhZ2dQWWJZa0lsdDZRdUN2bkI1OUs1OUYiLCJjbmYiOnsia2lkIjoi
ekF4WThHdlRxUGdxekNOUmxDUTJiWVhteExyeW5MT19yRU0xalV2TFRmYyJ9LCJw
cm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJ
aXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lM
Q0o0SWpvaWVEZGZTekpzTjNkd1kwc3dXWHBpYlhCNlRUSkNRa2RsWkc5VFYxUkhW
WE5DWW1reFRFbDBNMkZZVlNKOWZRLmV5SnBZWFFpT2pFM01EQTNOVFl6TVRjc0lt
VjRjQ0k2TVRjd01EYzJNelV4Tnl3aWJtSm1Jam94TnpBd056VTJNekUzTENKemRX
SWlPaUpwYlRwM2FYSmxZWEJ3UFVJeVV6WXRlalJhVVhGdFYwOTBOa0poV0VsbVpu
Y3ZPV0ZrTVdKaFl6VXlPVGs1WVRBMFlVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklq
RTVObU00WmpZMExXTTBPV1V0TkdRNU9DMWhNVFZpTFRRME5qY3hZbUk0TlRreVpp
SXNJbTV2Ym1ObElqb2lZek5qZUZKV2NIVmFNR1JwVGtSU00xWlhaSGRYU0U1b1lr
Y3hWbU16VG1waVIzUlVXbXhWZUZsdVJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RI
VWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalExTVRrdlkyeHBaVzUwY3k4NVlX
UXhZbUZqTlRJNU9UbGhNRFJoTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9p
SkJlSGR4WWxNM1JXRm5aMUJaWWxsclNXeDBObEYxUTNadVFqVTVTelU1UmlJc0lt
aGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FY
SmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAueEs5TjlMaXBOWk9nRElXMzlQ
eXhSbjZHenZKeF9fYkVjdVAzVl9vV0JwTEJ2dzdPTGNOMURVV1d5WEpHWUhrOWsw
TTV6VzhoN0F1SGpST2tFTTkyQWciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUIy
UzYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbSIs
ImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.A-xNYKJQ
LCZPo-c_vkB3NXBDp0XK42Sf0240rip5JmN4oGe56Cp7cB9cKrH0a1Po8X6qBI0O
yPe36XR-pE4-Dw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "nmJ9-wttuJWaEM4tLhDPQySoiFrCBPX6pcrNAg-21OM"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:24519/clients/9ad1bac52999a04a/access-token",
  "chal": "AxwqbS7EaggPYbYkIlt6QuCvnB59K59F",
  "client_id": "im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com",
  "cnf": {
    "kid": "zAxY8GvTqPgqzCNRlCQ2bYXmxLrynLO_rEM1jUvLTfc"
  },
  "exp": 1700760277,
  "iat": 1700756317,
  "iss": "http://wire.com:24519/clients/9ad1bac52999a04a/access-token",
  "jti": "0c27a84d-e0ae-452f-b380-7f3925a5c3a2",
  "nbf": 1700756317,
  "nonce": "c3cxRVpuZ0diNDR3VWdwWHNhbG1Vc3NjbGtTZlUxYnE",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieDdfSzJsN3dwY0swWXpibXB6TTJCQkdlZG9TV1RHVXNCYmkxTEl0M2FYVSJ9fQ.eyJpYXQiOjE3MDA3NTYzMTcsImV4cCI6MTcwMDc2MzUxNywibmJmIjoxNzAwNzU2MzE3LCJzdWIiOiJpbTp3aXJlYXBwPUIyUzYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbSIsImp0aSI6IjE5NmM4ZjY0LWM0OWUtNGQ5OC1hMTViLTQ0NjcxYmI4NTkyZiIsIm5vbmNlIjoiYzNjeFJWcHVaMGRpTkRSM1ZXZHdXSE5oYkcxVmMzTmpiR3RUWmxVeFluRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ1MTkvY2xpZW50cy85YWQxYmFjNTI5OTlhMDRhL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJBeHdxYlM3RWFnZ1BZYllrSWx0NlF1Q3ZuQjU5SzU5RiIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.xK9N9LipNZOgDIW39PyxRn6GzvJx__bEcuP3V_oWBpLBvw7OLcN1DUWWyXJGYHk9k0M5zW8h7AuHjROkEM92Ag",
  "scope": "wire_client_id",
  "sub": "im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKsyYR9IQwM/ETYSwt05HpzyVs/shr3JKWihHQABmUKl
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAnmJ9+wttuJWaEM4tLhDPQySoiFrCBPX6pcrNAg+21OM=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/sJHQa965f6n1AEpiYx8mAFVj8Jq7dOCL
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTIxL2FjbWUvd2lyZS9hY2NvdW50L05pSnhRcXRRdkVFRzZIbjVOOTZYeEtvSlA0ampvOVM5IiwidHlwIjoiSldUIiwibm9uY2UiOiJVVnBTWm5oS2FtZEVORmc1ZVRNek16TkVObGx6YkcxTlJUZFhjVTVYYlVnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjEvYWNtZS93aXJlL2NoYWxsZW5nZS9zVjdTQWRIVGRaVFNWc3JRYXdqTmZKcTlhMGh1ZTBxZi9zSkhRYTk2NWY2bjFBRXBpWXg4bUFGVmo4SnE3ZE9DTCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltNXRTamt0ZDNSMGRVcFhZVVZOTkhSTWFFUlFVWGxUYjJsR2NrTkNVRmcyY0dOeVRrRm5MVEl4VDAwaWZYMC5leUpwWVhRaU9qRTNNREEzTlRZek1UY3NJbVY0Y0NJNk1UY3dNRGMyTURJM055d2libUptSWpveE56QXdOelUyTXpFM0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRMU1Ua3ZZMnhwWlc1MGN5ODVZV1F4WW1Gak5USTVPVGxoTURSaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5UWpKVE5pMTZORnBSY1cxWFQzUTJRbUZZU1dabWR5ODVZV1F4WW1Gak5USTVPVGxoTURSaFFIZHBjbVV1WTI5dElpd2lZWFZrSWpvaWFIUjBjRG92TDNkcGNtVXVZMjl0T2pJME5URTVMMk5zYVdWdWRITXZPV0ZrTVdKaFl6VXlPVGs1WVRBMFlTOWhZMk5sYzNNdGRHOXJaVzRpTENKcWRHa2lPaUl3WXpJM1lUZzBaQzFsTUdGbExUUTFNbVl0WWpNNE1DMDNaak01TWpWaE5XTXpZVElpTENKdWIyNWpaU0k2SW1NelkzaFNWbkIxV2pCa2FVNUVVak5XVjJSM1YwaE9hR0pITVZaak0wNXFZa2QwVkZwc1ZYaFpia1VpTENKamFHRnNJam9pUVhoM2NXSlROMFZoWjJkUVdXSlphMGxzZERaUmRVTjJia0kxT1VzMU9VWWlMQ0pqYm1ZaU9uc2lhMmxrSWpvaWVrRjRXVGhIZGxSeFVHZHhla05PVW14RFVUSmlXVmh0ZUV4eWVXNU1UMTl5UlUweGFsVjJURlJtWXlKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVdWRVpHWlRla3B6VGpOa2Qxa3djM2RYV0hCcFlsaENObFJVU2tOUmEyUnNXa2M1VkZZeFVraFdXRTVEV1cxcmVGUkZiREJOTWtaWlZsTktPV1pSTG1WNVNuQlpXRkZwVDJwRk0wMUVRVE5PVkZsNlRWUmpjMGx0VmpSalEwazJUVlJqZDAxRVl6Sk5lbFY0VG5sM2FXSnRTbTFKYW05NFRucEJkMDU2VlRKTmVrVXpURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGVkplVlY2V1hSbGFsSmhWVmhHZEZZd09UQk9hMHBvVjBWc2JWcHVZM1pQVjBaclRWZEthRmw2VlhsUFZHczFXVlJCTUZsVlFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2xxUlRWT2JVMDBXbXBaTUV4WFRUQlBWMVYwVGtkUk5VOURNV2hOVkZacFRGUlJNRTVxWTNoWmJVazBUbFJyZVZwcFNYTkpiVFYyWW0xT2JFbHFiMmxaZWs1cVpVWktWMk5JVm1GTlIxSndWR3RTVTAweFdsaGFTR1JZVTBVMWIxbHJZM2hXYlUxNlZHMXdhVkl6VWxWWGJYaFdaVVpzZFZKVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxFeFRWUnJkbGt5ZUhCYVZ6VXdZM2s0TlZsWFVYaFpiVVpxVGxSSk5VOVViR2hOUkZKb1RESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTa0psU0dSNFdXeE5NMUpYUm01YU1VSmFXV3hzY2xOWGVEQk9iRVl4VVROYWRWRnFWVFZUZWxVMVVtbEpjMGx0YUdoaWJWSnpXbE5KTmtsdGJIUlBibVJ3WTIxV2FHTklRVGxLVkZGM1dWZDRjRmt5Vm1aa01teDVXbFZDTTJGWVNteE1iVTUyWWxOSmMwbHVVbXhaVnpCcFQybEtNMkZZU214SmJqQXVlRXM1VGpsTWFYQk9XazluUkVsWE16bFFlWGhTYmpaSGVuWktlRjlmWWtWamRWQXpWbDl2VjBKd1RFSjJkemRQVEdOT01VUlZWMWQ1V0VwSFdVaHJPV3N3VFRWNlZ6aG9OMEYxU0dwU1QydEZUVGt5UVdjaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFVJeVV6WXRlalJhVVhGdFYwOTBOa0poV0VsbVpuY3ZPV0ZrTVdKaFl6VXlPVGs1WVRBMFlVQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvMUxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLkEteE5ZS0pRTENaUG8tY192a0IzTlhCRHAwWEs0MlNmMDI0MHJpcDVKbU40b0dlNTZDcDdjQjljS3JIMGExUG84WDZxQkkwT3lQZTM2WFItcEU0LUR3In0",
  "signature": "0XJFA3NsmxPhOw7bTsLesusyFThCwYrbarOBxSaV55AOSSnygsFoxET_TKMMGO2fw-dto2plHQu2PbzDRY8gCQ"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im5tSjktd3R0dUpXYUVNNHRMaERQUXlTb2lGckNCUFg2cGNyTkFnLTIxT00ifX0.eyJpYXQiOjE3MDA3NTYzMTcsImV4cCI6MTcwMDc2MDI3NywibmJmIjoxNzAwNzU2MzE3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ1MTkvY2xpZW50cy85YWQxYmFjNTI5OTlhMDRhL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9QjJTNi16NFpRcW1XT3Q2QmFYSWZmdy85YWQxYmFjNTI5OTlhMDRhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NTE5L2NsaWVudHMvOWFkMWJhYzUyOTk5YTA0YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiIwYzI3YTg0ZC1lMGFlLTQ1MmYtYjM4MC03ZjM5MjVhNWMzYTIiLCJub25jZSI6ImMzY3hSVnB1WjBkaU5EUjNWV2R3V0hOaGJHMVZjM05qYkd0VFpsVXhZbkUiLCJjaGFsIjoiQXh3cWJTN0VhZ2dQWWJZa0lsdDZRdUN2bkI1OUs1OUYiLCJjbmYiOnsia2lkIjoiekF4WThHdlRxUGdxekNOUmxDUTJiWVhteExyeW5MT19yRU0xalV2TFRmYyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVEZGZTekpzTjNkd1kwc3dXWHBpYlhCNlRUSkNRa2RsWkc5VFYxUkhWWE5DWW1reFRFbDBNMkZZVlNKOWZRLmV5SnBZWFFpT2pFM01EQTNOVFl6TVRjc0ltVjRjQ0k2TVRjd01EYzJNelV4Tnl3aWJtSm1Jam94TnpBd056VTJNekUzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFVJeVV6WXRlalJhVVhGdFYwOTBOa0poV0VsbVpuY3ZPV0ZrTVdKaFl6VXlPVGs1WVRBMFlVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqRTVObU00WmpZMExXTTBPV1V0TkdRNU9DMWhNVFZpTFRRME5qY3hZbUk0TlRreVppSXNJbTV2Ym1ObElqb2lZek5qZUZKV2NIVmFNR1JwVGtSU00xWlhaSGRYU0U1b1lrY3hWbU16VG1waVIzUlVXbXhWZUZsdVJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalExTVRrdlkyeHBaVzUwY3k4NVlXUXhZbUZqTlRJNU9UbGhNRFJoTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSkJlSGR4WWxNM1JXRm5aMUJaWWxsclNXeDBObEYxUTNadVFqVTVTelU1UmlJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAueEs5TjlMaXBOWk9nRElXMzlQeXhSbjZHenZKeF9fYkVjdVAzVl9vV0JwTEJ2dzdPTGNOMURVV1d5WEpHWUhrOWswTTV6VzhoN0F1SGpST2tFTTkyQWciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUIyUzYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.A-xNYKJQLCZPo-c_vkB3NXBDp0XK42Sf0240rip5JmN4oGe56Cp7cB9cKrH0a1Po8X6qBI0OyPe36XR-pE4-Dw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32921/acme/wire/account/NiJxQqtQvEEG6Hn5N96XxKoJP4jjo9S9",
    "nonce": "UVpSZnhKamdENFg5eTMzMzNENllzbG1NRTdXcU5XbUg",
    "typ": "JWT",
    "url": "https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/sJHQa965f6n1AEpiYx8mAFVj8Jq7dOCL"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32921/acme/wire/directory>;rel="index"
link: <https://stepca:32921/acme/wire/authz/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf>;rel="up"
location: https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/sJHQa965f6n1AEpiYx8mAFVj8Jq7dOCL
replay-nonce: MXhsUWRDSjdIRGFzRjdGQmpHSWlsNHdJd3ozaXlZdWw
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/sJHQa965f6n1AEpiYx8mAFVj8Jq7dOCL",
  "status": "valid",
  "token": "AxwqbS7EaggPYbYkIlt6QuCvnB59K59F",
  "target": "http://wire.com:24519/clients/9ad1bac52999a04a/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=qu_Qbw2MAy4be03KjtnvvnYe-jQE2M_06CwciDhSgzo&code_challenge=BuLUNmaqXn7Qi3Ou0MWnoN_EwDiJmR14i1_CqkjFINM
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:19182/dex/auth?response_type=code&client_id=wireapp&state=YfG-BX6QOYzHtqBaKU_J9w&code_challenge=BuLUNmaqXn7Qi3Ou0MWnoN_EwDiJmR14i1_CqkjFINM&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A24519%2Fcallback&scope=openid+profile&nonce=NR0jYMe_G4SE92haeLW3hg
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:19182/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpkWFZRVldWb1JrRlRWVkpqTjJOak5FOUpkMUpaUm5oMg==
```
```text
grant_type=authorization_code&code=xfeuqy3xioqg67ptj5yvnr7pr&code_verifier=qu_Qbw2MAy4be03KjtnvvnYe-jQE2M_06CwciDhSgzo&redirect_uri=http%3A%2F%2Fwire.com%3A24519%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2ZDUxOGIwZDA4NGQxZWU1M2JmNjdhZTdlMmUwNzc5OTk2NTRjYmIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5MTgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVUl5VXpZdGVqUmFVWEZ0VjA5ME5rSmhXRWxtWm5jdk9XRmtNV0poWXpVeU9UazVZVEEwWVVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4NDYzMTcsImlhdCI6MTcwMDc1OTkxNywibm9uY2UiOiJOUjBqWU1lX0c0U0U5MmhhZUxXM2hnIiwiYXRfaGFzaCI6ImRiTGwxY3cweEwzaXJkeFZvN2dWRXciLCJuYW1lIjoiaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.GsvTsKmZjOnFdIBdHiF0nP5thlRviJb0PkNNtE2koDDicwW83tva5Yra7QdarueWhO0C7lvJSOD4hYtg4llR_VUXSxY74zdeHLCM5gLwNSEvsjWHE4HHUktS0Kee4_QP4PkxgRWD5KR1MpjB5B8NpMBFqsKxr6caR9lD4CPq3uI2aCEddd-6h0w_Wtai2vRkppHEK54YgXhJ-6VJWqo0466buyPPqS-xDNHnoxtwnqfBo4uXQjj8VQXRdaHUwBL8Sb2wqvY2tzgVngEWCc6V07nnUNjzukwsVRw5Lgjy1SglfStAG6mP5Q336P1heyJy_lqPraukiAcnEuwGuc_Cmg",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2ZDUxOGIwZDA4NGQxZWU1M2JmNjdhZTdlMmUwNzc5OTk2NTRjYmIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5MTgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVUl5VXpZdGVqUmFVWEZ0VjA5ME5rSmhXRWxtWm5jdk9XRmtNV0poWXpVeU9UazVZVEEwWVVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4NDYzMTcsImlhdCI6MTcwMDc1OTkxNywibm9uY2UiOiJOUjBqWU1lX0c0U0U5MmhhZUxXM2hnIiwiYXRfaGFzaCI6ImJHa0hSaDFHalo4eHJta0Y2X3o1OWciLCJjX2hhc2giOiI1b1BIOTZUSjRVSU9yZzVOLVRRUC1nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.qwN_XQOM1EizAsCB4ycQR9eVJLhze05MuF0jO_2du59O3kNXundOiPgNuP5nY1_c_Mkt8G0Nsx4taJpcgoDAQr1ARJKTPLKZgkSBfXTtMpyfBxJmdROX4cJY1Ipw4-wdPnuFVDufbB-aowNRcYuKeOqXMtnFXwgEvZp4rpj502qmhbThsm98RfqbHMxelsEeXgTEx30PdQ1LfO-lWQzdEYA3m37zSF9sIJJdbkytNwu5EJlTXVsLQwTL2pr9CUNP884s1RckwTCXSHKEOZ6h4uP0araTUQ2Mhx1uX9dh3yBZ8sWrL4uFfKsRsIse6eq6UQPt-r289FZeWMjgom2ziw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2ZDUxOGIwZDA4NGQxZWU1M2JmNjdhZTdlMmUwNzc5OTk2NTRjYmIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5MTgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVUl5VXpZdGVqUmFVWEZ0VjA5ME5rSmhXRWxtWm5jdk9XRmtNV0poWXpVeU9UazVZVEEwWVVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4NDYzMTcsImlhdCI6MTcwMDc1OTkxNywibm9uY2UiOiJOUjBqWU1lX0c0U0U5MmhhZUxXM2hnIiwiYXRfaGFzaCI6ImJHa0hSaDFHalo4eHJta0Y2X3o1OWciLCJjX2hhc2giOiI1b1BIOTZUSjRVSU9yZzVOLVRRUC1nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.qwN_XQOM1EizAsCB4ycQR9eVJLhze05MuF0jO_2du59O3kNXundOiPgNuP5nY1_c_Mkt8G0Nsx4taJpcgoDAQr1ARJKTPLKZgkSBfXTtMpyfBxJmdROX4cJY1Ipw4-wdPnuFVDufbB-aowNRcYuKeOqXMtnFXwgEvZp4rpj502qmhbThsm98RfqbHMxelsEeXgTEx30PdQ1LfO-lWQzdEYA3m37zSF9sIJJdbkytNwu5EJlTXVsLQwTL2pr9CUNP884s1RckwTCXSHKEOZ6h4uP0araTUQ2Mhx1uX9dh3yBZ8sWrL4uFfKsRsIse6eq6UQPt-r289FZeWMjgom2ziw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2ZDUxOGIwZDA4NGQxZWU1M2JmNjdhZTdlMmUwNzc5OTk2NTRjYmIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5MTgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVUl5VXpZdGVqUmFVWEZ0VjA5ME5rSmhXRWxtWm5jdk9XRmtNV0poWXpVeU9UazVZVEEwWVVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4NDYzMTcsImlhdCI6MTcwMDc1OTkxNywibm9uY2UiOiJOUjBqWU1lX0c0U0U5MmhhZUxXM2hnIiwiYXRfaGFzaCI6ImJHa0hSaDFHalo4eHJta0Y2X3o1OWciLCJjX2hhc2giOiI1b1BIOTZUSjRVSU9yZzVOLVRRUC1nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.qwN_XQOM1EizAsCB4ycQR9eVJLhze05MuF0jO_2du59O3kNXundOiPgNuP5nY1_c_Mkt8G0Nsx4taJpcgoDAQr1ARJKTPLKZgkSBfXTtMpyfBxJmdROX4cJY1Ipw4-wdPnuFVDufbB-aowNRcYuKeOqXMtnFXwgEvZp4rpj502qmhbThsm98RfqbHMxelsEeXgTEx30PdQ1LfO-lWQzdEYA3m37zSF9sIJJdbkytNwu5EJlTXVsLQwTL2pr9CUNP884s1RckwTCXSHKEOZ6h4uP0araTUQ2Mhx1uX9dh3yBZ8sWrL4uFfKsRsIse6eq6UQPt-r289FZeWMjgom2ziw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2ZDUxOGIwZDA4NGQxZWU1M2JmNjdhZTdl
MmUwNzc5OTk2NTRjYmIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5MTgyL2RleCIsI
nN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVUl5VXpZdGVqUmFVWEZ0VjA5ME5rSmhXR
WxtWm5jdk9XRmtNV0poWXpVeU9UazVZVEEwWVVCM2FYSmxMbU52YlJJRWJHUmhjQ
SIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4NDYzMTcsImlhdCI6MTcwMDc1O
TkxNywibm9uY2UiOiJOUjBqWU1lX0c0U0U5MmhhZUxXM2hnIiwiYXRfaGFzaCI6I
mJHa0hSaDFHalo4eHJta0Y2X3o1OWciLCJjX2hhc2giOiI1b1BIOTZUSjRVSU9yZ
zVOLVRRUC1nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlL
mNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.qwN_XQOM1
EizAsCB4ycQR9eVJLhze05MuF0jO_2du59O3kNXundOiPgNuP5nY1_c_Mkt8G0Ns
x4taJpcgoDAQr1ARJKTPLKZgkSBfXTtMpyfBxJmdROX4cJY1Ipw4-wdPnuFVDufb
B-aowNRcYuKeOqXMtnFXwgEvZp4rpj502qmhbThsm98RfqbHMxelsEeXgTEx30Pd
Q1LfO-lWQzdEYA3m37zSF9sIJJdbkytNwu5EJlTXVsLQwTL2pr9CUNP884s1Rckw
TCXSHKEOZ6h4uP0araTUQ2Mhx1uX9dh3yBZ8sWrL4uFfKsRsIse6eq6UQPt-r289
FZeWMjgom2ziw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "86d518b0d084d1ee53bf67ae7e2e077999654cbb"
}
```

```json
{
  "at_hash": "bGkHRh1GjZ8xrmkF6_z59g",
  "aud": "wireapp",
  "c_hash": "5oPH96TJ4UIOrg5N-TQP-g",
  "exp": 1700846317,
  "iat": 1700759917,
  "iss": "http://dex:19182/dex",
  "name": "im:wireapp=%40alice_wire@wire.com",
  "nonce": "NR0jYMe_G4SE92haeLW3hg",
  "preferred_username": "Alice Smith",
  "sub": "CjtpbTp3aXJlYXBwPUIyUzYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyl3BqYwqewuhbW6nBNqS
PfLEx52KMsC0LbFxPbCUazYk7q9MlxvHzIsqleHYwSnFS5D7wKU60ldLH9od+18e
GyljwfBeFzV5hzahvulpdZlv/L7wAVXn65NEfh77uW1F42+SLbRni3VMeceScDxt
z1MGEQwRNsrp4mUKBYVDLEQbzHz3tfpR1eZ3MZbvwXySCXw4/3t1heURdyx3K60d
00WZPrXAGPxpTSyjatYGeww7t1dw8Nv6yteNgAyGHtDGDS/TU4QjM/fuA+tziSFV
vr6UZjxCEA7H9p39wuxfgILQvD/XkcEsyZD1vxe4q9lj+9dM/hShotoprXiQI4Ke
hQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/tKYqHAOd4hlpfQ84bpko2ez4vsXOON16
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTIxL2FjbWUvd2lyZS9hY2NvdW50L05pSnhRcXRRdkVFRzZIbjVOOTZYeEtvSlA0ampvOVM5IiwidHlwIjoiSldUIiwibm9uY2UiOiJNWGhzVVdSRFNqZElSR0Z6UmpkR1FtcEhTV2xzTkhkSmQzb3phWGxaZFd3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjEvYWNtZS93aXJlL2NoYWxsZW5nZS9zVjdTQWRIVGRaVFNWc3JRYXdqTmZKcTlhMGh1ZTBxZi90S1lxSEFPZDRobHBmUTg0YnBrbzJlejR2c1hPT04xNiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJamcyWkRVeE9HSXdaREE0TkdReFpXVTFNMkptTmpkaFpUZGxNbVV3TnpjNU9UazJOVFJqWW1JaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTVNVGd5TDJSbGVDSXNJbk4xWWlJNklrTnFkSEJpVkhBellWaEtiRmxZUW5kUVZVbDVWWHBaZEdWcVVtRlZXRVowVmpBNU1FNXJTbWhYUld4dFdtNWpkazlYUm10TlYwcG9XWHBWZVU5VWF6VlpWRUV3V1ZWQ00yRllTbXhNYlU1MllsSkpSV0pIVW1oalFTSXNJbUYxWkNJNkluZHBjbVZoY0hBaUxDSmxlSEFpT2pFM01EQTRORFl6TVRjc0ltbGhkQ0k2TVRjd01EYzFPVGt4Tnl3aWJtOXVZMlVpT2lKT1VqQnFXVTFsWDBjMFUwVTVNbWhoWlV4WE0yaG5JaXdpWVhSZmFHRnphQ0k2SW1KSGEwaFNhREZIYWxvNGVISnRhMFkyWDNvMU9XY2lMQ0pqWDJoaGMyZ2lPaUkxYjFCSU9UWlVTalJWU1U5eVp6Vk9MVlJSVUMxbklpd2libUZ0WlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJa0ZzYVdObElGTnRhWFJvSW4wLnF3Tl9YUU9NMUVpekFzQ0I0eWNRUjllVkpMaHplMDVNdUYwak9fMmR1NTlPM2tOWHVuZE9pUGdOdVA1blkxX2NfTWt0OEcwTnN4NHRhSnBjZ29EQVFyMUFSSktUUExLWmdrU0JmWFR0TXB5ZkJ4Sm1kUk9YNGNKWTFJcHc0LXdkUG51RlZEdWZiQi1hb3dOUmNZdUtlT3FYTXRuRlh3Z0V2WnA0cnBqNTAycW1oYlRoc205OFJmcWJITXhlbHNFZVhnVEV4MzBQZFExTGZPLWxXUXpkRVlBM20zN3pTRjlzSUpKZGJreXROd3U1RUpsVFhWc0xRd1RMMnByOUNVTlA4ODRzMVJja3dUQ1hTSEtFT1o2aDR1UDBhcmFUVVEyTWh4MXVYOWRoM3lCWjhzV3JMNHVGZktzUnNJc2U2ZXE2VVFQdC1yMjg5RlplV01qZ29tMnppdyIsImtleWF1dGgiOiJBeHdxYlM3RWFnZ1BZYllrSWx0NlF1Q3ZuQjU5SzU5Ri56QXhZOEd2VHFQZ3F6Q05SbENRMmJZWG14THJ5bkxPX3JFTTFqVXZMVGZjIn0",
  "signature": "zFpA-N1h-CDlV5UT2NZ3y2NAvmWBi4DZ6wJTJ3b1ID2FfPmYxrn06q3aNr3ANbTPOPsnK39oDgYqloPc6b-KAQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg2ZDUxOGIwZDA4NGQxZWU1M2JmNjdhZTdlMmUwNzc5OTk2NTRjYmIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5MTgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVUl5VXpZdGVqUmFVWEZ0VjA5ME5rSmhXRWxtWm5jdk9XRmtNV0poWXpVeU9UazVZVEEwWVVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4NDYzMTcsImlhdCI6MTcwMDc1OTkxNywibm9uY2UiOiJOUjBqWU1lX0c0U0U5MmhhZUxXM2hnIiwiYXRfaGFzaCI6ImJHa0hSaDFHalo4eHJta0Y2X3o1OWciLCJjX2hhc2giOiI1b1BIOTZUSjRVSU9yZzVOLVRRUC1nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.qwN_XQOM1EizAsCB4ycQR9eVJLhze05MuF0jO_2du59O3kNXundOiPgNuP5nY1_c_Mkt8G0Nsx4taJpcgoDAQr1ARJKTPLKZgkSBfXTtMpyfBxJmdROX4cJY1Ipw4-wdPnuFVDufbB-aowNRcYuKeOqXMtnFXwgEvZp4rpj502qmhbThsm98RfqbHMxelsEeXgTEx30PdQ1LfO-lWQzdEYA3m37zSF9sIJJdbkytNwu5EJlTXVsLQwTL2pr9CUNP884s1RckwTCXSHKEOZ6h4uP0araTUQ2Mhx1uX9dh3yBZ8sWrL4uFfKsRsIse6eq6UQPt-r289FZeWMjgom2ziw",
    "keyauth": "AxwqbS7EaggPYbYkIlt6QuCvnB59K59F.zAxY8GvTqPgqzCNRlCQ2bYXmxLrynLO_rEM1jUvLTfc"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32921/acme/wire/account/NiJxQqtQvEEG6Hn5N96XxKoJP4jjo9S9",
    "nonce": "MXhsUWRDSjdIRGFzRjdGQmpHSWlsNHdJd3ozaXlZdWw",
    "typ": "JWT",
    "url": "https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/tKYqHAOd4hlpfQ84bpko2ez4vsXOON16"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32921/acme/wire/directory>;rel="index"
link: <https://stepca:32921/acme/wire/authz/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf>;rel="up"
location: https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/tKYqHAOd4hlpfQ84bpko2ez4vsXOON16
replay-nonce: aU9KUk1RaW1iTTFpcDlnQVpxcE1ya0NaMGxZYTc5MjU
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32921/acme/wire/challenge/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf/tKYqHAOd4hlpfQ84bpko2ez4vsXOON16",
  "status": "valid",
  "token": "AxwqbS7EaggPYbYkIlt6QuCvnB59K59F",
  "target": "http://dex:19182/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTIxL2FjbWUvd2lyZS9hY2NvdW50L05pSnhRcXRRdkVFRzZIbjVOOTZYeEtvSlA0ampvOVM5IiwidHlwIjoiSldUIiwibm9uY2UiOiJhVTlLVWsxUmFXMWlUVEZwY0RsblFWcHhjRTF5YTBOYU1HeFpZVGM1TWpVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjEvYWNtZS93aXJlL29yZGVyL1RJR0xkV1JOSEVVWjY0MHZvT3Q1R1Q5Q2lYY2Rjbk1QIn0",
  "payload": "",
  "signature": "Z7kiF9IkcYiRPNeJvRyxPsPUgvISpk7swqDBWLG6cXkf_KNJgQpbWWJDgVPt0n9Lv59Mc0iyN1SBtcGNhq0uCQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32921/acme/wire/account/NiJxQqtQvEEG6Hn5N96XxKoJP4jjo9S9",
    "nonce": "aU9KUk1RaW1iTTFpcDlnQVpxcE1ya0NaMGxZYTc5MjU",
    "typ": "JWT",
    "url": "https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32921/acme/wire/directory>;rel="index"
location: https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP
replay-nonce: OHkyM0JxU05BRG1qbW11Qm9MMkwzOG5Eb0hWQXdtMng
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32921/acme/wire/authz/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf"
  ],
  "expires": "2023-11-24T17:18:37Z",
  "notBefore": "2023-11-23T17:18:37.372558Z",
  "notAfter": "2033-11-20T17:18:37.372558Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTIxL2FjbWUvd2lyZS9hY2NvdW50L05pSnhRcXRRdkVFRzZIbjVOOTZYeEtvSlA0ampvOVM5IiwidHlwIjoiSldUIiwibm9uY2UiOiJPSGt5TTBKeFUwNUJSRzFxYlcxMVFtOU1Na3d6T0c1RWIwaFdRWGR0TW5nIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjEvYWNtZS93aXJlL29yZGVyL1RJR0xkV1JOSEVVWjY0MHZvT3Q1R1Q5Q2lYY2Rjbk1QL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTFRDQjRBSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTWVfeXRwZThLWEN0R00yNXFjek5nUVJubmFFbGt4bExBVzR0U3lMZDJsMW9Id3dlZ1lKS29aSWh2Y05BUWtPTVcwd2F6QnBCZ05WSFJFRVlqQmdoanRwYlRwM2FYSmxZWEJ3UFVJeVV6WXRlalJhVVhGdFYwOTBOa0poV0VsbVpuY3ZPV0ZrTVdKaFl6VXlPVGs1WVRBMFlVQjNhWEpsTG1OdmJZWWhhVzA2ZDJseVpXRndjRDBsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dE1BVUdBeXRsY0FOQkFPeXNydk93SWJfejFPZkloeGFoQWxrQ3ZHUDBRNm9LeUhNV29iUGl5bjgyd2hoWnkyYnJyRi1DeElZYTFMczRxVHRxeTZRdi1xNE9XN0l5SlhBc1BBSSJ9",
  "signature": "t0cKaVxWOPZ1BJi87CsA-4bc6oRm8PL2utfnR3U8AkiFiaC8vDSFDCQbng26AtSyq0b3BNzgZcPTVNzRr-HjDQ"
}
```
```json
{
  "payload": {
    "csr": "MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMe_ytpe8KXCtGM25qczNgQRnnaElkxlLAW4tSyLd2l1oHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJlYXBwPUIyUzYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANBAOysrvOwIb_z1OfIhxahAlkCvGP0Q6oKyHMWobPiyn82whhZy2brrF-CxIYa1Ls4qTtqy6Qv-q4OW7IyJXAsPAI"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32921/acme/wire/account/NiJxQqtQvEEG6Hn5N96XxKoJP4jjo9S9",
    "nonce": "OHkyM0JxU05BRG1qbW11Qm9MMkwzOG5Eb0hWQXdtMng",
    "typ": "JWT",
    "url": "https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMe/ytpe8KXCtGM25qczNgQRnnaElkxl
LAW4tSyLd2l1oHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJl
YXBwPUIyUzYtejRaUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJl
LmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANB
AOysrvOwIb/z1OfIhxahAlkCvGP0Q6oKyHMWobPiyn82whhZy2brrF+CxIYa1Ls4
qTtqy6Qv+q4OW7IyJXAsPAI=
-----END CERTIFICATE REQUEST-----

```
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = wire.com, 2.16.840.1.113730.3.1.241 = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    c7:bf:ca:da:5e:f0:a5:c2:b4:63:36:e6:a7:33:36:
                    04:11:9e:76:84:96:4c:65:2c:05:b8:b5:2c:8b:77:
                    69:75
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com, URI:im:wireapp=%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        ec:ac:ae:f3:b0:21:bf:f3:d4:e7:c8:87:16:a1:02:59:02:bc:
        63:f4:43:aa:0a:c8:73:16:a1:b3:e2:ca:7f:36:c2:18:59:cb:
        66:eb:ac:5f:82:c4:86:1a:d4:bb:38:a9:3b:6a:cb:a4:2f:fa:
        ae:0e:5b:b2:32:25:70:2c:3c:02

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32921/acme/wire/directory>;rel="index"
location: https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP
replay-nonce: Z3A4aW1rU1RPQk1sQVN5NnhSVDRHV2FEcGxORmdYOVo
vary: Origin
```
```json
{
  "certificate": "https://stepca:32921/acme/wire/certificate/QBn00Pnr9oXNbX3rSEjCyRDuHNDmJ8rF",
  "status": "valid",
  "finalize": "https://stepca:32921/acme/wire/order/TIGLdWRNHEUZ640voOt5GT9CiXcdcnMP/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32921/acme/wire/authz/sV7SAdHTdZTSVsrQawjNfJq9a0hue0qf"
  ],
  "expires": "2023-11-24T17:18:37Z",
  "notBefore": "2023-11-23T17:18:37.372558Z",
  "notAfter": "2033-11-20T17:18:37.372558Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32921/acme/wire/certificate/QBn00Pnr9oXNbX3rSEjCyRDuHNDmJ8rF
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTIxL2FjbWUvd2lyZS9hY2NvdW50L05pSnhRcXRRdkVFRzZIbjVOOTZYeEtvSlA0ampvOVM5IiwidHlwIjoiSldUIiwibm9uY2UiOiJaM0E0YVcxclUxUlBRazFzUVZONU5uaFNWRFJIVjJGRWNHeE9SbWRZT1ZvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MjEvYWNtZS93aXJlL2NlcnRpZmljYXRlL1FCbjAwUG5yOW9YTmJYM3JTRWpDeVJEdUhORG1KOHJGIn0",
  "payload": "",
  "signature": "01lLmin8kneCkHvxEj0nIiZlSmealgHjbLgYLhG4qxYd-FzNwitXfWSysItmmZXGTwEi75oAFVlzEe4nTs8kBg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32921/acme/wire/account/NiJxQqtQvEEG6Hn5N96XxKoJP4jjo9S9",
    "nonce": "Z3A4aW1rU1RPQk1sQVN5NnhSVDRHV2FEcGxORmdYOVo",
    "typ": "JWT",
    "url": "https://stepca:32921/acme/wire/certificate/QBn00Pnr9oXNbX3rSEjCyRDuHNDmJ8rF"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32921/acme/wire/directory>;rel="index"
replay-nonce: MldWY01ESEFnNDhEaHROZTNMY243bm9STjNaNTJzWTU
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAb+gAwIBAgIQUu/ROy/v/0dCyqqR6T9hFjAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzExMjMxNzE4MzdaFw0zMzExMjAxNzE4MzdaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMe/ytpe8KXCtGM25qcz\nNgQRnnaElkxlLAW4tSyLd2l1o4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUwFsz00P/gqSrw99q8nIOs2TdMtkwHwYD\nVR0jBBgwFoAU43Znt9pjM05KWFt8oE5JD/HHaBEwaQYDVR0RBGIwYIYhaW06d2ly\nZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29thjtpbTp3aXJlYXBwPUIyUzYtejRa\nUXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbTAdBgwrBgEE\nAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSQAwRgIhANPHhjSf\n8rP8IRNAVlhyXaKzrMaYxouh6Qm32qOzmqBZAiEA7ZV/gAm2B2VkI0jkm96htoXY\n1sGjkdNjdD9nmzJpZA4=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV6gAwIBAgIQZx0HZ30xTJVntiCgpD4S4zAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMTIzMTcx\nODM1WhcNMzMxMTIwMTcxODM1WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHNV\nAwoaDTg18RCFufW8DHaIv5OAF+GN1G5k9J3DgZkCARrMbiUKwE7k8hm1q37ddC+V\nxO/paYFWeNa3AsxtCzqjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBTjdme32mMzTkpYW3ygTkkP8cdoETAfBgNVHSMEGDAW\ngBRwmHYYwdfbii6DViaqQW7rAc80wzAKBggqhkjOPQQDAgNJADBGAiEA2Rn1j7Ds\ntO1KxKG2vMEar/WZ1Nm1XL3CBY9YMV9GY6oCIQDmlNzqXvvhUty+oXRO+WFkuyyC\nJAfLKEMV6wGOuW19gg==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICGjCCAb+gAwIBAgIQUu/ROy/v/0dCyqqR6T9hFjAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzExMjMxNzE4MzdaFw0zMzExMjAxNzE4MzdaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMe/ytpe8KXCtGM25qcz
NgQRnnaElkxlLAW4tSyLd2l1o4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUwFsz00P/gqSrw99q8nIOs2TdMtkwHwYD
VR0jBBgwFoAU43Znt9pjM05KWFt8oE5JD/HHaBEwaQYDVR0RBGIwYIYhaW06d2ly
ZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29thjtpbTp3aXJlYXBwPUIyUzYtejRa
UXFtV090NkJhWElmZncvOWFkMWJhYzUyOTk5YTA0YUB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSQAwRgIhANPHhjSf
8rP8IRNAVlhyXaKzrMaYxouh6Qm32qOzmqBZAiEA7ZV/gAm2B2VkI0jkm96htoXY
1sGjkdNjdD9nmzJpZA4=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            52:ef:d1:3b:2f:ef:ff:47:42:ca:aa:91:e9:3f:61:16
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Nov 23 17:18:37 2023 GMT
            Not After : Nov 20 17:18:37 2033 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    c7:bf:ca:da:5e:f0:a5:c2:b4:63:36:e6:a7:33:36:
                    04:11:9e:76:84:96:4c:65:2c:05:b8:b5:2c:8b:77:
                    69:75
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                C0:5B:33:D3:43:FF:82:A4:AB:C3:DF:6A:F2:72:0E:B3:64:DD:32:D9
            X509v3 Authority Key Identifier: 
                E3:76:67:B7:DA:63:33:4E:4A:58:5B:7C:A0:4E:49:0F:F1:C7:68:11
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=%40alice_wire@wire.com, URI:im:wireapp=B2S6-z4ZQqmWOt6BaXIffw/9ad1bac52999a04a@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:d3:c7:86:34:9f:f2:b3:fc:21:13:40:56:58:
        72:5d:a2:b3:ac:c6:98:c6:8b:a1:e9:09:b7:da:a3:b3:9a:a0:
        59:02:21:00:ed:95:7f:80:09:b6:07:65:64:23:48:e4:9b:de:
        a1:b6:85:d8:d6:c1:a3:91:d3:63:74:3f:67:9b:32:69:64:0e

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV6gAwIBAgIQZx0HZ30xTJVntiCgpD4S4zAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMTIzMTcx
ODM1WhcNMzMxMTIwMTcxODM1WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHNV
AwoaDTg18RCFufW8DHaIv5OAF+GN1G5k9J3DgZkCARrMbiUKwE7k8hm1q37ddC+V
xO/paYFWeNa3AsxtCzqjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBTjdme32mMzTkpYW3ygTkkP8cdoETAfBgNVHSMEGDAW
gBRwmHYYwdfbii6DViaqQW7rAc80wzAKBggqhkjOPQQDAgNJADBGAiEA2Rn1j7Ds
tO1KxKG2vMEar/WZ1Nm1XL3CBY9YMV9GY6oCIQDmlNzqXvvhUty+oXRO+WFkuyyC
JAfLKEMV6wGOuW19gg==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            67:1d:07:67:7d:31:4c:95:67:b6:20:a0:a4:3e:12:e3
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Nov 23 17:18:35 2023 GMT
            Not After : Nov 20 17:18:35 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:73:55:03:0a:1a:0d:38:35:f1:10:85:b9:f5:bc:
                    0c:76:88:bf:93:80:17:e1:8d:d4:6e:64:f4:9d:c3:
                    81:99:02:01:1a:cc:6e:25:0a:c0:4e:e4:f2:19:b5:
                    ab:7e:dd:74:2f:95:c4:ef:e9:69:81:56:78:d6:b7:
                    02:cc:6d:0b:3a
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                E3:76:67:B7:DA:63:33:4E:4A:58:5B:7C:A0:4E:49:0F:F1:C7:68:11
            X509v3 Authority Key Identifier: 
                70:98:76:18:C1:D7:DB:8A:2E:83:56:26:AA:41:6E:EB:01:CF:34:C3
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:d9:19:f5:8f:b0:ec:b4:ed:4a:c4:a1:b6:bc:
        c1:1a:af:f5:99:d4:d9:b5:5c:bd:c2:05:8f:58:31:5f:46:63:
        aa:02:21:00:e6:94:dc:ea:5e:fb:e1:52:dc:be:a1:74:4e:f9:
        61:64:bb:2c:82:24:07:cb:28:43:15:eb:01:8e:b9:6d:7d:82

```
