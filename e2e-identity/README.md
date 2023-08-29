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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/19e82407ab8f2ab4/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/rR8fiwENTYf2X0I9NC6CE70d0knhXxY7
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/1l8R6fyr5Fl6klrfNSRgNZxVFKyX8BYA
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/BZ0Y9vLuddsNnSAHmFxdi8aP1hCcUNSW
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32906/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32906/acme/wire/new-nonce",
  "newAccount": "https://stepca:32906/acme/wire/new-account",
  "newOrder": "https://stepca:32906/acme/wire/new-order",
  "revokeCert": "https://stepca:32906/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32906/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32906/acme/wire/directory>;rel="index"
replay-nonce: TXFLMWRnTWJ6aDQ5TE9NSzZDdm9SUXIxUDRVODYwQ0s
```
```text
TXFLMWRnTWJ6aDQ5TE9NSzZDdm9SUXIxUDRVODYwQ0s
```
#### 5. create a new account
```http request
POST https://stepca:32906/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InhqY1BCQmpkQ0ZYS0FGdi1FOXVIOUhpZWRXYXdJeXdyN2lvUFpDMVFoM1EifSwibm9uY2UiOiJUWEZMTVdSblRXSjZhRFE1VEU5TlN6WkRkbTlTVVhJeFVEUlZPRFl3UTBzIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDYvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "i81OGa1vXh1hX2g2ZzZWXrRF0564QPTkkj_5KWEXKisjyqaWfbGh3WJv6fbJSN_1osY0XhHykVRPjVABUpp2DA"
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
      "x": "xjcPBBjdCFXKAFv-E9uH9HiedWawIywr7ioPZC1Qh3Q"
    },
    "nonce": "TXFLMWRnTWJ6aDQ5TE9NSzZDdm9SUXIxUDRVODYwQ0s",
    "typ": "JWT",
    "url": "https://stepca:32906/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32906/acme/wire/directory>;rel="index"
location: https://stepca:32906/acme/wire/account/58S0p9I8BPSKpVkmEWKIhQSOSW3yPez8
replay-nonce: ajN4blZMUTNsczl3WEJQNTlsdGE4eUt3Q1MzY3djUEU
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32906/acme/wire/account/58S0p9I8BPSKpVkmEWKIhQSOSW3yPez8/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32906/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTA2L2FjbWUvd2lyZS9hY2NvdW50LzU4UzBwOUk4QlBTS3BWa21FV0tJaFFTT1NXM3lQZXo4IiwidHlwIjoiSldUIiwibm9uY2UiOiJhak40YmxaTVVUTnNjemwzV0VKUU5UbHNkR0U0ZVV0M1ExTXpZM2RqVUVVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDYvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9dDZ3UnBJOEJSU2V2aUJ3d2lGcDVNUS8xOWU4MjQwN2FiOGYyYWI0QHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9YWxpY2Vfd2lyZVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wOC0yOVQxMzowNTo1OC45NDgzODNaIiwibm90QWZ0ZXIiOiIyMDMzLTA4LTI2VDEzOjA1OjU4Ljk0ODM4M1oifQ",
  "signature": "bBAXtYTjvq41y4FlrJPTgoTNoX5Apvvq2UzTon0BVJ-ur13la-cVMRwm1cj0Vk4jTB8q9IE9tVIZ_AzFmBgjAg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2033-08-26T13:05:58.948383Z",
    "notBefore": "2023-08-29T13:05:58.948383Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32906/acme/wire/account/58S0p9I8BPSKpVkmEWKIhQSOSW3yPez8",
    "nonce": "ajN4blZMUTNsczl3WEJQNTlsdGE4eUt3Q1MzY3djUEU",
    "typ": "JWT",
    "url": "https://stepca:32906/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32906/acme/wire/directory>;rel="index"
location: https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8
replay-nonce: ZDJuMDVpbFhRcEtZVnc0SzRCQnQybmlCUnZrVk1iSkc
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32906/acme/wire/authz/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI"
  ],
  "expires": "2023-08-30T13:05:58Z",
  "notBefore": "2023-08-29T13:05:58.948383Z",
  "notAfter": "2033-08-26T13:05:58.948383Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32906/acme/wire/authz/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTA2L2FjbWUvd2lyZS9hY2NvdW50LzU4UzBwOUk4QlBTS3BWa21FV0tJaFFTT1NXM3lQZXo4IiwidHlwIjoiSldUIiwibm9uY2UiOiJaREp1TURWcGJGaFJjRXRaVm5jMFN6UkNRblF5Ym1sQ1VuWnJWazFpU2tjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDYvYWNtZS93aXJlL2F1dGh6L0NBQWhZS0thOTNVV1hYWUVuaDVpYVRETXZmc2RXUnBJIn0",
  "payload": "",
  "signature": "3MjIelDCn8hS6V8H5QKSE8YagLi67fKzHB77uodAasvHX0PUWUTgnPR29uGrWDWkDxIJDXh0Zyi8IYG0hhiODg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32906/acme/wire/account/58S0p9I8BPSKpVkmEWKIhQSOSW3yPez8",
    "nonce": "ZDJuMDVpbFhRcEtZVnc0SzRCQnQybmlCUnZrVk1iSkc",
    "typ": "JWT",
    "url": "https://stepca:32906/acme/wire/authz/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32906/acme/wire/directory>;rel="index"
location: https://stepca:32906/acme/wire/authz/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI
replay-nonce: RGhRYnZFTWFGTVVab2ZtdjNqdk1IUU5iYjdJUXE4dlg
```
```json
{
  "status": "pending",
  "expires": "2023-08-30T13:05:58Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/1l8R6fyr5Fl6klrfNSRgNZxVFKyX8BYA",
      "status": "pending",
      "token": "HnlLVREbQmYwV96AMUbYtXzMfPTEFQ5f",
      "target": "http://dex:23900/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/rR8fiwENTYf2X0I9NC6CE70d0knhXxY7",
      "status": "pending",
      "token": "HnlLVREbQmYwV96AMUbYtXzMfPTEFQ5f",
      "target": "http://wire.com:24555/clients/19e82407ab8f2ab4/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:24555/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
Qjh5alllTXg0OFg5RWY3OW1XWTBpTmNSTVFZeGVNWmg
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieGpjUEJCamRDRlhLQUZ2LUU5dUg5SGllZFdhd0l5d3I3aW9QWkMxUWgzUSJ9fQ.eyJpYXQiOjE2OTMzMTQzNTgsImV4cCI6MTY5MzMxNzk1OCwibmJmIjoxNjkzMzE0MzUzLCJzdWIiOiJpbTp3aXJlYXBwPXQ2d1JwSThCUlNldmlCd3dpRnA1TVEvMTllODI0MDdhYjhmMmFiNEB3aXJlLmNvbSIsImp0aSI6ImI5MWUyZDg3LThiNzgtNGE5OS05MTUwLTlmNTU1MzQxYmU5YSIsIm5vbmNlIjoiUWpoNWFsbGxUWGcwT0ZnNVJXWTNPVzFYV1RCcFRtTlNUVkZaZUdWTldtZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ1NTUvY2xpZW50cy8xOWU4MjQwN2FiOGYyYWI0L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJIbmxMVlJFYlFtWXdWOTZBTVViWXRYek1mUFRFRlE1ZiJ9.9T1XKch9E7-CqPoKc6fSl5XfWvQ_fckUCyAwgjpNBKWAEfdqhT_BGldZ7JUvcwiPFXmxmaLRv-SdgkvBagdxDA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieGpjUEJCamRDRlhLQUZ2LUU5dUg5SGll
ZFdhd0l5d3I3aW9QWkMxUWgzUSJ9fQ.eyJpYXQiOjE2OTMzMTQzNTgsImV4cCI6M
TY5MzMxNzk1OCwibmJmIjoxNjkzMzE0MzUzLCJzdWIiOiJpbTp3aXJlYXBwPXQ2d
1JwSThCUlNldmlCd3dpRnA1TVEvMTllODI0MDdhYjhmMmFiNEB3aXJlLmNvbSIsI
mp0aSI6ImI5MWUyZDg3LThiNzgtNGE5OS05MTUwLTlmNTU1MzQxYmU5YSIsIm5vb
mNlIjoiUWpoNWFsbGxUWGcwT0ZnNVJXWTNPVzFYV1RCcFRtTlNUVkZaZUdWTldtZ
yIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ1NTUvY2xpZ
W50cy8xOWU4MjQwN2FiOGYyYWI0L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJIbmxMV
lJFYlFtWXdWOTZBTVViWXRYek1mUFRFRlE1ZiJ9.9T1XKch9E7-CqPoKc6fSl5Xf
WvQ_fckUCyAwgjpNBKWAEfdqhT_BGldZ7JUvcwiPFXmxmaLRv-SdgkvBagdxDA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "xjcPBBjdCFXKAFv-E9uH9HiedWawIywr7ioPZC1Qh3Q"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "HnlLVREbQmYwV96AMUbYtXzMfPTEFQ5f",
  "exp": 1693317958,
  "htm": "POST",
  "htu": "http://wire.com:24555/clients/19e82407ab8f2ab4/access-token",
  "iat": 1693314358,
  "jti": "b91e2d87-8b78-4a99-9150-9f555341be9a",
  "nbf": 1693314353,
  "nonce": "Qjh5alllTXg0OFg5RWY3OW1XWTBpTmNSTVFZeGVNWmg",
  "sub": "im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL+kop6p2taixYROBQCRkY7zsoHW7LTRJSrTu9V/dhYM
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAxjcPBBjdCFXKAFv+E9uH9HiedWawIywr7ioPZC1Qh3Q=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:24555/clients/19e82407ab8f2ab4/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZUdwalVFSkNhbVJEUmxoTFFVWjJMVVU1ZFVnNVNHbGxaRmRoZDBsNWQzSTNhVzlRV2tNeFVXZ3pVU0o5ZlEuZXlKcFlYUWlPakUyT1RNek1UUXpOVGdzSW1WNGNDSTZNVFk1TXpNeE56azFPQ3dpYm1KbUlqb3hOamt6TXpFME16VXpMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQWFEyZDFKd1NUaENVbE5sZG1sQ2QzZHBSbkExVFZFdk1UbGxPREkwTURkaFlqaG1NbUZpTkVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1JNU1XVXlaRGczTFRoaU56Z3ROR0U1T1MwNU1UVXdMVGxtTlRVMU16UXhZbVU1WVNJc0ltNXZibU5sSWpvaVVXcG9OV0ZzYkd4VVdHY3dUMFpuTlZKWFdUTlBWekZZVjFSQ2NGUnRUbE5VVmtaYVpVZFdUbGR0WnlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qUTFOVFV2WTJ4cFpXNTBjeTh4T1dVNE1qUXdOMkZpT0dZeVlXSTBMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lKSWJteE1WbEpGWWxGdFdYZFdPVFpCVFZWaVdYUlllazFtVUZSRlJsRTFaaUo5LjlUMVhLY2g5RTctQ3FQb0tjNmZTbDVYZld2UV9mY2tVQ3lBd2dqcE5CS1dBRWZkcWhUX0JHbGRaN0pVdmN3aVBGWG14bWFMUnYtU2Rna3ZCYWdkeERB
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJjN2VoaWE0QWxNTUlhRkJ6bDBjeWhrMWx6bl8yal9sSTQzd0tESTZNSWsifX0.eyJpYXQiOjE2OTMzMTQzNTgsImV4cCI6MTY5MzMxNDcxOCwibmJmIjoxNjkzMzE0MzUzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ1NTUvY2xpZW50cy8xOWU4MjQwN2FiOGYyYWI0L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9dDZ3UnBJOEJSU2V2aUJ3d2lGcDVNUS8xOWU4MjQwN2FiOGYyYWI0QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NTU1L2NsaWVudHMvMTllODI0MDdhYjhmMmFiNC9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI2NWFlYmEzNS03YzVkLTQ4MzItOTY1Ni1iMWUyYjdiODEyMWIiLCJub25jZSI6IlFqaDVhbGxsVFhnME9GZzVSV1kzT1cxWFdUQnBUbU5TVFZGWmVHVk5XbWciLCJjaGFsIjoiSG5sTFZSRWJRbVl3Vjk2QU1VYll0WHpNZlBURUZRNWYiLCJjbmYiOnsia2lkIjoiNjE0VzVWTEtabEtGME5rbWlUYVBKSVRDaXNWeGpyUTBGUm9SSjMtTFZXVSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVHcGpVRUpDYW1SRFJsaExRVVoyTFVVNWRVZzVTR2xsWkZkaGQwbDVkM0kzYVc5UVdrTXhVV2d6VVNKOWZRLmV5SnBZWFFpT2pFMk9UTXpNVFF6TlRnc0ltVjRjQ0k2TVRZNU16TXhOemsxT0N3aWJtSm1Jam94Tmprek16RTBNelV6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFhRMmQxSndTVGhDVWxObGRtbENkM2RwUm5BMVRWRXZNVGxsT0RJME1EZGhZamhtTW1GaU5FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltSTVNV1V5WkRnM0xUaGlOemd0TkdFNU9TMDVNVFV3TFRsbU5UVTFNelF4WW1VNVlTSXNJbTV2Ym1ObElqb2lVV3BvTldGc2JHeFVXR2N3VDBabk5WSlhXVE5QVnpGWVYxUkNjRlJ0VGxOVVZrWmFaVWRXVGxkdFp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalExTlRVdlkyeHBaVzUwY3k4eE9XVTRNalF3TjJGaU9HWXlZV0kwTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSklibXhNVmxKRllsRnRXWGRXT1RaQlRWVmlXWFJZZWsxbVVGUkZSbEUxWmlKOS45VDFYS2NoOUU3LUNxUG9LYzZmU2w1WGZXdlFfZmNrVUN5QXdnanBOQktXQUVmZHFoVF9CR2xkWjdKVXZjd2lQRlhteG1hTFJ2LVNkZ2t2QmFnZHhEQSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA9dDZ3UnBJOEJSU2V2aUJ3d2lGcDVNUS8xOWU4MjQwN2FiOGYyYWI0QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.f1dFyk7pC6JDa7N9tSnGaQ-379-rXEVf6JZcy0aCXxzNtcgpOMb_YHdxUBR8k3Vz2iOkZChD7ob2gV9DMfMLAg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJjN2VoaWE0QWxNTUlhRkJ6bDBjeWhrMWx6bl8yal9sSTQzd0tESTZNSWsifX0.eyJpYXQiOjE2OTMzMTQzNTgsImV4cCI6MTY5MzMxNDcxOCwibmJmIjoxNjkzMzE0MzUzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ1NTUvY2xpZW50cy8xOWU4MjQwN2FiOGYyYWI0L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9dDZ3UnBJOEJSU2V2aUJ3d2lGcDVNUS8xOWU4MjQwN2FiOGYyYWI0QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NTU1L2NsaWVudHMvMTllODI0MDdhYjhmMmFiNC9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI2NWFlYmEzNS03YzVkLTQ4MzItOTY1Ni1iMWUyYjdiODEyMWIiLCJub25jZSI6IlFqaDVhbGxsVFhnME9GZzVSV1kzT1cxWFdUQnBUbU5TVFZGWmVHVk5XbWciLCJjaGFsIjoiSG5sTFZSRWJRbVl3Vjk2QU1VYll0WHpNZlBURUZRNWYiLCJjbmYiOnsia2lkIjoiNjE0VzVWTEtabEtGME5rbWlUYVBKSVRDaXNWeGpyUTBGUm9SSjMtTFZXVSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVHcGpVRUpDYW1SRFJsaExRVVoyTFVVNWRVZzVTR2xsWkZkaGQwbDVkM0kzYVc5UVdrTXhVV2d6VVNKOWZRLmV5SnBZWFFpT2pFMk9UTXpNVFF6TlRnc0ltVjRjQ0k2TVRZNU16TXhOemsxT0N3aWJtSm1Jam94Tmprek16RTBNelV6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFhRMmQxSndTVGhDVWxObGRtbENkM2RwUm5BMVRWRXZNVGxsT0RJME1EZGhZamhtTW1GaU5FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltSTVNV1V5WkRnM0xUaGlOemd0TkdFNU9TMDVNVFV3TFRsbU5UVTFNelF4WW1VNVlTSXNJbTV2Ym1ObElqb2lVV3BvTldGc2JHeFVXR2N3VDBabk5WSlhXVE5QVnpGWVYxUkNjRlJ0VGxOVVZrWmFaVWRXVGxkdFp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalExTlRVdlkyeHBaVzUwY3k4eE9XVTRNalF3TjJGaU9HWXlZV0kwTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSklibXhNVmxKRllsRnRXWGRXT1RaQlRWVmlXWFJZZWsxbVVGUkZSbEUxWmlKOS45VDFYS2NoOUU3LUNxUG9LYzZmU2w1WGZXdlFfZmNrVUN5QXdnanBOQktXQUVmZHFoVF9CR2xkWjdKVXZjd2lQRlhteG1hTFJ2LVNkZ2t2QmFnZHhEQSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA9dDZ3UnBJOEJSU2V2aUJ3d2lGcDVNUS8xOWU4MjQwN2FiOGYyYWI0QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.f1dFyk7pC6JDa7N9tSnGaQ-379-rXEVf6JZcy0aCXxzNtcgpOMb_YHdxUBR8k3Vz2iOkZChD7ob2gV9DMfMLAg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InJjN2VoaWE0QWxNTUlhRkJ6bDBjeWhrMWx6
bl8yal9sSTQzd0tESTZNSWsifX0.eyJpYXQiOjE2OTMzMTQzNTgsImV4cCI6MTY5
MzMxNDcxOCwibmJmIjoxNjkzMzE0MzUzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQ1NTUvY2xpZW50cy8xOWU4MjQwN2FiOGYyYWI0L2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9dDZ3UnBJOEJSU2V2aUJ3d2lGcDVNUS8xOWU4MjQwN2Fi
OGYyYWI0QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NTU1L2Ns
aWVudHMvMTllODI0MDdhYjhmMmFiNC9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI2NWFl
YmEzNS03YzVkLTQ4MzItOTY1Ni1iMWUyYjdiODEyMWIiLCJub25jZSI6IlFqaDVh
bGxsVFhnME9GZzVSV1kzT1cxWFdUQnBUbU5TVFZGWmVHVk5XbWciLCJjaGFsIjoi
SG5sTFZSRWJRbVl3Vjk2QU1VYll0WHpNZlBURUZRNWYiLCJjbmYiOnsia2lkIjoi
NjE0VzVWTEtabEtGME5rbWlUYVBKSVRDaXNWeGpyUTBGUm9SSjMtTFZXVSJ9LCJw
cm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJ
aXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lM
Q0o0SWpvaWVHcGpVRUpDYW1SRFJsaExRVVoyTFVVNWRVZzVTR2xsWkZkaGQwbDVk
M0kzYVc5UVdrTXhVV2d6VVNKOWZRLmV5SnBZWFFpT2pFMk9UTXpNVFF6TlRnc0lt
VjRjQ0k2TVRZNU16TXhOemsxT0N3aWJtSm1Jam94Tmprek16RTBNelV6TENKemRX
SWlPaUpwYlRwM2FYSmxZWEJ3UFhRMmQxSndTVGhDVWxObGRtbENkM2RwUm5BMVRW
RXZNVGxsT0RJME1EZGhZamhtTW1GaU5FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklt
STVNV1V5WkRnM0xUaGlOemd0TkdFNU9TMDVNVFV3TFRsbU5UVTFNelF4WW1VNVlT
SXNJbTV2Ym1ObElqb2lVV3BvTldGc2JHeFVXR2N3VDBabk5WSlhXVE5QVnpGWVYx
UkNjRlJ0VGxOVVZrWmFaVWRXVGxkdFp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RI
VWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalExTlRVdlkyeHBaVzUwY3k4eE9X
VTRNalF3TjJGaU9HWXlZV0kwTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9p
SklibXhNVmxKRllsRnRXWGRXT1RaQlRWVmlXWFJZZWsxbVVGUkZSbEUxWmlKOS45
VDFYS2NoOUU3LUNxUG9LYzZmU2w1WGZXdlFfZmNrVUN5QXdnanBOQktXQUVmZHFo
VF9CR2xkWjdKVXZjd2lQRlhteG1hTFJ2LVNkZ2t2QmFnZHhEQSIsImNsaWVudF9p
ZCI6ImltOndpcmVhcHA9dDZ3UnBJOEJSU2V2aUJ3d2lGcDVNUS8xOWU4MjQwN2Fi
OGYyYWI0QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9j
bGllbnRfaWQifQ.f1dFyk7pC6JDa7N9tSnGaQ-379-rXEVf6JZcy0aCXxzNtcgpO
Mb_YHdxUBR8k3Vz2iOkZChD7ob2gV9DMfMLAg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "rc7ehia4AlMMIaFBzl0cyhk1lzn_2j_lI43wKDI6MIk"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:24555/clients/19e82407ab8f2ab4/access-token",
  "chal": "HnlLVREbQmYwV96AMUbYtXzMfPTEFQ5f",
  "client_id": "im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com",
  "cnf": {
    "kid": "614W5VLKZlKF0NkmiTaPJITCisVxjrQ0FRoRJ3-LVWU"
  },
  "exp": 1693314718,
  "iat": 1693314358,
  "iss": "http://wire.com:24555/clients/19e82407ab8f2ab4/access-token",
  "jti": "65aeba35-7c5d-4832-9656-b1e2b7b8121b",
  "nbf": 1693314353,
  "nonce": "Qjh5alllTXg0OFg5RWY3OW1XWTBpTmNSTVFZeGVNWmg",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieGpjUEJCamRDRlhLQUZ2LUU5dUg5SGllZFdhd0l5d3I3aW9QWkMxUWgzUSJ9fQ.eyJpYXQiOjE2OTMzMTQzNTgsImV4cCI6MTY5MzMxNzk1OCwibmJmIjoxNjkzMzE0MzUzLCJzdWIiOiJpbTp3aXJlYXBwPXQ2d1JwSThCUlNldmlCd3dpRnA1TVEvMTllODI0MDdhYjhmMmFiNEB3aXJlLmNvbSIsImp0aSI6ImI5MWUyZDg3LThiNzgtNGE5OS05MTUwLTlmNTU1MzQxYmU5YSIsIm5vbmNlIjoiUWpoNWFsbGxUWGcwT0ZnNVJXWTNPVzFYV1RCcFRtTlNUVkZaZUdWTldtZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ1NTUvY2xpZW50cy8xOWU4MjQwN2FiOGYyYWI0L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJIbmxMVlJFYlFtWXdWOTZBTVViWXRYek1mUFRFRlE1ZiJ9.9T1XKch9E7-CqPoKc6fSl5XfWvQ_fckUCyAwgjpNBKWAEfdqhT_BGldZ7JUvcwiPFXmxmaLRv-SdgkvBagdxDA",
  "scope": "wire_client_id",
  "sub": "im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIL7Im6iNILFDyReHFt8q1uS85AdG3BHRLDK+G2D9cTyV
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEArc7ehia4AlMMIaFBzl0cyhk1lzn/2j/lI43wKDI6MIk=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/rR8fiwENTYf2X0I9NC6CE70d0knhXxY7
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTA2L2FjbWUvd2lyZS9hY2NvdW50LzU4UzBwOUk4QlBTS3BWa21FV0tJaFFTT1NXM3lQZXo4IiwidHlwIjoiSldUIiwibm9uY2UiOiJSR2hSWW5aRlRXRkdUVlZhYjJadGRqTnFkazFJVVU1aVlqZEpVWEU0ZGxnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDYvYWNtZS93aXJlL2NoYWxsZW5nZS9DQUFoWUtLYTkzVVdYWFlFbmg1aWFURE12ZnNkV1JwSS9yUjhmaXdFTlRZZjJYMEk5TkM2Q0U3MGQwa25oWHhZNyJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluSmpOMlZvYVdFMFFXeE5UVWxoUmtKNmJEQmplV2hyTVd4NmJsOHlhbDlzU1RRemQwdEVTVFpOU1dzaWZYMC5leUpwWVhRaU9qRTJPVE16TVRRek5UZ3NJbVY0Y0NJNk1UWTVNek14TkRjeE9Dd2libUptSWpveE5qa3pNekUwTXpVekxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRMU5UVXZZMnhwWlc1MGN5OHhPV1U0TWpRd04yRmlPR1l5WVdJMEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5ZERaM1VuQkpPRUpTVTJWMmFVSjNkMmxHY0RWTlVTOHhPV1U0TWpRd04yRmlPR1l5WVdJMFFIZHBjbVV1WTI5dElpd2lZWFZrSWpvaWFIUjBjRG92TDNkcGNtVXVZMjl0T2pJME5UVTFMMk5zYVdWdWRITXZNVGxsT0RJME1EZGhZamhtTW1GaU5DOWhZMk5sYzNNdGRHOXJaVzRpTENKcWRHa2lPaUkyTldGbFltRXpOUzAzWXpWa0xUUTRNekl0T1RZMU5pMWlNV1V5WWpkaU9ERXlNV0lpTENKdWIyNWpaU0k2SWxGcWFEVmhiR3hzVkZobk1FOUdaelZTVjFrelQxY3hXRmRVUW5CVWJVNVRWRlpHV21WSFZrNVhiV2NpTENKamFHRnNJam9pU0c1c1RGWlNSV0pSYlZsM1ZqazJRVTFWWWxsMFdIcE5abEJVUlVaUk5XWWlMQ0pqYm1ZaU9uc2lhMmxrSWpvaU5qRTBWelZXVEV0YWJFdEdNRTVyYldsVVlWQktTVlJEYVhOV2VHcHlVVEJHVW05U1NqTXRURlpYVlNKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVdWSGNHcFZSVXBEWVcxU1JGSnNhRXhSVlZveVRGVlZOV1JWWnpWVFIyeHNXa1prYUdRd2JEVmtNMGt6WVZjNVVWZHJUWGhWVjJkNlZWTktPV1pSTG1WNVNuQlpXRkZwVDJwRk1rOVVUWHBOVkZGNlRsUm5jMGx0VmpSalEwazJUVlJaTlUxNlRYaE9lbXN4VDBOM2FXSnRTbTFKYW05NFRtcHJlazE2UlRCTmVsVjZURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGaFJNbVF4U25kVFZHaERWV3hPYkdSdGJFTmtNMlJ3VW01Qk1WUldSWFpOVkd4c1QwUkpNRTFFWkdoWmFtaHRUVzFHYVU1RlFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2x0U1RWTlYxVjVXa1JuTTB4VWFHbE9lbWQwVGtkRk5VOVRNRFZOVkZWM1RGUnNiVTVVVlRGTmVsRjRXVzFWTlZsVFNYTkpiVFYyWW0xT2JFbHFiMmxWVjNCdlRsZEdjMkpIZUZWWFIyTjNWREJhYms1V1NsaFhWRTVRVm5wR1dWWXhVa05qUmxKMFZHeE9WVlpyV21GYVZXUlhWR3hrZEZwNVNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxFeFRsUlZkbGt5ZUhCYVZ6VXdZM2s0ZUU5WFZUUk5hbEYzVGpKR2FVOUhXWGxaVjBrd1RESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTa2xpYlhoTlZteEtSbGxzUm5SWFdHUlhUMVJhUWxSV1ZtbFhXRkpaWldzeGJWVkdVa1pTYkVVeFdtbEtPUzQ1VkRGWVMyTm9PVVUzTFVOeFVHOUxZelptVTJ3MVdHWlhkbEZmWm1OclZVTjVRWGRuYW5CT1FrdFhRVVZtWkhGb1ZGOUNSMnhrV2pkS1ZYWmpkMmxRUmxodGVHMWhURkoyTFZOa1oydDJRbUZuWkhoRVFTSXNJbU5zYVdWdWRGOXBaQ0k2SW1sdE9uZHBjbVZoY0hBOWREWjNVbkJKT0VKU1UyVjJhVUozZDJsR2NEVk5VUzh4T1dVNE1qUXdOMkZpT0dZeVlXSTBRSGRwY21VdVkyOXRJaXdpWVhCcFgzWmxjbk5wYjI0aU9qVXNJbk5qYjNCbElqb2lkMmx5WlY5amJHbGxiblJmYVdRaWZRLmYxZEZ5azdwQzZKRGE3Tjl0U25HYVEtMzc5LXJYRVZmNkpaY3kwYUNYeHpOdGNncE9NYl9ZSGR4VUJSOGszVnoyaU9rWkNoRDdvYjJnVjlETWZNTEFnIn0",
  "signature": "uvN5FF8f_C6FZ5OWT6MNvXbKfQ2iQHsX3E07bM5gfeFCfj84y2AsixH_1dnfxsDrp7xBBlN1-q3tW_yFYfMUCw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJjN2VoaWE0QWxNTUlhRkJ6bDBjeWhrMWx6bl8yal9sSTQzd0tESTZNSWsifX0.eyJpYXQiOjE2OTMzMTQzNTgsImV4cCI6MTY5MzMxNDcxOCwibmJmIjoxNjkzMzE0MzUzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ1NTUvY2xpZW50cy8xOWU4MjQwN2FiOGYyYWI0L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9dDZ3UnBJOEJSU2V2aUJ3d2lGcDVNUS8xOWU4MjQwN2FiOGYyYWI0QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NTU1L2NsaWVudHMvMTllODI0MDdhYjhmMmFiNC9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI2NWFlYmEzNS03YzVkLTQ4MzItOTY1Ni1iMWUyYjdiODEyMWIiLCJub25jZSI6IlFqaDVhbGxsVFhnME9GZzVSV1kzT1cxWFdUQnBUbU5TVFZGWmVHVk5XbWciLCJjaGFsIjoiSG5sTFZSRWJRbVl3Vjk2QU1VYll0WHpNZlBURUZRNWYiLCJjbmYiOnsia2lkIjoiNjE0VzVWTEtabEtGME5rbWlUYVBKSVRDaXNWeGpyUTBGUm9SSjMtTFZXVSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVHcGpVRUpDYW1SRFJsaExRVVoyTFVVNWRVZzVTR2xsWkZkaGQwbDVkM0kzYVc5UVdrTXhVV2d6VVNKOWZRLmV5SnBZWFFpT2pFMk9UTXpNVFF6TlRnc0ltVjRjQ0k2TVRZNU16TXhOemsxT0N3aWJtSm1Jam94Tmprek16RTBNelV6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFhRMmQxSndTVGhDVWxObGRtbENkM2RwUm5BMVRWRXZNVGxsT0RJME1EZGhZamhtTW1GaU5FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltSTVNV1V5WkRnM0xUaGlOemd0TkdFNU9TMDVNVFV3TFRsbU5UVTFNelF4WW1VNVlTSXNJbTV2Ym1ObElqb2lVV3BvTldGc2JHeFVXR2N3VDBabk5WSlhXVE5QVnpGWVYxUkNjRlJ0VGxOVVZrWmFaVWRXVGxkdFp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalExTlRVdlkyeHBaVzUwY3k4eE9XVTRNalF3TjJGaU9HWXlZV0kwTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSklibXhNVmxKRllsRnRXWGRXT1RaQlRWVmlXWFJZZWsxbVVGUkZSbEUxWmlKOS45VDFYS2NoOUU3LUNxUG9LYzZmU2w1WGZXdlFfZmNrVUN5QXdnanBOQktXQUVmZHFoVF9CR2xkWjdKVXZjd2lQRlhteG1hTFJ2LVNkZ2t2QmFnZHhEQSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA9dDZ3UnBJOEJSU2V2aUJ3d2lGcDVNUS8xOWU4MjQwN2FiOGYyYWI0QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.f1dFyk7pC6JDa7N9tSnGaQ-379-rXEVf6JZcy0aCXxzNtcgpOMb_YHdxUBR8k3Vz2iOkZChD7ob2gV9DMfMLAg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32906/acme/wire/account/58S0p9I8BPSKpVkmEWKIhQSOSW3yPez8",
    "nonce": "RGhRYnZFTWFGTVVab2ZtdjNqdk1IUU5iYjdJUXE4dlg",
    "typ": "JWT",
    "url": "https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/rR8fiwENTYf2X0I9NC6CE70d0knhXxY7"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32906/acme/wire/directory>;rel="index"
link: <https://stepca:32906/acme/wire/authz/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI>;rel="up"
location: https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/rR8fiwENTYf2X0I9NC6CE70d0knhXxY7
replay-nonce: bnM3cVQ5aVRHdmpHQkVyMUlyTGoydGFER0JoQ0NFVEE
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/rR8fiwENTYf2X0I9NC6CE70d0knhXxY7",
  "status": "valid",
  "token": "HnlLVREbQmYwV96AMUbYtXzMfPTEFQ5f",
  "target": "http://wire.com:24555/clients/19e82407ab8f2ab4/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=InZL88iNptKpuzAn9gC-MA2b5l69wj7TkbuVvNDiHjA&code_challenge=omBGqy5hGMkZx34lh3Jj5RoNGEwQFMcTGi4ggx4zSQY
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:23900/dex/auth?response_type=code&client_id=wireapp&state=c3NqpR9BKrwnxTDoV9ArIQ&code_challenge=omBGqy5hGMkZx34lh3Jj5RoNGEwQFMcTGi4ggx4zSQY&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A24555%2Fcallback&scope=openid+profile&nonce=9bvSY4mi_rS9jATYe1ABag
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:23900/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDphWEZQTjJFMlQwcEVTbmhSY0VoUFNqYzNTRmhLYVZORA==
```
```text
grant_type=authorization_code&code=moic67cbxsfdzf2cotm6dnrmq&code_verifier=InZL88iNptKpuzAn9gC-MA2b5l69wj7TkbuVvNDiHjA&redirect_uri=http%3A%2F%2Fwire.com%3A24555%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRhYjk1N2Q0YmRlOTQzMGE3NDRlZDZmM2JlMmQ3ZDlmNWFlMGU0ZGEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzOTAwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWFEyZDFKd1NUaENVbE5sZG1sQ2QzZHBSbkExVFZFdk1UbGxPREkwTURkaFlqaG1NbUZpTkVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTM0MDA3NTksImlhdCI6MTY5MzMxNDM1OSwibm9uY2UiOiI5YnZTWTRtaV9yUzlqQVRZZTFBQmFnIiwiYXRfaGFzaCI6InM3OGp3WlBrQVRRMHR1ZGg2RDYxeHciLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZV93aXJlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.TK-nEyILwwA_XSo71VPFCqsAa_FSUeJJS8No7zWiFqDKF0dv5-HcQDABp-O6iSesNV6YBVGnFKJ-PpDoyF_lZI_o3XWcuG8BQi_YEOEcQijdPNDwSpwXXLNiJUaZjWoQCYeEvrIRBFNIkje1UQsGyZxI4UFWzSvW5O0hStt_5_19788KPUO3qJrEhZ6Ot79JIEELE_sEHoaGEsyXqcbnraxXV3IKLCajCkqrPPunPI50o5smt5VKSviiPuHIA0JKMEPYKmsR26Lq288qMIsFA0kjENZMc6gGcdZ-VPgH_VYdsRxtkzU3eS2j-4N-b_H8i6sjHWEjZ6KYvjRtfCeMJg",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRhYjk1N2Q0YmRlOTQzMGE3NDRlZDZmM2JlMmQ3ZDlmNWFlMGU0ZGEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzOTAwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWFEyZDFKd1NUaENVbE5sZG1sQ2QzZHBSbkExVFZFdk1UbGxPREkwTURkaFlqaG1NbUZpTkVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTM0MDA3NTksImlhdCI6MTY5MzMxNDM1OSwibm9uY2UiOiI5YnZTWTRtaV9yUzlqQVRZZTFBQmFnIiwiYXRfaGFzaCI6IkhPWEtQclU5V1ZfZkZHMWxFWktRUmciLCJjX2hhc2giOiJVNXluRlpkT1pQMzY0eHNyRU1YTnFRIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.CpSIVHyc0rVyVxnGZidk8dOGRYMr4GdrM6ia71DfmQwrLn0rnvOLftE2wnlGsnnYGmJRYkui0jV_BT2WbvxGBB4F74YOkjWLqXq0vW8tHdSg1B-88tZr3KhlvoXQn-humNaGKBrNikZYEG9Out3qeiCzhH8kPJHbw1YAK08-uXaivkD_dAckeXf34tvQDE7mLwqy0V86AjBHNL5rmQMWaHieFTdfNW5tFP22VkzouhYm9PuoMWw4DRqITMIT6XcfeOJlfApir142WTpoTw87a3MJAcS89BQWp4jRK6ZbEdtaV0u3V4chuJFeQlLaFIFM9SgRX_WlKBkkxSub9F0eqA",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImRhYjk1N2Q0YmRlOTQzMGE3NDRlZDZmM2JlMmQ3ZDlmNWFlMGU0ZGEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzOTAwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWFEyZDFKd1NUaENVbE5sZG1sQ2QzZHBSbkExVFZFdk1UbGxPREkwTURkaFlqaG1NbUZpTkVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTM0MDA3NTksImlhdCI6MTY5MzMxNDM1OSwibm9uY2UiOiI5YnZTWTRtaV9yUzlqQVRZZTFBQmFnIiwiYXRfaGFzaCI6IkhPWEtQclU5V1ZfZkZHMWxFWktRUmciLCJjX2hhc2giOiJVNXluRlpkT1pQMzY0eHNyRU1YTnFRIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.CpSIVHyc0rVyVxnGZidk8dOGRYMr4GdrM6ia71DfmQwrLn0rnvOLftE2wnlGsnnYGmJRYkui0jV_BT2WbvxGBB4F74YOkjWLqXq0vW8tHdSg1B-88tZr3KhlvoXQn-humNaGKBrNikZYEG9Out3qeiCzhH8kPJHbw1YAK08-uXaivkD_dAckeXf34tvQDE7mLwqy0V86AjBHNL5rmQMWaHieFTdfNW5tFP22VkzouhYm9PuoMWw4DRqITMIT6XcfeOJlfApir142WTpoTw87a3MJAcS89BQWp4jRK6ZbEdtaV0u3V4chuJFeQlLaFIFM9SgRX_WlKBkkxSub9F0eqA
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImRhYjk1N2Q0YmRlOTQzMGE3NDRlZDZmM2JlMmQ3ZDlmNWFlMGU0ZGEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzOTAwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWFEyZDFKd1NUaENVbE5sZG1sQ2QzZHBSbkExVFZFdk1UbGxPREkwTURkaFlqaG1NbUZpTkVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTM0MDA3NTksImlhdCI6MTY5MzMxNDM1OSwibm9uY2UiOiI5YnZTWTRtaV9yUzlqQVRZZTFBQmFnIiwiYXRfaGFzaCI6IkhPWEtQclU5V1ZfZkZHMWxFWktRUmciLCJjX2hhc2giOiJVNXluRlpkT1pQMzY0eHNyRU1YTnFRIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.CpSIVHyc0rVyVxnGZidk8dOGRYMr4GdrM6ia71DfmQwrLn0rnvOLftE2wnlGsnnYGmJRYkui0jV_BT2WbvxGBB4F74YOkjWLqXq0vW8tHdSg1B-88tZr3KhlvoXQn-humNaGKBrNikZYEG9Out3qeiCzhH8kPJHbw1YAK08-uXaivkD_dAckeXf34tvQDE7mLwqy0V86AjBHNL5rmQMWaHieFTdfNW5tFP22VkzouhYm9PuoMWw4DRqITMIT6XcfeOJlfApir142WTpoTw87a3MJAcS89BQWp4jRK6ZbEdtaV0u3V4chuJFeQlLaFIFM9SgRX_WlKBkkxSub9F0eqA)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImRhYjk1N2Q0YmRlOTQzMGE3NDRlZDZmM2Jl
MmQ3ZDlmNWFlMGU0ZGEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzOTAwL2RleCIsI
nN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWFEyZDFKd1NUaENVbE5sZG1sQ2QzZHBSb
kExVFZFdk1UbGxPREkwTURkaFlqaG1NbUZpTkVCM2FYSmxMbU52YlJJRWJHUmhjQ
SIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTM0MDA3NTksImlhdCI6MTY5MzMxN
DM1OSwibm9uY2UiOiI5YnZTWTRtaV9yUzlqQVRZZTFBQmFnIiwiYXRfaGFzaCI6I
khPWEtQclU5V1ZfZkZHMWxFWktRUmciLCJjX2hhc2giOiJVNXluRlpkT1pQMzY0e
HNyRU1YTnFRIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlc
nJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.CpSIVHyc0rVyVxnGZidk8dOGR
YMr4GdrM6ia71DfmQwrLn0rnvOLftE2wnlGsnnYGmJRYkui0jV_BT2WbvxGBB4F7
4YOkjWLqXq0vW8tHdSg1B-88tZr3KhlvoXQn-humNaGKBrNikZYEG9Out3qeiCzh
H8kPJHbw1YAK08-uXaivkD_dAckeXf34tvQDE7mLwqy0V86AjBHNL5rmQMWaHieF
TdfNW5tFP22VkzouhYm9PuoMWw4DRqITMIT6XcfeOJlfApir142WTpoTw87a3MJA
cS89BQWp4jRK6ZbEdtaV0u3V4chuJFeQlLaFIFM9SgRX_WlKBkkxSub9F0eqA
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "dab957d4bde9430a744ed6f3be2d7d9f5ae0e4da"
}
```

```json
{
  "at_hash": "HOXKPrU9WV_fFG1lEZKQRg",
  "aud": "wireapp",
  "c_hash": "U5ynFZdOZP364xsrEMXNqQ",
  "exp": 1693400759,
  "iat": 1693314359,
  "iss": "http://dex:23900/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "9bvSY4mi_rS9jATYe1ABag",
  "preferred_username": "Alice Smith",
  "sub": "CjtpbTp3aXJlYXBwPXQ2d1JwSThCUlNldmlCd3dpRnA1TVEvMTllODI0MDdhYjhmMmFiNEB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArggtxhbrQgRnlRZcl+uN
P8GNXqZW7/pA3qVC0hL6l1K0RXQlTEECt/CDudnXhAqueiY0whZa6zXNCy00MOkU
Wi4sIQkxBh+sCOM4CIxC2rw2ZeB+l4GFhjj1sHrq29xYjhrO7Ss5rl2z7FN2gqgK
q3DSUSiLsFKnsiyDbHlxIelynLNB2CWic1uYeCAwJuJ6d7cD69OK2DeGeeT9ZTUg
P3I8yZPYRR9//MTP04m4lCg49SgI05GUdCsrhpaTScdUbswpaVanAnOxZqoD+6kW
ozXeZWE5jMdhct3Kz7epmZEp7rljjBYhdVHLL/G9xkXPJtAI1K9VlxfZngits8U8
HQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/1l8R6fyr5Fl6klrfNSRgNZxVFKyX8BYA
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTA2L2FjbWUvd2lyZS9hY2NvdW50LzU4UzBwOUk4QlBTS3BWa21FV0tJaFFTT1NXM3lQZXo4IiwidHlwIjoiSldUIiwibm9uY2UiOiJibk0zY1ZRNWFWUkhkbXBIUWtWeU1VbHlUR295ZEdGRVIwSm9RME5GVkVFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDYvYWNtZS93aXJlL2NoYWxsZW5nZS9DQUFoWUtLYTkzVVdYWFlFbmg1aWFURE12ZnNkV1JwSS8xbDhSNmZ5cjVGbDZrbHJmTlNSZ05aeFZGS3lYOEJZQSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJbVJoWWprMU4yUTBZbVJsT1RRek1HRTNORFJsWkRabU0ySmxNbVEzWkRsbU5XRmxNR1UwWkdFaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSXpPVEF3TDJSbGVDSXNJbk4xWWlJNklrTnFkSEJpVkhBellWaEtiRmxZUW5kUVdGRXlaREZLZDFOVWFFTlZiRTVzWkcxc1EyUXpaSEJTYmtFeFZGWkZkazFVYkd4UFJFa3dUVVJrYUZscWFHMU5iVVpwVGtWQ00yRllTbXhNYlU1MllsSkpSV0pIVW1oalFTSXNJbUYxWkNJNkluZHBjbVZoY0hBaUxDSmxlSEFpT2pFMk9UTTBNREEzTlRrc0ltbGhkQ0k2TVRZNU16TXhORE0xT1N3aWJtOXVZMlVpT2lJNVluWlRXVFJ0YVY5eVV6bHFRVlJaWlRGQlFtRm5JaXdpWVhSZmFHRnphQ0k2SWtoUFdFdFFjbFU1VjFaZlprWkhNV3hGV2t0UlVtY2lMQ0pqWDJoaGMyZ2lPaUpWTlhsdVJscGtUMXBRTXpZMGVITnlSVTFZVG5GUklpd2libUZ0WlNJNkltbHRPbmRwY21WaGNIQTlZV3hwWTJWZmQybHlaU0lzSW5CeVpXWmxjbkpsWkY5MWMyVnlibUZ0WlNJNklrRnNhV05sSUZOdGFYUm9JbjAuQ3BTSVZIeWMwclZ5VnhuR1ppZGs4ZE9HUllNcjRHZHJNNmlhNzFEZm1Rd3JMbjBybnZPTGZ0RTJ3bmxHc25uWUdtSlJZa3VpMGpWX0JUMldidnhHQkI0Rjc0WU9raldMcVhxMHZXOHRIZFNnMUItODh0WnIzS2hsdm9YUW4taHVtTmFHS0JyTmlrWllFRzlPdXQzcWVpQ3poSDhrUEpIYncxWUFLMDgtdVhhaXZrRF9kQWNrZVhmMzR0dlFERTdtTHdxeTBWODZBakJITkw1cm1RTVdhSGllRlRkZk5XNXRGUDIyVmt6b3VoWW05UHVvTVd3NERScUlUTUlUNlhjZmVPSmxmQXBpcjE0MldUcG9Udzg3YTNNSkFjUzg5QlFXcDRqUks2WmJFZHRhVjB1M1Y0Y2h1SkZlUWxMYUZJRk05U2dSWF9XbEtCa2t4U3ViOUYwZXFBIiwia2V5YXV0aCI6IkhubExWUkViUW1Zd1Y5NkFNVWJZdFh6TWZQVEVGUTVmLjYxNFc1VkxLWmxLRjBOa21pVGFQSklUQ2lzVnhqclEwRlJvUkozLUxWV1UifQ",
  "signature": "_3NhKhIjqNkAEL_RG8zvuudWlP1NOu1Mxz5uqOIsqIR4lxPM3CdhvKZFQHBRUqZDTSyDDZpeFEjIs5J3XDjKCg"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImRhYjk1N2Q0YmRlOTQzMGE3NDRlZDZmM2JlMmQ3ZDlmNWFlMGU0ZGEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzOTAwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWFEyZDFKd1NUaENVbE5sZG1sQ2QzZHBSbkExVFZFdk1UbGxPREkwTURkaFlqaG1NbUZpTkVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTM0MDA3NTksImlhdCI6MTY5MzMxNDM1OSwibm9uY2UiOiI5YnZTWTRtaV9yUzlqQVRZZTFBQmFnIiwiYXRfaGFzaCI6IkhPWEtQclU5V1ZfZkZHMWxFWktRUmciLCJjX2hhc2giOiJVNXluRlpkT1pQMzY0eHNyRU1YTnFRIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.CpSIVHyc0rVyVxnGZidk8dOGRYMr4GdrM6ia71DfmQwrLn0rnvOLftE2wnlGsnnYGmJRYkui0jV_BT2WbvxGBB4F74YOkjWLqXq0vW8tHdSg1B-88tZr3KhlvoXQn-humNaGKBrNikZYEG9Out3qeiCzhH8kPJHbw1YAK08-uXaivkD_dAckeXf34tvQDE7mLwqy0V86AjBHNL5rmQMWaHieFTdfNW5tFP22VkzouhYm9PuoMWw4DRqITMIT6XcfeOJlfApir142WTpoTw87a3MJAcS89BQWp4jRK6ZbEdtaV0u3V4chuJFeQlLaFIFM9SgRX_WlKBkkxSub9F0eqA",
    "keyauth": "HnlLVREbQmYwV96AMUbYtXzMfPTEFQ5f.614W5VLKZlKF0NkmiTaPJITCisVxjrQ0FRoRJ3-LVWU"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32906/acme/wire/account/58S0p9I8BPSKpVkmEWKIhQSOSW3yPez8",
    "nonce": "bnM3cVQ5aVRHdmpHQkVyMUlyTGoydGFER0JoQ0NFVEE",
    "typ": "JWT",
    "url": "https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/1l8R6fyr5Fl6klrfNSRgNZxVFKyX8BYA"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32906/acme/wire/directory>;rel="index"
link: <https://stepca:32906/acme/wire/authz/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI>;rel="up"
location: https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/1l8R6fyr5Fl6klrfNSRgNZxVFKyX8BYA
replay-nonce: aTdnNFlyaVo1SjQ3eFBwTm9SREhISFBzYURVaVRoZ3c
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32906/acme/wire/challenge/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI/1l8R6fyr5Fl6klrfNSRgNZxVFKyX8BYA",
  "status": "valid",
  "token": "HnlLVREbQmYwV96AMUbYtXzMfPTEFQ5f",
  "target": "http://dex:23900/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTA2L2FjbWUvd2lyZS9hY2NvdW50LzU4UzBwOUk4QlBTS3BWa21FV0tJaFFTT1NXM3lQZXo4IiwidHlwIjoiSldUIiwibm9uY2UiOiJhVGRuTkZseWFWbzFTalEzZUZCd1RtOVNSRWhJU0ZCellVUlZhVlJvWjNjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDYvYWNtZS93aXJlL29yZGVyL05FZk1FOUtCMGdJRE82RlgxS3BTV1pqWDNSODVWMGc4In0",
  "payload": "",
  "signature": "FMlRXPpkrYry5BCHrc3TYJ8eR_riWUi6VDXrIV5Ts2Tbu550gmPDcxdXZUTraRk7sJi42jfzrr9vQIFWnlQyBg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32906/acme/wire/account/58S0p9I8BPSKpVkmEWKIhQSOSW3yPez8",
    "nonce": "aTdnNFlyaVo1SjQ3eFBwTm9SREhISFBzYURVaVRoZ3c",
    "typ": "JWT",
    "url": "https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32906/acme/wire/directory>;rel="index"
location: https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8
replay-nonce: bXZOc3BCSHd3WWoxTXZhMFJFUzFlRmFzZlYzVUQ2dGs
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32906/acme/wire/authz/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI"
  ],
  "expires": "2023-08-30T13:05:58Z",
  "notBefore": "2023-08-29T13:05:58.948383Z",
  "notAfter": "2033-08-26T13:05:58.948383Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTA2L2FjbWUvd2lyZS9hY2NvdW50LzU4UzBwOUk4QlBTS3BWa21FV0tJaFFTT1NXM3lQZXo4IiwidHlwIjoiSldUIiwibm9uY2UiOiJiWFpPYzNCQ1NIZDNXV294VFhaaE1GSkZVekZsUm1GelpsWXpWVVEyZEdzIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDYvYWNtZS93aXJlL29yZGVyL05FZk1FOUtCMGdJRE82RlgxS3BTV1pqWDNSODVWMGc4L2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCSVRDQjFBSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTVkzRHdRWTNRaFZ5Z0JiX2hQYmhfUjRublZtc0NNc0stNHFEMlF0VUlkMG9IQXdiZ1lKS29aSWh2Y05BUWtPTVdFd1h6QmRCZ05WSFJFRVZqQlVoanRwYlRwM2FYSmxZWEJ3UFhRMmQxSndTVGhDVWxObGRtbENkM2RwUm5BMVRWRXZNVGxsT0RJME1EZGhZamhtTW1GaU5FQjNhWEpsTG1OdmJZWVZhVzA2ZDJseVpXRndjRDFoYkdsalpWOTNhWEpsTUFVR0F5dGxjQU5CQU1NSXVjMld2TlFhSmpXTEVCNkdQNS0xcFFyRVBMV0hleGc5andGUzZmZnJ1MVMzcEN3YXhiUTVQdlB6ZWFBSTlweFN0am9IOWV6WndoZExUbkZZQ3drIn0",
  "signature": "QaPh0WQ52yD0FfkH9lcc0LGAj9YqszygoxfiwkmzRGffYiFv7nZvEFp6r5dYlqAn2CX1S9oXLz7n7YtEk1R8Ag"
}
```
```json
{
  "payload": {
    "csr": "MIIBITCB1AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMY3DwQY3QhVygBb_hPbh_R4nnVmsCMsK-4qD2QtUId0oHAwbgYJKoZIhvcNAQkOMWEwXzBdBgNVHREEVjBUhjtpbTp3aXJlYXBwPXQ2d1JwSThCUlNldmlCd3dpRnA1TVEvMTllODI0MDdhYjhmMmFiNEB3aXJlLmNvbYYVaW06d2lyZWFwcD1hbGljZV93aXJlMAUGAytlcANBAMMIuc2WvNQaJjWLEB6GP5-1pQrEPLWHexg9jwFS6ffru1S3pCwaxbQ5PvPzeaAI9pxStjoH9ezZwhdLTnFYCwk"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32906/acme/wire/account/58S0p9I8BPSKpVkmEWKIhQSOSW3yPez8",
    "nonce": "bXZOc3BCSHd3WWoxTXZhMFJFUzFlRmFzZlYzVUQ2dGs",
    "typ": "JWT",
    "url": "https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBITCB1AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMY3DwQY3QhVygBb/hPbh/R4nnVmsCMs
K+4qD2QtUId0oHAwbgYJKoZIhvcNAQkOMWEwXzBdBgNVHREEVjBUhjtpbTp3aXJl
YXBwPXQ2d1JwSThCUlNldmlCd3dpRnA1TVEvMTllODI0MDdhYjhmMmFiNEB3aXJl
LmNvbYYVaW06d2lyZWFwcD1hbGljZV93aXJlMAUGAytlcANBAMMIuc2WvNQaJjWL
EB6GP5+1pQrEPLWHexg9jwFS6ffru1S3pCwaxbQ5PvPzeaAI9pxStjoH9ezZwhdL
TnFYCwk=
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
                    c6:37:0f:04:18:dd:08:55:ca:00:5b:fe:13:db:87:
                    f4:78:9e:75:66:b0:23:2c:2b:ee:2a:0f:64:2d:50:
                    87:74
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        c3:08:b9:cd:96:bc:d4:1a:26:35:8b:10:1e:86:3f:9f:b5:a5:
        0a:c4:3c:b5:87:7b:18:3d:8f:01:52:e9:f7:eb:bb:54:b7:a4:
        2c:1a:c5:b4:39:3e:f3:f3:79:a0:08:f6:9c:52:b6:3a:07:f5:
        ec:d9:c2:17:4b:4e:71:58:0b:09

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32906/acme/wire/directory>;rel="index"
location: https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8
replay-nonce: NVNkWTVxWnFqaVBsYk5xR01qQWxxUzVacU1xOGd0Vnc
```
```json
{
  "certificate": "https://stepca:32906/acme/wire/certificate/BZ0Y9vLuddsNnSAHmFxdi8aP1hCcUNSW",
  "status": "valid",
  "finalize": "https://stepca:32906/acme/wire/order/NEfME9KB0gIDO6FX1KpSWZjX3R85V0g8/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32906/acme/wire/authz/CAAhYKKa93UWXXYEnh5iaTDMvfsdWRpI"
  ],
  "expires": "2023-08-30T13:05:58Z",
  "notBefore": "2023-08-29T13:05:58.948383Z",
  "notAfter": "2033-08-26T13:05:58.948383Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32906/acme/wire/certificate/BZ0Y9vLuddsNnSAHmFxdi8aP1hCcUNSW
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTA2L2FjbWUvd2lyZS9hY2NvdW50LzU4UzBwOUk4QlBTS3BWa21FV0tJaFFTT1NXM3lQZXo4IiwidHlwIjoiSldUIiwibm9uY2UiOiJOVk5rV1RWeFduRnFhVkJzWWs1eFIwMXFRV3h4VXpWYWNVMXhPR2QwVm5jIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDYvYWNtZS93aXJlL2NlcnRpZmljYXRlL0JaMFk5dkx1ZGRzTm5TQUhtRnhkaThhUDFoQ2NVTlNXIn0",
  "payload": "",
  "signature": "18sK7fnG5rKXy7mvUP6N3_JXN2HDokLMDQKLPbO9lqQb5Zrw9Zi8RT1kOt72QFBrA_WgC1h2l_M6-OIIbXzgCQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32906/acme/wire/account/58S0p9I8BPSKpVkmEWKIhQSOSW3yPez8",
    "nonce": "NVNkWTVxWnFqaVBsYk5xR01qQWxxUzVacU1xOGd0Vnc",
    "typ": "JWT",
    "url": "https://stepca:32906/acme/wire/certificate/BZ0Y9vLuddsNnSAHmFxdi8aP1hCcUNSW"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32906/acme/wire/directory>;rel="index"
replay-nonce: dXJuM0o0bU9KNWc4Sk91cE00OWxjZXhBZEh3R1R1Y1M
```
```json
"-----BEGIN CERTIFICATE-----\nMIICDTCCAbOgAwIBAgIQYBkeKaeo9/D8kYHJEmUnwDAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzA4MjkxMzA1NThaFw0zMzA4MjYxMzA1NThaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMY3DwQY3QhVygBb/hPb\nh/R4nnVmsCMsK+4qD2QtUId0o4HmMIHjMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUSRd5T7/ee1/r7rdeJXD8GlPuRwwwHwYD\nVR0jBBgwFoAUOkICldGwHrzcZ9eK9KU/1AjuTscwXQYDVR0RBFYwVIYVaW06d2ly\nZWFwcD1hbGljZV93aXJlhjtpbTp3aXJlYXBwPXQ2d1JwSThCUlNldmlCd3dpRnA1\nTVEvMTllODI0MDdhYjhmMmFiNEB3aXJlLmNvbTAdBgwrBgEEAYKkZMYoQAEEDTAL\nAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIgH6dXdZfwQbdf9jtqtPETDnWH\nnneeqemtj+/ARxKX98ECIQDRYEQPNn79KDV1NBo8K8Zu/K1YB3MmFvzgBfJtZLQN\nnQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBujCCAV+gAwIBAgIRALK32U9OyqsTtUqvQ73YuO8wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDgyOTEz\nMDU1N1oXDTMzMDgyNjEzMDU1N1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQX\nRoHvgUF2qi05MS3WZUen3IUx7ba9xyMPyE31IUJ3UQj8p7y73/wGEfpzxVlVSiyd\nUVyLmFX2f0Jv6XolMUBoo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUOkICldGwHrzcZ9eK9KU/1AjuTscwHwYDVR0jBBgw\nFoAUbsQV69UNIf435WL3bczhi7uI0sMwCgYIKoZIzj0EAwIDSQAwRgIhALd23LU6\nhGFjG5uPkhP8R2TMMbWrmNRND7YhiuYtOIozAiEAnb9PrAnQDF2hZ/jaslc/bfvl\nVB6NlbH7+N6jHFt/Mzw=\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICDTCCAbOgAwIBAgIQYBkeKaeo9/D8kYHJEmUnwDAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzA4MjkxMzA1NThaFw0zMzA4MjYxMzA1NThaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMY3DwQY3QhVygBb/hPb
h/R4nnVmsCMsK+4qD2QtUId0o4HmMIHjMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUSRd5T7/ee1/r7rdeJXD8GlPuRwwwHwYD
VR0jBBgwFoAUOkICldGwHrzcZ9eK9KU/1AjuTscwXQYDVR0RBFYwVIYVaW06d2ly
ZWFwcD1hbGljZV93aXJlhjtpbTp3aXJlYXBwPXQ2d1JwSThCUlNldmlCd3dpRnA1
TVEvMTllODI0MDdhYjhmMmFiNEB3aXJlLmNvbTAdBgwrBgEEAYKkZMYoQAEEDTAL
AgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIgH6dXdZfwQbdf9jtqtPETDnWH
nneeqemtj+/ARxKX98ECIQDRYEQPNn79KDV1NBo8K8Zu/K1YB3MmFvzgBfJtZLQN
nQ==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            60:19:1e:29:a7:a8:f7:f0:fc:91:81:c9:12:65:27:c0
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Aug 29 13:05:58 2023 GMT
            Not After : Aug 26 13:05:58 2033 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    c6:37:0f:04:18:dd:08:55:ca:00:5b:fe:13:db:87:
                    f4:78:9e:75:66:b0:23:2c:2b:ee:2a:0f:64:2d:50:
                    87:74
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                49:17:79:4F:BF:DE:7B:5F:EB:EE:B7:5E:25:70:FC:1A:53:EE:47:0C
            X509v3 Authority Key Identifier: 
                3A:42:02:95:D1:B0:1E:BC:DC:67:D7:8A:F4:A5:3F:D4:08:EE:4E:C7
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice_wire, URI:im:wireapp=t6wRpI8BRSeviBwwiFp5MQ/19e82407ab8f2ab4@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:1f:a7:57:75:97:f0:41:b7:5f:f6:3b:6a:b4:f1:
        13:0e:75:87:9e:77:9e:a9:e9:ad:8f:ef:c0:47:12:97:f7:c1:
        02:21:00:d1:60:44:0f:36:7e:fd:28:35:75:34:1a:3c:2b:c6:
        6e:fc:ad:58:07:73:26:16:fc:e0:05:f2:6d:64:b4:0d:9d

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBujCCAV+gAwIBAgIRALK32U9OyqsTtUqvQ73YuO8wCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDgyOTEz
MDU1N1oXDTMzMDgyNjEzMDU1N1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQX
RoHvgUF2qi05MS3WZUen3IUx7ba9xyMPyE31IUJ3UQj8p7y73/wGEfpzxVlVSiyd
UVyLmFX2f0Jv6XolMUBoo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUOkICldGwHrzcZ9eK9KU/1AjuTscwHwYDVR0jBBgw
FoAUbsQV69UNIf435WL3bczhi7uI0sMwCgYIKoZIzj0EAwIDSQAwRgIhALd23LU6
hGFjG5uPkhP8R2TMMbWrmNRND7YhiuYtOIozAiEAnb9PrAnQDF2hZ/jaslc/bfvl
VB6NlbH7+N6jHFt/Mzw=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            b2:b7:d9:4f:4e:ca:ab:13:b5:4a:af:43:bd:d8:b8:ef
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Aug 29 13:05:57 2023 GMT
            Not After : Aug 26 13:05:57 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:17:46:81:ef:81:41:76:aa:2d:39:31:2d:d6:65:
                    47:a7:dc:85:31:ed:b6:bd:c7:23:0f:c8:4d:f5:21:
                    42:77:51:08:fc:a7:bc:bb:df:fc:06:11:fa:73:c5:
                    59:55:4a:2c:9d:51:5c:8b:98:55:f6:7f:42:6f:e9:
                    7a:25:31:40:68
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                3A:42:02:95:D1:B0:1E:BC:DC:67:D7:8A:F4:A5:3F:D4:08:EE:4E:C7
            X509v3 Authority Key Identifier: 
                6E:C4:15:EB:D5:0D:21:FE:37:E5:62:F7:6D:CC:E1:8B:BB:88:D2:C3
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:b7:76:dc:b5:3a:84:61:63:1b:9b:8f:92:13:
        fc:47:64:cc:31:b5:ab:98:d4:4d:0f:b6:21:8a:e6:2d:38:8a:
        33:02:21:00:9d:bf:4f:ac:09:d0:0c:5d:a1:67:f8:da:b2:57:
        3f:6d:fb:e5:54:1e:8d:95:b1:fb:f8:de:a3:1c:5b:7f:33:3c

```
