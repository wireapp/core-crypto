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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/7358d069e64422ca/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/V3LKiNPifdQwz0PLladtHRH9WtOu9XFj
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+authorization-server:  GET /dex/auth
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+authorization-server:  POST /dex/token
    authorization-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/oPyI2NPNHw9do0Mql8ZNfvjSo0rQn9H1
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/c0exFVPsOlFAzAnROtOZlL8am0ZGx91A
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:33294/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:33294/acme/wire/new-nonce",
  "newAccount": "https://stepca:33294/acme/wire/new-account",
  "newOrder": "https://stepca:33294/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:33294/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:33294/acme/wire/directory>;rel="index"
replay-nonce: ald2NnlpUnRJYUM3UFI5UHNDVVR4SUtEUU1EN2lKcEk
```
```text
ald2NnlpUnRJYUM3UFI5UHNDVVR4SUtEUU1EN2lKcEk
```
#### 5. create a new account
```http request
POST https://stepca:33294/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJGZ2FMTFExTlY0eFVVQlpLczk0YTVDUzVSLVU2QmwtckdvVEVvR2NyazgifSwibm9uY2UiOiJhbGQyTm5scFVuUkpZVU0zVUZJNVVITkRWVlI0U1V0RVVVMUVOMmxLY0VrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyOTQvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "pj1JKuIR8_KWJcgD5fhIIUuUurfP0LVBcgsAkGPdNmi_yWOO-Ci7B2LY_PR5Pfc_6F3rmgoSoGGWzpqUkW38BQ"
}
```
```json
{
  "payload": {
    "contact": [
      "unknown@example.com"
    ],
    "onlyReturnExisting": false,
    "termsOfServiceAgreed": true
  },
  "protected": {
    "alg": "EdDSA",
    "jwk": {
      "crv": "Ed25519",
      "kty": "OKP",
      "x": "rFgaLLQ1NV4xUUBZKs94a5CS5R-U6Bl-rGoTEoGcrk8"
    },
    "nonce": "ald2NnlpUnRJYUM3UFI5UHNDVVR4SUtEUU1EN2lKcEk",
    "typ": "JWT",
    "url": "https://stepca:33294/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33294/acme/wire/directory>;rel="index"
location: https://stepca:33294/acme/wire/account/4gQp2PqyGfW5PrCZ0d60EkGOPiM5U231
replay-nonce: YVdxQlNYRTFWZ1puTEN0Ym1CbUY0R0tlSnQ2MElDZzA
```
```json
{
  "status": "valid",
  "orders": "https://stepca:33294/acme/wire/account/4gQp2PqyGfW5PrCZ0d60EkGOPiM5U231/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:33294/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjk0L2FjbWUvd2lyZS9hY2NvdW50LzRnUXAyUHF5R2ZXNVByQ1owZDYwRWtHT1BpTTVVMjMxIiwidHlwIjoiSldUIiwibm9uY2UiOiJZVmR4UWxOWVJURldaMXB1VEVOMFltMUNiVVkwUjB0bFNuUTJNRWxEWnpBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyOTQvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9T0dZMU4yVmxaREpqTUdJd05EUm1PVGsyT0daaU16bGlNakUwTkRreU9HTS83MzU4ZDA2OWU2NDQyMmNhQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9YWxpY2Vfd2lyZVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wNS0wOVQwOTo1NjoxOC41NzY5NzhaIiwibm90QWZ0ZXIiOiIyMDIzLTA1LTA5VDEwOjU2OjE4LjU3Njk3OFoifQ",
  "signature": "CDcE1-N8DWnP-JqJtyvBTumjdUr4M3ICXkVZ7TXK41Mt99_pahXslgP2pO-lOsFnNVx2WO4lS2U3BiYFgJ6EDg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2023-05-09T10:56:18.576978Z",
    "notBefore": "2023-05-09T09:56:18.576978Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33294/acme/wire/account/4gQp2PqyGfW5PrCZ0d60EkGOPiM5U231",
    "nonce": "YVdxQlNYRTFWZ1puTEN0Ym1CbUY0R0tlSnQ2MElDZzA",
    "typ": "JWT",
    "url": "https://stepca:33294/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33294/acme/wire/directory>;rel="index"
location: https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X
replay-nonce: bFlFTHZKNnBPdEVwV1NVTnZnS2hzdGlQMVJIdm9naHc
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33294/acme/wire/authz/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf"
  ],
  "expires": "2023-05-10T09:56:18Z",
  "notBefore": "2023-05-09T09:56:18.576978Z",
  "notAfter": "2023-05-09T10:56:18.576978Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:33294/acme/wire/authz/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjk0L2FjbWUvd2lyZS9hY2NvdW50LzRnUXAyUHF5R2ZXNVByQ1owZDYwRWtHT1BpTTVVMjMxIiwidHlwIjoiSldUIiwibm9uY2UiOiJiRmxGVEhaS05uQlBkRVZ3VjFOVlRuWm5TMmh6ZEdsUU1WSklkbTluYUhjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyOTQvYWNtZS93aXJlL2F1dGh6L29Zem9NaGp0V2ZCZkNyeWJVT1BTYXptWU5aaHI2aERmIn0",
  "payload": "",
  "signature": "7DxlfHWNYUjOgF48wfdTn0UJ0KJUi8clLaNI4fx8gMVQRFLqAVAGwq5YeHD10IJBXXmP3cLNzH-M0YjlfHMPAA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33294/acme/wire/account/4gQp2PqyGfW5PrCZ0d60EkGOPiM5U231",
    "nonce": "bFlFTHZKNnBPdEVwV1NVTnZnS2hzdGlQMVJIdm9naHc",
    "typ": "JWT",
    "url": "https://stepca:33294/acme/wire/authz/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33294/acme/wire/directory>;rel="index"
location: https://stepca:33294/acme/wire/authz/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf
replay-nonce: NWsyWmdzZUIzZ2lJSko2aGNtYXI5MzVsaVMwa2xYTko
```
```json
{
  "status": "pending",
  "expires": "2023-05-10T09:56:18Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/oPyI2NPNHw9do0Mql8ZNfvjSo0rQn9H1",
      "status": "pending",
      "token": "lzKZqjB6Xc3KbLJkEnfKbPYphnZhjNv0",
      "target": "http://dex:18263/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/V3LKiNPifdQwz0PLladtHRH9WtOu9XFj",
      "status": "pending",
      "token": "lzKZqjB6Xc3KbLJkEnfKbPYphnZhjNv0",
      "target": "http://wire.com:22899/clients/7358d069e64422ca/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:22899/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
bEsydFlSNTNCS01NV2dxMGJ6bmJUdFJuZFRMa0FPUUs
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoickZnYUxMUTFOVjR4VVVCWktzOTRhNUNTNVItVTZCbC1yR29URW9HY3JrOCJ9fQ.eyJpYXQiOjE2ODM2MjYxNzgsImV4cCI6MTY4MzYyOTc3OCwibmJmIjoxNjgzNjI2MTczLCJzdWIiOiJpbTp3aXJlYXBwPU9HWTFOMlZsWkRKak1HSXdORFJtT1RrMk9HWmlNemxpTWpFME5Ea3lPR00vNzM1OGQwNjllNjQ0MjJjYUB3aXJlLmNvbSIsImp0aSI6ImNjMzUzMmE3LWY5ZGEtNDFjNS04ZWVjLTk5YWViNzFlMmRiMyIsIm5vbmNlIjoiYkVzeWRGbFNOVE5DUzAxTlYyZHhNR0o2Ym1KVWRGSnVaRlJNYTBGUFVVcyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjI4OTkvY2xpZW50cy83MzU4ZDA2OWU2NDQyMmNhL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJsektacWpCNlhjM0tiTEprRW5mS2JQWXBoblpoak52MCJ9.EUOZbGivzgYa2tebgIjVogc6zYsERzq5L1cJ45_T1qbiVDcLLwlvTBs1U-LLWL9palub8vVLhFofUPTszni6Bg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoickZnYUxMUTFOVjR4VVVCWktzOTRhNUNT
NVItVTZCbC1yR29URW9HY3JrOCJ9fQ.eyJpYXQiOjE2ODM2MjYxNzgsImV4cCI6M
TY4MzYyOTc3OCwibmJmIjoxNjgzNjI2MTczLCJzdWIiOiJpbTp3aXJlYXBwPU9HW
TFOMlZsWkRKak1HSXdORFJtT1RrMk9HWmlNemxpTWpFME5Ea3lPR00vNzM1OGQwN
jllNjQ0MjJjYUB3aXJlLmNvbSIsImp0aSI6ImNjMzUzMmE3LWY5ZGEtNDFjNS04Z
WVjLTk5YWViNzFlMmRiMyIsIm5vbmNlIjoiYkVzeWRGbFNOVE5DUzAxTlYyZHhNR
0o2Ym1KVWRGSnVaRlJNYTBGUFVVcyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MjI4OTkvY2xpZW50cy83MzU4ZDA2OWU2NDQyMmNhL2FjY2Vzc
y10b2tlbiIsImNoYWwiOiJsektacWpCNlhjM0tiTEprRW5mS2JQWXBoblpoak52M
CJ9.EUOZbGivzgYa2tebgIjVogc6zYsERzq5L1cJ45_T1qbiVDcLLwlvTBs1U-LL
WL9palub8vVLhFofUPTszni6Bg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "rFgaLLQ1NV4xUUBZKs94a5CS5R-U6Bl-rGoTEoGcrk8"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "lzKZqjB6Xc3KbLJkEnfKbPYphnZhjNv0",
  "exp": 1683629778,
  "htm": "POST",
  "htu": "http://wire.com:22899/clients/7358d069e64422ca/access-token",
  "iat": 1683626178,
  "jti": "cc3532a7-f9da-41c5-8eec-99aeb71e2db3",
  "nbf": 1683626173,
  "nonce": "bEsydFlSNTNCS01NV2dxMGJ6bmJUdFJuZFRMa0FPUUs",
  "sub": "im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILOYwT3j6Um76IrP7w5Aq2d6byhLWOvAgnw7HO0yFSBj
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEArFgaLLQ1NV4xUUBZKs94a5CS5R+U6Bl+rGoTEoGcrk8=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:22899/clients/7358d069e64422ca/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pY2tabllVeE1VVEZPVmpSNFZWVkNXa3R6T1RSaE5VTlROVkl0VlRaQ2JDMXlSMjlVUlc5SFkzSnJPQ0o5ZlEuZXlKcFlYUWlPakUyT0RNMk1qWXhOemdzSW1WNGNDSTZNVFk0TXpZeU9UYzNPQ3dpYm1KbUlqb3hOamd6TmpJMk1UY3pMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTlIV1RGT01sWnNXa1JLYWsxSFNYZE9SRkp0VDFSck1rOUhXbWxOZW14cFRXcEZNRTVFYTNsUFIwMHZOek0xT0dRd05qbGxOalEwTWpKallVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltTmpNelV6TW1FM0xXWTVaR0V0TkRGak5TMDRaV1ZqTFRrNVlXVmlOekZsTW1SaU15SXNJbTV2Ym1ObElqb2lZa1Z6ZVdSR2JGTk9WRTVEVXpBeFRsWXlaSGhOUjBvMlltMUtWV1JHU25WYVJsSk5ZVEJHVUZWVmN5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakk0T1RrdlkyeHBaVzUwY3k4M016VTRaREEyT1dVMk5EUXlNbU5oTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnNla3RhY1dwQ05saGpNMHRpVEVwclJXNW1TMkpRV1hCb2JscG9hazUyTUNKOS5FVU9aYkdpdnpnWWEydGViZ0lqVm9nYzZ6WXNFUnpxNUwxY0o0NV9UMXFiaVZEY0xMd2x2VEJzMVUtTExXTDlwYWx1Yjh2VkxoRm9mVVBUc3puaTZCZw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlV6bG1UdEZqZzk1ZXB5NFpiS3J3QU9pRk5vaTk0NVhJZUJib1UtNU5tT28ifX0.eyJpYXQiOjE2ODM2MjYxNzgsImV4cCI6MTY5MTQwMjE3OCwibmJmIjoxNjgzNjI2MTczLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjI4OTkvY2xpZW50cy83MzU4ZDA2OWU2NDQyMmNhL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9T0dZMU4yVmxaREpqTUdJd05EUm1PVGsyT0daaU16bGlNakUwTkRreU9HTS83MzU4ZDA2OWU2NDQyMmNhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIyODk5L2NsaWVudHMvNzM1OGQwNjllNjQ0MjJjYS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhM2VhMDM5Zi00M2Q0LTQ4YTMtOTliYi02NWE5MTY0MmUxMDMiLCJub25jZSI6ImJFc3lkRmxTTlROQ1MwMU5WMmR4TUdKNmJtSlVkRkp1WkZSTWEwRlBVVXMiLCJjaGFsIjoibHpLWnFqQjZYYzNLYkxKa0VuZktiUFlwaG5aaGpOdjAiLCJjbmYiOnsia2lkIjoiMEExZ1J5c3dLUlRjd0RtNXBQTTZid0hSNFYzMnhtTFFGSi1QZGVkSWRjdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWNrWm5ZVXhNVVRGT1ZqUjRWVlZDV2t0ek9UUmhOVU5UTlZJdFZUWkNiQzF5UjI5VVJXOUhZM0pyT0NKOWZRLmV5SnBZWFFpT2pFMk9ETTJNall4Tnpnc0ltVjRjQ0k2TVRZNE16WXlPVGMzT0N3aWJtSm1Jam94Tmpnek5qSTJNVGN6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5SFdURk9NbFpzV2tSS2FrMUhTWGRPUkZKdFQxUnJNazlIV21sTmVteHBUV3BGTUU1RWEzbFBSMDB2TnpNMU9HUXdOamxsTmpRME1qSmpZVUIzYVhKbExtTnZiU0lzSW1wMGFTSTZJbU5qTXpVek1tRTNMV1k1WkdFdE5ERmpOUzA0WldWakxUazVZV1ZpTnpGbE1tUmlNeUlzSW01dmJtTmxJam9pWWtWemVXUkdiRk5PVkU1RFV6QXhUbFl5WkhoTlIwbzJZbTFLVldSR1NuVmFSbEpOWVRCR1VGVlZjeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJNE9Ua3ZZMnhwWlc1MGN5ODNNelU0WkRBMk9XVTJORFF5TW1OaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUpzZWt0YWNXcENObGhqTTB0aVRFcHJSVzVtUzJKUVdYQm9ibHBvYWs1Mk1DSjkuRVVPWmJHaXZ6Z1lhMnRlYmdJalZvZ2M2ellzRVJ6cTVMMWNKNDVfVDFxYmlWRGNMTHdsdlRCczFVLUxMV0w5cGFsdWI4dlZMaEZvZlVQVHN6bmk2QmciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU9HWTFOMlZsWkRKak1HSXdORFJtT1RrMk9HWmlNemxpTWpFME5Ea3lPR00vNzM1OGQwNjllNjQ0MjJjYUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.9fK_PeHZK6DzJmaGTNmWkT1PjfsvOmP0ekzcl95FdwX9hFqcXXjsgu6lC3MpgyfFvwnY3__6g70fBii7eKhiCw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlV6bG1UdEZqZzk1ZXB5NFpiS3J3QU9pRk5vaTk0NVhJZUJib1UtNU5tT28ifX0.eyJpYXQiOjE2ODM2MjYxNzgsImV4cCI6MTY5MTQwMjE3OCwibmJmIjoxNjgzNjI2MTczLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjI4OTkvY2xpZW50cy83MzU4ZDA2OWU2NDQyMmNhL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9T0dZMU4yVmxaREpqTUdJd05EUm1PVGsyT0daaU16bGlNakUwTkRreU9HTS83MzU4ZDA2OWU2NDQyMmNhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIyODk5L2NsaWVudHMvNzM1OGQwNjllNjQ0MjJjYS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhM2VhMDM5Zi00M2Q0LTQ4YTMtOTliYi02NWE5MTY0MmUxMDMiLCJub25jZSI6ImJFc3lkRmxTTlROQ1MwMU5WMmR4TUdKNmJtSlVkRkp1WkZSTWEwRlBVVXMiLCJjaGFsIjoibHpLWnFqQjZYYzNLYkxKa0VuZktiUFlwaG5aaGpOdjAiLCJjbmYiOnsia2lkIjoiMEExZ1J5c3dLUlRjd0RtNXBQTTZid0hSNFYzMnhtTFFGSi1QZGVkSWRjdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWNrWm5ZVXhNVVRGT1ZqUjRWVlZDV2t0ek9UUmhOVU5UTlZJdFZUWkNiQzF5UjI5VVJXOUhZM0pyT0NKOWZRLmV5SnBZWFFpT2pFMk9ETTJNall4Tnpnc0ltVjRjQ0k2TVRZNE16WXlPVGMzT0N3aWJtSm1Jam94Tmpnek5qSTJNVGN6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5SFdURk9NbFpzV2tSS2FrMUhTWGRPUkZKdFQxUnJNazlIV21sTmVteHBUV3BGTUU1RWEzbFBSMDB2TnpNMU9HUXdOamxsTmpRME1qSmpZVUIzYVhKbExtTnZiU0lzSW1wMGFTSTZJbU5qTXpVek1tRTNMV1k1WkdFdE5ERmpOUzA0WldWakxUazVZV1ZpTnpGbE1tUmlNeUlzSW01dmJtTmxJam9pWWtWemVXUkdiRk5PVkU1RFV6QXhUbFl5WkhoTlIwbzJZbTFLVldSR1NuVmFSbEpOWVRCR1VGVlZjeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJNE9Ua3ZZMnhwWlc1MGN5ODNNelU0WkRBMk9XVTJORFF5TW1OaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUpzZWt0YWNXcENObGhqTTB0aVRFcHJSVzVtUzJKUVdYQm9ibHBvYWs1Mk1DSjkuRVVPWmJHaXZ6Z1lhMnRlYmdJalZvZ2M2ellzRVJ6cTVMMWNKNDVfVDFxYmlWRGNMTHdsdlRCczFVLUxMV0w5cGFsdWI4dlZMaEZvZlVQVHN6bmk2QmciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU9HWTFOMlZsWkRKak1HSXdORFJtT1RrMk9HWmlNemxpTWpFME5Ea3lPR00vNzM1OGQwNjllNjQ0MjJjYUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.9fK_PeHZK6DzJmaGTNmWkT1PjfsvOmP0ekzcl95FdwX9hFqcXXjsgu6lC3MpgyfFvwnY3__6g70fBii7eKhiCw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IlV6bG1UdEZqZzk1ZXB5NFpiS3J3QU9pRk5v
aTk0NVhJZUJib1UtNU5tT28ifX0.eyJpYXQiOjE2ODM2MjYxNzgsImV4cCI6MTY5
MTQwMjE3OCwibmJmIjoxNjgzNjI2MTczLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjI4OTkvY2xpZW50cy83MzU4ZDA2OWU2NDQyMmNhL2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9T0dZMU4yVmxaREpqTUdJd05EUm1PVGsyT0daaU16bGlN
akUwTkRreU9HTS83MzU4ZDA2OWU2NDQyMmNhQHdpcmUuY29tIiwiYXVkIjoiaHR0
cDovL3dpcmUuY29tOjIyODk5L2NsaWVudHMvNzM1OGQwNjllNjQ0MjJjYS9hY2Nl
c3MtdG9rZW4iLCJqdGkiOiJhM2VhMDM5Zi00M2Q0LTQ4YTMtOTliYi02NWE5MTY0
MmUxMDMiLCJub25jZSI6ImJFc3lkRmxTTlROQ1MwMU5WMmR4TUdKNmJtSlVkRkp1
WkZSTWEwRlBVVXMiLCJjaGFsIjoibHpLWnFqQjZYYzNLYkxKa0VuZktiUFlwaG5a
aGpOdjAiLCJjbmYiOnsia2lkIjoiMEExZ1J5c3dLUlRjd0RtNXBQTTZid0hSNFYz
MnhtTFFGSi1QZGVkSWRjdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lz
SW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lz
SW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWNrWm5ZVXhNVVRGT1ZqUjRWVlZD
V2t0ek9UUmhOVU5UTlZJdFZUWkNiQzF5UjI5VVJXOUhZM0pyT0NKOWZRLmV5SnBZ
WFFpT2pFMk9ETTJNall4Tnpnc0ltVjRjQ0k2TVRZNE16WXlPVGMzT0N3aWJtSm1J
am94Tmpnek5qSTJNVGN6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5SFdURk9N
bFpzV2tSS2FrMUhTWGRPUkZKdFQxUnJNazlIV21sTmVteHBUV3BGTUU1RWEzbFBS
MDB2TnpNMU9HUXdOamxsTmpRME1qSmpZVUIzYVhKbExtTnZiU0lzSW1wMGFTSTZJ
bU5qTXpVek1tRTNMV1k1WkdFdE5ERmpOUzA0WldWakxUazVZV1ZpTnpGbE1tUmlN
eUlzSW01dmJtTmxJam9pWWtWemVXUkdiRk5PVkU1RFV6QXhUbFl5WkhoTlIwbzJZ
bTFLVldSR1NuVmFSbEpOWVRCR1VGVlZjeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9k
SFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJNE9Ua3ZZMnhwWlc1MGN5ODNN
elU0WkRBMk9XVTJORFF5TW1OaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lP
aUpzZWt0YWNXcENObGhqTTB0aVRFcHJSVzVtUzJKUVdYQm9ibHBvYWs1Mk1DSjku
RVVPWmJHaXZ6Z1lhMnRlYmdJalZvZ2M2ellzRVJ6cTVMMWNKNDVfVDFxYmlWRGNM
THdsdlRCczFVLUxMV0w5cGFsdWI4dlZMaEZvZlVQVHN6bmk2QmciLCJjbGllbnRf
aWQiOiJpbTp3aXJlYXBwPU9HWTFOMlZsWkRKak1HSXdORFJtT1RrMk9HWmlNemxp
TWpFME5Ea3lPR00vNzM1OGQwNjllNjQ0MjJjYUB3aXJlLmNvbSIsImFwaV92ZXJz
aW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.9fK_PeHZK6DzJmaGTNmW
kT1PjfsvOmP0ekzcl95FdwX9hFqcXXjsgu6lC3MpgyfFvwnY3__6g70fBii7eKhi
Cw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "UzlmTtFjg95epy4ZbKrwAOiFNoi945XIeBboU-5NmOo"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:22899/clients/7358d069e64422ca/access-token",
  "chal": "lzKZqjB6Xc3KbLJkEnfKbPYphnZhjNv0",
  "client_id": "im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com",
  "cnf": {
    "kid": "0A1gRyswKRTcwDm5pPM6bwHR4V32xmLQFJ-PdedIdcw"
  },
  "exp": 1691402178,
  "iat": 1683626178,
  "iss": "http://wire.com:22899/clients/7358d069e64422ca/access-token",
  "jti": "a3ea039f-43d4-48a3-99bb-65a91642e103",
  "nbf": 1683626173,
  "nonce": "bEsydFlSNTNCS01NV2dxMGJ6bmJUdFJuZFRMa0FPUUs",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoickZnYUxMUTFOVjR4VVVCWktzOTRhNUNTNVItVTZCbC1yR29URW9HY3JrOCJ9fQ.eyJpYXQiOjE2ODM2MjYxNzgsImV4cCI6MTY4MzYyOTc3OCwibmJmIjoxNjgzNjI2MTczLCJzdWIiOiJpbTp3aXJlYXBwPU9HWTFOMlZsWkRKak1HSXdORFJtT1RrMk9HWmlNemxpTWpFME5Ea3lPR00vNzM1OGQwNjllNjQ0MjJjYUB3aXJlLmNvbSIsImp0aSI6ImNjMzUzMmE3LWY5ZGEtNDFjNS04ZWVjLTk5YWViNzFlMmRiMyIsIm5vbmNlIjoiYkVzeWRGbFNOVE5DUzAxTlYyZHhNR0o2Ym1KVWRGSnVaRlJNYTBGUFVVcyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjI4OTkvY2xpZW50cy83MzU4ZDA2OWU2NDQyMmNhL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJsektacWpCNlhjM0tiTEprRW5mS2JQWXBoblpoak52MCJ9.EUOZbGivzgYa2tebgIjVogc6zYsERzq5L1cJ45_T1qbiVDcLLwlvTBs1U-LLWL9palub8vVLhFofUPTszni6Bg",
  "scope": "wire_client_id",
  "sub": "im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICR0lVby4b9GqzADW2SVyCF648L9FBBRZZs+Xb3K8+OU
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAUzlmTtFjg95epy4ZbKrwAOiFNoi945XIeBboU+5NmOo=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/V3LKiNPifdQwz0PLladtHRH9WtOu9XFj
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjk0L2FjbWUvd2lyZS9hY2NvdW50LzRnUXAyUHF5R2ZXNVByQ1owZDYwRWtHT1BpTTVVMjMxIiwidHlwIjoiSldUIiwibm9uY2UiOiJOV3N5V21kelpVSXpaMmxKU2tvMmFHTnRZWEk1TXpWc2FWTXdhMnhZVGtvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyOTQvYWNtZS93aXJlL2NoYWxsZW5nZS9vWXpvTWhqdFdmQmZDcnliVU9QU2F6bVlOWmhyNmhEZi9WM0xLaU5QaWZkUXd6MFBMbGFkdEhSSDlXdE91OVhGaiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklsVjZiRzFVZEVacVp6azFaWEI1TkZwaVMzSjNRVTlwUms1dmFUazBOVmhKWlVKaWIxVXROVTV0VDI4aWZYMC5leUpwWVhRaU9qRTJPRE0yTWpZeE56Z3NJbVY0Y0NJNk1UWTVNVFF3TWpFM09Dd2libUptSWpveE5qZ3pOakkyTVRjekxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJNE9Ua3ZZMnhwWlc1MGN5ODNNelU0WkRBMk9XVTJORFF5TW1OaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5VDBkWk1VNHlWbXhhUkVwcVRVZEpkMDVFVW0xUFZHc3lUMGRhYVUxNmJHbE5ha1V3VGtScmVVOUhUUzgzTXpVNFpEQTJPV1UyTkRReU1tTmhRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0RvdkwzZHBjbVV1WTI5dE9qSXlPRGs1TDJOc2FXVnVkSE12TnpNMU9HUXdOamxsTmpRME1qSmpZUzloWTJObGMzTXRkRzlyWlc0aUxDSnFkR2tpT2lKaE0yVmhNRE01WmkwME0yUTBMVFE0WVRNdE9UbGlZaTAyTldFNU1UWTBNbVV4TURNaUxDSnViMjVqWlNJNkltSkZjM2xrUm14VFRsUk9RMU13TVU1V01tUjRUVWRLTm1KdFNsVmtSa3AxV2taU1RXRXdSbEJWVlhNaUxDSmphR0ZzSWpvaWJIcExXbkZxUWpaWVl6TkxZa3hLYTBWdVprdGlVRmx3YUc1YWFHcE9kakFpTENKamJtWWlPbnNpYTJsa0lqb2lNRUV4WjFKNWMzZExVbFJqZDBSdE5YQlFUVFppZDBoU05GWXpNbmh0VEZGR1NpMVFaR1ZrU1dSamR5SjlMQ0p3Y205dlppSTZJbVY1U21oaVIyTnBUMmxLUmxwRlVsUlJVMGx6U1c1U05XTkRTVFpKYlZKM1lqTkJjbUZ1WkRCSmFYZHBZVzVrY2tscWNEZEpiWFF3WlZOSk5rbHJPVXhWUTBselNXMU9lV1JwU1RaSmExWnJUV3BWTVUxVWEybE1RMG8wU1dwdmFXTnJXbTVaVlhoTlZWUkdUMVpxVWpSV1ZsWkRWMnQwZWs5VVVtaE9WVTVVVGxaSmRGWlVXa05pUXpGNVVqSTVWVkpYT1VoWk0wcHlUME5LT1daUkxtVjVTbkJaV0ZGcFQycEZNazlFVFRKTmFsbDRUbnBuYzBsdFZqUmpRMGsyVFZSWk5FMTZXWGxQVkdNelQwTjNhV0p0U20xSmFtOTRUbXBuZWs1cVNUSk5WR042VEVOS2VtUlhTV2xQYVVwd1lsUndNMkZZU214WldFSjNVRlU1U0ZkVVJrOU5iRnB6VjJ0U1MyRnJNVWhUV0dSUFVrWktkRlF4VW5KTmF6bElWMjFzVG1WdGVIQlVWM0JHVFVVMVJXRXpiRkJTTURCMlRucE5NVTlIVVhkT2FteHNUbXBSTUUxcVNtcFpWVUl6WVZoS2JFeHRUblppVTBselNXMXdNR0ZUU1RaSmJVNXFUWHBWZWsxdFJUTk1WMWsxV2tkRmRFNUVSbXBPVXpBMFdsZFdha3hVYXpWWlYxWnBUbnBHYkUxdFVtbE5lVWx6U1cwMWRtSnRUbXhKYW05cFdXdFdlbVZYVWtkaVJrNVBWa1UxUkZWNlFYaFViRmw1V2tob1RsSXdiekpaYlRGTFZsZFNSMU51Vm1GU2JFcE9XVlJDUjFWR1ZsWmplVWx6U1cxb01HSlRTVFpKYkVKUVZURlJhVXhEU205a1NGVnBUMmxLYjJSSVVuZFBhVGgyWkRKc2VWcFROV3BpTWpBMlRXcEpORTlVYTNaWk1uaHdXbGMxTUdONU9ETk5lbFUwV2tSQk1rOVhWVEpPUkZGNVRXMU9hRXd5Um1wWk1sWjZZM2t4TUdJeWRHeGlhVWx6U1cxT2IxbFhkMmxQYVVwelpXdDBZV05YY0VOT2JHaHFUVEIwYVZSRmNISlNWelZ0VXpKS1VWZFlRbTlpYkhCdllXczFNazFEU2prdVJWVlBXbUpIYVhaNloxbGhNblJsWW1kSmFsWnZaMk0yZWxselJWSjZjVFZNTVdOS05EVmZWREZ4WW1sV1JHTk1USGRzZGxSQ2N6RlZMVXhNVjB3NWNHRnNkV0k0ZGxaTWFFWnZabFZRVkhONmJtazJRbWNpTENKamJHbGxiblJmYVdRaU9pSnBiVHAzYVhKbFlYQndQVTlIV1RGT01sWnNXa1JLYWsxSFNYZE9SRkp0VDFSck1rOUhXbWxOZW14cFRXcEZNRTVFYTNsUFIwMHZOek0xT0dRd05qbGxOalEwTWpKallVQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvekxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLjlmS19QZUhaSzZEekptYUdUTm1Xa1QxUGpmc3ZPbVAwZWt6Y2w5NUZkd1g5aEZxY1hYanNndTZsQzNNcGd5ZkZ2d25ZM19fNmc3MGZCaWk3ZUtoaUN3In0",
  "signature": "FJoC4NATNKxMUqKPTovrYmgTTO8SvYbNgYgydRc7FEkR39wHYWnqC0W4CwZdQg7khiutHSALOK8ylvpvOKAWBw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlV6bG1UdEZqZzk1ZXB5NFpiS3J3QU9pRk5vaTk0NVhJZUJib1UtNU5tT28ifX0.eyJpYXQiOjE2ODM2MjYxNzgsImV4cCI6MTY5MTQwMjE3OCwibmJmIjoxNjgzNjI2MTczLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjI4OTkvY2xpZW50cy83MzU4ZDA2OWU2NDQyMmNhL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9T0dZMU4yVmxaREpqTUdJd05EUm1PVGsyT0daaU16bGlNakUwTkRreU9HTS83MzU4ZDA2OWU2NDQyMmNhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIyODk5L2NsaWVudHMvNzM1OGQwNjllNjQ0MjJjYS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhM2VhMDM5Zi00M2Q0LTQ4YTMtOTliYi02NWE5MTY0MmUxMDMiLCJub25jZSI6ImJFc3lkRmxTTlROQ1MwMU5WMmR4TUdKNmJtSlVkRkp1WkZSTWEwRlBVVXMiLCJjaGFsIjoibHpLWnFqQjZYYzNLYkxKa0VuZktiUFlwaG5aaGpOdjAiLCJjbmYiOnsia2lkIjoiMEExZ1J5c3dLUlRjd0RtNXBQTTZid0hSNFYzMnhtTFFGSi1QZGVkSWRjdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWNrWm5ZVXhNVVRGT1ZqUjRWVlZDV2t0ek9UUmhOVU5UTlZJdFZUWkNiQzF5UjI5VVJXOUhZM0pyT0NKOWZRLmV5SnBZWFFpT2pFMk9ETTJNall4Tnpnc0ltVjRjQ0k2TVRZNE16WXlPVGMzT0N3aWJtSm1Jam94Tmpnek5qSTJNVGN6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5SFdURk9NbFpzV2tSS2FrMUhTWGRPUkZKdFQxUnJNazlIV21sTmVteHBUV3BGTUU1RWEzbFBSMDB2TnpNMU9HUXdOamxsTmpRME1qSmpZVUIzYVhKbExtTnZiU0lzSW1wMGFTSTZJbU5qTXpVek1tRTNMV1k1WkdFdE5ERmpOUzA0WldWakxUazVZV1ZpTnpGbE1tUmlNeUlzSW01dmJtTmxJam9pWWtWemVXUkdiRk5PVkU1RFV6QXhUbFl5WkhoTlIwbzJZbTFLVldSR1NuVmFSbEpOWVRCR1VGVlZjeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJNE9Ua3ZZMnhwWlc1MGN5ODNNelU0WkRBMk9XVTJORFF5TW1OaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUpzZWt0YWNXcENObGhqTTB0aVRFcHJSVzVtUzJKUVdYQm9ibHBvYWs1Mk1DSjkuRVVPWmJHaXZ6Z1lhMnRlYmdJalZvZ2M2ellzRVJ6cTVMMWNKNDVfVDFxYmlWRGNMTHdsdlRCczFVLUxMV0w5cGFsdWI4dlZMaEZvZlVQVHN6bmk2QmciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU9HWTFOMlZsWkRKak1HSXdORFJtT1RrMk9HWmlNemxpTWpFME5Ea3lPR00vNzM1OGQwNjllNjQ0MjJjYUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.9fK_PeHZK6DzJmaGTNmWkT1PjfsvOmP0ekzcl95FdwX9hFqcXXjsgu6lC3MpgyfFvwnY3__6g70fBii7eKhiCw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33294/acme/wire/account/4gQp2PqyGfW5PrCZ0d60EkGOPiM5U231",
    "nonce": "NWsyWmdzZUIzZ2lJSko2aGNtYXI5MzVsaVMwa2xYTko",
    "typ": "JWT",
    "url": "https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/V3LKiNPifdQwz0PLladtHRH9WtOu9XFj"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33294/acme/wire/directory>;rel="index"
link: <https://stepca:33294/acme/wire/authz/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf>;rel="up"
location: https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/V3LKiNPifdQwz0PLladtHRH9WtOu9XFj
replay-nonce: MjBocU5SUXp3azhlamxVTGdZZzh6bFA2NlBvR2RhMjI
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/V3LKiNPifdQwz0PLladtHRH9WtOu9XFj",
  "status": "valid",
  "token": "lzKZqjB6Xc3KbLJkEnfKbPYphnZhjNv0",
  "target": "http://wire.com:22899/clients/7358d069e64422ca/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=CTpN5s4PnzcqX7AOcZflrhta3ZYGOD7sCrPTTU5yHd0&code_challenge=ljoQqvGofFHxWQ9pIxNbfziFmhOagoIL-woDMeXiPtc
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:18263/dex/auth?response_type=code&client_id=wireapp&state=Smpg4xAilCp49HJ7TNkspA&code_challenge=ljoQqvGofFHxWQ9pIxNbfziFmhOagoIL-woDMeXiPtc&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A22899%2Fcallback&scope=openid+profile&nonce=0R0OZs_6LMrYaIFqtEd8wQ
```
#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:18263/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpSWEpqYzBZemJtVkdNVVI1YkV0WmRubzFka05MYVRGNg==
```
```text
grant_type=authorization_code&code=dzddq64yorlb2gxb7u6s2h4sd&code_verifier=CTpN5s4PnzcqX7AOcZflrhta3ZYGOD7sCrPTTU5yHd0&redirect_uri=http%3A%2F%2Fwire.com%3A22899%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjVmYzMzZjIxM2M1YzAwM2FiZWM4NzZkZDE3NWFmMmQzMGI5M2M1ZTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MjYzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIV1RGT01sWnNXa1JLYWsxSFNYZE9SRkp0VDFSck1rOUhXbWxOZW14cFRXcEZNRTVFYTNsUFIwMHZOek0xT0dRd05qbGxOalEwTWpKallVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgzNzEyNTc4LCJpYXQiOjE2ODM2MjYxNzgsIm5vbmNlIjoiMFIwT1pzXzZMTXJZYUlGcXRFZDh3USIsImF0X2hhc2giOiJiUklFTFhSZzZaTFV3dE9JTm1sbnFBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.Wkn5jiFhir75HJk_z_YcLfeeFJd1z8X2P8QOTMPNQVX10gIf_tjA6fXIJ-sBeW2dZXomfAIkBh17EJZ5DQA3SEAxBHeIduz__0x08ryscjUHgYutMCyqGPNHU7XlInSDKQjYhYsoUkvwZC7v9b0gXUpgGM58KyF2F2B_l3EoEnr-zsTrjlbK3umu_-1NFCXiuMEnP3wit5VmZU3GlHPPuej1SSN8OTDawq8ileKTmrMUpsWLnlHa9lrv_3bwV9_K8XBogkQC8oL-q9IE5zWdvbonzlbhyDcM_U-9kucKffTvajGO4d0G7U6442b5S9LWge6YsmAy6nUcG-hJxTyEQA",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjVmYzMzZjIxM2M1YzAwM2FiZWM4NzZkZDE3NWFmMmQzMGI5M2M1ZTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MjYzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIV1RGT01sWnNXa1JLYWsxSFNYZE9SRkp0VDFSck1rOUhXbWxOZW14cFRXcEZNRTVFYTNsUFIwMHZOek0xT0dRd05qbGxOalEwTWpKallVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgzNzEyNTc4LCJpYXQiOjE2ODM2MjYxNzgsIm5vbmNlIjoiMFIwT1pzXzZMTXJZYUlGcXRFZDh3USIsImF0X2hhc2giOiJ6MDc4UWowRDF0MWRPbDhaQ1pRQWJnIiwiY19oYXNoIjoiYVJCMEhTM2J4MHAxUjRRdHRtbmxiQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.A_qu0xb8hzhGYeCYBcfNCLp9-5wKyp5SOrCfLspOwo5WNKNyTgfQsnY3KGA1Q5rcjkl09pOMpVIdo38_IdFs7A0HQcBMepKELsk4Ygz6i0Dg_06NuWfbDSbKz91zkdJZvQnLMIjtRS83rrbvDnnOlcClu1xykO0hZzEcA9yme_HrWbr8PDPHloDCn_FWH8Ab_1WXSkRhB9r6Mq09OXGCtoiqcwSWpc2CwHWjaqGDj2S4bSp9nKrdLiMPFAsAVhEp4Wc61ZjMRtjYmN1xAntBmTuKORbCEJd2B1zAszl0oRznI7Eq7hjR-1wul-OaCo4IyItWWVuoh4-plnnk21YgTQ",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjVmYzMzZjIxM2M1YzAwM2FiZWM4NzZkZDE3NWFmMmQzMGI5M2M1ZTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MjYzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIV1RGT01sWnNXa1JLYWsxSFNYZE9SRkp0VDFSck1rOUhXbWxOZW14cFRXcEZNRTVFYTNsUFIwMHZOek0xT0dRd05qbGxOalEwTWpKallVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgzNzEyNTc4LCJpYXQiOjE2ODM2MjYxNzgsIm5vbmNlIjoiMFIwT1pzXzZMTXJZYUlGcXRFZDh3USIsImF0X2hhc2giOiJ6MDc4UWowRDF0MWRPbDhaQ1pRQWJnIiwiY19oYXNoIjoiYVJCMEhTM2J4MHAxUjRRdHRtbmxiQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.A_qu0xb8hzhGYeCYBcfNCLp9-5wKyp5SOrCfLspOwo5WNKNyTgfQsnY3KGA1Q5rcjkl09pOMpVIdo38_IdFs7A0HQcBMepKELsk4Ygz6i0Dg_06NuWfbDSbKz91zkdJZvQnLMIjtRS83rrbvDnnOlcClu1xykO0hZzEcA9yme_HrWbr8PDPHloDCn_FWH8Ab_1WXSkRhB9r6Mq09OXGCtoiqcwSWpc2CwHWjaqGDj2S4bSp9nKrdLiMPFAsAVhEp4Wc61ZjMRtjYmN1xAntBmTuKORbCEJd2B1zAszl0oRznI7Eq7hjR-1wul-OaCo4IyItWWVuoh4-plnnk21YgTQ
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjVmYzMzZjIxM2M1YzAwM2FiZWM4NzZkZDE3NWFmMmQzMGI5M2M1ZTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MjYzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIV1RGT01sWnNXa1JLYWsxSFNYZE9SRkp0VDFSck1rOUhXbWxOZW14cFRXcEZNRTVFYTNsUFIwMHZOek0xT0dRd05qbGxOalEwTWpKallVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgzNzEyNTc4LCJpYXQiOjE2ODM2MjYxNzgsIm5vbmNlIjoiMFIwT1pzXzZMTXJZYUlGcXRFZDh3USIsImF0X2hhc2giOiJ6MDc4UWowRDF0MWRPbDhaQ1pRQWJnIiwiY19oYXNoIjoiYVJCMEhTM2J4MHAxUjRRdHRtbmxiQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.A_qu0xb8hzhGYeCYBcfNCLp9-5wKyp5SOrCfLspOwo5WNKNyTgfQsnY3KGA1Q5rcjkl09pOMpVIdo38_IdFs7A0HQcBMepKELsk4Ygz6i0Dg_06NuWfbDSbKz91zkdJZvQnLMIjtRS83rrbvDnnOlcClu1xykO0hZzEcA9yme_HrWbr8PDPHloDCn_FWH8Ab_1WXSkRhB9r6Mq09OXGCtoiqcwSWpc2CwHWjaqGDj2S4bSp9nKrdLiMPFAsAVhEp4Wc61ZjMRtjYmN1xAntBmTuKORbCEJd2B1zAszl0oRznI7Eq7hjR-1wul-OaCo4IyItWWVuoh4-plnnk21YgTQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjVmYzMzZjIxM2M1YzAwM2FiZWM4NzZkZDE3
NWFmMmQzMGI5M2M1ZTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MjYzL2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIV1RGT01sWnNXa1JLYWsxSFNYZE9SR
kp0VDFSck1rOUhXbWxOZW14cFRXcEZNRTVFYTNsUFIwMHZOek0xT0dRd05qbGxOa
lEwTWpKallVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjgzNzEyNTc4LCJpYXQiOjE2ODM2MjYxNzgsIm5vbmNlIjoiMFIwT1pzX
zZMTXJZYUlGcXRFZDh3USIsImF0X2hhc2giOiJ6MDc4UWowRDF0MWRPbDhaQ1pRQ
WJnIiwiY19oYXNoIjoiYVJCMEhTM2J4MHAxUjRRdHRtbmxiQSIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZ
SBTbWl0aCJ9.A_qu0xb8hzhGYeCYBcfNCLp9-5wKyp5SOrCfLspOwo5WNKNyTgfQ
snY3KGA1Q5rcjkl09pOMpVIdo38_IdFs7A0HQcBMepKELsk4Ygz6i0Dg_06NuWfb
DSbKz91zkdJZvQnLMIjtRS83rrbvDnnOlcClu1xykO0hZzEcA9yme_HrWbr8PDPH
loDCn_FWH8Ab_1WXSkRhB9r6Mq09OXGCtoiqcwSWpc2CwHWjaqGDj2S4bSp9nKrd
LiMPFAsAVhEp4Wc61ZjMRtjYmN1xAntBmTuKORbCEJd2B1zAszl0oRznI7Eq7hjR
-1wul-OaCo4IyItWWVuoh4-plnnk21YgTQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "5fc33f213c5c003abec876dd175af2d30b93c5e2"
}
```

```json
{
  "at_hash": "z078Qj0D1t1dOl8ZCZQAbg",
  "aud": "wireapp",
  "c_hash": "aRB0HS3bx0p1R4QttmnlbA",
  "exp": 1683712578,
  "iat": 1683626178,
  "iss": "http://dex:18263/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "0R0OZs_6LMrYaIFqtEd8wQ",
  "preferred_username": "Alice Smith",
  "sub": "ClBpbTp3aXJlYXBwPU9HWTFOMlZsWkRKak1HSXdORFJtT1RrMk9HWmlNemxpTWpFME5Ea3lPR00vNzM1OGQwNjllNjQ0MjJjYUB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoGEAhIIMwHxQyMdGuoeG
/gdlZNclWNGfvKszfmu5fZ6G66i5tm2YjPKZPuvxZOJ5nJjlpDErwF6WI3LZuRX1
wp7UjoTV0XRA50LQs0CT4rsvDXUwa6RLmsQ6FMZQEqtosq5wPel9Ds8Cs0LBC+VK
eG05WYOvg6a1S/z+Sj3J1cuLsHtkqiy9EhgliumRasBvqAPfk5JsmEurFa5rOvGj
4Xsa94rI/jX4dpFU0RdMurvaFviNYD8VIVfo3ndfYx3DHqKPpkp8KkxnPCS9kdKy
9CyN0YCh5XRYtZv9tJQvK9aQgODHU8kHOCVk4UkMLF6+PI8d1vttm1Pt0aajzniT
ZwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/oPyI2NPNHw9do0Mql8ZNfvjSo0rQn9H1
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjk0L2FjbWUvd2lyZS9hY2NvdW50LzRnUXAyUHF5R2ZXNVByQ1owZDYwRWtHT1BpTTVVMjMxIiwidHlwIjoiSldUIiwibm9uY2UiOiJNakJvY1U1U1VYcDNhemhsYW14VlRHZFpaemg2YkZBMk5sQnZSMlJoTWpJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyOTQvYWNtZS93aXJlL2NoYWxsZW5nZS9vWXpvTWhqdFdmQmZDcnliVU9QU2F6bVlOWmhyNmhEZi9vUHlJMk5QTkh3OWRvME1xbDhaTmZ2alNvMHJRbjlIMSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJalZtWXpNelpqSXhNMk0xWXpBd00yRmlaV000Tnpaa1pERTNOV0ZtTW1Rek1HSTVNMk0xWlRJaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTRNall6TDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZUbElWMVJHVDAxc1duTlhhMUpMWVdzeFNGTllaRTlTUmtwMFZERlNjazFyT1VoWGJXeE9aVzE0Y0ZSWGNFWk5SVFZGWVROc1VGSXdNSFpPZWsweFQwZFJkMDVxYkd4T2FsRXdUV3BLYWxsVlFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qZ3pOekV5TlRjNExDSnBZWFFpT2pFMk9ETTJNall4Tnpnc0ltNXZibU5sSWpvaU1GSXdUMXB6WHpaTVRYSlpZVWxHY1hSRlpEaDNVU0lzSW1GMFgyaGhjMmdpT2lKNk1EYzRVV293UkRGME1XUlBiRGhhUTFwUlFXSm5JaXdpWTE5b1lYTm9Jam9pWVZKQ01FaFRNMko0TUhBeFVqUlJkSFJ0Ym14aVFTSXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObFgzZHBjbVVpTENKd2NtVm1aWEp5WldSZmRYTmxjbTVoYldVaU9pSkJiR2xqWlNCVGJXbDBhQ0o5LkFfcXUweGI4aHpoR1llQ1lCY2ZOQ0xwOS01d0t5cDVTT3JDZkxzcE93bzVXTktOeVRnZlFzblkzS0dBMVE1cmNqa2wwOXBPTXBWSWRvMzhfSWRGczdBMEhRY0JNZXBLRUxzazRZZ3o2aTBEZ18wNk51V2ZiRFNiS3o5MXprZEpadlFuTE1JanRSUzgzcnJidkRubk9sY0NsdTF4eWtPMGhaekVjQTl5bWVfSHJXYnI4UERQSGxvRENuX0ZXSDhBYl8xV1hTa1JoQjlyNk1xMDlPWEdDdG9pcWN3U1dwYzJDd0hXamFxR0RqMlM0YlNwOW5LcmRMaU1QRkFzQVZoRXA0V2M2MVpqTVJ0alltTjF4QW50Qm1UdUtPUmJDRUpkMkIxekFzemwwb1J6bkk3RXE3aGpSLTF3dWwtT2FDbzRJeUl0V1dWdW9oNC1wbG5uazIxWWdUUSIsImtleWF1dGgiOiJsektacWpCNlhjM0tiTEprRW5mS2JQWXBoblpoak52MC4wZHdQVnluRGg0WUpRTUZuYVBpZy1id1ZsOGNxN3h5emlBeXR3d2FsQXg4In0",
  "signature": "qPt1_7jKM9WqHmeo552kyc8aeDUIfyhmWrjtpfnehArLLNkFv4TJ4SrEBRjfLvhlHRjZKcJaKVrKf6Edz7l6BA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjVmYzMzZjIxM2M1YzAwM2FiZWM4NzZkZDE3NWFmMmQzMGI5M2M1ZTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MjYzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIV1RGT01sWnNXa1JLYWsxSFNYZE9SRkp0VDFSck1rOUhXbWxOZW14cFRXcEZNRTVFYTNsUFIwMHZOek0xT0dRd05qbGxOalEwTWpKallVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgzNzEyNTc4LCJpYXQiOjE2ODM2MjYxNzgsIm5vbmNlIjoiMFIwT1pzXzZMTXJZYUlGcXRFZDh3USIsImF0X2hhc2giOiJ6MDc4UWowRDF0MWRPbDhaQ1pRQWJnIiwiY19oYXNoIjoiYVJCMEhTM2J4MHAxUjRRdHRtbmxiQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.A_qu0xb8hzhGYeCYBcfNCLp9-5wKyp5SOrCfLspOwo5WNKNyTgfQsnY3KGA1Q5rcjkl09pOMpVIdo38_IdFs7A0HQcBMepKELsk4Ygz6i0Dg_06NuWfbDSbKz91zkdJZvQnLMIjtRS83rrbvDnnOlcClu1xykO0hZzEcA9yme_HrWbr8PDPHloDCn_FWH8Ab_1WXSkRhB9r6Mq09OXGCtoiqcwSWpc2CwHWjaqGDj2S4bSp9nKrdLiMPFAsAVhEp4Wc61ZjMRtjYmN1xAntBmTuKORbCEJd2B1zAszl0oRznI7Eq7hjR-1wul-OaCo4IyItWWVuoh4-plnnk21YgTQ",
    "keyauth": "lzKZqjB6Xc3KbLJkEnfKbPYphnZhjNv0.0dwPVynDh4YJQMFnaPig-bwVl8cq7xyziAytwwalAx8"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33294/acme/wire/account/4gQp2PqyGfW5PrCZ0d60EkGOPiM5U231",
    "nonce": "MjBocU5SUXp3azhlamxVTGdZZzh6bFA2NlBvR2RhMjI",
    "typ": "JWT",
    "url": "https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/oPyI2NPNHw9do0Mql8ZNfvjSo0rQn9H1"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33294/acme/wire/directory>;rel="index"
link: <https://stepca:33294/acme/wire/authz/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf>;rel="up"
location: https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/oPyI2NPNHw9do0Mql8ZNfvjSo0rQn9H1
replay-nonce: TGdHTXZNWkhGQ1JUbXB2RkNHUExoS1FabFdsazRITWc
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:33294/acme/wire/challenge/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf/oPyI2NPNHw9do0Mql8ZNfvjSo0rQn9H1",
  "status": "valid",
  "token": "lzKZqjB6Xc3KbLJkEnfKbPYphnZhjNv0",
  "target": "http://dex:18263/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjk0L2FjbWUvd2lyZS9hY2NvdW50LzRnUXAyUHF5R2ZXNVByQ1owZDYwRWtHT1BpTTVVMjMxIiwidHlwIjoiSldUIiwibm9uY2UiOiJUR2RIVFhaTldraEdRMUpVYlhCMlJrTkhVRXhvUzFGYWJGZHNhelJJVFdjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyOTQvYWNtZS93aXJlL29yZGVyL2RJSU45Y2hkUTBNeEdtUHN0czd6cjVoc0NKeUlubDlYIn0",
  "payload": "",
  "signature": "RjXYGwHO9Pmqh3uwVz6SeiU4QnWYQKz6aIVokgh1dCFdSnsGi9uNFEN89dQWmVRXZWH8J-WSWUtPFy7efGy4AA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33294/acme/wire/account/4gQp2PqyGfW5PrCZ0d60EkGOPiM5U231",
    "nonce": "TGdHTXZNWkhGQ1JUbXB2RkNHUExoS1FabFdsazRITWc",
    "typ": "JWT",
    "url": "https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33294/acme/wire/directory>;rel="index"
location: https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X
replay-nonce: UFd4ZkpBQ0ZBcTJpVTJSYzRnSWFqQzZpamdobFhmWnE
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33294/acme/wire/authz/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf"
  ],
  "expires": "2023-05-10T09:56:18Z",
  "notBefore": "2023-05-09T09:56:18.576978Z",
  "notAfter": "2023-05-09T10:56:18.576978Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjk0L2FjbWUvd2lyZS9hY2NvdW50LzRnUXAyUHF5R2ZXNVByQ1owZDYwRWtHT1BpTTVVMjMxIiwidHlwIjoiSldUIiwibm9uY2UiOiJVRmQ0WmtwQlEwWkJjVEpwVlRKU1l6Um5TV0ZxUXpacGFtZG9iRmhtV25FIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyOTQvYWNtZS93aXJlL29yZGVyL2RJSU45Y2hkUTBNeEdtUHN0czd6cjVoc0NKeUlubDlYL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCT0RDQjZ3SUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBS3hZR2l5ME5UVmVNVkZBV1NyUGVHdVFrdVVmbE9nWmZxeHFFeEtCbks1UG9JR0dNSUdEQmdrcWhraUc5dzBCQ1E0eGRqQjBNSElHQTFVZEVRUnJNR21HVUdsdE9uZHBjbVZoY0hBOVQwZFpNVTR5Vm14YVJFcHFUVWRKZDA1RVVtMVBWR3N5VDBkYWFVMTZiR2xOYWtVd1RrUnJlVTlIVFM4M016VTRaREEyT1dVMk5EUXlNbU5oUUhkcGNtVXVZMjl0aGhWcGJUcDNhWEpsWVhCd1BXRnNhV05sWDNkcGNtVXdCUVlESzJWd0EwRUFpU2VkT0N6UU9fM0lKTnRVdzdvLVJOamVfZHl0Q2IwVXY5Ukw4V0xGQ1hqYWdnLUdsdHFxdl9VSFFNSE9CakZzLURVM0ctNUJZNk53TDJSQ3dLRV9DQSJ9",
  "signature": "yLSJfpBDjx-I70dCfabOc-HN6XHC8bjTmgUbfCvODZrXW2WZX4AaIF353bApYzXT6L4Nyj70HGAtfypda_12Cw"
}
```
```json
{
  "payload": {
    "csr": "MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAKxYGiy0NTVeMVFAWSrPeGuQkuUflOgZfqxqExKBnK5PoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndpcmVhcHA9T0dZMU4yVmxaREpqTUdJd05EUm1PVGsyT0daaU16bGlNakUwTkRreU9HTS83MzU4ZDA2OWU2NDQyMmNhQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dpcmUwBQYDK2VwA0EAiSedOCzQO_3IJNtUw7o-RNje_dytCb0Uv9RL8WLFCXjagg-Gltqqv_UHQMHOBjFs-DU3G-5BY6NwL2RCwKE_CA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33294/acme/wire/account/4gQp2PqyGfW5PrCZ0d60EkGOPiM5U231",
    "nonce": "UFd4ZkpBQ0ZBcTJpVTJSYzRnSWFqQzZpamdobFhmWnE",
    "typ": "JWT",
    "url": "https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAKxYGiy0NTVeMVFAWSrPeGuQkuUflOgZ
fqxqExKBnK5PoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndp
cmVhcHA9T0dZMU4yVmxaREpqTUdJd05EUm1PVGsyT0daaU16bGlNakUwTkRreU9H
TS83MzU4ZDA2OWU2NDQyMmNhQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dp
cmUwBQYDK2VwA0EAiSedOCzQO/3IJNtUw7o+RNje/dytCb0Uv9RL8WLFCXjagg+G
ltqqv/UHQMHOBjFs+DU3G+5BY6NwL2RCwKE/CA==
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
                    ac:58:1a:2c:b4:35:35:5e:31:51:40:59:2a:cf:78:
                    6b:90:92:e5:1f:94:e8:19:7e:ac:6a:13:12:81:9c:
                    ae:4f
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        89:27:9d:38:2c:d0:3b:fd:c8:24:db:54:c3:ba:3e:44:d8:de:
        fd:dc:ad:09:bd:14:bf:d4:4b:f1:62:c5:09:78:da:82:0f:86:
        96:da:aa:bf:f5:07:40:c1:ce:06:31:6c:f8:35:37:1b:ee:41:
        63:a3:70:2f:64:42:c0:a1:3f:08

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33294/acme/wire/directory>;rel="index"
location: https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X
replay-nonce: alIzaDJRdHp2SVdLSnZ6MlF5N2oyZXBVcmNDYUVYVmY
```
```json
{
  "certificate": "https://stepca:33294/acme/wire/certificate/c0exFVPsOlFAzAnROtOZlL8am0ZGx91A",
  "status": "valid",
  "finalize": "https://stepca:33294/acme/wire/order/dIIN9chdQ0MxGmPsts7zr5hsCJyInl9X/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33294/acme/wire/authz/oYzoMhjtWfBfCrybUOPSazmYNZhr6hDf"
  ],
  "expires": "2023-05-10T09:56:18Z",
  "notBefore": "2023-05-09T09:56:18.576978Z",
  "notAfter": "2023-05-09T10:56:18.576978Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:33294/acme/wire/certificate/c0exFVPsOlFAzAnROtOZlL8am0ZGx91A
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjk0L2FjbWUvd2lyZS9hY2NvdW50LzRnUXAyUHF5R2ZXNVByQ1owZDYwRWtHT1BpTTVVMjMxIiwidHlwIjoiSldUIiwibm9uY2UiOiJhbEl6YURKUmRIcDJTVmRMU25aNk1sRjVOMm95WlhCVmNtTkRZVVZZVm1ZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyOTQvYWNtZS93aXJlL2NlcnRpZmljYXRlL2MwZXhGVlBzT2xGQXpBblJPdE9abEw4YW0wWkd4OTFBIn0",
  "payload": "",
  "signature": "7eQU8qzUAiKvVnM--4o-idlE25sReY_0JQ6csiJnFpiD8SFQw_99iMMGgktTGXhAkg7M-Q_FWokYVbMyhpFYBw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33294/acme/wire/account/4gQp2PqyGfW5PrCZ0d60EkGOPiM5U231",
    "nonce": "alIzaDJRdHp2SVdLSnZ6MlF5N2oyZXBVcmNDYUVYVmY",
    "typ": "JWT",
    "url": "https://stepca:33294/acme/wire/certificate/c0exFVPsOlFAzAnROtOZlL8am0ZGx91A"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:33294/acme/wire/directory>;rel="index"
replay-nonce: ZjdHODBnMUZLZUFURXRhc25WemVnV25IcHcweUVqZkE
```
```json
"-----BEGIN CERTIFICATE-----\nMIICLzCCAdWgAwIBAgIRAP2kTtURZA1hkFXX2JFd3X4wCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwNTA5MDk1NjE4WhcNMjMwNTA5MTA1NjE4WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCsWBostDU1XjFRQFkq\nz3hrkJLlH5ToGX6sahMSgZyuT6OCAQYwggECMA4GA1UdDwEB/wQEAwIHgDAdBgNV\nHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFDWUWMPyZJOEQ5rQ\nqEGLY8vl1ikfMB8GA1UdIwQYMBaAFCAFAdHMVtzvkqBekK8NATSWtBMKMHIGA1Ud\nEQRrMGmGUGltOndpcmVhcHA9T0dZMU4yVmxaREpqTUdJd05EUm1PVGsyT0daaU16\nbGlNakUwTkRreU9HTS83MzU4ZDA2OWU2NDQyMmNhQHdpcmUuY29thhVpbTp3aXJl\nYXBwPWFsaWNlX3dpcmUwHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoG\nCCqGSM49BAMCA0gAMEUCIQDFPMfqMOvD0OqfIxfVP+Z+KoCzAaj1gCSeXrzPGg56\nnAIgfvzWTOAoFpy2bBmHX/4YFmxe3RdVNpyv4byO+s05lAs=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAJu+r4Zta//Ce1zh5yCgT30wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDUwOTA5\nNTYxNloXDTMzMDUwNjA5NTYxNlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQV\nHNdHiGrq2GeqLW2Klo0X29M688ooQJGhNRGJJs7MzSwDU+7J0sVcuQ+oBinMrstS\ngDbWRfCSX4cBj4XIibNRo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUIAUB0cxW3O+SoF6Qrw0BNJa0EwowHwYDVR0jBBgw\nFoAUm/EG5fN8pwNxHaaHo/mtG5g+TXMwCgYIKoZIzj0EAwIDSAAwRQIhAOS/UjnA\nyzBsZ3Op8/HpMaJZlTygMpAnRn8UUdpubiuzAiBcQrcgR01N17Gl6DJ34OCP9xVz\nYfIvP9oBvmU7raA84w==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICLzCCAdWgAwIBAgIRAP2kTtURZA1hkFXX2JFd3X4wCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwNTA5MDk1NjE4WhcNMjMwNTA5MTA1NjE4WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCsWBostDU1XjFRQFkq
z3hrkJLlH5ToGX6sahMSgZyuT6OCAQYwggECMA4GA1UdDwEB/wQEAwIHgDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFDWUWMPyZJOEQ5rQ
qEGLY8vl1ikfMB8GA1UdIwQYMBaAFCAFAdHMVtzvkqBekK8NATSWtBMKMHIGA1Ud
EQRrMGmGUGltOndpcmVhcHA9T0dZMU4yVmxaREpqTUdJd05EUm1PVGsyT0daaU16
bGlNakUwTkRreU9HTS83MzU4ZDA2OWU2NDQyMmNhQHdpcmUuY29thhVpbTp3aXJl
YXBwPWFsaWNlX3dpcmUwHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoG
CCqGSM49BAMCA0gAMEUCIQDFPMfqMOvD0OqfIxfVP+Z+KoCzAaj1gCSeXrzPGg56
nAIgfvzWTOAoFpy2bBmHX/4YFmxe3RdVNpyv4byO+s05lAs=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            fd:a4:4e:d5:11:64:0d:61:90:55:d7:d8:91:5d:dd:7e
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: May  9 09:56:18 2023 GMT
            Not After : May  9 10:56:18 2023 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    ac:58:1a:2c:b4:35:35:5e:31:51:40:59:2a:cf:78:
                    6b:90:92:e5:1f:94:e8:19:7e:ac:6a:13:12:81:9c:
                    ae:4f
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                35:94:58:C3:F2:64:93:84:43:9A:D0:A8:41:8B:63:CB:E5:D6:29:1F
            X509v3 Authority Key Identifier: 
                20:05:01:D1:CC:56:DC:EF:92:A0:5E:90:AF:0D:01:34:96:B4:13:0A
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=OGY1N2VlZDJjMGIwNDRmOTk2OGZiMzliMjE0NDkyOGM/7358d069e64422ca@wire.com, URI:im:wireapp=alice_wire
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:c5:3c:c7:ea:30:eb:c3:d0:ea:9f:23:17:d5:
        3f:e6:7e:2a:80:b3:01:a8:f5:80:24:9e:5e:bc:cf:1a:0e:7a:
        9c:02:20:7e:fc:d6:4c:e0:28:16:9c:b6:6c:19:87:5f:fe:18:
        16:6c:5e:dd:17:55:36:9c:af:e1:bc:8e:fa:cd:39:94:0b

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAJu+r4Zta//Ce1zh5yCgT30wCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDUwOTA5
NTYxNloXDTMzMDUwNjA5NTYxNlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQV
HNdHiGrq2GeqLW2Klo0X29M688ooQJGhNRGJJs7MzSwDU+7J0sVcuQ+oBinMrstS
gDbWRfCSX4cBj4XIibNRo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUIAUB0cxW3O+SoF6Qrw0BNJa0EwowHwYDVR0jBBgw
FoAUm/EG5fN8pwNxHaaHo/mtG5g+TXMwCgYIKoZIzj0EAwIDSAAwRQIhAOS/UjnA
yzBsZ3Op8/HpMaJZlTygMpAnRn8UUdpubiuzAiBcQrcgR01N17Gl6DJ34OCP9xVz
YfIvP9oBvmU7raA84w==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9b:be:af:86:6d:6b:ff:c2:7b:5c:e1:e7:20:a0:4f:7d
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: May  9 09:56:16 2023 GMT
            Not After : May  6 09:56:16 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:15:1c:d7:47:88:6a:ea:d8:67:aa:2d:6d:8a:96:
                    8d:17:db:d3:3a:f3:ca:28:40:91:a1:35:11:89:26:
                    ce:cc:cd:2c:03:53:ee:c9:d2:c5:5c:b9:0f:a8:06:
                    29:cc:ae:cb:52:80:36:d6:45:f0:92:5f:87:01:8f:
                    85:c8:89:b3:51
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                20:05:01:D1:CC:56:DC:EF:92:A0:5E:90:AF:0D:01:34:96:B4:13:0A
            X509v3 Authority Key Identifier: 
                9B:F1:06:E5:F3:7C:A7:03:71:1D:A6:87:A3:F9:AD:1B:98:3E:4D:73
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:e4:bf:52:39:c0:cb:30:6c:67:73:a9:f3:f1:
        e9:31:a2:59:95:3c:a0:32:90:27:46:7f:14:51:da:6e:6e:2b:
        b3:02:20:5c:42:b7:20:47:4d:4d:d7:b1:a5:e8:32:77:e0:e0:
        8f:f7:15:73:61:f2:2f:3f:da:01:be:65:3b:ad:a0:3c:e3

```
