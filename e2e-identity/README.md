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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/a661e79735dc890f/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/x0gGlwzcz1VJWjgD9dM5RIuoSsLU4yva
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/Zaa3kx1T7ThIuYBI4KiS4dmBWetKeXNW
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/MPd3TpyTezfB7zED0ZBo2HPwCrCDDhHT
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:33067/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:33067/acme/wire/new-nonce",
  "newAccount": "https://stepca:33067/acme/wire/new-account",
  "newOrder": "https://stepca:33067/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:33067/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:33067/acme/wire/directory>;rel="index"
replay-nonce: MGxJVzQxbm5ydTBCc2tNOFR3VGFiaXhqN29LYU1leDI
```
```text
MGxJVzQxbm5ydTBCc2tNOFR3VGFiaXhqN29LYU1leDI
```
#### 5. create a new account
```http request
POST https://stepca:33067/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlJrd3QyNnNiejQ0VEZ3RTBMWmhuVGtVOGNnX0tjaVVwRDlYV3kwRXFvMDQifSwibm9uY2UiOiJNR3hKVnpReGJtNXlkVEJDYzJ0Tk9GUjNWR0ZpYVhocU4yOUxZVTFsZURJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwNjcvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "H99Fnu2AUPP0SWcCjoisGZqK-R9Y1J3l6tzC9y1I9ULkRtgGcZBBasUedHpx-Q3Vz9fi5WEaLh3I-KvR8K1oDg"
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
      "x": "Rkwt26sbz44TFwE0LZhnTkU8cg_KciUpD9XWy0Eqo04"
    },
    "nonce": "MGxJVzQxbm5ydTBCc2tNOFR3VGFiaXhqN29LYU1leDI",
    "typ": "JWT",
    "url": "https://stepca:33067/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33067/acme/wire/directory>;rel="index"
location: https://stepca:33067/acme/wire/account/3f8P2A33xAMTUVnNLJTZeHTCjw08Wxu6
replay-nonce: OWJSeWNDSUJ1UDc3WEJMcGdtdmx2S1FkRzNJUVlMamI
```
```json
{
  "status": "valid",
  "orders": "https://stepca:33067/acme/wire/account/3f8P2A33xAMTUVnNLJTZeHTCjw08Wxu6/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:33067/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDY3L2FjbWUvd2lyZS9hY2NvdW50LzNmOFAyQTMzeEFNVFVWbk5MSlRaZUhUQ2p3MDhXeHU2IiwidHlwIjoiSldUIiwibm9uY2UiOiJPV0pTZVdORFNVSjFVRGMzV0VKTWNHZHRkbXgyUzFGa1J6TkpVVmxNYW1JIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwNjcvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9TUdFeE5UQTJNRE5pTW1RNU5EZGhObUptTkdGak5HSmxOVEEyTURZeE5tTS9hNjYxZTc5NzM1ZGM4OTBmQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9YWxpY2Vfd2lyZVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wNi0wNlQxMjowODoxOC4zNjI3MzJaIiwibm90QWZ0ZXIiOiIyMDMzLTA2LTAzVDEyOjA4OjE4LjM2MjczMloifQ",
  "signature": "b1wV3g5sPIF4Re-AyJjcxPGdZ80YEfDyWzm2RImHn-uRo07CliZHy04X4gbMOBckPHBMJMFJz886B30aqYqFCw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2033-06-03T12:08:18.362732Z",
    "notBefore": "2023-06-06T12:08:18.362732Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33067/acme/wire/account/3f8P2A33xAMTUVnNLJTZeHTCjw08Wxu6",
    "nonce": "OWJSeWNDSUJ1UDc3WEJMcGdtdmx2S1FkRzNJUVlMamI",
    "typ": "JWT",
    "url": "https://stepca:33067/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33067/acme/wire/directory>;rel="index"
location: https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I
replay-nonce: U0VPbFE5N0R0Ujg0dWYwbjJoZVBQNEwwQXdqSUluWXU
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33067/acme/wire/authz/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk"
  ],
  "expires": "2023-06-07T12:08:18Z",
  "notBefore": "2023-06-06T12:08:18.362732Z",
  "notAfter": "2033-06-03T12:08:18.362732Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:33067/acme/wire/authz/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDY3L2FjbWUvd2lyZS9hY2NvdW50LzNmOFAyQTMzeEFNVFVWbk5MSlRaZUhUQ2p3MDhXeHU2IiwidHlwIjoiSldUIiwibm9uY2UiOiJVMFZQYkZFNU4wUjBVamcwZFdZd2JqSm9aVkJRTkV3d1FYZHFTVWx1V1hVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwNjcvYWNtZS93aXJlL2F1dGh6L1ZaOU92RGQ4dUNTWE1YalhWTWZRZzYzVExVbnhHWktrIn0",
  "payload": "",
  "signature": "5F7__UJvH6_kZBWRrS1GvxH8wS4tf6ROTuPOF_t2UwMm5QUn0l0eqDpqLPQX7Af4F3VTUgGPqw-MX6azukwbBw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33067/acme/wire/account/3f8P2A33xAMTUVnNLJTZeHTCjw08Wxu6",
    "nonce": "U0VPbFE5N0R0Ujg0dWYwbjJoZVBQNEwwQXdqSUluWXU",
    "typ": "JWT",
    "url": "https://stepca:33067/acme/wire/authz/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33067/acme/wire/directory>;rel="index"
location: https://stepca:33067/acme/wire/authz/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk
replay-nonce: NkRXZ1NONjQ1QTBMM3lpeUJ4QklmYWNZUzBtRzkwUGg
```
```json
{
  "status": "pending",
  "expires": "2023-06-07T12:08:18Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/Zaa3kx1T7ThIuYBI4KiS4dmBWetKeXNW",
      "status": "pending",
      "token": "84ShBugQ6MiMBPEjjLAxAUklhAzKubGS",
      "target": "http://dex:16070/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/x0gGlwzcz1VJWjgD9dM5RIuoSsLU4yva",
      "status": "pending",
      "token": "84ShBugQ6MiMBPEjjLAxAUklhAzKubGS",
      "target": "http://wire.com:15602/clients/a661e79735dc890f/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:15602/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
TENEdGk0cklldzVGYU1wcHRUS29uSXk2TVJ6NEFWcjE
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUmt3dDI2c2J6NDRURndFMExaaG5Ua1U4Y2dfS2NpVXBEOVhXeTBFcW8wNCJ9fQ.eyJpYXQiOjE2ODYwNTMyOTgsImV4cCI6MTY4NjA1Njg5OCwibmJmIjoxNjg2MDUzMjkzLCJzdWIiOiJpbTp3aXJlYXBwPU1HRXhOVEEyTUROaU1tUTVORGRoTm1KbU5HRmpOR0psTlRBMk1EWXhObU0vYTY2MWU3OTczNWRjODkwZkB3aXJlLmNvbSIsImp0aSI6IjFjMGQ4Y2UzLTBjNGYtNDZlYi04MmQ5LTNiYjIzMTRmNDdlYyIsIm5vbmNlIjoiVEVORWRHazBja2xsZHpWR1lVMXdjSFJVUzI5dVNYazJUVko2TkVGV2NqRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTU2MDIvY2xpZW50cy9hNjYxZTc5NzM1ZGM4OTBmL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI4NFNoQnVnUTZNaU1CUEVqakxBeEFVa2xoQXpLdWJHUyJ9.InDqAykzehhyrHTz74wWFx7L0muyJpINwNoNlGgvyC2CsYjBBSZttg1FoMzQp9qVKON84AH1971F3ot64SNCAA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUmt3dDI2c2J6NDRURndFMExaaG5Ua1U4
Y2dfS2NpVXBEOVhXeTBFcW8wNCJ9fQ.eyJpYXQiOjE2ODYwNTMyOTgsImV4cCI6M
TY4NjA1Njg5OCwibmJmIjoxNjg2MDUzMjkzLCJzdWIiOiJpbTp3aXJlYXBwPU1HR
XhOVEEyTUROaU1tUTVORGRoTm1KbU5HRmpOR0psTlRBMk1EWXhObU0vYTY2MWU3O
TczNWRjODkwZkB3aXJlLmNvbSIsImp0aSI6IjFjMGQ4Y2UzLTBjNGYtNDZlYi04M
mQ5LTNiYjIzMTRmNDdlYyIsIm5vbmNlIjoiVEVORWRHazBja2xsZHpWR1lVMXdjS
FJVUzI5dVNYazJUVko2TkVGV2NqRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MTU2MDIvY2xpZW50cy9hNjYxZTc5NzM1ZGM4OTBmL2FjY2Vzc
y10b2tlbiIsImNoYWwiOiI4NFNoQnVnUTZNaU1CUEVqakxBeEFVa2xoQXpLdWJHU
yJ9.InDqAykzehhyrHTz74wWFx7L0muyJpINwNoNlGgvyC2CsYjBBSZttg1FoMzQ
p9qVKON84AH1971F3ot64SNCAA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "Rkwt26sbz44TFwE0LZhnTkU8cg_KciUpD9XWy0Eqo04"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "84ShBugQ6MiMBPEjjLAxAUklhAzKubGS",
  "exp": 1686056898,
  "htm": "POST",
  "htu": "http://wire.com:15602/clients/a661e79735dc890f/access-token",
  "iat": 1686053298,
  "jti": "1c0d8ce3-0c4f-46eb-82d9-3bb2314f47ec",
  "nbf": 1686053293,
  "nonce": "TENEdGk0cklldzVGYU1wcHRUS29uSXk2TVJ6NEFWcjE",
  "sub": "im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICaZZfYEGXeuQdASOLfbbqTyz3P0gntXa8NzOl34qNIA
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARkwt26sbz44TFwE0LZhnTkU8cg/KciUpD9XWy0Eqo04=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:15602/clients/a661e79735dc890f/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVW10M2RESTJjMko2TkRSVVJuZEZNRXhhYUc1VWExVTRZMmRmUzJOcFZYQkVPVmhYZVRCRmNXOHdOQ0o5ZlEuZXlKcFlYUWlPakUyT0RZd05UTXlPVGdzSW1WNGNDSTZNVFk0TmpBMU5qZzVPQ3dpYm1KbUlqb3hOamcyTURVek1qa3pMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTFIUlhoT1ZFRXlUVVJPYVUxdFVUVk9SR1JvVG0xS2JVNUhSbXBPUjBwc1RsUkJNazFFV1hoT2JVMHZZVFkyTVdVM09UY3pOV1JqT0Rrd1prQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqRmpNR1E0WTJVekxUQmpOR1l0TkRabFlpMDRNbVE1TFROaVlqSXpNVFJtTkRkbFl5SXNJbTV2Ym1ObElqb2lWRVZPUldSSGF6QmphMnhzWkhwV1IxbFZNWGRqU0ZKVlV6STVkVk5ZYXpKVVZrbzJUa1ZHVjJOcVJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFUyTURJdlkyeHBaVzUwY3k5aE5qWXhaVGM1TnpNMVpHTTRPVEJtTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTRORk5vUW5WblVUWk5hVTFDVUVWcWFreEJlRUZWYTJ4b1FYcExkV0pIVXlKOS5JbkRxQXlremVoaHlySFR6NzR3V0Z4N0wwbXV5SnBJTndOb05sR2d2eUMyQ3NZakJCU1p0dGcxRm9NelFwOXFWS09OODRBSDE5NzFGM290NjRTTkNBQQ
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im52bnFvTEZPc0xGcEYzbEJDRVhpb0d1NGhuYUYxbENVU3F1T085RkU5MDAifX0.eyJpYXQiOjE2ODYwNTMyOTgsImV4cCI6MTY5MzgyOTI5OCwibmJmIjoxNjg2MDUzMjkzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTU2MDIvY2xpZW50cy9hNjYxZTc5NzM1ZGM4OTBmL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9TUdFeE5UQTJNRE5pTW1RNU5EZGhObUptTkdGak5HSmxOVEEyTURZeE5tTS9hNjYxZTc5NzM1ZGM4OTBmQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE1NjAyL2NsaWVudHMvYTY2MWU3OTczNWRjODkwZi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI2OThjMDg2MC1jM2E0LTQ2NGEtYmVkMy02NjdmOTViNzYyOTYiLCJub25jZSI6IlRFTkVkR2swY2tsbGR6VkdZVTF3Y0hSVVMyOXVTWGsyVFZKNk5FRldjakUiLCJjaGFsIjoiODRTaEJ1Z1E2TWlNQlBFampMQXhBVWtsaEF6S3ViR1MiLCJjbmYiOnsia2lkIjoiYkZBN08wbnctS3ZzYWxUdVJqTGg5aEUtd2dtQTJKR2E0SnhQbDBxVnpjZyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVVtdDNkREkyYzJKNk5EUlVSbmRGTUV4YWFHNVVhMVU0WTJkZlMyTnBWWEJFT1ZoWGVUQkZjVzh3TkNKOWZRLmV5SnBZWFFpT2pFMk9EWXdOVE15T1Rnc0ltVjRjQ0k2TVRZNE5qQTFOamc1T0N3aWJtSm1Jam94TmpnMk1EVXpNamt6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFUxSFJYaE9WRUV5VFVST2FVMXRVVFZPUkdSb1RtMUtiVTVIUm1wT1IwcHNUbFJCTWsxRVdYaE9iVTB2WVRZMk1XVTNPVGN6TldSak9Ea3daa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJakZqTUdRNFkyVXpMVEJqTkdZdE5EWmxZaTA0TW1RNUxUTmlZakl6TVRSbU5EZGxZeUlzSW01dmJtTmxJam9pVkVWT1JXUkhhekJqYTJ4c1pIcFdSMWxWTVhkalNGSlZVekk1ZFZOWWF6SlVWa28yVGtWR1YyTnFSU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk1ESXZZMnhwWlc1MGN5OWhOall4WlRjNU56TTFaR000T1RCbUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUk0TkZOb1FuVm5VVFpOYVUxQ1VFVnFha3hCZUVGVmEyeG9RWHBMZFdKSFV5SjkuSW5EcUF5a3plaGh5ckhUejc0d1dGeDdMMG11eUpwSU53Tm9ObEdndnlDMkNzWWpCQlNadHRnMUZvTXpRcDlxVktPTjg0QUgxOTcxRjNvdDY0U05DQUEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU1HRXhOVEEyTUROaU1tUTVORGRoTm1KbU5HRmpOR0psTlRBMk1EWXhObU0vYTY2MWU3OTczNWRjODkwZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.pJ1gg3wocgnGSIC1hIxnmAEYWz5t20m7ibcYewEU9zVXwbrVIssd7fYLgEkbpEJcts-VXFBJCgflltOsa_t_Bw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im52bnFvTEZPc0xGcEYzbEJDRVhpb0d1NGhuYUYxbENVU3F1T085RkU5MDAifX0.eyJpYXQiOjE2ODYwNTMyOTgsImV4cCI6MTY5MzgyOTI5OCwibmJmIjoxNjg2MDUzMjkzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTU2MDIvY2xpZW50cy9hNjYxZTc5NzM1ZGM4OTBmL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9TUdFeE5UQTJNRE5pTW1RNU5EZGhObUptTkdGak5HSmxOVEEyTURZeE5tTS9hNjYxZTc5NzM1ZGM4OTBmQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE1NjAyL2NsaWVudHMvYTY2MWU3OTczNWRjODkwZi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI2OThjMDg2MC1jM2E0LTQ2NGEtYmVkMy02NjdmOTViNzYyOTYiLCJub25jZSI6IlRFTkVkR2swY2tsbGR6VkdZVTF3Y0hSVVMyOXVTWGsyVFZKNk5FRldjakUiLCJjaGFsIjoiODRTaEJ1Z1E2TWlNQlBFampMQXhBVWtsaEF6S3ViR1MiLCJjbmYiOnsia2lkIjoiYkZBN08wbnctS3ZzYWxUdVJqTGg5aEUtd2dtQTJKR2E0SnhQbDBxVnpjZyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVVtdDNkREkyYzJKNk5EUlVSbmRGTUV4YWFHNVVhMVU0WTJkZlMyTnBWWEJFT1ZoWGVUQkZjVzh3TkNKOWZRLmV5SnBZWFFpT2pFMk9EWXdOVE15T1Rnc0ltVjRjQ0k2TVRZNE5qQTFOamc1T0N3aWJtSm1Jam94TmpnMk1EVXpNamt6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFUxSFJYaE9WRUV5VFVST2FVMXRVVFZPUkdSb1RtMUtiVTVIUm1wT1IwcHNUbFJCTWsxRVdYaE9iVTB2WVRZMk1XVTNPVGN6TldSak9Ea3daa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJakZqTUdRNFkyVXpMVEJqTkdZdE5EWmxZaTA0TW1RNUxUTmlZakl6TVRSbU5EZGxZeUlzSW01dmJtTmxJam9pVkVWT1JXUkhhekJqYTJ4c1pIcFdSMWxWTVhkalNGSlZVekk1ZFZOWWF6SlVWa28yVGtWR1YyTnFSU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk1ESXZZMnhwWlc1MGN5OWhOall4WlRjNU56TTFaR000T1RCbUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUk0TkZOb1FuVm5VVFpOYVUxQ1VFVnFha3hCZUVGVmEyeG9RWHBMZFdKSFV5SjkuSW5EcUF5a3plaGh5ckhUejc0d1dGeDdMMG11eUpwSU53Tm9ObEdndnlDMkNzWWpCQlNadHRnMUZvTXpRcDlxVktPTjg0QUgxOTcxRjNvdDY0U05DQUEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU1HRXhOVEEyTUROaU1tUTVORGRoTm1KbU5HRmpOR0psTlRBMk1EWXhObU0vYTY2MWU3OTczNWRjODkwZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.pJ1gg3wocgnGSIC1hIxnmAEYWz5t20m7ibcYewEU9zVXwbrVIssd7fYLgEkbpEJcts-VXFBJCgflltOsa_t_Bw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6Im52bnFvTEZPc0xGcEYzbEJDRVhpb0d1NGhu
YUYxbENVU3F1T085RkU5MDAifX0.eyJpYXQiOjE2ODYwNTMyOTgsImV4cCI6MTY5
MzgyOTI5OCwibmJmIjoxNjg2MDUzMjkzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MTU2MDIvY2xpZW50cy9hNjYxZTc5NzM1ZGM4OTBmL2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9TUdFeE5UQTJNRE5pTW1RNU5EZGhObUptTkdGak5HSmxO
VEEyTURZeE5tTS9hNjYxZTc5NzM1ZGM4OTBmQHdpcmUuY29tIiwiYXVkIjoiaHR0
cDovL3dpcmUuY29tOjE1NjAyL2NsaWVudHMvYTY2MWU3OTczNWRjODkwZi9hY2Nl
c3MtdG9rZW4iLCJqdGkiOiI2OThjMDg2MC1jM2E0LTQ2NGEtYmVkMy02NjdmOTVi
NzYyOTYiLCJub25jZSI6IlRFTkVkR2swY2tsbGR6VkdZVTF3Y0hSVVMyOXVTWGsy
VFZKNk5FRldjakUiLCJjaGFsIjoiODRTaEJ1Z1E2TWlNQlBFampMQXhBVWtsaEF6
S3ViR1MiLCJjbmYiOnsia2lkIjoiYkZBN08wbnctS3ZzYWxUdVJqTGg5aEUtd2dt
QTJKR2E0SnhQbDBxVnpjZyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lz
SW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lz
SW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVVtdDNkREkyYzJKNk5EUlVSbmRG
TUV4YWFHNVVhMVU0WTJkZlMyTnBWWEJFT1ZoWGVUQkZjVzh3TkNKOWZRLmV5SnBZ
WFFpT2pFMk9EWXdOVE15T1Rnc0ltVjRjQ0k2TVRZNE5qQTFOamc1T0N3aWJtSm1J
am94TmpnMk1EVXpNamt6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFUxSFJYaE9W
RUV5VFVST2FVMXRVVFZPUkdSb1RtMUtiVTVIUm1wT1IwcHNUbFJCTWsxRVdYaE9i
VTB2WVRZMk1XVTNPVGN6TldSak9Ea3daa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJ
akZqTUdRNFkyVXpMVEJqTkdZdE5EWmxZaTA0TW1RNUxUTmlZakl6TVRSbU5EZGxZ
eUlzSW01dmJtTmxJam9pVkVWT1JXUkhhekJqYTJ4c1pIcFdSMWxWTVhkalNGSlZV
ekk1ZFZOWWF6SlVWa28yVGtWR1YyTnFSU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9k
SFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk1ESXZZMnhwWlc1MGN5OWhO
all4WlRjNU56TTFaR000T1RCbUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lP
aUk0TkZOb1FuVm5VVFpOYVUxQ1VFVnFha3hCZUVGVmEyeG9RWHBMZFdKSFV5Sjku
SW5EcUF5a3plaGh5ckhUejc0d1dGeDdMMG11eUpwSU53Tm9ObEdndnlDMkNzWWpC
QlNadHRnMUZvTXpRcDlxVktPTjg0QUgxOTcxRjNvdDY0U05DQUEiLCJjbGllbnRf
aWQiOiJpbTp3aXJlYXBwPU1HRXhOVEEyTUROaU1tUTVORGRoTm1KbU5HRmpOR0ps
TlRBMk1EWXhObU0vYTY2MWU3OTczNWRjODkwZkB3aXJlLmNvbSIsImFwaV92ZXJz
aW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.pJ1gg3wocgnGSIC1hIxn
mAEYWz5t20m7ibcYewEU9zVXwbrVIssd7fYLgEkbpEJcts-VXFBJCgflltOsa_t_
Bw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "nvnqoLFOsLFpF3lBCEXioGu4hnaF1lCUSquOO9FE900"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:15602/clients/a661e79735dc890f/access-token",
  "chal": "84ShBugQ6MiMBPEjjLAxAUklhAzKubGS",
  "client_id": "im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com",
  "cnf": {
    "kid": "bFA7O0nw-KvsalTuRjLh9hE-wgmA2JGa4JxPl0qVzcg"
  },
  "exp": 1693829298,
  "iat": 1686053298,
  "iss": "http://wire.com:15602/clients/a661e79735dc890f/access-token",
  "jti": "698c0860-c3a4-464a-bed3-667f95b76296",
  "nbf": 1686053293,
  "nonce": "TENEdGk0cklldzVGYU1wcHRUS29uSXk2TVJ6NEFWcjE",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUmt3dDI2c2J6NDRURndFMExaaG5Ua1U4Y2dfS2NpVXBEOVhXeTBFcW8wNCJ9fQ.eyJpYXQiOjE2ODYwNTMyOTgsImV4cCI6MTY4NjA1Njg5OCwibmJmIjoxNjg2MDUzMjkzLCJzdWIiOiJpbTp3aXJlYXBwPU1HRXhOVEEyTUROaU1tUTVORGRoTm1KbU5HRmpOR0psTlRBMk1EWXhObU0vYTY2MWU3OTczNWRjODkwZkB3aXJlLmNvbSIsImp0aSI6IjFjMGQ4Y2UzLTBjNGYtNDZlYi04MmQ5LTNiYjIzMTRmNDdlYyIsIm5vbmNlIjoiVEVORWRHazBja2xsZHpWR1lVMXdjSFJVUzI5dVNYazJUVko2TkVGV2NqRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTU2MDIvY2xpZW50cy9hNjYxZTc5NzM1ZGM4OTBmL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI4NFNoQnVnUTZNaU1CUEVqakxBeEFVa2xoQXpLdWJHUyJ9.InDqAykzehhyrHTz74wWFx7L0muyJpINwNoNlGgvyC2CsYjBBSZttg1FoMzQp9qVKON84AH1971F3ot64SNCAA",
  "scope": "wire_client_id",
  "sub": "im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBwZ8T4QDljhdXARTbyTCNA3IVGShicMaZSJGtQuKArT
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAnvnqoLFOsLFpF3lBCEXioGu4hnaF1lCUSquOO9FE900=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/x0gGlwzcz1VJWjgD9dM5RIuoSsLU4yva
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDY3L2FjbWUvd2lyZS9hY2NvdW50LzNmOFAyQTMzeEFNVFVWbk5MSlRaZUhUQ2p3MDhXeHU2IiwidHlwIjoiSldUIiwibm9uY2UiOiJOa1JYWjFOT05qUTFRVEJNTTNscGVVSjRRa2xtWVdOWlV6QnRSemt3VUdnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwNjcvYWNtZS93aXJlL2NoYWxsZW5nZS9WWjlPdkRkOHVDU1hNWGpYVk1mUWc2M1RMVW54R1pLay94MGdHbHd6Y3oxVkpXamdEOWRNNVJJdW9Tc0xVNHl2YSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltNTJibkZ2VEVaUGMweEdjRVl6YkVKRFJWaHBiMGQxTkdodVlVWXhiRU5WVTNGMVQwODVSa1U1TURBaWZYMC5leUpwWVhRaU9qRTJPRFl3TlRNeU9UZ3NJbVY0Y0NJNk1UWTVNemd5T1RJNU9Dd2libUptSWpveE5qZzJNRFV6TWprekxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk1ESXZZMnhwWlc1MGN5OWhOall4WlRjNU56TTFaR000T1RCbUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5VFVkRmVFNVVRVEpOUkU1cFRXMVJOVTVFWkdoT2JVcHRUa2RHYWs1SFNteE9WRUV5VFVSWmVFNXRUUzloTmpZeFpUYzVOek0xWkdNNE9UQm1RSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0RvdkwzZHBjbVV1WTI5dE9qRTFOakF5TDJOc2FXVnVkSE12WVRZMk1XVTNPVGN6TldSak9Ea3daaTloWTJObGMzTXRkRzlyWlc0aUxDSnFkR2tpT2lJMk9UaGpNRGcyTUMxak0yRTBMVFEyTkdFdFltVmtNeTAyTmpkbU9UVmlOell5T1RZaUxDSnViMjVqWlNJNklsUkZUa1ZrUjJzd1kydHNiR1I2VmtkWlZURjNZMGhTVlZNeU9YVlRXR3N5VkZaS05rNUZSbGRqYWtVaUxDSmphR0ZzSWpvaU9EUlRhRUoxWjFFMlRXbE5RbEJGYW1wTVFYaEJWV3RzYUVGNlMzVmlSMU1pTENKamJtWWlPbnNpYTJsa0lqb2lZa1pCTjA4d2JuY3RTM1p6WVd4VWRWSnFUR2c1YUVVdGQyZHRRVEpLUjJFMFNuaFFiREJ4Vm5walp5SjlMQ0p3Y205dlppSTZJbVY1U21oaVIyTnBUMmxLUmxwRlVsUlJVMGx6U1c1U05XTkRTVFpKYlZKM1lqTkJjbUZ1WkRCSmFYZHBZVzVrY2tscWNEZEpiWFF3WlZOSk5rbHJPVXhWUTBselNXMU9lV1JwU1RaSmExWnJUV3BWTVUxVWEybE1RMG8wU1dwdmFWVnRkRE5rUkVreVl6SktOazVFVWxWU2JtUkdUVVY0WVdGSE5WVmhNVlUwV1RKa1psTXlUbkJXV0VKRlQxWm9XR1ZVUWtaalZ6aDNUa05LT1daUkxtVjVTbkJaV0ZGcFQycEZNazlFV1hkT1ZFMTVUMVJuYzBsdFZqUmpRMGsyVFZSWk5FNXFRVEZPYW1jMVQwTjNhV0p0U20xSmFtOTRUbXBuTWsxRVZYcE5hbXQ2VEVOS2VtUlhTV2xQYVVwd1lsUndNMkZZU214WldFSjNVRlV4U0ZKWWFFOVdSVVY1VkZWU1QyRlZNWFJWVkZaUFVrZFNiMVJ0TVV0aVZUVklVbTF3VDFJd2NITlViRkpDVFdzeFJWZFlhRTlpVlRCMldWUlpNazFYVlROUFZHTjZUbGRTYWs5RWEzZGFhMEl6WVZoS2JFeHRUblppVTBselNXMXdNR0ZUU1RaSmFrWnFUVWRSTkZreVZYcE1WRUpxVGtkWmRFNUVXbXhaYVRBMFRXMVJOVXhVVG1sWmFrbDZUVlJTYlU1RVpHeFplVWx6U1cwMWRtSnRUbXhKYW05cFZrVldUMUpYVWtoaGVrSnFZVEo0YzFwSWNGZFNNV3hXVFZoa2FsTkdTbFpWZWtrMVpGWk9XV0Y2U2xWV2EyOHlWR3RXUjFZeVRuRlNVMGx6U1cxb01HSlRTVFpKYkVKUVZURlJhVXhEU205a1NGVnBUMmxLYjJSSVVuZFBhVGgyWkRKc2VWcFROV3BpTWpBMlRWUlZNazFFU1haWk1uaHdXbGMxTUdONU9XaE9hbGw0V2xSak5VNTZUVEZhUjAwMFQxUkNiVXd5Um1wWk1sWjZZM2t4TUdJeWRHeGlhVWx6U1cxT2IxbFhkMmxQYVVrMFRrWk9iMUZ1Vm01VlZGcE9ZVlV4UTFWRlZuRmhhM2hDWlVWR1ZtRXllRzlSV0hCTVpGZEtTRlY1U2prdVNXNUVjVUY1YTNwbGFHaDVja2hVZWpjMGQxZEdlRGRNTUcxMWVVcHdTVTUzVG05T2JFZG5kbmxETWtOeldXcENRbE5hZEhSbk1VWnZUWHBSY0RseFZrdFBUamcwUVVneE9UY3hSak52ZERZMFUwNURRVUVpTENKamJHbGxiblJmYVdRaU9pSnBiVHAzYVhKbFlYQndQVTFIUlhoT1ZFRXlUVVJPYVUxdFVUVk9SR1JvVG0xS2JVNUhSbXBPUjBwc1RsUkJNazFFV1hoT2JVMHZZVFkyTVdVM09UY3pOV1JqT0Rrd1prQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvekxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLnBKMWdnM3dvY2duR1NJQzFoSXhubUFFWVd6NXQyMG03aWJjWWV3RVU5elZYd2JyVklzc2Q3ZllMZ0VrYnBFSmN0cy1WWEZCSkNnZmxsdE9zYV90X0J3In0",
  "signature": "O1dQvUsVtYbke-mB-rtoqhNWHkrNVUS16_L0PZC6Qcb90YUVxVQwYT3OKnPxZXuYmpCRePjygYkNa6eOWhhIBA"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im52bnFvTEZPc0xGcEYzbEJDRVhpb0d1NGhuYUYxbENVU3F1T085RkU5MDAifX0.eyJpYXQiOjE2ODYwNTMyOTgsImV4cCI6MTY5MzgyOTI5OCwibmJmIjoxNjg2MDUzMjkzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTU2MDIvY2xpZW50cy9hNjYxZTc5NzM1ZGM4OTBmL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9TUdFeE5UQTJNRE5pTW1RNU5EZGhObUptTkdGak5HSmxOVEEyTURZeE5tTS9hNjYxZTc5NzM1ZGM4OTBmQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE1NjAyL2NsaWVudHMvYTY2MWU3OTczNWRjODkwZi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI2OThjMDg2MC1jM2E0LTQ2NGEtYmVkMy02NjdmOTViNzYyOTYiLCJub25jZSI6IlRFTkVkR2swY2tsbGR6VkdZVTF3Y0hSVVMyOXVTWGsyVFZKNk5FRldjakUiLCJjaGFsIjoiODRTaEJ1Z1E2TWlNQlBFampMQXhBVWtsaEF6S3ViR1MiLCJjbmYiOnsia2lkIjoiYkZBN08wbnctS3ZzYWxUdVJqTGg5aEUtd2dtQTJKR2E0SnhQbDBxVnpjZyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVVtdDNkREkyYzJKNk5EUlVSbmRGTUV4YWFHNVVhMVU0WTJkZlMyTnBWWEJFT1ZoWGVUQkZjVzh3TkNKOWZRLmV5SnBZWFFpT2pFMk9EWXdOVE15T1Rnc0ltVjRjQ0k2TVRZNE5qQTFOamc1T0N3aWJtSm1Jam94TmpnMk1EVXpNamt6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFUxSFJYaE9WRUV5VFVST2FVMXRVVFZPUkdSb1RtMUtiVTVIUm1wT1IwcHNUbFJCTWsxRVdYaE9iVTB2WVRZMk1XVTNPVGN6TldSak9Ea3daa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJakZqTUdRNFkyVXpMVEJqTkdZdE5EWmxZaTA0TW1RNUxUTmlZakl6TVRSbU5EZGxZeUlzSW01dmJtTmxJam9pVkVWT1JXUkhhekJqYTJ4c1pIcFdSMWxWTVhkalNGSlZVekk1ZFZOWWF6SlVWa28yVGtWR1YyTnFSU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk1ESXZZMnhwWlc1MGN5OWhOall4WlRjNU56TTFaR000T1RCbUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUk0TkZOb1FuVm5VVFpOYVUxQ1VFVnFha3hCZUVGVmEyeG9RWHBMZFdKSFV5SjkuSW5EcUF5a3plaGh5ckhUejc0d1dGeDdMMG11eUpwSU53Tm9ObEdndnlDMkNzWWpCQlNadHRnMUZvTXpRcDlxVktPTjg0QUgxOTcxRjNvdDY0U05DQUEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU1HRXhOVEEyTUROaU1tUTVORGRoTm1KbU5HRmpOR0psTlRBMk1EWXhObU0vYTY2MWU3OTczNWRjODkwZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.pJ1gg3wocgnGSIC1hIxnmAEYWz5t20m7ibcYewEU9zVXwbrVIssd7fYLgEkbpEJcts-VXFBJCgflltOsa_t_Bw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33067/acme/wire/account/3f8P2A33xAMTUVnNLJTZeHTCjw08Wxu6",
    "nonce": "NkRXZ1NONjQ1QTBMM3lpeUJ4QklmYWNZUzBtRzkwUGg",
    "typ": "JWT",
    "url": "https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/x0gGlwzcz1VJWjgD9dM5RIuoSsLU4yva"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33067/acme/wire/directory>;rel="index"
link: <https://stepca:33067/acme/wire/authz/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk>;rel="up"
location: https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/x0gGlwzcz1VJWjgD9dM5RIuoSsLU4yva
replay-nonce: UG13amx5bllYbDAwaTZLM0prYkJvelduUTBhWU5UMDI
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/x0gGlwzcz1VJWjgD9dM5RIuoSsLU4yva",
  "status": "valid",
  "token": "84ShBugQ6MiMBPEjjLAxAUklhAzKubGS",
  "target": "http://wire.com:15602/clients/a661e79735dc890f/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=-LWuyIxVRDtctIbLnMJU0I3uN9723MDOURIhkFHGUD4&code_challenge=nzD__-6myeq8ShAEvsjkmh6Qk1FmkUolTJFetToAkTs
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:16070/dex/auth?response_type=code&client_id=wireapp&state=9KuC_GM616SsF47NJGOUkw&code_challenge=nzD__-6myeq8ShAEvsjkmh6Qk1FmkUolTJFetToAkTs&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A15602%2Fcallback&scope=openid+profile&nonce=xDWdABJLNZpYeeiU3q2eZA
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:16070/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDphM1pHVlc5MWJVZDJkSHBYYlhkMFMwTlpSVGx4YWpGRw==
```
```text
grant_type=authorization_code&code=q5jfcbhe2llgulvxi2los4dih&code_verifier=-LWuyIxVRDtctIbLnMJU0I3uN9723MDOURIhkFHGUD4&redirect_uri=http%3A%2F%2Fwire.com%3A15602%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlYmI0ZGE4Zjg1ZDJmMzBmNTIzMDk4YzRiMGFlZTMzMmM3ZGU3ZTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDcwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTFIUlhoT1ZFRXlUVVJPYVUxdFVUVk9SR1JvVG0xS2JVNUhSbXBPUjBwc1RsUkJNazFFV1hoT2JVMHZZVFkyTVdVM09UY3pOV1JqT0Rrd1prQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg2MTM5Njk4LCJpYXQiOjE2ODYwNTMyOTgsIm5vbmNlIjoieERXZEFCSkxOWnBZZWVpVTNxMmVaQSIsImF0X2hhc2giOiJVWC1Kc054QUxfVnp1MFViRUdUbDBBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.CGvt_CT8acCHx4l5AdKMqJLh12UtsjKWkKzn4qY8BfcAbfkiKGVjK_LuFAgpUySNKsa4skzcu3gC9VItOC_JXpQuXdz9XOEYaAKbGGN2R8BpA99skLOUp6fqToPlWYiAYULVcDjYxR92SIEyKjZoKDkMNGhlg-NZ7KVjYut129CU5n8ypWsILbw84sCBVg3eEbfTaJpBO3aXbGck5bZ5H8Bry8JWoSnA609wmSEqlmOn2pa9SqCgx8UhIxDxbD24MNaqj8-CK_V-zwa_pFQpP7ToZ3zKC3FtFsd0IyvN-6oKpCwtzG24yKEqtmw_mGu8Ihk0aredM8XmhGMF5yRegQ",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlYmI0ZGE4Zjg1ZDJmMzBmNTIzMDk4YzRiMGFlZTMzMmM3ZGU3ZTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDcwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTFIUlhoT1ZFRXlUVVJPYVUxdFVUVk9SR1JvVG0xS2JVNUhSbXBPUjBwc1RsUkJNazFFV1hoT2JVMHZZVFkyTVdVM09UY3pOV1JqT0Rrd1prQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg2MTM5Njk4LCJpYXQiOjE2ODYwNTMyOTgsIm5vbmNlIjoieERXZEFCSkxOWnBZZWVpVTNxMmVaQSIsImF0X2hhc2giOiJJNU1uQzRnd0xUaUxtaWl5eDlHcDVRIiwiY19oYXNoIjoiaDU2cldiZEpETVV1Rngzc2ZYX25BQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.Pzc3V6DiR6b6cHPhFTAd08mdbWn5cUFkfNDOnA5vsTZXhjDEdu2_-loYzp5K7szLi_0pbSatGbD-2wtrxh6p3n9RP_m476hhJ-mtRWd3JhqoYCAguXoPK_FU1OCrdWQ81k1yg1MZLH5L6m3_mp3-asqzRIdljADxrf8O5Hygy7KiD5qDMW9kX5oZPxm__aQRmZ5jBgDqMlN4Nh1Bmnu6oQnlbFizqOwZ-dmo-LrlR4PtupApDuMJpylTTHIMfY6n7yxNUdGM5JiPnwZBT4UoHlC_lkfSomGV1MlhS2-yLTGAZHXgeM_Y0gtbzjwKYsB3ZlrXBqLiAmK4yweGus70uw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlYmI0ZGE4Zjg1ZDJmMzBmNTIzMDk4YzRiMGFlZTMzMmM3ZGU3ZTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDcwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTFIUlhoT1ZFRXlUVVJPYVUxdFVUVk9SR1JvVG0xS2JVNUhSbXBPUjBwc1RsUkJNazFFV1hoT2JVMHZZVFkyTVdVM09UY3pOV1JqT0Rrd1prQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg2MTM5Njk4LCJpYXQiOjE2ODYwNTMyOTgsIm5vbmNlIjoieERXZEFCSkxOWnBZZWVpVTNxMmVaQSIsImF0X2hhc2giOiJJNU1uQzRnd0xUaUxtaWl5eDlHcDVRIiwiY19oYXNoIjoiaDU2cldiZEpETVV1Rngzc2ZYX25BQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.Pzc3V6DiR6b6cHPhFTAd08mdbWn5cUFkfNDOnA5vsTZXhjDEdu2_-loYzp5K7szLi_0pbSatGbD-2wtrxh6p3n9RP_m476hhJ-mtRWd3JhqoYCAguXoPK_FU1OCrdWQ81k1yg1MZLH5L6m3_mp3-asqzRIdljADxrf8O5Hygy7KiD5qDMW9kX5oZPxm__aQRmZ5jBgDqMlN4Nh1Bmnu6oQnlbFizqOwZ-dmo-LrlR4PtupApDuMJpylTTHIMfY6n7yxNUdGM5JiPnwZBT4UoHlC_lkfSomGV1MlhS2-yLTGAZHXgeM_Y0gtbzjwKYsB3ZlrXBqLiAmK4yweGus70uw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlYmI0ZGE4Zjg1ZDJmMzBmNTIzMDk4YzRiMGFlZTMzMmM3ZGU3ZTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDcwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTFIUlhoT1ZFRXlUVVJPYVUxdFVUVk9SR1JvVG0xS2JVNUhSbXBPUjBwc1RsUkJNazFFV1hoT2JVMHZZVFkyTVdVM09UY3pOV1JqT0Rrd1prQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg2MTM5Njk4LCJpYXQiOjE2ODYwNTMyOTgsIm5vbmNlIjoieERXZEFCSkxOWnBZZWVpVTNxMmVaQSIsImF0X2hhc2giOiJJNU1uQzRnd0xUaUxtaWl5eDlHcDVRIiwiY19oYXNoIjoiaDU2cldiZEpETVV1Rngzc2ZYX25BQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.Pzc3V6DiR6b6cHPhFTAd08mdbWn5cUFkfNDOnA5vsTZXhjDEdu2_-loYzp5K7szLi_0pbSatGbD-2wtrxh6p3n9RP_m476hhJ-mtRWd3JhqoYCAguXoPK_FU1OCrdWQ81k1yg1MZLH5L6m3_mp3-asqzRIdljADxrf8O5Hygy7KiD5qDMW9kX5oZPxm__aQRmZ5jBgDqMlN4Nh1Bmnu6oQnlbFizqOwZ-dmo-LrlR4PtupApDuMJpylTTHIMfY6n7yxNUdGM5JiPnwZBT4UoHlC_lkfSomGV1MlhS2-yLTGAZHXgeM_Y0gtbzjwKYsB3ZlrXBqLiAmK4yweGus70uw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlYmI0ZGE4Zjg1ZDJmMzBmNTIzMDk4YzRi
MGFlZTMzMmM3ZGU3ZTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDcwL2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTFIUlhoT1ZFRXlUVVJPYVUxdFVUVk9SR
1JvVG0xS2JVNUhSbXBPUjBwc1RsUkJNazFFV1hoT2JVMHZZVFkyTVdVM09UY3pOV
1JqT0Rrd1prQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjg2MTM5Njk4LCJpYXQiOjE2ODYwNTMyOTgsIm5vbmNlIjoieERXZEFCS
kxOWnBZZWVpVTNxMmVaQSIsImF0X2hhc2giOiJJNU1uQzRnd0xUaUxtaWl5eDlHc
DVRIiwiY19oYXNoIjoiaDU2cldiZEpETVV1Rngzc2ZYX25BQSIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZ
SBTbWl0aCJ9.Pzc3V6DiR6b6cHPhFTAd08mdbWn5cUFkfNDOnA5vsTZXhjDEdu2_
-loYzp5K7szLi_0pbSatGbD-2wtrxh6p3n9RP_m476hhJ-mtRWd3JhqoYCAguXoP
K_FU1OCrdWQ81k1yg1MZLH5L6m3_mp3-asqzRIdljADxrf8O5Hygy7KiD5qDMW9k
X5oZPxm__aQRmZ5jBgDqMlN4Nh1Bmnu6oQnlbFizqOwZ-dmo-LrlR4PtupApDuMJ
pylTTHIMfY6n7yxNUdGM5JiPnwZBT4UoHlC_lkfSomGV1MlhS2-yLTGAZHXgeM_Y
0gtbzjwKYsB3ZlrXBqLiAmK4yweGus70uw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "0ebb4da8f85d2f30f523098c4b0aee332c7de7e4"
}
```

```json
{
  "at_hash": "I5MnC4gwLTiLmiiyx9Gp5Q",
  "aud": "wireapp",
  "c_hash": "h56rWbdJDMUuFx3sfX_nAA",
  "exp": 1686139698,
  "iat": 1686053298,
  "iss": "http://dex:16070/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "xDWdABJLNZpYeeiU3q2eZA",
  "preferred_username": "Alice Smith",
  "sub": "ClBpbTp3aXJlYXBwPU1HRXhOVEEyTUROaU1tUTVORGRoTm1KbU5HRmpOR0psTlRBMk1EWXhObU0vYTY2MWU3OTczNWRjODkwZkB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAthtsqOR/txR4VGaaWSJ7
enfAhfNIDxfn6FEy/djxUxi6BF1pQuNumIgSk3mD9dLb7flCYTLPI59U+pFeoqA/
qj817l6Hyl3D1BWI3b7Z9/fcXG/1Vc5xf2hNAvxKIX41ls9ZjSADplJce7sA5dcy
nTzjnN2ufe7mA0O98aKewKC1t0lNrBmeKtziau0dpirW2a9Mr3rOPrca4aI3rGUy
jiq+QcZSfsdxfD3rdJng7iC4vAkgixW6cN90/zk/C+GAOM2qOcGsKc7O1Ij0+xtI
aJLynpm6M25EpFFo4X9mC2eVc9pB83rwTW1XzjmZ2gM5idEtDYoq9WYDgqF0iXkl
6wIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/Zaa3kx1T7ThIuYBI4KiS4dmBWetKeXNW
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDY3L2FjbWUvd2lyZS9hY2NvdW50LzNmOFAyQTMzeEFNVFVWbk5MSlRaZUhUQ2p3MDhXeHU2IiwidHlwIjoiSldUIiwibm9uY2UiOiJVRzEzYW14NWJsbFliREF3YVRaTE0wcHJZa0p2ZWxkdVVUQmhXVTVVTURJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwNjcvYWNtZS93aXJlL2NoYWxsZW5nZS9WWjlPdkRkOHVDU1hNWGpYVk1mUWc2M1RMVW54R1pLay9aYWEza3gxVDdUaEl1WUJJNEtpUzRkbUJXZXRLZVhOVyJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJakJsWW1JMFpHRTRaamcxWkRKbU16Qm1OVEl6TURrNFl6UmlNR0ZsWlRNek1tTTNaR1UzWlRRaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTJNRGN3TDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZURklVbGhvVDFaRlJYbFVWVkpQWVZVeGRGVlVWazlTUjFKdlZHMHhTMkpWTlVoU2JYQlBVakJ3YzFSc1VrSk5hekZGVjFob1QySlZNSFpaVkZreVRWZFZNMDlVWTNwT1YxSnFUMFJyZDFwclFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qZzJNVE01TmprNExDSnBZWFFpT2pFMk9EWXdOVE15T1Rnc0ltNXZibU5sSWpvaWVFUlhaRUZDU2t4T1duQlpaV1ZwVlROeE1tVmFRU0lzSW1GMFgyaGhjMmdpT2lKSk5VMXVRelJuZDB4VWFVeHRhV2w1ZURsSGNEVlJJaXdpWTE5b1lYTm9Jam9pYURVMmNsZGlaRXBFVFZWMVJuZ3pjMlpZWDI1QlFTSXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObFgzZHBjbVVpTENKd2NtVm1aWEp5WldSZmRYTmxjbTVoYldVaU9pSkJiR2xqWlNCVGJXbDBhQ0o5LlB6YzNWNkRpUjZiNmNIUGhGVEFkMDhtZGJXbjVjVUZrZk5ET25BNXZzVFpYaGpERWR1Ml8tbG9ZenA1SzdzekxpXzBwYlNhdEdiRC0yd3RyeGg2cDNuOVJQX200NzZoaEotbXRSV2QzSmhxb1lDQWd1WG9QS19GVTFPQ3JkV1E4MWsxeWcxTVpMSDVMNm0zX21wMy1hc3F6UklkbGpBRHhyZjhPNUh5Z3k3S2lENXFETVc5a1g1b1pQeG1fX2FRUm1aNWpCZ0RxTWxONE5oMUJtbnU2b1FubGJGaXpxT3daLWRtby1McmxSNFB0dXBBcER1TUpweWxUVEhJTWZZNm43eXhOVWRHTTVKaVBud1pCVDRVb0hsQ19sa2ZTb21HVjFNbGhTMi15TFRHQVpIWGdlTV9ZMGd0Ynpqd0tZc0IzWmxyWEJxTGlBbUs0eXdlR3VzNzB1dyIsImtleWF1dGgiOiI4NFNoQnVnUTZNaU1CUEVqakxBeEFVa2xoQXpLdWJHUy5kZzE5Z05IeUN3VDQ3MjNoZGNZRWc0R1BqV0d0UzNKWDFEUHlqS2tNTU1vIn0",
  "signature": "rTuVlCLkZpw-Ycd_vSh5V-5jkAV35D7rUkhCqwwCEgCIZDcT6yJKeo42lM5padHRqzviyISlLPCcmGBbS6VdDg"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBlYmI0ZGE4Zjg1ZDJmMzBmNTIzMDk4YzRiMGFlZTMzMmM3ZGU3ZTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDcwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTFIUlhoT1ZFRXlUVVJPYVUxdFVUVk9SR1JvVG0xS2JVNUhSbXBPUjBwc1RsUkJNazFFV1hoT2JVMHZZVFkyTVdVM09UY3pOV1JqT0Rrd1prQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg2MTM5Njk4LCJpYXQiOjE2ODYwNTMyOTgsIm5vbmNlIjoieERXZEFCSkxOWnBZZWVpVTNxMmVaQSIsImF0X2hhc2giOiJJNU1uQzRnd0xUaUxtaWl5eDlHcDVRIiwiY19oYXNoIjoiaDU2cldiZEpETVV1Rngzc2ZYX25BQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.Pzc3V6DiR6b6cHPhFTAd08mdbWn5cUFkfNDOnA5vsTZXhjDEdu2_-loYzp5K7szLi_0pbSatGbD-2wtrxh6p3n9RP_m476hhJ-mtRWd3JhqoYCAguXoPK_FU1OCrdWQ81k1yg1MZLH5L6m3_mp3-asqzRIdljADxrf8O5Hygy7KiD5qDMW9kX5oZPxm__aQRmZ5jBgDqMlN4Nh1Bmnu6oQnlbFizqOwZ-dmo-LrlR4PtupApDuMJpylTTHIMfY6n7yxNUdGM5JiPnwZBT4UoHlC_lkfSomGV1MlhS2-yLTGAZHXgeM_Y0gtbzjwKYsB3ZlrXBqLiAmK4yweGus70uw",
    "keyauth": "84ShBugQ6MiMBPEjjLAxAUklhAzKubGS.dg19gNHyCwT4723hdcYEg4GPjWGtS3JX1DPyjKkMMMo"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33067/acme/wire/account/3f8P2A33xAMTUVnNLJTZeHTCjw08Wxu6",
    "nonce": "UG13amx5bllYbDAwaTZLM0prYkJvelduUTBhWU5UMDI",
    "typ": "JWT",
    "url": "https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/Zaa3kx1T7ThIuYBI4KiS4dmBWetKeXNW"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33067/acme/wire/directory>;rel="index"
link: <https://stepca:33067/acme/wire/authz/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk>;rel="up"
location: https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/Zaa3kx1T7ThIuYBI4KiS4dmBWetKeXNW
replay-nonce: ZEo4S1h6UmVVYVZMSUlNcEN0MERyaTdObmZUQ1dwWUE
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:33067/acme/wire/challenge/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk/Zaa3kx1T7ThIuYBI4KiS4dmBWetKeXNW",
  "status": "valid",
  "token": "84ShBugQ6MiMBPEjjLAxAUklhAzKubGS",
  "target": "http://dex:16070/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDY3L2FjbWUvd2lyZS9hY2NvdW50LzNmOFAyQTMzeEFNVFVWbk5MSlRaZUhUQ2p3MDhXeHU2IiwidHlwIjoiSldUIiwibm9uY2UiOiJaRW80UzFoNlVtVlZZVlpNU1VsTmNFTjBNRVJ5YVRkT2JtWlVRMWR3V1VFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwNjcvYWNtZS93aXJlL29yZGVyL0Q3MXpVQVN3MWJNSGR4Y3Y1ejdaRVpQcGlJbVZRbzhJIn0",
  "payload": "",
  "signature": "tqfUopbWQ4nd_3cYk7K36_2pZh57fob9kPulsgHnUsRCFPThesL6XzM9_vSN-WsUvIl4xuHhCsOxhgLJBKteAA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33067/acme/wire/account/3f8P2A33xAMTUVnNLJTZeHTCjw08Wxu6",
    "nonce": "ZEo4S1h6UmVVYVZMSUlNcEN0MERyaTdObmZUQ1dwWUE",
    "typ": "JWT",
    "url": "https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33067/acme/wire/directory>;rel="index"
location: https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I
replay-nonce: RENucXZtUFVUeGNsTmc3enR1WThjdDFEbUxnTHF2WXA
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33067/acme/wire/authz/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk"
  ],
  "expires": "2023-06-07T12:08:18Z",
  "notBefore": "2023-06-06T12:08:18.362732Z",
  "notAfter": "2033-06-03T12:08:18.362732Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDY3L2FjbWUvd2lyZS9hY2NvdW50LzNmOFAyQTMzeEFNVFVWbk5MSlRaZUhUQ2p3MDhXeHU2IiwidHlwIjoiSldUIiwibm9uY2UiOiJSRU51Y1hadFVGVlVlR05zVG1jM2VuUjFXVGhqZERGRWJVeG5USEYyV1hBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwNjcvYWNtZS93aXJlL29yZGVyL0Q3MXpVQVN3MWJNSGR4Y3Y1ejdaRVpQcGlJbVZRbzhJL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCT0RDQjZ3SUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBRVpNTGR1ckc4LU9FeGNCTkMyWVowNUZQSElQeW5JbEtRX1Yxc3RCS3FOT29JR0dNSUdEQmdrcWhraUc5dzBCQ1E0eGRqQjBNSElHQTFVZEVRUnJNR21HVUdsdE9uZHBjbVZoY0hBOVRVZEZlRTVVUVRKTlJFNXBUVzFSTlU1RVpHaE9iVXB0VGtkR2FrNUhTbXhPVkVFeVRVUlplRTV0VFM5aE5qWXhaVGM1TnpNMVpHTTRPVEJtUUhkcGNtVXVZMjl0aGhWcGJUcDNhWEpsWVhCd1BXRnNhV05sWDNkcGNtVXdCUVlESzJWd0EwRUFBbFRtT3NNQ3RHWWh1SXJXSUJQM1hnMEpaa1FlV05QWXZhT1JTdVk5Q0RocklOZDVsT3dHX01NTmZSQ0tZeDN5U2xGNTZ2eGs4Q2RiQTVncnZfdjdBQSJ9",
  "signature": "VfUsAIrUndXLa6Iwmlj3LfHeUaS9V0czAo1NhSTy-7iOQNmH9gcRQ85oowZn4o9an3M8HzOwgNuMfFvN8IcNAg"
}
```
```json
{
  "payload": {
    "csr": "MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAEZMLdurG8-OExcBNC2YZ05FPHIPynIlKQ_V1stBKqNOoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndpcmVhcHA9TUdFeE5UQTJNRE5pTW1RNU5EZGhObUptTkdGak5HSmxOVEEyTURZeE5tTS9hNjYxZTc5NzM1ZGM4OTBmQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dpcmUwBQYDK2VwA0EAAlTmOsMCtGYhuIrWIBP3Xg0JZkQeWNPYvaORSuY9CDhrINd5lOwG_MMNfRCKYx3ySlF56vxk8CdbA5grv_v7AA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33067/acme/wire/account/3f8P2A33xAMTUVnNLJTZeHTCjw08Wxu6",
    "nonce": "RENucXZtUFVUeGNsTmc3enR1WThjdDFEbUxnTHF2WXA",
    "typ": "JWT",
    "url": "https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAEZMLdurG8+OExcBNC2YZ05FPHIPynIl
KQ/V1stBKqNOoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndp
cmVhcHA9TUdFeE5UQTJNRE5pTW1RNU5EZGhObUptTkdGak5HSmxOVEEyTURZeE5t
TS9hNjYxZTc5NzM1ZGM4OTBmQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dp
cmUwBQYDK2VwA0EAAlTmOsMCtGYhuIrWIBP3Xg0JZkQeWNPYvaORSuY9CDhrINd5
lOwG/MMNfRCKYx3ySlF56vxk8CdbA5grv/v7AA==
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
                    46:4c:2d:db:ab:1b:cf:8e:13:17:01:34:2d:98:67:
                    4e:45:3c:72:0f:ca:72:25:29:0f:d5:d6:cb:41:2a:
                    a3:4e
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        02:54:e6:3a:c3:02:b4:66:21:b8:8a:d6:20:13:f7:5e:0d:09:
        66:44:1e:58:d3:d8:bd:a3:91:4a:e6:3d:08:38:6b:20:d7:79:
        94:ec:06:fc:c3:0d:7d:10:8a:63:1d:f2:4a:51:79:ea:fc:64:
        f0:27:5b:03:98:2b:bf:fb:fb:00

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33067/acme/wire/directory>;rel="index"
location: https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I
replay-nonce: SWlEUmRQVHoyUG5KejhQTWt3UXJjTXZSRjlvUWNKTHA
```
```json
{
  "certificate": "https://stepca:33067/acme/wire/certificate/MPd3TpyTezfB7zED0ZBo2HPwCrCDDhHT",
  "status": "valid",
  "finalize": "https://stepca:33067/acme/wire/order/D71zUASw1bMHdxcv5z7ZEZPpiImVQo8I/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33067/acme/wire/authz/VZ9OvDd8uCSXMXjXVMfQg63TLUnxGZKk"
  ],
  "expires": "2023-06-07T12:08:18Z",
  "notBefore": "2023-06-06T12:08:18.362732Z",
  "notAfter": "2033-06-03T12:08:18.362732Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:33067/acme/wire/certificate/MPd3TpyTezfB7zED0ZBo2HPwCrCDDhHT
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDY3L2FjbWUvd2lyZS9hY2NvdW50LzNmOFAyQTMzeEFNVFVWbk5MSlRaZUhUQ2p3MDhXeHU2IiwidHlwIjoiSldUIiwibm9uY2UiOiJTV2xFVW1SUVZIb3lVRzVLZWpoUVRXdDNVWEpqVFhaU1JqbHZVV05LVEhBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwNjcvYWNtZS93aXJlL2NlcnRpZmljYXRlL01QZDNUcHlUZXpmQjd6RUQwWkJvMkhQd0NyQ0REaEhUIn0",
  "payload": "",
  "signature": "0SsKraW0kTsCLA6oL0iMifa2Wgo_HMFg6prH5rT-hH42hjQJgoaqtTju-HjIQBKP6o4SaDHLCBGlswHdDPTRBg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33067/acme/wire/account/3f8P2A33xAMTUVnNLJTZeHTCjw08Wxu6",
    "nonce": "SWlEUmRQVHoyUG5KejhQTWt3UXJjTXZSRjlvUWNKTHA",
    "typ": "JWT",
    "url": "https://stepca:33067/acme/wire/certificate/MPd3TpyTezfB7zED0ZBo2HPwCrCDDhHT"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:33067/acme/wire/directory>;rel="index"
replay-nonce: UWNVaE1SODE5TzF0ckloSEZrRTc4RDU0a1RPQ2FnbTI
```
```json
"-----BEGIN CERTIFICATE-----\nMIICIzCCAcmgAwIBAgIRAMenThsAtlCIhqyCAVH0GEEwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwNjA2MTIwODE4WhcNMzMwNjAzMTIwODE4WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQBGTC3bqxvPjhMXATQt\nmGdORTxyD8pyJSkP1dbLQSqjTqOB+zCB+DAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFNKA345X524Q+SHCLQ00zZ0cdBNoMB8G\nA1UdIwQYMBaAFME5AwrCFGOqvFlmddEH2+uh+tiRMHIGA1UdEQRrMGmGFWltOndp\ncmVhcHA9YWxpY2Vfd2lyZYZQaW06d2lyZWFwcD1NR0V4TlRBMk1ETmlNbVE1TkRk\naE5tSm1OR0ZqTkdKbE5UQTJNRFl4Tm1NL2E2NjFlNzk3MzVkYzg5MGZAd2lyZS5j\nb20wHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gA\nMEUCIQDZtqoDW2/voz+Bxv+arvKs4D9LrYcLrxZggqoyfDlXtwIgWQydK7muAf4A\npK3eVnJT+lAkA0ez9GGQhsceZNe80SE=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAP/U+N1JHsvQGzup+9TuHtYwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDYwNjEy\nMDgxNVoXDTMzMDYwMzEyMDgxNVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASb\nU608O/JI9Zuludc4npVxoIxiqmVF6fW0HVcPh0qJVIbOi31PHNP3j2+MHG0aMCaS\n7OxDLufmg5YdnDN3JCaxo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUwTkDCsIUY6q8WWZ10Qfb66H62JEwHwYDVR0jBBgw\nFoAUbP1RpVa66tSHaLyK7VmFyP0n9WQwCgYIKoZIzj0EAwIDSAAwRQIhAPKAMr9+\ncTWiPuFpdomnTBZRB7wwAk9dKR5a/l02Jx6OAiBebfLGFRQ1psRWsomqt8LGjjZ7\n5TVDcCtvnOTq+MSIJw==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICIzCCAcmgAwIBAgIRAMenThsAtlCIhqyCAVH0GEEwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwNjA2MTIwODE4WhcNMzMwNjAzMTIwODE4WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQBGTC3bqxvPjhMXATQt
mGdORTxyD8pyJSkP1dbLQSqjTqOB+zCB+DAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFNKA345X524Q+SHCLQ00zZ0cdBNoMB8G
A1UdIwQYMBaAFME5AwrCFGOqvFlmddEH2+uh+tiRMHIGA1UdEQRrMGmGFWltOndp
cmVhcHA9YWxpY2Vfd2lyZYZQaW06d2lyZWFwcD1NR0V4TlRBMk1ETmlNbVE1TkRk
aE5tSm1OR0ZqTkdKbE5UQTJNRFl4Tm1NL2E2NjFlNzk3MzVkYzg5MGZAd2lyZS5j
b20wHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gA
MEUCIQDZtqoDW2/voz+Bxv+arvKs4D9LrYcLrxZggqoyfDlXtwIgWQydK7muAf4A
pK3eVnJT+lAkA0ez9GGQhsceZNe80SE=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            c7:a7:4e:1b:00:b6:50:88:86:ac:82:01:51:f4:18:41
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Jun  6 12:08:18 2023 GMT
            Not After : Jun  3 12:08:18 2033 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    46:4c:2d:db:ab:1b:cf:8e:13:17:01:34:2d:98:67:
                    4e:45:3c:72:0f:ca:72:25:29:0f:d5:d6:cb:41:2a:
                    a3:4e
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                D2:80:DF:8E:57:E7:6E:10:F9:21:C2:2D:0D:34:CD:9D:1C:74:13:68
            X509v3 Authority Key Identifier: 
                C1:39:03:0A:C2:14:63:AA:BC:59:66:75:D1:07:DB:EB:A1:FA:D8:91
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice_wire, URI:im:wireapp=MGExNTA2MDNiMmQ5NDdhNmJmNGFjNGJlNTA2MDYxNmM/a661e79735dc890f@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:d9:b6:aa:03:5b:6f:ef:a3:3f:81:c6:ff:9a:
        ae:f2:ac:e0:3f:4b:ad:87:0b:af:16:60:82:aa:32:7c:39:57:
        b7:02:20:59:0c:9d:2b:b9:ae:01:fe:00:a4:ad:de:56:72:53:
        fa:50:24:03:47:b3:f4:61:90:86:c7:1e:64:d7:bc:d1:21

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAP/U+N1JHsvQGzup+9TuHtYwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDYwNjEy
MDgxNVoXDTMzMDYwMzEyMDgxNVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASb
U608O/JI9Zuludc4npVxoIxiqmVF6fW0HVcPh0qJVIbOi31PHNP3j2+MHG0aMCaS
7OxDLufmg5YdnDN3JCaxo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUwTkDCsIUY6q8WWZ10Qfb66H62JEwHwYDVR0jBBgw
FoAUbP1RpVa66tSHaLyK7VmFyP0n9WQwCgYIKoZIzj0EAwIDSAAwRQIhAPKAMr9+
cTWiPuFpdomnTBZRB7wwAk9dKR5a/l02Jx6OAiBebfLGFRQ1psRWsomqt8LGjjZ7
5TVDcCtvnOTq+MSIJw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ff:d4:f8:dd:49:1e:cb:d0:1b:3b:a9:fb:d4:ee:1e:d6
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Jun  6 12:08:15 2023 GMT
            Not After : Jun  3 12:08:15 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:9b:53:ad:3c:3b:f2:48:f5:9b:a5:b9:d7:38:9e:
                    95:71:a0:8c:62:aa:65:45:e9:f5:b4:1d:57:0f:87:
                    4a:89:54:86:ce:8b:7d:4f:1c:d3:f7:8f:6f:8c:1c:
                    6d:1a:30:26:92:ec:ec:43:2e:e7:e6:83:96:1d:9c:
                    33:77:24:26:b1
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                C1:39:03:0A:C2:14:63:AA:BC:59:66:75:D1:07:DB:EB:A1:FA:D8:91
            X509v3 Authority Key Identifier: 
                6C:FD:51:A5:56:BA:EA:D4:87:68:BC:8A:ED:59:85:C8:FD:27:F5:64
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:f2:80:32:bf:7e:71:35:a2:3e:e1:69:76:89:
        a7:4c:16:51:07:bc:30:02:4f:5d:29:1e:5a:fe:5d:36:27:1e:
        8e:02:20:5e:6d:f2:c6:15:14:35:a6:c4:56:b2:89:aa:b7:c2:
        c6:8e:36:7b:e5:35:43:70:2b:6f:9c:e4:ea:f8:c4:88:27

```
