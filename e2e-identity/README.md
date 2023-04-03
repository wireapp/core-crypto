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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/gTUrdUl5urNJXYVwOkjNottmM912qbBY
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/7789088759724732209/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/WZUHEg5Ts9MIO34qHCpZjWd3GCWR0am5
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /login
    wire-server->>wire-server: verifier & challenge codes
    wire-server->>+authorization-server:  200
    authorization-server->>-wire-client: 200
    wire-client->>+authorization-server:  POST /dex/auth/ldap/login
    authorization-server->>-wire-client: 200
    wire-client->>+authorization-server:  POST /dex/approval
    authorization-server->>+wire-server:  GET /callback
    wire-server->>+authorization-server:  POST /dex/token
    authorization-server->>authorization-server: verify verifier & challenge codes
    authorization-server->>-wire-server: 200
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/MmKxzFq9FtmE8pMpJv4LSLw6614DazdA
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/vq9x2zRm1jsiTTr2a4x6oyrbqI8gTDq9
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:55083/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:55083/acme/wire/new-nonce",
  "newAccount": "https://stepca:55083/acme/wire/new-account",
  "newOrder": "https://stepca:55083/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:55083/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:55083/acme/wire/directory>;rel="index"
replay-nonce: b0N0VFFwS3NITnhRcDNMSENRVFgzdGZYYmpQZmZDTWY
```
```text
b0N0VFFwS3NITnhRcDNMSENRVFgzdGZYYmpQZmZDTWY
```
#### 5. create a new account
```http request
POST https://stepca:55083/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImJOc1ZjZVRhZUJRYWtGak5wc1FDME1raDU5dGZYX0FOUklNbHNRdi1jazAifSwibm9uY2UiOiJiME4wVkZGd1MzTklUbmhSY0ROTVNFTlJWRmd6ZEdaWVltcFFabVpEVFdZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "5vFpLetWCJXXtLBog-hujWpaEJ0V8l0UdMDpyKwB0n1y2bYqvDj15YQalPAJExdUrMj7MXX08W8kfGBF9iHDAg"
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
      "x": "bNsVceTaeBQakFjNpsQC0Mkh59tfX_ANRIMlsQv-ck0"
    },
    "nonce": "b0N0VFFwS3NITnhRcDNMSENRVFgzdGZYYmpQZmZDTWY",
    "typ": "JWT",
    "url": "https://stepca:55083/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/account/wvYpqnUvADmOgk9Ln6TF6JPfQsrLx64T
replay-nonce: d01NWDFVZzFnTDYxcTQzbzVnWHNvQ01CdGYwcVRqY3c
```
```json
{
  "status": "valid",
  "orders": "https://stepca:55083/acme/wire/account/wvYpqnUvADmOgk9Ln6TF6JPfQsrLx64T/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:55083/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L3d2WXBxblV2QURtT2drOUxuNlRGNkpQZlFzckx4NjRUIiwidHlwIjoiSldUIiwibm9uY2UiOiJkMDFOV0RGVlp6Rm5URFl4Y1RRemJ6Vm5XSE52UTAxQ2RHWXdjVlJxWTNjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9TmpobE16SXhPV0ZqT0RSaU5EQXdZamswWkdGaFpEQTJOekV4TlRFeU5UZy82YzE4NjZmNTY3NjE2ZjMxQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9YWxpY2Vfd2lyZVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wNC0wNVQwOToyNjo1OC41NDY0MzNaIiwibm90QWZ0ZXIiOiIyMDIzLTA0LTA1VDEwOjI2OjU4LjU0NjQzM1oifQ",
  "signature": "rCscvD9WlSBAePIbgEXg6pRV_gZvgvPUhmX-4ZnUVwJFFj184fKUEg5Obn7SAyZsZ3HPadax24gn5JbPPZW_Dg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2023-04-05T10:26:58.546433Z",
    "notBefore": "2023-04-05T09:26:58.546433Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/wvYpqnUvADmOgk9Ln6TF6JPfQsrLx64T",
    "nonce": "d01NWDFVZzFnTDYxcTQzbzVnWHNvQ01CdGYwcVRqY3c",
    "typ": "JWT",
    "url": "https://stepca:55083/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl
replay-nonce: TGRxTnlVYlA1ZmJ1RWt6NmVKZExJeVNNSUtDM2RqakU
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55083/acme/wire/authz/gTUrdUl5urNJXYVwOkjNottmM912qbBY"
  ],
  "expires": "2023-04-06T09:26:58Z",
  "notBefore": "2023-04-05T09:26:58.546433Z",
  "notAfter": "2023-04-05T10:26:58.546433Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:55083/acme/wire/authz/gTUrdUl5urNJXYVwOkjNottmM912qbBY
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L3d2WXBxblV2QURtT2drOUxuNlRGNkpQZlFzckx4NjRUIiwidHlwIjoiSldUIiwibm9uY2UiOiJUR1J4VG5sVllsQTFabUoxUld0Nk5tVktaRXhKZVZOTlNVdERNMlJxYWtVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL2F1dGh6L2dUVXJkVWw1dXJOSlhZVndPa2pOb3R0bU05MTJxYkJZIn0",
  "payload": "",
  "signature": "jhtFd1fFkvdWbhApOmmz71D9KF3WEOkewfPPGm5yehc3N3VaBd46nOXVoBEWixiDZYQok2IX41jPFoewgUrHBA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/wvYpqnUvADmOgk9Ln6TF6JPfQsrLx64T",
    "nonce": "TGRxTnlVYlA1ZmJ1RWt6NmVKZExJeVNNSUtDM2RqakU",
    "typ": "JWT",
    "url": "https://stepca:55083/acme/wire/authz/gTUrdUl5urNJXYVwOkjNottmM912qbBY"
  }
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/authz/gTUrdUl5urNJXYVwOkjNottmM912qbBY
replay-nonce: RzQ2b0NTbElQOFJlZEJwTjB2U2lVQWVEQlg2TGY0OEk
```
```json
{
  "status": "pending",
  "expires": "2023-04-06T09:26:58Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/MmKxzFq9FtmE8pMpJv4LSLw6614DazdA",
      "status": "pending",
      "token": "4felRbxFi0JiHVCOz1xmxyVbOqSLzKZT"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/WZUHEg5Ts9MIO34qHCpZjWd3GCWR0am5",
      "status": "pending",
      "token": "4felRbxFi0JiHVCOz1xmxyVbOqSLzKZT"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:20083/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
UUgxQU01RXdlTTNIYlA0dlRwdHU4ZjE1R2ZFeHNTbE0
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiYk5zVmNlVGFlQlFha0ZqTnBzUUMwTWtoNTl0ZlhfQU5SSU1sc1F2LWNrMCJ9fQ.eyJpYXQiOjE2ODA2ODY4MTgsImV4cCI6MTY4MDY5MDQxOCwibmJmIjoxNjgwNjg2ODE4LCJzdWIiOiJpbTp3aXJlYXBwPU5qaGxNekl4T1dGak9EUmlOREF3WWprMFpHRmhaREEyTnpFeE5URXlOVGcvNmMxODY2ZjU2NzYxNmYzMUB3aXJlLmNvbSIsImp0aSI6ImU4ZWYxNDY4LWM5NDYtNDJjOS05MjIxLTlkNDQxYzliMjM0NyIsIm5vbmNlIjoiVVVneFFVMDFSWGRsVFROSVlsQTBkbFJ3ZEhVNFpqRTFSMlpGZUhOVGJFMCIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjAwODMvIiwiY2hhbCI6IjRmZWxSYnhGaTBKaUhWQ096MXhteHlWYk9xU0x6S1pUIn0.cCj54OkD8cicoalVrgsPpTQLNlvixOk1S4B8d9oziCKfQsd4PdZUItkrxn_jHNsHpeTMh09GMIY2sY7rhe6vBA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiYk5zVmNlVGFlQlFha0ZqTnBzUUMwTWto
NTl0ZlhfQU5SSU1sc1F2LWNrMCJ9fQ.eyJpYXQiOjE2ODA2ODY4MTgsImV4cCI6M
TY4MDY5MDQxOCwibmJmIjoxNjgwNjg2ODE4LCJzdWIiOiJpbTp3aXJlYXBwPU5qa
GxNekl4T1dGak9EUmlOREF3WWprMFpHRmhaREEyTnpFeE5URXlOVGcvNmMxODY2Z
jU2NzYxNmYzMUB3aXJlLmNvbSIsImp0aSI6ImU4ZWYxNDY4LWM5NDYtNDJjOS05M
jIxLTlkNDQxYzliMjM0NyIsIm5vbmNlIjoiVVVneFFVMDFSWGRsVFROSVlsQTBkb
FJ3ZEhVNFpqRTFSMlpGZUhOVGJFMCIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MjAwODMvIiwiY2hhbCI6IjRmZWxSYnhGaTBKaUhWQ096MXhte
HlWYk9xU0x6S1pUIn0.cCj54OkD8cicoalVrgsPpTQLNlvixOk1S4B8d9oziCKfQ
sd4PdZUItkrxn_jHNsHpeTMh09GMIY2sY7rhe6vBA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "bNsVceTaeBQakFjNpsQC0Mkh59tfX_ANRIMlsQv-ck0"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "4felRbxFi0JiHVCOz1xmxyVbOqSLzKZT",
  "exp": 1680690418,
  "htm": "POST",
  "htu": "http://wire.com:20083/",
  "iat": 1680686818,
  "jti": "e8ef1468-c946-42c9-9221-9d441c9b2347",
  "nbf": 1680686818,
  "nonce": "UUgxQU01RXdlTTNIYlA0dlRwdHU4ZjE1R2ZFeHNTbE0",
  "sub": "im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICSvjrNiooyuHTYcNpHNr//GcjY4dj5B1R29bZ0lTMss
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAbNsVceTaeBQakFjNpsQC0Mkh59tfX/ANRIMlsQv+ck0=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:20083/clients/7789088759724732209/access-token
                          /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pWWs1elZtTmxWR0ZsUWxGaGEwWnFUbkJ6VVVNd1RXdG9OVGwwWmxoZlFVNVNTVTFzYzFGMkxXTnJNQ0o5ZlEuZXlKcFlYUWlPakUyT0RBMk9EWTRNVGdzSW1WNGNDSTZNVFk0TURZNU1EUXhPQ3dpYm1KbUlqb3hOamd3TmpnMk9ERTRMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltVTRaV1l4TkRZNExXTTVORFl0TkRKak9TMDVNakl4TFRsa05EUXhZemxpTWpNME55SXNJbTV2Ym1ObElqb2lWVlZuZUZGVk1ERlNXR1JzVkZST1NWbHNRVEJrYkZKM1pFaFZORnBxUlRGU01scEdaVWhPVkdKRk1DSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakF3T0RNdklpd2lZMmhoYkNJNklqUm1aV3hTWW5oR2FUQkthVWhXUTA5Nk1YaHRlSGxXWWs5eFUweDZTMXBVSW4wLmNDajU0T2tEOGNpY29hbFZyZ3NQcFRRTE5sdml4T2sxUzRCOGQ5b3ppQ0tmUXNkNFBkWlVJdGtyeG5fakhOc0hwZVRNaDA5R01JWTJzWTdyaGU2dkJB
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkJQZWNmT2V1dUc3UUQ4M1YwaEZpY1Qta2Q0bC1hdEZJU2ttaGVtZHQyNVkifX0.eyJpYXQiOjE2ODA2ODY4MTgsImV4cCI6MTY4ODQ2MjgxOCwibmJmIjoxNjgwNjg2ODE4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjAwODMvIiwic3ViIjoiaW06d2lyZWFwcD1OamhsTXpJeE9XRmpPRFJpTkRBd1lqazBaR0ZoWkRBMk56RXhOVEV5TlRnLzZjMTg2NmY1Njc2MTZmMzFAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAwODMvIiwianRpIjoiNjNjNzBlNGEtZDZlMy00ZDllLThhMTQtMDg3MzgxMTM2MDZkIiwibm9uY2UiOiJVVWd4UVUwMVJYZGxUVE5JWWxBMGRsUndkSFU0WmpFMVIyWkZlSE5UYkUwIiwiY2hhbCI6IjRmZWxSYnhGaTBKaUhWQ096MXhteHlWYk9xU0x6S1pUIiwiY25mIjp7ImtpZCI6ImtWSHc0ODlUNWVmdUlheWZWUmpxWTZkbC1vX3h1NkxKNE9tX0NwSHlyTDQifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lZazV6Vm1ObFZHRmxRbEZoYTBacVRuQnpVVU13VFd0b05UbDBabGhmUVU1U1NVMXNjMUYyTFdOck1DSjlmUS5leUpwWVhRaU9qRTJPREEyT0RZNE1UZ3NJbVY0Y0NJNk1UWTRNRFk1TURReE9Dd2libUptSWpveE5qZ3dOamcyT0RFNExDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BVNXFhR3hOZWtsNFQxZEdhazlFVW1sT1JFRjNXV3ByTUZwSFJtaGFSRUV5VG5wRmVFNVVSWGxPVkdjdk5tTXhPRFkyWmpVMk56WXhObVl6TVVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VNFpXWXhORFk0TFdNNU5EWXROREpqT1MwNU1qSXhMVGxrTkRReFl6bGlNak0wTnlJc0ltNXZibU5sSWpvaVZWVm5lRkZWTURGU1dHUnNWRlJPU1Zsc1FUQmtiRkozWkVoVk5GcHFSVEZTTWxwR1pVaE9WR0pGTUNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQXdPRE12SWl3aVkyaGhiQ0k2SWpSbVpXeFNZbmhHYVRCS2FVaFdRMDk2TVhodGVIbFdZazl4VTB4NlMxcFVJbjAuY0NqNTRPa0Q4Y2ljb2FsVnJnc1BwVFFMTmx2aXhPazFTNEI4ZDlvemlDS2ZRc2Q0UGRaVUl0a3J4bl9qSE5zSHBlVE1oMDlHTUlZMnNZN3JoZTZ2QkEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5qaGxNekl4T1dGak9EUmlOREF3WWprMFpHRmhaREEyTnpFeE5URXlOVGcvNmMxODY2ZjU2NzYxNmYzMUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.3Udw8z6aJu_C0Fcyup48rHzQEFklHBVHDx95Q5MzST3LiIVpMcbnUK6cK0iyvEZCvBP7Y54GFoS1EhxdMq-bBw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkJQZWNmT2V1dUc3UUQ4M1YwaEZpY1Qta2Q0bC1hdEZJU2ttaGVtZHQyNVkifX0.eyJpYXQiOjE2ODA2ODY4MTgsImV4cCI6MTY4ODQ2MjgxOCwibmJmIjoxNjgwNjg2ODE4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjAwODMvIiwic3ViIjoiaW06d2lyZWFwcD1OamhsTXpJeE9XRmpPRFJpTkRBd1lqazBaR0ZoWkRBMk56RXhOVEV5TlRnLzZjMTg2NmY1Njc2MTZmMzFAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAwODMvIiwianRpIjoiNjNjNzBlNGEtZDZlMy00ZDllLThhMTQtMDg3MzgxMTM2MDZkIiwibm9uY2UiOiJVVWd4UVUwMVJYZGxUVE5JWWxBMGRsUndkSFU0WmpFMVIyWkZlSE5UYkUwIiwiY2hhbCI6IjRmZWxSYnhGaTBKaUhWQ096MXhteHlWYk9xU0x6S1pUIiwiY25mIjp7ImtpZCI6ImtWSHc0ODlUNWVmdUlheWZWUmpxWTZkbC1vX3h1NkxKNE9tX0NwSHlyTDQifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lZazV6Vm1ObFZHRmxRbEZoYTBacVRuQnpVVU13VFd0b05UbDBabGhmUVU1U1NVMXNjMUYyTFdOck1DSjlmUS5leUpwWVhRaU9qRTJPREEyT0RZNE1UZ3NJbVY0Y0NJNk1UWTRNRFk1TURReE9Dd2libUptSWpveE5qZ3dOamcyT0RFNExDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BVNXFhR3hOZWtsNFQxZEdhazlFVW1sT1JFRjNXV3ByTUZwSFJtaGFSRUV5VG5wRmVFNVVSWGxPVkdjdk5tTXhPRFkyWmpVMk56WXhObVl6TVVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VNFpXWXhORFk0TFdNNU5EWXROREpqT1MwNU1qSXhMVGxrTkRReFl6bGlNak0wTnlJc0ltNXZibU5sSWpvaVZWVm5lRkZWTURGU1dHUnNWRlJPU1Zsc1FUQmtiRkozWkVoVk5GcHFSVEZTTWxwR1pVaE9WR0pGTUNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQXdPRE12SWl3aVkyaGhiQ0k2SWpSbVpXeFNZbmhHYVRCS2FVaFdRMDk2TVhodGVIbFdZazl4VTB4NlMxcFVJbjAuY0NqNTRPa0Q4Y2ljb2FsVnJnc1BwVFFMTmx2aXhPazFTNEI4ZDlvemlDS2ZRc2Q0UGRaVUl0a3J4bl9qSE5zSHBlVE1oMDlHTUlZMnNZN3JoZTZ2QkEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5qaGxNekl4T1dGak9EUmlOREF3WWprMFpHRmhaREEyTnpFeE5URXlOVGcvNmMxODY2ZjU2NzYxNmYzMUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.3Udw8z6aJu_C0Fcyup48rHzQEFklHBVHDx95Q5MzST3LiIVpMcbnUK6cK0iyvEZCvBP7Y54GFoS1EhxdMq-bBw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IkJQZWNmT2V1dUc3UUQ4M1YwaEZpY1Qta2Q0
bC1hdEZJU2ttaGVtZHQyNVkifX0.eyJpYXQiOjE2ODA2ODY4MTgsImV4cCI6MTY4
ODQ2MjgxOCwibmJmIjoxNjgwNjg2ODE4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjAwODMvIiwic3ViIjoiaW06d2lyZWFwcD1OamhsTXpJeE9XRmpPRFJpTkRBd1lq
azBaR0ZoWkRBMk56RXhOVEV5TlRnLzZjMTg2NmY1Njc2MTZmMzFAd2lyZS5jb20i
LCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAwODMvIiwianRpIjoiNjNjNzBlNGEt
ZDZlMy00ZDllLThhMTQtMDg3MzgxMTM2MDZkIiwibm9uY2UiOiJVVWd4UVUwMVJY
ZGxUVE5JWWxBMGRsUndkSFU0WmpFMVIyWkZlSE5UYkUwIiwiY2hhbCI6IjRmZWxS
YnhGaTBKaUhWQ096MXhteHlWYk9xU0x6S1pUIiwiY25mIjp7ImtpZCI6ImtWSHc0
ODlUNWVmdUlheWZWUmpxWTZkbC1vX3h1NkxKNE9tX0NwSHlyTDQifSwicHJvb2Yi
OiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFu
ZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElq
b2lZazV6Vm1ObFZHRmxRbEZoYTBacVRuQnpVVU13VFd0b05UbDBabGhmUVU1U1NV
MXNjMUYyTFdOck1DSjlmUS5leUpwWVhRaU9qRTJPREEyT0RZNE1UZ3NJbVY0Y0NJ
Nk1UWTRNRFk1TURReE9Dd2libUptSWpveE5qZ3dOamcyT0RFNExDSnpkV0lpT2lK
cGJUcDNhWEpsWVhCd1BVNXFhR3hOZWtsNFQxZEdhazlFVW1sT1JFRjNXV3ByTUZw
SFJtaGFSRUV5VG5wRmVFNVVSWGxPVkdjdk5tTXhPRFkyWmpVMk56WXhObVl6TVVC
M2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VNFpXWXhORFk0TFdNNU5EWXROREpqT1Mw
NU1qSXhMVGxrTkRReFl6bGlNak0wTnlJc0ltNXZibU5sSWpvaVZWVm5lRkZWTURG
U1dHUnNWRlJPU1Zsc1FUQmtiRkozWkVoVk5GcHFSVEZTTWxwR1pVaE9WR0pGTUNJ
c0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIw
Nk1qQXdPRE12SWl3aVkyaGhiQ0k2SWpSbVpXeFNZbmhHYVRCS2FVaFdRMDk2TVho
dGVIbFdZazl4VTB4NlMxcFVJbjAuY0NqNTRPa0Q4Y2ljb2FsVnJnc1BwVFFMTmx2
aXhPazFTNEI4ZDlvemlDS2ZRc2Q0UGRaVUl0a3J4bl9qSE5zSHBlVE1oMDlHTUlZ
MnNZN3JoZTZ2QkEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5qaGxNekl4T1dG
ak9EUmlOREF3WWprMFpHRmhaREEyTnpFeE5URXlOVGcvNmMxODY2ZjU2NzYxNmYz
MUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50
X2lkIn0.3Udw8z6aJu_C0Fcyup48rHzQEFklHBVHDx95Q5MzST3LiIVpMcbnUK6c
K0iyvEZCvBP7Y54GFoS1EhxdMq-bBw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "BPecfOeuuG7QD83V0hFicT-kd4l-atFISkmhemdt25Y"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:20083/",
  "chal": "4felRbxFi0JiHVCOz1xmxyVbOqSLzKZT",
  "client_id": "im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com",
  "cnf": {
    "kid": "kVHw489T5efuIayfVRjqY6dl-o_xu6LJ4Om_CpHyrL4"
  },
  "exp": 1688462818,
  "iat": 1680686818,
  "iss": "http://wire.com:20083/",
  "jti": "63c70e4a-d6e3-4d9e-8a14-08738113606d",
  "nbf": 1680686818,
  "nonce": "UUgxQU01RXdlTTNIYlA0dlRwdHU4ZjE1R2ZFeHNTbE0",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiYk5zVmNlVGFlQlFha0ZqTnBzUUMwTWtoNTl0ZlhfQU5SSU1sc1F2LWNrMCJ9fQ.eyJpYXQiOjE2ODA2ODY4MTgsImV4cCI6MTY4MDY5MDQxOCwibmJmIjoxNjgwNjg2ODE4LCJzdWIiOiJpbTp3aXJlYXBwPU5qaGxNekl4T1dGak9EUmlOREF3WWprMFpHRmhaREEyTnpFeE5URXlOVGcvNmMxODY2ZjU2NzYxNmYzMUB3aXJlLmNvbSIsImp0aSI6ImU4ZWYxNDY4LWM5NDYtNDJjOS05MjIxLTlkNDQxYzliMjM0NyIsIm5vbmNlIjoiVVVneFFVMDFSWGRsVFROSVlsQTBkbFJ3ZEhVNFpqRTFSMlpGZUhOVGJFMCIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjAwODMvIiwiY2hhbCI6IjRmZWxSYnhGaTBKaUhWQ096MXhteHlWYk9xU0x6S1pUIn0.cCj54OkD8cicoalVrgsPpTQLNlvixOk1S4B8d9oziCKfQsd4PdZUItkrxn_jHNsHpeTMh09GMIY2sY7rhe6vBA",
  "scope": "wire_client_id",
  "sub": "im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGM/3yMztAR0ScOVndUiUEftbBM9wQayZiM68zCORmI5
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEABPecfOeuuG7QD83V0hFicT+kd4l+atFISkmhemdt25Y=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/WZUHEg5Ts9MIO34qHCpZjWd3GCWR0am5
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L3d2WXBxblV2QURtT2drOUxuNlRGNkpQZlFzckx4NjRUIiwidHlwIjoiSldUIiwibm9uY2UiOiJSelEyYjBOVGJFbFFPRkpsWkVKd1RqQjJVMmxWUVdWRVFsZzJUR1kwT0VrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL2NoYWxsZW5nZS9nVFVyZFVsNXVyTkpYWVZ3T2tqTm90dG1NOTEycWJCWS9XWlVIRWc1VHM5TUlPMzRxSENwWmpXZDNHQ1dSMGFtNSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrSlFaV05tVDJWMWRVYzNVVVE0TTFZd2FFWnBZMVF0YTJRMGJDMWhkRVpKVTJ0dGFHVnRaSFF5TlZraWZYMC5leUpwWVhRaU9qRTJPREEyT0RZNE1UZ3NJbVY0Y0NJNk1UWTRPRFEyTWpneE9Dd2libUptSWpveE5qZ3dOamcyT0RFNExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpBd09ETXZJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFPYW1oc1RYcEplRTlYUm1wUFJGSnBUa1JCZDFscWF6QmFSMFpvV2tSQk1rNTZSWGhPVkVWNVRsUm5MelpqTVRnMk5tWTFOamMyTVRabU16RkFkMmx5WlM1amIyMGlMQ0poZFdRaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQXdPRE12SWl3aWFuUnBJam9pTmpOak56QmxOR0V0WkRabE15MDBaRGxsTFRoaE1UUXRNRGczTXpneE1UTTJNRFprSWl3aWJtOXVZMlVpT2lKVlZXZDRVVlV3TVZKWVpHeFVWRTVKV1d4Qk1HUnNVbmRrU0ZVMFdtcEZNVkl5V2tabFNFNVVZa1V3SWl3aVkyaGhiQ0k2SWpSbVpXeFNZbmhHYVRCS2FVaFdRMDk2TVhodGVIbFdZazl4VTB4NlMxcFVJaXdpWTI1bUlqcDdJbXRwWkNJNkltdFdTSGMwT0RsVU5XVm1kVWxoZVdaV1VtcHhXVFprYkMxdlgzaDFOa3hLTkU5dFgwTndTSGx5VERRaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsWmF6VjZWbTFPYkZaSFJteFJiRVpvWVRCYWNWUnVRbnBWVlUxM1ZGZDBiMDVVYkRCYWJHaG1VVlUxVTFOVk1YTmpNVVl5VEZkT2NrMURTamxtVVM1bGVVcHdXVmhSYVU5cVJUSlBSRUV5VDBSWk5FMVVaM05KYlZZMFkwTkpOazFVV1RSTlJGazFUVVJSZUU5RGQybGliVXB0U1dwdmVFNXFaM2RPYW1jeVQwUkZORXhEU25wa1YwbHBUMmxLY0dKVWNETmhXRXBzV1ZoQ2QxQlZOWEZoUjNoT1pXdHNORlF4WkVkaGF6bEZWVzFzVDFKRlJqTlhWM0J5VFVad1NGSnRhR0ZTUlVWNVZHNXdSbVZGTlZWU1dHeFBWa2RqZGs1dFRYaFBSRmt5V21wVk1rNTZXWGhPYlZsNlRWVkNNMkZZU214TWJVNTJZbE5KYzBsdGNEQmhVMGsyU1cxVk5GcFhXWGhPUkZrMFRGZE5OVTVFV1hST1JFcHFUMU13TlUxcVNYaE1WR3hyVGtSUmVGbDZiR2xOYWswd1RubEpjMGx0TlhaaWJVNXNTV3B2YVZaV1ZtNWxSa1pXVFVSR1UxZEhVbk5XUmxKUFUxWnNjMUZVUW10aVJrb3pXa1ZvVms1R2NIRlNWRVpUVFd4d1IxcFZhRTlXUjBwR1RVTkpjMGx0YURCaVUwazJTV3hDVUZVeFVXbE1RMHB2WkVoVmFVOXBTbTlrU0ZKM1QyazRkbVF5YkhsYVV6VnFZakl3TmsxcVFYZFBSRTEyU1dsM2FWa3lhR2hpUTBrMlNXcFNiVnBYZUZOWmJtaEhZVlJDUzJGVmFGZFJNRGsyVFZob2RHVkliRmRaYXpsNFZUQjRObE14Y0ZWSmJqQXVZME5xTlRSUGEwUTRZMmxqYjJGc1ZuSm5jMUJ3VkZGTVRteDJhWGhQYXpGVE5FSTRaRGx2ZW1sRFMyWlJjMlEwVUdSYVZVbDBhM0o0Ymw5cVNFNXpTSEJsVkUxb01EbEhUVWxaTW5OWk4zSm9aVFoyUWtFaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFU1cWFHeE5la2w0VDFkR2FrOUVVbWxPUkVGM1dXcHJNRnBIUm1oYVJFRXlUbnBGZUU1VVJYbE9WR2N2Tm1NeE9EWTJaalUyTnpZeE5tWXpNVUIzYVhKbExtTnZiU0lzSW1Gd2FWOTJaWEp6YVc5dUlqb3pMQ0p6WTI5d1pTSTZJbmRwY21WZlkyeHBaVzUwWDJsa0luMC4zVWR3OHo2YUp1X0MwRmN5dXA0OHJIelFFRmtsSEJWSER4OTVRNU16U1QzTGlJVnBNY2JuVUs2Y0swaXl2RVpDdkJQN1k1NEdGb1MxRWh4ZE1xLWJCdyJ9",
  "signature": "-nI5A3_qZlwOs1BN1BhVRI56fmfLvSPErsgA2LeHdjkzRuFRl8aMeRqGJsG0aMuRnUbqgxSCIB0G4HYnJXA0DA"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkJQZWNmT2V1dUc3UUQ4M1YwaEZpY1Qta2Q0bC1hdEZJU2ttaGVtZHQyNVkifX0.eyJpYXQiOjE2ODA2ODY4MTgsImV4cCI6MTY4ODQ2MjgxOCwibmJmIjoxNjgwNjg2ODE4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjAwODMvIiwic3ViIjoiaW06d2lyZWFwcD1OamhsTXpJeE9XRmpPRFJpTkRBd1lqazBaR0ZoWkRBMk56RXhOVEV5TlRnLzZjMTg2NmY1Njc2MTZmMzFAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAwODMvIiwianRpIjoiNjNjNzBlNGEtZDZlMy00ZDllLThhMTQtMDg3MzgxMTM2MDZkIiwibm9uY2UiOiJVVWd4UVUwMVJYZGxUVE5JWWxBMGRsUndkSFU0WmpFMVIyWkZlSE5UYkUwIiwiY2hhbCI6IjRmZWxSYnhGaTBKaUhWQ096MXhteHlWYk9xU0x6S1pUIiwiY25mIjp7ImtpZCI6ImtWSHc0ODlUNWVmdUlheWZWUmpxWTZkbC1vX3h1NkxKNE9tX0NwSHlyTDQifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lZazV6Vm1ObFZHRmxRbEZoYTBacVRuQnpVVU13VFd0b05UbDBabGhmUVU1U1NVMXNjMUYyTFdOck1DSjlmUS5leUpwWVhRaU9qRTJPREEyT0RZNE1UZ3NJbVY0Y0NJNk1UWTRNRFk1TURReE9Dd2libUptSWpveE5qZ3dOamcyT0RFNExDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BVNXFhR3hOZWtsNFQxZEdhazlFVW1sT1JFRjNXV3ByTUZwSFJtaGFSRUV5VG5wRmVFNVVSWGxPVkdjdk5tTXhPRFkyWmpVMk56WXhObVl6TVVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VNFpXWXhORFk0TFdNNU5EWXROREpqT1MwNU1qSXhMVGxrTkRReFl6bGlNak0wTnlJc0ltNXZibU5sSWpvaVZWVm5lRkZWTURGU1dHUnNWRlJPU1Zsc1FUQmtiRkozWkVoVk5GcHFSVEZTTWxwR1pVaE9WR0pGTUNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQXdPRE12SWl3aVkyaGhiQ0k2SWpSbVpXeFNZbmhHYVRCS2FVaFdRMDk2TVhodGVIbFdZazl4VTB4NlMxcFVJbjAuY0NqNTRPa0Q4Y2ljb2FsVnJnc1BwVFFMTmx2aXhPazFTNEI4ZDlvemlDS2ZRc2Q0UGRaVUl0a3J4bl9qSE5zSHBlVE1oMDlHTUlZMnNZN3JoZTZ2QkEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5qaGxNekl4T1dGak9EUmlOREF3WWprMFpHRmhaREEyTnpFeE5URXlOVGcvNmMxODY2ZjU2NzYxNmYzMUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.3Udw8z6aJu_C0Fcyup48rHzQEFklHBVHDx95Q5MzST3LiIVpMcbnUK6cK0iyvEZCvBP7Y54GFoS1EhxdMq-bBw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/wvYpqnUvADmOgk9Ln6TF6JPfQsrLx64T",
    "nonce": "RzQ2b0NTbElQOFJlZEJwTjB2U2lVQWVEQlg2TGY0OEk",
    "typ": "JWT",
    "url": "https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/WZUHEg5Ts9MIO34qHCpZjWd3GCWR0am5"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
link: <https://stepca:55083/acme/wire/authz/gTUrdUl5urNJXYVwOkjNottmM912qbBY>;rel="up"
location: https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/WZUHEg5Ts9MIO34qHCpZjWd3GCWR0am5
replay-nonce: c08wTE5ZaDllcm1oZ25uYXU0QmlZR2J1UEdvbTF0QTI
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/WZUHEg5Ts9MIO34qHCpZjWd3GCWR0am5",
  "status": "valid",
  "token": "4felRbxFi0JiHVCOz1xmxyVbOqSLzKZT"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. Client clicks login button
```http request
GET http://wire.com:20083/login
```
#### 19. Resource server generates Verifier & Challenge Codes

```text
code_verifier=rLzC_iEaBJ4LJmq0u1B7oI8BDmWqNRWQPPRp6mq3-yg&code_challenge=OFQ2RG7O5Hc8dEzD0QLmxXIRsvJw_nzG_EQHGoyYWlo
```
#### 20. Resource server calls authorize url

#### 21. Authorization server redirects to login prompt

```text
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <title>dex</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="../../static/main.css" rel="stylesheet">
    <link href="../../theme/styles.css" rel="stylesheet">
    <link rel="icon" href="../../theme/favicon.png">
  </head>

  <body class="theme-body">
    <div class="theme-navbar">
      <div class="theme-navbar__logo-wrap">
        <img class="theme-navbar__logo" src="../../theme/logo.png">
      </div>
    </div>

    <div class="dex-container">


<div class="theme-panel">
  <h2 class="theme-heading">Log in to Your Account</h2>
  <form method="post" action="/dex/auth/ldap/login?back=&amp;state=mell7g7s6ab2lwvjkqobrwzc3">
    <div class="theme-form-row">
      <div class="theme-form-label">
        <label for="userid">Email Address</label>
      </div>
	  <input tabindex="1" required id="login" name="login" type="text" class="theme-form-input" placeholder="email address"  autofocus />
    </div>
    <div class="theme-form-row">
      <div class="theme-form-label">
        <label for="password">Password</label>
      </div>
	  <input tabindex="2" required id="password" name="password" type="password" class="theme-form-input" placeholder="password" />
    </div>

    

    <button tabindex="3" id="submit-login" type="submit" class="dex-btn theme-btn--primary">Login</button>

  </form>
  
</div>

    </div>
  </body>
</html>


```
#### 22. Client submits the login form
```http request
POST http://dex:16238/dex/auth/ldap/login?back=&state=mell7g7s6ab2lwvjkqobrwzc3
content-type: application/x-www-form-urlencoded
```
```text
password=foo&login=alicesmith%40wire.com
```
#### 23. Authorization Server presents consent form to client
```http request
200
content-type: text/html; charset=utf-8
```
```text
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <title>dex</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="static/main.css" rel="stylesheet">
    <link href="theme/styles.css" rel="stylesheet">
    <link rel="icon" href="theme/favicon.png">
  </head>

  <body class="theme-body">
    <div class="theme-navbar">
      <div class="theme-navbar__logo-wrap">
        <img class="theme-navbar__logo" src="theme/logo.png">
      </div>
    </div>

    <div class="dex-container">


<div class="theme-panel">
  <h2 class="theme-heading">Grant Access</h2>

  <hr class="dex-separator">
  <div>
    
    <div class="dex-subtle-text">Example App would like to:</div>
    <ul class="dex-list">
      
      <li>View basic profile information</li>
      
    </ul>
    
  </div>
  <hr class="dex-separator">

  <div>
    <div class="theme-form-row">
      <form method="post">
        <input type="hidden" name="req" value="mell7g7s6ab2lwvjkqobrwzc3"/>
        <input type="hidden" name="approval" value="approve">
        <button type="submit" class="dex-btn theme-btn--success">
            <span class="dex-btn-text">Grant Access</span>
        </button>
      </form>
    </div>
    <div class="theme-form-row">
      <form method="post">
        <input type="hidden" name="req" value="mell7g7s6ab2lwvjkqobrwzc3"/>
        <input type="hidden" name="approval" value="rejected">
        <button type="submit" class="dex-btn theme-btn-provider">
            <span class="dex-btn-text">Cancel</span>
        </button>
      </form>
    </div>
  </div>

</div>

    </div>
  </body>
</html>


```
#### 24. Client submits consent form
```http request
POST http://dex:16238/dex/approval?req=mell7g7s6ab2lwvjkqobrwzc3&hmac=PfR3_Mh6zAHM8RFnpkH59EfkhKpqxc9Ks61q4FRnT4w
content-type: application/x-www-form-urlencoded
```
```text
req=mell7g7s6ab2lwvjkqobrwzc3&approval=approve
```
#### 25. Authorization server calls callback url with authorization code
```http request
GET http://wire.com/callback
accept: */*
referer: http://dex:16238/dex/approval?req=mell7g7s6ab2lwvjkqobrwzc3&hmac=PfR3_Mh6zAHM8RFnpkH59EfkhKpqxc9Ks61q4FRnT4w
host: wire.com:20083
```
#### 26. Resource server call /oauth/token to get Id token
```http request
POST http://dex:16238/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDphRWRKVDAxWFNqZzBXRFpNTUdKd04wcHRla2haTlZKbA==
```
```text
grant_type=authorization_code&code=qnj6xtpak7tvccnxvj2gn6yrk&code_verifier=rLzC_iEaBJ4LJmq0u1B7oI8BDmWqNRWQPPRp6mq3-yg&redirect_uri=http%3A%2F%2Fwire.com%3A20083%2Fcallback
```
#### 27. Authorization server validates Verifier & Challenge Codes

```text
code_verifier=rLzC_iEaBJ4LJmq0u1B7oI8BDmWqNRWQPPRp6mq3-yg&code_challenge=OFQ2RG7O5Hc8dEzD0QLmxXIRsvJw_nzG_EQHGoyYWlo
```
#### 28. Authorization server returns Access & Id token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiJ2bmtIZFlGT2FkaVFjVFZMUDRPaUxnIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.P4CuHAlLZgWUW7jKJMfKQnH-j0b94XZJswe93ts6bXrzMA1GsMipezqqxBt2qEUCdOaXLYp3j9IvLPsjJ2XPQ2sltL8Ro3xa15laat0qFtTtmkoSJgmbEPvp1i3NlaYiFDwbXHrXsA-95m_DY2aeLsRo8oqI6UIXpzF0XKCjDVgvqp-wn6HJa0yjO7xvIlPqSQjYl-uaa9F5hCpn0IAzxfaXyHNjLMRuFIR53o0W1VQy5lt6vEamekZkH4VeQBTrwlTERLO6ov3G7EwDQ-mUVqK9dCrd8FfyiZCZChrwOB4EzHX1FpKnPcfnGrb4MMnZYTmnKMY6Q1-5SaCjCtunyQ",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA",
  "token_type": "bearer"
}
```
#### 29. Resource server returns Id token to client

```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA
```
#### 30. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0
NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SR
UYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOe
ll4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNme
l9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCV
V93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZ
SBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FX
n5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl
3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosj
opzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0M
TQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyy
Ow8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "244a30157fa0312d64591ac88444906cd9866e54"
}
```

```json
{
  "at_hash": "9VyfLWJJnyTBXVmKh4BU_w",
  "aud": "wireapp",
  "c_hash": "m-qewK7tPtSOS6W7yW0zjw",
  "exp": 1680773218,
  "iat": 1680686818,
  "iss": "http://dex:16238/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "OKxqSfz_TJnXll5NZQqGfw",
  "preferred_username": "Alice Smith",
  "sub": "ClBpbTp3aXJlYXBwPU5qaGxNekl4T1dGak9EUmlOREF3WWprMFpHRmhaREEyTnpFeE5URXlOVGcvNmMxODY2ZjU2NzYxNmYzMUB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1s41e97DTyZN13sqt6J+
L4PjURI2UpNZRdeKgn7Hl6/2SY3Knrs9etWMnLGV91O3ZE+6b7kvAps7x9q4vsFQ
e0IHFACB2XUQ3SeDnVjXl31vkfcnE3lyueDqP+ErRuxfcNoj17OKxxuesle74A2R
3Ni3qe0btlUjrIcSwQGVmacmoNeAyvQ2xahoxycBGAwjWihyFISVnwBK2PZoMAxX
dcMGt5weo18QId4SB/kluRMat9aKzXc4qhVEa19/jeTh0Rc6u/5HfQn4UoWu4RfU
+XEtNBtNiS4wIQNyVXnRvTLCe2QSePmiNv5/jVr5qPBgHVuOgkPC6omUgJlH58rG
8wIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/MmKxzFq9FtmE8pMpJv4LSLw6614DazdA
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L3d2WXBxblV2QURtT2drOUxuNlRGNkpQZlFzckx4NjRUIiwidHlwIjoiSldUIiwibm9uY2UiOiJjMDh3VEU1WmFEbGxjbTFvWjI1dVlYVTBRbWxaUjJKMVVFZHZiVEYwUVRJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL2NoYWxsZW5nZS9nVFVyZFVsNXVyTkpYWVZ3T2tqTm90dG1NOTEycWJCWS9NbUt4ekZxOUZ0bUU4cE1wSnY0TFNMdzY2MTREYXpkQSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJakkwTkdFek1ERTFOMlpoTURNeE1tUTJORFU1TVdGak9EZzBORFE1TURaalpEazROalpsTlRRaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTJNak00TDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZUVnhZVWQ0VG1WcmJEUlVNV1JIWVdzNVJWVnRiRTlTUlVZelYxZHdjazFHY0VoU2JXaGhVa1ZGZVZSdWNFWmxSVFZWVWxoc1QxWkhZM1pPYlUxNFQwUlpNbHBxVlRKT2VsbDRUbTFaZWsxVlFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qZ3dOemN6TWpFNExDSnBZWFFpT2pFMk9EQTJPRFk0TVRnc0ltNXZibU5sSWpvaVQwdDRjVk5tZWw5VVNtNVliR3cxVGxwUmNVZG1keUlzSW1GMFgyaGhjMmdpT2lJNVZubG1URmRLU201NVZFSllWbTFMYURSQ1ZWOTNJaXdpWTE5b1lYTm9Jam9pYlMxeFpYZExOM1JRZEZOUFV6WlhOM2xYTUhwcWR5SXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObFgzZHBjbVVpTENKd2NtVm1aWEp5WldSZmRYTmxjbTVoYldVaU9pSkJiR2xqWlNCVGJXbDBhQ0o5LkFlbVU0dkdCc3pfN2otX0Z4Q1oxY2RNUGVqd2dJZ0RTN0JlaGFqSnllcWtBbmNRVktfRlhuNUs4WmhGcXFwUGJhQkI3WlZGOG1BQnE4cHdfUFBuWXRNMzZPOGtQZnh2NXk2bHhnaGxWNXZ2MGFpejQ5ZUdsM1lDZ1B2T0xLVkg3R29wNEo0S3l0eUZ5bHNGd3pIYkR1eTAtenp2X1RtOUt0SGplZHJMcmYxajliVlR0SG9zam9wekdOM2VBblZiM2F5WHJpdHpKdUlvZXEzYkdrbVhyeWtXY01XSmxWTmZRbDVjd1BvR000T0JNXzlFOGJaME1UUUhpNHNHMURpcF96aEVmdnRSWXRNX04wUkJSeVB5SmdXYlRiOTBheGw5RUtDemN3Q2hVRk5kck5fRERNVHl5T3c4VVZSQmh1cHZ0UzFmekdETVVuNHBpbkpxUGxLeElqQSIsImtleWF1dGgiOiI0ZmVsUmJ4RmkwSmlIVkNPejF4bXh5VmJPcVNMektaVC5XdFlzOEI5YjZvTkYyckM2NmNrLU5XblFlbDBZVEhvUXd3S0ZHSjR3U2NrIn0",
  "signature": "1FB5naDYBenXXPtgyAWjnss4KECwfW7UvhA3YZSPuL0IfPbuFy7EEbo-PdbCsHKyMqMnkbtg4Vjsxi_NaZHSDQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0NGEzMDE1N2ZhMDMxMmQ2NDU5MWFjODg0NDQ5MDZjZDk4NjZlNTQifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MjM4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVxYUd4TmVrbDRUMWRHYWs5RVVtbE9SRUYzV1dwck1GcEhSbWhhUkVFeVRucEZlRTVVUlhsT1ZHY3ZObU14T0RZMlpqVTJOell4Tm1Zek1VQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwNzczMjE4LCJpYXQiOjE2ODA2ODY4MTgsIm5vbmNlIjoiT0t4cVNmel9USm5YbGw1TlpRcUdmdyIsImF0X2hhc2giOiI5VnlmTFdKSm55VEJYVm1LaDRCVV93IiwiY19oYXNoIjoibS1xZXdLN3RQdFNPUzZXN3lXMHpqdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.AemU4vGBsz_7j-_FxCZ1cdMPejwgIgDS7BehajJyeqkAncQVK_FXn5K8ZhFqqpPbaBB7ZVF8mABq8pw_PPnYtM36O8kPfxv5y6lxghlV5vv0aiz49eGl3YCgPvOLKVH7Gop4J4KytyFylsFwzHbDuy0-zzv_Tm9KtHjedrLrf1j9bVTtHosjopzGN3eAnVb3ayXritzJuIoeq3bGkmXrykWcMWJlVNfQl5cwPoGM4OBM_9E8bZ0MTQHi4sG1Dip_zhEfvtRYtM_N0RBRyPyJgWbTb90axl9EKCzcwChUFNdrN_DDMTyyOw8UVRBhupvtS1fzGDMUn4pinJqPlKxIjA",
    "keyauth": "4felRbxFi0JiHVCOz1xmxyVbOqSLzKZT.WtYs8B9b6oNF2rC66ck-NWnQel0YTHoQwwKFGJ4wSck"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/wvYpqnUvADmOgk9Ln6TF6JPfQsrLx64T",
    "nonce": "c08wTE5ZaDllcm1oZ25uYXU0QmlZR2J1UEdvbTF0QTI",
    "typ": "JWT",
    "url": "https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/MmKxzFq9FtmE8pMpJv4LSLw6614DazdA"
  }
}
```
#### 31. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
link: <https://stepca:55083/acme/wire/authz/gTUrdUl5urNJXYVwOkjNottmM912qbBY>;rel="up"
location: https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/MmKxzFq9FtmE8pMpJv4LSLw6614DazdA
replay-nonce: bTZyclVyVndvcldlMldLZHU5cTg4VjdhOEFlMlF1Qms
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:55083/acme/wire/challenge/gTUrdUl5urNJXYVwOkjNottmM912qbBY/MmKxzFq9FtmE8pMpJv4LSLw6614DazdA",
  "status": "valid",
  "token": "4felRbxFi0JiHVCOz1xmxyVbOqSLzKZT"
}
```
### Client presents a CSR and gets its certificate
#### 32. verify the status of the order
```http request
POST https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L3d2WXBxblV2QURtT2drOUxuNlRGNkpQZlFzckx4NjRUIiwidHlwIjoiSldUIiwibm9uY2UiOiJiVFp5Y2xWeVZuZHZjbGRsTWxkTFpIVTVjVGc0VmpkaE9FRmxNbEYxUW1zIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL29yZGVyL0lkQzFwaGx6QXI5Y0dIQnZIcGtVN0VCc25JTnBFRE9sIn0",
  "payload": "",
  "signature": "yaE5k4gjRUwPROC7yzqpjNubZg8I2LOXPqEDyJIF5_XduKQlucvkIoxms0pBpRnvQyjFdP85hCJLFDNVe7CRCA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/wvYpqnUvADmOgk9Ln6TF6JPfQsrLx64T",
    "nonce": "bTZyclVyVndvcldlMldLZHU5cTg4VjdhOEFlMlF1Qms",
    "typ": "JWT",
    "url": "https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl"
  }
}
```
#### 33. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl
replay-nonce: a0JXTU8xclpDNWRNVlpZYzJuQkIzZ2xqMWJWMzZPbmw
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55083/acme/wire/authz/gTUrdUl5urNJXYVwOkjNottmM912qbBY"
  ],
  "expires": "2023-04-06T09:26:58Z",
  "notBefore": "2023-04-05T09:26:58.546433Z",
  "notAfter": "2023-04-05T10:26:58.546433Z"
}
```
#### 34. create a CSR and call finalize url
```http request
POST https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L3d2WXBxblV2QURtT2drOUxuNlRGNkpQZlFzckx4NjRUIiwidHlwIjoiSldUIiwibm9uY2UiOiJhMEpYVFU4eGNscEROV1JOVmxwWll6SnVRa0l6WjJ4cU1XSldNelpQYm13IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL29yZGVyL0lkQzFwaGx6QXI5Y0dIQnZIcGtVN0VCc25JTnBFRE9sL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCT0RDQjZ3SUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBR3piRlhIazJuZ1VHcEJZemFiRUF0REpJZWZiWDFfd0RVU0RKYkVMX25KTm9JR0dNSUdEQmdrcWhraUc5dzBCQ1E0eGRqQjBNSElHQTFVZEVRUnJNR21HVUdsdE9uZHBjbVZoY0hBOVRtcG9iRTE2U1hoUFYwWnFUMFJTYVU1RVFYZFphbXN3V2tkR2FGcEVRVEpPZWtWNFRsUkZlVTVVWnk4Mll6RTROalptTlRZM05qRTJaak14UUhkcGNtVXVZMjl0aGhWcGJUcDNhWEpsWVhCd1BXRnNhV05sWDNkcGNtVXdCUVlESzJWd0EwRUEtRllKZkh1ZjE1YVpZUXVRekN2THE3dldna0t0a1VOVFJPNkRLc1hpY3VtbEJicXdSQmc2OTkydFV4cUdFV1FlWUZLRldJbENiRDZEd3FvVjgwSVFBQSJ9",
  "signature": "MS0KGc-kgK657jIHfeecYj3TX_mQyEilvsQzDt_GV27FEI9BKSUUw5kcQMzZBFEJbMcPy664ADUbgWqtKiP0Bg"
}
```
```json
{
  "payload": {
    "csr": "MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGzbFXHk2ngUGpBYzabEAtDJIefbX1_wDUSDJbEL_nJNoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndpcmVhcHA9TmpobE16SXhPV0ZqT0RSaU5EQXdZamswWkdGaFpEQTJOekV4TlRFeU5UZy82YzE4NjZmNTY3NjE2ZjMxQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dpcmUwBQYDK2VwA0EA-FYJfHuf15aZYQuQzCvLq7vWgkKtkUNTRO6DKsXicumlBbqwRBg6992tUxqGEWQeYFKFWIlCbD6DwqoV80IQAA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/wvYpqnUvADmOgk9Ln6TF6JPfQsrLx64T",
    "nonce": "a0JXTU8xclpDNWRNVlpZYzJuQkIzZ2xqMWJWMzZPbmw",
    "typ": "JWT",
    "url": "https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGzbFXHk2ngUGpBYzabEAtDJIefbX1/w
DUSDJbEL/nJNoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndp
cmVhcHA9TmpobE16SXhPV0ZqT0RSaU5EQXdZamswWkdGaFpEQTJOekV4TlRFeU5U
Zy82YzE4NjZmNTY3NjE2ZjMxQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dp
cmUwBQYDK2VwA0EA+FYJfHuf15aZYQuQzCvLq7vWgkKtkUNTRO6DKsXicumlBbqw
RBg6992tUxqGEWQeYFKFWIlCbD6DwqoV80IQAA==
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
                    6c:db:15:71:e4:da:78:14:1a:90:58:cd:a6:c4:02:
                    d0:c9:21:e7:db:5f:5f:f0:0d:44:83:25:b1:0b:fe:
                    72:4d
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        f8:56:09:7c:7b:9f:d7:96:99:61:0b:90:cc:2b:cb:ab:bb:d6:
        82:42:ad:91:43:53:44:ee:83:2a:c5:e2:72:e9:a5:05:ba:b0:
        44:18:3a:f7:dd:ad:53:1a:86:11:64:1e:60:52:85:58:89:42:
        6c:3e:83:c2:aa:15:f3:42:10:00

```

#### 35. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl
replay-nonce: NENueHMyU1NTaGdNYTZnMDBqNEVmR1FIWmJqbEs3RWc
```
```json
{
  "certificate": "https://stepca:55083/acme/wire/certificate/vq9x2zRm1jsiTTr2a4x6oyrbqI8gTDq9",
  "status": "valid",
  "finalize": "https://stepca:55083/acme/wire/order/IdC1phlzAr9cGHBvHpkU7EBsnINpEDOl/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55083/acme/wire/authz/gTUrdUl5urNJXYVwOkjNottmM912qbBY"
  ],
  "expires": "2023-04-06T09:26:58Z",
  "notBefore": "2023-04-05T09:26:58.546433Z",
  "notAfter": "2023-04-05T10:26:58.546433Z"
}
```
#### 36. fetch the certificate
```http request
POST https://stepca:55083/acme/wire/certificate/vq9x2zRm1jsiTTr2a4x6oyrbqI8gTDq9
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L3d2WXBxblV2QURtT2drOUxuNlRGNkpQZlFzckx4NjRUIiwidHlwIjoiSldUIiwibm9uY2UiOiJORU51ZUhNeVUxTlRhR2ROWVRabk1EQnFORVZtUjFGSVdtSnFiRXMzUldjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL2NlcnRpZmljYXRlL3ZxOXgyelJtMWpzaVRUcjJhNHg2b3lyYnFJOGdURHE5In0",
  "payload": "",
  "signature": "q2UUn6HjUaVrzT5dO5AgixmteGZAm5lRwygi2XVXc8kD2k-0ZvN_OhS0p7Qf0nRltGJm7yLccMEyxhwLKi2uCw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/wvYpqnUvADmOgk9Ln6TF6JPfQsrLx64T",
    "nonce": "NENueHMyU1NTaGdNYTZnMDBqNEVmR1FIWmJqbEs3RWc",
    "typ": "JWT",
    "url": "https://stepca:55083/acme/wire/certificate/vq9x2zRm1jsiTTr2a4x6oyrbqI8gTDq9"
  }
}
```
#### 37. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:55083/acme/wire/directory>;rel="index"
replay-nonce: dFVHQ1ZLdEk2c1QyR0RXWmd2cW9nUlZuUUZ4THpGSzM
```
```json
"-----BEGIN CERTIFICATE-----\nMIICLjCCAdSgAwIBAgIQIi6jHWSEF/LHAkiyoiSHbjAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzA0MDUwOTI2NThaFw0yMzA0MDUxMDI2NThaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGzbFXHk2ngUGpBYzabE\nAtDJIefbX1/wDUSDJbEL/nJNo4IBBjCCAQIwDgYDVR0PAQH/BAQDAgeAMB0GA1Ud\nJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUhifYTPG7M3pyQMrz\nHYmakvfDG80wHwYDVR0jBBgwFoAUHPSH1n7X87LAYJnc+cFG2a3ZAQ4wcgYDVR0R\nBGswaYZQaW06d2lyZWFwcD1OamhsTXpJeE9XRmpPRFJpTkRBd1lqazBaR0ZoWkRB\nMk56RXhOVEV5TlRnLzZjMTg2NmY1Njc2MTZmMzFAd2lyZS5jb22GFWltOndpcmVh\ncHA9YWxpY2Vfd2lyZTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYI\nKoZIzj0EAwIDSAAwRQIhAKY0Zs8SYwS7mFFenPDoCDHPQbCbV9VdvYpBQncOFD5K\nAiAisX68Di4B0dN059YsVDXpM0drnkrVTRKHV+F+ipDjZQ==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBtzCCAV6gAwIBAgIQPbElEJQ58HlbQf7bqrJjXTAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNDA1MDky\nNjUzWhcNMzMwNDAyMDkyNjUzWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGbM\nrA1eqJE9xlGOwO+sYbexThtlU/to9jJj5SBoKPx7Q8QMBlmPTjqDVumXhUvSe+xY\nJE7M+lBXfVZCywzIIPWjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBQc9IfWftfzssBgmdz5wUbZrdkBDjAfBgNVHSMEGDAW\ngBQY+1rDw64QLm/weFQC1mo9y29ddTAKBggqhkjOPQQDAgNHADBEAiARvd7RBuuv\nOhUy7ncjd/nzoN5Qs0p6D+ujdSLDqLlNIAIgfkwAAgsQMDF3ClqVM/p9cmS95B0g\nCAdIObqPoNL5MJo=\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICLjCCAdSgAwIBAgIQIi6jHWSEF/LHAkiyoiSHbjAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzA0MDUwOTI2NThaFw0yMzA0MDUxMDI2NThaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGzbFXHk2ngUGpBYzabE
AtDJIefbX1/wDUSDJbEL/nJNo4IBBjCCAQIwDgYDVR0PAQH/BAQDAgeAMB0GA1Ud
JQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUhifYTPG7M3pyQMrz
HYmakvfDG80wHwYDVR0jBBgwFoAUHPSH1n7X87LAYJnc+cFG2a3ZAQ4wcgYDVR0R
BGswaYZQaW06d2lyZWFwcD1OamhsTXpJeE9XRmpPRFJpTkRBd1lqazBaR0ZoWkRB
Mk56RXhOVEV5TlRnLzZjMTg2NmY1Njc2MTZmMzFAd2lyZS5jb22GFWltOndpcmVh
cHA9YWxpY2Vfd2lyZTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYI
KoZIzj0EAwIDSAAwRQIhAKY0Zs8SYwS7mFFenPDoCDHPQbCbV9VdvYpBQncOFD5K
AiAisX68Di4B0dN059YsVDXpM0drnkrVTRKHV+F+ipDjZQ==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            22:2e:a3:1d:64:84:17:f2:c7:02:48:b2:a2:24:87:6e
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Apr  5 09:26:58 2023 GMT
            Not After : Apr  5 10:26:58 2023 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    6c:db:15:71:e4:da:78:14:1a:90:58:cd:a6:c4:02:
                    d0:c9:21:e7:db:5f:5f:f0:0d:44:83:25:b1:0b:fe:
                    72:4d
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                86:27:D8:4C:F1:BB:33:7A:72:40:CA:F3:1D:89:9A:92:F7:C3:1B:CD
            X509v3 Authority Key Identifier: 
                1C:F4:87:D6:7E:D7:F3:B2:C0:60:99:DC:F9:C1:46:D9:AD:D9:01:0E
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com, URI:im:wireapp=alice_wire
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:a6:34:66:cf:12:63:04:bb:98:51:5e:9c:f0:
        e8:08:31:cf:41:b0:9b:57:d5:5d:bd:8a:41:42:77:0e:14:3e:
        4a:02:20:22:b1:7e:bc:0e:2e:01:d1:d3:74:e7:d6:2c:54:35:
        e9:33:47:6b:9e:4a:d5:4d:12:87:57:e1:7e:8a:90:e3:65

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBtzCCAV6gAwIBAgIQPbElEJQ58HlbQf7bqrJjXTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNDA1MDky
NjUzWhcNMzMwNDAyMDkyNjUzWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGbM
rA1eqJE9xlGOwO+sYbexThtlU/to9jJj5SBoKPx7Q8QMBlmPTjqDVumXhUvSe+xY
JE7M+lBXfVZCywzIIPWjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQc9IfWftfzssBgmdz5wUbZrdkBDjAfBgNVHSMEGDAW
gBQY+1rDw64QLm/weFQC1mo9y29ddTAKBggqhkjOPQQDAgNHADBEAiARvd7RBuuv
OhUy7ncjd/nzoN5Qs0p6D+ujdSLDqLlNIAIgfkwAAgsQMDF3ClqVM/p9cmS95B0g
CAdIObqPoNL5MJo=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3d:b1:25:10:94:39:f0:79:5b:41:fe:db:aa:b2:63:5d
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Apr  5 09:26:53 2023 GMT
            Not After : Apr  2 09:26:53 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:66:cc:ac:0d:5e:a8:91:3d:c6:51:8e:c0:ef:ac:
                    61:b7:b1:4e:1b:65:53:fb:68:f6:32:63:e5:20:68:
                    28:fc:7b:43:c4:0c:06:59:8f:4e:3a:83:56:e9:97:
                    85:4b:d2:7b:ec:58:24:4e:cc:fa:50:57:7d:56:42:
                    cb:0c:c8:20:f5
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                1C:F4:87:D6:7E:D7:F3:B2:C0:60:99:DC:F9:C1:46:D9:AD:D9:01:0E
            X509v3 Authority Key Identifier: 
                18:FB:5A:C3:C3:AE:10:2E:6F:F0:78:54:02:D6:6A:3D:CB:6F:5D:75
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:11:bd:de:d1:06:eb:af:3a:15:32:ee:77:23:77:
        f9:f3:a0:de:50:b3:4a:7a:0f:eb:a3:75:22:c3:a8:b9:4d:20:
        02:20:7e:4c:00:02:0b:10:30:31:77:0a:5a:95:33:fa:7d:72:
        64:bd:e4:1d:20:08:07:48:39:ba:8f:a0:d2:f9:30:9a

```
