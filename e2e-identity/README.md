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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/3238c2a01f3de75a/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/6dPWfVj5g5LRPDhmZ9Vmrv9IBqe08zkA
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/37LTLIqINqCUS1M6r6ol0sIWPU1vAggJ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/Fbw04vNdcIYczZOEiO4tgUDRwmI6SXDZ
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:33011/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:33011/acme/wire/new-nonce",
  "newAccount": "https://stepca:33011/acme/wire/new-account",
  "newOrder": "https://stepca:33011/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:33011/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:33011/acme/wire/directory>;rel="index"
replay-nonce: aDBrbjZGY2pJR2NpN01ucGU1bk9qcjg4Q0lRb1h0emQ
```
```text
aDBrbjZGY2pJR2NpN01ucGU1bk9qcjg4Q0lRb1h0emQ
```
#### 5. create a new account
```http request
POST https://stepca:33011/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ino3SC1hNmE2ZFNqRS1BWEFKVHNHTVhRSzh6UGJEcF80dGdHZWh5Y3hxOW8ifSwibm9uY2UiOiJhREJyYmpaR1kycEpSMk5wTjAxdWNHVTFiazlxY2pnNFEwbFJiMWgwZW1RIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTEvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "vmZug3-AWv2Z_4NzTx-I2JO47fGBpb0VrjL0aKnVwJQZuE2xbcYrVEmFj2UpXh61QuBvpXBUlU_lbuHvoUjRDg"
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
      "x": "z7H-a6a6dSjE-AXAJTsGMXQK8zPbDp_4tgGehycxq9o"
    },
    "nonce": "aDBrbjZGY2pJR2NpN01ucGU1bk9qcjg4Q0lRb1h0emQ",
    "typ": "JWT",
    "url": "https://stepca:33011/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33011/acme/wire/directory>;rel="index"
location: https://stepca:33011/acme/wire/account/OBDgZZZsG5PYkLUC3FgZ0GkVU13IdTyh
replay-nonce: UGdMMWp6NXlWQzNWZHFaOFRCYzFwTnIxRm1NQ29XTGg
```
```json
{
  "status": "valid",
  "orders": "https://stepca:33011/acme/wire/account/OBDgZZZsG5PYkLUC3FgZ0GkVU13IdTyh/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:33011/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDExL2FjbWUvd2lyZS9hY2NvdW50L09CRGdaWlpzRzVQWWtMVUMzRmdaMEdrVlUxM0lkVHloIiwidHlwIjoiSldUIiwibm9uY2UiOiJVR2RNTVdwNk5YbFdRek5XWkhGYU9GUkNZekZ3VG5JeFJtMU5RMjlYVEdnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTEvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9T1Rjd09HWXpOVGszTmpObU5EazRNemswT1RNeFlqRTBZVEF3T0RkbVpXRS8zMjM4YzJhMDFmM2RlNzVhQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9YWxpY2Vfd2lyZVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wNS0yM1QxNToxNjo0NS4xODEzNVoiLCJub3RBZnRlciI6IjIwMjMtMDUtMjNUMTY6MTY6NDUuMTgxMzVaIn0",
  "signature": "AKM0hdPKhrI6rTGrWl9Dw1Y3uk9y1pji1Arb1-pxs6UJRr1bqzzIiGIf9CvGm7s_BD8MEbPgamggJ15NM1jcCw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2023-05-23T16:16:45.18135Z",
    "notBefore": "2023-05-23T15:16:45.18135Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33011/acme/wire/account/OBDgZZZsG5PYkLUC3FgZ0GkVU13IdTyh",
    "nonce": "UGdMMWp6NXlWQzNWZHFaOFRCYzFwTnIxRm1NQ29XTGg",
    "typ": "JWT",
    "url": "https://stepca:33011/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33011/acme/wire/directory>;rel="index"
location: https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3
replay-nonce: SDdCdDBMZlQ2MjNJbVVsNEFFUkJWTEZWY2FqZ0lTUzU
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33011/acme/wire/authz/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN"
  ],
  "expires": "2023-05-24T15:16:45Z",
  "notBefore": "2023-05-23T15:16:45.18135Z",
  "notAfter": "2023-05-23T16:16:45.18135Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:33011/acme/wire/authz/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDExL2FjbWUvd2lyZS9hY2NvdW50L09CRGdaWlpzRzVQWWtMVUMzRmdaMEdrVlUxM0lkVHloIiwidHlwIjoiSldUIiwibm9uY2UiOiJTRGRDZERCTVpsUTJNak5KYlZWc05FRkZVa0pXVEVaV1kyRnFaMGxUVXpVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTEvYWNtZS93aXJlL2F1dGh6L3dRdTRCc2RIc2VwSmFiUURtZkhjSDA0V2pTQjBXR05OIn0",
  "payload": "",
  "signature": "nbcElxlahKeA9U2FyWKIUjBHKsatEOgipRDgHXJKlOzBVa3mbwLPJDS1eSTnY1TiWP6X6DxUIxKYgpoybF_9BA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33011/acme/wire/account/OBDgZZZsG5PYkLUC3FgZ0GkVU13IdTyh",
    "nonce": "SDdCdDBMZlQ2MjNJbVVsNEFFUkJWTEZWY2FqZ0lTUzU",
    "typ": "JWT",
    "url": "https://stepca:33011/acme/wire/authz/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33011/acme/wire/directory>;rel="index"
location: https://stepca:33011/acme/wire/authz/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN
replay-nonce: ZmxoTGlJYk12NVRDNGdNNDRiY3RXdk1aTllRWkVIOXQ
```
```json
{
  "status": "pending",
  "expires": "2023-05-24T15:16:45Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/37LTLIqINqCUS1M6r6ol0sIWPU1vAggJ",
      "status": "pending",
      "token": "gA14QrWDRfdrr5QMUdyFfAKcNFxcDSUG",
      "target": "http://dex:17757/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/6dPWfVj5g5LRPDhmZ9Vmrv9IBqe08zkA",
      "status": "pending",
      "token": "gA14QrWDRfdrr5QMUdyFfAKcNFxcDSUG",
      "target": "http://wire.com:23651/clients/3238c2a01f3de75a/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:23651/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
ZEhNZWJ1R3g0Z0taZ2Z2N1lRMmVWSzEwNlBDSFdPWVc
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiejdILWE2YTZkU2pFLUFYQUpUc0dNWFFLOHpQYkRwXzR0Z0dlaHljeHE5byJ9fQ.eyJpYXQiOjE2ODQ4NTUwMDUsImV4cCI6MTY4NDg1ODYwNSwibmJmIjoxNjg0ODU1MDAwLCJzdWIiOiJpbTp3aXJlYXBwPU9UY3dPR1l6TlRrM05qTm1ORGs0TXprME9UTXhZakUwWVRBd09EZG1aV0UvMzIzOGMyYTAxZjNkZTc1YUB3aXJlLmNvbSIsImp0aSI6ImVkMjZjODAwLTRhOWEtNDkwMi04YjhiLTljM2MxMjU2MDU2NyIsIm5vbmNlIjoiWkVoTlpXSjFSM2cwWjB0YVoyWjJOMWxSTW1WV1N6RXdObEJEU0ZkUFdWYyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjM2NTEvY2xpZW50cy8zMjM4YzJhMDFmM2RlNzVhL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJnQTE0UXJXRFJmZHJyNVFNVWR5RmZBS2NORnhjRFNVRyJ9.CGDKVgtxaP7UaqQKQXBzOJwgn7Uk7KV-qG8qJrQk3xljlDZuEgiwPtvHgd0c3bEgar3sbcrBRW-SUieueIOgAw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiejdILWE2YTZkU2pFLUFYQUpUc0dNWFFL
OHpQYkRwXzR0Z0dlaHljeHE5byJ9fQ.eyJpYXQiOjE2ODQ4NTUwMDUsImV4cCI6M
TY4NDg1ODYwNSwibmJmIjoxNjg0ODU1MDAwLCJzdWIiOiJpbTp3aXJlYXBwPU9UY
3dPR1l6TlRrM05qTm1ORGs0TXprME9UTXhZakUwWVRBd09EZG1aV0UvMzIzOGMyY
TAxZjNkZTc1YUB3aXJlLmNvbSIsImp0aSI6ImVkMjZjODAwLTRhOWEtNDkwMi04Y
jhiLTljM2MxMjU2MDU2NyIsIm5vbmNlIjoiWkVoTlpXSjFSM2cwWjB0YVoyWjJOM
WxSTW1WV1N6RXdObEJEU0ZkUFdWYyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MjM2NTEvY2xpZW50cy8zMjM4YzJhMDFmM2RlNzVhL2FjY2Vzc
y10b2tlbiIsImNoYWwiOiJnQTE0UXJXRFJmZHJyNVFNVWR5RmZBS2NORnhjRFNVR
yJ9.CGDKVgtxaP7UaqQKQXBzOJwgn7Uk7KV-qG8qJrQk3xljlDZuEgiwPtvHgd0c
3bEgar3sbcrBRW-SUieueIOgAw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "z7H-a6a6dSjE-AXAJTsGMXQK8zPbDp_4tgGehycxq9o"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "gA14QrWDRfdrr5QMUdyFfAKcNFxcDSUG",
  "exp": 1684858605,
  "htm": "POST",
  "htu": "http://wire.com:23651/clients/3238c2a01f3de75a/access-token",
  "iat": 1684855005,
  "jti": "ed26c800-4a9a-4902-8b8b-9c3c12560567",
  "nbf": 1684855000,
  "nonce": "ZEhNZWJ1R3g0Z0taZ2Z2N1lRMmVWSzEwNlBDSFdPWVc",
  "sub": "im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIM0vSCdfpyLmHqpcCj3dYR3Ec25KhPPnH8IWYw18IiLs
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAz7H+a6a6dSjE+AXAJTsGMXQK8zPbDp/4tgGehycxq9o=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:23651/clients/3238c2a01f3de75a/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZWpkSUxXRTJZVFprVTJwRkxVRllRVXBVYzBkTldGRkxPSHBRWWtSd1h6UjBaMGRsYUhsamVIRTVieUo5ZlEuZXlKcFlYUWlPakUyT0RRNE5UVXdNRFVzSW1WNGNDSTZNVFk0TkRnMU9EWXdOU3dpYm1KbUlqb3hOamcwT0RVMU1EQXdMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTlVWTNkUFIxbDZUbFJyTTA1cVRtMU9SR3MwVFhwck1FOVVUWGhaYWtVd1dWUkJkMDlFWkcxYVYwVXZNekl6T0dNeVlUQXhaak5rWlRjMVlVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltVmtNalpqT0RBd0xUUmhPV0V0TkRrd01pMDRZamhpTFRsak0yTXhNalUyTURVMk55SXNJbTV2Ym1ObElqb2lXa1ZvVGxwWFNqRlNNMmN3V2pCMFlWb3lXakpPTVd4U1RXMVdWMU42UlhkT2JFSkVVMFprVUZkV1l5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak0yTlRFdlkyeHBaVzUwY3k4ek1qTTRZekpoTURGbU0yUmxOelZoTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSm5RVEUwVVhKWFJGSm1aSEp5TlZGTlZXUjVSbVpCUzJOT1JuaGpSRk5WUnlKOS5DR0RLVmd0eGFQN1VhcVFLUVhCek9Kd2duN1VrN0tWLXFHOHFKclFrM3hsamxEWnVFZ2l3UHR2SGdkMGMzYkVnYXIzc2JjckJSVy1TVWlldWVJT2dBdw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkVaTDM3VXNwS1otbkJ1Y01RcGFMTHpOQVAyYjVZampkeFM2U2M4Mjc1Z0UifX0.eyJpYXQiOjE2ODQ4NTUwMDUsImV4cCI6MTY5MjYzMTAwNSwibmJmIjoxNjg0ODU1MDAwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2NTEvY2xpZW50cy8zMjM4YzJhMDFmM2RlNzVhL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9T1Rjd09HWXpOVGszTmpObU5EazRNemswT1RNeFlqRTBZVEF3T0RkbVpXRS8zMjM4YzJhMDFmM2RlNzVhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzNjUxL2NsaWVudHMvMzIzOGMyYTAxZjNkZTc1YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJkNzhlYmU1Mi01YTdiLTQ0MjctYTc4MC0zMTk1MDRkNDZiMDgiLCJub25jZSI6IlpFaE5aV0oxUjNnMFowdGFaMloyTjFsUk1tVldTekV3TmxCRFNGZFBXVmMiLCJjaGFsIjoiZ0ExNFFyV0RSZmRycjVRTVVkeUZmQUtjTkZ4Y0RTVUciLCJjbmYiOnsia2lkIjoidlYxWkNpLXNYYTdvOW8tdFBVUzk5MDBpZ05GSFlScmVqM0syUXh1cjVwRSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVqZElMV0UyWVRaa1UycEZMVUZZUVVwVWMwZE5XRkZMT0hwUVlrUndYelIwWjBkbGFIbGplSEU1YnlKOWZRLmV5SnBZWFFpT2pFMk9EUTROVFV3TURVc0ltVjRjQ0k2TVRZNE5EZzFPRFl3TlN3aWJtSm1Jam94TmpnME9EVTFNREF3TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5VVkzZFBSMWw2VGxSck0wNXFUbTFPUkdzMFRYcHJNRTlVVFhoWmFrVXdXVlJCZDA5RVpHMWFWMFV2TXpJek9HTXlZVEF4WmpOa1pUYzFZVUIzYVhKbExtTnZiU0lzSW1wMGFTSTZJbVZrTWpaak9EQXdMVFJoT1dFdE5Ea3dNaTA0WWpoaUxUbGpNMk14TWpVMk1EVTJOeUlzSW01dmJtTmxJam9pV2tWb1RscFhTakZTTTJjd1dqQjBZVm95V2pKT01XeFNUVzFXVjFONlJYZE9iRUpFVTBaa1VGZFdZeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNMk5URXZZMnhwWlc1MGN5OHpNak00WXpKaE1ERm1NMlJsTnpWaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUpuUVRFMFVYSlhSRkptWkhKeU5WRk5WV1I1Um1aQlMyTk9SbmhqUkZOVlJ5SjkuQ0dES1ZndHhhUDdVYXFRS1FYQnpPSndnbjdVazdLVi1xRzhxSnJRazN4bGpsRFp1RWdpd1B0dkhnZDBjM2JFZ2FyM3NiY3JCUlctU1VpZXVlSU9nQXciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU9UY3dPR1l6TlRrM05qTm1ORGs0TXprME9UTXhZakUwWVRBd09EZG1aV0UvMzIzOGMyYTAxZjNkZTc1YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.yXyvEzQCZswfdnTn_2ibmBMBQ2l23O0e04cBflPl_rIyHLxuNXRBQjR8SbeshGyBqrJJ72kSKe2UY0c3SOC0AA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkVaTDM3VXNwS1otbkJ1Y01RcGFMTHpOQVAyYjVZampkeFM2U2M4Mjc1Z0UifX0.eyJpYXQiOjE2ODQ4NTUwMDUsImV4cCI6MTY5MjYzMTAwNSwibmJmIjoxNjg0ODU1MDAwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2NTEvY2xpZW50cy8zMjM4YzJhMDFmM2RlNzVhL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9T1Rjd09HWXpOVGszTmpObU5EazRNemswT1RNeFlqRTBZVEF3T0RkbVpXRS8zMjM4YzJhMDFmM2RlNzVhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzNjUxL2NsaWVudHMvMzIzOGMyYTAxZjNkZTc1YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJkNzhlYmU1Mi01YTdiLTQ0MjctYTc4MC0zMTk1MDRkNDZiMDgiLCJub25jZSI6IlpFaE5aV0oxUjNnMFowdGFaMloyTjFsUk1tVldTekV3TmxCRFNGZFBXVmMiLCJjaGFsIjoiZ0ExNFFyV0RSZmRycjVRTVVkeUZmQUtjTkZ4Y0RTVUciLCJjbmYiOnsia2lkIjoidlYxWkNpLXNYYTdvOW8tdFBVUzk5MDBpZ05GSFlScmVqM0syUXh1cjVwRSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVqZElMV0UyWVRaa1UycEZMVUZZUVVwVWMwZE5XRkZMT0hwUVlrUndYelIwWjBkbGFIbGplSEU1YnlKOWZRLmV5SnBZWFFpT2pFMk9EUTROVFV3TURVc0ltVjRjQ0k2TVRZNE5EZzFPRFl3TlN3aWJtSm1Jam94TmpnME9EVTFNREF3TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5VVkzZFBSMWw2VGxSck0wNXFUbTFPUkdzMFRYcHJNRTlVVFhoWmFrVXdXVlJCZDA5RVpHMWFWMFV2TXpJek9HTXlZVEF4WmpOa1pUYzFZVUIzYVhKbExtTnZiU0lzSW1wMGFTSTZJbVZrTWpaak9EQXdMVFJoT1dFdE5Ea3dNaTA0WWpoaUxUbGpNMk14TWpVMk1EVTJOeUlzSW01dmJtTmxJam9pV2tWb1RscFhTakZTTTJjd1dqQjBZVm95V2pKT01XeFNUVzFXVjFONlJYZE9iRUpFVTBaa1VGZFdZeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNMk5URXZZMnhwWlc1MGN5OHpNak00WXpKaE1ERm1NMlJsTnpWaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUpuUVRFMFVYSlhSRkptWkhKeU5WRk5WV1I1Um1aQlMyTk9SbmhqUkZOVlJ5SjkuQ0dES1ZndHhhUDdVYXFRS1FYQnpPSndnbjdVazdLVi1xRzhxSnJRazN4bGpsRFp1RWdpd1B0dkhnZDBjM2JFZ2FyM3NiY3JCUlctU1VpZXVlSU9nQXciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU9UY3dPR1l6TlRrM05qTm1ORGs0TXprME9UTXhZakUwWVRBd09EZG1aV0UvMzIzOGMyYTAxZjNkZTc1YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.yXyvEzQCZswfdnTn_2ibmBMBQ2l23O0e04cBflPl_rIyHLxuNXRBQjR8SbeshGyBqrJJ72kSKe2UY0c3SOC0AA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IkVaTDM3VXNwS1otbkJ1Y01RcGFMTHpOQVAy
YjVZampkeFM2U2M4Mjc1Z0UifX0.eyJpYXQiOjE2ODQ4NTUwMDUsImV4cCI6MTY5
MjYzMTAwNSwibmJmIjoxNjg0ODU1MDAwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjM2NTEvY2xpZW50cy8zMjM4YzJhMDFmM2RlNzVhL2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9T1Rjd09HWXpOVGszTmpObU5EazRNemswT1RNeFlqRTBZ
VEF3T0RkbVpXRS8zMjM4YzJhMDFmM2RlNzVhQHdpcmUuY29tIiwiYXVkIjoiaHR0
cDovL3dpcmUuY29tOjIzNjUxL2NsaWVudHMvMzIzOGMyYTAxZjNkZTc1YS9hY2Nl
c3MtdG9rZW4iLCJqdGkiOiJkNzhlYmU1Mi01YTdiLTQ0MjctYTc4MC0zMTk1MDRk
NDZiMDgiLCJub25jZSI6IlpFaE5aV0oxUjNnMFowdGFaMloyTjFsUk1tVldTekV3
TmxCRFNGZFBXVmMiLCJjaGFsIjoiZ0ExNFFyV0RSZmRycjVRTVVkeUZmQUtjTkZ4
Y0RTVUciLCJjbmYiOnsia2lkIjoidlYxWkNpLXNYYTdvOW8tdFBVUzk5MDBpZ05G
SFlScmVqM0syUXh1cjVwRSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lz
SW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lz
SW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVqZElMV0UyWVRaa1UycEZMVUZZ
UVVwVWMwZE5XRkZMT0hwUVlrUndYelIwWjBkbGFIbGplSEU1YnlKOWZRLmV5SnBZ
WFFpT2pFMk9EUTROVFV3TURVc0ltVjRjQ0k2TVRZNE5EZzFPRFl3TlN3aWJtSm1J
am94TmpnME9EVTFNREF3TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5VVkzZFBS
MWw2VGxSck0wNXFUbTFPUkdzMFRYcHJNRTlVVFhoWmFrVXdXVlJCZDA5RVpHMWFW
MFV2TXpJek9HTXlZVEF4WmpOa1pUYzFZVUIzYVhKbExtTnZiU0lzSW1wMGFTSTZJ
bVZrTWpaak9EQXdMVFJoT1dFdE5Ea3dNaTA0WWpoaUxUbGpNMk14TWpVMk1EVTJO
eUlzSW01dmJtTmxJam9pV2tWb1RscFhTakZTTTJjd1dqQjBZVm95V2pKT01XeFNU
VzFXVjFONlJYZE9iRUpFVTBaa1VGZFdZeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9k
SFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNMk5URXZZMnhwWlc1MGN5OHpN
ak00WXpKaE1ERm1NMlJsTnpWaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lP
aUpuUVRFMFVYSlhSRkptWkhKeU5WRk5WV1I1Um1aQlMyTk9SbmhqUkZOVlJ5Sjku
Q0dES1ZndHhhUDdVYXFRS1FYQnpPSndnbjdVazdLVi1xRzhxSnJRazN4bGpsRFp1
RWdpd1B0dkhnZDBjM2JFZ2FyM3NiY3JCUlctU1VpZXVlSU9nQXciLCJjbGllbnRf
aWQiOiJpbTp3aXJlYXBwPU9UY3dPR1l6TlRrM05qTm1ORGs0TXprME9UTXhZakUw
WVRBd09EZG1aV0UvMzIzOGMyYTAxZjNkZTc1YUB3aXJlLmNvbSIsImFwaV92ZXJz
aW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.yXyvEzQCZswfdnTn_2ib
mBMBQ2l23O0e04cBflPl_rIyHLxuNXRBQjR8SbeshGyBqrJJ72kSKe2UY0c3SOC0
AA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "EZL37UspKZ-nBucMQpaLLzNAP2b5YjjdxS6Sc8275gE"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:23651/clients/3238c2a01f3de75a/access-token",
  "chal": "gA14QrWDRfdrr5QMUdyFfAKcNFxcDSUG",
  "client_id": "im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com",
  "cnf": {
    "kid": "vV1ZCi-sXa7o9o-tPUS9900igNFHYRrej3K2Qxur5pE"
  },
  "exp": 1692631005,
  "iat": 1684855005,
  "iss": "http://wire.com:23651/clients/3238c2a01f3de75a/access-token",
  "jti": "d78ebe52-5a7b-4427-a780-319504d46b08",
  "nbf": 1684855000,
  "nonce": "ZEhNZWJ1R3g0Z0taZ2Z2N1lRMmVWSzEwNlBDSFdPWVc",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiejdILWE2YTZkU2pFLUFYQUpUc0dNWFFLOHpQYkRwXzR0Z0dlaHljeHE5byJ9fQ.eyJpYXQiOjE2ODQ4NTUwMDUsImV4cCI6MTY4NDg1ODYwNSwibmJmIjoxNjg0ODU1MDAwLCJzdWIiOiJpbTp3aXJlYXBwPU9UY3dPR1l6TlRrM05qTm1ORGs0TXprME9UTXhZakUwWVRBd09EZG1aV0UvMzIzOGMyYTAxZjNkZTc1YUB3aXJlLmNvbSIsImp0aSI6ImVkMjZjODAwLTRhOWEtNDkwMi04YjhiLTljM2MxMjU2MDU2NyIsIm5vbmNlIjoiWkVoTlpXSjFSM2cwWjB0YVoyWjJOMWxSTW1WV1N6RXdObEJEU0ZkUFdWYyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjM2NTEvY2xpZW50cy8zMjM4YzJhMDFmM2RlNzVhL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJnQTE0UXJXRFJmZHJyNVFNVWR5RmZBS2NORnhjRFNVRyJ9.CGDKVgtxaP7UaqQKQXBzOJwgn7Uk7KV-qG8qJrQk3xljlDZuEgiwPtvHgd0c3bEgar3sbcrBRW-SUieueIOgAw",
  "scope": "wire_client_id",
  "sub": "im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICZNx9QsMN8/8z7Vml1zu4i0dKp9mQV4UJlwweg6mOVL
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAEZL37UspKZ+nBucMQpaLLzNAP2b5YjjdxS6Sc8275gE=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/6dPWfVj5g5LRPDhmZ9Vmrv9IBqe08zkA
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDExL2FjbWUvd2lyZS9hY2NvdW50L09CRGdaWlpzRzVQWWtMVUMzRmdaMEdrVlUxM0lkVHloIiwidHlwIjoiSldUIiwibm9uY2UiOiJabXhvVEdsSllrMTJOVlJETkdkTk5EUmlZM1JYZGsxYVRsbFJXa1ZJT1hRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTEvYWNtZS93aXJlL2NoYWxsZW5nZS93UXU0QnNkSHNlcEphYlFEbWZIY0gwNFdqU0IwV0dOTi82ZFBXZlZqNWc1TFJQRGhtWjlWbXJ2OUlCcWUwOHprQSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrVmFURE0zVlhOd1Mxb3Ria0oxWTAxUmNHRk1USHBPUVZBeVlqVlphbXBrZUZNMlUyTTRNamMxWjBVaWZYMC5leUpwWVhRaU9qRTJPRFE0TlRVd01EVXNJbVY0Y0NJNk1UWTVNall6TVRBd05Td2libUptSWpveE5qZzBPRFUxTURBd0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNMk5URXZZMnhwWlc1MGN5OHpNak00WXpKaE1ERm1NMlJsTnpWaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5VDFSamQwOUhXWHBPVkdzelRtcE9iVTVFYXpSTmVtc3dUMVJOZUZscVJUQlpWRUYzVDBSa2JWcFhSUzh6TWpNNFl6SmhNREZtTTJSbE56VmhRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0RvdkwzZHBjbVV1WTI5dE9qSXpOalV4TDJOc2FXVnVkSE12TXpJek9HTXlZVEF4WmpOa1pUYzFZUzloWTJObGMzTXRkRzlyWlc0aUxDSnFkR2tpT2lKa056aGxZbVUxTWkwMVlUZGlMVFEwTWpjdFlUYzRNQzB6TVRrMU1EUmtORFppTURnaUxDSnViMjVqWlNJNklscEZhRTVhVjBveFVqTm5NRm93ZEdGYU1sb3lUakZzVWsxdFZsZFRla1YzVG14Q1JGTkdaRkJYVm1NaUxDSmphR0ZzSWpvaVowRXhORkZ5VjBSU1ptUnljalZSVFZWa2VVWm1RVXRqVGtaNFkwUlRWVWNpTENKamJtWWlPbnNpYTJsa0lqb2lkbFl4V2tOcExYTllZVGR2T1c4dGRGQlZVems1TURCcFowNUdTRmxTY21WcU0wc3lVWGgxY2pWd1JTSjlMQ0p3Y205dlppSTZJbVY1U21oaVIyTnBUMmxLUmxwRlVsUlJVMGx6U1c1U05XTkRTVFpKYlZKM1lqTkJjbUZ1WkRCSmFYZHBZVzVrY2tscWNEZEpiWFF3WlZOSk5rbHJPVXhWUTBselNXMU9lV1JwU1RaSmExWnJUV3BWTVUxVWEybE1RMG8wU1dwdmFXVnFaRWxNVjBVeVdWUmFhMVV5Y0VaTVZVWlpVVlZ3VldNd1pFNVhSa1pNVDBod1VWbHJVbmRZZWxJd1dqQmtiR0ZJYkdwbFNFVTFZbmxLT1daUkxtVjVTbkJaV0ZGcFQycEZNazlFVVRST1ZGVjNUVVJWYzBsdFZqUmpRMGsyVFZSWk5FNUVaekZQUkZsM1RsTjNhV0p0U20xSmFtOTRUbXBuTUU5RVZURk5SRUYzVEVOS2VtUlhTV2xQYVVwd1lsUndNMkZZU214WldFSjNVRlU1VlZrelpGQlNNV3cyVkd4U2NrMHdOWEZVYlRGUFVrZHpNRlJZY0hKTlJUbFZWRmhvV21GclZYZFhWbEpDWkRBNVJWcEhNV0ZXTUZWMlRYcEplazlIVFhsWlZFRjRXbXBPYTFwVVl6RlpWVUl6WVZoS2JFeHRUblppVTBselNXMXdNR0ZUU1RaSmJWWnJUV3BhYWs5RVFYZE1WRkpvVDFkRmRFNUVhM2ROYVRBMFdXcG9hVXhVYkdwTk1rMTRUV3BWTWsxRVZUSk9lVWx6U1cwMWRtSnRUbXhKYW05cFYydFdiMVJzY0ZoVGFrWlRUVEpqZDFkcVFqQlpWbTk1VjJwS1QwMVhlRk5VVnpGWFZqRk9ObEpZWkU5aVJVcEZWVEJhYTFWR1pGZFplVWx6U1cxb01HSlRTVFpKYkVKUVZURlJhVXhEU205a1NGVnBUMmxLYjJSSVVuZFBhVGgyWkRKc2VWcFROV3BpTWpBMlRXcE5NazVVUlhaWk1uaHdXbGMxTUdONU9IcE5hazAwV1hwS2FFMUVSbTFOTWxKc1RucFdhRXd5Um1wWk1sWjZZM2t4TUdJeWRHeGlhVWx6U1cxT2IxbFhkMmxQYVVwdVVWUkZNRlZZU2xoU1JrcHRXa2hLZVU1V1JrNVdWMUkxVW0xYVFsTXlUazlTYm1ocVVrWk9WbEo1U2prdVEwZEVTMVpuZEhoaFVEZFZZWEZSUzFGWVFucFBTbmRuYmpkVmF6ZExWaTF4UnpoeFNuSlJhek40Ykdwc1JGcDFSV2RwZDFCMGRraG5aREJqTTJKRloyRnlNM05pWTNKQ1VsY3RVMVZwWlhWbFNVOW5RWGNpTENKamJHbGxiblJmYVdRaU9pSnBiVHAzYVhKbFlYQndQVTlVWTNkUFIxbDZUbFJyTTA1cVRtMU9SR3MwVFhwck1FOVVUWGhaYWtVd1dWUkJkMDlFWkcxYVYwVXZNekl6T0dNeVlUQXhaak5rWlRjMVlVQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvekxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLnlYeXZFelFDWnN3ZmRuVG5fMmlibUJNQlEybDIzTzBlMDRjQmZsUGxfckl5SEx4dU5YUkJRalI4U2Jlc2hHeUJxckpKNzJrU0tlMlVZMGMzU09DMEFBIn0",
  "signature": "4SKj26JHTcmIC1R0NfkVybTZqWwpXVeATRPttgWADo21qcnGhhuULBXhAKzk0SfuVCnJ8MJp52OSxsziG8zcCQ"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkVaTDM3VXNwS1otbkJ1Y01RcGFMTHpOQVAyYjVZampkeFM2U2M4Mjc1Z0UifX0.eyJpYXQiOjE2ODQ4NTUwMDUsImV4cCI6MTY5MjYzMTAwNSwibmJmIjoxNjg0ODU1MDAwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2NTEvY2xpZW50cy8zMjM4YzJhMDFmM2RlNzVhL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9T1Rjd09HWXpOVGszTmpObU5EazRNemswT1RNeFlqRTBZVEF3T0RkbVpXRS8zMjM4YzJhMDFmM2RlNzVhQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzNjUxL2NsaWVudHMvMzIzOGMyYTAxZjNkZTc1YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJkNzhlYmU1Mi01YTdiLTQ0MjctYTc4MC0zMTk1MDRkNDZiMDgiLCJub25jZSI6IlpFaE5aV0oxUjNnMFowdGFaMloyTjFsUk1tVldTekV3TmxCRFNGZFBXVmMiLCJjaGFsIjoiZ0ExNFFyV0RSZmRycjVRTVVkeUZmQUtjTkZ4Y0RTVUciLCJjbmYiOnsia2lkIjoidlYxWkNpLXNYYTdvOW8tdFBVUzk5MDBpZ05GSFlScmVqM0syUXh1cjVwRSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVqZElMV0UyWVRaa1UycEZMVUZZUVVwVWMwZE5XRkZMT0hwUVlrUndYelIwWjBkbGFIbGplSEU1YnlKOWZRLmV5SnBZWFFpT2pFMk9EUTROVFV3TURVc0ltVjRjQ0k2TVRZNE5EZzFPRFl3TlN3aWJtSm1Jam94TmpnME9EVTFNREF3TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5VVkzZFBSMWw2VGxSck0wNXFUbTFPUkdzMFRYcHJNRTlVVFhoWmFrVXdXVlJCZDA5RVpHMWFWMFV2TXpJek9HTXlZVEF4WmpOa1pUYzFZVUIzYVhKbExtTnZiU0lzSW1wMGFTSTZJbVZrTWpaak9EQXdMVFJoT1dFdE5Ea3dNaTA0WWpoaUxUbGpNMk14TWpVMk1EVTJOeUlzSW01dmJtTmxJam9pV2tWb1RscFhTakZTTTJjd1dqQjBZVm95V2pKT01XeFNUVzFXVjFONlJYZE9iRUpFVTBaa1VGZFdZeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNMk5URXZZMnhwWlc1MGN5OHpNak00WXpKaE1ERm1NMlJsTnpWaEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUpuUVRFMFVYSlhSRkptWkhKeU5WRk5WV1I1Um1aQlMyTk9SbmhqUkZOVlJ5SjkuQ0dES1ZndHhhUDdVYXFRS1FYQnpPSndnbjdVazdLVi1xRzhxSnJRazN4bGpsRFp1RWdpd1B0dkhnZDBjM2JFZ2FyM3NiY3JCUlctU1VpZXVlSU9nQXciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU9UY3dPR1l6TlRrM05qTm1ORGs0TXprME9UTXhZakUwWVRBd09EZG1aV0UvMzIzOGMyYTAxZjNkZTc1YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.yXyvEzQCZswfdnTn_2ibmBMBQ2l23O0e04cBflPl_rIyHLxuNXRBQjR8SbeshGyBqrJJ72kSKe2UY0c3SOC0AA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33011/acme/wire/account/OBDgZZZsG5PYkLUC3FgZ0GkVU13IdTyh",
    "nonce": "ZmxoTGlJYk12NVRDNGdNNDRiY3RXdk1aTllRWkVIOXQ",
    "typ": "JWT",
    "url": "https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/6dPWfVj5g5LRPDhmZ9Vmrv9IBqe08zkA"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33011/acme/wire/directory>;rel="index"
link: <https://stepca:33011/acme/wire/authz/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN>;rel="up"
location: https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/6dPWfVj5g5LRPDhmZ9Vmrv9IBqe08zkA
replay-nonce: WkNhSXhaOFNkMU5kdjBkZ3ZGVk5ud2puOU1MdlJHRDU
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/6dPWfVj5g5LRPDhmZ9Vmrv9IBqe08zkA",
  "status": "valid",
  "token": "gA14QrWDRfdrr5QMUdyFfAKcNFxcDSUG",
  "target": "http://wire.com:23651/clients/3238c2a01f3de75a/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=Dv6l9Zs2JtqLCYFpSyYW8p8NudhtPFm3wd84gXB7nYI&code_challenge=G-QscWWmEQGwOieRApls5GIFCeCRVbGIVpqtiQPqYNM
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:17757/dex/auth?response_type=code&client_id=wireapp&state=nmwU-ndfEz3CRsBb09Szlw&code_challenge=G-QscWWmEQGwOieRApls5GIFCeCRVbGIVpqtiQPqYNM&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A23651%2Fcallback&scope=openid+profile&nonce=IeZWOgSb8ulszBSJniDtnw
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:17757/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpNR1ExVFdaelFYUkxOVVI1VWpWcWJsVjBlRWhqVGxSSw==
```
```text
grant_type=authorization_code&code=m4dzhrf6pz4qovvzrntw44j7w&code_verifier=Dv6l9Zs2JtqLCYFpSyYW8p8NudhtPFm3wd84gXB7nYI&redirect_uri=http%3A%2F%2Fwire.com%3A23651%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyNTEwNTAyOTc3MTI5YzNhYjRlYjVkODA4MjE5NmM2ZmI1OTkyNTEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3NzU3L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlVWTNkUFIxbDZUbFJyTTA1cVRtMU9SR3MwVFhwck1FOVVUWGhaYWtVd1dWUkJkMDlFWkcxYVYwVXZNekl6T0dNeVlUQXhaak5rWlRjMVlVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0OTQxNDA1LCJpYXQiOjE2ODQ4NTUwMDUsIm5vbmNlIjoiSWVaV09nU2I4dWxzekJTSm5pRHRudyIsImF0X2hhc2giOiJGZTF1SW9Gdi1aNHpxNFJ2WW5jZHdnIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.Y6gh-S3vk6I9qY52CMxS0lY4XGOAXUOWqOB9qxOC0_zaUtzDUoWUxtvgbBQYk4fy6kivHrdqn4nAyg3cPX8LQj1zadNrdauCAJ1hsunWNX71PI_2xeXROmIwXFVwksq8i8mieICQyGNSi4FnbYNG6cJqPbWctWzmGX11xRsyXJuwKwzMT85LOzHRZ1j_Kdm7FrEjOl9TXymZYEEdOR9UOaQtRaRfttjKMEcYTumk5FbgH77fHnYhx7hCE2-nY68_XirhDke7BmDUqmz26XuT7ygCcQSABWZe2nQPorXeo2KBm22QMPGamBB2zUduLb5KnmaLojeyIdEYmdaNYK1EGA",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyNTEwNTAyOTc3MTI5YzNhYjRlYjVkODA4MjE5NmM2ZmI1OTkyNTEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3NzU3L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlVWTNkUFIxbDZUbFJyTTA1cVRtMU9SR3MwVFhwck1FOVVUWGhaYWtVd1dWUkJkMDlFWkcxYVYwVXZNekl6T0dNeVlUQXhaak5rWlRjMVlVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0OTQxNDA1LCJpYXQiOjE2ODQ4NTUwMDUsIm5vbmNlIjoiSWVaV09nU2I4dWxzekJTSm5pRHRudyIsImF0X2hhc2giOiJYTnpLS24yUzU4c21DSjZDWWlfRmRBIiwiY19oYXNoIjoiUEZ4NWhnWGhKREFxTG45X0xQSGNnQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.M4XZU1dNO3LumZ5zOSSLvQmSxHXcxmn-3OJjPVuwtfstgkjRveNiiqe_pl0tTlmUrfDzp7AOEZEbJfSMTD-TzI6AJR8xu9rizLFwPeH0nk8nVoYk_66QKLnong3kF_7M_jJwbKb9KeFKKm3WI3w6-LGAO6mByQZOTfZrukNMNZkq0TxP5_Qx5nYUMX4xSInVvz_Zg3UNVSAWATlMZQSkB-iVCekDy4jYgRC-1lPljI8eHZ2lwEBzwshq7Er0iWebMEaq4fNIQCf9zs086SebDEmDYPhUh7dFJWlmtnVZeJeP57KZeoo2L9JyMpWc9jJHQZpp2U2K2U12UqLPm-voGw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyNTEwNTAyOTc3MTI5YzNhYjRlYjVkODA4MjE5NmM2ZmI1OTkyNTEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3NzU3L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlVWTNkUFIxbDZUbFJyTTA1cVRtMU9SR3MwVFhwck1FOVVUWGhaYWtVd1dWUkJkMDlFWkcxYVYwVXZNekl6T0dNeVlUQXhaak5rWlRjMVlVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0OTQxNDA1LCJpYXQiOjE2ODQ4NTUwMDUsIm5vbmNlIjoiSWVaV09nU2I4dWxzekJTSm5pRHRudyIsImF0X2hhc2giOiJYTnpLS24yUzU4c21DSjZDWWlfRmRBIiwiY19oYXNoIjoiUEZ4NWhnWGhKREFxTG45X0xQSGNnQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.M4XZU1dNO3LumZ5zOSSLvQmSxHXcxmn-3OJjPVuwtfstgkjRveNiiqe_pl0tTlmUrfDzp7AOEZEbJfSMTD-TzI6AJR8xu9rizLFwPeH0nk8nVoYk_66QKLnong3kF_7M_jJwbKb9KeFKKm3WI3w6-LGAO6mByQZOTfZrukNMNZkq0TxP5_Qx5nYUMX4xSInVvz_Zg3UNVSAWATlMZQSkB-iVCekDy4jYgRC-1lPljI8eHZ2lwEBzwshq7Er0iWebMEaq4fNIQCf9zs086SebDEmDYPhUh7dFJWlmtnVZeJeP57KZeoo2L9JyMpWc9jJHQZpp2U2K2U12UqLPm-voGw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyNTEwNTAyOTc3MTI5YzNhYjRlYjVkODA4MjE5NmM2ZmI1OTkyNTEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3NzU3L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlVWTNkUFIxbDZUbFJyTTA1cVRtMU9SR3MwVFhwck1FOVVUWGhaYWtVd1dWUkJkMDlFWkcxYVYwVXZNekl6T0dNeVlUQXhaak5rWlRjMVlVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0OTQxNDA1LCJpYXQiOjE2ODQ4NTUwMDUsIm5vbmNlIjoiSWVaV09nU2I4dWxzekJTSm5pRHRudyIsImF0X2hhc2giOiJYTnpLS24yUzU4c21DSjZDWWlfRmRBIiwiY19oYXNoIjoiUEZ4NWhnWGhKREFxTG45X0xQSGNnQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.M4XZU1dNO3LumZ5zOSSLvQmSxHXcxmn-3OJjPVuwtfstgkjRveNiiqe_pl0tTlmUrfDzp7AOEZEbJfSMTD-TzI6AJR8xu9rizLFwPeH0nk8nVoYk_66QKLnong3kF_7M_jJwbKb9KeFKKm3WI3w6-LGAO6mByQZOTfZrukNMNZkq0TxP5_Qx5nYUMX4xSInVvz_Zg3UNVSAWATlMZQSkB-iVCekDy4jYgRC-1lPljI8eHZ2lwEBzwshq7Er0iWebMEaq4fNIQCf9zs086SebDEmDYPhUh7dFJWlmtnVZeJeP57KZeoo2L9JyMpWc9jJHQZpp2U2K2U12UqLPm-voGw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyNTEwNTAyOTc3MTI5YzNhYjRlYjVkODA4
MjE5NmM2ZmI1OTkyNTEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3NzU3L2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlVWTNkUFIxbDZUbFJyTTA1cVRtMU9SR
3MwVFhwck1FOVVUWGhaYWtVd1dWUkJkMDlFWkcxYVYwVXZNekl6T0dNeVlUQXhaa
k5rWlRjMVlVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjg0OTQxNDA1LCJpYXQiOjE2ODQ4NTUwMDUsIm5vbmNlIjoiSWVaV09nU
2I4dWxzekJTSm5pRHRudyIsImF0X2hhc2giOiJYTnpLS24yUzU4c21DSjZDWWlfR
mRBIiwiY19oYXNoIjoiUEZ4NWhnWGhKREFxTG45X0xQSGNnQSIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZ
SBTbWl0aCJ9.M4XZU1dNO3LumZ5zOSSLvQmSxHXcxmn-3OJjPVuwtfstgkjRveNi
iqe_pl0tTlmUrfDzp7AOEZEbJfSMTD-TzI6AJR8xu9rizLFwPeH0nk8nVoYk_66Q
KLnong3kF_7M_jJwbKb9KeFKKm3WI3w6-LGAO6mByQZOTfZrukNMNZkq0TxP5_Qx
5nYUMX4xSInVvz_Zg3UNVSAWATlMZQSkB-iVCekDy4jYgRC-1lPljI8eHZ2lwEBz
wshq7Er0iWebMEaq4fNIQCf9zs086SebDEmDYPhUh7dFJWlmtnVZeJeP57KZeoo2
L9JyMpWc9jJHQZpp2U2K2U12UqLPm-voGw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "12510502977129c3ab4eb5d8082196c6fb599251"
}
```

```json
{
  "at_hash": "XNzKKn2S58smCJ6CYi_FdA",
  "aud": "wireapp",
  "c_hash": "PFx5hgXhJDAqLn9_LPHcgA",
  "exp": 1684941405,
  "iat": 1684855005,
  "iss": "http://dex:17757/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "IeZWOgSb8ulszBSJniDtnw",
  "preferred_username": "Alice Smith",
  "sub": "ClBpbTp3aXJlYXBwPU9UY3dPR1l6TlRrM05qTm1ORGs0TXprME9UTXhZakUwWVRBd09EZG1aV0UvMzIzOGMyYTAxZjNkZTc1YUB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2NPUk+a4P5qCn7FBABzw
+HRCXNb00Ng8SZAnPJUVCV5LaUHXzmJuyYs0iJSCKUBeZUmopS4RAQgit8VVkriX
SsdZoDO21Kqknsv9dIP4Jhcl2NrddAi09vZ9uWcxExeoK/mWvrVES7VDnySIpxJU
wXFokzBUcoNhT51KdumexO/L0aOe39Be3AIquQM0AHA544j5YZolsW3WTTSeqnY0
P+6cejd9j67QvjX0rZ9Sqip5IdTNcstj4THQHv4B7D8XDN4Ri9/W3kS9jtnHi1TU
qp0ino+DUgYivdI6GVSHLPIeios/FYcEQvLxBCwE2cwJnW3NVx9WammRqOoX3kKc
rQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/37LTLIqINqCUS1M6r6ol0sIWPU1vAggJ
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDExL2FjbWUvd2lyZS9hY2NvdW50L09CRGdaWlpzRzVQWWtMVUMzRmdaMEdrVlUxM0lkVHloIiwidHlwIjoiSldUIiwibm9uY2UiOiJXa05oU1hoYU9GTmtNVTVrZGpCa1ozWkdWazV1ZDJwdU9VMU1kbEpIUkRVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTEvYWNtZS93aXJlL2NoYWxsZW5nZS93UXU0QnNkSHNlcEphYlFEbWZIY0gwNFdqU0IwV0dOTi8zN0xUTElxSU5xQ1VTMU02cjZvbDBzSVdQVTF2QWdnSiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJakV5TlRFd05UQXlPVGMzTVRJNVl6TmhZalJsWWpWa09EQTRNakU1Tm1NMlptSTFPVGt5TlRFaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTNOelUzTDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZUbFZXVE5rVUZJeGJEWlViRkp5VFRBMWNWUnRNVTlTUjNNd1ZGaHdjazFGT1ZWVVdHaGFZV3RWZDFkV1VrSmtNRGxGV2tjeFlWWXdWWFpOZWtsNlQwZE5lVmxVUVhoYWFrNXJXbFJqTVZsVlFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qZzBPVFF4TkRBMUxDSnBZWFFpT2pFMk9EUTROVFV3TURVc0ltNXZibU5sSWpvaVNXVmFWMDluVTJJNGRXeHpla0pUU201cFJIUnVkeUlzSW1GMFgyaGhjMmdpT2lKWVRucExTMjR5VXpVNGMyMURTalpEV1dsZlJtUkJJaXdpWTE5b1lYTm9Jam9pVUVaNE5XaG5XR2hLUkVGeFRHNDVYMHhRU0dOblFTSXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObFgzZHBjbVVpTENKd2NtVm1aWEp5WldSZmRYTmxjbTVoYldVaU9pSkJiR2xqWlNCVGJXbDBhQ0o5Lk00WFpVMWROTzNMdW1aNXpPU1NMdlFtU3hIWGN4bW4tM09KalBWdXd0ZnN0Z2tqUnZlTmlpcWVfcGwwdFRsbVVyZkR6cDdBT0VaRWJKZlNNVEQtVHpJNkFKUjh4dTlyaXpMRndQZUgwbms4blZvWWtfNjZRS0xub25nM2tGXzdNX2pKd2JLYjlLZUZLS20zV0kzdzYtTEdBTzZtQnlRWk9UZlpydWtOTU5aa3EwVHhQNV9ReDVuWVVNWDR4U0luVnZ6X1pnM1VOVlNBV0FUbE1aUVNrQi1pVkNla0R5NGpZZ1JDLTFsUGxqSThlSFoybHdFQnp3c2hxN0VyMGlXZWJNRWFxNGZOSVFDZjl6czA4NlNlYkRFbURZUGhVaDdkRkpXbG10blZaZUplUDU3S1plb28yTDlKeU1wV2M5akpIUVpwcDJVMksyVTEyVXFMUG0tdm9HdyIsImtleWF1dGgiOiJnQTE0UXJXRFJmZHJyNVFNVWR5RmZBS2NORnhjRFNVRy5yZ0lZUkl3RG5xZW9nRkZhcDZob0RnT29BRGxPMktjRFBFVG9aSGJGWEVvIn0",
  "signature": "wFcFqNZYFJx3tUaAkqdVcpcv9fWj8xQYWpcYGK234sju5GGiL4yB37C-0wL_0fYYwSZy8WtpPCyvuFg25aE-Bg"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyNTEwNTAyOTc3MTI5YzNhYjRlYjVkODA4MjE5NmM2ZmI1OTkyNTEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3NzU3L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlVWTNkUFIxbDZUbFJyTTA1cVRtMU9SR3MwVFhwck1FOVVUWGhaYWtVd1dWUkJkMDlFWkcxYVYwVXZNekl6T0dNeVlUQXhaak5rWlRjMVlVQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0OTQxNDA1LCJpYXQiOjE2ODQ4NTUwMDUsIm5vbmNlIjoiSWVaV09nU2I4dWxzekJTSm5pRHRudyIsImF0X2hhc2giOiJYTnpLS24yUzU4c21DSjZDWWlfRmRBIiwiY19oYXNoIjoiUEZ4NWhnWGhKREFxTG45X0xQSGNnQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.M4XZU1dNO3LumZ5zOSSLvQmSxHXcxmn-3OJjPVuwtfstgkjRveNiiqe_pl0tTlmUrfDzp7AOEZEbJfSMTD-TzI6AJR8xu9rizLFwPeH0nk8nVoYk_66QKLnong3kF_7M_jJwbKb9KeFKKm3WI3w6-LGAO6mByQZOTfZrukNMNZkq0TxP5_Qx5nYUMX4xSInVvz_Zg3UNVSAWATlMZQSkB-iVCekDy4jYgRC-1lPljI8eHZ2lwEBzwshq7Er0iWebMEaq4fNIQCf9zs086SebDEmDYPhUh7dFJWlmtnVZeJeP57KZeoo2L9JyMpWc9jJHQZpp2U2K2U12UqLPm-voGw",
    "keyauth": "gA14QrWDRfdrr5QMUdyFfAKcNFxcDSUG.rgIYRIwDnqeogFFap6hoDgOoADlO2KcDPEToZHbFXEo"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33011/acme/wire/account/OBDgZZZsG5PYkLUC3FgZ0GkVU13IdTyh",
    "nonce": "WkNhSXhaOFNkMU5kdjBkZ3ZGVk5ud2puOU1MdlJHRDU",
    "typ": "JWT",
    "url": "https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/37LTLIqINqCUS1M6r6ol0sIWPU1vAggJ"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33011/acme/wire/directory>;rel="index"
link: <https://stepca:33011/acme/wire/authz/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN>;rel="up"
location: https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/37LTLIqINqCUS1M6r6ol0sIWPU1vAggJ
replay-nonce: OTZVRWtPWm1KYmVFZHB2dkhLQThCVFZ0WW1qUmNlVmk
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:33011/acme/wire/challenge/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN/37LTLIqINqCUS1M6r6ol0sIWPU1vAggJ",
  "status": "valid",
  "token": "gA14QrWDRfdrr5QMUdyFfAKcNFxcDSUG",
  "target": "http://dex:17757/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDExL2FjbWUvd2lyZS9hY2NvdW50L09CRGdaWlpzRzVQWWtMVUMzRmdaMEdrVlUxM0lkVHloIiwidHlwIjoiSldUIiwibm9uY2UiOiJPVFpWUld0UFdtMUtZbVZGWkhCMmRraExRVGhDVkZaMFdXMXFVbU5sVm1rIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTEvYWNtZS93aXJlL29yZGVyL09OQmoyM2pZczJ1SVdoV1lLcmR3blZnMno5aWhEU3AzIn0",
  "payload": "",
  "signature": "98SpDjIcKVTWCazboibFbHYKsvyTqzJWln9IcOpXcWvhmCL1l7HNQ_Jqgl9rtx3q85_Uryj-BHPmmd7SUdRPCw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33011/acme/wire/account/OBDgZZZsG5PYkLUC3FgZ0GkVU13IdTyh",
    "nonce": "OTZVRWtPWm1KYmVFZHB2dkhLQThCVFZ0WW1qUmNlVmk",
    "typ": "JWT",
    "url": "https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33011/acme/wire/directory>;rel="index"
location: https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3
replay-nonce: VlhuaWxrcjdyTDVQMFJKUFA3bUZLcnVJVkpaZEU1b1k
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33011/acme/wire/authz/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN"
  ],
  "expires": "2023-05-24T15:16:45Z",
  "notBefore": "2023-05-23T15:16:45.18135Z",
  "notAfter": "2023-05-23T16:16:45.18135Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDExL2FjbWUvd2lyZS9hY2NvdW50L09CRGdaWlpzRzVQWWtMVUMzRmdaMEdrVlUxM0lkVHloIiwidHlwIjoiSldUIiwibm9uY2UiOiJWbGh1YVd4cmNqZHlURFZRTUZKS1VGQTNiVVpMY25WSlZrcGFaRVUxYjFrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTEvYWNtZS93aXJlL29yZGVyL09OQmoyM2pZczJ1SVdoV1lLcmR3blZnMno5aWhEU3AzL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCT0RDQjZ3SUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTS14X211bXVuVW94UGdGd0NVN0JqRjBDdk16Mnc2Zi1MWUJub2NuTWF2YW9JR0dNSUdEQmdrcWhraUc5dzBCQ1E0eGRqQjBNSElHQTFVZEVRUnJNR21HVUdsdE9uZHBjbVZoY0hBOVQxUmpkMDlIV1hwT1ZHc3pUbXBPYlU1RWF6Uk5lbXN3VDFSTmVGbHFSVEJaVkVGM1QwUmtiVnBYUlM4ek1qTTRZekpoTURGbU0yUmxOelZoUUhkcGNtVXVZMjl0aGhWcGJUcDNhWEpsWVhCd1BXRnNhV05sWDNkcGNtVXdCUVlESzJWd0EwRUFNWjlMNzI1N2xBLU1tbnJ2bElvQ2pGVTFlOW1BVjVjdWZMWURjNEk0YzhOWjVPeEF3WVgzWkxQSVIyYW9WR0l6cERUTGJaTGZqbHRLQjA5bkRScm9DQSJ9",
  "signature": "I40hI70axTMXRHDI2cfeyz3hU0WI5crKtViJklfRZhFhLjyPew8ejZ6E-47Z1qH9C2kDZbULKAS174g9lF38Aw"
}
```
```json
{
  "payload": {
    "csr": "MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAM-x_mumunUoxPgFwCU7BjF0CvMz2w6f-LYBnocnMavaoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndpcmVhcHA9T1Rjd09HWXpOVGszTmpObU5EazRNemswT1RNeFlqRTBZVEF3T0RkbVpXRS8zMjM4YzJhMDFmM2RlNzVhQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dpcmUwBQYDK2VwA0EAMZ9L7257lA-MmnrvlIoCjFU1e9mAV5cufLYDc4I4c8NZ5OxAwYX3ZLPIR2aoVGIzpDTLbZLfjltKB09nDRroCA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33011/acme/wire/account/OBDgZZZsG5PYkLUC3FgZ0GkVU13IdTyh",
    "nonce": "VlhuaWxrcjdyTDVQMFJKUFA3bUZLcnVJVkpaZEU1b1k",
    "typ": "JWT",
    "url": "https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAM+x/mumunUoxPgFwCU7BjF0CvMz2w6f
+LYBnocnMavaoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndp
cmVhcHA9T1Rjd09HWXpOVGszTmpObU5EazRNemswT1RNeFlqRTBZVEF3T0RkbVpX
RS8zMjM4YzJhMDFmM2RlNzVhQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dp
cmUwBQYDK2VwA0EAMZ9L7257lA+MmnrvlIoCjFU1e9mAV5cufLYDc4I4c8NZ5OxA
wYX3ZLPIR2aoVGIzpDTLbZLfjltKB09nDRroCA==
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
                    cf:b1:fe:6b:a6:ba:75:28:c4:f8:05:c0:25:3b:06:
                    31:74:0a:f3:33:db:0e:9f:f8:b6:01:9e:87:27:31:
                    ab:da
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        31:9f:4b:ef:6e:7b:94:0f:8c:9a:7a:ef:94:8a:02:8c:55:35:
        7b:d9:80:57:97:2e:7c:b6:03:73:82:38:73:c3:59:e4:ec:40:
        c1:85:f7:64:b3:c8:47:66:a8:54:62:33:a4:34:cb:6d:92:df:
        8e:5b:4a:07:4f:67:0d:1a:e8:08

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33011/acme/wire/directory>;rel="index"
location: https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3
replay-nonce: NkZiYVlmYUl5ZGtSTFJxSTZ0dDVleXp4eU94QWhJa3Y
```
```json
{
  "certificate": "https://stepca:33011/acme/wire/certificate/Fbw04vNdcIYczZOEiO4tgUDRwmI6SXDZ",
  "status": "valid",
  "finalize": "https://stepca:33011/acme/wire/order/ONBj23jYs2uIWhWYKrdwnVg2z9ihDSp3/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33011/acme/wire/authz/wQu4BsdHsepJabQDmfHcH04WjSB0WGNN"
  ],
  "expires": "2023-05-24T15:16:45Z",
  "notBefore": "2023-05-23T15:16:45.18135Z",
  "notAfter": "2023-05-23T16:16:45.18135Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:33011/acme/wire/certificate/Fbw04vNdcIYczZOEiO4tgUDRwmI6SXDZ
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDExL2FjbWUvd2lyZS9hY2NvdW50L09CRGdaWlpzRzVQWWtMVUMzRmdaMEdrVlUxM0lkVHloIiwidHlwIjoiSldUIiwibm9uY2UiOiJOa1ppWVZsbVlVbDVaR3RTVEZKeFNUWjBkRFZsZVhwNGVVOTRRV2hKYTNZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTEvYWNtZS93aXJlL2NlcnRpZmljYXRlL0ZidzA0dk5kY0lZY3paT0VpTzR0Z1VEUndtSTZTWERaIn0",
  "payload": "",
  "signature": "OWLTOqEGIawvdikMcLQj_L6kNFyUMmXg9ekwFrf1Cm23lrK5G5658nhdpcCST2L72eDgjd3IMCzdfCt4BoCEAQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33011/acme/wire/account/OBDgZZZsG5PYkLUC3FgZ0GkVU13IdTyh",
    "nonce": "NkZiYVlmYUl5ZGtSTFJxSTZ0dDVleXp4eU94QWhJa3Y",
    "typ": "JWT",
    "url": "https://stepca:33011/acme/wire/certificate/Fbw04vNdcIYczZOEiO4tgUDRwmI6SXDZ"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:33011/acme/wire/directory>;rel="index"
replay-nonce: Qk9NbTN3QlJkdktxbkZMYVBNUWZOVXg1MkQ0WFFKc0M
```
```json
"-----BEGIN CERTIFICATE-----\nMIICIjCCAcigAwIBAgIQfIQL73fDuFXiFa/H7aWcyzAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzA1MjMxNTE2NDVaFw0yMzA1MjMxNjE2NDVaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAM+x/mumunUoxPgFwCU7\nBjF0CvMz2w6f+LYBnocnMavao4H7MIH4MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQU4AWR1uY0FHNxkHlAjLv6B3wTLl0wHwYD\nVR0jBBgwFoAUHdrTUbdzTf1nboZujI3ZoQGdB7EwcgYDVR0RBGswaYYVaW06d2ly\nZWFwcD1hbGljZV93aXJlhlBpbTp3aXJlYXBwPU9UY3dPR1l6TlRrM05qTm1ORGs0\nTXprME9UTXhZakUwWVRBd09EZG1aV0UvMzIzOGMyYTAxZjNkZTc1YUB3aXJlLmNv\nbTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAw\nRQIgB/4pxnrKgCkehd9toCiLRHanEyscBbhufeUELT5urCYCIQC9D1LWQDnXfmp1\n6AxVTHOAg61xCRrLAmqWUo/Lx0ANMA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV+gAwIBAgIRANySvvk/JQ7gFnspEPekidEwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDUyMzE1\nMTY0MloXDTMzMDUyMDE1MTY0MlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATI\nr3aCwi1VluaZAnNn6t4kgDB/2P/JCMmaQcIHb/a0PqMKucjfAAF6/kjClE1zHxKI\n94LYzQpNLUssHiFwJdaRo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUHdrTUbdzTf1nboZujI3ZoQGdB7EwHwYDVR0jBBgw\nFoAUkelW1upd1Opf50mhz87uRtvkENgwCgYIKoZIzj0EAwIDRwAwRAIgBd4Tk/NL\n7xSyGSflG5xNBD/XqK1URwq0WbhGiUbqQwoCIDeaXp5Y26O97NYoEAM8RYIeIzpH\n7wcGLbNz+qBNvMab\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICIjCCAcigAwIBAgIQfIQL73fDuFXiFa/H7aWcyzAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzA1MjMxNTE2NDVaFw0yMzA1MjMxNjE2NDVaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAM+x/mumunUoxPgFwCU7
BjF0CvMz2w6f+LYBnocnMavao4H7MIH4MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQU4AWR1uY0FHNxkHlAjLv6B3wTLl0wHwYD
VR0jBBgwFoAUHdrTUbdzTf1nboZujI3ZoQGdB7EwcgYDVR0RBGswaYYVaW06d2ly
ZWFwcD1hbGljZV93aXJlhlBpbTp3aXJlYXBwPU9UY3dPR1l6TlRrM05qTm1ORGs0
TXprME9UTXhZakUwWVRBd09EZG1aV0UvMzIzOGMyYTAxZjNkZTc1YUB3aXJlLmNv
bTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAw
RQIgB/4pxnrKgCkehd9toCiLRHanEyscBbhufeUELT5urCYCIQC9D1LWQDnXfmp1
6AxVTHOAg61xCRrLAmqWUo/Lx0ANMA==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7c:84:0b:ef:77:c3:b8:55:e2:15:af:c7:ed:a5:9c:cb
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: May 23 15:16:45 2023 GMT
            Not After : May 23 16:16:45 2023 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    cf:b1:fe:6b:a6:ba:75:28:c4:f8:05:c0:25:3b:06:
                    31:74:0a:f3:33:db:0e:9f:f8:b6:01:9e:87:27:31:
                    ab:da
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                E0:05:91:D6:E6:34:14:73:71:90:79:40:8C:BB:FA:07:7C:13:2E:5D
            X509v3 Authority Key Identifier: 
                1D:DA:D3:51:B7:73:4D:FD:67:6E:86:6E:8C:8D:D9:A1:01:9D:07:B1
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice_wire, URI:im:wireapp=OTcwOGYzNTk3NjNmNDk4Mzk0OTMxYjE0YTAwODdmZWE/3238c2a01f3de75a@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:07:fe:29:c6:7a:ca:80:29:1e:85:df:6d:a0:28:
        8b:44:76:a7:13:2b:1c:05:b8:6e:7d:e5:04:2d:3e:6e:ac:26:
        02:21:00:bd:0f:52:d6:40:39:d7:7e:6a:75:e8:0c:55:4c:73:
        80:83:ad:71:09:1a:cb:02:6a:96:52:8f:cb:c7:40:0d:30

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV+gAwIBAgIRANySvvk/JQ7gFnspEPekidEwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDUyMzE1
MTY0MloXDTMzMDUyMDE1MTY0MlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATI
r3aCwi1VluaZAnNn6t4kgDB/2P/JCMmaQcIHb/a0PqMKucjfAAF6/kjClE1zHxKI
94LYzQpNLUssHiFwJdaRo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUHdrTUbdzTf1nboZujI3ZoQGdB7EwHwYDVR0jBBgw
FoAUkelW1upd1Opf50mhz87uRtvkENgwCgYIKoZIzj0EAwIDRwAwRAIgBd4Tk/NL
7xSyGSflG5xNBD/XqK1URwq0WbhGiUbqQwoCIDeaXp5Y26O97NYoEAM8RYIeIzpH
7wcGLbNz+qBNvMab
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            dc:92:be:f9:3f:25:0e:e0:16:7b:29:10:f7:a4:89:d1
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: May 23 15:16:42 2023 GMT
            Not After : May 20 15:16:42 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:c8:af:76:82:c2:2d:55:96:e6:99:02:73:67:ea:
                    de:24:80:30:7f:d8:ff:c9:08:c9:9a:41:c2:07:6f:
                    f6:b4:3e:a3:0a:b9:c8:df:00:01:7a:fe:48:c2:94:
                    4d:73:1f:12:88:f7:82:d8:cd:0a:4d:2d:4b:2c:1e:
                    21:70:25:d6:91
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                1D:DA:D3:51:B7:73:4D:FD:67:6E:86:6E:8C:8D:D9:A1:01:9D:07:B1
            X509v3 Authority Key Identifier: 
                91:E9:56:D6:EA:5D:D4:EA:5F:E7:49:A1:CF:CE:EE:46:DB:E4:10:D8
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:05:de:13:93:f3:4b:ef:14:b2:19:27:e5:1b:9c:
        4d:04:3f:d7:a8:ad:54:47:0a:b4:59:b8:46:89:46:ea:43:0a:
        02:20:37:9a:5e:9e:58:db:a3:bd:ec:d6:28:10:03:3c:45:82:
        1e:23:3a:47:ef:07:06:2d:b3:73:fa:a0:4d:bc:c6:9b

```
