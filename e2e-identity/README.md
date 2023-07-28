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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/ef6a91a91d3337a/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/vrVPmwGhchmsuKJffwy0NASsR643ivxB
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/n5FFoVwi6IonK80GtLFgpG18ZoKEXoqQ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/DHrQ0c6czMSXpJlF36wt0PptFHMLvmQW
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
```
```json
{
  "newNonce": "https://stepca:32787/acme/wire/new-nonce",
  "newAccount": "https://stepca:32787/acme/wire/new-account",
  "newOrder": "https://stepca:32787/acme/wire/new-order"
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
replay-nonce: Szk1M1kyalRLVmFQR2swOTI3T3JTam4xM1dHenV1MU0
```
```text
Szk1M1kyalRLVmFQR2swOTI3T3JTam4xM1dHenV1MU0
```
#### 5. create a new account
```http request
POST https://stepca:32787/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJXSVBUWWxaTEQwTmpySUVEd2w2NDJUUkg3UnhYYjlnQW5ham5PMGFiaG8ifSwibm9uY2UiOiJTemsxTTFreWFsUkxWbUZRUjJzd09USTNUM0pUYW00eE0xZEhlblYxTVUwIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "bR6RTGNg0mSzBpL2_ut8ZNkwqyttaqmDUvyaunyL3ZKryZiEFhJ-I63cLhOPZ7yjm5YthvuVuHXTkNmCOIUkCg"
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
      "x": "rWIPTYlZLD0NjrIEDwl642TRH7RxXb9gAnajnO0abho"
    },
    "nonce": "Szk1M1kyalRLVmFQR2swOTI3T3JTam4xM1dHenV1MU0",
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
location: https://stepca:32787/acme/wire/account/IYFNc4A0aeSpHOVaqOL366OoVNBPUs1f
replay-nonce: Wm1PaE1haEI3VXJrdTlvMzlzSmI1WVBudjhtT1dSVEE
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32787/acme/wire/account/IYFNc4A0aeSpHOVaqOL366OoVNBPUs1f/orders"
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
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L0lZRk5jNEEwYWVTcEhPVmFxT0wzNjZPb1ZOQlBVczFmIiwidHlwIjoiSldUIiwibm9uY2UiOiJXbTFQYUUxaGFFSTNWWEpyZFRsdk16bHpTbUkxV1ZCdWRqaHRUMWRTVkVFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9TmpZM05UVmhOR1l6TXpFNE5HRmpNRGd5T0dRNVpUWmhPR00zTnpZeE5USS9lZjZhOTFhOTFkMzMzN2FAd2lyZS5jb21cIixcImhhbmRsZVwiOlwiaW06d2lyZWFwcD1hbGljZV93aXJlXCJ9In1dLCJub3RCZWZvcmUiOiIyMDIzLTA3LTMxVDA5OjI3OjUyLjc1NDYzNloiLCJub3RBZnRlciI6IjIwMzMtMDctMjhUMDk6Mjc6NTIuNzU0NjM2WiJ9",
  "signature": "ImdJCgVTxzDEMRTUCoNk1lAQi9_5-x6PiT7i5V-tTgbQuKtgDpXAix0pawojE_AcadWjJOkLWPTxC7dp9B_LBA"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2033-07-28T09:27:52.754636Z",
    "notBefore": "2023-07-31T09:27:52.754636Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/IYFNc4A0aeSpHOVaqOL366OoVNBPUs1f",
    "nonce": "Wm1PaE1haEI3VXJrdTlvMzlzSmI1WVBudjhtT1dSVEE",
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
location: https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ
replay-nonce: U0NTTUR6aVpMSExTYmFQdHpxa2Viak9EcGZlZnd3ODA
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32787/acme/wire/authz/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES"
  ],
  "expires": "2023-08-01T09:27:52Z",
  "notBefore": "2023-07-31T09:27:52.754636Z",
  "notAfter": "2033-07-28T09:27:52.754636Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32787/acme/wire/authz/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L0lZRk5jNEEwYWVTcEhPVmFxT0wzNjZPb1ZOQlBVczFmIiwidHlwIjoiSldUIiwibm9uY2UiOiJVME5UVFVSNmFWcE1TRXhUWW1GUWRIcHhhMlZpYWs5RWNHWmxabmQzT0RBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL2F1dGh6L1ZSYVQ0Y0JyMWVZdlJIelUyblhBeVQycFVnelVjOUVTIn0",
  "payload": "",
  "signature": "lN1I0xxiTl7PN89v30zId7FfSL7TJVZ_-P0-Er-IbTw0ozSb4ba4HN1VEeM6P-IPS8VOZGaX4fXlbHXfp28MDw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/IYFNc4A0aeSpHOVaqOL366OoVNBPUs1f",
    "nonce": "U0NTTUR6aVpMSExTYmFQdHpxa2Viak9EcGZlZnd3ODA",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/authz/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
location: https://stepca:32787/acme/wire/authz/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES
replay-nonce: cjlzRXlDWDlDYXBCTXAxRlpkTWdhNkVGdzlidlZkMlo
```
```json
{
  "status": "pending",
  "expires": "2023-08-01T09:27:52Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/n5FFoVwi6IonK80GtLFgpG18ZoKEXoqQ",
      "status": "pending",
      "token": "PmPL5ifCHeBvoeGTj7idCieaCkONv9Bh",
      "target": "http://dex:16002/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/vrVPmwGhchmsuKJffwy0NASsR643ivxB",
      "status": "pending",
      "token": "PmPL5ifCHeBvoeGTj7idCieaCkONv9Bh",
      "target": "http://wire.com:23176/clients/ef6a91a91d3337a/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:23176/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
ZXgyc0dBWlJQRUxnYW13NWR6RDZHc1dqYzJmZHkzblI
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoicldJUFRZbFpMRDBOanJJRUR3bDY0MlRSSDdSeFhiOWdBbmFqbk8wYWJobyJ9fQ.eyJpYXQiOjE2OTA3OTU2NzIsImV4cCI6MTY5MDc5OTI3MiwibmJmIjoxNjkwNzk1NjY3LCJzdWIiOiJpbTp3aXJlYXBwPU5qWTNOVFZoTkdZek16RTROR0ZqTURneU9HUTVaVFpoT0dNM056WXhOVEkvZWY2YTkxYTkxZDMzMzdhQHdpcmUuY29tIiwianRpIjoiYjdmYzQxNGUtMzc0OS00Mjc2LTg3MzUtZjgzMzU4ZThhMjhmIiwibm9uY2UiOiJaWGd5YzBkQldsSlFSVXhuWVcxM05XUjZSRFpIYzFkcVl6Sm1aSGt6YmxJIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzE3Ni9jbGllbnRzL2VmNmE5MWE5MWQzMzM3YS9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiUG1QTDVpZkNIZUJ2b2VHVGo3aWRDaWVhQ2tPTnY5QmgifQ.D8tvYks_Skprd3YLgFHdbHxbhzuPlwI_-clcwfqDCXSLv13iiikNoFmBKhDbNDrf8DHuHfpnIDUjAnowTT91Aw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoicldJUFRZbFpMRDBOanJJRUR3bDY0MlRS
SDdSeFhiOWdBbmFqbk8wYWJobyJ9fQ.eyJpYXQiOjE2OTA3OTU2NzIsImV4cCI6M
TY5MDc5OTI3MiwibmJmIjoxNjkwNzk1NjY3LCJzdWIiOiJpbTp3aXJlYXBwPU5qW
TNOVFZoTkdZek16RTROR0ZqTURneU9HUTVaVFpoT0dNM056WXhOVEkvZWY2YTkxY
TkxZDMzMzdhQHdpcmUuY29tIiwianRpIjoiYjdmYzQxNGUtMzc0OS00Mjc2LTg3M
zUtZjgzMzU4ZThhMjhmIiwibm9uY2UiOiJaWGd5YzBkQldsSlFSVXhuWVcxM05XU
jZSRFpIYzFkcVl6Sm1aSGt6YmxJIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6L
y93aXJlLmNvbToyMzE3Ni9jbGllbnRzL2VmNmE5MWE5MWQzMzM3YS9hY2Nlc3Mtd
G9rZW4iLCJjaGFsIjoiUG1QTDVpZkNIZUJ2b2VHVGo3aWRDaWVhQ2tPTnY5Qmgif
Q.D8tvYks_Skprd3YLgFHdbHxbhzuPlwI_-clcwfqDCXSLv13iiikNoFmBKhDbND
rf8DHuHfpnIDUjAnowTT91Aw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "rWIPTYlZLD0NjrIEDwl642TRH7RxXb9gAnajnO0abho"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "PmPL5ifCHeBvoeGTj7idCieaCkONv9Bh",
  "exp": 1690799272,
  "htm": "POST",
  "htu": "http://wire.com:23176/clients/ef6a91a91d3337a/access-token",
  "iat": 1690795672,
  "jti": "b7fc414e-3749-4276-8735-f83358e8a28f",
  "nbf": 1690795667,
  "nonce": "ZXgyc0dBWlJQRUxnYW13NWR6RDZHc1dqYzJmZHkzblI",
  "sub": "im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGZXZOk3T+fsUFBsjUaEjIDk1bJixBqWuZsrY2NnxBMV
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEArWIPTYlZLD0NjrIEDwl642TRH7RxXb9gAnajnO0abho=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:23176/clients/ef6a91a91d3337a/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pY2xkSlVGUlpiRnBNUkRCT2FuSkpSVVIzYkRZME1sUlNTRGRTZUZoaU9XZEJibUZxYms4d1lXSm9ieUo5ZlEuZXlKcFlYUWlPakUyT1RBM09UVTJOeklzSW1WNGNDSTZNVFk1TURjNU9USTNNaXdpYm1KbUlqb3hOamt3TnprMU5qWTNMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVxV1ROT1ZGWm9Ua2RaZWsxNlJUUk9SMFpxVFVSbmVVOUhVVFZhVkZwb1QwZE5NMDU2V1hoT1ZFa3ZaV1kyWVRreFlUa3haRE16TXpkaFFIZHBjbVV1WTI5dElpd2lhblJwSWpvaVlqZG1ZelF4TkdVdE16YzBPUzAwTWpjMkxUZzNNelV0Wmpnek16VTRaVGhoTWpobUlpd2libTl1WTJVaU9pSmFXR2Q1WXpCa1FsZHNTbEZTVlhodVdWY3hNMDVYVWpaU1JGcElZekZrY1ZsNlNtMWFTR3Q2WW14Sklpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJbWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNekUzTmk5amJHbGxiblJ6TDJWbU5tRTVNV0U1TVdRek16TTNZUzloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVVHMVFURFZwWmtOSVpVSjJiMlZIVkdvM2FXUkRhV1ZoUTJ0UFRuWTVRbWdpZlEuRDh0dllrc19Ta3ByZDNZTGdGSGRiSHhiaHp1UGx3SV8tY2xjd2ZxRENYU0x2MTNpaWlrTm9GbUJLaERiTkRyZjhESHVIZnBuSURVakFub3dUVDkxQXc
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImdtNDZXQzJZY1N4MWdjbXYydUFKU2R4SlBsdkx4bUdjSjdVQlVOV0syb1EifX0.eyJpYXQiOjE2OTA3OTU2NzIsImV4cCI6MTY5ODU3MTY3MiwibmJmIjoxNjkwNzk1NjY3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjMxNzYvY2xpZW50cy9lZjZhOTFhOTFkMzMzN2EvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcD1OalkzTlRWaE5HWXpNekU0TkdGak1EZ3lPR1E1WlRaaE9HTTNOell4TlRJL2VmNmE5MWE5MWQzMzM3YUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzE3Ni9jbGllbnRzL2VmNmE5MWE5MWQzMzM3YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiIxMmJlOGE4ZS0xNjE5LTRkZWEtYmY4Yy1lMmY3YmFiMTljYzYiLCJub25jZSI6IlpYZ3ljMGRCV2xKUVJVeG5ZVzEzTldSNlJEWkhjMWRxWXpKbVpIa3pibEkiLCJjaGFsIjoiUG1QTDVpZkNIZUJ2b2VHVGo3aWRDaWVhQ2tPTnY5QmgiLCJjbmYiOnsia2lkIjoidXlsTUhqb2U4RlpZSmFZUVFNUGJBQUNXTWc2UGFUNEFkQVF4OHRncGRvQSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWNsZEpVRlJaYkZwTVJEQk9hbkpKUlVSM2JEWTBNbFJTU0RkU2VGaGlPV2RCYm1GcWJrOHdZV0pvYnlKOWZRLmV5SnBZWFFpT2pFMk9UQTNPVFUyTnpJc0ltVjRjQ0k2TVRZNU1EYzVPVEkzTWl3aWJtSm1Jam94Tmprd056azFOalkzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1cVdUTk9WRlpvVGtkWmVrMTZSVFJPUjBacVRVUm5lVTlIVVRWYVZGcG9UMGROTTA1NldYaE9WRWt2WldZMllUa3hZVGt4WkRNek16ZGhRSGRwY21VdVkyOXRJaXdpYW5ScElqb2lZamRtWXpReE5HVXRNemMwT1MwME1qYzJMVGczTXpVdFpqZ3pNelU0WlRoaE1qaG1JaXdpYm05dVkyVWlPaUphV0dkNVl6QmtRbGRzU2xGU1ZYaHVXVmN4TTA1WFVqWlNSRnBJWXpGa2NWbDZTbTFhU0d0NllteEpJaXdpYUhSdElqb2lVRTlUVkNJc0ltaDBkU0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95TXpFM05pOWpiR2xsYm5SekwyVm1ObUU1TVdFNU1XUXpNek0zWVM5aFkyTmxjM010ZEc5clpXNGlMQ0pqYUdGc0lqb2lVRzFRVERWcFprTklaVUoyYjJWSFZHbzNhV1JEYVdWaFEydFBUblk1UW1naWZRLkQ4dHZZa3NfU2twcmQzWUxnRkhkYkh4Ymh6dVBsd0lfLWNsY3dmcURDWFNMdjEzaWlpa05vRm1CS2hEYk5EcmY4REh1SGZwbklEVWpBbm93VFQ5MUF3IiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcD1OalkzTlRWaE5HWXpNekU0TkdGak1EZ3lPR1E1WlRaaE9HTTNOell4TlRJL2VmNmE5MWE5MWQzMzM3YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.PU-jXARlM5qYmtEu_U1htQtCiEZkWBEkXhdLQJRj3PkO-jgNw6EywAiUGes8ylnfkiqox6EtIG1xPqbpLqopCg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImdtNDZXQzJZY1N4MWdjbXYydUFKU2R4SlBsdkx4bUdjSjdVQlVOV0syb1EifX0.eyJpYXQiOjE2OTA3OTU2NzIsImV4cCI6MTY5ODU3MTY3MiwibmJmIjoxNjkwNzk1NjY3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjMxNzYvY2xpZW50cy9lZjZhOTFhOTFkMzMzN2EvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcD1OalkzTlRWaE5HWXpNekU0TkdGak1EZ3lPR1E1WlRaaE9HTTNOell4TlRJL2VmNmE5MWE5MWQzMzM3YUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzE3Ni9jbGllbnRzL2VmNmE5MWE5MWQzMzM3YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiIxMmJlOGE4ZS0xNjE5LTRkZWEtYmY4Yy1lMmY3YmFiMTljYzYiLCJub25jZSI6IlpYZ3ljMGRCV2xKUVJVeG5ZVzEzTldSNlJEWkhjMWRxWXpKbVpIa3pibEkiLCJjaGFsIjoiUG1QTDVpZkNIZUJ2b2VHVGo3aWRDaWVhQ2tPTnY5QmgiLCJjbmYiOnsia2lkIjoidXlsTUhqb2U4RlpZSmFZUVFNUGJBQUNXTWc2UGFUNEFkQVF4OHRncGRvQSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWNsZEpVRlJaYkZwTVJEQk9hbkpKUlVSM2JEWTBNbFJTU0RkU2VGaGlPV2RCYm1GcWJrOHdZV0pvYnlKOWZRLmV5SnBZWFFpT2pFMk9UQTNPVFUyTnpJc0ltVjRjQ0k2TVRZNU1EYzVPVEkzTWl3aWJtSm1Jam94Tmprd056azFOalkzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1cVdUTk9WRlpvVGtkWmVrMTZSVFJPUjBacVRVUm5lVTlIVVRWYVZGcG9UMGROTTA1NldYaE9WRWt2WldZMllUa3hZVGt4WkRNek16ZGhRSGRwY21VdVkyOXRJaXdpYW5ScElqb2lZamRtWXpReE5HVXRNemMwT1MwME1qYzJMVGczTXpVdFpqZ3pNelU0WlRoaE1qaG1JaXdpYm05dVkyVWlPaUphV0dkNVl6QmtRbGRzU2xGU1ZYaHVXVmN4TTA1WFVqWlNSRnBJWXpGa2NWbDZTbTFhU0d0NllteEpJaXdpYUhSdElqb2lVRTlUVkNJc0ltaDBkU0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95TXpFM05pOWpiR2xsYm5SekwyVm1ObUU1TVdFNU1XUXpNek0zWVM5aFkyTmxjM010ZEc5clpXNGlMQ0pqYUdGc0lqb2lVRzFRVERWcFprTklaVUoyYjJWSFZHbzNhV1JEYVdWaFEydFBUblk1UW1naWZRLkQ4dHZZa3NfU2twcmQzWUxnRkhkYkh4Ymh6dVBsd0lfLWNsY3dmcURDWFNMdjEzaWlpa05vRm1CS2hEYk5EcmY4REh1SGZwbklEVWpBbm93VFQ5MUF3IiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcD1OalkzTlRWaE5HWXpNekU0TkdGak1EZ3lPR1E1WlRaaE9HTTNOell4TlRJL2VmNmE5MWE5MWQzMzM3YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.PU-jXARlM5qYmtEu_U1htQtCiEZkWBEkXhdLQJRj3PkO-jgNw6EywAiUGes8ylnfkiqox6EtIG1xPqbpLqopCg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6ImdtNDZXQzJZY1N4MWdjbXYydUFKU2R4SlBs
dkx4bUdjSjdVQlVOV0syb1EifX0.eyJpYXQiOjE2OTA3OTU2NzIsImV4cCI6MTY5
ODU3MTY3MiwibmJmIjoxNjkwNzk1NjY3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjMxNzYvY2xpZW50cy9lZjZhOTFhOTFkMzMzN2EvYWNjZXNzLXRva2VuIiwic3Vi
IjoiaW06d2lyZWFwcD1OalkzTlRWaE5HWXpNekU0TkdGak1EZ3lPR1E1WlRaaE9H
TTNOell4TlRJL2VmNmE5MWE5MWQzMzM3YUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6
Ly93aXJlLmNvbToyMzE3Ni9jbGllbnRzL2VmNmE5MWE5MWQzMzM3YS9hY2Nlc3Mt
dG9rZW4iLCJqdGkiOiIxMmJlOGE4ZS0xNjE5LTRkZWEtYmY4Yy1lMmY3YmFiMTlj
YzYiLCJub25jZSI6IlpYZ3ljMGRCV2xKUVJVeG5ZVzEzTldSNlJEWkhjMWRxWXpK
bVpIa3pibEkiLCJjaGFsIjoiUG1QTDVpZkNIZUJ2b2VHVGo3aWRDaWVhQ2tPTnY5
QmgiLCJjbmYiOnsia2lkIjoidXlsTUhqb2U4RlpZSmFZUVFNUGJBQUNXTWc2UGFU
NEFkQVF4OHRncGRvQSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5S
NWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1O
eWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWNsZEpVRlJaYkZwTVJEQk9hbkpKUlVS
M2JEWTBNbFJTU0RkU2VGaGlPV2RCYm1GcWJrOHdZV0pvYnlKOWZRLmV5SnBZWFFp
T2pFMk9UQTNPVFUyTnpJc0ltVjRjQ0k2TVRZNU1EYzVPVEkzTWl3aWJtSm1Jam94
Tmprd056azFOalkzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1cVdUTk9WRlpv
VGtkWmVrMTZSVFJPUjBacVRVUm5lVTlIVVRWYVZGcG9UMGROTTA1NldYaE9WRWt2
WldZMllUa3hZVGt4WkRNek16ZGhRSGRwY21VdVkyOXRJaXdpYW5ScElqb2lZamRt
WXpReE5HVXRNemMwT1MwME1qYzJMVGczTXpVdFpqZ3pNelU0WlRoaE1qaG1JaXdp
Ym05dVkyVWlPaUphV0dkNVl6QmtRbGRzU2xGU1ZYaHVXVmN4TTA1WFVqWlNSRnBJ
WXpGa2NWbDZTbTFhU0d0NllteEpJaXdpYUhSdElqb2lVRTlUVkNJc0ltaDBkU0k2
SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95TXpFM05pOWpiR2xsYm5SekwyVm1ObUU1
TVdFNU1XUXpNek0zWVM5aFkyTmxjM010ZEc5clpXNGlMQ0pqYUdGc0lqb2lVRzFR
VERWcFprTklaVUoyYjJWSFZHbzNhV1JEYVdWaFEydFBUblk1UW1naWZRLkQ4dHZZ
a3NfU2twcmQzWUxnRkhkYkh4Ymh6dVBsd0lfLWNsY3dmcURDWFNMdjEzaWlpa05v
Rm1CS2hEYk5EcmY4REh1SGZwbklEVWpBbm93VFQ5MUF3IiwiY2xpZW50X2lkIjoi
aW06d2lyZWFwcD1OalkzTlRWaE5HWXpNekU0TkdGak1EZ3lPR1E1WlRaaE9HTTNO
ell4TlRJL2VmNmE5MWE5MWQzMzM3YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjoz
LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.PU-jXARlM5qYmtEu_U1htQtCiEZk
WBEkXhdLQJRj3PkO-jgNw6EywAiUGes8ylnfkiqox6EtIG1xPqbpLqopCg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "gm46WC2YcSx1gcmv2uAJSdxJPlvLxmGcJ7UBUNWK2oQ"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:23176/clients/ef6a91a91d3337a/access-token",
  "chal": "PmPL5ifCHeBvoeGTj7idCieaCkONv9Bh",
  "client_id": "im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com",
  "cnf": {
    "kid": "uylMHjoe8FZYJaYQQMPbAACWMg6PaT4AdAQx8tgpdoA"
  },
  "exp": 1698571672,
  "iat": 1690795672,
  "iss": "http://wire.com:23176/clients/ef6a91a91d3337a/access-token",
  "jti": "12be8a8e-1619-4dea-bf8c-e2f7bab19cc6",
  "nbf": 1690795667,
  "nonce": "ZXgyc0dBWlJQRUxnYW13NWR6RDZHc1dqYzJmZHkzblI",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoicldJUFRZbFpMRDBOanJJRUR3bDY0MlRSSDdSeFhiOWdBbmFqbk8wYWJobyJ9fQ.eyJpYXQiOjE2OTA3OTU2NzIsImV4cCI6MTY5MDc5OTI3MiwibmJmIjoxNjkwNzk1NjY3LCJzdWIiOiJpbTp3aXJlYXBwPU5qWTNOVFZoTkdZek16RTROR0ZqTURneU9HUTVaVFpoT0dNM056WXhOVEkvZWY2YTkxYTkxZDMzMzdhQHdpcmUuY29tIiwianRpIjoiYjdmYzQxNGUtMzc0OS00Mjc2LTg3MzUtZjgzMzU4ZThhMjhmIiwibm9uY2UiOiJaWGd5YzBkQldsSlFSVXhuWVcxM05XUjZSRFpIYzFkcVl6Sm1aSGt6YmxJIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzE3Ni9jbGllbnRzL2VmNmE5MWE5MWQzMzM3YS9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiUG1QTDVpZkNIZUJ2b2VHVGo3aWRDaWVhQ2tPTnY5QmgifQ.D8tvYks_Skprd3YLgFHdbHxbhzuPlwI_-clcwfqDCXSLv13iiikNoFmBKhDbNDrf8DHuHfpnIDUjAnowTT91Aw",
  "scope": "wire_client_id",
  "sub": "im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJQAVCLHVcll1S8HQnyL2aLzfxi2L+kw04H+I9X1Mr6p
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAgm46WC2YcSx1gcmv2uAJSdxJPlvLxmGcJ7UBUNWK2oQ=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/vrVPmwGhchmsuKJffwy0NASsR643ivxB
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L0lZRk5jNEEwYWVTcEhPVmFxT0wzNjZPb1ZOQlBVczFmIiwidHlwIjoiSldUIiwibm9uY2UiOiJjamx6UlhsRFdEbERZWEJDVFhBeFJscGtUV2RoTmtWR2R6bGlkbFprTWxvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL2NoYWxsZW5nZS9WUmFUNGNCcjFlWXZSSHpVMm5YQXlUMnBVZ3pVYzlFUy92clZQbXdHaGNobXN1S0pmZnd5ME5BU3NSNjQzaXZ4QiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltZHRORFpYUXpKWlkxTjRNV2RqYlhZeWRVRktVMlI0U2xCc2RreDRiVWRqU2pkVlFsVk9WMHN5YjFFaWZYMC5leUpwWVhRaU9qRTJPVEEzT1RVMk56SXNJbVY0Y0NJNk1UWTVPRFUzTVRZM01pd2libUptSWpveE5qa3dOemsxTmpZM0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNeE56WXZZMnhwWlc1MGN5OWxaalpoT1RGaE9URmtNek16TjJFdllXTmpaWE56TFhSdmEyVnVJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFPYWxrelRsUldhRTVIV1hwTmVrVTBUa2RHYWsxRVozbFBSMUUxV2xSYWFFOUhUVE5PZWxsNFRsUkpMMlZtTm1FNU1XRTVNV1F6TXpNM1lVQjNhWEpsTG1OdmJTSXNJbUYxWkNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU16RTNOaTlqYkdsbGJuUnpMMlZtTm1FNU1XRTVNV1F6TXpNM1lTOWhZMk5sYzNNdGRHOXJaVzRpTENKcWRHa2lPaUl4TW1KbE9HRTRaUzB4TmpFNUxUUmtaV0V0WW1ZNFl5MWxNbVkzWW1GaU1UbGpZellpTENKdWIyNWpaU0k2SWxwWVozbGpNR1JDVjJ4S1VWSlZlRzVaVnpFelRsZFNObEpFV2toak1XUnhXWHBLYlZwSWEzcGliRWtpTENKamFHRnNJam9pVUcxUVREVnBaa05JWlVKMmIyVkhWR28zYVdSRGFXVmhRMnRQVG5ZNVFtZ2lMQ0pqYm1ZaU9uc2lhMmxrSWpvaWRYbHNUVWhxYjJVNFJscFpTbUZaVVZGTlVHSkJRVU5YVFdjMlVHRlVORUZrUVZGNE9IUm5jR1J2UVNKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVdOc1pFcFZSbEphWWtad1RWSkVRazloYmtwS1VsVlNNMkpFV1RCTmJGSlRVMFJrVTJWR2FHbFBWMlJDWW0xR2NXSnJPSGRaVjBwdllubEtPV1pSTG1WNVNuQlpXRkZwVDJwRk1rOVVRVE5QVkZVeVRucEpjMGx0VmpSalEwazJUVlJaTlUxRVl6VlBWRWt6VFdsM2FXSnRTbTFKYW05NFRtcHJkMDU2YXpGT2Fsa3pURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGVTFjVmRVVGs5V1JscHZWR3RrV21Wck1UWlNWRkpQVWpCYWNWUlZVbTVsVlRsSVZWUldZVlpHY0c5VU1HUk9UVEExTmxkWWFFOVdSV3QyV2xkWk1sbFVhM2haVkd0NFdrUk5lazE2WkdoUlNHUndZMjFWZFZreU9YUkphWGRwWVc1U2NFbHFiMmxaYW1SdFdYcFJlRTVIVlhSTmVtTXdUMU13TUUxcVl6Sk1WR2N6VFhwVmRGcHFaM3BOZWxVMFdsUm9hRTFxYUcxSmFYZHBZbTA1ZFZreVZXbFBhVXBoVjBka05WbDZRbXRSYkdSelUyeEdVMVpZYUhWWFZtTjRUVEExV0ZWcVdsTlNSbkJKV1hwR2EyTldiRFpUYlRGaFUwZDBObGx0ZUVwSmFYZHBZVWhTZEVscWIybFZSVGxVVmtOSmMwbHRhREJrVTBrMlNXMW9NR1JJUVRaTWVUa3pZVmhLYkV4dFRuWmlWRzk1VFhwRk0wNXBPV3BpUjJ4c1ltNVNla3d5Vm0xT2JVVTFUVmRGTlUxWFVYcE5lazB6V1ZNNWFGa3lUbXhqTTAxMFpFYzVjbHBYTkdsTVEwcHFZVWRHYzBscWIybFZSekZSVkVSV2NGcHJUa2xhVlVveVlqSldTRlpIYnpOaFYxSkVZVmRXYUZFeWRGQlVibGsxVVcxbmFXWlJMa1E0ZEhaWmEzTmZVMnR3Y21ReldVeG5Sa2hrWWtoNFltaDZkVkJzZDBsZkxXTnNZM2RtY1VSRFdGTk1kakV6YVdscGEwNXZSbTFDUzJoRVlrNUVjbVk0UkVoMVNHWndia2xFVldwQmJtOTNWRlE1TVVGM0lpd2lZMnhwWlc1MFgybGtJam9pYVcwNmQybHlaV0Z3Y0QxT2Fsa3pUbFJXYUU1SFdYcE5la1UwVGtkR2FrMUVaM2xQUjFFMVdsUmFhRTlIVFROT2VsbDRUbFJKTDJWbU5tRTVNV0U1TVdRek16TTNZVUIzYVhKbExtTnZiU0lzSW1Gd2FWOTJaWEp6YVc5dUlqb3pMQ0p6WTI5d1pTSTZJbmRwY21WZlkyeHBaVzUwWDJsa0luMC5QVS1qWEFSbE01cVltdEV1X1UxaHRRdENpRVprV0JFa1hoZExRSlJqM1BrTy1qZ053NkV5d0FpVUdlczh5bG5ma2lxb3g2RXRJRzF4UHFicExxb3BDZyJ9",
  "signature": "SMejFykGTjAzRc7CirmWO9hm4oMBfQzeMxuNE54_WmTPNvmZdxiBIvUKl8yk7zUsxUxGhh0XAi-auOi74E1UCQ"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImdtNDZXQzJZY1N4MWdjbXYydUFKU2R4SlBsdkx4bUdjSjdVQlVOV0syb1EifX0.eyJpYXQiOjE2OTA3OTU2NzIsImV4cCI6MTY5ODU3MTY3MiwibmJmIjoxNjkwNzk1NjY3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjMxNzYvY2xpZW50cy9lZjZhOTFhOTFkMzMzN2EvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcD1OalkzTlRWaE5HWXpNekU0TkdGak1EZ3lPR1E1WlRaaE9HTTNOell4TlRJL2VmNmE5MWE5MWQzMzM3YUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzE3Ni9jbGllbnRzL2VmNmE5MWE5MWQzMzM3YS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiIxMmJlOGE4ZS0xNjE5LTRkZWEtYmY4Yy1lMmY3YmFiMTljYzYiLCJub25jZSI6IlpYZ3ljMGRCV2xKUVJVeG5ZVzEzTldSNlJEWkhjMWRxWXpKbVpIa3pibEkiLCJjaGFsIjoiUG1QTDVpZkNIZUJ2b2VHVGo3aWRDaWVhQ2tPTnY5QmgiLCJjbmYiOnsia2lkIjoidXlsTUhqb2U4RlpZSmFZUVFNUGJBQUNXTWc2UGFUNEFkQVF4OHRncGRvQSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWNsZEpVRlJaYkZwTVJEQk9hbkpKUlVSM2JEWTBNbFJTU0RkU2VGaGlPV2RCYm1GcWJrOHdZV0pvYnlKOWZRLmV5SnBZWFFpT2pFMk9UQTNPVFUyTnpJc0ltVjRjQ0k2TVRZNU1EYzVPVEkzTWl3aWJtSm1Jam94Tmprd056azFOalkzTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1cVdUTk9WRlpvVGtkWmVrMTZSVFJPUjBacVRVUm5lVTlIVVRWYVZGcG9UMGROTTA1NldYaE9WRWt2WldZMllUa3hZVGt4WkRNek16ZGhRSGRwY21VdVkyOXRJaXdpYW5ScElqb2lZamRtWXpReE5HVXRNemMwT1MwME1qYzJMVGczTXpVdFpqZ3pNelU0WlRoaE1qaG1JaXdpYm05dVkyVWlPaUphV0dkNVl6QmtRbGRzU2xGU1ZYaHVXVmN4TTA1WFVqWlNSRnBJWXpGa2NWbDZTbTFhU0d0NllteEpJaXdpYUhSdElqb2lVRTlUVkNJc0ltaDBkU0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95TXpFM05pOWpiR2xsYm5SekwyVm1ObUU1TVdFNU1XUXpNek0zWVM5aFkyTmxjM010ZEc5clpXNGlMQ0pqYUdGc0lqb2lVRzFRVERWcFprTklaVUoyYjJWSFZHbzNhV1JEYVdWaFEydFBUblk1UW1naWZRLkQ4dHZZa3NfU2twcmQzWUxnRkhkYkh4Ymh6dVBsd0lfLWNsY3dmcURDWFNMdjEzaWlpa05vRm1CS2hEYk5EcmY4REh1SGZwbklEVWpBbm93VFQ5MUF3IiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcD1OalkzTlRWaE5HWXpNekU0TkdGak1EZ3lPR1E1WlRaaE9HTTNOell4TlRJL2VmNmE5MWE5MWQzMzM3YUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.PU-jXARlM5qYmtEu_U1htQtCiEZkWBEkXhdLQJRj3PkO-jgNw6EywAiUGes8ylnfkiqox6EtIG1xPqbpLqopCg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/IYFNc4A0aeSpHOVaqOL366OoVNBPUs1f",
    "nonce": "cjlzRXlDWDlDYXBCTXAxRlpkTWdhNkVGdzlidlZkMlo",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/vrVPmwGhchmsuKJffwy0NASsR643ivxB"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
link: <https://stepca:32787/acme/wire/authz/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES>;rel="up"
location: https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/vrVPmwGhchmsuKJffwy0NASsR643ivxB
replay-nonce: MXJkSWIyUFZiN09zUXlYajNYZWNnVHVDYzY4b1NBbjg
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/vrVPmwGhchmsuKJffwy0NASsR643ivxB",
  "status": "valid",
  "token": "PmPL5ifCHeBvoeGTj7idCieaCkONv9Bh",
  "target": "http://wire.com:23176/clients/ef6a91a91d3337a/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=S_pTcgu7by-I6OxS1TFMD0OilR485CCm_g3a38_QMTY&code_challenge=cMnU2uuUpSJ0mef4MADqwRE8B9RmxO0jgqe1GVD1IFc
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:16002/dex/auth?response_type=code&client_id=wireapp&state=Tp-IjfQECeLyMqzEGGYYVQ&code_challenge=cMnU2uuUpSJ0mef4MADqwRE8B9RmxO0jgqe1GVD1IFc&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A23176%2Fcallback&scope=openid+profile&nonce=VF-FNsxNvIl1kEJQzZ-Fwg
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:16002/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDplREU1UmswMGRUWlhhVUpVY3pSR2FrSjJiRWg0Y0hoMw==
```
```text
grant_type=authorization_code&code=bdhe7tori6nleufaypfepyts3&code_verifier=S_pTcgu7by-I6OxS1TFMD0OilR485CCm_g3a38_QMTY&redirect_uri=http%3A%2F%2Fwire.com%3A23176%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ3OGFiYmZkZTVkYmE2ZjJkNDI4YWZmNDVmODA0YzAyZDE0YTFlYjkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDAyL2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVxV1ROT1ZGWm9Ua2RaZWsxNlJUUk9SMFpxVFVSbmVVOUhVVFZhVkZwb1QwZE5NMDU2V1hoT1ZFa3ZaV1kyWVRreFlUa3haRE16TXpkaFFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY5MDg4MjA3MiwiaWF0IjoxNjkwNzk1NjcyLCJub25jZSI6IlZGLUZOc3hOdklsMWtFSlF6Wi1Gd2ciLCJhdF9oYXNoIjoiRnEzaEJkTDRTSFlsWVBMMHRvNU52dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.NNBlGkzKo5FtRkMpSXMSZbf4qV5zar_WdJQbFqmbwU-apEGzrgSOifHx_hYYIda6SnggwmESPJt6JZbsXys0_bcm72wAGGkOxPUcSNlJ0JQHK-dtS2ITJpmQn4HClM6m_CQh-Y5Rb9MzuOkE5_7niom8L2LyCT7Z7YT7LfwZsjVE40bEviJmNlUfHmPIN0c5FPILY2HfqJ1iHx0VnFic9r9Leld3bRQVqEFiaq2ZXJGGUfoGjr_kZLyfswLkbQe8D0ra285uI_QE2tBn8a_ooJW7CTpNvXKDjySu7fQfW8s34jUV0hA_XtLfXUtwdlwMvdJ_u65yP-FNOQXZDQ6tXA",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ3OGFiYmZkZTVkYmE2ZjJkNDI4YWZmNDVmODA0YzAyZDE0YTFlYjkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDAyL2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVxV1ROT1ZGWm9Ua2RaZWsxNlJUUk9SMFpxVFVSbmVVOUhVVFZhVkZwb1QwZE5NMDU2V1hoT1ZFa3ZaV1kyWVRreFlUa3haRE16TXpkaFFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY5MDg4MjA3MiwiaWF0IjoxNjkwNzk1NjcyLCJub25jZSI6IlZGLUZOc3hOdklsMWtFSlF6Wi1Gd2ciLCJhdF9oYXNoIjoiWUNxZXJac3pCZlhkS2RHaktUX1YtUSIsImNfaGFzaCI6IlZVMkRUX1ZRMjU1dVZzajZwNExwVGciLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZV93aXJlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.CULrJ14yGoeJOJY7am5rqXjYoQ7i9Ka8VtgVvODHm5IszHfq7sJvPoBH2hFZrZ8Re1fXU5cli55skDxksOIlUooMyGQuqM8bvwz7NoOSJx4njENBYRqYosUVllT1ugWleGhTjZrTw5tPy2TifSWSVXmjk2R0lRcF-yOv3YWRJtPnOgRiQIi50GzvfZlZgepCxyAJsNpqyYfmCdZFBfFVOZKLU19jfV-BCE9S5JiGgwNdgMtKmo9s0oJKtXHe4zh4RqdeSSM4MhkkgM9EuKwq0t8wRG2hpTJQ6dT-54rrXF5zrg3KbFi9wB0QwO3Nuxatp_55dKjjC29xkqXHD4Z9Ag",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ3OGFiYmZkZTVkYmE2ZjJkNDI4YWZmNDVmODA0YzAyZDE0YTFlYjkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDAyL2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVxV1ROT1ZGWm9Ua2RaZWsxNlJUUk9SMFpxVFVSbmVVOUhVVFZhVkZwb1QwZE5NMDU2V1hoT1ZFa3ZaV1kyWVRreFlUa3haRE16TXpkaFFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY5MDg4MjA3MiwiaWF0IjoxNjkwNzk1NjcyLCJub25jZSI6IlZGLUZOc3hOdklsMWtFSlF6Wi1Gd2ciLCJhdF9oYXNoIjoiWUNxZXJac3pCZlhkS2RHaktUX1YtUSIsImNfaGFzaCI6IlZVMkRUX1ZRMjU1dVZzajZwNExwVGciLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZV93aXJlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.CULrJ14yGoeJOJY7am5rqXjYoQ7i9Ka8VtgVvODHm5IszHfq7sJvPoBH2hFZrZ8Re1fXU5cli55skDxksOIlUooMyGQuqM8bvwz7NoOSJx4njENBYRqYosUVllT1ugWleGhTjZrTw5tPy2TifSWSVXmjk2R0lRcF-yOv3YWRJtPnOgRiQIi50GzvfZlZgepCxyAJsNpqyYfmCdZFBfFVOZKLU19jfV-BCE9S5JiGgwNdgMtKmo9s0oJKtXHe4zh4RqdeSSM4MhkkgM9EuKwq0t8wRG2hpTJQ6dT-54rrXF5zrg3KbFi9wB0QwO3Nuxatp_55dKjjC29xkqXHD4Z9Ag
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ3OGFiYmZkZTVkYmE2ZjJkNDI4YWZmNDVmODA0YzAyZDE0YTFlYjkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDAyL2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVxV1ROT1ZGWm9Ua2RaZWsxNlJUUk9SMFpxVFVSbmVVOUhVVFZhVkZwb1QwZE5NMDU2V1hoT1ZFa3ZaV1kyWVRreFlUa3haRE16TXpkaFFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY5MDg4MjA3MiwiaWF0IjoxNjkwNzk1NjcyLCJub25jZSI6IlZGLUZOc3hOdklsMWtFSlF6Wi1Gd2ciLCJhdF9oYXNoIjoiWUNxZXJac3pCZlhkS2RHaktUX1YtUSIsImNfaGFzaCI6IlZVMkRUX1ZRMjU1dVZzajZwNExwVGciLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZV93aXJlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.CULrJ14yGoeJOJY7am5rqXjYoQ7i9Ka8VtgVvODHm5IszHfq7sJvPoBH2hFZrZ8Re1fXU5cli55skDxksOIlUooMyGQuqM8bvwz7NoOSJx4njENBYRqYosUVllT1ugWleGhTjZrTw5tPy2TifSWSVXmjk2R0lRcF-yOv3YWRJtPnOgRiQIi50GzvfZlZgepCxyAJsNpqyYfmCdZFBfFVOZKLU19jfV-BCE9S5JiGgwNdgMtKmo9s0oJKtXHe4zh4RqdeSSM4MhkkgM9EuKwq0t8wRG2hpTJQ6dT-54rrXF5zrg3KbFi9wB0QwO3Nuxatp_55dKjjC29xkqXHD4Z9Ag)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ3OGFiYmZkZTVkYmE2ZjJkNDI4YWZmNDVm
ODA0YzAyZDE0YTFlYjkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDAyL2RleCIsI
nN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVxV1ROT1ZGWm9Ua2RaZWsxNlJUUk9SM
FpxVFVSbmVVOUhVVFZhVkZwb1QwZE5NMDU2V1hoT1ZFa3ZaV1kyWVRreFlUa3haR
E16TXpkaFFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4c
CI6MTY5MDg4MjA3MiwiaWF0IjoxNjkwNzk1NjcyLCJub25jZSI6IlZGLUZOc3hOd
klsMWtFSlF6Wi1Gd2ciLCJhdF9oYXNoIjoiWUNxZXJac3pCZlhkS2RHaktUX1YtU
SIsImNfaGFzaCI6IlZVMkRUX1ZRMjU1dVZzajZwNExwVGciLCJuYW1lIjoiaW06d
2lyZWFwcD1hbGljZV93aXJlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU
21pdGgifQ.CULrJ14yGoeJOJY7am5rqXjYoQ7i9Ka8VtgVvODHm5IszHfq7sJvPo
BH2hFZrZ8Re1fXU5cli55skDxksOIlUooMyGQuqM8bvwz7NoOSJx4njENBYRqYos
UVllT1ugWleGhTjZrTw5tPy2TifSWSVXmjk2R0lRcF-yOv3YWRJtPnOgRiQIi50G
zvfZlZgepCxyAJsNpqyYfmCdZFBfFVOZKLU19jfV-BCE9S5JiGgwNdgMtKmo9s0o
JKtXHe4zh4RqdeSSM4MhkkgM9EuKwq0t8wRG2hpTJQ6dT-54rrXF5zrg3KbFi9wB
0QwO3Nuxatp_55dKjjC29xkqXHD4Z9Ag
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "478abbfde5dba6f2d428aff45f804c02d14a1eb9"
}
```

```json
{
  "at_hash": "YCqerZszBfXdKdGjKT_V-Q",
  "aud": "wireapp",
  "c_hash": "VU2DT_VQ255uVsj6p4LpTg",
  "exp": 1690882072,
  "iat": 1690795672,
  "iss": "http://dex:16002/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "VF-FNsxNvIl1kEJQzZ-Fwg",
  "preferred_username": "Alice Smith",
  "sub": "Ck9pbTp3aXJlYXBwPU5qWTNOVFZoTkdZek16RTROR0ZqTURneU9HUTVaVFpoT0dNM056WXhOVEkvZWY2YTkxYTkxZDMzMzdhQHdpcmUuY29tEgRsZGFw"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7lT4uYG5Iae9FvxQ4oPW
N4uD06dT+tCYenEUZyTTXQBobolqbuf21ggWDBx9Mh7u8nFD3cdGF/gmVaJnxHQA
bAdr48R0Pv9hbd4RGNrYiiR1rmyB7Dp4kpdn1Jwvdlwxrr8jNPMOQ7LhFO31I3DK
9YykHuFPKP/3YEbb3Ek3OvprsCpZbJ6FJcj9QkBAULwLIshMytLY5y+vWtq+wICg
2rYMFcCYPNbBD8TjfWq1vWsFIyjXbGqWXMLq7r+crdi9QHrPYD/aQ4dZGweV+FCa
EWLvQVLNJSO4G8bgonuokj92A1//+4jN5xqqbreokygSYTOSOVbR+qooGLb0nm+O
cwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/n5FFoVwi6IonK80GtLFgpG18ZoKEXoqQ
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L0lZRk5jNEEwYWVTcEhPVmFxT0wzNjZPb1ZOQlBVczFmIiwidHlwIjoiSldUIiwibm9uY2UiOiJNWEprU1dJeVVGWmlOMDl6VVhsWWFqTllaV05uVkhWRFl6WTRiMU5CYmpnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL2NoYWxsZW5nZS9WUmFUNGNCcjFlWXZSSHpVMm5YQXlUMnBVZ3pVYzlFUy9uNUZGb1Z3aTZJb25LODBHdExGZ3BHMThab0tFWG9xUSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJalEzT0dGaVltWmtaVFZrWW1FMlpqSmtOREk0WVdabU5EVm1PREEwWXpBeVpERTBZVEZsWWpraWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTJNREF5TDJSbGVDSXNJbk4xWWlJNklrTnJPWEJpVkhBellWaEtiRmxZUW5kUVZUVnhWMVJPVDFaR1dtOVVhMlJhWldzeE5sSlVVazlTTUZweFZGVlNibVZWT1VoVlZGWmhWa1p3YjFRd1pFNU5NRFUyVjFob1QxWkZhM1phVjFreVdWUnJlRmxVYTNoYVJFMTZUWHBrYUZGSVpIQmpiVlYxV1RJNWRFVm5Vbk5hUjBaM0lpd2lZWFZrSWpvaWQybHlaV0Z3Y0NJc0ltVjRjQ0k2TVRZNU1EZzRNakEzTWl3aWFXRjBJam94Tmprd056azFOamN5TENKdWIyNWpaU0k2SWxaR0xVWk9jM2hPZGtsc01XdEZTbEY2V2kxR2QyY2lMQ0poZEY5b1lYTm9Jam9pV1VOeFpYSmFjM3BDWmxoa1MyUkhha3RVWDFZdFVTSXNJbU5mYUdGemFDSTZJbFpWTWtSVVgxWlJNalUxZFZaemFqWndORXh3VkdjaUxDSnVZVzFsSWpvaWFXMDZkMmx5WldGd2NEMWhiR2xqWlY5M2FYSmxJaXdpY0hKbFptVnljbVZrWDNWelpYSnVZVzFsSWpvaVFXeHBZMlVnVTIxcGRHZ2lmUS5DVUxySjE0eUdvZUpPSlk3YW01cnFYallvUTdpOUthOFZ0Z1Z2T0RIbTVJc3pIZnE3c0p2UG9CSDJoRlpyWjhSZTFmWFU1Y2xpNTVza0R4a3NPSWxVb29NeUdRdXFNOGJ2d3o3Tm9PU0p4NG5qRU5CWVJxWW9zVVZsbFQxdWdXbGVHaFRqWnJUdzV0UHkyVGlmU1dTVlhtamsyUjBsUmNGLXlPdjNZV1JKdFBuT2dSaVFJaTUwR3p2ZlpsWmdlcEN4eUFKc05wcXlZZm1DZFpGQmZGVk9aS0xVMTlqZlYtQkNFOVM1SmlHZ3dOZGdNdEttbzlzMG9KS3RYSGU0emg0UnFkZVNTTTRNaGtrZ005RXVLd3EwdDh3UkcyaHBUSlE2ZFQtNTRyclhGNXpyZzNLYkZpOXdCMFF3TzNOdXhhdHBfNTVkS2pqQzI5eGtxWEhENFo5QWciLCJrZXlhdXRoIjoiUG1QTDVpZkNIZUJ2b2VHVGo3aWRDaWVhQ2tPTnY5QmgudXlsTUhqb2U4RlpZSmFZUVFNUGJBQUNXTWc2UGFUNEFkQVF4OHRncGRvQSJ9",
  "signature": "vJT1Qr1TYbaTcxz11k3aCNC7kjrpsLU4h-ZSY8XOYLE8kFkxbsAntmkyqO33edvMAmnQsDsBJAwJfXmLx8A0Cw"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjQ3OGFiYmZkZTVkYmE2ZjJkNDI4YWZmNDVmODA0YzAyZDE0YTFlYjkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2MDAyL2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVxV1ROT1ZGWm9Ua2RaZWsxNlJUUk9SMFpxVFVSbmVVOUhVVFZhVkZwb1QwZE5NMDU2V1hoT1ZFa3ZaV1kyWVRreFlUa3haRE16TXpkaFFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY5MDg4MjA3MiwiaWF0IjoxNjkwNzk1NjcyLCJub25jZSI6IlZGLUZOc3hOdklsMWtFSlF6Wi1Gd2ciLCJhdF9oYXNoIjoiWUNxZXJac3pCZlhkS2RHaktUX1YtUSIsImNfaGFzaCI6IlZVMkRUX1ZRMjU1dVZzajZwNExwVGciLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZV93aXJlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.CULrJ14yGoeJOJY7am5rqXjYoQ7i9Ka8VtgVvODHm5IszHfq7sJvPoBH2hFZrZ8Re1fXU5cli55skDxksOIlUooMyGQuqM8bvwz7NoOSJx4njENBYRqYosUVllT1ugWleGhTjZrTw5tPy2TifSWSVXmjk2R0lRcF-yOv3YWRJtPnOgRiQIi50GzvfZlZgepCxyAJsNpqyYfmCdZFBfFVOZKLU19jfV-BCE9S5JiGgwNdgMtKmo9s0oJKtXHe4zh4RqdeSSM4MhkkgM9EuKwq0t8wRG2hpTJQ6dT-54rrXF5zrg3KbFi9wB0QwO3Nuxatp_55dKjjC29xkqXHD4Z9Ag",
    "keyauth": "PmPL5ifCHeBvoeGTj7idCieaCkONv9Bh.uylMHjoe8FZYJaYQQMPbAACWMg6PaT4AdAQx8tgpdoA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/IYFNc4A0aeSpHOVaqOL366OoVNBPUs1f",
    "nonce": "MXJkSWIyUFZiN09zUXlYajNYZWNnVHVDYzY4b1NBbjg",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/n5FFoVwi6IonK80GtLFgpG18ZoKEXoqQ"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
link: <https://stepca:32787/acme/wire/authz/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES>;rel="up"
location: https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/n5FFoVwi6IonK80GtLFgpG18ZoKEXoqQ
replay-nonce: bUxONUhqOHhFVERFam1YYTVQSm1YYXpNVVRyb3N1dlY
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32787/acme/wire/challenge/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES/n5FFoVwi6IonK80GtLFgpG18ZoKEXoqQ",
  "status": "valid",
  "token": "PmPL5ifCHeBvoeGTj7idCieaCkONv9Bh",
  "target": "http://dex:16002/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L0lZRk5jNEEwYWVTcEhPVmFxT0wzNjZPb1ZOQlBVczFmIiwidHlwIjoiSldUIiwibm9uY2UiOiJiVXhPTlVocU9IaEZWRVJGYW0xWVlUVlFTbTFZWVhwTlZWUnliM04xZGxZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL29yZGVyL055dU1wQkVkQ2hqSTV3bzRFSkVGUU9qdmI2M1g2OE5aIn0",
  "payload": "",
  "signature": "0elETVng1gkKkMgQF_eTf5kBc-R--GcRFitnxUh65o16douTBodbhG56V1Cdudbcik3E_zkXaqvinpf6oOyADw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/IYFNc4A0aeSpHOVaqOL366OoVNBPUs1f",
    "nonce": "bUxONUhqOHhFVERFam1YYTVQSm1YYXpNVVRyb3N1dlY",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
location: https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ
replay-nonce: UFdkTzBJT0VuMVVMTFlZdmhmSzBuaU45MjdsV2JRMEQ
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32787/acme/wire/authz/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES"
  ],
  "expires": "2023-08-01T09:27:52Z",
  "notBefore": "2023-07-31T09:27:52.754636Z",
  "notAfter": "2033-07-28T09:27:52.754636Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L0lZRk5jNEEwYWVTcEhPVmFxT0wzNjZPb1ZOQlBVczFmIiwidHlwIjoiSldUIiwibm9uY2UiOiJVRmRrVHpCSlQwVnVNVlZNVEZsWmRtaG1TekJ1YVU0NU1qZHNWMkpSTUVRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL29yZGVyL055dU1wQkVkQ2hqSTV3bzRFSkVGUU9qdmI2M1g2OE5aL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTnpDQjZnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBSzFpRDAySldTdzlEWTZ5QkE4SmV1TmswUi0wY1YyX1lBSjJvNXp0R200YW9JR0ZNSUdDQmdrcWhraUc5dzBCQ1E0eGRUQnpNSEVHQTFVZEVRUnFNR2lHVDJsdE9uZHBjbVZoY0hBOVRtcFpNMDVVVm1oT1IxbDZUWHBGTkU1SFJtcE5SR2Q1VDBkUk5WcFVXbWhQUjAwelRucFplRTVVU1M5bFpqWmhPVEZoT1RGa016TXpOMkZBZDJseVpTNWpiMjJHRldsdE9uZHBjbVZoY0hBOVlXeHBZMlZmZDJseVpUQUZCZ01yWlhBRFFRQUZiMXhKcEEzLXZkS3U3MWM5cEktM2otN0tYVVpURHhYTTdhMUFmcmRJTl81OVdGWlZrOHpIZWZqdjBLYi1YLXRmektVM05WYmFGLXFMSjRSdWlIY0oifQ",
  "signature": "5XYPjUdteFrGtUnlINgVacNZpmtDvXqavafhVEJT-ZYSDQq-l9dc_NoHVDIS6zLzFcmDt5e68vr_g0GiktnWCA"
}
```
```json
{
  "payload": {
    "csr": "MIIBNzCB6gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAK1iD02JWSw9DY6yBA8JeuNk0R-0cV2_YAJ2o5ztGm4aoIGFMIGCBgkqhkiG9w0BCQ4xdTBzMHEGA1UdEQRqMGiGT2ltOndpcmVhcHA9TmpZM05UVmhOR1l6TXpFNE5HRmpNRGd5T0dRNVpUWmhPR00zTnpZeE5USS9lZjZhOTFhOTFkMzMzN2FAd2lyZS5jb22GFWltOndpcmVhcHA9YWxpY2Vfd2lyZTAFBgMrZXADQQAFb1xJpA3-vdKu71c9pI-3j-7KXUZTDxXM7a1AfrdIN_59WFZVk8zHefjv0Kb-X-tfzKU3NVbaF-qLJ4RuiHcJ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/IYFNc4A0aeSpHOVaqOL366OoVNBPUs1f",
    "nonce": "UFdkTzBJT0VuMVVMTFlZdmhmSzBuaU45MjdsV2JRMEQ",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBNzCB6gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAK1iD02JWSw9DY6yBA8JeuNk0R+0cV2/
YAJ2o5ztGm4aoIGFMIGCBgkqhkiG9w0BCQ4xdTBzMHEGA1UdEQRqMGiGT2ltOndp
cmVhcHA9TmpZM05UVmhOR1l6TXpFNE5HRmpNRGd5T0dRNVpUWmhPR00zTnpZeE5U
SS9lZjZhOTFhOTFkMzMzN2FAd2lyZS5jb22GFWltOndpcmVhcHA9YWxpY2Vfd2ly
ZTAFBgMrZXADQQAFb1xJpA3+vdKu71c9pI+3j+7KXUZTDxXM7a1AfrdIN/59WFZV
k8zHefjv0Kb+X+tfzKU3NVbaF+qLJ4RuiHcJ
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
                    ad:62:0f:4d:89:59:2c:3d:0d:8e:b2:04:0f:09:7a:
                    e3:64:d1:1f:b4:71:5d:bf:60:02:76:a3:9c:ed:1a:
                    6e:1a
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        05:6f:5c:49:a4:0d:fe:bd:d2:ae:ef:57:3d:a4:8f:b7:8f:ee:
        ca:5d:46:53:0f:15:cc:ed:ad:40:7e:b7:48:37:fe:7d:58:56:
        55:93:cc:c7:79:f8:ef:d0:a6:fe:5f:eb:5f:cc:a5:37:35:56:
        da:17:ea:8b:27:84:6e:88:77:09

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32787/acme/wire/directory>;rel="index"
location: https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ
replay-nonce: dVZEY3EzMENsOVB5TTdqQ0xLUGNMa3FyT2MwNHV0cUI
```
```json
{
  "certificate": "https://stepca:32787/acme/wire/certificate/DHrQ0c6czMSXpJlF36wt0PptFHMLvmQW",
  "status": "valid",
  "finalize": "https://stepca:32787/acme/wire/order/NyuMpBEdChjI5wo4EJEFQOjvb63X68NZ/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32787/acme/wire/authz/VRaT4cBr1eYvRHzU2nXAyT2pUgzUc9ES"
  ],
  "expires": "2023-08-01T09:27:52Z",
  "notBefore": "2023-07-31T09:27:52.754636Z",
  "notAfter": "2033-07-28T09:27:52.754636Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32787/acme/wire/certificate/DHrQ0c6czMSXpJlF36wt0PptFHMLvmQW
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzg3L2FjbWUvd2lyZS9hY2NvdW50L0lZRk5jNEEwYWVTcEhPVmFxT0wzNjZPb1ZOQlBVczFmIiwidHlwIjoiSldUIiwibm9uY2UiOiJkVlpFWTNFek1FTnNPVkI1VFRkcVEweExVR05NYTNGeVQyTXdOSFYwY1VJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3ODcvYWNtZS93aXJlL2NlcnRpZmljYXRlL0RIclEwYzZjek1TWHBKbEYzNnd0MFBwdEZITUx2bVFXIn0",
  "payload": "",
  "signature": "mzZC9WlQbqH-bO5sudSf7EyJg5785mHeB5tgkJWmaXtGv3K23mEU-P1nvhdPQM2pAK1Y6OBiUrjPBqb0w8cECQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32787/acme/wire/account/IYFNc4A0aeSpHOVaqOL366OoVNBPUs1f",
    "nonce": "dVZEY3EzMENsOVB5TTdqQ0xLUGNMa3FyT2MwNHV0cUI",
    "typ": "JWT",
    "url": "https://stepca:32787/acme/wire/certificate/DHrQ0c6czMSXpJlF36wt0PptFHMLvmQW"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32787/acme/wire/directory>;rel="index"
replay-nonce: UE0xWkY2UWp0ald5M1BNZzdpc3R5QTBkdzBIOGNJNGg
```
```json
"-----BEGIN CERTIFICATE-----\nMIICITCCAcegAwIBAgIQR1p0BYNat2/TaZ6fQ0VMEzAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzA3MzEwOTI3NTJaFw0zMzA3MjgwOTI3NTJaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAK1iD02JWSw9DY6yBA8J\neuNk0R+0cV2/YAJ2o5ztGm4ao4H6MIH3MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQU9r3Fgf8j7EW1YqMX5PJRTnzP2JowHwYD\nVR0jBBgwFoAUKrfsq6lXfJxv+1K6ZqL+nQF7JM8wcQYDVR0RBGowaIYVaW06d2ly\nZWFwcD1hbGljZV93aXJlhk9pbTp3aXJlYXBwPU5qWTNOVFZoTkdZek16RTROR0Zq\nTURneU9HUTVaVFpoT0dNM056WXhOVEkvZWY2YTkxYTkxZDMzMzdhQHdpcmUuY29t\nMB0GDCsGAQQBgqRkxihAAQQNMAsCAQYEBHdpcmUEADAKBggqhkjOPQQDAgNIADBF\nAiEAnF9mIGN0oYJoK9wdCKFKa7nMrdmQFn/jpPW6c8XaaegCIA44rKycEh1zHB/W\n0lQDi9BobI4bjNc3KI3xDXTBQ8zD\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV+gAwIBAgIRANQWShCNltymDyF5wZjoItswCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDczMTA5\nMjc1MVoXDTMzMDcyODA5Mjc1MVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASx\nZNVsvP/BinJ2Vr7b2cC5jIHATJRsR9d3JdIdh7GArgsE4dHns1U3N6cbR5UYI1UA\n3L07+DFTYTw/SnC78mdko2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUKrfsq6lXfJxv+1K6ZqL+nQF7JM8wHwYDVR0jBBgw\nFoAUHk5gRHkSTo8fs6gmiZKhCaDi3ggwCgYIKoZIzj0EAwIDRwAwRAIgS7eV9Ev8\naOI/WLLaRhqzwgJML557AUybtMmpygAbRCQCIGnlpyv2NvRTaRahYV1ZlB5VXMxQ\nsjraUYrz4GWJu9Kg\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICITCCAcegAwIBAgIQR1p0BYNat2/TaZ6fQ0VMEzAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzA3MzEwOTI3NTJaFw0zMzA3MjgwOTI3NTJaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAK1iD02JWSw9DY6yBA8J
euNk0R+0cV2/YAJ2o5ztGm4ao4H6MIH3MA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQU9r3Fgf8j7EW1YqMX5PJRTnzP2JowHwYD
VR0jBBgwFoAUKrfsq6lXfJxv+1K6ZqL+nQF7JM8wcQYDVR0RBGowaIYVaW06d2ly
ZWFwcD1hbGljZV93aXJlhk9pbTp3aXJlYXBwPU5qWTNOVFZoTkdZek16RTROR0Zq
TURneU9HUTVaVFpoT0dNM056WXhOVEkvZWY2YTkxYTkxZDMzMzdhQHdpcmUuY29t
MB0GDCsGAQQBgqRkxihAAQQNMAsCAQYEBHdpcmUEADAKBggqhkjOPQQDAgNIADBF
AiEAnF9mIGN0oYJoK9wdCKFKa7nMrdmQFn/jpPW6c8XaaegCIA44rKycEh1zHB/W
0lQDi9BobI4bjNc3KI3xDXTBQ8zD
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            47:5a:74:05:83:5a:b7:6f:d3:69:9e:9f:43:45:4c:13
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Jul 31 09:27:52 2023 GMT
            Not After : Jul 28 09:27:52 2033 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    ad:62:0f:4d:89:59:2c:3d:0d:8e:b2:04:0f:09:7a:
                    e3:64:d1:1f:b4:71:5d:bf:60:02:76:a3:9c:ed:1a:
                    6e:1a
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                F6:BD:C5:81:FF:23:EC:45:B5:62:A3:17:E4:F2:51:4E:7C:CF:D8:9A
            X509v3 Authority Key Identifier: 
                2A:B7:EC:AB:A9:57:7C:9C:6F:FB:52:BA:66:A2:FE:9D:01:7B:24:CF
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice_wire, URI:im:wireapp=NjY3NTVhNGYzMzE4NGFjMDgyOGQ5ZTZhOGM3NzYxNTI/ef6a91a91d3337a@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:9c:5f:66:20:63:74:a1:82:68:2b:dc:1d:08:
        a1:4a:6b:b9:cc:ad:d9:90:16:7f:e3:a4:f5:ba:73:c5:da:69:
        e8:02:20:0e:38:ac:ac:9c:12:1d:73:1c:1f:d6:d2:54:03:8b:
        d0:68:6c:8e:1b:8c:d7:37:28:8d:f1:0d:74:c1:43:cc:c3

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV+gAwIBAgIRANQWShCNltymDyF5wZjoItswCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDczMTA5
Mjc1MVoXDTMzMDcyODA5Mjc1MVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASx
ZNVsvP/BinJ2Vr7b2cC5jIHATJRsR9d3JdIdh7GArgsE4dHns1U3N6cbR5UYI1UA
3L07+DFTYTw/SnC78mdko2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUKrfsq6lXfJxv+1K6ZqL+nQF7JM8wHwYDVR0jBBgw
FoAUHk5gRHkSTo8fs6gmiZKhCaDi3ggwCgYIKoZIzj0EAwIDRwAwRAIgS7eV9Ev8
aOI/WLLaRhqzwgJML557AUybtMmpygAbRCQCIGnlpyv2NvRTaRahYV1ZlB5VXMxQ
sjraUYrz4GWJu9Kg
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            d4:16:4a:10:8d:96:dc:a6:0f:21:79:c1:98:e8:22:db
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Jul 31 09:27:51 2023 GMT
            Not After : Jul 28 09:27:51 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:b1:64:d5:6c:bc:ff:c1:8a:72:76:56:be:db:d9:
                    c0:b9:8c:81:c0:4c:94:6c:47:d7:77:25:d2:1d:87:
                    b1:80:ae:0b:04:e1:d1:e7:b3:55:37:37:a7:1b:47:
                    95:18:23:55:00:dc:bd:3b:f8:31:53:61:3c:3f:4a:
                    70:bb:f2:67:64
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                2A:B7:EC:AB:A9:57:7C:9C:6F:FB:52:BA:66:A2:FE:9D:01:7B:24:CF
            X509v3 Authority Key Identifier: 
                1E:4E:60:44:79:12:4E:8F:1F:B3:A8:26:89:92:A1:09:A0:E2:DE:08
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:4b:b7:95:f4:4b:fc:68:e2:3f:58:b2:da:46:1a:
        b3:c2:02:4c:2f:9e:7b:01:4c:9b:b4:c9:a9:ca:00:1b:44:24:
        02:20:69:e5:a7:2b:f6:36:f4:53:69:16:a1:61:5d:59:94:1e:
        55:5c:cc:50:b2:3a:da:51:8a:f3:e0:65:89:bb:d2:a0

```
