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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/594930e9d50bb175/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/cd3ux1eT49wplLh1ZeXME3XJevdHsg32
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/vKyRRuY8f4gJNdDvqsh6LOghzkA84IGb
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/oKaQdQpJTCU47Q1MxNjRIGhPL4zoT0Zh
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:33174/acme/wire/directory
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
  "newNonce": "https://stepca:33174/acme/wire/new-nonce",
  "newAccount": "https://stepca:33174/acme/wire/new-account",
  "newOrder": "https://stepca:33174/acme/wire/new-order",
  "revokeCert": "https://stepca:33174/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:33174/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:33174/acme/wire/directory>;rel="index"
replay-nonce: d3Fjc3UzUjZEOHplR0dwb2VoVVhZbUNsM3FNSk5DSmY
vary: Origin
```
```text
d3Fjc3UzUjZEOHplR0dwb2VoVVhZbUNsM3FNSk5DSmY
```
#### 5. create a new account
```http request
POST https://stepca:33174/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImNzX1pSM3FIY1czUUM4SVBBcXdMZmhOUXpUV1VvTkwwZGFJWENxSDRlZEEifSwibm9uY2UiOiJkM0ZqYzNVelVqWkVPSHBsUjBkd2IyVm9WVmhaYlVOc00zRk5TazVEU21ZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMxNzQvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "tGKNJO-s4-iK5GojUY6u0BYo6h_FOX-P_Dy01jhz4OSQRoQQavY0_qokDY4HK4_dNIlSMlRiCTLgF5nu0dJZAQ"
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
      "x": "cs_ZR3qHcW3QC8IPAqwLfhNQzTWUoNL0daIXCqH4edA"
    },
    "nonce": "d3Fjc3UzUjZEOHplR0dwb2VoVVhZbUNsM3FNSk5DSmY",
    "typ": "JWT",
    "url": "https://stepca:33174/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33174/acme/wire/directory>;rel="index"
location: https://stepca:33174/acme/wire/account/DGf1QYeVK8HhTncCkIFuQBz2IFzxlHSZ
replay-nonce: SWdJa2FTQTk5QkxicjNkUnJja3Z4M0pFRUFZRlVsNm0
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:33174/acme/wire/account/DGf1QYeVK8HhTncCkIFuQBz2IFzxlHSZ/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:33174/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMTc0L2FjbWUvd2lyZS9hY2NvdW50L0RHZjFRWWVWSzhIaFRuY0NrSUZ1UUJ6MklGenhsSFNaIiwidHlwIjoiSldUIiwibm9uY2UiOiJTV2RKYTJGVFFUazVRa3hpY2pOa1VuSmphM1o0TTBwRlJVRlpSbFZzTm0wIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMxNzQvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9Q3piZkZqRE9RcmVuQ2JEeFZtZ25Gdy81OTQ5MzBlOWQ1MGJiMTc1QHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMS0wNFQxNTo0MTo1Ni43NzMyOTRaIiwibm90QWZ0ZXIiOiIyMDM0LTAxLTAxVDE1OjQxOjU2Ljc3MzI5NFoifQ",
  "signature": "1mwzVjyPuvrUIZ51gAKnIynOI8eprgxNKGaTLb2h_mSWB3Ri48WKg3irJslNphnliwdNyCTEy4OC-0hNfmzcBw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2034-01-01T15:41:56.773294Z",
    "notBefore": "2024-01-04T15:41:56.773294Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33174/acme/wire/account/DGf1QYeVK8HhTncCkIFuQBz2IFzxlHSZ",
    "nonce": "SWdJa2FTQTk5QkxicjNkUnJja3Z4M0pFRUFZRlVsNm0",
    "typ": "JWT",
    "url": "https://stepca:33174/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33174/acme/wire/directory>;rel="index"
location: https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3
replay-nonce: RUxzN3J2VUJPNDhpMFFoR3psb1RCNndESkxKNG1zbjQ
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33174/acme/wire/authz/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x"
  ],
  "expires": "2024-01-05T15:41:56Z",
  "notBefore": "2024-01-04T15:41:56.773294Z",
  "notAfter": "2034-01-01T15:41:56.773294Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:33174/acme/wire/authz/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMTc0L2FjbWUvd2lyZS9hY2NvdW50L0RHZjFRWWVWSzhIaFRuY0NrSUZ1UUJ6MklGenhsSFNaIiwidHlwIjoiSldUIiwibm9uY2UiOiJSVXh6TjNKMlZVSlBORGhwTUZGb1IzcHNiMVJDTm5kRVNreEtORzF6YmpRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMxNzQvYWNtZS93aXJlL2F1dGh6L0ZLU2lZd1NZODlHVUlMbGU4NFFzejhSVzNrS1Z6VzZ4In0",
  "payload": "",
  "signature": "68xYgurw85TPRVRZcTI20fH1YaV4s8Jtu3t6IccnLX3HFE07oZ6gY1ybiw6zvdxBIwHsMaINypwhH8LDIRa4Aw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33174/acme/wire/account/DGf1QYeVK8HhTncCkIFuQBz2IFzxlHSZ",
    "nonce": "RUxzN3J2VUJPNDhpMFFoR3psb1RCNndESkxKNG1zbjQ",
    "typ": "JWT",
    "url": "https://stepca:33174/acme/wire/authz/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33174/acme/wire/directory>;rel="index"
location: https://stepca:33174/acme/wire/authz/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x
replay-nonce: bDAxS3VDbmJ4MmI3THg4Q3hKdVNicG13WjN4eDYxZHk
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2024-01-05T15:41:56Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/vKyRRuY8f4gJNdDvqsh6LOghzkA84IGb",
      "status": "pending",
      "token": "Q0RPbim7bgWVpDQ9E3O6YfREBqJIBHDe",
      "target": "http://dex:23482/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/cd3ux1eT49wplLh1ZeXME3XJevdHsg32",
      "status": "pending",
      "token": "Q0RPbim7bgWVpDQ9E3O6YfREBqJIBHDe",
      "target": "http://wire.com:21515/clients/594930e9d50bb175/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:21515/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
RlRDanFSb3IyUWs3aHBzUVJ5Z3VNcGFDajJETGdWS2g
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiY3NfWlIzcUhjVzNRQzhJUEFxd0xmaE5RelRXVW9OTDBkYUlYQ3FINGVkQSJ9fQ.eyJpYXQiOjE3MDQzNzkzMTYsImV4cCI6MTcwNDM4NjUxNiwibmJmIjoxNzA0Mzc5MzE2LCJzdWIiOiJpbTp3aXJlYXBwPUN6YmZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJlLmNvbSIsImp0aSI6IjYzNjcxOWFkLTVlZDQtNGI4MS04YmM4LWI5MTQ1NzNjMDg5OCIsIm5vbmNlIjoiUmxSRGFuRlNiM0l5VVdzM2FIQnpVVko1WjNWTmNHRkRhakpFVEdkV1MyZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjE1MTUvY2xpZW50cy81OTQ5MzBlOWQ1MGJiMTc1L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJRMFJQYmltN2JnV1ZwRFE5RTNPNllmUkVCcUpJQkhEZSIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.yGTxaI2SHYfebmCnCxesg2sztuJILhYybBa0fzmK0JUPQ2m9RlkwDv9tEhtEm4F0p2fIFrblPjL_vLyoJ_4cDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiY3NfWlIzcUhjVzNRQzhJUEFxd0xmaE5R
elRXVW9OTDBkYUlYQ3FINGVkQSJ9fQ.eyJpYXQiOjE3MDQzNzkzMTYsImV4cCI6M
TcwNDM4NjUxNiwibmJmIjoxNzA0Mzc5MzE2LCJzdWIiOiJpbTp3aXJlYXBwPUN6Y
mZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJlLmNvbSIsI
mp0aSI6IjYzNjcxOWFkLTVlZDQtNGI4MS04YmM4LWI5MTQ1NzNjMDg5OCIsIm5vb
mNlIjoiUmxSRGFuRlNiM0l5VVdzM2FIQnpVVko1WjNWTmNHRkRhakpFVEdkV1MyZ
yIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjE1MTUvY2xpZ
W50cy81OTQ5MzBlOWQ1MGJiMTc1L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJRMFJQY
mltN2JnV1ZwRFE5RTNPNllmUkVCcUpJQkhEZSIsImhhbmRsZSI6ImltOndpcmVhc
HA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.yGTxaI2SH
YfebmCnCxesg2sztuJILhYybBa0fzmK0JUPQ2m9RlkwDv9tEhtEm4F0p2fIFrblP
jL_vLyoJ_4cDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "cs_ZR3qHcW3QC8IPAqwLfhNQzTWUoNL0daIXCqH4edA"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "Q0RPbim7bgWVpDQ9E3O6YfREBqJIBHDe",
  "exp": 1704386516,
  "handle": "im:wireapp=%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:21515/clients/594930e9d50bb175/access-token",
  "iat": 1704379316,
  "jti": "636719ad-5ed4-4b81-8bc8-b914573c0898",
  "nbf": 1704379316,
  "nonce": "RlRDanFSb3IyUWs3aHBzUVJ5Z3VNcGFDajJETGdWS2g",
  "sub": "im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPMOsVPdSPeBQw16ZblF61tPBsBZeurlVJGf40c7R4MQ
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcs/ZR3qHcW3QC8IPAqwLfhNQzTWUoNL0daIXCqH4edA=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:21515/clients/594930e9d50bb175/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pWTNOZldsSXpjVWhqVnpOUlF6aEpVRUZ4ZDB4bWFFNVJlbFJYVlc5T1REQmtZVWxZUTNGSU5HVmtRU0o5ZlEuZXlKcFlYUWlPakUzTURRek56a3pNVFlzSW1WNGNDSTZNVGN3TkRNNE5qVXhOaXdpYm1KbUlqb3hOekEwTXpjNU16RTJMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVU42WW1aR2FrUlBVWEpsYmtOaVJIaFdiV2R1Um5jdk5UazBPVE13WlRsa05UQmlZakUzTlVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpZek5qY3hPV0ZrTFRWbFpEUXROR0k0TVMwNFltTTRMV0k1TVRRMU56TmpNRGc1T0NJc0ltNXZibU5sSWpvaVVteFNSR0Z1UmxOaU0wbDVWVmR6TTJGSVFucFZWa28xV2pOV1RtTkhSa1JoYWtwRlZFZGtWMU15WnlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qRTFNVFV2WTJ4cFpXNTBjeTgxT1RRNU16QmxPV1ExTUdKaU1UYzFMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lKUk1GSlFZbWx0TjJKblYxWndSRkU1UlROUE5sbG1Va1ZDY1VwSlFraEVaU0lzSW1oaGJtUnNaU0k2SW1sdE9uZHBjbVZoY0hBOUpUUXdZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW5SbFlXMGlPaUozYVhKbEluMC55R1R4YUkyU0hZZmVibUNuQ3hlc2cyc3p0dUpJTGhZeWJCYTBmem1LMEpVUFEybTlSbGt3RHY5dEVodEVtNEYwcDJmSUZyYmxQakxfdkx5b0pfNGNEdw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkVydjlDZEg4Nm9taHhfeC1zYko5dENXRElxZUkyRm9UTVpweTJDTnV0cE0ifX0.eyJpYXQiOjE3MDQzNzkzMTYsImV4cCI6MTcwNDM4MzI3NiwibmJmIjoxNzA0Mzc5MzE2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjE1MTUvY2xpZW50cy81OTQ5MzBlOWQ1MGJiMTc1L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9Q3piZkZqRE9RcmVuQ2JEeFZtZ25Gdy81OTQ5MzBlOWQ1MGJiMTc1QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIxNTE1L2NsaWVudHMvNTk0OTMwZTlkNTBiYjE3NS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJjMDg4YjE2Ni03MTI2LTQ5ZTgtYWE5Zi0zOTg0OGQzZGM5NDEiLCJub25jZSI6IlJsUkRhbkZTYjNJeVVXczNhSEJ6VVZKNVozVk5jR0ZEYWpKRVRHZFdTMmciLCJjaGFsIjoiUTBSUGJpbTdiZ1dWcERROUUzTzZZZlJFQnFKSUJIRGUiLCJjbmYiOnsia2lkIjoidVhhUVJ3YWttQTFtX3Q0a084OUlSQ3NKV1NlR2hfU2xzMHU5eWhXTm95MCJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVkzTmZXbEl6Y1VoalZ6TlJRemhKVUVGeGQweG1hRTVSZWxSWFZXOU9UREJrWVVsWVEzRklOR1ZrUVNKOWZRLmV5SnBZWFFpT2pFM01EUXpOemt6TVRZc0ltVjRjQ0k2TVRjd05ETTROalV4Tml3aWJtSm1Jam94TnpBME16YzVNekUyTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFVONlltWkdha1JQVVhKbGJrTmlSSGhXYldkdVJuY3ZOVGswT1RNd1pUbGtOVEJpWWpFM05VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqWXpOamN4T1dGa0xUVmxaRFF0TkdJNE1TMDRZbU00TFdJNU1UUTFOek5qTURnNU9DSXNJbTV2Ym1ObElqb2lVbXhTUkdGdVJsTmlNMGw1VlZkek0yRklRbnBWVmtvMVdqTldUbU5IUmtSaGFrcEZWRWRrVjFNeVp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakUxTVRVdlkyeHBaVzUwY3k4MU9UUTVNekJsT1dRMU1HSmlNVGMxTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSlJNRkpRWW1sdE4ySm5WMVp3UkZFNVJUTlBObGxtVWtWQ2NVcEpRa2hFWlNJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAueUdUeGFJMlNIWWZlYm1DbkN4ZXNnMnN6dHVKSUxoWXliQmEwZnptSzBKVVBRMm05Umxrd0R2OXRFaHRFbTRGMHAyZklGcmJsUGpMX3ZMeW9KXzRjRHciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUN6YmZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.kR1ox0dLsr3C62sszjkH4ZaER-Q8t7n5GWzYwloHXCkv9arMXcZECMIpuiMMvwupMoleb14NVbHhptsCFp3WCw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkVydjlDZEg4Nm9taHhfeC1zYko5dENXRElxZUkyRm9UTVpweTJDTnV0cE0ifX0.eyJpYXQiOjE3MDQzNzkzMTYsImV4cCI6MTcwNDM4MzI3NiwibmJmIjoxNzA0Mzc5MzE2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjE1MTUvY2xpZW50cy81OTQ5MzBlOWQ1MGJiMTc1L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9Q3piZkZqRE9RcmVuQ2JEeFZtZ25Gdy81OTQ5MzBlOWQ1MGJiMTc1QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIxNTE1L2NsaWVudHMvNTk0OTMwZTlkNTBiYjE3NS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJjMDg4YjE2Ni03MTI2LTQ5ZTgtYWE5Zi0zOTg0OGQzZGM5NDEiLCJub25jZSI6IlJsUkRhbkZTYjNJeVVXczNhSEJ6VVZKNVozVk5jR0ZEYWpKRVRHZFdTMmciLCJjaGFsIjoiUTBSUGJpbTdiZ1dWcERROUUzTzZZZlJFQnFKSUJIRGUiLCJjbmYiOnsia2lkIjoidVhhUVJ3YWttQTFtX3Q0a084OUlSQ3NKV1NlR2hfU2xzMHU5eWhXTm95MCJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVkzTmZXbEl6Y1VoalZ6TlJRemhKVUVGeGQweG1hRTVSZWxSWFZXOU9UREJrWVVsWVEzRklOR1ZrUVNKOWZRLmV5SnBZWFFpT2pFM01EUXpOemt6TVRZc0ltVjRjQ0k2TVRjd05ETTROalV4Tml3aWJtSm1Jam94TnpBME16YzVNekUyTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFVONlltWkdha1JQVVhKbGJrTmlSSGhXYldkdVJuY3ZOVGswT1RNd1pUbGtOVEJpWWpFM05VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqWXpOamN4T1dGa0xUVmxaRFF0TkdJNE1TMDRZbU00TFdJNU1UUTFOek5qTURnNU9DSXNJbTV2Ym1ObElqb2lVbXhTUkdGdVJsTmlNMGw1VlZkek0yRklRbnBWVmtvMVdqTldUbU5IUmtSaGFrcEZWRWRrVjFNeVp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakUxTVRVdlkyeHBaVzUwY3k4MU9UUTVNekJsT1dRMU1HSmlNVGMxTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSlJNRkpRWW1sdE4ySm5WMVp3UkZFNVJUTlBObGxtVWtWQ2NVcEpRa2hFWlNJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAueUdUeGFJMlNIWWZlYm1DbkN4ZXNnMnN6dHVKSUxoWXliQmEwZnptSzBKVVBRMm05Umxrd0R2OXRFaHRFbTRGMHAyZklGcmJsUGpMX3ZMeW9KXzRjRHciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUN6YmZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.kR1ox0dLsr3C62sszjkH4ZaER-Q8t7n5GWzYwloHXCkv9arMXcZECMIpuiMMvwupMoleb14NVbHhptsCFp3WCw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IkVydjlDZEg4Nm9taHhfeC1zYko5dENXRElx
ZUkyRm9UTVpweTJDTnV0cE0ifX0.eyJpYXQiOjE3MDQzNzkzMTYsImV4cCI6MTcw
NDM4MzI3NiwibmJmIjoxNzA0Mzc5MzE2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjE1MTUvY2xpZW50cy81OTQ5MzBlOWQ1MGJiMTc1L2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9Q3piZkZqRE9RcmVuQ2JEeFZtZ25Gdy81OTQ5MzBlOWQ1
MGJiMTc1QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIxNTE1L2Ns
aWVudHMvNTk0OTMwZTlkNTBiYjE3NS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJjMDg4
YjE2Ni03MTI2LTQ5ZTgtYWE5Zi0zOTg0OGQzZGM5NDEiLCJub25jZSI6IlJsUkRh
bkZTYjNJeVVXczNhSEJ6VVZKNVozVk5jR0ZEYWpKRVRHZFdTMmciLCJjaGFsIjoi
UTBSUGJpbTdiZ1dWcERROUUzTzZZZlJFQnFKSUJIRGUiLCJjbmYiOnsia2lkIjoi
dVhhUVJ3YWttQTFtX3Q0a084OUlSQ3NKV1NlR2hfU2xzMHU5eWhXTm95MCJ9LCJw
cm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJ
aXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lM
Q0o0SWpvaVkzTmZXbEl6Y1VoalZ6TlJRemhKVUVGeGQweG1hRTVSZWxSWFZXOU9U
REJrWVVsWVEzRklOR1ZrUVNKOWZRLmV5SnBZWFFpT2pFM01EUXpOemt6TVRZc0lt
VjRjQ0k2TVRjd05ETTROalV4Tml3aWJtSm1Jam94TnpBME16YzVNekUyTENKemRX
SWlPaUpwYlRwM2FYSmxZWEJ3UFVONlltWkdha1JQVVhKbGJrTmlSSGhXYldkdVJu
Y3ZOVGswT1RNd1pUbGtOVEJpWWpFM05VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklq
WXpOamN4T1dGa0xUVmxaRFF0TkdJNE1TMDRZbU00TFdJNU1UUTFOek5qTURnNU9D
SXNJbTV2Ym1ObElqb2lVbXhTUkdGdVJsTmlNMGw1VlZkek0yRklRbnBWVmtvMVdq
TldUbU5IUmtSaGFrcEZWRWRrVjFNeVp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RI
VWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakUxTVRVdlkyeHBaVzUwY3k4MU9U
UTVNekJsT1dRMU1HSmlNVGMxTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9p
SlJNRkpRWW1sdE4ySm5WMVp3UkZFNVJUTlBObGxtVWtWQ2NVcEpRa2hFWlNJc0lt
aGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FY
SmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAueUdUeGFJMlNIWWZlYm1DbkN4
ZXNnMnN6dHVKSUxoWXliQmEwZnptSzBKVVBRMm05Umxrd0R2OXRFaHRFbTRGMHAy
ZklGcmJsUGpMX3ZMeW9KXzRjRHciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUN6
YmZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJlLmNvbSIs
ImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.kR1ox0dL
sr3C62sszjkH4ZaER-Q8t7n5GWzYwloHXCkv9arMXcZECMIpuiMMvwupMoleb14N
VbHhptsCFp3WCw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "Erv9CdH86omhx_x-sbJ9tCWDIqeI2FoTMZpy2CNutpM"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:21515/clients/594930e9d50bb175/access-token",
  "chal": "Q0RPbim7bgWVpDQ9E3O6YfREBqJIBHDe",
  "client_id": "im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com",
  "cnf": {
    "kid": "uXaQRwakmA1m_t4kO89IRCsJWSeGh_Sls0u9yhWNoy0"
  },
  "exp": 1704383276,
  "iat": 1704379316,
  "iss": "http://wire.com:21515/clients/594930e9d50bb175/access-token",
  "jti": "c088b166-7126-49e8-aa9f-39848d3dc941",
  "nbf": 1704379316,
  "nonce": "RlRDanFSb3IyUWs3aHBzUVJ5Z3VNcGFDajJETGdWS2g",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiY3NfWlIzcUhjVzNRQzhJUEFxd0xmaE5RelRXVW9OTDBkYUlYQ3FINGVkQSJ9fQ.eyJpYXQiOjE3MDQzNzkzMTYsImV4cCI6MTcwNDM4NjUxNiwibmJmIjoxNzA0Mzc5MzE2LCJzdWIiOiJpbTp3aXJlYXBwPUN6YmZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJlLmNvbSIsImp0aSI6IjYzNjcxOWFkLTVlZDQtNGI4MS04YmM4LWI5MTQ1NzNjMDg5OCIsIm5vbmNlIjoiUmxSRGFuRlNiM0l5VVdzM2FIQnpVVko1WjNWTmNHRkRhakpFVEdkV1MyZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjE1MTUvY2xpZW50cy81OTQ5MzBlOWQ1MGJiMTc1L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJRMFJQYmltN2JnV1ZwRFE5RTNPNllmUkVCcUpJQkhEZSIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.yGTxaI2SHYfebmCnCxesg2sztuJILhYybBa0fzmK0JUPQ2m9RlkwDv9tEhtEm4F0p2fIFrblPjL_vLyoJ_4cDw",
  "scope": "wire_client_id",
  "sub": "im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICyl1ujeZkhvEDKp7MYhJYTsCgF/inCfMdS0Kwa3Esq1
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAErv9CdH86omhx/x+sbJ9tCWDIqeI2FoTMZpy2CNutpM=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/cd3ux1eT49wplLh1ZeXME3XJevdHsg32
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMTc0L2FjbWUvd2lyZS9hY2NvdW50L0RHZjFRWWVWSzhIaFRuY0NrSUZ1UUJ6MklGenhsSFNaIiwidHlwIjoiSldUIiwibm9uY2UiOiJiREF4UzNWRGJtSjRNbUkzVEhnNFEzaEtkVk5pY0cxM1dqTjRlRFl4WkhrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMxNzQvYWNtZS93aXJlL2NoYWxsZW5nZS9GS1NpWXdTWTg5R1VJTGxlODRRc3o4Ulcza0tWelc2eC9jZDN1eDFlVDQ5d3BsTGgxWmVYTUUzWEpldmRIc2czMiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrVnlkamxEWkVnNE5tOXRhSGhmZUMxellrbzVkRU5YUkVseFpVa3lSbTlVVFZwd2VUSkRUblYwY0UwaWZYMC5leUpwWVhRaU9qRTNNRFF6Tnprek1UWXNJbVY0Y0NJNk1UY3dORE00TXpJM05pd2libUptSWpveE56QTBNemM1TXpFMkxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpFMU1UVXZZMnhwWlc1MGN5ODFPVFE1TXpCbE9XUTFNR0ppTVRjMUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5UTNwaVprWnFSRTlSY21WdVEySkVlRlp0WjI1R2R5ODFPVFE1TXpCbE9XUTFNR0ppTVRjMVFIZHBjbVV1WTI5dElpd2lZWFZrSWpvaWFIUjBjRG92TDNkcGNtVXVZMjl0T2pJeE5URTFMMk5zYVdWdWRITXZOVGswT1RNd1pUbGtOVEJpWWpFM05TOWhZMk5sYzNNdGRHOXJaVzRpTENKcWRHa2lPaUpqTURnNFlqRTJOaTAzTVRJMkxUUTVaVGd0WVdFNVppMHpPVGcwT0dRelpHTTVOREVpTENKdWIyNWpaU0k2SWxKc1VrUmhia1pUWWpOSmVWVlhjek5oU0VKNlZWWktOVm96Vms1alIwWkVZV3BLUlZSSFpGZFRNbWNpTENKamFHRnNJam9pVVRCU1VHSnBiVGRpWjFkV2NFUlJPVVV6VHpaWlpsSkZRbkZLU1VKSVJHVWlMQ0pqYm1ZaU9uc2lhMmxrSWpvaWRWaGhVVkozWVd0dFFURnRYM1EwYTA4NE9VbFNRM05LVjFObFIyaGZVMnh6TUhVNWVXaFhUbTk1TUNKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVZrelRtWlhiRWw2WTFWb2FsWjZUbEpSZW1oS1ZVVkdlR1F3ZUcxaFJUVlNaV3hTV0ZaWE9VOVVSRUpyV1ZWc1dWRXpSa2xPUjFaclVWTktPV1pSTG1WNVNuQlpXRkZwVDJwRk0wMUVVWHBPZW10NlRWUlpjMGx0VmpSalEwazJUVlJqZDA1RVRUUk9hbFY0VG1sM2FXSnRTbTFKYW05NFRucEJNRTE2WXpWTmVrVXlURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGVk9ObGx0V2tkaGExSlFWVmhLYkdKclRtbFNTR2hYWWxka2RWSnVZM1pPVkdzd1QxUk5kMXBVYkd0T1ZFSnBXV3BGTTA1VlFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2xxV1hwT2FtTjRUMWRHYTB4VVZteGFSRkYwVGtkSk5FMVRNRFJaYlUwMFRGZEpOVTFVVVRGT2VrNXFUVVJuTlU5RFNYTkpiVFYyWW0xT2JFbHFiMmxWYlhoVFVrZEdkVkpzVG1sTk1HdzFWbFprZWsweVJrbFJibkJXVm10dk1WZHFUbGRVYlU1SVVtdFNhR0ZyY0VaV1JXUnJWakZOZVZwNVNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWtVeFRWUlZkbGt5ZUhCYVZ6VXdZM2s0TVU5VVVUVk5la0pzVDFkUk1VMUhTbWxOVkdNeFRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTbEpOUmtwUldXMXNkRTR5U201V01WcDNVa1pGTlZKVVRsQk9iR3h0Vld0V1EyTlZjRXBSYTJoRldsTkpjMGx0YUdoaWJWSnpXbE5KTmtsdGJIUlBibVJ3WTIxV2FHTklRVGxLVkZGM1dWZDRjRmt5Vm1aa01teDVXbFZDTTJGWVNteE1iVTUyWWxOSmMwbHVVbXhaVnpCcFQybEtNMkZZU214SmJqQXVlVWRVZUdGSk1sTklXV1psWW0xRGJrTjRaWE5uTW5ONmRIVktTVXhvV1hsaVFtRXdabnB0U3pCS1ZWQlJNbTA1VW14cmQwUjJPWFJGYUhSRmJUUkdNSEF5WmtsR2NtSnNVR3BNWDNaTWVXOUtYelJqUkhjaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFVONlltWkdha1JQVVhKbGJrTmlSSGhXYldkdVJuY3ZOVGswT1RNd1pUbGtOVEJpWWpFM05VQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvMUxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLmtSMW94MGRMc3IzQzYyc3N6amtINFphRVItUTh0N241R1d6WXdsb0hYQ2t2OWFyTVhjWkVDTUlwdWlNTXZ3dXBNb2xlYjE0TlZiSGhwdHNDRnAzV0N3In0",
  "signature": "0lentZVsBBOzIIJ6H998vZaBLBS_EgE3Q_WCQx2I0NTXLPA409q3VVgbk9YPN16afEowwv82C418UH_dhN2cAg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkVydjlDZEg4Nm9taHhfeC1zYko5dENXRElxZUkyRm9UTVpweTJDTnV0cE0ifX0.eyJpYXQiOjE3MDQzNzkzMTYsImV4cCI6MTcwNDM4MzI3NiwibmJmIjoxNzA0Mzc5MzE2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjE1MTUvY2xpZW50cy81OTQ5MzBlOWQ1MGJiMTc1L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9Q3piZkZqRE9RcmVuQ2JEeFZtZ25Gdy81OTQ5MzBlOWQ1MGJiMTc1QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIxNTE1L2NsaWVudHMvNTk0OTMwZTlkNTBiYjE3NS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJjMDg4YjE2Ni03MTI2LTQ5ZTgtYWE5Zi0zOTg0OGQzZGM5NDEiLCJub25jZSI6IlJsUkRhbkZTYjNJeVVXczNhSEJ6VVZKNVozVk5jR0ZEYWpKRVRHZFdTMmciLCJjaGFsIjoiUTBSUGJpbTdiZ1dWcERROUUzTzZZZlJFQnFKSUJIRGUiLCJjbmYiOnsia2lkIjoidVhhUVJ3YWttQTFtX3Q0a084OUlSQ3NKV1NlR2hfU2xzMHU5eWhXTm95MCJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVkzTmZXbEl6Y1VoalZ6TlJRemhKVUVGeGQweG1hRTVSZWxSWFZXOU9UREJrWVVsWVEzRklOR1ZrUVNKOWZRLmV5SnBZWFFpT2pFM01EUXpOemt6TVRZc0ltVjRjQ0k2TVRjd05ETTROalV4Tml3aWJtSm1Jam94TnpBME16YzVNekUyTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFVONlltWkdha1JQVVhKbGJrTmlSSGhXYldkdVJuY3ZOVGswT1RNd1pUbGtOVEJpWWpFM05VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqWXpOamN4T1dGa0xUVmxaRFF0TkdJNE1TMDRZbU00TFdJNU1UUTFOek5qTURnNU9DSXNJbTV2Ym1ObElqb2lVbXhTUkdGdVJsTmlNMGw1VlZkek0yRklRbnBWVmtvMVdqTldUbU5IUmtSaGFrcEZWRWRrVjFNeVp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakUxTVRVdlkyeHBaVzUwY3k4MU9UUTVNekJsT1dRMU1HSmlNVGMxTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSlJNRkpRWW1sdE4ySm5WMVp3UkZFNVJUTlBObGxtVWtWQ2NVcEpRa2hFWlNJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAueUdUeGFJMlNIWWZlYm1DbkN4ZXNnMnN6dHVKSUxoWXliQmEwZnptSzBKVVBRMm05Umxrd0R2OXRFaHRFbTRGMHAyZklGcmJsUGpMX3ZMeW9KXzRjRHciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUN6YmZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.kR1ox0dLsr3C62sszjkH4ZaER-Q8t7n5GWzYwloHXCkv9arMXcZECMIpuiMMvwupMoleb14NVbHhptsCFp3WCw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33174/acme/wire/account/DGf1QYeVK8HhTncCkIFuQBz2IFzxlHSZ",
    "nonce": "bDAxS3VDbmJ4MmI3THg4Q3hKdVNicG13WjN4eDYxZHk",
    "typ": "JWT",
    "url": "https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/cd3ux1eT49wplLh1ZeXME3XJevdHsg32"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33174/acme/wire/directory>;rel="index"
link: <https://stepca:33174/acme/wire/authz/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x>;rel="up"
location: https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/cd3ux1eT49wplLh1ZeXME3XJevdHsg32
replay-nonce: NEtueEpHUldqb0NaU3lHMml0UDFNTndXTVplTHFaSDM
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/cd3ux1eT49wplLh1ZeXME3XJevdHsg32",
  "status": "valid",
  "token": "Q0RPbim7bgWVpDQ9E3O6YfREBqJIBHDe",
  "target": "http://wire.com:21515/clients/594930e9d50bb175/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=G1hNdgREzM8GfgPi7O6JKaUA7wFErlMIQFt2S6rS93I&code_challenge=kpat3oc9vxB2waGuZWW6629tZRaKXUijrCp54TXfw1M
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:23482/dex/auth?response_type=code&client_id=wireapp&state=W3GosEEp0rUUTAZsuaqCxw&code_challenge=kpat3oc9vxB2waGuZWW6629tZRaKXUijrCp54TXfw1M&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A21515%2Fcallback&scope=openid+profile&nonce=lifTrCqgEcxD5Wjg9UdM2w
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:23482/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpWRm8wY0ZkVlJISmxXRE5ETjBSTGVraE5SMUYwVVdReA==
```
```text
grant_type=authorization_code&code=tzh7iguhissh67jjnzmdwv2hc&code_verifier=G1hNdgREzM8GfgPi7O6JKaUA7wFErlMIQFt2S6rS93I&redirect_uri=http%3A%2F%2Fwire.com%3A21515%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhN2RhMmY1MjY4MTU5ODkyYmUwMDVlNDYzNWEwOGI1YTEzMjRhYzMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzNDgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVU42WW1aR2FrUlBVWEpsYmtOaVJIaFdiV2R1Um5jdk5UazBPVE13WlRsa05UQmlZakUzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQ0NjkzMTYsImlhdCI6MTcwNDM4MjkxNiwibm9uY2UiOiJsaWZUckNxZ0VjeEQ1V2pnOVVkTTJ3IiwiYXRfaGFzaCI6ImxkblZ4aUZXNkRlOUEtUHRtc2tyMmciLCJuYW1lIjoiaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.DAqDysYS5BEehIbvgDZ6JBV2bvaeibWhP8aapNBRv5Vw0-vS0UDARy-xrH8E0rh8XplmQrf-pyIm1AmgUR4AAWVmTP52WEg-m5UUJkvUwfG0VF3T1wdut7mwdonFcz0RGVM1VrtcAbACWkprcwU95Dn_3QR0DD7hxMCqUX8wgxTtLH8kLzS8wL7lMhJguMfXwlbuA_tTNyW1BEvH3v4vxKDMBZn0eqC72eNMkoJv87McJlcQ644mv3BQti23Pf40HaV_3_pjiJowZiQ8AstjkUSdXjSJpT9hUgyjCQv2Z2FVHQ8WsoWHaHbsBIiE_cvOcXJaBNO8NZP4EnAw0A1j0Q",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhN2RhMmY1MjY4MTU5ODkyYmUwMDVlNDYzNWEwOGI1YTEzMjRhYzMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzNDgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVU42WW1aR2FrUlBVWEpsYmtOaVJIaFdiV2R1Um5jdk5UazBPVE13WlRsa05UQmlZakUzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQ0NjkzMTYsImlhdCI6MTcwNDM4MjkxNiwibm9uY2UiOiJsaWZUckNxZ0VjeEQ1V2pnOVVkTTJ3IiwiYXRfaGFzaCI6Ik1EQ0RfTzVKbTF1Rzd2YUtNMGRrbkEiLCJjX2hhc2giOiJNX21SdlNWRExnMVF1RXJiaWpEUGdnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ukgBw8CS1xsmHF-oVM_UykToITUBRsOpmP6SCqZFBNtYREGzdTJBCgEv5KIHyYIZRgPiIQQOqROclCj49oHdYxu2g3EHh6OVoD9ANEC630_erPMXqAM4JhKE8tjNOVkTSrVsFOpgmwwmadSe52ud3ZXLvMV_1XfInqmmlb8DATSD69uHm-QOETuohmgNvzPegHkqpb2Nf6mk0bnFPBkAQwWn0TJGMRu3YmcAdHAjcSvVpITV3Bcl8hiF_kGMykr5Kit1six0ctl-SR0o0Ao4DuG5pJNcpiAT3aQEb8VRosujkIiNFNvAwqMlk7LDUm4Y9Y5312coHxXS3g5cLuZABw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhN2RhMmY1MjY4MTU5ODkyYmUwMDVlNDYzNWEwOGI1YTEzMjRhYzMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzNDgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVU42WW1aR2FrUlBVWEpsYmtOaVJIaFdiV2R1Um5jdk5UazBPVE13WlRsa05UQmlZakUzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQ0NjkzMTYsImlhdCI6MTcwNDM4MjkxNiwibm9uY2UiOiJsaWZUckNxZ0VjeEQ1V2pnOVVkTTJ3IiwiYXRfaGFzaCI6Ik1EQ0RfTzVKbTF1Rzd2YUtNMGRrbkEiLCJjX2hhc2giOiJNX21SdlNWRExnMVF1RXJiaWpEUGdnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ukgBw8CS1xsmHF-oVM_UykToITUBRsOpmP6SCqZFBNtYREGzdTJBCgEv5KIHyYIZRgPiIQQOqROclCj49oHdYxu2g3EHh6OVoD9ANEC630_erPMXqAM4JhKE8tjNOVkTSrVsFOpgmwwmadSe52ud3ZXLvMV_1XfInqmmlb8DATSD69uHm-QOETuohmgNvzPegHkqpb2Nf6mk0bnFPBkAQwWn0TJGMRu3YmcAdHAjcSvVpITV3Bcl8hiF_kGMykr5Kit1six0ctl-SR0o0Ao4DuG5pJNcpiAT3aQEb8VRosujkIiNFNvAwqMlk7LDUm4Y9Y5312coHxXS3g5cLuZABw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhN2RhMmY1MjY4MTU5ODkyYmUwMDVlNDYzNWEwOGI1YTEzMjRhYzMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzNDgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVU42WW1aR2FrUlBVWEpsYmtOaVJIaFdiV2R1Um5jdk5UazBPVE13WlRsa05UQmlZakUzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQ0NjkzMTYsImlhdCI6MTcwNDM4MjkxNiwibm9uY2UiOiJsaWZUckNxZ0VjeEQ1V2pnOVVkTTJ3IiwiYXRfaGFzaCI6Ik1EQ0RfTzVKbTF1Rzd2YUtNMGRrbkEiLCJjX2hhc2giOiJNX21SdlNWRExnMVF1RXJiaWpEUGdnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ukgBw8CS1xsmHF-oVM_UykToITUBRsOpmP6SCqZFBNtYREGzdTJBCgEv5KIHyYIZRgPiIQQOqROclCj49oHdYxu2g3EHh6OVoD9ANEC630_erPMXqAM4JhKE8tjNOVkTSrVsFOpgmwwmadSe52ud3ZXLvMV_1XfInqmmlb8DATSD69uHm-QOETuohmgNvzPegHkqpb2Nf6mk0bnFPBkAQwWn0TJGMRu3YmcAdHAjcSvVpITV3Bcl8hiF_kGMykr5Kit1six0ctl-SR0o0Ao4DuG5pJNcpiAT3aQEb8VRosujkIiNFNvAwqMlk7LDUm4Y9Y5312coHxXS3g5cLuZABw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhN2RhMmY1MjY4MTU5ODkyYmUwMDVlNDYz
NWEwOGI1YTEzMjRhYzMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzNDgyL2RleCIsI
nN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVU42WW1aR2FrUlBVWEpsYmtOaVJIaFdiV
2R1Um5jdk5UazBPVE13WlRsa05UQmlZakUzTlVCM2FYSmxMbU52YlJJRWJHUmhjQ
SIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQ0NjkzMTYsImlhdCI6MTcwNDM4M
jkxNiwibm9uY2UiOiJsaWZUckNxZ0VjeEQ1V2pnOVVkTTJ3IiwiYXRfaGFzaCI6I
k1EQ0RfTzVKbTF1Rzd2YUtNMGRrbkEiLCJjX2hhc2giOiJNX21SdlNWRExnMVF1R
XJiaWpEUGdnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlL
mNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ukgBw8CS1
xsmHF-oVM_UykToITUBRsOpmP6SCqZFBNtYREGzdTJBCgEv5KIHyYIZRgPiIQQOq
ROclCj49oHdYxu2g3EHh6OVoD9ANEC630_erPMXqAM4JhKE8tjNOVkTSrVsFOpgm
wwmadSe52ud3ZXLvMV_1XfInqmmlb8DATSD69uHm-QOETuohmgNvzPegHkqpb2Nf
6mk0bnFPBkAQwWn0TJGMRu3YmcAdHAjcSvVpITV3Bcl8hiF_kGMykr5Kit1six0c
tl-SR0o0Ao4DuG5pJNcpiAT3aQEb8VRosujkIiNFNvAwqMlk7LDUm4Y9Y5312coH
xXS3g5cLuZABw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "1a7da2f5268159892be005e4635a08b5a1324ac3"
}
```

```json
{
  "at_hash": "MDCD_O5Jm1uG7vaKM0dknA",
  "aud": "wireapp",
  "c_hash": "M_mRvSVDLg1QuErbijDPgg",
  "exp": 1704469316,
  "iat": 1704382916,
  "iss": "http://dex:23482/dex",
  "name": "im:wireapp=%40alice_wire@wire.com",
  "nonce": "lifTrCqgEcxD5Wjg9UdM2w",
  "preferred_username": "Alice Smith",
  "sub": "CjtpbTp3aXJlYXBwPUN6YmZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4YqE5wGOoS6iwUSreJcS
U6Keq1x0B7gTDfAExUYvbLT+UrVgND4bpRWAKcdWsFoGtQNCrPpjd9Wk8PAdFFhw
75zWURpXAH/SZ2QciIVYAzd5ehkcsLsGUAl7/sCiKY8ibV9R4S2G54y8K83YTh5C
pfh91rDi4VP0AClEMdimgAFEjv6kN7+ZmZZKwPDznxPMY0ciTR8ZKHgwQAxAn6Nc
Tr+foKWCtzd/JT/gl3383v403cKjV9/qMzmD7+nBn21l71ij0Q5HStEjQt8yjwam
b1mYkG+V/uNS61RJDjiDyE7UFs8g5SDjM0oTLG07+02aNLcstC5vF+66u8wN5xRL
swIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/vKyRRuY8f4gJNdDvqsh6LOghzkA84IGb
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMTc0L2FjbWUvd2lyZS9hY2NvdW50L0RHZjFRWWVWSzhIaFRuY0NrSUZ1UUJ6MklGenhsSFNaIiwidHlwIjoiSldUIiwibm9uY2UiOiJORXR1ZUVwSFVsZHFiME5hVTNsSE1tbDBVREZOVG5kWFRWcGxUSEZhU0RNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMxNzQvYWNtZS93aXJlL2NoYWxsZW5nZS9GS1NpWXdTWTg5R1VJTGxlODRRc3o4Ulcza0tWelc2eC92S3lSUnVZOGY0Z0pOZER2cXNoNkxPZ2h6a0E4NElHYiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJakZoTjJSaE1tWTFNalk0TVRVNU9Ea3lZbVV3TURWbE5EWXpOV0V3T0dJMVlURXpNalJoWXpNaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSXpORGd5TDJSbGVDSXNJbk4xWWlJNklrTnFkSEJpVkhBellWaEtiRmxZUW5kUVZVNDJXVzFhUjJGclVsQlZXRXBzWW10T2FWSklhRmRpVjJSMVVtNWpkazVVYXpCUFZFMTNXbFJzYTA1VVFtbFpha1V6VGxWQ00yRllTbXhNYlU1MllsSkpSV0pIVW1oalFTSXNJbUYxWkNJNkluZHBjbVZoY0hBaUxDSmxlSEFpT2pFM01EUTBOamt6TVRZc0ltbGhkQ0k2TVRjd05ETTRNamt4Tml3aWJtOXVZMlVpT2lKc2FXWlVja054WjBWamVFUTFWMnBuT1ZWa1RUSjNJaXdpWVhSZmFHRnphQ0k2SWsxRVEwUmZUelZLYlRGMVJ6ZDJZVXROTUdScmJrRWlMQ0pqWDJoaGMyZ2lPaUpOWDIxU2RsTldSRXhuTVZGMVJYSmlhV3BFVUdkbklpd2libUZ0WlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJa0ZzYVdObElGTnRhWFJvSW4wLnVrZ0J3OENTMXhzbUhGLW9WTV9VeWtUb0lUVUJSc09wbVA2U0NxWkZCTnRZUkVHemRUSkJDZ0V2NUtJSHlZSVpSZ1BpSVFRT3FST2NsQ2o0OW9IZFl4dTJnM0VIaDZPVm9EOUFORUM2MzBfZXJQTVhxQU00SmhLRTh0ak5PVmtUU3JWc0ZPcGdtd3dtYWRTZTUydWQzWlhMdk1WXzFYZklucW1tbGI4REFUU0Q2OXVIbS1RT0VUdW9obWdOdnpQZWdIa3FwYjJOZjZtazBibkZQQmtBUXdXbjBUSkdNUnUzWW1jQWRIQWpjU3ZWcElUVjNCY2w4aGlGX2tHTXlrcjVLaXQxc2l4MGN0bC1TUjBvMEFvNER1RzVwSk5jcGlBVDNhUUViOFZSb3N1amtJaU5GTnZBd3FNbGs3TERVbTRZOVk1MzEyY29IeFhTM2c1Y0x1WkFCdyIsImtleWF1dGgiOiJRMFJQYmltN2JnV1ZwRFE5RTNPNllmUkVCcUpJQkhEZS51WGFRUndha21BMW1fdDRrTzg5SVJDc0pXU2VHaF9TbHMwdTl5aFdOb3kwIn0",
  "signature": "1BsCWn93y-RO61kpKSd7GAL20pACsq1bLQS8aQ-kNi48VH-1iUyW40Nzc22-_EjvB3G9VniCu3Diq3QYVu54CA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhN2RhMmY1MjY4MTU5ODkyYmUwMDVlNDYzNWEwOGI1YTEzMjRhYzMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIzNDgyL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVU42WW1aR2FrUlBVWEpsYmtOaVJIaFdiV2R1Um5jdk5UazBPVE13WlRsa05UQmlZakUzTlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDQ0NjkzMTYsImlhdCI6MTcwNDM4MjkxNiwibm9uY2UiOiJsaWZUckNxZ0VjeEQ1V2pnOVVkTTJ3IiwiYXRfaGFzaCI6Ik1EQ0RfTzVKbTF1Rzd2YUtNMGRrbkEiLCJjX2hhc2giOiJNX21SdlNWRExnMVF1RXJiaWpEUGdnIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ukgBw8CS1xsmHF-oVM_UykToITUBRsOpmP6SCqZFBNtYREGzdTJBCgEv5KIHyYIZRgPiIQQOqROclCj49oHdYxu2g3EHh6OVoD9ANEC630_erPMXqAM4JhKE8tjNOVkTSrVsFOpgmwwmadSe52ud3ZXLvMV_1XfInqmmlb8DATSD69uHm-QOETuohmgNvzPegHkqpb2Nf6mk0bnFPBkAQwWn0TJGMRu3YmcAdHAjcSvVpITV3Bcl8hiF_kGMykr5Kit1six0ctl-SR0o0Ao4DuG5pJNcpiAT3aQEb8VRosujkIiNFNvAwqMlk7LDUm4Y9Y5312coHxXS3g5cLuZABw",
    "keyauth": "Q0RPbim7bgWVpDQ9E3O6YfREBqJIBHDe.uXaQRwakmA1m_t4kO89IRCsJWSeGh_Sls0u9yhWNoy0"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33174/acme/wire/account/DGf1QYeVK8HhTncCkIFuQBz2IFzxlHSZ",
    "nonce": "NEtueEpHUldqb0NaU3lHMml0UDFNTndXTVplTHFaSDM",
    "typ": "JWT",
    "url": "https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/vKyRRuY8f4gJNdDvqsh6LOghzkA84IGb"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33174/acme/wire/directory>;rel="index"
link: <https://stepca:33174/acme/wire/authz/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x>;rel="up"
location: https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/vKyRRuY8f4gJNdDvqsh6LOghzkA84IGb
replay-nonce: Y2tqa1BhbDdCUU5HZ2NEYVphMGZ3a1VEczM0ZkdTT3o
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:33174/acme/wire/challenge/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x/vKyRRuY8f4gJNdDvqsh6LOghzkA84IGb",
  "status": "valid",
  "token": "Q0RPbim7bgWVpDQ9E3O6YfREBqJIBHDe",
  "target": "http://dex:23482/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMTc0L2FjbWUvd2lyZS9hY2NvdW50L0RHZjFRWWVWSzhIaFRuY0NrSUZ1UUJ6MklGenhsSFNaIiwidHlwIjoiSldUIiwibm9uY2UiOiJZMnRxYTFCaGJEZENVVTVIWjJORVlWcGhNR1ozYTFWRWN6TTBaa2RUVDNvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMxNzQvYWNtZS93aXJlL29yZGVyL0xwS09mdlg3cFlpVmVucjhGQUpFT2pVUHVpejVBQ24zIn0",
  "payload": "",
  "signature": "0sbmbJC-PL658w62Da37tdASfKDfSrGjFkM8qv6hOMEYxoQofZ2POqbhZgM_8AO_qHvWuEaGvkRpILrkPeI4Dg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33174/acme/wire/account/DGf1QYeVK8HhTncCkIFuQBz2IFzxlHSZ",
    "nonce": "Y2tqa1BhbDdCUU5HZ2NEYVphMGZ3a1VEczM0ZkdTT3o",
    "typ": "JWT",
    "url": "https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33174/acme/wire/directory>;rel="index"
location: https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3
replay-nonce: UkpJTDBtbGFSek5nalY0dmc2VWFGallpTDVyV0dhSzA
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33174/acme/wire/authz/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x"
  ],
  "expires": "2024-01-05T15:41:56Z",
  "notBefore": "2024-01-04T15:41:56.773294Z",
  "notAfter": "2034-01-01T15:41:56.773294Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMTc0L2FjbWUvd2lyZS9hY2NvdW50L0RHZjFRWWVWSzhIaFRuY0NrSUZ1UUJ6MklGenhsSFNaIiwidHlwIjoiSldUIiwibm9uY2UiOiJVa3BKVERCdGJHRlNlazVuYWxZMGRtYzJWV0ZHYWxscFREVnlWMGRoU3pBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMxNzQvYWNtZS93aXJlL29yZGVyL0xwS09mdlg3cFlpVmVucjhGQUpFT2pVUHVpejVBQ24zL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTFRDQjRBSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTU9Ma25CLWxXY3p4aDZRaE4ycXBQalNNVlNZaDN1ZnRuS29GYkVnZ20wcm9Id3dlZ1lKS29aSWh2Y05BUWtPTVcwd2F6QnBCZ05WSFJFRVlqQmdoanRwYlRwM2FYSmxZWEJ3UFVONlltWkdha1JQVVhKbGJrTmlSSGhXYldkdVJuY3ZOVGswT1RNd1pUbGtOVEJpWWpFM05VQjNhWEpsTG1OdmJZWWhhVzA2ZDJseVpXRndjRDBsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dE1BVUdBeXRsY0FOQkFOZlpjQmd6eUZQYUpJbHd0RDdUTThJRm96SXI5VUlpYkdTVFVFSTFJdTB2NDhqTGlnUVJqbEhFdnN3aUI2OVVwdWEzMzJuQjJGRzNNMm5jcndmN1FRRSJ9",
  "signature": "0WryiPJkmpydr5q83OYX8s6p6370MQftHaaEbrDvbwLBOg7T9x_3UeXoqJ_jyF9yUiTTf_IaDbrqSfBHopHUCA"
}
```
```json
{
  "payload": {
    "csr": "MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMOLknB-lWczxh6QhN2qpPjSMVSYh3uftnKoFbEggm0roHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJlYXBwPUN6YmZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJlLmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANBANfZcBgzyFPaJIlwtD7TM8IFozIr9UIibGSTUEI1Iu0v48jLigQRjlHEvswiB69Upua332nB2FG3M2ncrwf7QQE"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33174/acme/wire/account/DGf1QYeVK8HhTncCkIFuQBz2IFzxlHSZ",
    "nonce": "UkpJTDBtbGFSek5nalY0dmc2VWFGallpTDVyV0dhSzA",
    "typ": "JWT",
    "url": "https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMOLknB+lWczxh6QhN2qpPjSMVSYh3uf
tnKoFbEggm0roHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJl
YXBwPUN6YmZGakRPUXJlbkNiRHhWbWduRncvNTk0OTMwZTlkNTBiYjE3NUB3aXJl
LmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANB
ANfZcBgzyFPaJIlwtD7TM8IFozIr9UIibGSTUEI1Iu0v48jLigQRjlHEvswiB69U
pua332nB2FG3M2ncrwf7QQE=
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
                    c3:8b:92:70:7e:95:67:33:c6:1e:90:84:dd:aa:a4:
                    f8:d2:31:54:98:87:7b:9f:b6:72:a8:15:b1:20:82:
                    6d:2b
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com, URI:im:wireapp=%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        d7:d9:70:18:33:c8:53:da:24:89:70:b4:3e:d3:33:c2:05:a3:
        32:2b:f5:42:22:6c:64:93:50:42:35:22:ed:2f:e3:c8:cb:8a:
        04:11:8e:51:c4:be:cc:22:07:af:54:a6:e6:b7:df:69:c1:d8:
        51:b7:33:69:dc:af:07:fb:41:01

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33174/acme/wire/directory>;rel="index"
location: https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3
replay-nonce: UjlpVElnWFRzS3hBQms2WVdtMGlVSk05T1RiaWRDNTE
vary: Origin
```
```json
{
  "certificate": "https://stepca:33174/acme/wire/certificate/oKaQdQpJTCU47Q1MxNjRIGhPL4zoT0Zh",
  "status": "valid",
  "finalize": "https://stepca:33174/acme/wire/order/LpKOfvX7pYiVenr8FAJEOjUPuiz5ACn3/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33174/acme/wire/authz/FKSiYwSY89GUILle84Qsz8RW3kKVzW6x"
  ],
  "expires": "2024-01-05T15:41:56Z",
  "notBefore": "2024-01-04T15:41:56.773294Z",
  "notAfter": "2034-01-01T15:41:56.773294Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:33174/acme/wire/certificate/oKaQdQpJTCU47Q1MxNjRIGhPL4zoT0Zh
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMTc0L2FjbWUvd2lyZS9hY2NvdW50L0RHZjFRWWVWSzhIaFRuY0NrSUZ1UUJ6MklGenhsSFNaIiwidHlwIjoiSldUIiwibm9uY2UiOiJVamxwVkVsbldGUnpTM2hCUW1zMldWZHRNR2xWU2swNVQxUmlhV1JETlRFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMxNzQvYWNtZS93aXJlL2NlcnRpZmljYXRlL29LYVFkUXBKVENVNDdRMU14TmpSSUdoUEw0em9UMFpoIn0",
  "payload": "",
  "signature": "WW4tU0WtS5ukcY3hGlpyYNsy8YWSxN8k-yCpTjPCLtGICAr3Ss5lq8H6KAnPAPUYowdZU5WO2UEHnyVdq3UrDQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33174/acme/wire/account/DGf1QYeVK8HhTncCkIFuQBz2IFzxlHSZ",
    "nonce": "UjlpVElnWFRzS3hBQms2WVdtMGlVSk05T1RiaWRDNTE",
    "typ": "JWT",
    "url": "https://stepca:33174/acme/wire/certificate/oKaQdQpJTCU47Q1MxNjRIGhPL4zoT0Zh"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:33174/acme/wire/directory>;rel="index"
replay-nonce: ZlA3UGxPcVVTc0V1dWt2U2ZFRkVJcnV6c0ZGd3RCSWY
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGzCCAcCgAwIBAgIRAPWpbohhWchd/yQqt19TOAowCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMTA0MTU0MTU2WhcNMzQwMTAxMTU0MTU2WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDDi5JwfpVnM8YekITd\nqqT40jFUmId7n7ZyqBWxIIJtK6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHX0CS98vcUJlZ+Qdcmec96hR11xMB8G\nA1UdIwQYMBaAFK5Q8WXZQy5tn4NmvU1MzK/cKpuRMGkGA1UdEQRiMGCGIWltOndp\ncmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY7aW06d2lyZWFwcD1DemJmRmpE\nT1FyZW5DYkR4Vm1nbkZ3LzU5NDkzMGU5ZDUwYmIxNzVAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0kAMEYCIQD0uzBc\nI5ScUfP67iCKOHPbYhlcFGs3pyvtGCRKzCxeawIhAOm8a22sI0nsay5yjX1VzMqL\n+29MXLLOuHpMUWy1OKEZ\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBtzCCAV6gAwIBAgIQAvG7iOqXDrU8ejVYoo7l/jAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTA0MTU0\nMTU1WhcNMzQwMTAxMTU0MTU1WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF9a\ncFswr+8p0k3UdNu40piOucKCnYJxMyEDctHl4GNQYo/PhpOkZ6u95kBxrqb/f+ii\nf8d3Gh7HAodo8tc9vDajZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBSuUPFl2UMubZ+DZr1NTMyv3CqbkTAfBgNVHSMEGDAW\ngBQtHkFcbVr6OPxwRmA2r1ldHPaucTAKBggqhkjOPQQDAgNHADBEAiB1PrLHI9f+\ntKXfuMiydaenxND+3ClDAdnQ71V7/UjB/AIgVu67KjDigckqQESZLah+iZc1DfaR\nRuSkSGa9zURWKWs=\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGzCCAcCgAwIBAgIRAPWpbohhWchd/yQqt19TOAowCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMTA0MTU0MTU2WhcNMzQwMTAxMTU0MTU2WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDDi5JwfpVnM8YekITd
qqT40jFUmId7n7ZyqBWxIIJtK6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFHX0CS98vcUJlZ+Qdcmec96hR11xMB8G
A1UdIwQYMBaAFK5Q8WXZQy5tn4NmvU1MzK/cKpuRMGkGA1UdEQRiMGCGIWltOndp
cmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY7aW06d2lyZWFwcD1DemJmRmpE
T1FyZW5DYkR4Vm1nbkZ3LzU5NDkzMGU5ZDUwYmIxNzVAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0kAMEYCIQD0uzBc
I5ScUfP67iCKOHPbYhlcFGs3pyvtGCRKzCxeawIhAOm8a22sI0nsay5yjX1VzMqL
+29MXLLOuHpMUWy1OKEZ
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f5:a9:6e:88:61:59:c8:5d:ff:24:2a:b7:5f:53:38:0a
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan  4 15:41:56 2024 GMT
            Not After : Jan  1 15:41:56 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    c3:8b:92:70:7e:95:67:33:c6:1e:90:84:dd:aa:a4:
                    f8:d2:31:54:98:87:7b:9f:b6:72:a8:15:b1:20:82:
                    6d:2b
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                75:F4:09:2F:7C:BD:C5:09:95:9F:90:75:C9:9E:73:DE:A1:47:5D:71
            X509v3 Authority Key Identifier: 
                AE:50:F1:65:D9:43:2E:6D:9F:83:66:BD:4D:4C:CC:AF:DC:2A:9B:91
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=%40alice_wire@wire.com, URI:im:wireapp=CzbfFjDOQrenCbDxVmgnFw/594930e9d50bb175@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:f4:bb:30:5c:23:94:9c:51:f3:fa:ee:20:8a:
        38:73:db:62:19:5c:14:6b:37:a7:2b:ed:18:24:4a:cc:2c:5e:
        6b:02:21:00:e9:bc:6b:6d:ac:23:49:ec:6b:2e:72:8d:7d:55:
        cc:ca:8b:fb:6f:4c:5c:b2:ce:b8:7a:4c:51:6c:b5:38:a1:19

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBtzCCAV6gAwIBAgIQAvG7iOqXDrU8ejVYoo7l/jAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTA0MTU0
MTU1WhcNMzQwMTAxMTU0MTU1WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABF9a
cFswr+8p0k3UdNu40piOucKCnYJxMyEDctHl4GNQYo/PhpOkZ6u95kBxrqb/f+ii
f8d3Gh7HAodo8tc9vDajZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBSuUPFl2UMubZ+DZr1NTMyv3CqbkTAfBgNVHSMEGDAW
gBQtHkFcbVr6OPxwRmA2r1ldHPaucTAKBggqhkjOPQQDAgNHADBEAiB1PrLHI9f+
tKXfuMiydaenxND+3ClDAdnQ71V7/UjB/AIgVu67KjDigckqQESZLah+iZc1DfaR
RuSkSGa9zURWKWs=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            02:f1:bb:88:ea:97:0e:b5:3c:7a:35:58:a2:8e:e5:fe
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan  4 15:41:55 2024 GMT
            Not After : Jan  1 15:41:55 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:5f:5a:70:5b:30:af:ef:29:d2:4d:d4:74:db:b8:
                    d2:98:8e:b9:c2:82:9d:82:71:33:21:03:72:d1:e5:
                    e0:63:50:62:8f:cf:86:93:a4:67:ab:bd:e6:40:71:
                    ae:a6:ff:7f:e8:a2:7f:c7:77:1a:1e:c7:02:87:68:
                    f2:d7:3d:bc:36
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                AE:50:F1:65:D9:43:2E:6D:9F:83:66:BD:4D:4C:CC:AF:DC:2A:9B:91
            X509v3 Authority Key Identifier: 
                2D:1E:41:5C:6D:5A:FA:38:FC:70:46:60:36:AF:59:5D:1C:F6:AE:71
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:75:3e:b2:c7:23:d7:fe:b4:a5:df:b8:c8:b2:75:
        a7:a7:c4:d0:fe:dc:29:43:01:d9:d0:ef:55:7b:fd:48:c1:fc:
        02:20:56:ee:bb:2a:30:e2:81:c9:2a:40:44:99:2d:a8:7e:89:
        97:35:0d:f6:91:46:e4:a4:48:66:bd:cd:44:56:29:6b

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATWgAwIBAgIQULSYJ6Kpz5QNgkz8hVVuHDAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTA0MTU0
MTU0WhcNMzQwMTAxMTU0MTU0WjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3
aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQyiaYB1O9tK+nn
iYNXnN3Q5y4JL7ssY97hh6iOhQruCh+O07cQY+QlgZ58CNKYYl8FfhQL37jc8Q12
1fAZUAN4o0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd
BgNVHQ4EFgQULR5BXG1a+jj8cEZgNq9ZXRz2rnEwCgYIKoZIzj0EAwIDSQAwRgIh
AOg4Ycqihnbf1Mqna1psHwnb8fvth5/xVtuBYzBd4MWnAiEA4nedSLutm5Dg0WER
BSe6wMYvuo4Z4uT2UB/9nBg2FiY=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            50:b4:98:27:a2:a9:cf:94:0d:82:4c:fc:85:55:6e:1c
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan  4 15:41:54 2024 GMT
            Not After : Jan  1 15:41:54 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:32:89:a6:01:d4:ef:6d:2b:e9:e7:89:83:57:9c:
                    dd:d0:e7:2e:09:2f:bb:2c:63:de:e1:87:a8:8e:85:
                    0a:ee:0a:1f:8e:d3:b7:10:63:e4:25:81:9e:7c:08:
                    d2:98:62:5f:05:7e:14:0b:df:b8:dc:f1:0d:76:d5:
                    f0:19:50:03:78
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                2D:1E:41:5C:6D:5A:FA:38:FC:70:46:60:36:AF:59:5D:1C:F6:AE:71
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:e8:38:61:ca:a2:86:76:df:d4:ca:a7:6b:5a:
        6c:1f:09:db:f1:fb:ed:87:9f:f1:56:db:81:63:30:5d:e0:c5:
        a7:02:21:00:e2:77:9d:48:bb:ad:9b:90:e0:d1:61:11:05:27:
        ba:c0:c6:2f:ba:8e:19:e2:e4:f6:50:1f:fd:9c:18:36:16:26

```

openssl verify chain ✅