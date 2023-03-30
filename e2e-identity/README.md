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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/qj0CPQKllmpgxmHik890WXwdHUNkN180
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/6648489842345594552/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/8T0p0u1lxsCezM22dTdhjM0WW4cNz2NC
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
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/rWT4tf7ppbiJvgbOgePKPrFViNaJb0vb
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/IF3RiEp4JuW7Cag7YhWVqTriXPSq8YSP
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:56379/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:56379/acme/wire/new-nonce",
  "newAccount": "https://stepca:56379/acme/wire/new-account",
  "newOrder": "https://stepca:56379/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:56379/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:56379/acme/wire/directory>;rel="index"
replay-nonce: QkMxN2lpUGRRZ2kySHV5NmR6U3pYbEhZdFYwSkhJRXc
```
```text
QkMxN2lpUGRRZ2kySHV5NmR6U3pYbEhZdFYwSkhJRXc
```
#### 5. create a new account
```http request
POST https://stepca:56379/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImduNnJzOFBZZEhBS0VER1ZNWVk0LWVGTmcxOWpYd0lMVWFvbmIyZmRzUU0ifSwibm9uY2UiOiJRa014TjJscFVHUlJaMmt5U0hWNU5tUjZVM3BZYkVoWmRGWXdTa2hKUlhjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNzkvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "a_fXeEJOL5-6D98Dy-THXt12QugZqwHdZUDA5sGf_EA_nSXpFLhoa2dfQ35ErGtkZGkuD_vEWFAeyFOTQAxbCQ"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "typ": "JWT",
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "gn6rs8PYdHAKEDGVMYY4-eFNg19jXwILUaonb2fdsQM"
    },
    "nonce": "QkMxN2lpUGRRZ2kySHV5NmR6U3pYbEhZdFYwSkhJRXc",
    "url": "https://stepca:56379/acme/wire/new-account"
  },
  "payload": {
    "termsOfServiceAgreed": true,
    "contact": [
      "unknown@example.com"
    ],
    "onlyReturnExisting": false
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:56379/acme/wire/directory>;rel="index"
location: https://stepca:56379/acme/wire/account/6aIvpYXZuVCHUNXmxr8gdBHcDps9SavG
replay-nonce: R1pTb2FjejNGNXBRNURjZEZsQTZhN1J3azlCaE1qOHU
```
```json
{
  "status": "valid",
  "orders": "https://stepca:56379/acme/wire/account/6aIvpYXZuVCHUNXmxr8gdBHcDps9SavG/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:56379/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2Mzc5L2FjbWUvd2lyZS9hY2NvdW50LzZhSXZwWVhadVZDSFVOWG14cjhnZEJIY0RwczlTYXZHIiwidHlwIjoiSldUIiwibm9uY2UiOiJSMXBUYjJGamVqTkdOWEJSTlVSalpFWnNRVFpoTjFKM2F6bENhRTFxT0hVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNzkvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIlNtaXRoLCBBbGljZSBNIChRQSlcIixcImRvbWFpblwiOlwid2lyZS5jb21cIixcImNsaWVudC1pZFwiOlwiaW06d2lyZWFwcD1OekEzWkdZMU16QmtPRGxrTkRBME1qaGxNalppWlRVelpXWXdPVFF3TlRRLzVjNDQyZTQ5NTFjZDRlYjhAd2lyZS5jb21cIixcImhhbmRsZVwiOlwiYWxpY2Uuc21pdGhcIn0ifV0sIm5vdEJlZm9yZSI6IjIwMjMtMDMtMzBUMTU6MDI6MjkuNzIzMzY5WiIsIm5vdEFmdGVyIjoiMjAyMy0wMy0zMFQxNjowMjoyOS43MjMzNjlaIn0",
  "signature": "sBNQTqz84zH34Y0idVsdlkKoOW1GyIeCskzYBgYTNBS9vdLKLh5KZIn9Nh467W6wQDRAKz18wNB4Oy5vyubNBg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56379/acme/wire/account/6aIvpYXZuVCHUNXmxr8gdBHcDps9SavG",
    "typ": "JWT",
    "nonce": "R1pTb2FjejNGNXBRNURjZEZsQTZhN1J3azlCaE1qOHU",
    "url": "https://stepca:56379/acme/wire/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NzA3ZGY1MzBkODlkNDA0MjhlMjZiZTUzZWYwOTQwNTQ/5c442e4951cd4eb8@wire.com\",\"handle\":\"alice.smith\"}"
      }
    ],
    "notBefore": "2023-03-30T15:02:29.723369Z",
    "notAfter": "2023-03-30T16:02:29.723369Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:56379/acme/wire/directory>;rel="index"
location: https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2
replay-nonce: UUNYc2lvcnh3cTVBbTlLV3hENTlkcXpxcUhib0YxM0Q
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NzA3ZGY1MzBkODlkNDA0MjhlMjZiZTUzZWYwOTQwNTQ/5c442e4951cd4eb8@wire.com\",\"handle\":\"alice.smith\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56379/acme/wire/authz/qj0CPQKllmpgxmHik890WXwdHUNkN180"
  ],
  "expires": "2023-03-31T15:02:29Z",
  "notBefore": "2023-03-30T15:02:29.723369Z",
  "notAfter": "2023-03-30T16:02:29.723369Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:56379/acme/wire/authz/qj0CPQKllmpgxmHik890WXwdHUNkN180
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2Mzc5L2FjbWUvd2lyZS9hY2NvdW50LzZhSXZwWVhadVZDSFVOWG14cjhnZEJIY0RwczlTYXZHIiwidHlwIjoiSldUIiwibm9uY2UiOiJVVU5ZYzJsdmNuaDNjVFZCYlRsTFYzaEVOVGxrY1hweGNVaGliMFl4TTBRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNzkvYWNtZS93aXJlL2F1dGh6L3FqMENQUUtsbG1wZ3htSGlrODkwV1h3ZEhVTmtOMTgwIn0",
  "payload": "",
  "signature": "Soyn-4b84Kbk9FhaEsZbIHZg2QaPJ0wF4ZhOiuS342zSlHTK9Gq05-6Xufx1l2R7SOCeL1kGiv8277tn1DEmBA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56379/acme/wire/account/6aIvpYXZuVCHUNXmxr8gdBHcDps9SavG",
    "typ": "JWT",
    "nonce": "UUNYc2lvcnh3cTVBbTlLV3hENTlkcXpxcUhib0YxM0Q",
    "url": "https://stepca:56379/acme/wire/authz/qj0CPQKllmpgxmHik890WXwdHUNkN180"
  },
  "payload": {}
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56379/acme/wire/directory>;rel="index"
location: https://stepca:56379/acme/wire/authz/qj0CPQKllmpgxmHik890WXwdHUNkN180
replay-nonce: czFEb1VFYnowb0VxN2FvYXpRQUVWV2w2MGFLVUppQUw
```
```json
{
  "status": "pending",
  "expires": "2023-03-31T15:02:29Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/rWT4tf7ppbiJvgbOgePKPrFViNaJb0vb",
      "status": "pending",
      "token": "bqC8Q6uKR3e2tvUEniIdAr6KfOOyc4YR"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/8T0p0u1lxsCezM22dTdhjM0WW4cNz2NC",
      "status": "pending",
      "token": "bqC8Q6uKR3e2tvUEniIdAr6KfOOyc4YR"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NzA3ZGY1MzBkODlkNDA0MjhlMjZiZTUzZWYwOTQwNTQ/5c442e4951cd4eb8@wire.com\",\"handle\":\"alice.smith\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:22913/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
dlBwNlJaZVA3MFVOM0NYRGVwU3lJbXhXUnNnR0cwMHM
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZ242cnM4UFlkSEFLRURHVk1ZWTQtZUZOZzE5alh3SUxVYW9uYjJmZHNRTSJ9fQ.eyJpYXQiOjE2ODAxODg1NDksImV4cCI6MTY4MDE5MjE0OSwibmJmIjoxNjgwMTg4NTQ5LCJzdWIiOiJpbTp3aXJlYXBwPU56QTNaR1kxTXpCa09EbGtOREEwTWpobE1qWmlaVFV6WldZd09UUXdOVFEvNWM0NDJlNDk1MWNkNGViOEB3aXJlLmNvbSIsImp0aSI6ImU0ZDRhYmY5LTE4ZTUtNDRmOS04N2UyLTlhNDJhOTY1MGRjZCIsIm5vbmNlIjoiZGxCd05sSmFaVkEzTUZWT00wTllSR1Z3VTNsSmJYaFhVbk5uUjBjd01ITSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjI5MTMvIiwiY2hhbCI6ImJxQzhRNnVLUjNlMnR2VUVuaUlkQXI2S2ZPT3ljNFlSIn0.VxVLhIu6BlHtkRRVsj56nwPhGnrfPnGdGvSWdJytrPRtWULKgrxsjt5EPL6CZi5jy6Z2OW_IdgC9i3tr395HDQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZ242cnM4UFlkSEFLRURHVk1ZWTQtZUZO
ZzE5alh3SUxVYW9uYjJmZHNRTSJ9fQ.eyJpYXQiOjE2ODAxODg1NDksImV4cCI6M
TY4MDE5MjE0OSwibmJmIjoxNjgwMTg4NTQ5LCJzdWIiOiJpbTp3aXJlYXBwPU56Q
TNaR1kxTXpCa09EbGtOREEwTWpobE1qWmlaVFV6WldZd09UUXdOVFEvNWM0NDJlN
Dk1MWNkNGViOEB3aXJlLmNvbSIsImp0aSI6ImU0ZDRhYmY5LTE4ZTUtNDRmOS04N
2UyLTlhNDJhOTY1MGRjZCIsIm5vbmNlIjoiZGxCd05sSmFaVkEzTUZWT00wTllSR
1Z3VTNsSmJYaFhVbk5uUjBjd01ITSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MjI5MTMvIiwiY2hhbCI6ImJxQzhRNnVLUjNlMnR2VUVuaUlkQ
XI2S2ZPT3ljNFlSIn0.VxVLhIu6BlHtkRRVsj56nwPhGnrfPnGdGvSWdJytrPRtW
ULKgrxsjt5EPL6CZi5jy6Z2OW_IdgC9i3tr395HDQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "gn6rs8PYdHAKEDGVMYY4-eFNg19jXwILUaonb2fdsQM"
  }
}
```

```json
{
  "iat": 1680188549,
  "exp": 1680192149,
  "nbf": 1680188549,
  "sub": "im:wireapp=NzA3ZGY1MzBkODlkNDA0MjhlMjZiZTUzZWYwOTQwNTQ/5c442e4951cd4eb8@wire.com",
  "jti": "e4d4abf9-18e5-44f9-87e2-9a42a9650dcd",
  "nonce": "dlBwNlJaZVA3MFVOM0NYRGVwU3lJbXhXUnNnR0cwMHM",
  "htm": "POST",
  "htu": "http://wire.com:22913/",
  "chal": "bqC8Q6uKR3e2tvUEniIdAr6KfOOyc4YR"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKjKiFlIGI6c/3i8gnfxMW7t7HMh2xDuz7YAebLGbOqF
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAgn6rs8PYdHAKEDGVMYY4+eFNg19jXwILUaonb2fdsQM=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:22913/clients/6648489842345594552/access-token
                          /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pWjI0MmNuTTRVRmxrU0VGTFJVUkhWazFaV1RRdFpVWk9aekU1YWxoM1NVeFZZVzl1WWpKbVpITlJUU0o5ZlEuZXlKcFlYUWlPakUyT0RBeE9EZzFORGtzSW1WNGNDSTZNVFk0TURFNU1qRTBPU3dpYm1KbUlqb3hOamd3TVRnNE5UUTVMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTU2UVROYVIxa3hUWHBDYTA5RWJHdE9SRUV3VFdwb2JFMXFXbWxhVkZWNldsZFpkMDlVVVhkT1ZGRXZOV00wTkRKbE5EazFNV05rTkdWaU9FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltVTBaRFJoWW1ZNUxURTRaVFV0TkRSbU9TMDROMlV5TFRsaE5ESmhPVFkxTUdSalpDSXNJbTV2Ym1ObElqb2laR3hDZDA1c1NtRmFWa0V6VFVaV1QwMHdUbGxTUjFaM1ZUTnNTbUpZYUZoVmJrNXVVakJqZDAxSVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakk1TVRNdklpd2lZMmhoYkNJNkltSnhRemhSTm5WTFVqTmxNblIyVlVWdWFVbGtRWEkyUzJaUFQzbGpORmxTSW4wLlZ4VkxoSXU2QmxIdGtSUlZzajU2bndQaEducmZQbkdkR3ZTV2RKeXRyUFJ0V1VMS2dyeHNqdDVFUEw2Q1ppNWp5NloyT1dfSWRnQzlpM3RyMzk1SERR
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlU4b0FuQ0FwZVMxSGJfOWxSQzJoR3ZTdnhOeFVMOVlSazZGLWhCbWl3c1kifX0.eyJpYXQiOjE2ODAxODg1NDksImV4cCI6MTY4Nzk2NDU0OSwibmJmIjoxNjgwMTg4NTQ5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjI5MTMvIiwic3ViIjoiaW06d2lyZWFwcD1OekEzWkdZMU16QmtPRGxrTkRBME1qaGxNalppWlRVelpXWXdPVFF3TlRRLzVjNDQyZTQ5NTFjZDRlYjhAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjI5MTMvIiwianRpIjoiOTIyN2VlYzctYzdiMC00YTczLTlkZDUtNWIwMzcyZDczYjE2Iiwibm9uY2UiOiJkbEJ3TmxKYVpWQTNNRlZPTTBOWVJHVndVM2xKYlhoWFVuTm5SMGN3TUhNIiwiY2hhbCI6ImJxQzhRNnVLUjNlMnR2VUVuaUlkQXI2S2ZPT3ljNFlSIiwiY25mIjp7ImtpZCI6IllRNW9LZTY4b0YydE5WTFRuZjV6aUJmSEFyWndzcThCZ0ZwR0ZQTy1QQzgifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2laMjQyY25NNFVGbGtTRUZMUlVSSFZrMVpXVFF0WlVaT1p6RTVhbGgzU1V4VllXOXVZakptWkhOUlRTSjlmUS5leUpwWVhRaU9qRTJPREF4T0RnMU5Ea3NJbVY0Y0NJNk1UWTRNREU1TWpFME9Td2libUptSWpveE5qZ3dNVGc0TlRRNUxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BVNTZRVE5hUjFreFRYcENhMDlFYkd0T1JFRXdUV3BvYkUxcVdtbGFWRlY2V2xkWmQwOVVVWGRPVkZFdk5XTTBOREpsTkRrMU1XTmtOR1ZpT0VCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VMFpEUmhZbVk1TFRFNFpUVXRORFJtT1MwNE4yVXlMVGxoTkRKaE9UWTFNR1JqWkNJc0ltNXZibU5sSWpvaVpHeENkMDVzU21GYVZrRXpUVVpXVDAwd1RsbFNSMVozVlROc1NtSllhRmhWYms1dVVqQmpkMDFJVFNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qSTVNVE12SWl3aVkyaGhiQ0k2SW1KeFF6aFJOblZMVWpObE1uUjJWVVZ1YVVsa1FYSTJTMlpQVDNsak5GbFNJbjAuVnhWTGhJdTZCbEh0a1JSVnNqNTZud1BoR25yZlBuR2RHdlNXZEp5dHJQUnRXVUxLZ3J4c2p0NUVQTDZDWmk1ank2WjJPV19JZGdDOWkzdHIzOTVIRFEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU56QTNaR1kxTXpCa09EbGtOREEwTWpobE1qWmlaVFV6WldZd09UUXdOVFEvNWM0NDJlNDk1MWNkNGViOEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.D45U4fCCNuhJFtoRUY9qbqmFnqsiVLV-fFNpfb2Fsi_czmEaiozX_UPp3EupzeoTkWeOMpuqywViVJok2j-XBQ",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlU4b0FuQ0FwZVMxSGJfOWxSQzJoR3ZTdnhOeFVMOVlSazZGLWhCbWl3c1kifX0.eyJpYXQiOjE2ODAxODg1NDksImV4cCI6MTY4Nzk2NDU0OSwibmJmIjoxNjgwMTg4NTQ5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjI5MTMvIiwic3ViIjoiaW06d2lyZWFwcD1OekEzWkdZMU16QmtPRGxrTkRBME1qaGxNalppWlRVelpXWXdPVFF3TlRRLzVjNDQyZTQ5NTFjZDRlYjhAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjI5MTMvIiwianRpIjoiOTIyN2VlYzctYzdiMC00YTczLTlkZDUtNWIwMzcyZDczYjE2Iiwibm9uY2UiOiJkbEJ3TmxKYVpWQTNNRlZPTTBOWVJHVndVM2xKYlhoWFVuTm5SMGN3TUhNIiwiY2hhbCI6ImJxQzhRNnVLUjNlMnR2VUVuaUlkQXI2S2ZPT3ljNFlSIiwiY25mIjp7ImtpZCI6IllRNW9LZTY4b0YydE5WTFRuZjV6aUJmSEFyWndzcThCZ0ZwR0ZQTy1QQzgifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2laMjQyY25NNFVGbGtTRUZMUlVSSFZrMVpXVFF0WlVaT1p6RTVhbGgzU1V4VllXOXVZakptWkhOUlRTSjlmUS5leUpwWVhRaU9qRTJPREF4T0RnMU5Ea3NJbVY0Y0NJNk1UWTRNREU1TWpFME9Td2libUptSWpveE5qZ3dNVGc0TlRRNUxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BVNTZRVE5hUjFreFRYcENhMDlFYkd0T1JFRXdUV3BvYkUxcVdtbGFWRlY2V2xkWmQwOVVVWGRPVkZFdk5XTTBOREpsTkRrMU1XTmtOR1ZpT0VCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VMFpEUmhZbVk1TFRFNFpUVXRORFJtT1MwNE4yVXlMVGxoTkRKaE9UWTFNR1JqWkNJc0ltNXZibU5sSWpvaVpHeENkMDVzU21GYVZrRXpUVVpXVDAwd1RsbFNSMVozVlROc1NtSllhRmhWYms1dVVqQmpkMDFJVFNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qSTVNVE12SWl3aVkyaGhiQ0k2SW1KeFF6aFJOblZMVWpObE1uUjJWVVZ1YVVsa1FYSTJTMlpQVDNsak5GbFNJbjAuVnhWTGhJdTZCbEh0a1JSVnNqNTZud1BoR25yZlBuR2RHdlNXZEp5dHJQUnRXVUxLZ3J4c2p0NUVQTDZDWmk1ank2WjJPV19JZGdDOWkzdHIzOTVIRFEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU56QTNaR1kxTXpCa09EbGtOREEwTWpobE1qWmlaVFV6WldZd09UUXdOVFEvNWM0NDJlNDk1MWNkNGViOEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.D45U4fCCNuhJFtoRUY9qbqmFnqsiVLV-fFNpfb2Fsi_czmEaiozX_UPp3EupzeoTkWeOMpuqywViVJok2j-XBQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IlU4b0FuQ0FwZVMxSGJfOWxSQzJoR3ZTdnhO
eFVMOVlSazZGLWhCbWl3c1kifX0.eyJpYXQiOjE2ODAxODg1NDksImV4cCI6MTY4
Nzk2NDU0OSwibmJmIjoxNjgwMTg4NTQ5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjI5MTMvIiwic3ViIjoiaW06d2lyZWFwcD1OekEzWkdZMU16QmtPRGxrTkRBME1q
aGxNalppWlRVelpXWXdPVFF3TlRRLzVjNDQyZTQ5NTFjZDRlYjhAd2lyZS5jb20i
LCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjI5MTMvIiwianRpIjoiOTIyN2VlYzct
YzdiMC00YTczLTlkZDUtNWIwMzcyZDczYjE2Iiwibm9uY2UiOiJkbEJ3TmxKYVpW
QTNNRlZPTTBOWVJHVndVM2xKYlhoWFVuTm5SMGN3TUhNIiwiY2hhbCI6ImJxQzhR
NnVLUjNlMnR2VUVuaUlkQXI2S2ZPT3ljNFlSIiwiY25mIjp7ImtpZCI6IllRNW9L
ZTY4b0YydE5WTFRuZjV6aUJmSEFyWndzcThCZ0ZwR0ZQTy1QQzgifSwicHJvb2Yi
OiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFu
ZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElq
b2laMjQyY25NNFVGbGtTRUZMUlVSSFZrMVpXVFF0WlVaT1p6RTVhbGgzU1V4VllX
OXVZakptWkhOUlRTSjlmUS5leUpwWVhRaU9qRTJPREF4T0RnMU5Ea3NJbVY0Y0NJ
Nk1UWTRNREU1TWpFME9Td2libUptSWpveE5qZ3dNVGc0TlRRNUxDSnpkV0lpT2lK
cGJUcDNhWEpsWVhCd1BVNTZRVE5hUjFreFRYcENhMDlFYkd0T1JFRXdUV3BvYkUx
cVdtbGFWRlY2V2xkWmQwOVVVWGRPVkZFdk5XTTBOREpsTkRrMU1XTmtOR1ZpT0VC
M2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VMFpEUmhZbVk1TFRFNFpUVXRORFJtT1Mw
NE4yVXlMVGxoTkRKaE9UWTFNR1JqWkNJc0ltNXZibU5sSWpvaVpHeENkMDVzU21G
YVZrRXpUVVpXVDAwd1RsbFNSMVozVlROc1NtSllhRmhWYms1dVVqQmpkMDFJVFNJ
c0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIw
Nk1qSTVNVE12SWl3aVkyaGhiQ0k2SW1KeFF6aFJOblZMVWpObE1uUjJWVVZ1YVVs
a1FYSTJTMlpQVDNsak5GbFNJbjAuVnhWTGhJdTZCbEh0a1JSVnNqNTZud1BoR25y
ZlBuR2RHdlNXZEp5dHJQUnRXVUxLZ3J4c2p0NUVQTDZDWmk1ank2WjJPV19JZGdD
OWkzdHIzOTVIRFEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU56QTNaR1kxTXpC
a09EbGtOREEwTWpobE1qWmlaVFV6WldZd09UUXdOVFEvNWM0NDJlNDk1MWNkNGVi
OEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50
X2lkIn0.D45U4fCCNuhJFtoRUY9qbqmFnqsiVLV-fFNpfb2Fsi_czmEaiozX_UPp
3EupzeoTkWeOMpuqywViVJok2j-XBQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "at+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "U8oAnCApeS1Hb_9lRC2hGvSvxNxUL9YRk6F-hBmiwsY"
  }
}
```

```json
{
  "iat": 1680188549,
  "exp": 1687964549,
  "nbf": 1680188549,
  "iss": "http://wire.com:22913/",
  "sub": "im:wireapp=NzA3ZGY1MzBkODlkNDA0MjhlMjZiZTUzZWYwOTQwNTQ/5c442e4951cd4eb8@wire.com",
  "aud": "http://wire.com:22913/",
  "jti": "9227eec7-c7b0-4a73-9dd5-5b0372d73b16",
  "nonce": "dlBwNlJaZVA3MFVOM0NYRGVwU3lJbXhXUnNnR0cwMHM",
  "chal": "bqC8Q6uKR3e2tvUEniIdAr6KfOOyc4YR",
  "cnf": {
    "kid": "YQ5oKe68oF2tNVLTnf5ziBfHArZwsq8BgFpGFPO-PC8"
  },
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiZ242cnM4UFlkSEFLRURHVk1ZWTQtZUZOZzE5alh3SUxVYW9uYjJmZHNRTSJ9fQ.eyJpYXQiOjE2ODAxODg1NDksImV4cCI6MTY4MDE5MjE0OSwibmJmIjoxNjgwMTg4NTQ5LCJzdWIiOiJpbTp3aXJlYXBwPU56QTNaR1kxTXpCa09EbGtOREEwTWpobE1qWmlaVFV6WldZd09UUXdOVFEvNWM0NDJlNDk1MWNkNGViOEB3aXJlLmNvbSIsImp0aSI6ImU0ZDRhYmY5LTE4ZTUtNDRmOS04N2UyLTlhNDJhOTY1MGRjZCIsIm5vbmNlIjoiZGxCd05sSmFaVkEzTUZWT00wTllSR1Z3VTNsSmJYaFhVbk5uUjBjd01ITSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjI5MTMvIiwiY2hhbCI6ImJxQzhRNnVLUjNlMnR2VUVuaUlkQXI2S2ZPT3ljNFlSIn0.VxVLhIu6BlHtkRRVsj56nwPhGnrfPnGdGvSWdJytrPRtWULKgrxsjt5EPL6CZi5jy6Z2OW_IdgC9i3tr395HDQ",
  "client_id": "im:wireapp=NzA3ZGY1MzBkODlkNDA0MjhlMjZiZTUzZWYwOTQwNTQ/5c442e4951cd4eb8@wire.com",
  "api_version": 3,
  "scope": "wire_client_id"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIEHa82RlbZ+MZWy5pQk+nteb9vvW5fD5RvuptzWvTty7
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAU8oAnCApeS1Hb/9lRC2hGvSvxNxUL9YRk6F+hBmiwsY=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/8T0p0u1lxsCezM22dTdhjM0WW4cNz2NC
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2Mzc5L2FjbWUvd2lyZS9hY2NvdW50LzZhSXZwWVhadVZDSFVOWG14cjhnZEJIY0RwczlTYXZHIiwidHlwIjoiSldUIiwibm9uY2UiOiJjekZFYjFWRllub3diMFZ4TjJGdllYcFJRVVZXVjJ3Mk1HRkxWVXBwUVV3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNzkvYWNtZS93aXJlL2NoYWxsZW5nZS9xajBDUFFLbGxtcGd4bUhpazg5MFdYd2RIVU5rTjE4MC84VDBwMHUxbHhzQ2V6TTIyZFRkaGpNMFdXNGNOejJOQyJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklsVTRiMEZ1UTBGd1pWTXhTR0pmT1d4U1F6Sm9SM1pUZG5oT2VGVk1PVmxTYXpaR0xXaENiV2wzYzFraWZYMC5leUpwWVhRaU9qRTJPREF4T0RnMU5Ea3NJbVY0Y0NJNk1UWTROemsyTkRVME9Td2libUptSWpveE5qZ3dNVGc0TlRRNUxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJNU1UTXZJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFPZWtFeldrZFpNVTE2UW10UFJHeHJUa1JCTUUxcWFHeE5hbHBwV2xSVmVscFhXWGRQVkZGM1RsUlJMelZqTkRReVpUUTVOVEZqWkRSbFlqaEFkMmx5WlM1amIyMGlMQ0poZFdRaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qSTVNVE12SWl3aWFuUnBJam9pT1RJeU4yVmxZemN0WXpkaU1DMDBZVGN6TFRsa1pEVXROV0l3TXpjeVpEY3pZakUySWl3aWJtOXVZMlVpT2lKa2JFSjNUbXhLWVZwV1FUTk5SbFpQVFRCT1dWSkhWbmRWTTJ4S1lsaG9XRlZ1VG01U01HTjNUVWhOSWl3aVkyaGhiQ0k2SW1KeFF6aFJOblZMVWpObE1uUjJWVVZ1YVVsa1FYSTJTMlpQVDNsak5GbFNJaXdpWTI1bUlqcDdJbXRwWkNJNklsbFJOVzlMWlRZNGIwWXlkRTVXVEZSdVpqVjZhVUptU0VGeVduZHpjVGhDWjBad1IwWlFUeTFRUXpnaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsYU1qUXlZMjVOTkZWR2JHdFRSVVpNVWxWU1NGWnJNVnBYVkZGMFdsVmFUMXA2UlRWaGJHZ3pVMVY0VmxsWE9YVlpha3B0V2toT1VsUlRTamxtVVM1bGVVcHdXVmhSYVU5cVJUSlBSRUY0VDBSbk1VNUVhM05KYlZZMFkwTkpOazFVV1RSTlJFVTFUV3BGTUU5VGQybGliVXB0U1dwdmVFNXFaM2ROVkdjMFRsUlJOVXhEU25wa1YwbHBUMmxLY0dKVWNETmhXRXBzV1ZoQ2QxQlZOVFpSVkU1aFVqRnJlRlJZY0VOaE1EbEZZa2QwVDFKRlJYZFVWM0J2WWtVeGNWZHRiR0ZXUmxZMlYyeGtXbVF3T1ZWVldHUlBWa1pGZGs1WFRUQk9SRXBzVGtSck1VMVhUbXRPUjFacFQwVkNNMkZZU214TWJVNTJZbE5KYzBsdGNEQmhVMGsyU1cxVk1GcEVVbWhaYlZrMVRGUkZORnBVVlhST1JGSnRUMU13TkU0eVZYbE1WR3hvVGtSS2FFOVVXVEZOUjFKcVdrTkpjMGx0TlhaaWJVNXNTV3B2YVZwSGVFTmtNRFZ6VTIxR1lWWnJSWHBVVlZwWFZEQXdkMVJzYkZOU01Wb3pWbFJPYzFOdFNsbGhSbWhXWW1zMWRWVnFRbXBrTURGSlZGTkpjMGx0YURCaVUwazJTV3hDVUZVeFVXbE1RMHB2WkVoVmFVOXBTbTlrU0ZKM1QyazRkbVF5YkhsYVV6VnFZakl3TmsxcVNUVk5WRTEyU1dsM2FWa3lhR2hpUTBrMlNXMUtlRkY2YUZKT2JsWk1WV3BPYkUxdVVqSldWVloxWVZWc2ExRllTVEpUTWxwUVZETnNhazVHYkZOSmJqQXVWbmhXVEdoSmRUWkNiRWgwYTFKU1ZuTnFOVFp1ZDFCb1IyNXlabEJ1UjJSSGRsTlhaRXA1ZEhKUVVuUlhWVXhMWjNKNGMycDBOVVZRVERaRFdtazFhbmsyV2pKUFYxOUpaR2RET1dremRISXpPVFZJUkZFaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFU1NlFUTmFSMWt4VFhwQ2EwOUViR3RPUkVFd1RXcG9iRTFxV21sYVZGVjZXbGRaZDA5VVVYZE9WRkV2TldNME5ESmxORGsxTVdOa05HVmlPRUIzYVhKbExtTnZiU0lzSW1Gd2FWOTJaWEp6YVc5dUlqb3pMQ0p6WTI5d1pTSTZJbmRwY21WZlkyeHBaVzUwWDJsa0luMC5ENDVVNGZDQ051aEpGdG9SVVk5cWJxbUZucXNpVkxWLWZGTnBmYjJGc2lfY3ptRWFpb3pYX1VQcDNFdXB6ZW9Ua1dlT01wdXF5d1ZpVkpvazJqLVhCUSJ9",
  "signature": "JRrhsp7nUMcQofgYz252bOymf5dgf-K_NJLpNd-X2qqw104UDLRsBX-RVcXpZVcV9r9x_c30HJt-ccj2haS4Dw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56379/acme/wire/account/6aIvpYXZuVCHUNXmxr8gdBHcDps9SavG",
    "typ": "JWT",
    "nonce": "czFEb1VFYnowb0VxN2FvYXpRQUVWV2w2MGFLVUppQUw",
    "url": "https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/8T0p0u1lxsCezM22dTdhjM0WW4cNz2NC"
  },
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlU4b0FuQ0FwZVMxSGJfOWxSQzJoR3ZTdnhOeFVMOVlSazZGLWhCbWl3c1kifX0.eyJpYXQiOjE2ODAxODg1NDksImV4cCI6MTY4Nzk2NDU0OSwibmJmIjoxNjgwMTg4NTQ5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjI5MTMvIiwic3ViIjoiaW06d2lyZWFwcD1OekEzWkdZMU16QmtPRGxrTkRBME1qaGxNalppWlRVelpXWXdPVFF3TlRRLzVjNDQyZTQ5NTFjZDRlYjhAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjI5MTMvIiwianRpIjoiOTIyN2VlYzctYzdiMC00YTczLTlkZDUtNWIwMzcyZDczYjE2Iiwibm9uY2UiOiJkbEJ3TmxKYVpWQTNNRlZPTTBOWVJHVndVM2xKYlhoWFVuTm5SMGN3TUhNIiwiY2hhbCI6ImJxQzhRNnVLUjNlMnR2VUVuaUlkQXI2S2ZPT3ljNFlSIiwiY25mIjp7ImtpZCI6IllRNW9LZTY4b0YydE5WTFRuZjV6aUJmSEFyWndzcThCZ0ZwR0ZQTy1QQzgifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2laMjQyY25NNFVGbGtTRUZMUlVSSFZrMVpXVFF0WlVaT1p6RTVhbGgzU1V4VllXOXVZakptWkhOUlRTSjlmUS5leUpwWVhRaU9qRTJPREF4T0RnMU5Ea3NJbVY0Y0NJNk1UWTRNREU1TWpFME9Td2libUptSWpveE5qZ3dNVGc0TlRRNUxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BVNTZRVE5hUjFreFRYcENhMDlFYkd0T1JFRXdUV3BvYkUxcVdtbGFWRlY2V2xkWmQwOVVVWGRPVkZFdk5XTTBOREpsTkRrMU1XTmtOR1ZpT0VCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VMFpEUmhZbVk1TFRFNFpUVXRORFJtT1MwNE4yVXlMVGxoTkRKaE9UWTFNR1JqWkNJc0ltNXZibU5sSWpvaVpHeENkMDVzU21GYVZrRXpUVVpXVDAwd1RsbFNSMVozVlROc1NtSllhRmhWYms1dVVqQmpkMDFJVFNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qSTVNVE12SWl3aVkyaGhiQ0k2SW1KeFF6aFJOblZMVWpObE1uUjJWVVZ1YVVsa1FYSTJTMlpQVDNsak5GbFNJbjAuVnhWTGhJdTZCbEh0a1JSVnNqNTZud1BoR25yZlBuR2RHdlNXZEp5dHJQUnRXVUxLZ3J4c2p0NUVQTDZDWmk1ank2WjJPV19JZGdDOWkzdHIzOTVIRFEiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU56QTNaR1kxTXpCa09EbGtOREEwTWpobE1qWmlaVFV6WldZd09UUXdOVFEvNWM0NDJlNDk1MWNkNGViOEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.D45U4fCCNuhJFtoRUY9qbqmFnqsiVLV-fFNpfb2Fsi_czmEaiozX_UPp3EupzeoTkWeOMpuqywViVJok2j-XBQ"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56379/acme/wire/directory>;rel="index"
link: <https://stepca:56379/acme/wire/authz/qj0CPQKllmpgxmHik890WXwdHUNkN180>;rel="up"
location: https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/8T0p0u1lxsCezM22dTdhjM0WW4cNz2NC
replay-nonce: ODBNT2VFQWtYZndiYTVCd0tXQVBnRlpRMXN1Z2wxV0Q
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/8T0p0u1lxsCezM22dTdhjM0WW4cNz2NC",
  "status": "valid",
  "token": "bqC8Q6uKR3e2tvUEniIdAr6KfOOyc4YR"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. Client clicks login button
```http request
GET http://wire.com:22913/login
```
#### 19. Resource server generates Verifier & Challenge Codes

```text
code_verifier=AiH5ORgqxa5EOAShISJrfD2XHbgqricG727GB1dsk_g&code_challenge=wQB_LEqH0Prf5wiZCMnpp7ESFgPBA42DvpJ30ep9Md4
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
  <form method="post" action="/dex/auth/ldap/login?back=&amp;state=azax4zk32tx42rcuryjweglzp">
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
POST http://dex:15050/dex/auth/ldap/login?back=&state=azax4zk32tx42rcuryjweglzp
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
        <input type="hidden" name="req" value="azax4zk32tx42rcuryjweglzp"/>
        <input type="hidden" name="approval" value="approve">
        <button type="submit" class="dex-btn theme-btn--success">
            <span class="dex-btn-text">Grant Access</span>
        </button>
      </form>
    </div>
    <div class="theme-form-row">
      <form method="post">
        <input type="hidden" name="req" value="azax4zk32tx42rcuryjweglzp"/>
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
POST http://dex:15050/dex/approval?req=azax4zk32tx42rcuryjweglzp&hmac=UD1TVZ6VC6Ek_tUqnhal1rmEJNrPMspjhUKpmc5EyU8
content-type: application/x-www-form-urlencoded
```
```text
approval=approve&req=azax4zk32tx42rcuryjweglzp
```
#### 25. Authorization server calls callback url with authorization code
```http request
GET http://wire.com/callback
accept: */*
referer: http://dex:15050/dex/approval?req=azax4zk32tx42rcuryjweglzp&hmac=UD1TVZ6VC6Ek_tUqnhal1rmEJNrPMspjhUKpmc5EyU8
host: wire.com:22913
```
#### 26. Resource server call /oauth/token to get Id token
```http request
POST http://dex:15050/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpOR1JOY0RJMmQwNUhkMXBXWWxOYVZtbHRTWGhyUzNScw==
```
```text
grant_type=authorization_code&code=artmh7iruqgnapepj6su6z4dk&code_verifier=AiH5ORgqxa5EOAShISJrfD2XHbgqricG727GB1dsk_g&redirect_uri=http%3A%2F%2Fwire.com%3A22913%2Fcallback
```
#### 27. Authorization server validates Verifier & Challenge Codes

```text
code_verifier=AiH5ORgqxa5EOAShISJrfD2XHbgqricG727GB1dsk_g&code_challenge=wQB_LEqH0Prf5wiZCMnpp7ESFgPBA42DvpJ30ep9Md4
```
#### 28. Authorization server returns Access & Id token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYTQ2OGY3NjY5NTkzNDIwMWY0ZmFkZjEwYWVkZTI1N2IwZmYxZGMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1MDUwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTU2UVROYVIxa3hUWHBDYTA5RWJHdE9SRUV3VFdwb2JFMXFXbWxhVkZWNldsZFpkMDlVVVhkT1ZGRXZOV00wTkRKbE5EazFNV05rTkdWaU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMjc0OTQ5LCJpYXQiOjE2ODAxODg1NDksIm5vbmNlIjoiM1pBcGtjODBqVU1HV0JkQlkwZ0gzZyIsImF0X2hhc2giOiJIVHNXYlJRdEpnQ0ZKakVkMGpZQTl3IiwibmFtZSI6ImFsaWNlLnNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.I8QX26pao45n2e1_DLLKoLTRb97kEUbfD3CMvcntPg27fdko05hjEEWy5vE89kwGiIXdM54bULVYyOujEbg23qZ2wR2EouMNjZSb71jgB2b6TRiIDJ0OQx3kYmo8pISFybNMJ-T46RyA8_Exq5ob3zs75KUK6ROiBdr59GwUROrQG93jAi83POEh0itsvh71vhAMDoBB0MjIUmOtwE3lwXAqwSDzUyRXdt_iH-r_3WFsJu-gleTvHW4Bj24IMQhpvf2vBxmg0Q8xGDW8UiVr5IWQDH7EPgas2NihiKjft2lHAzSRsdk-ueVCk-jEuCOw5LCsq2jJ_O3n5tsid2fsJQ",
  "token_type": "bearer",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYTQ2OGY3NjY5NTkzNDIwMWY0ZmFkZjEwYWVkZTI1N2IwZmYxZGMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1MDUwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTU2UVROYVIxa3hUWHBDYTA5RWJHdE9SRUV3VFdwb2JFMXFXbWxhVkZWNldsZFpkMDlVVVhkT1ZGRXZOV00wTkRKbE5EazFNV05rTkdWaU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMjc0OTQ5LCJpYXQiOjE2ODAxODg1NDksIm5vbmNlIjoiM1pBcGtjODBqVU1HV0JkQlkwZ0gzZyIsImF0X2hhc2giOiJGUGlqTGJFS1FhWG1JU1RNYlBwclFRIiwiY19oYXNoIjoiSUFiZWNWSEs5R0RHck1GUVI1ckpUdyIsIm5hbWUiOiJhbGljZS5zbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IlNtaXRoLCBBbGljZSBNIChRQSkifQ.GENirtBtyYcN9J4bXzkvphsyT1Xiyuwigz5_iaj58ocZHWCF2zjUAZakOzWPeBZGVg6wqVZVMClspV1a4jkPrhdOqyZy2OCxJAvxf0h4h_U3fH2-odVndXdOUqZDQUZAinGDkJdhnoRLZhQP4aCd2mzwubmnvQeI3qwUtliXDojyGIdzTnE0AzIaK6brTat-F56IXFEKhIT7Z3gcaB0W7qz_KoF1iWY8-BA8JxV81IQlD78rqh0L0pApbmnZYRnZRfrKTDGMUZCY4TySeI1G6v955P9wNJrWl4IZuvtcAR6jkR1At8-GTyezb4UIF5GqUzAvfeG5HmxQHUv04bnFyw"
}
```
#### 29. Resource server returns Id token to client

```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYTQ2OGY3NjY5NTkzNDIwMWY0ZmFkZjEwYWVkZTI1N2IwZmYxZGMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1MDUwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTU2UVROYVIxa3hUWHBDYTA5RWJHdE9SRUV3VFdwb2JFMXFXbWxhVkZWNldsZFpkMDlVVVhkT1ZGRXZOV00wTkRKbE5EazFNV05rTkdWaU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMjc0OTQ5LCJpYXQiOjE2ODAxODg1NDksIm5vbmNlIjoiM1pBcGtjODBqVU1HV0JkQlkwZ0gzZyIsImF0X2hhc2giOiJGUGlqTGJFS1FhWG1JU1RNYlBwclFRIiwiY19oYXNoIjoiSUFiZWNWSEs5R0RHck1GUVI1ckpUdyIsIm5hbWUiOiJhbGljZS5zbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IlNtaXRoLCBBbGljZSBNIChRQSkifQ.GENirtBtyYcN9J4bXzkvphsyT1Xiyuwigz5_iaj58ocZHWCF2zjUAZakOzWPeBZGVg6wqVZVMClspV1a4jkPrhdOqyZy2OCxJAvxf0h4h_U3fH2-odVndXdOUqZDQUZAinGDkJdhnoRLZhQP4aCd2mzwubmnvQeI3qwUtliXDojyGIdzTnE0AzIaK6brTat-F56IXFEKhIT7Z3gcaB0W7qz_KoF1iWY8-BA8JxV81IQlD78rqh0L0pApbmnZYRnZRfrKTDGMUZCY4TySeI1G6v955P9wNJrWl4IZuvtcAR6jkR1At8-GTyezb4UIF5GqUzAvfeG5HmxQHUv04bnFyw
```
#### 30. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYTQ2OGY3NjY5NTkzNDIwMWY0ZmFkZjEwYWVkZTI1N2IwZmYxZGMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1MDUwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTU2UVROYVIxa3hUWHBDYTA5RWJHdE9SRUV3VFdwb2JFMXFXbWxhVkZWNldsZFpkMDlVVVhkT1ZGRXZOV00wTkRKbE5EazFNV05rTkdWaU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMjc0OTQ5LCJpYXQiOjE2ODAxODg1NDksIm5vbmNlIjoiM1pBcGtjODBqVU1HV0JkQlkwZ0gzZyIsImF0X2hhc2giOiJGUGlqTGJFS1FhWG1JU1RNYlBwclFRIiwiY19oYXNoIjoiSUFiZWNWSEs5R0RHck1GUVI1ckpUdyIsIm5hbWUiOiJhbGljZS5zbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IlNtaXRoLCBBbGljZSBNIChRQSkifQ.GENirtBtyYcN9J4bXzkvphsyT1Xiyuwigz5_iaj58ocZHWCF2zjUAZakOzWPeBZGVg6wqVZVMClspV1a4jkPrhdOqyZy2OCxJAvxf0h4h_U3fH2-odVndXdOUqZDQUZAinGDkJdhnoRLZhQP4aCd2mzwubmnvQeI3qwUtliXDojyGIdzTnE0AzIaK6brTat-F56IXFEKhIT7Z3gcaB0W7qz_KoF1iWY8-BA8JxV81IQlD78rqh0L0pApbmnZYRnZRfrKTDGMUZCY4TySeI1G6v955P9wNJrWl4IZuvtcAR6jkR1At8-GTyezb4UIF5GqUzAvfeG5HmxQHUv04bnFyw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYTQ2OGY3NjY5NTkzNDIwMWY0ZmFkZjEw
YWVkZTI1N2IwZmYxZGMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1MDUwL2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTU2UVROYVIxa3hUWHBDYTA5RWJHdE9SR
UV3VFdwb2JFMXFXbWxhVkZWNldsZFpkMDlVVVhkT1ZGRXZOV00wTkRKbE5EazFNV
05rTkdWaU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjgwMjc0OTQ5LCJpYXQiOjE2ODAxODg1NDksIm5vbmNlIjoiM1pBcGtjO
DBqVU1HV0JkQlkwZ0gzZyIsImF0X2hhc2giOiJGUGlqTGJFS1FhWG1JU1RNYlBwc
lFRIiwiY19oYXNoIjoiSUFiZWNWSEs5R0RHck1GUVI1ckpUdyIsIm5hbWUiOiJhb
GljZS5zbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IlNtaXRoLCBBbGljZSBNI
ChRQSkifQ.GENirtBtyYcN9J4bXzkvphsyT1Xiyuwigz5_iaj58ocZHWCF2zjUAZ
akOzWPeBZGVg6wqVZVMClspV1a4jkPrhdOqyZy2OCxJAvxf0h4h_U3fH2-odVndX
dOUqZDQUZAinGDkJdhnoRLZhQP4aCd2mzwubmnvQeI3qwUtliXDojyGIdzTnE0Az
IaK6brTat-F56IXFEKhIT7Z3gcaB0W7qz_KoF1iWY8-BA8JxV81IQlD78rqh0L0p
ApbmnZYRnZRfrKTDGMUZCY4TySeI1G6v955P9wNJrWl4IZuvtcAR6jkR1At8-GTy
ezb4UIF5GqUzAvfeG5HmxQHUv04bnFyw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "6ba468f76695934201f4fadf10aede257b0ff1dc"
}
```

```json
{
  "iss": "http://dex:15050/dex",
  "sub": "ClBpbTp3aXJlYXBwPU56QTNaR1kxTXpCa09EbGtOREEwTWpobE1qWmlaVFV6WldZd09UUXdOVFEvNWM0NDJlNDk1MWNkNGViOEB3aXJlLmNvbRIEbGRhcA",
  "aud": "wireapp",
  "exp": 1680274949,
  "iat": 1680188549,
  "nonce": "3ZApkc80jUMGWBdBY0gH3g",
  "at_hash": "FPijLbEKQaXmISTMbPprQQ",
  "c_hash": "IAbecVHK9GDGrMFQR5rJTw",
  "name": "alice.smith",
  "preferred_username": "Smith, Alice M (QA)"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt2NCVQndwFIoQX5Rg/bT
SBWnZD9xAxxOIaYrfaZsVexNYSZxF7eUO2E9TLzMj1WRiw5xkCAd23AItEGKkSMM
a82WkfMhWSYeJm2OSlXfoTjiYPdwGAUPKPxwywJbWFZjyBTYTQCzlnz+I74ttqcd
zm8zBdFU93hQuC4ETgRHsm8Pr5w+XFrl76hAkpWkRwbqfMWnEXe38GjEuPW6i9N8
EcGJErfo7xaRQos0W8M2XC501tG3vmdTqO8/Ylb+K6ueOjvNT8y/CoBwtH68P4VS
ugtYXG0r66EwmZVD9OG3gYHthxn1z/xwzkUaovXVFt9R9eLXi2aqMTzv8m7bGPqz
wwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/rWT4tf7ppbiJvgbOgePKPrFViNaJb0vb
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2Mzc5L2FjbWUvd2lyZS9hY2NvdW50LzZhSXZwWVhadVZDSFVOWG14cjhnZEJIY0RwczlTYXZHIiwidHlwIjoiSldUIiwibm9uY2UiOiJPREJOVDJWRlFXdFlabmRpWVRWQ2QwdFhRVkJuUmxwUk1YTjFaMnd4VjBRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNzkvYWNtZS93aXJlL2NoYWxsZW5nZS9xajBDUFFLbGxtcGd4bUhpazg5MFdYd2RIVU5rTjE4MC9yV1Q0dGY3cHBiaUp2Z2JPZ2VQS1ByRlZpTmFKYjB2YiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJalppWVRRMk9HWTNOalk1TlRrek5ESXdNV1kwWm1Ga1pqRXdZV1ZrWlRJMU4ySXdabVl4WkdNaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTFNRFV3TDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZUVTJVVlJPWVZJeGEzaFVXSEJEWVRBNVJXSkhkRTlTUlVWM1ZGZHdiMkpGTVhGWGJXeGhWa1pXTmxkc1pGcGtNRGxWVlZoa1QxWkdSWFpPVjAwd1RrUktiRTVFYXpGTlYwNXJUa2RXYVU5RlFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qZ3dNamMwT1RRNUxDSnBZWFFpT2pFMk9EQXhPRGcxTkRrc0ltNXZibU5sSWpvaU0xcEJjR3RqT0RCcVZVMUhWMEprUWxrd1owZ3paeUlzSW1GMFgyaGhjMmdpT2lKR1VHbHFUR0pGUzFGaFdHMUpVMVJOWWxCd2NsRlJJaXdpWTE5b1lYTm9Jam9pU1VGaVpXTldTRXM1UjBSSGNrMUdVVkkxY2twVWR5SXNJbTVoYldVaU9pSmhiR2xqWlM1emJXbDBhQ0lzSW5CeVpXWmxjbkpsWkY5MWMyVnlibUZ0WlNJNklsTnRhWFJvTENCQmJHbGpaU0JOSUNoUlFTa2lmUS5HRU5pcnRCdHlZY045SjRiWHprdnBoc3lUMVhpeXV3aWd6NV9pYWo1OG9jWkhXQ0YyempVQVpha096V1BlQlpHVmc2d3FWWlZNQ2xzcFYxYTRqa1ByaGRPcXlaeTJPQ3hKQXZ4ZjBoNGhfVTNmSDItb2RWbmRYZE9VcVpEUVVaQWluR0RrSmRobm9STFpoUVA0YUNkMm16d3VibW52UWVJM3F3VXRsaVhEb2p5R0lkelRuRTBBeklhSzZiclRhdC1GNTZJWEZFS2hJVDdaM2djYUIwVzdxel9Lb0YxaVdZOC1CQThKeFY4MUlRbEQ3OHJxaDBMMHBBcGJtblpZUm5aUmZyS1RER01VWkNZNFR5U2VJMUc2djk1NVA5d05KcldsNEladXZ0Y0FSNmprUjFBdDgtR1R5ZXpiNFVJRjVHcVV6QXZmZUc1SG14UUhVdjA0Ym5GeXciLCJrZXlhdXRoIjoiYnFDOFE2dUtSM2UydHZVRW5pSWRBcjZLZk9PeWM0WVIuRkxuYzlWczBfMndQcjRlNEV1YlZuWEJCcVJKM2VaMWh4ZHREdjJpdmFuTSJ9",
  "signature": "KZrhCAKpN1Ba0P362tvOh-erES0lC-lsIg5Rfi1aNPV8g9fLoZQF6kxj2MXDCe1zaO-dw1Od4NAVRtz28rwXAQ"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56379/acme/wire/account/6aIvpYXZuVCHUNXmxr8gdBHcDps9SavG",
    "typ": "JWT",
    "nonce": "ODBNT2VFQWtYZndiYTVCd0tXQVBnRlpRMXN1Z2wxV0Q",
    "url": "https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/rWT4tf7ppbiJvgbOgePKPrFViNaJb0vb"
  },
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjZiYTQ2OGY3NjY5NTkzNDIwMWY0ZmFkZjEwYWVkZTI1N2IwZmYxZGMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1MDUwL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTU2UVROYVIxa3hUWHBDYTA5RWJHdE9SRUV3VFdwb2JFMXFXbWxhVkZWNldsZFpkMDlVVVhkT1ZGRXZOV00wTkRKbE5EazFNV05rTkdWaU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMjc0OTQ5LCJpYXQiOjE2ODAxODg1NDksIm5vbmNlIjoiM1pBcGtjODBqVU1HV0JkQlkwZ0gzZyIsImF0X2hhc2giOiJGUGlqTGJFS1FhWG1JU1RNYlBwclFRIiwiY19oYXNoIjoiSUFiZWNWSEs5R0RHck1GUVI1ckpUdyIsIm5hbWUiOiJhbGljZS5zbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IlNtaXRoLCBBbGljZSBNIChRQSkifQ.GENirtBtyYcN9J4bXzkvphsyT1Xiyuwigz5_iaj58ocZHWCF2zjUAZakOzWPeBZGVg6wqVZVMClspV1a4jkPrhdOqyZy2OCxJAvxf0h4h_U3fH2-odVndXdOUqZDQUZAinGDkJdhnoRLZhQP4aCd2mzwubmnvQeI3qwUtliXDojyGIdzTnE0AzIaK6brTat-F56IXFEKhIT7Z3gcaB0W7qz_KoF1iWY8-BA8JxV81IQlD78rqh0L0pApbmnZYRnZRfrKTDGMUZCY4TySeI1G6v955P9wNJrWl4IZuvtcAR6jkR1At8-GTyezb4UIF5GqUzAvfeG5HmxQHUv04bnFyw",
    "keyauth": "bqC8Q6uKR3e2tvUEniIdAr6KfOOyc4YR.FLnc9Vs0_2wPr4e4EubVnXBBqRJ3eZ1hxdtDv2ivanM"
  }
}
```
#### 31. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56379/acme/wire/directory>;rel="index"
link: <https://stepca:56379/acme/wire/authz/qj0CPQKllmpgxmHik890WXwdHUNkN180>;rel="up"
location: https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/rWT4tf7ppbiJvgbOgePKPrFViNaJb0vb
replay-nonce: ZERQQ2J5endCSmx4UnZIRzRMbnliWmlhaU10cjZQeFA
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:56379/acme/wire/challenge/qj0CPQKllmpgxmHik890WXwdHUNkN180/rWT4tf7ppbiJvgbOgePKPrFViNaJb0vb",
  "status": "valid",
  "token": "bqC8Q6uKR3e2tvUEniIdAr6KfOOyc4YR"
}
```
### Client presents a CSR and gets its certificate
#### 32. verify the status of the order
```http request
POST https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2Mzc5L2FjbWUvd2lyZS9hY2NvdW50LzZhSXZwWVhadVZDSFVOWG14cjhnZEJIY0RwczlTYXZHIiwidHlwIjoiSldUIiwibm9uY2UiOiJaRVJRUTJKNWVuZENTbXg0VW5aSVJ6Uk1ibmxpV21saGFVMTBjalpRZUZBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNzkvYWNtZS93aXJlL29yZGVyL0lVWk5nUHBjSFFKTXhZZlIxRmtUaEtuVlpaSlRtV2oyIn0",
  "payload": "",
  "signature": "6bBqFT5uU8lFCJWwPwQhWeAn3KMcRh-1JgsjPuRboLeZhVe_DGszTwyJNE419HZaMZMCcv4MNb4P7-B0Y10zCw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56379/acme/wire/account/6aIvpYXZuVCHUNXmxr8gdBHcDps9SavG",
    "typ": "JWT",
    "nonce": "ZERQQ2J5endCSmx4UnZIRzRMbnliWmlhaU10cjZQeFA",
    "url": "https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2"
  },
  "payload": {}
}
```
#### 33. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56379/acme/wire/directory>;rel="index"
location: https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2
replay-nonce: RWQ5VXhxWmdoNDhtWDRrNjdia0EwQnJiSHFZWUkxOWk
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NzA3ZGY1MzBkODlkNDA0MjhlMjZiZTUzZWYwOTQwNTQ/5c442e4951cd4eb8@wire.com\",\"handle\":\"alice.smith\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56379/acme/wire/authz/qj0CPQKllmpgxmHik890WXwdHUNkN180"
  ],
  "expires": "2023-03-31T15:02:29Z",
  "notBefore": "2023-03-30T15:02:29.723369Z",
  "notAfter": "2023-03-30T16:02:29.723369Z"
}
```
#### 34. create a CSR and call finalize url
```http request
POST https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2Mzc5L2FjbWUvd2lyZS9hY2NvdW50LzZhSXZwWVhadVZDSFVOWG14cjhnZEJIY0RwczlTYXZHIiwidHlwIjoiSldUIiwibm9uY2UiOiJSV1E1VlhoeFdtZG9ORGh0V0RSck5qZGlhMEV3UW5KaVNIRlpXVWt4T1drIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNzkvYWNtZS93aXJlL29yZGVyL0lVWk5nUHBjSFFKTXhZZlIxRmtUaEtuVlpaSlRtV2oyL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTkRDQjV3SUJBREE1TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFa01DSUdDMkNHU0FHRy1FSURBWUZ4REJOVGJXbDBhQ3dnUVd4cFkyVWdUU0FvVVVFcE1Db3dCUVlESzJWd0F5RUFnbjZyczhQWWRIQUtFREdWTVlZNC1lRk5nMTlqWHdJTFVhb25iMmZkc1FPZ2V6QjVCZ2txaGtpRzl3MEJDUTR4YkRCcU1HZ0dBMVVkRVFSaE1GLUdVR2x0T25kcGNtVmhjSEE5Ym5waE0zcG5lVEZ0ZW1KcmIyUnNhMjVrWVRCdGFtaHNiV3A2YVhwMGRYcDZkM2wzYjNSeGQyNTBjUzgxWXpRME1tVTBPVFV4WTJRMFpXSTRRSGRwY21VdVkyOXRoZ3RoYkdsalpTNXpiV2wwYURBRkJnTXJaWEFEUVFCZ2JGbmdZVDZGdGJlNWlpV2I3Y0pqRUxFUW5DQU5rWDhuQ3o3OWlYZkZ2RVBaaEg4SUZRY2lBeElvUGU5d1FOdUpkU3l3TFRUbzR3cy1Jam1iMlg0RyJ9",
  "signature": "LRE0sSVUxjrLA5_mPohsHFVapg9SnYiaDiwtMG76kG67BR4hUaqt77ST9SBliOPPcFoHwEbz7A75PWRe7ZxOAw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56379/acme/wire/account/6aIvpYXZuVCHUNXmxr8gdBHcDps9SavG",
    "typ": "JWT",
    "nonce": "RWQ5VXhxWmdoNDhtWDRrNjdia0EwQnJiSHFZWUkxOWk",
    "url": "https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2/finalize"
  },
  "payload": {
    "csr": "MIIBNDCB5wIBADA5MREwDwYDVQQKDAh3aXJlLmNvbTEkMCIGC2CGSAGG-EIDAYFxDBNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEAgn6rs8PYdHAKEDGVMYY4-eFNg19jXwILUaonb2fdsQOgezB5BgkqhkiG9w0BCQ4xbDBqMGgGA1UdEQRhMF-GUGltOndpcmVhcHA9bnphM3pneTFtemJrb2Rsa25kYTBtamhsbWp6aXp0dXp6d3l3b3Rxd250cS81YzQ0MmU0OTUxY2Q0ZWI4QHdpcmUuY29thgthbGljZS5zbWl0aDAFBgMrZXADQQBgbFngYT6Ftbe5iiWb7cJjELEQnCANkX8nCz79iXfFvEPZhH8IFQciAxIoPe9wQNuJdSywLTTo4ws-Ijmb2X4G"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBNDCB5wIBADA5MREwDwYDVQQKDAh3aXJlLmNvbTEkMCIGC2CGSAGG+EIDAYFx
DBNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEAgn6rs8PYdHAKEDGVMYY4
+eFNg19jXwILUaonb2fdsQOgezB5BgkqhkiG9w0BCQ4xbDBqMGgGA1UdEQRhMF+G
UGltOndpcmVhcHA9bnphM3pneTFtemJrb2Rsa25kYTBtamhsbWp6aXp0dXp6d3l3
b3Rxd250cS81YzQ0MmU0OTUxY2Q0ZWI4QHdpcmUuY29thgthbGljZS5zbWl0aDAF
BgMrZXADQQBgbFngYT6Ftbe5iiWb7cJjELEQnCANkX8nCz79iXfFvEPZhH8IFQci
AxIoPe9wQNuJdSywLTTo4ws+Ijmb2X4G
-----END CERTIFICATE REQUEST-----

```
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = wire.com, 2.16.840.1.113730.3.1.241 = "Smith, Alice M (QA)"
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    82:7e:ab:b3:c3:d8:74:70:0a:10:31:95:31:86:38:
                    f9:e1:4d:83:5f:63:5f:02:0b:51:aa:27:6f:67:dd:
                    b1:03
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=nza3zgy1mzbkodlknda0mjhlmjziztuzzwywotqwntq/5c442e4951cd4eb8@wire.com, URI:alice.smith
    Signature Algorithm: ED25519
    Signature Value:
        60:6c:59:e0:61:3e:85:b5:b7:b9:8a:25:9b:ed:c2:63:10:b1:
        10:9c:20:0d:91:7f:27:0b:3e:fd:89:77:c5:bc:43:d9:84:7f:
        08:15:07:22:03:12:28:3d:ef:70:40:db:89:75:2c:b0:2d:34:
        e8:e3:0b:3e:22:39:9b:d9:7e:06

```

#### 35. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56379/acme/wire/directory>;rel="index"
location: https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2
replay-nonce: bndNckxhV0tMMW82cTVUMzVubWNJQUVQMzRONVZVSDg
```
```json
{
  "certificate": "https://stepca:56379/acme/wire/certificate/IF3RiEp4JuW7Cag7YhWVqTriXPSq8YSP",
  "status": "valid",
  "finalize": "https://stepca:56379/acme/wire/order/IUZNgPpcHQJMxYfR1FkThKnVZZJTmWj2/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NzA3ZGY1MzBkODlkNDA0MjhlMjZiZTUzZWYwOTQwNTQ/5c442e4951cd4eb8@wire.com\",\"handle\":\"alice.smith\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56379/acme/wire/authz/qj0CPQKllmpgxmHik890WXwdHUNkN180"
  ],
  "expires": "2023-03-31T15:02:29Z",
  "notBefore": "2023-03-30T15:02:29.723369Z",
  "notAfter": "2023-03-30T16:02:29.723369Z"
}
```
#### 36. fetch the certificate
```http request
POST https://stepca:56379/acme/wire/certificate/IF3RiEp4JuW7Cag7YhWVqTriXPSq8YSP
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2Mzc5L2FjbWUvd2lyZS9hY2NvdW50LzZhSXZwWVhadVZDSFVOWG14cjhnZEJIY0RwczlTYXZHIiwidHlwIjoiSldUIiwibm9uY2UiOiJibmROY2t4aFYwdE1NVzgyY1RWVU16VnViV05KUVVWUU16Uk9OVlpWU0RnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNzkvYWNtZS93aXJlL2NlcnRpZmljYXRlL0lGM1JpRXA0SnVXN0NhZzdZaFdWcVRyaVhQU3E4WVNQIn0",
  "payload": "",
  "signature": "_AJu5-s8EghTCqVI18eJEVDh7b4gip6KWq-xyiMjlTho-i-kqo619dfegBk8-gPxqgjk0ZU1ZHjQvl5W10itCQ"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56379/acme/wire/account/6aIvpYXZuVCHUNXmxr8gdBHcDps9SavG",
    "typ": "JWT",
    "nonce": "bndNckxhV0tMMW82cTVUMzVubWNJQUVQMzRONVZVSDg",
    "url": "https://stepca:56379/acme/wire/certificate/IF3RiEp4JuW7Cag7YhWVqTriXPSq8YSP"
  },
  "payload": {}
}
```
#### 37. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:56379/acme/wire/directory>;rel="index"
replay-nonce: SnBrY1E1RkM1OTRqSE5BS1V3b20zTTJVbndrQ1VBbTM
```
```json
"-----BEGIN CERTIFICATE-----\nMIICKjCCAdCgAwIBAgIQIyhSonQ2OUxdD+ihiOTPczAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzAzMzAxNTAyMjlaFw0yMzAzMzAxNjAyMjlaMDExETAPBgNVBAoTCHdpcmUuY29t\nMRwwGgYDVQQDExNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEAgn6rs8PY\ndHAKEDGVMYY4+eFNg19jXwILUaonb2fdsQOjgfswgfgwDgYDVR0PAQH/BAQDAgeA\nMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUk6wRWZ6E\nTsVV5kgY03qJTPTx8P4wHwYDVR0jBBgwFoAUBxFnWEdAjxSQ/NdzGYYnEKd5ySww\naAYDVR0RBGEwX4YLYWxpY2Uuc21pdGiGUGltOndpcmVhcHA9bnphM3pneTFtemJr\nb2Rsa25kYTBtamhsbWp6aXp0dXp6d3l3b3Rxd250cS81YzQ0MmU0OTUxY2Q0ZWI4\nQHdpcmUuY29tMB0GDCsGAQQBgqRkxihAAQQNMAsCAQYEBHdpcmUEADAKBggqhkjO\nPQQDAgNIADBFAiAXI+z02wn3M62uxq6dUCrqRu/Ho7Z8QzVg4qPrcR6ePQIhAOao\nu7D5f/3VBugzpmDxzZEBXlbVOJ0lLhDLVaJX1Gef\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAKPQtQaVkXMZTtjRB0O9/x8wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMzMDE1\nMDIxOFoXDTMzMDMyNzE1MDIxOFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS9\ne/FC3Ih/mykB6bkkl+V/iJHPBEZXlMlv5/Vimpzn9Mw5f34VoRhbBHqe8PYR/0Fl\nVHR+VRkoTsmo8IxA7/N8o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUBxFnWEdAjxSQ/NdzGYYnEKd5ySwwHwYDVR0jBBgw\nFoAUCiYdxIj9OpxXw2A5eldf7A6Xo6kwCgYIKoZIzj0EAwIDSAAwRQIhAL+w6yii\neREk1LgbLxOBT4vk/0CDwyKefKqOGO3sBq8pAiBMED99hMRXrt3skQhwfWPwkOdB\n8ENcErnRGd87/bb/2g==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICKjCCAdCgAwIBAgIQIyhSonQ2OUxdD+ihiOTPczAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzAzMzAxNTAyMjlaFw0yMzAzMzAxNjAyMjlaMDExETAPBgNVBAoTCHdpcmUuY29t
MRwwGgYDVQQDExNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEAgn6rs8PY
dHAKEDGVMYY4+eFNg19jXwILUaonb2fdsQOjgfswgfgwDgYDVR0PAQH/BAQDAgeA
MB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUk6wRWZ6E
TsVV5kgY03qJTPTx8P4wHwYDVR0jBBgwFoAUBxFnWEdAjxSQ/NdzGYYnEKd5ySww
aAYDVR0RBGEwX4YLYWxpY2Uuc21pdGiGUGltOndpcmVhcHA9bnphM3pneTFtemJr
b2Rsa25kYTBtamhsbWp6aXp0dXp6d3l3b3Rxd250cS81YzQ0MmU0OTUxY2Q0ZWI4
QHdpcmUuY29tMB0GDCsGAQQBgqRkxihAAQQNMAsCAQYEBHdpcmUEADAKBggqhkjO
PQQDAgNIADBFAiAXI+z02wn3M62uxq6dUCrqRu/Ho7Z8QzVg4qPrcR6ePQIhAOao
u7D5f/3VBugzpmDxzZEBXlbVOJ0lLhDLVaJX1Gef
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            23:28:52:a2:74:36:39:4c:5d:0f:e8:a1:88:e4:cf:73
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Mar 30 15:02:29 2023 GMT
            Not After : Mar 30 16:02:29 2023 GMT
        Subject: O = wire.com, CN = "Smith, Alice M (QA)"
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    82:7e:ab:b3:c3:d8:74:70:0a:10:31:95:31:86:38:
                    f9:e1:4d:83:5f:63:5f:02:0b:51:aa:27:6f:67:dd:
                    b1:03
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                93:AC:11:59:9E:84:4E:C5:55:E6:48:18:D3:7A:89:4C:F4:F1:F0:FE
            X509v3 Authority Key Identifier: 
                07:11:67:58:47:40:8F:14:90:FC:D7:73:19:86:27:10:A7:79:C9:2C
            X509v3 Subject Alternative Name: 
                URI:alice.smith, URI:im:wireapp=nza3zgy1mzbkodlknda0mjhlmjziztuzzwywotqwntq/5c442e4951cd4eb8@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:17:23:ec:f4:db:09:f7:33:ad:ae:c6:ae:9d:50:
        2a:ea:46:ef:c7:a3:b6:7c:43:35:60:e2:a3:eb:71:1e:9e:3d:
        02:21:00:e6:a8:bb:b0:f9:7f:fd:d5:06:e8:33:a6:60:f1:cd:
        91:01:5e:56:d5:38:9d:25:2e:10:cb:55:a2:57:d4:67:9f

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAKPQtQaVkXMZTtjRB0O9/x8wCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMzMDE1
MDIxOFoXDTMzMDMyNzE1MDIxOFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS9
e/FC3Ih/mykB6bkkl+V/iJHPBEZXlMlv5/Vimpzn9Mw5f34VoRhbBHqe8PYR/0Fl
VHR+VRkoTsmo8IxA7/N8o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUBxFnWEdAjxSQ/NdzGYYnEKd5ySwwHwYDVR0jBBgw
FoAUCiYdxIj9OpxXw2A5eldf7A6Xo6kwCgYIKoZIzj0EAwIDSAAwRQIhAL+w6yii
eREk1LgbLxOBT4vk/0CDwyKefKqOGO3sBq8pAiBMED99hMRXrt3skQhwfWPwkOdB
8ENcErnRGd87/bb/2g==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            a3:d0:b5:06:95:91:73:19:4e:d8:d1:07:43:bd:ff:1f
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Mar 30 15:02:18 2023 GMT
            Not After : Mar 27 15:02:18 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:bd:7b:f1:42:dc:88:7f:9b:29:01:e9:b9:24:97:
                    e5:7f:88:91:cf:04:46:57:94:c9:6f:e7:f5:62:9a:
                    9c:e7:f4:cc:39:7f:7e:15:a1:18:5b:04:7a:9e:f0:
                    f6:11:ff:41:65:54:74:7e:55:19:28:4e:c9:a8:f0:
                    8c:40:ef:f3:7c
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                07:11:67:58:47:40:8F:14:90:FC:D7:73:19:86:27:10:A7:79:C9:2C
            X509v3 Authority Key Identifier: 
                0A:26:1D:C4:88:FD:3A:9C:57:C3:60:39:7A:57:5F:EC:0E:97:A3:A9
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:bf:b0:eb:28:a2:79:11:24:d4:b8:1b:2f:13:
        81:4f:8b:e4:ff:40:83:c3:22:9e:7c:aa:8e:18:ed:ec:06:af:
        29:02:20:4c:10:3f:7d:84:c4:57:ae:dd:ec:91:08:70:7d:63:
        f0:90:e7:41:f0:43:5c:12:b9:d1:19:df:3b:fd:b6:ff:da

```
