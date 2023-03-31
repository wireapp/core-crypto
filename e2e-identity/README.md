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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/14873968977886990451/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/1pceubrFUZAvVQI5XgtLDMfLefhOt4YI
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
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/k6kgSdPou50Dg67NAxYiycqIFfuoDyHo
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/tn6EGsb1UcZrhBej6dswoH1Z8GdzKdjs
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:56437/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:56437/acme/wire/new-nonce",
  "newAccount": "https://stepca:56437/acme/wire/new-account",
  "newOrder": "https://stepca:56437/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:56437/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:56437/acme/wire/directory>;rel="index"
replay-nonce: WjVoZlpKNzY3WFYwbVFxWkdNM2JnclJ6VHRVUm5DMWE
```
```text
WjVoZlpKNzY3WFYwbVFxWkdNM2JnclJ6VHRVUm5DMWE
```
#### 5. create a new account
```http request
POST https://stepca:56437/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjFUVzFTbWhkTUd4SU9tYjdEM3hVVWZzQUE4MEM0U0FXOUxGbGNBOWplNEEifSwibm9uY2UiOiJXalZvWmxwS056WTNXRll3YlZGeFdrZE5NMkpuY2xKNlZIUlZVbTVETVdFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTY0MzcvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "XcSoHt_I_G4R2ZpCdnqaWn9L3J8ssZQUG7Jb3wou6soRapdQxZo8OR88kbv-iIyMrvWGHJAAU97GrRHJ7SNICQ"
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
      "x": "1TW1SmhdMGxIOmb7D3xUUfsAA80C4SAW9LFlcA9je4A"
    },
    "nonce": "WjVoZlpKNzY3WFYwbVFxWkdNM2JnclJ6VHRVUm5DMWE",
    "typ": "JWT",
    "url": "https://stepca:56437/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:56437/acme/wire/directory>;rel="index"
location: https://stepca:56437/acme/wire/account/UwSlDcGbWOFkA7dimS4yEUki6ZEllaK4
replay-nonce: Z1FDc1ZENldKeXhtS1oxcjczQk45amFCMlZxZ3VhNUQ
```
```json
{
  "status": "valid",
  "orders": "https://stepca:56437/acme/wire/account/UwSlDcGbWOFkA7dimS4yEUki6ZEllaK4/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:56437/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2NDM3L2FjbWUvd2lyZS9hY2NvdW50L1V3U2xEY0diV09Ga0E3ZGltUzR5RVVraTZaRWxsYUs0IiwidHlwIjoiSldUIiwibm9uY2UiOiJaMUZEYzFaRU5sZEtlWGh0UzFveGNqY3pRazQ1YW1GQ01sWnhaM1ZoTlVRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTY0MzcvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIlNtaXRoLCBBbGljZSBNIChRQSlcIixcImRvbWFpblwiOlwid2lyZS5jb21cIixcImNsaWVudC1pZFwiOlwiaW06d2lyZWFwcD1aRGszT1RZd1lUbGxPV1JsTkdZeU16aG1PRGxsTjJRellUZGhORGRsTkRnL2NlNmFmM2ZhY2YyMjUwNzNAd2lyZS5jb21cIixcImhhbmRsZVwiOlwiaW06d2lyZWFwcD1hbGljZS5zbWl0aFwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wMy0zMVQxMDo1MTo0Ni42MTcxNFoiLCJub3RBZnRlciI6IjIwMjMtMDMtMzFUMTE6NTE6NDYuNjE3MTRaIn0",
  "signature": "bsQgnLd5zsI2TtYQ885-36ZKSr-sikEtn740DWx37uDaz4naBeR6PPubonlVb1ob_Q4upeg2OPHH9AqcgO4QAQ"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDk3OTYwYTllOWRlNGYyMzhmODllN2QzYTdhNDdlNDg/ce6af3facf225073@wire.com\",\"handle\":\"im:wireapp=alice.smith\"}"
      }
    ],
    "notAfter": "2023-03-31T11:51:46.61714Z",
    "notBefore": "2023-03-31T10:51:46.61714Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56437/acme/wire/account/UwSlDcGbWOFkA7dimS4yEUki6ZEllaK4",
    "nonce": "Z1FDc1ZENldKeXhtS1oxcjczQk45amFCMlZxZ3VhNUQ",
    "typ": "JWT",
    "url": "https://stepca:56437/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:56437/acme/wire/directory>;rel="index"
location: https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia
replay-nonce: QXMxVWpoVExtY2NrRDh5ODRGd0c0ZGpUd2Q5RXBaN2I
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDk3OTYwYTllOWRlNGYyMzhmODllN2QzYTdhNDdlNDg/ce6af3facf225073@wire.com\",\"handle\":\"im:wireapp=alice.smith\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56437/acme/wire/authz/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC"
  ],
  "expires": "2023-04-01T10:51:46Z",
  "notBefore": "2023-03-31T10:51:46.61714Z",
  "notAfter": "2023-03-31T11:51:46.61714Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:56437/acme/wire/authz/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2NDM3L2FjbWUvd2lyZS9hY2NvdW50L1V3U2xEY0diV09Ga0E3ZGltUzR5RVVraTZaRWxsYUs0IiwidHlwIjoiSldUIiwibm9uY2UiOiJRWE14Vldwb1ZFeHRZMk5yUkRoNU9EUkdkMGMwWkdwVWQyUTVSWEJhTjJJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTY0MzcvYWNtZS93aXJlL2F1dGh6L2ZvVk1Pdk1jYXBYbFdTckhxdTRCckQxUkZPUlpPR3JDIn0",
  "payload": "",
  "signature": "u0m03lAKKRRjk7t7_DQ_tCuI13V4x0y5dFcrsrRekZbywLvpwqylDxJF-sFREksfzTNsU2wfwr3UllE6S2C6AA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56437/acme/wire/account/UwSlDcGbWOFkA7dimS4yEUki6ZEllaK4",
    "nonce": "QXMxVWpoVExtY2NrRDh5ODRGd0c0ZGpUd2Q5RXBaN2I",
    "typ": "JWT",
    "url": "https://stepca:56437/acme/wire/authz/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC"
  }
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56437/acme/wire/directory>;rel="index"
location: https://stepca:56437/acme/wire/authz/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC
replay-nonce: RFRRUUhWYUZCOW1qb3dabHFOY3JoUFpWSmRldmVFbWo
```
```json
{
  "status": "pending",
  "expires": "2023-04-01T10:51:46Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/k6kgSdPou50Dg67NAxYiycqIFfuoDyHo",
      "status": "pending",
      "token": "NEi1HaRRYqM0R9cGZaHdv0dBWIkRbyCY"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/1pceubrFUZAvVQI5XgtLDMfLefhOt4YI",
      "status": "pending",
      "token": "NEi1HaRRYqM0R9cGZaHdv0dBWIkRbyCY"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDk3OTYwYTllOWRlNGYyMzhmODllN2QzYTdhNDdlNDg/ce6af3facf225073@wire.com\",\"handle\":\"im:wireapp=alice.smith\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:23961/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
SnduZDZFSkpWcnJjYVZxVHNjNkpGRUxjTzZWR3dIamk
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMVRXMVNtaGRNR3hJT21iN0QzeFVVZnNBQTgwQzRTQVc5TEZsY0E5amU0QSJ9fQ.eyJpYXQiOjE2ODAyNTk5MDYsImV4cCI6MTY4MDI2MzUwNiwibmJmIjoxNjgwMjU5OTA2LCJzdWIiOiJpbTp3aXJlYXBwPVpEazNPVFl3WVRsbE9XUmxOR1l5TXpobU9EbGxOMlF6WVRkaE5EZGxORGcvY2U2YWYzZmFjZjIyNTA3M0B3aXJlLmNvbSIsImp0aSI6Ijc5OTk2ZjE3LTRmZjUtNGMwZi04MTEwLThjYjczNzdmN2M0NCIsIm5vbmNlIjoiU25kdVpEWkZTa3BXY25KallWWnhWSE5qTmtwR1JVeGpUelpXUjNkSWFtayIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjM5NjEvIiwiY2hhbCI6Ik5FaTFIYVJSWXFNMFI5Y0daYUhkdjBkQldJa1JieUNZIn0.SsK6AIJmFq8m8Co71ffDUs08OiDIRXDJaS-_MhFbgK7dqUIRJLMQi4vA0awf39-h8eSMwo3_X77ZoCpp1fdTBw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMVRXMVNtaGRNR3hJT21iN0QzeFVVZnNB
QTgwQzRTQVc5TEZsY0E5amU0QSJ9fQ.eyJpYXQiOjE2ODAyNTk5MDYsImV4cCI6M
TY4MDI2MzUwNiwibmJmIjoxNjgwMjU5OTA2LCJzdWIiOiJpbTp3aXJlYXBwPVpEa
zNPVFl3WVRsbE9XUmxOR1l5TXpobU9EbGxOMlF6WVRkaE5EZGxORGcvY2U2YWYzZ
mFjZjIyNTA3M0B3aXJlLmNvbSIsImp0aSI6Ijc5OTk2ZjE3LTRmZjUtNGMwZi04M
TEwLThjYjczNzdmN2M0NCIsIm5vbmNlIjoiU25kdVpEWkZTa3BXY25KallWWnhWS
E5qTmtwR1JVeGpUelpXUjNkSWFtayIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MjM5NjEvIiwiY2hhbCI6Ik5FaTFIYVJSWXFNMFI5Y0daYUhkd
jBkQldJa1JieUNZIn0.SsK6AIJmFq8m8Co71ffDUs08OiDIRXDJaS-_MhFbgK7dq
UIRJLMQi4vA0awf39-h8eSMwo3_X77ZoCpp1fdTBw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "1TW1SmhdMGxIOmb7D3xUUfsAA80C4SAW9LFlcA9je4A"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "NEi1HaRRYqM0R9cGZaHdv0dBWIkRbyCY",
  "exp": 1680263506,
  "htm": "POST",
  "htu": "http://wire.com:23961/",
  "iat": 1680259906,
  "jti": "79996f17-4ff5-4c0f-8110-8cb7377f7c44",
  "nbf": 1680259906,
  "nonce": "SnduZDZFSkpWcnJjYVZxVHNjNkpGRUxjTzZWR3dIamk",
  "sub": "im:wireapp=ZDk3OTYwYTllOWRlNGYyMzhmODllN2QzYTdhNDdlNDg/ce6af3facf225073@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPLOTDee3o0wJJbgAGwOStTz64TvtjWZAjFkOA9eSxaR
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA1TW1SmhdMGxIOmb7D3xUUfsAA80C4SAW9LFlcA9je4A=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:23961/clients/14873968977886990451/access-token
                          /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTVZSWE1WTnRhR1JOUjNoSlQyMWlOMFF6ZUZWVlpuTkJRVGd3UXpSVFFWYzVURVpzWTBFNWFtVTBRU0o5ZlEuZXlKcFlYUWlPakUyT0RBeU5UazVNRFlzSW1WNGNDSTZNVFk0TURJMk16VXdOaXdpYm1KbUlqb3hOamd3TWpVNU9UQTJMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVnBFYXpOUFZGbDNXVlJzYkU5WFVteE9SMWw1VFhwb2JVOUViR3hPTWxGNldWUmthRTVFWkd4T1JHY3ZZMlUyWVdZelptRmpaakl5TlRBM00wQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqYzVPVGsyWmpFM0xUUm1aalV0TkdNd1ppMDRNVEV3TFRoallqY3pOemRtTjJNME5DSXNJbTV2Ym1ObElqb2lVMjVrZFZwRVdrWlRhM0JYWTI1S2FsbFdXbmhXU0U1cVRtdHdSMUpWZUdwVWVscFhVak5rU1dGdGF5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak01TmpFdklpd2lZMmhoYkNJNklrNUZhVEZJWVZKU1dYRk5NRkk1WTBkYVlVaGtkakJrUWxkSmExSmllVU5aSW4wLlNzSzZBSUptRnE4bThDbzcxZmZEVXMwOE9pRElSWERKYVMtX01oRmJnSzdkcVVJUkpMTVFpNHZBMGF3ZjM5LWg4ZVNNd28zX1g3N1pvQ3BwMWZkVEJ3
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdVdXlTWVlUZ1laMHdoam5icklsZTd1M3pkZE55cWtmOG45bWFfMXpPUVEifX0.eyJpYXQiOjE2ODAyNTk5MDYsImV4cCI6MTY4ODAzNTkwNiwibmJmIjoxNjgwMjU5OTA2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM5NjEvIiwic3ViIjoiaW06d2lyZWFwcD1aRGszT1RZd1lUbGxPV1JsTkdZeU16aG1PRGxsTjJRellUZGhORGRsTkRnL2NlNmFmM2ZhY2YyMjUwNzNAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjM5NjEvIiwianRpIjoiNmMwZTQwZjItOTEzZC00ZmYzLWIzYWQtZmU2NWI4NDJhNWUzIiwibm9uY2UiOiJTbmR1WkRaRlNrcFdjbkpqWVZaeFZITmpOa3BHUlV4alR6WldSM2RJYW1rIiwiY2hhbCI6Ik5FaTFIYVJSWXFNMFI5Y0daYUhkdjBkQldJa1JieUNZIiwiY25mIjp7ImtpZCI6IlBuWlZmUG00SEl6SHB0cVdrRXNWdzRHYXJNdGpmTGRGdEdTWF9jd09fd0UifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNVlJYTVZOdGFHUk5SM2hKVDIxaU4wUXplRlZWWm5OQlFUZ3dRelJUUVZjNVRFWnNZMEU1YW1VMFFTSjlmUS5leUpwWVhRaU9qRTJPREF5TlRrNU1EWXNJbVY0Y0NJNk1UWTRNREkyTXpVd05pd2libUptSWpveE5qZ3dNalU1T1RBMkxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWcEVhek5QVkZsM1dWUnNiRTlYVW14T1IxbDVUWHBvYlU5RWJHeE9NbEY2V1ZSa2FFNUVaR3hPUkdjdlkyVTJZV1l6Wm1GalpqSXlOVEEzTTBCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpjNU9UazJaakUzTFRSbVpqVXROR013WmkwNE1URXdMVGhqWWpjek56ZG1OMk0wTkNJc0ltNXZibU5sSWpvaVUyNWtkVnBFV2taVGEzQlhZMjVLYWxsV1duaFdTRTVxVG10d1IxSlZlR3BVZWxwWFVqTmtTV0Z0YXlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qTTVOakV2SWl3aVkyaGhiQ0k2SWs1RmFURklZVkpTV1hGTk1GSTVZMGRhWVVoa2RqQmtRbGRKYTFKaWVVTlpJbjAuU3NLNkFJSm1GcThtOENvNzFmZkRVczA4T2lESVJYREphUy1fTWhGYmdLN2RxVUlSSkxNUWk0dkEwYXdmMzktaDhlU013bzNfWDc3Wm9DcHAxZmRUQnciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVpEazNPVFl3WVRsbE9XUmxOR1l5TXpobU9EbGxOMlF6WVRkaE5EZGxORGcvY2U2YWYzZmFjZjIyNTA3M0B3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.bq5zfvEN6wpXGo0Fqz9s4UyrB-qXcKmMTMKP9puDduR2kqZ1U8EWs2m2r3-ornn1Ju0DUmh-zZWEAqfzOFHTAQ",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdVdXlTWVlUZ1laMHdoam5icklsZTd1M3pkZE55cWtmOG45bWFfMXpPUVEifX0.eyJpYXQiOjE2ODAyNTk5MDYsImV4cCI6MTY4ODAzNTkwNiwibmJmIjoxNjgwMjU5OTA2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM5NjEvIiwic3ViIjoiaW06d2lyZWFwcD1aRGszT1RZd1lUbGxPV1JsTkdZeU16aG1PRGxsTjJRellUZGhORGRsTkRnL2NlNmFmM2ZhY2YyMjUwNzNAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjM5NjEvIiwianRpIjoiNmMwZTQwZjItOTEzZC00ZmYzLWIzYWQtZmU2NWI4NDJhNWUzIiwibm9uY2UiOiJTbmR1WkRaRlNrcFdjbkpqWVZaeFZITmpOa3BHUlV4alR6WldSM2RJYW1rIiwiY2hhbCI6Ik5FaTFIYVJSWXFNMFI5Y0daYUhkdjBkQldJa1JieUNZIiwiY25mIjp7ImtpZCI6IlBuWlZmUG00SEl6SHB0cVdrRXNWdzRHYXJNdGpmTGRGdEdTWF9jd09fd0UifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNVlJYTVZOdGFHUk5SM2hKVDIxaU4wUXplRlZWWm5OQlFUZ3dRelJUUVZjNVRFWnNZMEU1YW1VMFFTSjlmUS5leUpwWVhRaU9qRTJPREF5TlRrNU1EWXNJbVY0Y0NJNk1UWTRNREkyTXpVd05pd2libUptSWpveE5qZ3dNalU1T1RBMkxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWcEVhek5QVkZsM1dWUnNiRTlYVW14T1IxbDVUWHBvYlU5RWJHeE9NbEY2V1ZSa2FFNUVaR3hPUkdjdlkyVTJZV1l6Wm1GalpqSXlOVEEzTTBCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpjNU9UazJaakUzTFRSbVpqVXROR013WmkwNE1URXdMVGhqWWpjek56ZG1OMk0wTkNJc0ltNXZibU5sSWpvaVUyNWtkVnBFV2taVGEzQlhZMjVLYWxsV1duaFdTRTVxVG10d1IxSlZlR3BVZWxwWFVqTmtTV0Z0YXlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qTTVOakV2SWl3aVkyaGhiQ0k2SWs1RmFURklZVkpTV1hGTk1GSTVZMGRhWVVoa2RqQmtRbGRKYTFKaWVVTlpJbjAuU3NLNkFJSm1GcThtOENvNzFmZkRVczA4T2lESVJYREphUy1fTWhGYmdLN2RxVUlSSkxNUWk0dkEwYXdmMzktaDhlU013bzNfWDc3Wm9DcHAxZmRUQnciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVpEazNPVFl3WVRsbE9XUmxOR1l5TXpobU9EbGxOMlF6WVRkaE5EZGxORGcvY2U2YWYzZmFjZjIyNTA3M0B3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.bq5zfvEN6wpXGo0Fqz9s4UyrB-qXcKmMTMKP9puDduR2kqZ1U8EWs2m2r3-ornn1Ju0DUmh-zZWEAqfzOFHTAQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IkdVdXlTWVlUZ1laMHdoam5icklsZTd1M3pk
ZE55cWtmOG45bWFfMXpPUVEifX0.eyJpYXQiOjE2ODAyNTk5MDYsImV4cCI6MTY4
ODAzNTkwNiwibmJmIjoxNjgwMjU5OTA2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjM5NjEvIiwic3ViIjoiaW06d2lyZWFwcD1aRGszT1RZd1lUbGxPV1JsTkdZeU16
aG1PRGxsTjJRellUZGhORGRsTkRnL2NlNmFmM2ZhY2YyMjUwNzNAd2lyZS5jb20i
LCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjM5NjEvIiwianRpIjoiNmMwZTQwZjIt
OTEzZC00ZmYzLWIzYWQtZmU2NWI4NDJhNWUzIiwibm9uY2UiOiJTbmR1WkRaRlNr
cFdjbkpqWVZaeFZITmpOa3BHUlV4alR6WldSM2RJYW1rIiwiY2hhbCI6Ik5FaTFI
YVJSWXFNMFI5Y0daYUhkdjBkQldJa1JieUNZIiwiY25mIjp7ImtpZCI6IlBuWlZm
UG00SEl6SHB0cVdrRXNWdzRHYXJNdGpmTGRGdEdTWF9jd09fd0UifSwicHJvb2Yi
OiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFu
ZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElq
b2lNVlJYTVZOdGFHUk5SM2hKVDIxaU4wUXplRlZWWm5OQlFUZ3dRelJUUVZjNVRF
WnNZMEU1YW1VMFFTSjlmUS5leUpwWVhRaU9qRTJPREF5TlRrNU1EWXNJbVY0Y0NJ
Nk1UWTRNREkyTXpVd05pd2libUptSWpveE5qZ3dNalU1T1RBMkxDSnpkV0lpT2lK
cGJUcDNhWEpsWVhCd1BWcEVhek5QVkZsM1dWUnNiRTlYVW14T1IxbDVUWHBvYlU5
RWJHeE9NbEY2V1ZSa2FFNUVaR3hPUkdjdlkyVTJZV1l6Wm1GalpqSXlOVEEzTTBC
M2FYSmxMbU52YlNJc0ltcDBhU0k2SWpjNU9UazJaakUzTFRSbVpqVXROR013Wmkw
NE1URXdMVGhqWWpjek56ZG1OMk0wTkNJc0ltNXZibU5sSWpvaVUyNWtkVnBFV2ta
VGEzQlhZMjVLYWxsV1duaFdTRTVxVG10d1IxSlZlR3BVZWxwWFVqTmtTV0Z0YXlJ
c0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIw
Nk1qTTVOakV2SWl3aVkyaGhiQ0k2SWs1RmFURklZVkpTV1hGTk1GSTVZMGRhWVVo
a2RqQmtRbGRKYTFKaWVVTlpJbjAuU3NLNkFJSm1GcThtOENvNzFmZkRVczA4T2lE
SVJYREphUy1fTWhGYmdLN2RxVUlSSkxNUWk0dkEwYXdmMzktaDhlU013bzNfWDc3
Wm9DcHAxZmRUQnciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVpEazNPVFl3WVRs
bE9XUmxOR1l5TXpobU9EbGxOMlF6WVRkaE5EZGxORGcvY2U2YWYzZmFjZjIyNTA3
M0B3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50
X2lkIn0.bq5zfvEN6wpXGo0Fqz9s4UyrB-qXcKmMTMKP9puDduR2kqZ1U8EWs2m2
r3-ornn1Ju0DUmh-zZWEAqfzOFHTAQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "GUuySYYTgYZ0whjnbrIle7u3zddNyqkf8n9ma_1zOQQ"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:23961/",
  "chal": "NEi1HaRRYqM0R9cGZaHdv0dBWIkRbyCY",
  "client_id": "im:wireapp=ZDk3OTYwYTllOWRlNGYyMzhmODllN2QzYTdhNDdlNDg/ce6af3facf225073@wire.com",
  "cnf": {
    "kid": "PnZVfPm4HIzHptqWkEsVw4GarMtjfLdFtGSX_cwO_wE"
  },
  "exp": 1688035906,
  "iat": 1680259906,
  "iss": "http://wire.com:23961/",
  "jti": "6c0e40f2-913d-4ff3-b3ad-fe65b842a5e3",
  "nbf": 1680259906,
  "nonce": "SnduZDZFSkpWcnJjYVZxVHNjNkpGRUxjTzZWR3dIamk",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMVRXMVNtaGRNR3hJT21iN0QzeFVVZnNBQTgwQzRTQVc5TEZsY0E5amU0QSJ9fQ.eyJpYXQiOjE2ODAyNTk5MDYsImV4cCI6MTY4MDI2MzUwNiwibmJmIjoxNjgwMjU5OTA2LCJzdWIiOiJpbTp3aXJlYXBwPVpEazNPVFl3WVRsbE9XUmxOR1l5TXpobU9EbGxOMlF6WVRkaE5EZGxORGcvY2U2YWYzZmFjZjIyNTA3M0B3aXJlLmNvbSIsImp0aSI6Ijc5OTk2ZjE3LTRmZjUtNGMwZi04MTEwLThjYjczNzdmN2M0NCIsIm5vbmNlIjoiU25kdVpEWkZTa3BXY25KallWWnhWSE5qTmtwR1JVeGpUelpXUjNkSWFtayIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjM5NjEvIiwiY2hhbCI6Ik5FaTFIYVJSWXFNMFI5Y0daYUhkdjBkQldJa1JieUNZIn0.SsK6AIJmFq8m8Co71ffDUs08OiDIRXDJaS-_MhFbgK7dqUIRJLMQi4vA0awf39-h8eSMwo3_X77ZoCpp1fdTBw",
  "scope": "wire_client_id",
  "sub": "im:wireapp=ZDk3OTYwYTllOWRlNGYyMzhmODllN2QzYTdhNDdlNDg/ce6af3facf225073@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAa7jKlIaVhIRumerrws2sZOzPPEUIVTukt8Lbk15LVI
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAGUuySYYTgYZ0whjnbrIle7u3zddNyqkf8n9ma/1zOQQ=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/1pceubrFUZAvVQI5XgtLDMfLefhOt4YI
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2NDM3L2FjbWUvd2lyZS9hY2NvdW50L1V3U2xEY0diV09Ga0E3ZGltUzR5RVVraTZaRWxsYUs0IiwidHlwIjoiSldUIiwibm9uY2UiOiJSRlJSVVVoV1lVWkNPVzFxYjNkYWJIRk9ZM0pvVUZwV1NtUmxkbVZGYldvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTY0MzcvYWNtZS93aXJlL2NoYWxsZW5nZS9mb1ZNT3ZNY2FwWGxXU3JIcXU0QnJEMVJGT1JaT0dyQy8xcGNldWJyRlVaQXZWUUk1WGd0TERNZkxlZmhPdDRZSSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrZFZkWGxUV1ZsVVoxbGFNSGRvYW01aWNrbHNaVGQxTTNwa1pFNTVjV3RtT0c0NWJXRmZNWHBQVVZFaWZYMC5leUpwWVhRaU9qRTJPREF5TlRrNU1EWXNJbVY0Y0NJNk1UWTRPREF6TlRrd05pd2libUptSWpveE5qZ3dNalU1T1RBMkxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNNU5qRXZJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFhUkdzelQxUlpkMWxVYkd4UFYxSnNUa2RaZVUxNmFHMVBSR3hzVGpKUmVsbFVaR2hPUkdSc1RrUm5MMk5sTm1GbU0yWmhZMll5TWpVd056TkFkMmx5WlM1amIyMGlMQ0poZFdRaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qTTVOakV2SWl3aWFuUnBJam9pTm1Nd1pUUXdaakl0T1RFelpDMDBabVl6TFdJellXUXRabVUyTldJNE5ESmhOV1V6SWl3aWJtOXVZMlVpT2lKVGJtUjFXa1JhUmxOcmNGZGpia3BxV1ZaYWVGWklUbXBPYTNCSFVsVjRhbFI2V2xkU00yUkpZVzFySWl3aVkyaGhiQ0k2SWs1RmFURklZVkpTV1hGTk1GSTVZMGRhWVVoa2RqQmtRbGRKYTFKaWVVTlpJaXdpWTI1bUlqcDdJbXRwWkNJNklsQnVXbFptVUcwMFNFbDZTSEIwY1ZkclJYTldkelJIWVhKTmRHcG1UR1JHZEVkVFdGOWpkMDlmZDBVaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsTlZsSllUVlpPZEdGSFVrNVNNMmhLVkRJeGFVNHdVWHBsUmxaV1dtNU9RbEZVWjNkUmVsSlVVVlpqTlZSRlduTlpNRVUxWVcxVk1GRlRTamxtVVM1bGVVcHdXVmhSYVU5cVJUSlBSRUY1VGxSck5VMUVXWE5KYlZZMFkwTkpOazFVV1RSTlJFa3lUWHBWZDA1cGQybGliVXB0U1dwdmVFNXFaM2ROYWxVMVQxUkJNa3hEU25wa1YwbHBUMmxLY0dKVWNETmhXRXBzV1ZoQ2QxQldjRVZoZWs1UVZrWnNNMWRXVW5OaVJUbFlWVzE0VDFJeGJEVlVXSEJ2WWxVNVJXSkhlRTlOYkVZMlYxWlNhMkZGTlVWYVIzaFBVa2RqZGxreVZUSlpWMWw2V20xR2FscHFTWGxPVkVFelRUQkNNMkZZU214TWJVNTJZbE5KYzBsdGNEQmhVMGsyU1dwak5VOVVhekphYWtVelRGUlNiVnBxVlhST1IwMTNXbWt3TkUxVVJYZE1WR2hxV1dwamVrNTZaRzFPTWswd1RrTkpjMGx0TlhaaWJVNXNTV3B2YVZVeU5XdGtWbkJGVjJ0YVZHRXpRbGhaTWpWTFlXeHNWMWR1YUZkVFJUVnhWRzEwZDFJeFNsWmxSM0JWWld4d1dGVnFUbXRUVjBaMFlYbEpjMGx0YURCaVUwazJTV3hDVUZVeFVXbE1RMHB2WkVoVmFVOXBTbTlrU0ZKM1QyazRkbVF5YkhsYVV6VnFZakl3TmsxcVRUVk9ha1YyU1dsM2FWa3lhR2hpUTBrMlNXczFSbUZVUmtsWlZrcFRWMWhHVGsxR1NUVlpNR1JoV1ZWb2EyUnFRbXRSYkdSS1lURkthV1ZWVGxwSmJqQXVVM05MTmtGSlNtMUdjVGh0T0VOdk56Rm1aa1JWY3pBNFQybEVTVkpZUkVwaFV5MWZUV2hHWW1kTE4yUnhWVWxTU2t4TlVXazBka0V3WVhkbU16a3RhRGhsVTAxM2J6TmZXRGMzV205RGNIQXhabVJVUW5jaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFZwRWF6TlBWRmwzV1ZSc2JFOVhVbXhPUjFsNVRYcG9iVTlFYkd4T01sRjZXVlJrYUU1RVpHeE9SR2N2WTJVMllXWXpabUZqWmpJeU5UQTNNMEIzYVhKbExtTnZiU0lzSW1Gd2FWOTJaWEp6YVc5dUlqb3pMQ0p6WTI5d1pTSTZJbmRwY21WZlkyeHBaVzUwWDJsa0luMC5icTV6ZnZFTjZ3cFhHbzBGcXo5czRVeXJCLXFYY0ttTVRNS1A5cHVEZHVSMmtxWjFVOEVXczJtMnIzLW9ybm4xSnUwRFVtaC16WldFQXFmek9GSFRBUSJ9",
  "signature": "ZB6cT3mXJoJ0h2mc0QRH-kj_eEFsO7D044VMVlbb1jUFYvPsnZrEZuAtliDWmVTUg6M2b06OZnPQEY9E5z0oCg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkdVdXlTWVlUZ1laMHdoam5icklsZTd1M3pkZE55cWtmOG45bWFfMXpPUVEifX0.eyJpYXQiOjE2ODAyNTk5MDYsImV4cCI6MTY4ODAzNTkwNiwibmJmIjoxNjgwMjU5OTA2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM5NjEvIiwic3ViIjoiaW06d2lyZWFwcD1aRGszT1RZd1lUbGxPV1JsTkdZeU16aG1PRGxsTjJRellUZGhORGRsTkRnL2NlNmFmM2ZhY2YyMjUwNzNAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjM5NjEvIiwianRpIjoiNmMwZTQwZjItOTEzZC00ZmYzLWIzYWQtZmU2NWI4NDJhNWUzIiwibm9uY2UiOiJTbmR1WkRaRlNrcFdjbkpqWVZaeFZITmpOa3BHUlV4alR6WldSM2RJYW1rIiwiY2hhbCI6Ik5FaTFIYVJSWXFNMFI5Y0daYUhkdjBkQldJa1JieUNZIiwiY25mIjp7ImtpZCI6IlBuWlZmUG00SEl6SHB0cVdrRXNWdzRHYXJNdGpmTGRGdEdTWF9jd09fd0UifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNVlJYTVZOdGFHUk5SM2hKVDIxaU4wUXplRlZWWm5OQlFUZ3dRelJUUVZjNVRFWnNZMEU1YW1VMFFTSjlmUS5leUpwWVhRaU9qRTJPREF5TlRrNU1EWXNJbVY0Y0NJNk1UWTRNREkyTXpVd05pd2libUptSWpveE5qZ3dNalU1T1RBMkxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWcEVhek5QVkZsM1dWUnNiRTlYVW14T1IxbDVUWHBvYlU5RWJHeE9NbEY2V1ZSa2FFNUVaR3hPUkdjdlkyVTJZV1l6Wm1GalpqSXlOVEEzTTBCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpjNU9UazJaakUzTFRSbVpqVXROR013WmkwNE1URXdMVGhqWWpjek56ZG1OMk0wTkNJc0ltNXZibU5sSWpvaVUyNWtkVnBFV2taVGEzQlhZMjVLYWxsV1duaFdTRTVxVG10d1IxSlZlR3BVZWxwWFVqTmtTV0Z0YXlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qTTVOakV2SWl3aVkyaGhiQ0k2SWs1RmFURklZVkpTV1hGTk1GSTVZMGRhWVVoa2RqQmtRbGRKYTFKaWVVTlpJbjAuU3NLNkFJSm1GcThtOENvNzFmZkRVczA4T2lESVJYREphUy1fTWhGYmdLN2RxVUlSSkxNUWk0dkEwYXdmMzktaDhlU013bzNfWDc3Wm9DcHAxZmRUQnciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVpEazNPVFl3WVRsbE9XUmxOR1l5TXpobU9EbGxOMlF6WVRkaE5EZGxORGcvY2U2YWYzZmFjZjIyNTA3M0B3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.bq5zfvEN6wpXGo0Fqz9s4UyrB-qXcKmMTMKP9puDduR2kqZ1U8EWs2m2r3-ornn1Ju0DUmh-zZWEAqfzOFHTAQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56437/acme/wire/account/UwSlDcGbWOFkA7dimS4yEUki6ZEllaK4",
    "nonce": "RFRRUUhWYUZCOW1qb3dabHFOY3JoUFpWSmRldmVFbWo",
    "typ": "JWT",
    "url": "https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/1pceubrFUZAvVQI5XgtLDMfLefhOt4YI"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56437/acme/wire/directory>;rel="index"
link: <https://stepca:56437/acme/wire/authz/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC>;rel="up"
location: https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/1pceubrFUZAvVQI5XgtLDMfLefhOt4YI
replay-nonce: bXB4WHdOakpjN1JrSWlqR3dIVGdtaWhaQ0RXb2lhYmQ
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/1pceubrFUZAvVQI5XgtLDMfLefhOt4YI",
  "status": "valid",
  "token": "NEi1HaRRYqM0R9cGZaHdv0dBWIkRbyCY"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. Client clicks login button
```http request
GET http://wire.com:23961/login
```
#### 19. Resource server generates Verifier & Challenge Codes

```text
code_verifier=LovDgcmdRzC_FrUNoVlSv3AsRy5XO08AYjoWSHY0pFU&code_challenge=d0waU0Xqx96kFD3D7lsk883wZ4FzuZfgzE-wPWiU8LU
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
  <form method="post" action="/dex/auth/ldap/login?back=&amp;state=dyzcpwpksfuphhjwrbv4fcydd">
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
POST http://dex:17203/dex/auth/ldap/login?back=&state=dyzcpwpksfuphhjwrbv4fcydd
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
        <input type="hidden" name="req" value="dyzcpwpksfuphhjwrbv4fcydd"/>
        <input type="hidden" name="approval" value="approve">
        <button type="submit" class="dex-btn theme-btn--success">
            <span class="dex-btn-text">Grant Access</span>
        </button>
      </form>
    </div>
    <div class="theme-form-row">
      <form method="post">
        <input type="hidden" name="req" value="dyzcpwpksfuphhjwrbv4fcydd"/>
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
POST http://dex:17203/dex/approval?req=dyzcpwpksfuphhjwrbv4fcydd&hmac=UAkydoO_ILIeO6c3i4Glj5dtHrDRUjtjrlJ2XeFHGcU
content-type: application/x-www-form-urlencoded
```
```text
req=dyzcpwpksfuphhjwrbv4fcydd&approval=approve
```
#### 25. Authorization server calls callback url with authorization code
```http request
GET http://wire.com/callback
accept: */*
referer: http://dex:17203/dex/approval?req=dyzcpwpksfuphhjwrbv4fcydd&hmac=UAkydoO_ILIeO6c3i4Glj5dtHrDRUjtjrlJ2XeFHGcU
host: wire.com:23961
```
#### 26. Resource server call /oauth/token to get Id token
```http request
POST http://dex:17203/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpaMmRHTUUxR1QxRlpWakk0UnpVNVVHVnBlRWMwVlVSTQ==
```
```text
grant_type=authorization_code&code=kaz6pizwh4b5iob7gdcy4cbi3&code_verifier=LovDgcmdRzC_FrUNoVlSv3AsRy5XO08AYjoWSHY0pFU&redirect_uri=http%3A%2F%2Fwire.com%3A23961%2Fcallback
```
#### 27. Authorization server validates Verifier & Challenge Codes

```text
code_verifier=LovDgcmdRzC_FrUNoVlSv3AsRy5XO08AYjoWSHY0pFU&code_challenge=d0waU0Xqx96kFD3D7lsk883wZ4FzuZfgzE-wPWiU8LU
```
#### 28. Authorization server returns Access & Id token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg0OTMxYWUzYzIyMjRjZjRkYjNhMGU3NzcyZTgzMWIzYzYwNWEzMTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MjAzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFYXpOUFZGbDNXVlJzYkU5WFVteE9SMWw1VFhwb2JVOUViR3hPTWxGNldWUmthRTVFWkd4T1JHY3ZZMlUyWVdZelptRmpaakl5TlRBM00wQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMzQ2MzA2LCJpYXQiOjE2ODAyNTk5MDYsIm5vbmNlIjoiYzJYQmZRMm45Y001NzVzMWdVZV92QSIsImF0X2hhc2giOiJueWQ5NmdQalJfYjB1Mkk5d2x5NnJ3IiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Uuc21pdGgiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIn0.ZShpFpWnyVCwEMQ6zOpYeoG4K2N1K9B47jLUkAjufAG8QfGl305z3o37KOhD6woZ6NUumwhCOev21Piu0sLePMlPn_YJwhNkYy7uogL0LhcvQ9gdkEuvEMKYkcXmNPdIGJfd6hrNAbvmJFyhmw0K_f5cX6LKqKDG20qn7HJ1vhiDLR4cNrisRMw98Dmwbz4qxMLR60MPC_uLQYHTX7z_0jcEqwF2fXcD_cU-NrMOH8zStzQP8ZW3EtsGexZrMJ5WAWv_HSxt0ujFyj7DH1Pp6cHJ3QEzFxRx1v9xfEepXaV46wl9UGGAf201Qc9qY4N3NKN4391GJ2xjd93GTXRMjg",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg0OTMxYWUzYzIyMjRjZjRkYjNhMGU3NzcyZTgzMWIzYzYwNWEzMTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MjAzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFYXpOUFZGbDNXVlJzYkU5WFVteE9SMWw1VFhwb2JVOUViR3hPTWxGNldWUmthRTVFWkd4T1JHY3ZZMlUyWVdZelptRmpaakl5TlRBM00wQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMzQ2MzA2LCJpYXQiOjE2ODAyNTk5MDYsIm5vbmNlIjoiYzJYQmZRMm45Y001NzVzMWdVZV92QSIsImF0X2hhc2giOiJ2cm8xVE8tT212VHp5aDlvQUtRdU93IiwiY19oYXNoIjoiT3Vsc2I3ZDh0Mk1UZUJNNFhaN080dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.oUtpwUXeyx9wEOv0WwoQsWDhgmVD_g5hIdQYN8m6FLwI7qlaidVltqhxHDSM8ekiVgr6Ow_DLEqnqaTjUFqcQkeoVD4dPdY36iLpukvWKQfsyT7a_5qU6gokOMYmkvNUJk8YV35wW8B2ONtTboQeMeIXvJydPBo_BlcimR1LS0c59CSTrUGOUpL3j2RnbW8gMtgerVIJ75drh4CUH6-OHYjCof7aD7-3TqNNRYuIRDlwaGY8t3DNBUZv_mBIBS0Tx71EvUL1aGFFCJ48JBNVSZVHgI1DEXRjie66vKtsyS5QLjNd3AAQMrmzuxuks4EFC5b6Y8gvGTA4e77uHDE_Sg",
  "token_type": "bearer"
}
```
#### 29. Resource server returns Id token to client

```text
eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg0OTMxYWUzYzIyMjRjZjRkYjNhMGU3NzcyZTgzMWIzYzYwNWEzMTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MjAzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFYXpOUFZGbDNXVlJzYkU5WFVteE9SMWw1VFhwb2JVOUViR3hPTWxGNldWUmthRTVFWkd4T1JHY3ZZMlUyWVdZelptRmpaakl5TlRBM00wQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMzQ2MzA2LCJpYXQiOjE2ODAyNTk5MDYsIm5vbmNlIjoiYzJYQmZRMm45Y001NzVzMWdVZV92QSIsImF0X2hhc2giOiJ2cm8xVE8tT212VHp5aDlvQUtRdU93IiwiY19oYXNoIjoiT3Vsc2I3ZDh0Mk1UZUJNNFhaN080dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.oUtpwUXeyx9wEOv0WwoQsWDhgmVD_g5hIdQYN8m6FLwI7qlaidVltqhxHDSM8ekiVgr6Ow_DLEqnqaTjUFqcQkeoVD4dPdY36iLpukvWKQfsyT7a_5qU6gokOMYmkvNUJk8YV35wW8B2ONtTboQeMeIXvJydPBo_BlcimR1LS0c59CSTrUGOUpL3j2RnbW8gMtgerVIJ75drh4CUH6-OHYjCof7aD7-3TqNNRYuIRDlwaGY8t3DNBUZv_mBIBS0Tx71EvUL1aGFFCJ48JBNVSZVHgI1DEXRjie66vKtsyS5QLjNd3AAQMrmzuxuks4EFC5b6Y8gvGTA4e77uHDE_Sg
```
#### 30. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg0OTMxYWUzYzIyMjRjZjRkYjNhMGU3NzcyZTgzMWIzYzYwNWEzMTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MjAzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFYXpOUFZGbDNXVlJzYkU5WFVteE9SMWw1VFhwb2JVOUViR3hPTWxGNldWUmthRTVFWkd4T1JHY3ZZMlUyWVdZelptRmpaakl5TlRBM00wQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMzQ2MzA2LCJpYXQiOjE2ODAyNTk5MDYsIm5vbmNlIjoiYzJYQmZRMm45Y001NzVzMWdVZV92QSIsImF0X2hhc2giOiJ2cm8xVE8tT212VHp5aDlvQUtRdU93IiwiY19oYXNoIjoiT3Vsc2I3ZDh0Mk1UZUJNNFhaN080dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.oUtpwUXeyx9wEOv0WwoQsWDhgmVD_g5hIdQYN8m6FLwI7qlaidVltqhxHDSM8ekiVgr6Ow_DLEqnqaTjUFqcQkeoVD4dPdY36iLpukvWKQfsyT7a_5qU6gokOMYmkvNUJk8YV35wW8B2ONtTboQeMeIXvJydPBo_BlcimR1LS0c59CSTrUGOUpL3j2RnbW8gMtgerVIJ75drh4CUH6-OHYjCof7aD7-3TqNNRYuIRDlwaGY8t3DNBUZv_mBIBS0Tx71EvUL1aGFFCJ48JBNVSZVHgI1DEXRjie66vKtsyS5QLjNd3AAQMrmzuxuks4EFC5b6Y8gvGTA4e77uHDE_Sg)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg0OTMxYWUzYzIyMjRjZjRkYjNhMGU3Nzcy
ZTgzMWIzYzYwNWEzMTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MjAzL2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFYXpOUFZGbDNXVlJzYkU5WFVteE9SM
Ww1VFhwb2JVOUViR3hPTWxGNldWUmthRTVFWkd4T1JHY3ZZMlUyWVdZelptRmpaa
kl5TlRBM00wQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjgwMzQ2MzA2LCJpYXQiOjE2ODAyNTk5MDYsIm5vbmNlIjoiYzJYQmZRM
m45Y001NzVzMWdVZV92QSIsImF0X2hhc2giOiJ2cm8xVE8tT212VHp5aDlvQUtRd
U93IiwiY19oYXNoIjoiT3Vsc2I3ZDh0Mk1UZUJNNFhaN080dyIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlLnNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pd
GgsIEFsaWNlIE0gKFFBKSJ9.oUtpwUXeyx9wEOv0WwoQsWDhgmVD_g5hIdQYN8m6
FLwI7qlaidVltqhxHDSM8ekiVgr6Ow_DLEqnqaTjUFqcQkeoVD4dPdY36iLpukvW
KQfsyT7a_5qU6gokOMYmkvNUJk8YV35wW8B2ONtTboQeMeIXvJydPBo_BlcimR1L
S0c59CSTrUGOUpL3j2RnbW8gMtgerVIJ75drh4CUH6-OHYjCof7aD7-3TqNNRYuI
RDlwaGY8t3DNBUZv_mBIBS0Tx71EvUL1aGFFCJ48JBNVSZVHgI1DEXRjie66vKts
yS5QLjNd3AAQMrmzuxuks4EFC5b6Y8gvGTA4e77uHDE_Sg
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "84931ae3c2224cf4db3a0e7772e831b3c605a312"
}
```

```json
{
  "at_hash": "vro1TO-OmvTzyh9oAKQuOw",
  "aud": "wireapp",
  "c_hash": "Oulsb7d8t2MTeBM4XZ7O4w",
  "exp": 1680346306,
  "iat": 1680259906,
  "iss": "http://dex:17203/dex",
  "name": "im:wireapp=alice.smith",
  "nonce": "c2XBfQ2n9cM575s1gUe_vA",
  "preferred_username": "Smith, Alice M (QA)",
  "sub": "ClBpbTp3aXJlYXBwPVpEazNPVFl3WVRsbE9XUmxOR1l5TXpobU9EbGxOMlF6WVRkaE5EZGxORGcvY2U2YWYzZmFjZjIyNTA3M0B3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvdP0L0HjcQMYCNAq4cNw
iBJ88fAAoRX57G/tdEPUxE1V9XcXbsPZPnuj5402XKothjO5PY0sIOeJvg/VXk4x
Yxyh+X31LMCqCDe0zCIzuqKGh87FnCzm4GaZyzbvc7S/7wpRBO/ftcEuhu6ciQNJ
Ch2gvysPRZfA4NdUYw41VYk6zEP5uSZbYrrLlQcOv6o/Vxkiqip8dy/6vbg9jCnD
wj+f+hxwhW4kFFv6sGYLyZp9c6yWzdJ2QwPtswSdGz++R5VtxiU1nO5Hodym3exO
w3Ma3ao/drZBCnbbElxJjsljKM0XqjWwuTFOxIXv4bARxLQBHaduL8M2LwqrUcSw
VQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/k6kgSdPou50Dg67NAxYiycqIFfuoDyHo
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2NDM3L2FjbWUvd2lyZS9hY2NvdW50L1V3U2xEY0diV09Ga0E3ZGltUzR5RVVraTZaRWxsYUs0IiwidHlwIjoiSldUIiwibm9uY2UiOiJiWEI0V0hkT2FrcGpOMUpyU1dscVIzZElWR2R0YVdoYVEwUlhiMmxoWW1RIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTY0MzcvYWNtZS93aXJlL2NoYWxsZW5nZS9mb1ZNT3ZNY2FwWGxXU3JIcXU0QnJEMVJGT1JaT0dyQy9rNmtnU2RQb3U1MERnNjdOQXhZaXljcUlGZnVvRHlIbyJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJamcwT1RNeFlXVXpZekl5TWpSalpqUmtZak5oTUdVM056Y3laVGd6TVdJell6WXdOV0V6TVRJaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTNNakF6TDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZuQkZZWHBPVUZaR2JETlhWbEp6WWtVNVdGVnRlRTlTTVd3MVZGaHdiMkpWT1VWaVIzaFBUV3hHTmxkV1VtdGhSVFZGV2tkNFQxSkhZM1paTWxVeVdWZFplbHB0Um1wYWFrbDVUbFJCTTAwd1FqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qZ3dNelEyTXpBMkxDSnBZWFFpT2pFMk9EQXlOVGs1TURZc0ltNXZibU5sSWpvaVl6SllRbVpSTW00NVkwMDFOelZ6TVdkVlpWOTJRU0lzSW1GMFgyaGhjMmdpT2lKMmNtOHhWRTh0VDIxMlZIcDVhRGx2UVV0UmRVOTNJaXdpWTE5b1lYTm9Jam9pVDNWc2MySTNaRGgwTWsxVVpVSk5ORmhhTjA4MGR5SXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObExuTnRhWFJvSWl3aWNISmxabVZ5Y21Wa1gzVnpaWEp1WVcxbElqb2lVMjFwZEdnc0lFRnNhV05sSUUwZ0tGRkJLU0o5Lm9VdHB3VVhleXg5d0VPdjBXd29Rc1dEaGdtVkRfZzVoSWRRWU44bTZGTHdJN3FsYWlkVmx0cWh4SERTTThla2lWZ3I2T3dfRExFcW5xYVRqVUZxY1FrZW9WRDRkUGRZMzZpTHB1a3ZXS1Fmc3lUN2FfNXFVNmdva09NWW1rdk5VSms4WVYzNXdXOEIyT050VGJvUWVNZUlYdkp5ZFBCb19CbGNpbVIxTFMwYzU5Q1NUclVHT1VwTDNqMlJuYlc4Z010Z2VyVklKNzVkcmg0Q1VINi1PSFlqQ29mN2FENy0zVHFOTlJZdUlSRGx3YUdZOHQzRE5CVVp2X21CSUJTMFR4NzFFdlVMMWFHRkZDSjQ4SkJOVlNaVkhnSTFERVhSamllNjZ2S3RzeVM1UUxqTmQzQUFRTXJtenV4dWtzNEVGQzViNlk4Z3ZHVEE0ZTc3dUhERV9TZyIsImtleWF1dGgiOiJORWkxSGFSUllxTTBSOWNHWmFIZHYwZEJXSWtSYnlDWS5OMW5xTk5RZ0hTcU9KQk9WeFlIeVhPWVBtcTZwTWR2N1V4ZWxmaDlLY19rIn0",
  "signature": "iQaoFbhZK5OLZIDCYjO3-dFYVxi_8BWJMsxv_EThgx-mDCfLCRdQKCuzss3rdfx9TsBRTqZZEQUGcvdKJvPrAA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijg0OTMxYWUzYzIyMjRjZjRkYjNhMGU3NzcyZTgzMWIzYzYwNWEzMTIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MjAzL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFYXpOUFZGbDNXVlJzYkU5WFVteE9SMWw1VFhwb2JVOUViR3hPTWxGNldWUmthRTVFWkd4T1JHY3ZZMlUyWVdZelptRmpaakl5TlRBM00wQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMzQ2MzA2LCJpYXQiOjE2ODAyNTk5MDYsIm5vbmNlIjoiYzJYQmZRMm45Y001NzVzMWdVZV92QSIsImF0X2hhc2giOiJ2cm8xVE8tT212VHp5aDlvQUtRdU93IiwiY19oYXNoIjoiT3Vsc2I3ZDh0Mk1UZUJNNFhaN080dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.oUtpwUXeyx9wEOv0WwoQsWDhgmVD_g5hIdQYN8m6FLwI7qlaidVltqhxHDSM8ekiVgr6Ow_DLEqnqaTjUFqcQkeoVD4dPdY36iLpukvWKQfsyT7a_5qU6gokOMYmkvNUJk8YV35wW8B2ONtTboQeMeIXvJydPBo_BlcimR1LS0c59CSTrUGOUpL3j2RnbW8gMtgerVIJ75drh4CUH6-OHYjCof7aD7-3TqNNRYuIRDlwaGY8t3DNBUZv_mBIBS0Tx71EvUL1aGFFCJ48JBNVSZVHgI1DEXRjie66vKtsyS5QLjNd3AAQMrmzuxuks4EFC5b6Y8gvGTA4e77uHDE_Sg",
    "keyauth": "NEi1HaRRYqM0R9cGZaHdv0dBWIkRbyCY.N1nqNNQgHSqOJBOVxYHyXOYPmq6pMdv7Uxelfh9Kc_k"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56437/acme/wire/account/UwSlDcGbWOFkA7dimS4yEUki6ZEllaK4",
    "nonce": "bXB4WHdOakpjN1JrSWlqR3dIVGdtaWhaQ0RXb2lhYmQ",
    "typ": "JWT",
    "url": "https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/k6kgSdPou50Dg67NAxYiycqIFfuoDyHo"
  }
}
```
#### 31. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56437/acme/wire/directory>;rel="index"
link: <https://stepca:56437/acme/wire/authz/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC>;rel="up"
location: https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/k6kgSdPou50Dg67NAxYiycqIFfuoDyHo
replay-nonce: c2hURjFoUlNtcXRoTDdWZVk1cUFJcnh6ZnY1UEE3TXA
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:56437/acme/wire/challenge/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC/k6kgSdPou50Dg67NAxYiycqIFfuoDyHo",
  "status": "valid",
  "token": "NEi1HaRRYqM0R9cGZaHdv0dBWIkRbyCY"
}
```
### Client presents a CSR and gets its certificate
#### 32. verify the status of the order
```http request
POST https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2NDM3L2FjbWUvd2lyZS9hY2NvdW50L1V3U2xEY0diV09Ga0E3ZGltUzR5RVVraTZaRWxsYUs0IiwidHlwIjoiSldUIiwibm9uY2UiOiJjMmhVUmpGb1VsTnRjWFJvVERkV1pWazFjVUZKY25oNlpuWTFVRUUzVFhBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTY0MzcvYWNtZS93aXJlL29yZGVyL2lUUWlVUWdyT3h3cVVEdUhJR0VUZzUyejNjSkxHNElhIn0",
  "payload": "",
  "signature": "WkFslxEISzg1wF39_zC5Cc9-Utp4DheBWIBQFAXFgrtYg3dqr3FWzKYlPLfxMK-18niHdAcNpK-sFzCAGrNFAg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56437/acme/wire/account/UwSlDcGbWOFkA7dimS4yEUki6ZEllaK4",
    "nonce": "c2hURjFoUlNtcXRoTDdWZVk1cUFJcnh6ZnY1UEE3TXA",
    "typ": "JWT",
    "url": "https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia"
  }
}
```
#### 33. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56437/acme/wire/directory>;rel="index"
location: https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia
replay-nonce: N1FWTm9kUGVDM3ppd0VVVHo4Rm1TMWVDTTRIYTN1dmI
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDk3OTYwYTllOWRlNGYyMzhmODllN2QzYTdhNDdlNDg/ce6af3facf225073@wire.com\",\"handle\":\"im:wireapp=alice.smith\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56437/acme/wire/authz/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC"
  ],
  "expires": "2023-04-01T10:51:46Z",
  "notBefore": "2023-03-31T10:51:46.61714Z",
  "notAfter": "2023-03-31T11:51:46.61714Z"
}
```
#### 34. create a CSR and call finalize url
```http request
POST https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2NDM3L2FjbWUvd2lyZS9hY2NvdW50L1V3U2xEY0diV09Ga0E3ZGltUzR5RVVraTZaRWxsYUs0IiwidHlwIjoiSldUIiwibm9uY2UiOiJOMUZXVG05a1VHVkRNM3BwZDBWVlZIbzRSbTFUTVdWRFRUUklZVE4xZG1JIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTY0MzcvYWNtZS93aXJlL29yZGVyL2lUUWlVUWdyT3h3cVVEdUhJR0VUZzUyejNjSkxHNElhL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCUVRDQjlBSUJBREE1TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFa01DSUdDMkNHU0FHRy1FSURBWUZ4REJOVGJXbDBhQ3dnUVd4cFkyVWdUU0FvVVVFcE1Db3dCUVlESzJWd0F5RUExVFcxU21oZE1HeElPbWI3RDN4VVVmc0FBODBDNFNBVzlMRmxjQTlqZTRDZ2dZY3dnWVFHQ1NxR1NJYjNEUUVKRGpGM01IVXdjd1lEVlIwUkJHd3dhb1pRYVcwNmQybHlaV0Z3Y0QxNlpHc3piM1I1ZDNsMGJHeHZkM0pzYm1kNWVXMTZhRzF2Wkd4c2JqSnhlbmwwWkdodVpHUnNibVJuTDJObE5tRm1NMlpoWTJZeU1qVXdOek5BZDJseVpTNWpiMjJHRm1sdE9uZHBjbVZoY0hBOVlXeHBZMlV1YzIxcGRHZ3dCUVlESzJWd0EwRUFLYXgtV1NDdm5uN1BLdjBuelVMZFdiWWRjQlVZRDE0QXhLUDQwM1JaYkZwU2U5UjY5a3VsNU9ObG5qTUlwRDhMT1hLZXAxSC1SRDd6RTVRYTdndUNEUSJ9",
  "signature": "Dw1NNDZ51zQ9HWh1e7YpFBMqO6p_sDmxuCjCnJD0wj8i_q0BfQXKHAxa8FjHBxJqJtbaEg8O8BojZy6QCgyfAg"
}
```
```json
{
  "payload": {
    "csr": "MIIBQTCB9AIBADA5MREwDwYDVQQKDAh3aXJlLmNvbTEkMCIGC2CGSAGG-EIDAYFxDBNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEA1TW1SmhdMGxIOmb7D3xUUfsAA80C4SAW9LFlcA9je4CggYcwgYQGCSqGSIb3DQEJDjF3MHUwcwYDVR0RBGwwaoZQaW06d2lyZWFwcD16ZGszb3R5d3l0bGxvd3Jsbmd5eW16aG1vZGxsbjJxenl0ZGhuZGRsbmRnL2NlNmFmM2ZhY2YyMjUwNzNAd2lyZS5jb22GFmltOndpcmVhcHA9YWxpY2Uuc21pdGgwBQYDK2VwA0EAKax-WSCvnn7PKv0nzULdWbYdcBUYD14AxKP403RZbFpSe9R69kul5ONlnjMIpD8LOXKep1H-RD7zE5Qa7guCDQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56437/acme/wire/account/UwSlDcGbWOFkA7dimS4yEUki6ZEllaK4",
    "nonce": "N1FWTm9kUGVDM3ppd0VVVHo4Rm1TMWVDTTRIYTN1dmI",
    "typ": "JWT",
    "url": "https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBQTCB9AIBADA5MREwDwYDVQQKDAh3aXJlLmNvbTEkMCIGC2CGSAGG+EIDAYFx
DBNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEA1TW1SmhdMGxIOmb7D3xU
UfsAA80C4SAW9LFlcA9je4CggYcwgYQGCSqGSIb3DQEJDjF3MHUwcwYDVR0RBGww
aoZQaW06d2lyZWFwcD16ZGszb3R5d3l0bGxvd3Jsbmd5eW16aG1vZGxsbjJxenl0
ZGhuZGRsbmRnL2NlNmFmM2ZhY2YyMjUwNzNAd2lyZS5jb22GFmltOndpcmVhcHA9
YWxpY2Uuc21pdGgwBQYDK2VwA0EAKax+WSCvnn7PKv0nzULdWbYdcBUYD14AxKP4
03RZbFpSe9R69kul5ONlnjMIpD8LOXKep1H+RD7zE5Qa7guCDQ==
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
                    d5:35:b5:4a:68:5d:30:6c:48:3a:66:fb:0f:7c:54:
                    51:fb:00:03:cd:02:e1:20:16:f4:b1:65:70:0f:63:
                    7b:80
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=zdk3otywytllowrlngyymzhmodlln2qzytdhnddlndg/ce6af3facf225073@wire.com, URI:im:wireapp=alice.smith
    Signature Algorithm: ED25519
    Signature Value:
        29:ac:7e:59:20:af:9e:7e:cf:2a:fd:27:cd:42:dd:59:b6:1d:
        70:15:18:0f:5e:00:c4:a3:f8:d3:74:59:6c:5a:52:7b:d4:7a:
        f6:4b:a5:e4:e3:65:9e:33:08:a4:3f:0b:39:72:9e:a7:51:fe:
        44:3e:f3:13:94:1a:ee:0b:82:0d

```

#### 35. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56437/acme/wire/directory>;rel="index"
location: https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia
replay-nonce: alBNc1NtbEQ5cmxucVBtTk5NaUdKQVp6eVU4RkNqTEI
```
```json
{
  "certificate": "https://stepca:56437/acme/wire/certificate/tn6EGsb1UcZrhBej6dswoH1Z8GdzKdjs",
  "status": "valid",
  "finalize": "https://stepca:56437/acme/wire/order/iTQiUQgrOxwqUDuHIGETg52z3cJLG4Ia/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDk3OTYwYTllOWRlNGYyMzhmODllN2QzYTdhNDdlNDg/ce6af3facf225073@wire.com\",\"handle\":\"im:wireapp=alice.smith\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56437/acme/wire/authz/foVMOvMcapXlWSrHqu4BrD1RFORZOGrC"
  ],
  "expires": "2023-04-01T10:51:46Z",
  "notBefore": "2023-03-31T10:51:46.61714Z",
  "notAfter": "2023-03-31T11:51:46.61714Z"
}
```
#### 36. fetch the certificate
```http request
POST https://stepca:56437/acme/wire/certificate/tn6EGsb1UcZrhBej6dswoH1Z8GdzKdjs
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2NDM3L2FjbWUvd2lyZS9hY2NvdW50L1V3U2xEY0diV09Ga0E3ZGltUzR5RVVraTZaRWxsYUs0IiwidHlwIjoiSldUIiwibm9uY2UiOiJhbEJOYzFOdGJFUTVjbXh1Y1ZCdFRrNU5hVWRLUVZwNmVWVTRSa05xVEVJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTY0MzcvYWNtZS93aXJlL2NlcnRpZmljYXRlL3RuNkVHc2IxVWNacmhCZWo2ZHN3b0gxWjhHZHpLZGpzIn0",
  "payload": "",
  "signature": "8C-m4ycwQogvWRmgwVC_3Yg2ves7GhPtNBRiy46ZGK5lGVGVORnwEcAmW4rlf4ZEitfYCGiXAChfqejGPfAECQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56437/acme/wire/account/UwSlDcGbWOFkA7dimS4yEUki6ZEllaK4",
    "nonce": "alBNc1NtbEQ5cmxucVBtTk5NaUdKQVp6eVU4RkNqTEI",
    "typ": "JWT",
    "url": "https://stepca:56437/acme/wire/certificate/tn6EGsb1UcZrhBej6dswoH1Z8GdzKdjs"
  }
}
```
#### 37. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:56437/acme/wire/directory>;rel="index"
replay-nonce: RHBiNVdETHJ5WmdnUjlydWtQY3pZUm0xak1POUNKbWM
```
```json
"-----BEGIN CERTIFICATE-----\nMIICODCCAd6gAwIBAgIRAOXV5nV+BIYHFDyg7ZqN5P0wCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwMzMxMTA1MTQ2WhcNMjMwMzMxMTE1MTQ2WjAxMREwDwYDVQQKEwh3aXJlLmNv\nbTEcMBoGA1UEAxMTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhANU1tUpo\nXTBsSDpm+w98VFH7AAPNAuEgFvSxZXAPY3uAo4IBBzCCAQMwDgYDVR0PAQH/BAQD\nAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUiLra\nkprF78Tt/sNU6lrpF/uBczkwHwYDVR0jBBgwFoAUBgK2DW8p8JclscBJ8vhaBmEW\n7GcwcwYDVR0RBGwwaoYWaW06d2lyZWFwcD1hbGljZS5zbWl0aIZQaW06d2lyZWFw\ncD16ZGszb3R5d3l0bGxvd3Jsbmd5eW16aG1vZGxsbjJxenl0ZGhuZGRsbmRnL2Nl\nNmFmM2ZhY2YyMjUwNzNAd2lyZS5jb20wHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQE\nd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIH+z7VqLycri9xaLTJmdE4ib0QQ/7nml\nn8yUU9RP5UR3AiEAgEWDSr3PbP70ojXWzLAENVcJNYoTHBpAyYzRiY8qXps=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAK3R3fn75TztsBDUx3MobF8wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMzMTEw\nNTE0MVoXDTMzMDMyODEwNTE0MVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASh\nnwXNXwVXLL7kaL3s/0TwEvkIhHxhnAFTCG4mTtLjcYNoUGdEAD570z3xjjV9WdEf\nD8iPXtP5CJghCAgSUSdIo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUBgK2DW8p8JclscBJ8vhaBmEW7GcwHwYDVR0jBBgw\nFoAUZ2Ly9s0z5I7JCzwlAk3LJ6KGz/UwCgYIKoZIzj0EAwIDSAAwRQIgXXoTnCjR\n3X2hDw8uZa6Efv6bXzhVuFgnjNwygynftGYCIQDSi0NxDrd4ql6aXx+J2Fp/72yu\npPXKguccqxu0/r2kbQ==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICODCCAd6gAwIBAgIRAOXV5nV+BIYHFDyg7ZqN5P0wCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwMzMxMTA1MTQ2WhcNMjMwMzMxMTE1MTQ2WjAxMREwDwYDVQQKEwh3aXJlLmNv
bTEcMBoGA1UEAxMTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhANU1tUpo
XTBsSDpm+w98VFH7AAPNAuEgFvSxZXAPY3uAo4IBBzCCAQMwDgYDVR0PAQH/BAQD
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUiLra
kprF78Tt/sNU6lrpF/uBczkwHwYDVR0jBBgwFoAUBgK2DW8p8JclscBJ8vhaBmEW
7GcwcwYDVR0RBGwwaoYWaW06d2lyZWFwcD1hbGljZS5zbWl0aIZQaW06d2lyZWFw
cD16ZGszb3R5d3l0bGxvd3Jsbmd5eW16aG1vZGxsbjJxenl0ZGhuZGRsbmRnL2Nl
NmFmM2ZhY2YyMjUwNzNAd2lyZS5jb20wHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQE
d2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIH+z7VqLycri9xaLTJmdE4ib0QQ/7nml
n8yUU9RP5UR3AiEAgEWDSr3PbP70ojXWzLAENVcJNYoTHBpAyYzRiY8qXps=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            e5:d5:e6:75:7e:04:86:07:14:3c:a0:ed:9a:8d:e4:fd
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Mar 31 10:51:46 2023 GMT
            Not After : Mar 31 11:51:46 2023 GMT
        Subject: O = wire.com, CN = "Smith, Alice M (QA)"
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    d5:35:b5:4a:68:5d:30:6c:48:3a:66:fb:0f:7c:54:
                    51:fb:00:03:cd:02:e1:20:16:f4:b1:65:70:0f:63:
                    7b:80
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                88:BA:DA:92:9A:C5:EF:C4:ED:FE:C3:54:EA:5A:E9:17:FB:81:73:39
            X509v3 Authority Key Identifier: 
                06:02:B6:0D:6F:29:F0:97:25:B1:C0:49:F2:F8:5A:06:61:16:EC:67
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice.smith, URI:im:wireapp=zdk3otywytllowrlngyymzhmodlln2qzytdhnddlndg/ce6af3facf225073@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:7f:b3:ed:5a:8b:c9:ca:e2:f7:16:8b:4c:99:9d:
        13:88:9b:d1:04:3f:ee:79:a5:9f:cc:94:53:d4:4f:e5:44:77:
        02:21:00:80:45:83:4a:bd:cf:6c:fe:f4:a2:35:d6:cc:b0:04:
        35:57:09:35:8a:13:1c:1a:40:c9:8c:d1:89:8f:2a:5e:9b

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAK3R3fn75TztsBDUx3MobF8wCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMzMTEw
NTE0MVoXDTMzMDMyODEwNTE0MVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASh
nwXNXwVXLL7kaL3s/0TwEvkIhHxhnAFTCG4mTtLjcYNoUGdEAD570z3xjjV9WdEf
D8iPXtP5CJghCAgSUSdIo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUBgK2DW8p8JclscBJ8vhaBmEW7GcwHwYDVR0jBBgw
FoAUZ2Ly9s0z5I7JCzwlAk3LJ6KGz/UwCgYIKoZIzj0EAwIDSAAwRQIgXXoTnCjR
3X2hDw8uZa6Efv6bXzhVuFgnjNwygynftGYCIQDSi0NxDrd4ql6aXx+J2Fp/72yu
pPXKguccqxu0/r2kbQ==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ad:d1:dd:f9:fb:e5:3c:ed:b0:10:d4:c7:73:28:6c:5f
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Mar 31 10:51:41 2023 GMT
            Not After : Mar 28 10:51:41 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:a1:9f:05:cd:5f:05:57:2c:be:e4:68:bd:ec:ff:
                    44:f0:12:f9:08:84:7c:61:9c:01:53:08:6e:26:4e:
                    d2:e3:71:83:68:50:67:44:00:3e:7b:d3:3d:f1:8e:
                    35:7d:59:d1:1f:0f:c8:8f:5e:d3:f9:08:98:21:08:
                    08:12:51:27:48
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                06:02:B6:0D:6F:29:F0:97:25:B1:C0:49:F2:F8:5A:06:61:16:EC:67
            X509v3 Authority Key Identifier: 
                67:62:F2:F6:CD:33:E4:8E:C9:0B:3C:25:02:4D:CB:27:A2:86:CF:F5
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:5d:7a:13:9c:28:d1:dd:7d:a1:0f:0f:2e:65:ae:
        84:7e:fe:9b:5f:38:55:b8:58:27:8c:dc:32:83:29:df:b4:66:
        02:21:00:d2:8b:43:71:0e:b7:78:aa:5e:9a:5f:1f:89:d8:5a:
        7f:ef:6c:ae:a4:f5:ca:82:e7:1c:ab:1b:b4:fe:bd:a4:6d

```
