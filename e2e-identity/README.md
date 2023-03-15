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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/14770476051734854687/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/hjfXUWY63sWV47AQVa6hzy7sWTX6mPP1
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /login
    wire-server->>wire-server: verifier & challenge codes
    wire-server->>+authorization-server:  GET /dex/auth
    authorization-server->>-wire-client: 200
    wire-client->>+authorization-server:  POST /dex/auth/ldap/login
    authorization-server->>-wire-client: 200
    wire-client->>+authorization-server:  POST /dex/approval
    authorization-server->>+wire-server:  GET /callback
    wire-server->>+authorization-server:  POST /dex/token
    authorization-server->>authorization-server: verify verifier & challenge codes
    authorization-server->>-wire-server: 200
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/0h2cuf6Ox6CjeZ1JJsXGIe7A7LFTQv4s
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/IyN4CPBH8TjMHbXB3ZISLpvO7WkwFfHc
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
replay-nonce: WHZaeW5jc2RVdGNiWlNyREhUTVZKdm9yWEtwaDRhUVU
```
```text
WHZaeW5jc2RVdGNiWlNyREhUTVZKdm9yWEtwaDRhUVU
```
#### 5. create a new account
```http request
POST https://stepca:55083/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkFlSHJ4bVBKQUhRSktlRzdXaUlLWTFVbkF3NDAzZDN4ZHJGcTFfTDVKNVEifSwibm9uY2UiOiJXSFphZVc1amMyUlZkR05pV2xOeVJFaFVUVlpLZG05eVdFdHdhRFJoVVZVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "CicACPbtqvS2i2d1XqBp2-QwOGIVlCTQj4Ws2ELguChtObXkFPEm-djOiRlp23TLu-IoLQd0lq7Aw1xf8GQHCw"
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
      "x": "AeHrxmPJAHQJKeG7WiIKY1UnAw403d3xdrFq1_L5J5Q"
    },
    "nonce": "WHZaeW5jc2RVdGNiWlNyREhUTVZKdm9yWEtwaDRhUVU",
    "url": "https://stepca:55083/acme/wire/new-account"
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
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/account/J5EGMJMLG9nCrm8CsPHOnDShCmGDFcpT
replay-nonce: ZHVLRGJod0s2WThGUzh1WXhJenNZVXJoODZpeXI4M2o
```
```json
{
  "status": "valid",
  "orders": "https://stepca:55083/acme/wire/account/J5EGMJMLG9nCrm8CsPHOnDShCmGDFcpT/orders"
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
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L0o1RUdNSk1MRzluQ3JtOENzUEhPbkRTaENtR0RGY3BUIiwidHlwIjoiSldUIiwibm9uY2UiOiJaSFZMUkdKb2QwczJXVGhHVXpoMVdYaEplbk5aVlhKb09EWnBlWEk0TTJvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIlNtaXRoLCBBbGljZSBNIChRQSlcIixcImRvbWFpblwiOlwid2lyZS5jb21cIixcImNsaWVudC1pZFwiOlwiaW06d2lyZWFwcD1ZbVJqT0ROaE9HRmpOekkzTkRNM05XRXpORGxpWlRReU1UVmxORFpsTjJVL2NjZmI0NWI2MzMxMWZjMWZAd2lyZS5jb21cIixcImhhbmRsZVwiOlwiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wMy0xNVQxMzowMDowNC4yODk3NloiLCJub3RBZnRlciI6IjIwMjMtMDMtMTVUMTQ6MDA6MDQuMjg5NzZaIn0",
  "signature": "WdBDcT-fR7wCJrhExd8R9IJRuKdkCsRjDXQi0xFtAoOLwFVxCbI2wPCfGdQCBG7Tn8JludRu1Z5NIfjXI45RAA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/J5EGMJMLG9nCrm8CsPHOnDShCmGDFcpT",
    "typ": "JWT",
    "nonce": "ZHVLRGJod0s2WThGUzh1WXhJenNZVXJoODZpeXI4M2o",
    "url": "https://stepca:55083/acme/wire/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YmRjODNhOGFjNzI3NDM3NWEzNDliZTQyMTVlNDZlN2U/ccfb45b63311fc1f@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
      }
    ],
    "notBefore": "2023-03-15T13:00:04.28976Z",
    "notAfter": "2023-03-15T14:00:04.28976Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv
replay-nonce: UkRVUE96SjFWUE5RWXVSRVZxTjVtTjJxVmlWbmVPVFM
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YmRjODNhOGFjNzI3NDM3NWEzNDliZTQyMTVlNDZlN2U/ccfb45b63311fc1f@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55083/acme/wire/authz/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL"
  ],
  "expires": "2023-03-16T13:00:04Z",
  "notBefore": "2023-03-15T13:00:04.28976Z",
  "notAfter": "2023-03-15T14:00:04.28976Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:55083/acme/wire/authz/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L0o1RUdNSk1MRzluQ3JtOENzUEhPbkRTaENtR0RGY3BUIiwidHlwIjoiSldUIiwibm9uY2UiOiJVa1JWVUU5NlNqRldVRTVSV1hWU1JWWnhUalZ0VGpKeFZtbFdibVZQVkZNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL2F1dGh6LzltVWE1T1lCWmJ1U2tjRG1rN1dBcVBDTnBSaUU0OFdMIn0",
  "payload": "",
  "signature": "BSWEFVe_5zco8w0P0iqaL6PaDV5UVx7Qgqm0xLLEM85CRb2BaKQQIljGiPuNQShbECdX6ONQga25kbBmQPRNAA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/J5EGMJMLG9nCrm8CsPHOnDShCmGDFcpT",
    "typ": "JWT",
    "nonce": "UkRVUE96SjFWUE5RWXVSRVZxTjVtTjJxVmlWbmVPVFM",
    "url": "https://stepca:55083/acme/wire/authz/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL"
  },
  "payload": {}
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/authz/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL
replay-nonce: b3RzSGRVVXV0MTBnQ3p3U0tDeU1DRkhlZFBkNWRXakU
```
```json
{
  "status": "pending",
  "expires": "2023-03-16T13:00:04Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/0h2cuf6Ox6CjeZ1JJsXGIe7A7LFTQv4s",
      "status": "pending",
      "token": "Lnq4no5QBybc8P4d01pCWDzlaO34tATl"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/hjfXUWY63sWV47AQVa6hzy7sWTX6mPP1",
      "status": "pending",
      "token": "Lnq4no5QBybc8P4d01pCWDzlaO34tATl"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YmRjODNhOGFjNzI3NDM3NWEzNDliZTQyMTVlNDZlN2U/ccfb45b63311fc1f@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:20327/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
ZGQ3WGFvZjBiVUJMVkJVQzR0YThrcTJIbnNpOTRVZkg
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiQWVIcnhtUEpBSFFKS2VHN1dpSUtZMVVuQXc0MDNkM3hkckZxMV9MNUo1USJ9fQ.eyJpYXQiOjE2Nzg4ODUyMDQsImV4cCI6MTY3ODk3MTYwNCwibmJmIjoxNjc4ODg1MjA0LCJzdWIiOiJpbTp3aXJlYXBwPVltUmpPRE5oT0dGak56STNORE0zTldFek5EbGlaVFF5TVRWbE5EWmxOMlUvY2NmYjQ1YjYzMzExZmMxZkB3aXJlLmNvbSIsImp0aSI6ImU3OTljOTQwLWE4NzEtNGRhOC04YmNhLTYxNGUwNDU3MjA5MyIsIm5vbmNlIjoiWkdRM1dHRnZaakJpVlVKTVZrSlZRelIwWVRocmNUSklibk5wT1RSVlprZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjAzMjcvIiwiY2hhbCI6IkxucTRubzVRQnliYzhQNGQwMXBDV0R6bGFPMzR0QVRsIn0.RblE2bMC2WoP9xfsihW0ak9s9w4XYHZo_jdHPj3FSVgoZFb8bINeOL2CCo6G5eP2-0VhXAiw3a7HOCy3TKGYDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiQWVIcnhtUEpBSFFKS2VHN1dpSUtZMVVu
QXc0MDNkM3hkckZxMV9MNUo1USJ9fQ.eyJpYXQiOjE2Nzg4ODUyMDQsImV4cCI6M
TY3ODk3MTYwNCwibmJmIjoxNjc4ODg1MjA0LCJzdWIiOiJpbTp3aXJlYXBwPVltU
mpPRE5oT0dGak56STNORE0zTldFek5EbGlaVFF5TVRWbE5EWmxOMlUvY2NmYjQ1Y
jYzMzExZmMxZkB3aXJlLmNvbSIsImp0aSI6ImU3OTljOTQwLWE4NzEtNGRhOC04Y
mNhLTYxNGUwNDU3MjA5MyIsIm5vbmNlIjoiWkdRM1dHRnZaakJpVlVKTVZrSlZRe
lIwWVRocmNUSklibk5wT1RSVlprZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MjAzMjcvIiwiY2hhbCI6IkxucTRubzVRQnliYzhQNGQwMXBDV
0R6bGFPMzR0QVRsIn0.RblE2bMC2WoP9xfsihW0ak9s9w4XYHZo_jdHPj3FSVgoZ
Fb8bINeOL2CCo6G5eP2-0VhXAiw3a7HOCy3TKGYDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "AeHrxmPJAHQJKeG7WiIKY1UnAw403d3xdrFq1_L5J5Q"
  }
}
```

```json
{
  "iat": 1678885204,
  "exp": 1678971604,
  "nbf": 1678885204,
  "sub": "im:wireapp=YmRjODNhOGFjNzI3NDM3NWEzNDliZTQyMTVlNDZlN2U/ccfb45b63311fc1f@wire.com",
  "jti": "e799c940-a871-4da8-8bca-614e04572093",
  "nonce": "ZGQ3WGFvZjBiVUJMVkJVQzR0YThrcTJIbnNpOTRVZkg",
  "htm": "POST",
  "htu": "http://wire.com:20327/",
  "chal": "Lnq4no5QBybc8P4d01pCWDzlaO34tATl"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDg/QsdeHwhN+oIdh+Wpol5WdyPvQdievulgovQFYPK8
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAAeHrxmPJAHQJKeG7WiIKY1UnAw403d3xdrFq1/L5J5Q=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:20327/clients/14770476051734854687/access-token
                          /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pUVdWSWNuaHRVRXBCU0ZGS1MyVkhOMWRwU1V0Wk1WVnVRWGMwTUROa00zaGtja1p4TVY5TU5VbzFVU0o5ZlEuZXlKcFlYUWlPakUyTnpnNE9EVXlNRFFzSW1WNGNDSTZNVFkzT0RrM01UWXdOQ3dpYm1KbUlqb3hOamM0T0RnMU1qQTBMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVmx0VW1wUFJFNW9UMGRHYWs1NlNUTk9SRTB6VGxkRmVrNUViR2xhVkZGNVRWUldiRTVFV214T01sVXZZMk5tWWpRMVlqWXpNekV4Wm1NeFprQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltVTNPVGxqT1RRd0xXRTROekV0TkdSaE9DMDRZbU5oTFRZeE5HVXdORFUzTWpBNU15SXNJbTV2Ym1ObElqb2lXa2RSTTFkSFJuWmFha0pwVmxWS1RWWnJTbFpSZWxJd1dWUm9jbU5VU2tsaWJrNXdUMVJTVmxwclp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakF6TWpjdklpd2lZMmhoYkNJNklreHVjVFJ1YnpWUlFubGlZemhRTkdRd01YQkRWMFI2YkdGUE16UjBRVlJzSW4wLlJibEUyYk1DMldvUDl4ZnNpaFcwYWs5czl3NFhZSFpvX2pkSFBqM0ZTVmdvWkZiOGJJTmVPTDJDQ282RzVlUDItMFZoWEFpdzNhN0hPQ3kzVEtHWUR3
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImlwbVI1RkozZWtBcDhxZmtRTVJfLVk0YU5MamM4XzU2MDNJOGc0YWhsTVEifX0.eyJpYXQiOjE2Nzg4ODUyMDQsImV4cCI6MTY4NjY2MTIwNCwibmJmIjoxNjc4ODg1MjA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjAzMjcvIiwic3ViIjoiaW06d2lyZWFwcD1ZbVJqT0ROaE9HRmpOekkzTkRNM05XRXpORGxpWlRReU1UVmxORFpsTjJVL2NjZmI0NWI2MzMxMWZjMWZAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAzMjcvIiwianRpIjoiNDY5NDk1ZDQtNzNmZi00MzFmLWE3YmItYWRiYTQwZGEyN2Y4Iiwibm9uY2UiOiJaR1EzV0dGdlpqQmlWVUpNVmtKVlF6UjBZVGhyY1RKSWJuTnBPVFJWWmtnIiwiY2hhbCI6IkxucTRubzVRQnliYzhQNGQwMXBDV0R6bGFPMzR0QVRsIiwiY25mIjp7ImtpZCI6ImJ1OUxpM2huQjhDTWlRVVNRSm5Jd1ZJUVFxZC1xY0RqeFBTNUZvWWszYVEifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lRV1ZJY25odFVFcEJTRkZLUzJWSE4xZHBTVXRaTVZWdVFYYzBNRE5rTTNoa2NrWnhNVjlNTlVvMVVTSjlmUS5leUpwWVhRaU9qRTJOemc0T0RVeU1EUXNJbVY0Y0NJNk1UWTNPRGszTVRZd05Dd2libUptSWpveE5qYzRPRGcxTWpBMExDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWbHRVbXBQUkU1b1QwZEdhazU2U1ROT1JFMHpUbGRGZWs1RWJHbGFWRkY1VFZSV2JFNUVXbXhPTWxVdlkyTm1ZalExWWpZek16RXhabU14WmtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VM09UbGpPVFF3TFdFNE56RXROR1JoT0MwNFltTmhMVFl4TkdVd05EVTNNakE1TXlJc0ltNXZibU5sSWpvaVdrZFJNMWRIUm5aYWFrSnBWbFZLVFZaclNsWlJlbEl3V1ZSb2NtTlVTa2xpYms1d1QxUlNWbHByWnlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQXpNamN2SWl3aVkyaGhiQ0k2SWt4dWNUUnVielZSUW5saVl6aFFOR1F3TVhCRFYwUjZiR0ZQTXpSMFFWUnNJbjAuUmJsRTJiTUMyV29QOXhmc2loVzBhazlzOXc0WFlIWm9famRIUGozRlNWZ29aRmI4YklOZU9MMkNDbzZHNWVQMi0wVmhYQWl3M2E3SE9DeTNUS0dZRHciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVltUmpPRE5oT0dGak56STNORE0zTldFek5EbGlaVFF5TVRWbE5EWmxOMlUvY2NmYjQ1YjYzMzExZmMxZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.daeC4zbWOmROqxAbHE3YujKbmlI6QU_7GVIQfM0hGJjgbosDuODxV3Ka-WasyrX69WUq2SmB46kdoTyprGU1Dg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImlwbVI1RkozZWtBcDhxZmtRTVJfLVk0YU5MamM4XzU2MDNJOGc0YWhsTVEifX0.eyJpYXQiOjE2Nzg4ODUyMDQsImV4cCI6MTY4NjY2MTIwNCwibmJmIjoxNjc4ODg1MjA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjAzMjcvIiwic3ViIjoiaW06d2lyZWFwcD1ZbVJqT0ROaE9HRmpOekkzTkRNM05XRXpORGxpWlRReU1UVmxORFpsTjJVL2NjZmI0NWI2MzMxMWZjMWZAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAzMjcvIiwianRpIjoiNDY5NDk1ZDQtNzNmZi00MzFmLWE3YmItYWRiYTQwZGEyN2Y4Iiwibm9uY2UiOiJaR1EzV0dGdlpqQmlWVUpNVmtKVlF6UjBZVGhyY1RKSWJuTnBPVFJWWmtnIiwiY2hhbCI6IkxucTRubzVRQnliYzhQNGQwMXBDV0R6bGFPMzR0QVRsIiwiY25mIjp7ImtpZCI6ImJ1OUxpM2huQjhDTWlRVVNRSm5Jd1ZJUVFxZC1xY0RqeFBTNUZvWWszYVEifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lRV1ZJY25odFVFcEJTRkZLUzJWSE4xZHBTVXRaTVZWdVFYYzBNRE5rTTNoa2NrWnhNVjlNTlVvMVVTSjlmUS5leUpwWVhRaU9qRTJOemc0T0RVeU1EUXNJbVY0Y0NJNk1UWTNPRGszTVRZd05Dd2libUptSWpveE5qYzRPRGcxTWpBMExDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWbHRVbXBQUkU1b1QwZEdhazU2U1ROT1JFMHpUbGRGZWs1RWJHbGFWRkY1VFZSV2JFNUVXbXhPTWxVdlkyTm1ZalExWWpZek16RXhabU14WmtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VM09UbGpPVFF3TFdFNE56RXROR1JoT0MwNFltTmhMVFl4TkdVd05EVTNNakE1TXlJc0ltNXZibU5sSWpvaVdrZFJNMWRIUm5aYWFrSnBWbFZLVFZaclNsWlJlbEl3V1ZSb2NtTlVTa2xpYms1d1QxUlNWbHByWnlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQXpNamN2SWl3aVkyaGhiQ0k2SWt4dWNUUnVielZSUW5saVl6aFFOR1F3TVhCRFYwUjZiR0ZQTXpSMFFWUnNJbjAuUmJsRTJiTUMyV29QOXhmc2loVzBhazlzOXc0WFlIWm9famRIUGozRlNWZ29aRmI4YklOZU9MMkNDbzZHNWVQMi0wVmhYQWl3M2E3SE9DeTNUS0dZRHciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVltUmpPRE5oT0dGak56STNORE0zTldFek5EbGlaVFF5TVRWbE5EWmxOMlUvY2NmYjQ1YjYzMzExZmMxZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.daeC4zbWOmROqxAbHE3YujKbmlI6QU_7GVIQfM0hGJjgbosDuODxV3Ka-WasyrX69WUq2SmB46kdoTyprGU1Dg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6ImlwbVI1RkozZWtBcDhxZmtRTVJfLVk0YU5M
amM4XzU2MDNJOGc0YWhsTVEifX0.eyJpYXQiOjE2Nzg4ODUyMDQsImV4cCI6MTY4
NjY2MTIwNCwibmJmIjoxNjc4ODg1MjA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjAzMjcvIiwic3ViIjoiaW06d2lyZWFwcD1ZbVJqT0ROaE9HRmpOekkzTkRNM05X
RXpORGxpWlRReU1UVmxORFpsTjJVL2NjZmI0NWI2MzMxMWZjMWZAd2lyZS5jb20i
LCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAzMjcvIiwianRpIjoiNDY5NDk1ZDQt
NzNmZi00MzFmLWE3YmItYWRiYTQwZGEyN2Y4Iiwibm9uY2UiOiJaR1EzV0dGdlpq
QmlWVUpNVmtKVlF6UjBZVGhyY1RKSWJuTnBPVFJWWmtnIiwiY2hhbCI6IkxucTRu
bzVRQnliYzhQNGQwMXBDV0R6bGFPMzR0QVRsIiwiY25mIjp7ImtpZCI6ImJ1OUxp
M2huQjhDTWlRVVNRSm5Jd1ZJUVFxZC1xY0RqeFBTNUZvWWszYVEifSwicHJvb2Yi
OiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFu
ZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElq
b2lRV1ZJY25odFVFcEJTRkZLUzJWSE4xZHBTVXRaTVZWdVFYYzBNRE5rTTNoa2Nr
WnhNVjlNTlVvMVVTSjlmUS5leUpwWVhRaU9qRTJOemc0T0RVeU1EUXNJbVY0Y0NJ
Nk1UWTNPRGszTVRZd05Dd2libUptSWpveE5qYzRPRGcxTWpBMExDSnpkV0lpT2lK
cGJUcDNhWEpsWVhCd1BWbHRVbXBQUkU1b1QwZEdhazU2U1ROT1JFMHpUbGRGZWs1
RWJHbGFWRkY1VFZSV2JFNUVXbXhPTWxVdlkyTm1ZalExWWpZek16RXhabU14WmtC
M2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VM09UbGpPVFF3TFdFNE56RXROR1JoT0Mw
NFltTmhMVFl4TkdVd05EVTNNakE1TXlJc0ltNXZibU5sSWpvaVdrZFJNMWRIUm5a
YWFrSnBWbFZLVFZaclNsWlJlbEl3V1ZSb2NtTlVTa2xpYms1d1QxUlNWbHByWnlJ
c0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIw
Nk1qQXpNamN2SWl3aVkyaGhiQ0k2SWt4dWNUUnVielZSUW5saVl6aFFOR1F3TVhC
RFYwUjZiR0ZQTXpSMFFWUnNJbjAuUmJsRTJiTUMyV29QOXhmc2loVzBhazlzOXc0
WFlIWm9famRIUGozRlNWZ29aRmI4YklOZU9MMkNDbzZHNWVQMi0wVmhYQWl3M2E3
SE9DeTNUS0dZRHciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVltUmpPRE5oT0dG
ak56STNORE0zTldFek5EbGlaVFF5TVRWbE5EWmxOMlUvY2NmYjQ1YjYzMzExZmMx
ZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50
X2lkIn0.daeC4zbWOmROqxAbHE3YujKbmlI6QU_7GVIQfM0hGJjgbosDuODxV3Ka
-WasyrX69WUq2SmB46kdoTyprGU1Dg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "at+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "ipmR5FJ3ekAp8qfkQMR_-Y4aNLjc8_5603I8g4ahlMQ"
  }
}
```

```json
{
  "iat": 1678885204,
  "exp": 1686661204,
  "nbf": 1678885204,
  "iss": "http://wire.com:20327/",
  "sub": "im:wireapp=YmRjODNhOGFjNzI3NDM3NWEzNDliZTQyMTVlNDZlN2U/ccfb45b63311fc1f@wire.com",
  "aud": "http://wire.com:20327/",
  "jti": "469495d4-73ff-431f-a7bb-adba40da27f8",
  "nonce": "ZGQ3WGFvZjBiVUJMVkJVQzR0YThrcTJIbnNpOTRVZkg",
  "chal": "Lnq4no5QBybc8P4d01pCWDzlaO34tATl",
  "cnf": {
    "kid": "bu9Li3hnB8CMiQUSQJnIwVIQQqd-qcDjxPS5FoYk3aQ"
  },
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiQWVIcnhtUEpBSFFKS2VHN1dpSUtZMVVuQXc0MDNkM3hkckZxMV9MNUo1USJ9fQ.eyJpYXQiOjE2Nzg4ODUyMDQsImV4cCI6MTY3ODk3MTYwNCwibmJmIjoxNjc4ODg1MjA0LCJzdWIiOiJpbTp3aXJlYXBwPVltUmpPRE5oT0dGak56STNORE0zTldFek5EbGlaVFF5TVRWbE5EWmxOMlUvY2NmYjQ1YjYzMzExZmMxZkB3aXJlLmNvbSIsImp0aSI6ImU3OTljOTQwLWE4NzEtNGRhOC04YmNhLTYxNGUwNDU3MjA5MyIsIm5vbmNlIjoiWkdRM1dHRnZaakJpVlVKTVZrSlZRelIwWVRocmNUSklibk5wT1RSVlprZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjAzMjcvIiwiY2hhbCI6IkxucTRubzVRQnliYzhQNGQwMXBDV0R6bGFPMzR0QVRsIn0.RblE2bMC2WoP9xfsihW0ak9s9w4XYHZo_jdHPj3FSVgoZFb8bINeOL2CCo6G5eP2-0VhXAiw3a7HOCy3TKGYDw",
  "client_id": "im:wireapp=YmRjODNhOGFjNzI3NDM3NWEzNDliZTQyMTVlNDZlN2U/ccfb45b63311fc1f@wire.com",
  "api_version": 3,
  "scope": "wire_client_id"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIGlWAr/2boA25AhjQMuzqWHOKsaKiCJcoXJcq/m5/skb
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAipmR5FJ3ekAp8qfkQMR/+Y4aNLjc8/5603I8g4ahlMQ=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/hjfXUWY63sWV47AQVa6hzy7sWTX6mPP1
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L0o1RUdNSk1MRzluQ3JtOENzUEhPbkRTaENtR0RGY3BUIiwidHlwIjoiSldUIiwibm9uY2UiOiJiM1J6U0dSVlZYVjBNVEJuUTNwM1UwdERlVTFEUmtobFpGQmtOV1JYYWtVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL2NoYWxsZW5nZS85bVVhNU9ZQlpidVNrY0RtazdXQXFQQ05wUmlFNDhXTC9oamZYVVdZNjNzV1Y0N0FRVmE2aHp5N3NXVFg2bVBQMSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltbHdiVkkxUmtvelpXdEJjRGh4Wm10UlRWSmZMVmswWVU1TWFtTTRYelUyTUROSk9HYzBZV2hzVFZFaWZYMC5leUpwWVhRaU9qRTJOemc0T0RVeU1EUXNJbVY0Y0NJNk1UWTROalkyTVRJd05Dd2libUptSWpveE5qYzRPRGcxTWpBMExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpBek1qY3ZJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFaYlZKcVQwUk9hRTlIUm1wT2Vra3pUa1JOTTA1WFJYcE9SR3hwV2xSUmVVMVVWbXhPUkZwc1RqSlZMMk5qWm1JME5XSTJNek14TVdaak1XWkFkMmx5WlM1amIyMGlMQ0poZFdRaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQXpNamN2SWl3aWFuUnBJam9pTkRZNU5EazFaRFF0TnpObVppMDBNekZtTFdFM1ltSXRZV1JpWVRRd1pHRXlOMlk0SWl3aWJtOXVZMlVpT2lKYVIxRXpWMGRHZGxwcVFtbFdWVXBOVm10S1ZsRjZVakJaVkdoeVkxUktTV0p1VG5CUFZGSldXbXRuSWl3aVkyaGhiQ0k2SWt4dWNUUnVielZSUW5saVl6aFFOR1F3TVhCRFYwUjZiR0ZQTXpSMFFWUnNJaXdpWTI1bUlqcDdJbXRwWkNJNkltSjFPVXhwTTJodVFqaERUV2xSVlZOUlNtNUpkMVpKVVZGeFpDMXhZMFJxZUZCVE5VWnZXV3N6WVZFaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsUlYxWkpZMjVvZEZWRmNFSlRSa1pMVXpKV1NFNHhaSEJUVlhSYVRWWldkVkZZWXpCTlJFNXJUVE5vYTJOclduaE5WamxOVGxWdk1WVlRTamxtVVM1bGVVcHdXVmhSYVU5cVJUSk9lbWMwVDBSVmVVMUVVWE5KYlZZMFkwTkpOazFVV1ROUFJHc3pUVlJaZDA1RGQybGliVXB0U1dwdmVFNXFZelJQUkdjeFRXcEJNRXhEU25wa1YwbHBUMmxLY0dKVWNETmhXRXBzV1ZoQ2QxQldiSFJWYlhCUVVrVTFiMVF3WkVkaGF6VTJVMVJPVDFKRk1IcFViR1JHWldzMVJXSkhiR0ZXUmtZMVZGWlNWMkpGTlVWWGJYaFBUV3hWZGxreVRtMVphbEV4V1dwWmVrMTZSWGhhYlUxNFdtdENNMkZZU214TWJVNTJZbE5KYzBsdGNEQmhVMGsyU1cxVk0wOVViR3BQVkZGM1RGZEZORTU2UlhST1IxSm9UME13TkZsdFRtaE1WRmw0VGtkVmQwNUVWVE5OYWtFMVRYbEpjMGx0TlhaaWJVNXNTV3B2YVZkclpGSk5NV1JJVW01YVlXRnJTbkJXYkZaTFZGWmFjbE5zV2xKbGJFbDNWMVpTYjJOdFRsVlRhMnhwWW1zMWQxUXhVbE5XYkhCeVdubEpjMGx0YURCaVUwazJTV3hDVUZVeFVXbE1RMHB2WkVoVmFVOXBTbTlrU0ZKM1QyazRkbVF5YkhsYVV6VnFZakl3TmsxcVFYcE5hbU4yU1dsM2FWa3lhR2hpUTBrMlNXdDRkV05VVW5WaWVsWlNVVzVzYVZsNmFGRk9SMUYzVFZoQ1JGWXdValppUjBaUVRYcFNNRkZXVW5OSmJqQXVVbUpzUlRKaVRVTXlWMjlRT1hobWMybG9WekJoYXpsek9YYzBXRmxJV205ZmFtUklVR296UmxOV1oyOWFSbUk0WWtsT1pVOU1Na05EYnpaSE5XVlFNaTB3Vm1oWVFXbDNNMkUzU0U5RGVUTlVTMGRaUkhjaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFZsdFVtcFBSRTVvVDBkR2FrNTZTVE5PUkUwelRsZEZlazVFYkdsYVZGRjVUVlJXYkU1RVdteE9NbFV2WTJObVlqUTFZall6TXpFeFptTXhaa0IzYVhKbExtTnZiU0lzSW1Gd2FWOTJaWEp6YVc5dUlqb3pMQ0p6WTI5d1pTSTZJbmRwY21WZlkyeHBaVzUwWDJsa0luMC5kYWVDNHpiV09tUk9xeEFiSEUzWXVqS2JtbEk2UVVfN0dWSVFmTTBoR0pqZ2Jvc0R1T0R4VjNLYS1XYXN5clg2OVdVcTJTbUI0Nmtkb1R5cHJHVTFEZyJ9",
  "signature": "dntrUaq_PcOxey0kVvd2zKG_2Y6IqWMiO7N1NNlCDao14umDsD6p4HikczRW4Z6B93l8ZVIN5F-Kupk_G3G4Aw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/J5EGMJMLG9nCrm8CsPHOnDShCmGDFcpT",
    "typ": "JWT",
    "nonce": "b3RzSGRVVXV0MTBnQ3p3U0tDeU1DRkhlZFBkNWRXakU",
    "url": "https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/hjfXUWY63sWV47AQVa6hzy7sWTX6mPP1"
  },
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImlwbVI1RkozZWtBcDhxZmtRTVJfLVk0YU5MamM4XzU2MDNJOGc0YWhsTVEifX0.eyJpYXQiOjE2Nzg4ODUyMDQsImV4cCI6MTY4NjY2MTIwNCwibmJmIjoxNjc4ODg1MjA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjAzMjcvIiwic3ViIjoiaW06d2lyZWFwcD1ZbVJqT0ROaE9HRmpOekkzTkRNM05XRXpORGxpWlRReU1UVmxORFpsTjJVL2NjZmI0NWI2MzMxMWZjMWZAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAzMjcvIiwianRpIjoiNDY5NDk1ZDQtNzNmZi00MzFmLWE3YmItYWRiYTQwZGEyN2Y4Iiwibm9uY2UiOiJaR1EzV0dGdlpqQmlWVUpNVmtKVlF6UjBZVGhyY1RKSWJuTnBPVFJWWmtnIiwiY2hhbCI6IkxucTRubzVRQnliYzhQNGQwMXBDV0R6bGFPMzR0QVRsIiwiY25mIjp7ImtpZCI6ImJ1OUxpM2huQjhDTWlRVVNRSm5Jd1ZJUVFxZC1xY0RqeFBTNUZvWWszYVEifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lRV1ZJY25odFVFcEJTRkZLUzJWSE4xZHBTVXRaTVZWdVFYYzBNRE5rTTNoa2NrWnhNVjlNTlVvMVVTSjlmUS5leUpwWVhRaU9qRTJOemc0T0RVeU1EUXNJbVY0Y0NJNk1UWTNPRGszTVRZd05Dd2libUptSWpveE5qYzRPRGcxTWpBMExDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWbHRVbXBQUkU1b1QwZEdhazU2U1ROT1JFMHpUbGRGZWs1RWJHbGFWRkY1VFZSV2JFNUVXbXhPTWxVdlkyTm1ZalExWWpZek16RXhabU14WmtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VM09UbGpPVFF3TFdFNE56RXROR1JoT0MwNFltTmhMVFl4TkdVd05EVTNNakE1TXlJc0ltNXZibU5sSWpvaVdrZFJNMWRIUm5aYWFrSnBWbFZLVFZaclNsWlJlbEl3V1ZSb2NtTlVTa2xpYms1d1QxUlNWbHByWnlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQXpNamN2SWl3aVkyaGhiQ0k2SWt4dWNUUnVielZSUW5saVl6aFFOR1F3TVhCRFYwUjZiR0ZQTXpSMFFWUnNJbjAuUmJsRTJiTUMyV29QOXhmc2loVzBhazlzOXc0WFlIWm9famRIUGozRlNWZ29aRmI4YklOZU9MMkNDbzZHNWVQMi0wVmhYQWl3M2E3SE9DeTNUS0dZRHciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVltUmpPRE5oT0dGak56STNORE0zTldFek5EbGlaVFF5TVRWbE5EWmxOMlUvY2NmYjQ1YjYzMzExZmMxZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.daeC4zbWOmROqxAbHE3YujKbmlI6QU_7GVIQfM0hGJjgbosDuODxV3Ka-WasyrX69WUq2SmB46kdoTyprGU1Dg"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
link: <https://stepca:55083/acme/wire/authz/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL>;rel="up"
location: https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/hjfXUWY63sWV47AQVa6hzy7sWTX6mPP1
replay-nonce: RzNCNTUxVnY2eU90eDF6cFA1WVF1akg0ZFVJWnI2YnE
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/hjfXUWY63sWV47AQVa6hzy7sWTX6mPP1",
  "status": "valid",
  "token": "Lnq4no5QBybc8P4d01pCWDzlaO34tATl"
}
```
### Authenticate end user using Open ID Connect implicit flow
#### 18. Client clicks login button
```http request
GET http://wire.com/login
accept: */*
host: wire.com:20327
```
#### 19. Resource server generates Verifier & Challenge Codes

```text
code_verifier=W9A3RPcUuwn9ZHcsceDXdrMYIRUeTObWGgMkkm7Ccy8&code_challenge=ooFDboNX6t6ktN9c_IvXdi6RptfhpAf0PQ9I-C7z-8c
```
#### 20. Resource server calls authorize url
```http request
GET http://dex:16571/dex/auth?response_type=code&client_id=wireapp&state=Dw_zkp_dmCH-sM3-ElahCQ&code_challenge=ooFDboNX6t6ktN9c_IvXdi6RptfhpAf0PQ9I-C7z-8c&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A20327%2Fcallback&scope=openid+profile&nonce=dnAe_09o-fmCdIo1uYGRnA
```
#### 21. Authorization server redirects to login prompt


```text
200 http://dex:16571/dex/auth/ldap/login?back=&state=tkdwd5ty63f2canyzqsbxztio
{
    "content-length": "1525",
    "date": "Wed, 15 Mar 2023 13:00:04 GMT",
    "content-type": "text/html",
}
```

<details>
<summary>Html</summary>

```html
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
  <form method="post" action="/dex/auth/ldap/login?back=&amp;state=tkdwd5ty63f2canyzqsbxztio">
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

</details>


#### 22. Client submits the login form
```http request
POST http://dex:16571/dex/auth/ldap/login?back=&state=tkdwd5ty63f2canyzqsbxztio
content-type: application/x-www-form-urlencoded
```
```text
login=alicesmith%40wire.com&password=foo
```
#### 23. (Optional) Authorization server presents consent form to client


```text
200 http://dex:16571/dex/approval?req=tkdwd5ty63f2canyzqsbxztio&hmac=-iauUNpTfdH2z1hkebghHeCvs3xmlIqN3pSnl1aIlIM
{
    "date": "Wed, 15 Mar 2023 13:00:04 GMT",
    "content-length": "1713",
    "content-type": "text/html",
}
```

<details>
<summary>Html</summary>

```html
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
        <input type="hidden" name="req" value="tkdwd5ty63f2canyzqsbxztio"/>
        <input type="hidden" name="approval" value="approve">
        <button type="submit" class="dex-btn theme-btn--success">
            <span class="dex-btn-text">Grant Access</span>
        </button>
      </form>
    </div>
    <div class="theme-form-row">
      <form method="post">
        <input type="hidden" name="req" value="tkdwd5ty63f2canyzqsbxztio"/>
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

</details>


#### 24. Client submits consent form
```http request
POST http://dex:16571/dex/approval?req=tkdwd5ty63f2canyzqsbxztio&hmac=-iauUNpTfdH2z1hkebghHeCvs3xmlIqN3pSnl1aIlIM
content-type: application/x-www-form-urlencoded
```
```text
req=tkdwd5ty63f2canyzqsbxztio&approval=approve
```
#### 25. Authorization server calls callback url with authorization code
```http request
GET http://wire.com/callback
accept: */*
referer: http://dex:16571/dex/approval?req=tkdwd5ty63f2canyzqsbxztio&hmac=-iauUNpTfdH2z1hkebghHeCvs3xmlIqN3pSnl1aIlIM
host: wire.com:20327
```
#### 26. Resource server call /oauth/token to get Id token
```http request
POST http://dex:16571/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpha1oxVFdSblVXOVJSV1paVFVJek5HNVRjbkF5UmtSSA==
```
```text
grant_type=authorization_code&code=ssakpqukx2hlyddtc2i4cbhlg&code_verifier=W9A3RPcUuwn9ZHcsceDXdrMYIRUeTObWGgMkkm7Ccy8&redirect_uri=http%3A%2F%2Fwire.com%3A20327%2Fcallback
```
#### 27. Authorization server validates Verifier & Challenge Codes

```text
code_verifier=W9A3RPcUuwn9ZHcsceDXdrMYIRUeTObWGgMkkm7Ccy8&code_challenge=ooFDboNX6t6ktN9c_IvXdi6RptfhpAf0PQ9I-C7z-8c
```
#### 28. Authorization server returns Access & Id token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZmJlNDRjMGNlMjA4NTEyMTY3YmYxNWI3MTA4YTc1MmNiNjFiYWIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2NTcxL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmx0VW1wUFJFNW9UMGRHYWs1NlNUTk9SRTB6VGxkRmVrNUViR2xhVkZGNVRWUldiRTVFV214T01sVXZZMk5tWWpRMVlqWXpNekV4Wm1NeFprQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4OTcxNjA0LCJpYXQiOjE2Nzg4ODUyMDQsIm5vbmNlIjoiZG5BZV8wOW8tZm1DZElvMXVZR1JuQSIsImF0X2hhc2giOiJScGlYYlRYSVVjX3FGM3dCWktjMklBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Uuc21pdGgucWFAd2lyZS5jb20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIn0.Bt6gQyx_o3ndZ-nVIQbU0Et743nAjxzb2VCzXGYgmUqlcheuLSGvTiNKAAekjQ6VBiF8qUYQpurZ1XmbjfpkQKauZY5NeLl5enjD-w2u9UNjVsVD5g9ZpfsrI5-RwjGgBwKY2BzH1ueR13ICo_-03Ac_0Xavp5M7igjq4FqVdRz0mTC2mC_oodA4Jx8Q6-nQgNCIqf7ga5Ah9gYxafvAl6MJcbf990QAqW6-Vhb9_0pI85eC5tGHcdkeXCa1iOT9AJgbOvKUR7d-iJtLcjZ9d4nt1jInk0cTSeptjYsBLQYX1NrJa62Ng0RHAxJ6OpVHF8fII5q_c4s4YfYhrPzK6Q",
  "token_type": "bearer",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZmJlNDRjMGNlMjA4NTEyMTY3YmYxNWI3MTA4YTc1MmNiNjFiYWIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2NTcxL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmx0VW1wUFJFNW9UMGRHYWs1NlNUTk9SRTB6VGxkRmVrNUViR2xhVkZGNVRWUldiRTVFV214T01sVXZZMk5tWWpRMVlqWXpNekV4Wm1NeFprQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4OTcxNjA0LCJpYXQiOjE2Nzg4ODUyMDQsIm5vbmNlIjoiZG5BZV8wOW8tZm1DZElvMXVZR1JuQSIsImF0X2hhc2giOiJ0LVhIWkJZM0x6bDBaazVVdG9Xcl9BIiwiY19oYXNoIjoiYzdLRUE3QzhTSkl5TXo5VV9SU0lEQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.kFApxjQkQzkq3uqyO2vDRq7ixVXJ8ukypOze2mdTAnlmeS2PcFIN1z7yea4MEEFjtxbm_wj_i4Ws4PLxCCuBW9u8XJAegK6ull36BZWSodBV6q2xERr4QDPGyzBnHYbptek2Tup9bk4PyB5WsD7-72dEXJbQLkEWpHAtbYsCxw8_bm6Y-EoKQ79QaiH7W-E3IinjZHjlmvDEKEHvmL8JhmuLHgy_COgkKs8-2mPSEPvoNIbKvb6FLdSq0WfXChUJZSnSPpWLa9IzyMizdbXj-EzwVkT_5V05_l3J7dWcziYEZ76jQ70N4QA1kU4fUqEdkDVaL24E7U22ZojPWP4AHg"
}
```
#### 29. Resource server returns Id token to client

```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZmJlNDRjMGNlMjA4NTEyMTY3YmYxNWI3MTA4YTc1MmNiNjFiYWIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2NTcxL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmx0VW1wUFJFNW9UMGRHYWs1NlNUTk9SRTB6VGxkRmVrNUViR2xhVkZGNVRWUldiRTVFV214T01sVXZZMk5tWWpRMVlqWXpNekV4Wm1NeFprQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4OTcxNjA0LCJpYXQiOjE2Nzg4ODUyMDQsIm5vbmNlIjoiZG5BZV8wOW8tZm1DZElvMXVZR1JuQSIsImF0X2hhc2giOiJ0LVhIWkJZM0x6bDBaazVVdG9Xcl9BIiwiY19oYXNoIjoiYzdLRUE3QzhTSkl5TXo5VV9SU0lEQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.kFApxjQkQzkq3uqyO2vDRq7ixVXJ8ukypOze2mdTAnlmeS2PcFIN1z7yea4MEEFjtxbm_wj_i4Ws4PLxCCuBW9u8XJAegK6ull36BZWSodBV6q2xERr4QDPGyzBnHYbptek2Tup9bk4PyB5WsD7-72dEXJbQLkEWpHAtbYsCxw8_bm6Y-EoKQ79QaiH7W-E3IinjZHjlmvDEKEHvmL8JhmuLHgy_COgkKs8-2mPSEPvoNIbKvb6FLdSq0WfXChUJZSnSPpWLa9IzyMizdbXj-EzwVkT_5V05_l3J7dWcziYEZ76jQ70N4QA1kU4fUqEdkDVaL24E7U22ZojPWP4AHg
```
#### 30. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZmJlNDRjMGNlMjA4NTEyMTY3YmYxNWI3MTA4YTc1MmNiNjFiYWIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2NTcxL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmx0VW1wUFJFNW9UMGRHYWs1NlNUTk9SRTB6VGxkRmVrNUViR2xhVkZGNVRWUldiRTVFV214T01sVXZZMk5tWWpRMVlqWXpNekV4Wm1NeFprQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4OTcxNjA0LCJpYXQiOjE2Nzg4ODUyMDQsIm5vbmNlIjoiZG5BZV8wOW8tZm1DZElvMXVZR1JuQSIsImF0X2hhc2giOiJ0LVhIWkJZM0x6bDBaazVVdG9Xcl9BIiwiY19oYXNoIjoiYzdLRUE3QzhTSkl5TXo5VV9SU0lEQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.kFApxjQkQzkq3uqyO2vDRq7ixVXJ8ukypOze2mdTAnlmeS2PcFIN1z7yea4MEEFjtxbm_wj_i4Ws4PLxCCuBW9u8XJAegK6ull36BZWSodBV6q2xERr4QDPGyzBnHYbptek2Tup9bk4PyB5WsD7-72dEXJbQLkEWpHAtbYsCxw8_bm6Y-EoKQ79QaiH7W-E3IinjZHjlmvDEKEHvmL8JhmuLHgy_COgkKs8-2mPSEPvoNIbKvb6FLdSq0WfXChUJZSnSPpWLa9IzyMizdbXj-EzwVkT_5V05_l3J7dWcziYEZ76jQ70N4QA1kU4fUqEdkDVaL24E7U22ZojPWP4AHg)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZmJlNDRjMGNlMjA4NTEyMTY3YmYxNWI3
MTA4YTc1MmNiNjFiYWIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2NTcxL2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmx0VW1wUFJFNW9UMGRHYWs1NlNUTk9SR
TB6VGxkRmVrNUViR2xhVkZGNVRWUldiRTVFV214T01sVXZZMk5tWWpRMVlqWXpNe
kV4Wm1NeFprQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjc4OTcxNjA0LCJpYXQiOjE2Nzg4ODUyMDQsIm5vbmNlIjoiZG5BZV8wO
W8tZm1DZElvMXVZR1JuQSIsImF0X2hhc2giOiJ0LVhIWkJZM0x6bDBaazVVdG9Xc
l9BIiwiY19oYXNoIjoiYzdLRUE3QzhTSkl5TXo5VV9SU0lEQSIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZ
XJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.kFApxjQkQzkq3uqyO2vDRq7i
xVXJ8ukypOze2mdTAnlmeS2PcFIN1z7yea4MEEFjtxbm_wj_i4Ws4PLxCCuBW9u8
XJAegK6ull36BZWSodBV6q2xERr4QDPGyzBnHYbptek2Tup9bk4PyB5WsD7-72dE
XJbQLkEWpHAtbYsCxw8_bm6Y-EoKQ79QaiH7W-E3IinjZHjlmvDEKEHvmL8JhmuL
Hgy_COgkKs8-2mPSEPvoNIbKvb6FLdSq0WfXChUJZSnSPpWLa9IzyMizdbXj-Ezw
VkT_5V05_l3J7dWcziYEZ76jQ70N4QA1kU4fUqEdkDVaL24E7U22ZojPWP4AHg
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "58fbe44c0ce208512167bf15b7108a752cb61bab"
}
```

```json
{
  "iss": "http://dex:16571/dex",
  "sub": "ClBpbTp3aXJlYXBwPVltUmpPRE5oT0dGak56STNORE0zTldFek5EbGlaVFF5TVRWbE5EWmxOMlUvY2NmYjQ1YjYzMzExZmMxZkB3aXJlLmNvbRIEbGRhcA",
  "aud": "wireapp",
  "exp": 1678971604,
  "iat": 1678885204,
  "nonce": "dnAe_09o-fmCdIo1uYGRnA",
  "at_hash": "t-XHZBY3Lzl0Zk5UtoWr_A",
  "c_hash": "c7KEA7C8SJIyMz9U_RSIDA",
  "name": "im:wireapp=alice.smith.qa@wire.com",
  "preferred_username": "Smith, Alice M (QA)"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2fUGY5MmDZ/4yQfPxHAk
HrBow4F5DUHQq/Xx1dG06Gy/L9jvZXiaPKYFb53OKSRPRpp2dJ2TTD6nQpo9nJX2
gpPCtywoCt5xb2uM7Fg9UW18PQgOu+peUBs/7UrRd4TjEpKP2CFj6RJScZuG3g4v
9A+oqkUz4sZ4zo3g6VxXRnT62/ZYEzmio/7bI23mQipmvR3PsxJYX/iakSLUDO7H
sCvPlxLJU5x5eZeiPefN7qc4ZD3q1REXRrXIodhdoo645mVZSecLvKulfaFREwF5
x8pCK/xxolE0g1u3V4hHxzlbI7yEV4a5BA+Ik5xFUWI7MrAsp4aB8ies4+RymgR2
AwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/0h2cuf6Ox6CjeZ1JJsXGIe7A7LFTQv4s
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L0o1RUdNSk1MRzluQ3JtOENzUEhPbkRTaENtR0RGY3BUIiwidHlwIjoiSldUIiwibm9uY2UiOiJSek5DTlRVeFZuWTJlVTkwZURGNmNGQTFXVkYxYWtnMFpGVkpXbkkyWW5FIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL2NoYWxsZW5nZS85bVVhNU9ZQlpidVNrY0RtazdXQXFQQ05wUmlFNDhXTC8waDJjdWY2T3g2Q2plWjFKSnNYR0llN0E3TEZUUXY0cyJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJalU0Wm1KbE5EUmpNR05sTWpBNE5URXlNVFkzWW1ZeE5XSTNNVEE0WVRjMU1tTmlOakZpWVdJaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTJOVGN4TDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZteDBWVzF3VUZKRk5XOVVNR1JIWVdzMU5sTlVUazlTUlRCNlZHeGtSbVZyTlVWaVIyeGhWa1pHTlZSV1VsZGlSVFZGVjIxNFQwMXNWWFpaTWs1dFdXcFJNVmxxV1hwTmVrVjRXbTFOZUZwclFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qYzRPVGN4TmpBMExDSnBZWFFpT2pFMk56ZzRPRFV5TURRc0ltNXZibU5sSWpvaVpHNUJaVjh3T1c4dFptMURaRWx2TVhWWlIxSnVRU0lzSW1GMFgyaGhjMmdpT2lKMExWaElXa0paTTB4NmJEQmFhelZWZEc5WGNsOUJJaXdpWTE5b1lYTm9Jam9pWXpkTFJVRTNRemhUU2tsNVRYbzVWVjlTVTBsRVFTSXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObExuTnRhWFJvTG5GaFFIZHBjbVV1WTI5dElpd2ljSEpsWm1WeWNtVmtYM1Z6WlhKdVlXMWxJam9pVTIxcGRHZ3NJRUZzYVdObElFMGdLRkZCS1NKOS5rRkFweGpRa1F6a3EzdXF5TzJ2RFJxN2l4VlhKOHVreXBPemUybWRUQW5sbWVTMlBjRklOMXo3eWVhNE1FRUZqdHhibV93al9pNFdzNFBMeENDdUJXOXU4WEpBZWdLNnVsbDM2QlpXU29kQlY2cTJ4RVJyNFFEUEd5ekJuSFlicHRlazJUdXA5Yms0UHlCNVdzRDctNzJkRVhKYlFMa0VXcEhBdGJZc0N4dzhfYm02WS1Fb0tRNzlRYWlIN1ctRTNJaW5qWkhqbG12REVLRUh2bUw4SmhtdUxIZ3lfQ09na0tzOC0ybVBTRVB2b05JYkt2YjZGTGRTcTBXZlhDaFVKWlNuU1BwV0xhOUl6eU1pemRiWGotRXp3VmtUXzVWMDVfbDNKN2RXY3ppWUVaNzZqUTcwTjRRQTFrVTRmVXFFZGtEVmFMMjRFN1UyMlpvalBXUDRBSGciLCJrZXlhdXRoIjoiTG5xNG5vNVFCeWJjOFA0ZDAxcENXRHpsYU8zNHRBVGwuXzd6UTg3dE5pZmFwYlh3UXV5dnpnVW9DbGpNZnZOVlYxdEFDZnFJcjNyNCJ9",
  "signature": "GsvH7vb8d8k5ZGI7_2pmjMbxQLNIPuzNAIlyEvwnKXvTEIiSKHiUtEpj-JR3AHu54jGSyfECBFE1y3QRYbzFBg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/J5EGMJMLG9nCrm8CsPHOnDShCmGDFcpT",
    "typ": "JWT",
    "nonce": "RzNCNTUxVnY2eU90eDF6cFA1WVF1akg0ZFVJWnI2YnE",
    "url": "https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/0h2cuf6Ox6CjeZ1JJsXGIe7A7LFTQv4s"
  },
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU4ZmJlNDRjMGNlMjA4NTEyMTY3YmYxNWI3MTA4YTc1MmNiNjFiYWIifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE2NTcxL2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmx0VW1wUFJFNW9UMGRHYWs1NlNUTk9SRTB6VGxkRmVrNUViR2xhVkZGNVRWUldiRTVFV214T01sVXZZMk5tWWpRMVlqWXpNekV4Wm1NeFprQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4OTcxNjA0LCJpYXQiOjE2Nzg4ODUyMDQsIm5vbmNlIjoiZG5BZV8wOW8tZm1DZElvMXVZR1JuQSIsImF0X2hhc2giOiJ0LVhIWkJZM0x6bDBaazVVdG9Xcl9BIiwiY19oYXNoIjoiYzdLRUE3QzhTSkl5TXo5VV9SU0lEQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.kFApxjQkQzkq3uqyO2vDRq7ixVXJ8ukypOze2mdTAnlmeS2PcFIN1z7yea4MEEFjtxbm_wj_i4Ws4PLxCCuBW9u8XJAegK6ull36BZWSodBV6q2xERr4QDPGyzBnHYbptek2Tup9bk4PyB5WsD7-72dEXJbQLkEWpHAtbYsCxw8_bm6Y-EoKQ79QaiH7W-E3IinjZHjlmvDEKEHvmL8JhmuLHgy_COgkKs8-2mPSEPvoNIbKvb6FLdSq0WfXChUJZSnSPpWLa9IzyMizdbXj-EzwVkT_5V05_l3J7dWcziYEZ76jQ70N4QA1kU4fUqEdkDVaL24E7U22ZojPWP4AHg",
    "keyauth": "Lnq4no5QBybc8P4d01pCWDzlaO34tATl._7zQ87tNifapbXwQuyvzgUoCljMfvNVV1tACfqIr3r4"
  }
}
```
#### 31. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
link: <https://stepca:55083/acme/wire/authz/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL>;rel="up"
location: https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/0h2cuf6Ox6CjeZ1JJsXGIe7A7LFTQv4s
replay-nonce: UzZkU1hRZVY3SEhXbk1SWU9JOFF1dXZyTFZkWkRvUzA
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:55083/acme/wire/challenge/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL/0h2cuf6Ox6CjeZ1JJsXGIe7A7LFTQv4s",
  "status": "valid",
  "token": "Lnq4no5QBybc8P4d01pCWDzlaO34tATl"
}
```
### Client presents a CSR and gets its certificate
#### 32. verify the status of the order
```http request
POST https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L0o1RUdNSk1MRzluQ3JtOENzUEhPbkRTaENtR0RGY3BUIiwidHlwIjoiSldUIiwibm9uY2UiOiJVelprVTFoUlpWWTNTRWhYYmsxU1dVOUpPRkYxZFhaeVRGWmtXa1J2VXpBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL29yZGVyL0FSUzg2Y3ppWUdHVldhVDNlS0Z6eFRTUnRJZkozc1d2In0",
  "payload": "",
  "signature": "QyRISV4PYdHhYu9NIBvrJLQMAyWfTqfCUoMN42bRGbZrEN3FxMVh8mWupnng_QxBvm6It9MESo2DtlbKG53gDg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/J5EGMJMLG9nCrm8CsPHOnDShCmGDFcpT",
    "typ": "JWT",
    "nonce": "UzZkU1hRZVY3SEhXbk1SWU9JOFF1dXZyTFZkWkRvUzA",
    "url": "https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv"
  },
  "payload": {}
}
```
#### 33. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv
replay-nonce: bHRwQnZkdHFTMHNubXM1VkVtQjRiWDY1YmR5Mk5zWG8
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YmRjODNhOGFjNzI3NDM3NWEzNDliZTQyMTVlNDZlN2U/ccfb45b63311fc1f@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55083/acme/wire/authz/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL"
  ],
  "expires": "2023-03-16T13:00:04Z",
  "notBefore": "2023-03-15T13:00:04.28976Z",
  "notAfter": "2023-03-15T14:00:04.28976Z"
}
```
#### 34. create a CSR and call finalize url
```http request
POST https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L0o1RUdNSk1MRzluQ3JtOENzUEhPbkRTaENtR0RGY3BUIiwidHlwIjoiSldUIiwibm9uY2UiOiJiSFJ3UW5aa2RIRlRNSE51YlhNMVZrVnRRalJpV0RZMVltUjVNazV6V0c4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL29yZGVyL0FSUzg2Y3ppWUdHVldhVDNlS0Z6eFRTUnRJZkozc1d2L2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCVURDQ0FRSUNBUUF3T1RFa01DSUdDMkNHU0FHRy1FSURBWUZ4REJOVGJXbDBhQ3dnUVd4cFkyVWdUU0FvVVVFcE1SRXdEd1lEVlFRS0RBaDNhWEpsTG1OdmJUQXFNQVVHQXl0bGNBTWhBQUhoNjhaanlRQjBDU25odTFvaUNtTlZKd01PTk4zZDhYYXhhdGZ5LVNlVW9JR1ZNSUdTQmdrcWhraUc5dzBCQ1E0eGdZUXdnWUV3ZndZRFZSMFJCSGd3ZG9aUWFXMDZkMmx5WldGd2NEMTViWEpxYjJSdWFHOW5abXB1ZW1remJtUnRNMjUzWlhwdVpHeHBlblJ4ZVcxMGRteHVaSHBzYmpKMUwyTmpabUkwTldJMk16TXhNV1pqTVdaQWQybHlaUzVqYjIyR0ltbHRPbmRwY21WaGNIQTlZV3hwWTJVdWMyMXBkR2d1Y1dGQWQybHlaUzVqYjIwd0JRWURLMlZ3QTBFQW1RWUhFQm5hWGMxRTlaajNRVGVqTVBjYk9kdkd1MFZJX25lXzFIX3ZyQl9sb1hQV1FzbVlJYTR4WWhjak4xT0Rrc2t3ek44Y18xcm5wWU1yTGQ0YUJ3In0",
  "signature": "MDvvdzGAwPA4oxEuqqVXJbjEeWs7zjstcU6IM1d1OZMC33haojFLUjRG-kZYY6oknOOtOM_L8ImLR_tlmFd9AQ"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/J5EGMJMLG9nCrm8CsPHOnDShCmGDFcpT",
    "typ": "JWT",
    "nonce": "bHRwQnZkdHFTMHNubXM1VkVtQjRiWDY1YmR5Mk5zWG8",
    "url": "https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv/finalize"
  },
  "payload": {
    "csr": "MIIBUDCCAQICAQAwOTEkMCIGC2CGSAGG-EIDAYFxDBNTbWl0aCwgQWxpY2UgTSAoUUEpMREwDwYDVQQKDAh3aXJlLmNvbTAqMAUGAytlcAMhAAHh68ZjyQB0CSnhu1oiCmNVJwMONN3d8Xaxatfy-SeUoIGVMIGSBgkqhkiG9w0BCQ4xgYQwgYEwfwYDVR0RBHgwdoZQaW06d2lyZWFwcD15bXJqb2RuaG9nZmpuemkzbmRtM253ZXpuZGxpenRxeW10dmxuZHpsbjJ1L2NjZmI0NWI2MzMxMWZjMWZAd2lyZS5jb22GImltOndpcmVhcHA9YWxpY2Uuc21pdGgucWFAd2lyZS5jb20wBQYDK2VwA0EAmQYHEBnaXc1E9Zj3QTejMPcbOdvGu0VI_ne_1H_vrB_loXPWQsmYIa4xYhcjN1ODkskwzN8c_1rnpYMrLd4aBw"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBUDCCAQICAQAwOTEkMCIGC2CGSAGG+EIDAYFxDBNTbWl0aCwgQWxpY2UgTSAo
UUEpMREwDwYDVQQKDAh3aXJlLmNvbTAqMAUGAytlcAMhAAHh68ZjyQB0CSnhu1oi
CmNVJwMONN3d8Xaxatfy+SeUoIGVMIGSBgkqhkiG9w0BCQ4xgYQwgYEwfwYDVR0R
BHgwdoZQaW06d2lyZWFwcD15bXJqb2RuaG9nZmpuemkzbmRtM253ZXpuZGxpenRx
eW10dmxuZHpsbjJ1L2NjZmI0NWI2MzMxMWZjMWZAd2lyZS5jb22GImltOndpcmVh
cHA9YWxpY2Uuc21pdGgucWFAd2lyZS5jb20wBQYDK2VwA0EAmQYHEBnaXc1E9Zj3
QTejMPcbOdvGu0VI/ne/1H/vrB/loXPWQsmYIa4xYhcjN1ODkskwzN8c/1rnpYMr
Ld4aBw==
-----END CERTIFICATE REQUEST-----

```
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: 2.16.840.1.113730.3.1.241 = "Smith, Alice M (QA)", O = wire.com
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    01:e1:eb:c6:63:c9:00:74:09:29:e1:bb:5a:22:0a:
                    63:55:27:03:0e:34:dd:dd:f1:76:b1:6a:d7:f2:f9:
                    27:94
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=ymrjodnhogfjnzi3ndm3nwezndliztqymtvlndzln2u/ccfb45b63311fc1f@wire.com, URI:im:wireapp=alice.smith.qa@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        99:06:07:10:19:da:5d:cd:44:f5:98:f7:41:37:a3:30:f7:1b:
        39:db:c6:bb:45:48:fe:77:bf:d4:7f:ef:ac:1f:e5:a1:73:d6:
        42:c9:98:21:ae:31:62:17:23:37:53:83:92:c9:30:cc:df:1c:
        ff:5a:e7:a5:83:2b:2d:de:1a:07

```

#### 35. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55083/acme/wire/directory>;rel="index"
location: https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv
replay-nonce: azRuRWtqNTlrTWpqMU43dUZMQkFTUHRqQm5xckF6Tjc
```
```json
{
  "certificate": "https://stepca:55083/acme/wire/certificate/IyN4CPBH8TjMHbXB3ZISLpvO7WkwFfHc",
  "status": "valid",
  "finalize": "https://stepca:55083/acme/wire/order/ARS86cziYGGVWaT3eKFzxTSRtIfJ3sWv/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YmRjODNhOGFjNzI3NDM3NWEzNDliZTQyMTVlNDZlN2U/ccfb45b63311fc1f@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55083/acme/wire/authz/9mUa5OYBZbuSkcDmk7WAqPCNpRiE48WL"
  ],
  "expires": "2023-03-16T13:00:04Z",
  "notBefore": "2023-03-15T13:00:04.28976Z",
  "notAfter": "2023-03-15T14:00:04.28976Z"
}
```
#### 36. fetch the certificate
```http request
POST https://stepca:55083/acme/wire/certificate/IyN4CPBH8TjMHbXB3ZISLpvO7WkwFfHc
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDgzL2FjbWUvd2lyZS9hY2NvdW50L0o1RUdNSk1MRzluQ3JtOENzUEhPbkRTaENtR0RGY3BUIiwidHlwIjoiSldUIiwibm9uY2UiOiJhelJ1Uld0cU5UbHJUV3BxTVU0M2RVWk1Ra0ZUVUhScVFtNXhja0Y2VGpjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwODMvYWNtZS93aXJlL2NlcnRpZmljYXRlL0l5TjRDUEJIOFRqTUhiWEIzWklTTHB2TzdXa3dGZkhjIn0",
  "payload": "",
  "signature": "ZK4SNHoLpKxMsEcpADRo5ErlKYAj8SHDYDENelDZ8l5fvDmf-1mpYaBFYPc1XcAjnzi0KPpfrDbrtkgVrl7aBg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55083/acme/wire/account/J5EGMJMLG9nCrm8CsPHOnDShCmGDFcpT",
    "typ": "JWT",
    "nonce": "azRuRWtqNTlrTWpqMU43dUZMQkFTUHRqQm5xckF6Tjc",
    "url": "https://stepca:55083/acme/wire/certificate/IyN4CPBH8TjMHbXB3ZISLpvO7WkwFfHc"
  },
  "payload": {}
}
```
#### 37. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:55083/acme/wire/directory>;rel="index"
replay-nonce: TlY5S2dZc2JYRXVFNEdtYVRldGNlT3B6RjEyeE1tcFQ
```
```json
"-----BEGIN CERTIFICATE-----\nMIICQzCCAemgAwIBAgIQJ1DBbpmq5aPPgxQxJHJe6TAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzAzMTUxMzAwMDRaFw0yMzAzMTUxNDAwMDRaMDExETAPBgNVBAoTCHdpcmUuY29t\nMRwwGgYDVQQDExNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEAAeHrxmPJ\nAHQJKeG7WiIKY1UnAw403d3xdrFq1/L5J5SjggETMIIBDzAOBgNVHQ8BAf8EBAMC\nB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBRID6/t\nYkI2FqMmkaC475kkHvEUGjAfBgNVHSMEGDAWgBQlpuER92NN9ZeAG5nufZI0ufGi\nAjB/BgNVHREEeDB2hiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29t\nhlBpbTp3aXJlYXBwPXltcmpvZG5ob2dmam56aTNuZG0zbndlem5kbGl6dHF5bXR2\nbG5kemxuMnUvY2NmYjQ1YjYzMzExZmMxZkB3aXJlLmNvbTAdBgwrBgEEAYKkZMYo\nQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIhAPu2zEzHrARkLZtD\nkTbYTgXO369dA16vjxZMaoE9NyTaAiAy+E1BpvrJ7zsxDYhRRJNkJsJtVIudzWLb\nQ3ifrEl5dw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAMvaNXM3X7AcJqk+APIfLfowCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMxNTEz\nMDAwMVoXDTMzMDMxMjEzMDAwMVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASC\nyFxdoNiKt+d0pLP4XN12u8LuDd5MfLXnRJvE0JswR+UO1jtQL4Co71D9b73O8/+r\nrqLZjMU7TSiBCBt2YOvNo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUJabhEfdjTfWXgBuZ7n2SNLnxogIwHwYDVR0jBBgw\nFoAU6ZDURNmNXJdA+upGntWANTcBqX0wCgYIKoZIzj0EAwIDSAAwRQIgYNpGXils\n7C9J6fC7p1d6xW42+/mN5okoUNcAKzMH4bUCIQDQd7MRWcqvFisN59zILDrdak9p\nGeucUWlmxsyohHKHvQ==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICQzCCAemgAwIBAgIQJ1DBbpmq5aPPgxQxJHJe6TAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzAzMTUxMzAwMDRaFw0yMzAzMTUxNDAwMDRaMDExETAPBgNVBAoTCHdpcmUuY29t
MRwwGgYDVQQDExNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEAAeHrxmPJ
AHQJKeG7WiIKY1UnAw403d3xdrFq1/L5J5SjggETMIIBDzAOBgNVHQ8BAf8EBAMC
B4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBRID6/t
YkI2FqMmkaC475kkHvEUGjAfBgNVHSMEGDAWgBQlpuER92NN9ZeAG5nufZI0ufGi
AjB/BgNVHREEeDB2hiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29t
hlBpbTp3aXJlYXBwPXltcmpvZG5ob2dmam56aTNuZG0zbndlem5kbGl6dHF5bXR2
bG5kemxuMnUvY2NmYjQ1YjYzMzExZmMxZkB3aXJlLmNvbTAdBgwrBgEEAYKkZMYo
QAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIhAPu2zEzHrARkLZtD
kTbYTgXO369dA16vjxZMaoE9NyTaAiAy+E1BpvrJ7zsxDYhRRJNkJsJtVIudzWLb
Q3ifrEl5dw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            27:50:c1:6e:99:aa:e5:a3:cf:83:14:31:24:72:5e:e9
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Mar 15 13:00:04 2023 GMT
            Not After : Mar 15 14:00:04 2023 GMT
        Subject: O = wire.com, CN = "Smith, Alice M (QA)"
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    01:e1:eb:c6:63:c9:00:74:09:29:e1:bb:5a:22:0a:
                    63:55:27:03:0e:34:dd:dd:f1:76:b1:6a:d7:f2:f9:
                    27:94
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                48:0F:AF:ED:62:42:36:16:A3:26:91:A0:B8:EF:99:24:1E:F1:14:1A
            X509v3 Authority Key Identifier: 
                25:A6:E1:11:F7:63:4D:F5:97:80:1B:99:EE:7D:92:34:B9:F1:A2:02
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice.smith.qa@wire.com, URI:im:wireapp=ymrjodnhogfjnzi3ndm3nwezndliztqymtvlndzln2u/ccfb45b63311fc1f@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:fb:b6:cc:4c:c7:ac:04:64:2d:9b:43:91:36:
        d8:4e:05:ce:df:af:5d:03:5e:af:8f:16:4c:6a:81:3d:37:24:
        da:02:20:32:f8:4d:41:a6:fa:c9:ef:3b:31:0d:88:51:44:93:
        64:26:c2:6d:54:8b:9d:cd:62:db:43:78:9f:ac:49:79:77

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAMvaNXM3X7AcJqk+APIfLfowCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMxNTEz
MDAwMVoXDTMzMDMxMjEzMDAwMVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASC
yFxdoNiKt+d0pLP4XN12u8LuDd5MfLXnRJvE0JswR+UO1jtQL4Co71D9b73O8/+r
rqLZjMU7TSiBCBt2YOvNo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUJabhEfdjTfWXgBuZ7n2SNLnxogIwHwYDVR0jBBgw
FoAU6ZDURNmNXJdA+upGntWANTcBqX0wCgYIKoZIzj0EAwIDSAAwRQIgYNpGXils
7C9J6fC7p1d6xW42+/mN5okoUNcAKzMH4bUCIQDQd7MRWcqvFisN59zILDrdak9p
GeucUWlmxsyohHKHvQ==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            cb:da:35:73:37:5f:b0:1c:26:a9:3e:00:f2:1f:2d:fa
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Mar 15 13:00:01 2023 GMT
            Not After : Mar 12 13:00:01 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:82:c8:5c:5d:a0:d8:8a:b7:e7:74:a4:b3:f8:5c:
                    dd:76:bb:c2:ee:0d:de:4c:7c:b5:e7:44:9b:c4:d0:
                    9b:30:47:e5:0e:d6:3b:50:2f:80:a8:ef:50:fd:6f:
                    bd:ce:f3:ff:ab:ae:a2:d9:8c:c5:3b:4d:28:81:08:
                    1b:76:60:eb:cd
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                25:A6:E1:11:F7:63:4D:F5:97:80:1B:99:EE:7D:92:34:B9:F1:A2:02
            X509v3 Authority Key Identifier: 
                E9:90:D4:44:D9:8D:5C:97:40:FA:EA:46:9E:D5:80:35:37:01:A9:7D
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:60:da:46:5e:29:6c:ec:2f:49:e9:f0:bb:a7:57:
        7a:c5:6e:36:fb:f9:8d:e6:89:28:50:d7:00:2b:33:07:e1:b5:
        02:21:00:d0:77:b3:11:59:ca:af:16:2b:0d:e7:dc:c8:2c:3a:
        dd:6a:4f:69:19:eb:9c:51:69:66:c6:cc:a8:84:72:87:bd

```
