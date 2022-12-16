# Wire end to end identity example
Ed25519 - SHA256
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/wire-acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/wire-acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/authz/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST /clients/8150466174584694760/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/challenge/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm/rUfoVWOaiCrk6SabEEGx3wNjSuHlVjhI
    acme-server->>+wire-server: GET /.well-known/acme-challenge/t0QjXPekqvRMR7zT33ZDmgbqjOTEazBi
    wire-server->>-acme-server: 200
    acme-server->>+wire-server: GET /.well-known/acme-challenge/biKmls8novc1ik8UFoNZLSnRt0PZ5tDY
    wire-server->>-acme-server: 200
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/certificate/w5mXKMKOQ0yJyHY4xbFUR4AHNTxB2Q2L
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55979/acme/wire-acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55979/acme/wire-acme/new-nonce",
  "newAccount": "https://localhost:55979/acme/wire-acme/new-account",
  "newOrder": "https://localhost:55979/acme/wire-acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55979/acme/wire-acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
replay-nonce: dmVQallIV29ZZkcwVkNLQTRKbG9HcVdyTWU5WEszdTE
```
```json
"dmVQallIV29ZZkcwVkNLQTRKbG9HcVdyTWU5WEszdTE"
```
#### 5. create a new account
```http request
POST https://localhost:55979/acme/wire-acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ild0RWhOMXZXMlE5MG14d1pmVnVBMVA5TmlHRk9oODdFVmk4N0pIZUJEZ1kifSwibm9uY2UiOiJkbVZRYWxsSVYyOVpaa2N3VmtOTFFUUktiRzlIY1ZkeVRXVTVXRXN6ZFRFIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTU5NzkvYWNtZS93aXJlLWFjbWUvbmV3LWFjY291bnQifQ",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "RqLU8rvtwDa9WEEAgbIp9417Pe-u29TGtmOdLoNZC29z5YqPwoWeLeUOiZHg6FIAw11LYwSuseYCVOU8QGY0CQ"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "typ": "JWT",
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "WtEhN1vW2Q90mxwZfVuA1P9NiGFOh87EVi87JHeBDgY"
    },
    "nonce": "dmVQallIV29ZZkcwVkNLQTRKbG9HcVdyTWU5WEszdTE",
    "url": "https://localhost:55979/acme/wire-acme/new-account"
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
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/account/04SCJwrMBHkKneTwZd7FednND54jtIiX
replay-nonce: RzI5eXZYSWEwSG00QUw1ZVlSa2hNQkxaZEx0dk42bnU
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55979/acme/wire-acme/account/04SCJwrMBHkKneTwZd7FednND54jtIiX/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55979/acme/wire-acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvMDRTQ0p3ck1CSGtLbmVUd1pkN0ZlZG5ORDU0anRJaVgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlJ6STVlWFpZU1dFd1NHMDBRVXcxWlZsU2EyaE5Ra3hhWkV4MGRrNDJiblUiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9uZXctb3JkZXIifQ",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaWRwLmV4YW1wbGUuY29tIn0seyJ0eXBlIjoiZG5zIiwidmFsdWUiOiJ3aXJlLmV4YW1wbGUuY29tIn1dLCJub3RCZWZvcmUiOiIyMDIzLTAxLTExVDEyOjEzOjAxLjg0NTc2N1oiLCJub3RBZnRlciI6IjIwMjMtMDEtMTFUMTM6MTM6MDEuODQ1NzY3WiJ9",
  "signature": "jsZ2VlUbsQ7DHlVTiAy_fZZ0TJTtQLUBbVSP-m0LsCPFEJItBYOkWOTDP8eSUYZpw87okZXxkROu-heZ9kZAAw"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55979/acme/wire-acme/account/04SCJwrMBHkKneTwZd7FednND54jtIiX",
    "typ": "JWT",
    "nonce": "RzI5eXZYSWEwSG00QUw1ZVlSa2hNQkxaZEx0dk42bnU",
    "url": "https://localhost:55979/acme/wire-acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "dns",
        "value": "idp.example.com"
      },
      {
        "type": "dns",
        "value": "wire.example.com"
      }
    ],
    "notBefore": "2023-01-11T12:13:01.845767Z",
    "notAfter": "2023-01-11T13:13:01.845767Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm
replay-nonce: ZWdQa0txYlFFZ0lOZHpFajIzTUJ0ZG1sSldXVTRTcWE
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55979/acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55979/acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm",
    "https://localhost:55979/acme/wire-acme/authz/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh"
  ],
  "expires": "2023-01-12T12:13:01Z",
  "notBefore": "2023-01-11T12:13:01.845767Z",
  "notAfter": "2023-01-11T13:13:01.845767Z"
}
```
### Display-name and handle already authorized
#### 9. fetch first challenge
```http request
POST https://localhost:55979/acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvMDRTQ0p3ck1CSGtLbmVUd1pkN0ZlZG5ORDU0anRJaVgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlpXZFFhMHR4WWxGRlowbE9aSHBGYWpJelRVSjBaRzFzU2xkWFZUUlRjV0UiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9hdXRoei8xTXcxTmNWZ3UxY3VzQjlSVGR0RlZkRW82VVFEdWVabSJ9",
  "payload": "",
  "signature": "UT9rhbdQP98UFYoez1kvZqGUC01URSqci66B19A2DhZ_znUdVC-kf_u0fQJpyG11eJdXWsOKmVdR-QxadGaKAw"
}
```
#### 10. get back first challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm
replay-nonce: aEhqc0VXVU5PeEEyV0lUZVFtbmJVNkRMMlEwZzBnMFA
```
```json
{
  "status": "pending",
  "expires": "2023-01-12T12:13:01Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm/TuF58OmHJrsINXztl5KIz9RC64AyF5TY",
      "status": "pending",
      "token": "t0QjXPekqvRMR7zT33ZDmgbqjOTEazBi"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm/rUfoVWOaiCrk6SabEEGx3wNjSuHlVjhI",
      "status": "pending",
      "token": "t0QjXPekqvRMR7zT33ZDmgbqjOTEazBi"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm/muypsbrwZXoSGdr5uQzOwDIAN1AhWNK5",
      "status": "pending",
      "token": "t0QjXPekqvRMR7zT33ZDmgbqjOTEazBi"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "idp.example.com"
  }
}
```
### ACME provides a Wire client ID challenge
#### 11. fetch second challenge
```http request
POST https://localhost:55979/acme/wire-acme/authz/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvMDRTQ0p3ck1CSGtLbmVUd1pkN0ZlZG5ORDU0anRJaVgiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImFFaHFjMFZYVlU1UGVFRXlWMGxVWlZGdGJtSlZOa1JNTWxFd1p6Qm5NRkEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9hdXRoei9sNm43bVNxY1Y4TkltejRLQ3k1R2ZZYko3cTNISFNqaCJ9",
  "payload": "",
  "signature": "XtsG57OGbBw3982VxEw4-b8Y0CvGvsd76sY5bMFvRkyQR9KM_El4JkE3rwumn5hLEs-D9VFsW2fHQZEcWRZABw"
}
```
#### 12. get back second challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/authz/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh
replay-nonce: WVRtM0xiWVNoc3E0WkpYQmpKM2VkVXc0WjQ5R1I0Wmg
```
```json
{
  "status": "pending",
  "expires": "2023-01-12T12:13:01Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh/vJ0fstRH9jKqbKSQfyOlFvQeQs8gyjOs",
      "status": "pending",
      "token": "biKmls8novc1ik8UFoNZLSnRt0PZ5tDY"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh/BQjNIt83DmZal41i2JkRQ4bx7iuWrYBm",
      "status": "pending",
      "token": "biKmls8novc1ik8UFoNZLSnRt0PZ5tDY"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh/XyMkg1yB5cS1iDFDh7EzCBDIgs8PZ0O2",
      "status": "pending",
      "token": "biKmls8novc1ik8UFoNZLSnRt0PZ5tDY"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "wire.example.com"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 13. fetch a nonce from wire-server
```http request
GET http://localhost:59549/clients/token/nonce

```
#### 14. get wire-server nonce
```http request
200

```
```json
"U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU"
```
#### 15. create the client Dpop token with both nonces
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiV3RFaE4xdlcyUTkwbXh3WmZWdUExUDlOaUdGT2g4N0VWaTg3SkhlQkRnWSJ9fQ.eyJpYXQiOjE2NzM0MzkxODEsImV4cCI6MTY3MzUyNTU4MSwibmJmIjoxNjczNDM5MTgxLCJzdWIiOiJpbTp3aXJlYXBwOk4yWTJORFEwWXpZNE9URTFOR0ZsWkRnMFpUZGlNemRpWkdSaVpHUTBZakEvNzExYzQ1Y2Q4MWY1MjdlOEB3aXJlLmNvbSIsImp0aSI6ImYyNzgyMDYyLTczYTAtNDRlMS04NGE4LWY0YmU0NDBjZGU4MSIsIm5vbmNlIjoiVTA5WlIwdG5XRTVRUzFvelMyZDNia0YyZVdKeVIzWlZVSHBwU1RKc01uVSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjU5NTQ5L2NsaWVudHMvODE1MDQ2NjE3NDU4NDY5NDc2MC9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoidDBRalhQZWtxdlJNUjd6VDMzWkRtZ2Jxak9URWF6QmkifQ.CJfLqBa68vzHu8CJiMOirRRttNtqtC2H-MVsvH5GKiaNz-nMLry3O_rif7nN89B6pqFCFcKFv7L6ajq5MeKzDA)
```http request
POST http://localhost:59549/clients/8150466174584694760/access-token

```
#### 16. get a Dpop access token from wire-server
```http request
200

```
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Imd3YXE0ckFqN3FBalhJNmZNMVkwaG9oVThiaVhRbXZLVW5QczB3SFVWYlEifX0.eyJpYXQiOjE2NzM0MzkxODEsImV4cCI6MTY4MTIxNTE4MSwibmJmIjoxNjczNDM5MTgxLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5NTQ5L2NsaWVudHMvODE1MDQ2NjE3NDU4NDY5NDc2MC9hY2Nlc3MtdG9rZW4iLCJzdWIiOiJpbTp3aXJlYXBwOk4yWTJORFEwWXpZNE9URTFOR0ZsWkRnMFpUZGlNemRpWkdSaVpHUTBZakEvNzExYzQ1Y2Q4MWY1MjdlOEB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTk1NDkvY2xpZW50cy84MTUwNDY2MTc0NTg0Njk0NzYwL2FjY2Vzcy10b2tlbiIsImp0aSI6IjhjZDZmZDQxLTVmYzgtNDgwNS1iZmMzLWQyMDg4MWUxYzBiOCIsIm5vbmNlIjoiVTA5WlIwdG5XRTVRUzFvelMyZDNia0YyZVdKeVIzWlZVSHBwU1RKc01uVSIsImNoYWwiOiJ0MFFqWFBla3F2Uk1SN3pUMzNaRG1nYnFqT1RFYXpCaSIsImNuZiI6eyJraWQiOiJXaWdfb3o0eVdJSExvV01zcU4yR1ctSm1ndkVaeUJ4NjFkcGxscXJGakR3In0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVjNSRmFFNHhkbGN5VVRrd2JYaDNXbVpXZFVFeFVEbE9hVWRHVDJnNE4wVldhVGczU2tobFFrUm5XU0o5ZlEuZXlKcFlYUWlPakUyTnpNME16a3hPREVzSW1WNGNDSTZNVFkzTXpVeU5UVTRNU3dpYm1KbUlqb3hOamN6TkRNNU1UZ3hMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndPazR5V1RKT1JGRXdXWHBaTkU5VVJURk9SMFpzV2tSbk1GcFVaR2xOZW1ScFdrZFNhVnBIVVRCWmFrRXZOekV4WXpRMVkyUTRNV1kxTWpkbE9FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltWXlOemd5TURZeUxUY3pZVEF0TkRSbE1TMDROR0U0TFdZMFltVTBOREJqWkdVNE1TSXNJbTV2Ym1ObElqb2lWVEE1V2xJd2RHNVhSVFZSVXpGdmVsTXlaRE5pYTBZeVpWZEtlVkl6V2xaVlNIQndVMVJLYzAxdVZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZiRzlqWVd4b2IzTjBPalU1TlRRNUwyTnNhV1Z1ZEhNdk9ERTFNRFEyTmpFM05EVTRORFk1TkRjMk1DOWhZMk5sYzNNdGRHOXJaVzRpTENKamFHRnNJam9pZERCUmFsaFFaV3R4ZGxKTlVqZDZWRE16V2tSdFoySnhhazlVUldGNlFta2lmUS5DSmZMcUJhNjh2ekh1OENKaU1PaXJSUnR0TnRxdEMySC1NVnN2SDVHS2lhTnotbk1McnkzT19yaWY3bk44OUI2cHFGQ0ZjS0Z2N0w2YWpxNU1lS3pEQSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA6TjJZMk5EUTBZelk0T1RFMU5HRmxaRGcwWlRkaU16ZGlaR1JpWkdRMFlqQS83MTFjNDVjZDgxZjUyN2U4QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ._QC0q4Wc5bwUEcrcSYVk4ZZcotYIFZxdEIhNCuACLRUhvWlNn4e5AmDnc_0wH3ToxeC8X1ExUFU5iNfjtUbCDw)
### Client provides access token
#### 17. send DPoP access token to acme server to have it validated
```http request
POST https://localhost:55979/acme/wire-acme/challenge/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm/rUfoVWOaiCrk6SabEEGx3wNjSuHlVjhI
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvMDRTQ0p3ck1CSGtLbmVUd1pkN0ZlZG5ORDU0anRJaVgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IldWUnRNMHhpV1ZOb2MzRTBXa3BZUW1wS00yVmtWWGMwV2pRNVIxSTBXbWciLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9jaGFsbGVuZ2UvMU13MU5jVmd1MWN1c0I5UlRkdEZWZEVvNlVRRHVlWm0vclVmb1ZXT2FpQ3JrNlNhYkVFR3gzd05qU3VIbFZqaEkifQ",
  "payload": "",
  "signature": "fNAmsRNmegXPATQeTWGlwm-qreS2D61-Up_croeimygdXyJG5tJk-MCoIqZZUJUZEQVCaQqfOHJlHJlYPrD7BQ"
}
```
#### 18. acme server verifies client-id with an http challenge
```http request
GET http://wire.com/.well-known/acme-challenge/t0QjXPekqvRMR7zT33ZDmgbqjOTEazBi

```

#### 19. acme server verifies handle + display-name with an OIDC challenge
```http request
GET http://wire.com/.well-known/acme-challenge/biKmls8novc1ik8UFoNZLSnRt0PZ5tDY

```

#### 20. both challenges are valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
link: <https://localhost:55979/acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm>;rel="up"
location: https://localhost:55979/acme/wire-acme/challenge/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm/rUfoVWOaiCrk6SabEEGx3wNjSuHlVjhI
replay-nonce: eEVHMmlWQzBEQW5aMnhBNjRCRlNncW1adWhIRXR2bnM
```
```json
{
  "type": "http-01",
  "url": "https://localhost:55979/acme/wire-acme/challenge/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm/rUfoVWOaiCrk6SabEEGx3wNjSuHlVjhI",
  "status": "valid",
  "token": "t0QjXPekqvRMR7zT33ZDmgbqjOTEazBi"
}
```
### Client presents a CSR and gets its certificate
#### 21. verify the status of the order
```http request
POST https://localhost:55979/acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvMDRTQ0p3ck1CSGtLbmVUd1pkN0ZlZG5ORDU0anRJaVgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlFUVnZWWFEwVTFWd2QxbFFkVVIxVldGTVZGUlJlazVNWkdaaGEyeGhlR2MiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9vcmRlci93eEVjNzFkWWFxTzZQQ3pObkJoZGNkUXVsbm1VV1pibSJ9",
  "payload": "",
  "signature": "kRSwWQ7w5_Nl531S2tXYL-lJhKQiIYxrP-jdFGklG60HDD5PK_kkl9qZST06SqNQJ0zsAhLbUoAtvjWDDZV9Ag"
}
```
#### 22. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm
replay-nonce: SDJoYUQyNGhvTkVIQjc3SDhNUDhub3hGa05zZ1BGRlg
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55979/acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55979/acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm",
    "https://localhost:55979/acme/wire-acme/authz/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh"
  ],
  "expires": "2023-01-12T12:13:01Z",
  "notBefore": "2023-01-11T12:13:01.845767Z",
  "notAfter": "2023-01-11T13:13:01.845767Z"
}
```
#### 23. create a CSR and call finalize url
```http request
POST https://localhost:55979/acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvMDRTQ0p3ck1CSGtLbmVUd1pkN0ZlZG5ORDU0anRJaVgiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlNESm9ZVVF5TkdodlRrVklRamMzU0RoTlVEaHViM2hHYTA1eloxQkdSbGciLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9vcmRlci93eEVjNzFkWWFxTzZQQ3pObkJoZGNkUXVsbm1VV1pibS9maW5hbGl6ZSJ9",
  "payload": "eyJjc3IiOiJNSUctTUhJQ0FRQXdBREFxTUFVR0F5dGxjQU1oQUZyUklUZGIxdGtQZEpzY0dYMWJnTlRfVFloaFRvZk94Rll2T3lSM2dRNEdvRDh3UFFZSktvWklodmNOQVFrT01UQXdMakFzQmdOVkhSRUVKVEFqZ2hCM2FYSmxMbVY0WVcxd2JHVXVZMjl0Z2c5cFpIQXVaWGhoYlhCc1pTNWpiMjB3QlFZREsyVndBMEVBNzhGYkxnUXZqZTFGTU13S2VSTjl4c2dvUlFQNndnazdJNDE1Zk1DclYxTTQ3TVlwb3dGS1pWMmJDTDVTZ0lqb2taMkdhYU1SYzlzWWtyYVpjVm00REEifQ",
  "signature": "yo4l80E8_82jrpIIHGrqqhftzJ2pGv1x5EvjwyXQaclSfUZE605yOFPl5lFNeGLZ2WvdQBIN6dI5MVHfJ4eqAA"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55979/acme/wire-acme/account/04SCJwrMBHkKneTwZd7FednND54jtIiX",
    "typ": "JWT",
    "nonce": "SDJoYUQyNGhvTkVIQjc3SDhNUDhub3hGa05zZ1BGRlg",
    "url": "https://localhost:55979/acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm/finalize"
  },
  "payload": {
    "csr": "MIG-MHICAQAwADAqMAUGAytlcAMhAFrRITdb1tkPdJscGX1bgNT_TYhhTofOxFYvOyR3gQ4GoD8wPQYJKoZIhvcNAQkOMTAwLjAsBgNVHREEJTAjghB3aXJlLmV4YW1wbGUuY29tgg9pZHAuZXhhbXBsZS5jb20wBQYDK2VwA0EA78FbLgQvje1FMMwKeRN9xsgoRQP6wgk7I415fMCrV1M47MYpowFKZV2bCL5SgIjokZ2GaaMRc9sYkraZcVm4DA"
  }
}
```
#### 24. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm
replay-nonce: blhwU0tQNHBRZ2UyS1A4aFRRVXEzdnV6YnNSQklnS3Y
```
```json
{
  "certificate": "https://localhost:55979/acme/wire-acme/certificate/w5mXKMKOQ0yJyHY4xbFUR4AHNTxB2Q2L",
  "status": "valid",
  "finalize": "https://localhost:55979/acme/wire-acme/order/wxEc71dYaqO6PCzNnBhdcdQulnmUWZbm/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55979/acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm",
    "https://localhost:55979/acme/wire-acme/authz/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh"
  ],
  "expires": "2023-01-12T12:13:01Z",
  "notBefore": "2023-01-11T12:13:01.845767Z",
  "notAfter": "2023-01-11T13:13:01.845767Z"
}
```
#### 25. fetch the certificate
```http request
POST https://localhost:55979/acme/wire-acme/certificate/w5mXKMKOQ0yJyHY4xbFUR4AHNTxB2Q2L
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvMDRTQ0p3ck1CSGtLbmVUd1pkN0ZlZG5ORDU0anRJaVgiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImJsaHdVMHRRTkhCUloyVXlTMUE0YUZSUlZYRXpkblY2WW5OU1FrbG5TM1kiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9jZXJ0aWZpY2F0ZS93NW1YS01LT1EweUp5SFk0eGJGVVI0QUhOVHhCMlEyTCJ9",
  "payload": "",
  "signature": "zI7JfNGpcS6a9CMzybpkcsM6V2Rxw-BYUuSHLNdQzsp9U7U6gyNx_D5_IPShjGUcSFRQYyvEEE0pNqYhsKJnBw"
}
```
#### 26. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
replay-nonce: eHVMdWtIdW9LdkhQWFFhclFUekpmUjNqbkpxenhpQTA
```
```json
[
  "MIIBxjCCAWugAwIBAgIQTw/iH52pH9KDPWXcdsSHqjAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzAxMTExMjEzMDFaFw0yMzAxMTExMzEzMDFaMAAwKjAFBgMrZXADIQBa0SE3W9bZ\nD3SbHBl9W4DU/02IYU6HzsRWLzskd4EOBqOBxzCBxDAOBgNVHQ8BAf8EBAMCB4Aw\nHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBTWykZ0L4Tm\nxOb3z2wyGBZt9VobEjAfBgNVHSMEGDAWgBRfioUEdEH5erzMyvRrhhkWnEaFSzAv\nBgNVHREBAf8EJTAjgg9pZHAuZXhhbXBsZS5jb22CEHdpcmUuZXhhbXBsZS5jb20w\nIgYMKwYBBAGCpGTGKEABBBIwEAIBBgQJd2lyZS1hY21lBAAwCgYIKoZIzj0EAwID\nSQAwRgIhAKsV7C0xfVFYevQIfdn4wNWtjrX6JsN2zPRIePKDaMIcAiEAz+SDccjx\n8xREYFScXwAFpL4Mx9/4XQO+m8zJQC9Tk2U=",
  "MIIBtzCCAV6gAwIBAgIQfAscdxcfDXHMAFasqdNBPDAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMTExMTIx\nMjU3WhcNMzMwMTA4MTIxMjU3WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFWD\ntLq8ovTIgEdoVOPgU/BgUDFE0V48EusREV1BXcLueyV9N8er+vQdLcr19RK6oWnl\nb2wIsxiILoda6LQTIdKjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBRfioUEdEH5erzMyvRrhhkWnEaFSzAfBgNVHSMEGDAW\ngBTjq3jLTiX2rPKMnFbgtu6MXTaC7jAKBggqhkjOPQQDAgNHADBEAiAViOrHFnxH\nDf6QMpv5yyx7PBrYu+JQebVYjZUbNl7uvQIgN1YgmiPdj2pO8hUW7rgfTIqrk/H4\n9rp3jmjHk4kXjK4="
]
```
P256 - SHA256
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/wire-acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/wire-acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/authz/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/authz/aBe5qSW0PvgCJn5DE8QjbnmcoLWcEirx
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST /clients/5941187132678151086/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/challenge/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc/F7Q2EzodGFphmO5ZSLgCFkOlyDMI6eaX
    acme-server->>+wire-server: GET /.well-known/acme-challenge/zDxBZFTtS7rYPb4QGFFWWmfSgYL2JpVq
    wire-server->>-acme-server: 200
    acme-server->>+wire-server: GET /.well-known/acme-challenge/79ETTJzY7nCik4em1ljlLsiUmWRfdb2U
    wire-server->>-acme-server: 200
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/certificate/bkhkN4kUVJbQnJFUEB8J7AqUglmJPIFW
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55979/acme/wire-acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55979/acme/wire-acme/new-nonce",
  "newAccount": "https://localhost:55979/acme/wire-acme/new-account",
  "newOrder": "https://localhost:55979/acme/wire-acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55979/acme/wire-acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
replay-nonce: dVJpRUtTZVFISXpvUmJ0UTNZejY4akdGa2pXeG45VHQ
```
```json
"dVJpRUtTZVFISXpvUmJ0UTNZejY4akdGa2pXeG45VHQ"
```
#### 5. create a new account
```http request
POST https://localhost:55979/acme/wire-acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InE4WC1sZzJXM2hKMnlvb2ZzcVhaaTlEQjZfYmFWZ1VHWWNMbUR0M3NEOWMiLCJ5IjoiSUpaVmc3N2l1blVGeFFwOTlmVUNtd2ZFc3pQZnNnRTVzR1RpdWgwMHRTOCJ9LCJub25jZSI6ImRWSnBSVXRUWlZGSVNYcHZVbUowVVROWmVqWTRha2RHYTJwWGVHNDVWSFEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9uZXctYWNjb3VudCJ9",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "h1q8H_lGNhb_Fg8RkQVCRqbSYsKerc96_ZP0nKPWy-QdjeUCmUIGZ8wl0gVu-F8oyC_Oke51J7KRwv1e89GKig"
}
...decoded...
{
  "protected": {
    "alg": "ES256",
    "typ": "JWT",
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "q8X-lg2W3hJ2yoofsqXZi9DB6_baVgUGYcLmDt3sD9c",
      "y": "IJZVg77iunUFxQp99fUCmwfEszPfsgE5sGTiuh00tS8"
    },
    "nonce": "dVJpRUtTZVFISXpvUmJ0UTNZejY4akdGa2pXeG45VHQ",
    "url": "https://localhost:55979/acme/wire-acme/new-account"
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
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/account/i9L0w5HQR7JEC8j1SrOWIkGBWXKArqR7
replay-nonce: dkYwT01SSVNkVUhGZmNhc0xOMGx2UlhNR2xGbFpYbGc
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55979/acme/wire-acme/account/i9L0w5HQR7JEC8j1SrOWIkGBWXKArqR7/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55979/acme/wire-acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvaTlMMHc1SFFSN0pFQzhqMVNyT1dJa0dCV1hLQXJxUjciLCJ0eXAiOiJKV1QiLCJub25jZSI6ImRrWXdUMDFTU1ZOa1ZVaEdabU5oYzB4T01HeDJVbGhOUjJ4R2JGcFliR2MiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9uZXctb3JkZXIifQ",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaWRwLmV4YW1wbGUuY29tIn0seyJ0eXBlIjoiZG5zIiwidmFsdWUiOiJ3aXJlLmV4YW1wbGUuY29tIn1dLCJub3RCZWZvcmUiOiIyMDIzLTAxLTExVDEyOjEzOjA1LjE1MTIwN1oiLCJub3RBZnRlciI6IjIwMjMtMDEtMTFUMTM6MTM6MDUuMTUxMjA3WiJ9",
  "signature": "--F1eAiS6jPBdZwCkDin_q1OSfgNL4n1E5r-_AsJ89Sjfx9-hqrEip9-VXJxttW6wH5yK-j9UiaxV-5pzO7prA"
}
...decoded...
{
  "protected": {
    "alg": "ES256",
    "kid": "https://localhost:55979/acme/wire-acme/account/i9L0w5HQR7JEC8j1SrOWIkGBWXKArqR7",
    "typ": "JWT",
    "nonce": "dkYwT01SSVNkVUhGZmNhc0xOMGx2UlhNR2xGbFpYbGc",
    "url": "https://localhost:55979/acme/wire-acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "dns",
        "value": "idp.example.com"
      },
      {
        "type": "dns",
        "value": "wire.example.com"
      }
    ],
    "notBefore": "2023-01-11T12:13:05.151207Z",
    "notAfter": "2023-01-11T13:13:05.151207Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk
replay-nonce: aWhQVGxSdE5MbkhpS0NXRUZpQ080eE5jSHl1bXh3MjA
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55979/acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55979/acme/wire-acme/authz/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc",
    "https://localhost:55979/acme/wire-acme/authz/aBe5qSW0PvgCJn5DE8QjbnmcoLWcEirx"
  ],
  "expires": "2023-01-12T12:13:05Z",
  "notBefore": "2023-01-11T12:13:05.151207Z",
  "notAfter": "2023-01-11T13:13:05.151207Z"
}
```
### Display-name and handle already authorized
#### 9. fetch first challenge
```http request
POST https://localhost:55979/acme/wire-acme/authz/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvaTlMMHc1SFFSN0pFQzhqMVNyT1dJa0dCV1hLQXJxUjciLCJ0eXAiOiJKV1QiLCJub25jZSI6ImFXaFFWR3hTZEU1TWJraHBTME5YUlVacFEwODBlRTVqU0hsMWJYaDNNakEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9hdXRoei8wQllheDZuSWEzeHFSZmpXdGJGQ0RrWlR2VXBJS1dYYyJ9",
  "payload": "",
  "signature": "pT6R46YZgkh3S_PsEDXem4ZF0f3NJ5HUyb92nbtNjcXnz5_5hPA8_DuwvDgkuJW9YSCZQGhBcqAc6rPV7XOz2A"
}
```
#### 10. get back first challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/authz/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc
replay-nonce: dWlmSDBjbEh3MW85ampQRWtOY2QzdldtNHV3dDJZRm0
```
```json
{
  "status": "pending",
  "expires": "2023-01-12T12:13:05Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc/SyPiKaGx8rf8uGUiWflYXo7ShP7TO3sC",
      "status": "pending",
      "token": "zDxBZFTtS7rYPb4QGFFWWmfSgYL2JpVq"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc/F7Q2EzodGFphmO5ZSLgCFkOlyDMI6eaX",
      "status": "pending",
      "token": "zDxBZFTtS7rYPb4QGFFWWmfSgYL2JpVq"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc/TW798jQjeJQUMi1s9uF6o9O7iG9ZXBAn",
      "status": "pending",
      "token": "zDxBZFTtS7rYPb4QGFFWWmfSgYL2JpVq"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "idp.example.com"
  }
}
```
### ACME provides a Wire client ID challenge
#### 11. fetch second challenge
```http request
POST https://localhost:55979/acme/wire-acme/authz/aBe5qSW0PvgCJn5DE8QjbnmcoLWcEirx
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvaTlMMHc1SFFSN0pFQzhqMVNyT1dJa0dCV1hLQXJxUjciLCJ0eXAiOiJKV1QiLCJub25jZSI6ImRXbG1TREJqYkVoM01XODVhbXBRUld0T1kyUXpkbGR0TkhWM2RESlpSbTAiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9hdXRoei9hQmU1cVNXMFB2Z0NKbjVERThRamJubWNvTFdjRWlyeCJ9",
  "payload": "",
  "signature": "UdFvOd2R7aLvPiSVWQjF_zzDg_9rfqk8i3hZ5uX8PxTZGV_CdjP3vsWK-ULuehBLn53OIgUr_VnJPWs9EJFTVg"
}
```
#### 12. get back second challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/authz/aBe5qSW0PvgCJn5DE8QjbnmcoLWcEirx
replay-nonce: Q1BJaFVHYXNZaEE3QUltZmZyRkJGQmFiY3h2UEhMRmI
```
```json
{
  "status": "pending",
  "expires": "2023-01-12T12:13:05Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/aBe5qSW0PvgCJn5DE8QjbnmcoLWcEirx/Q6slMQz0FVOBg8tHcyMNQQex2TxsD5hX",
      "status": "pending",
      "token": "79ETTJzY7nCik4em1ljlLsiUmWRfdb2U"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/aBe5qSW0PvgCJn5DE8QjbnmcoLWcEirx/VDrfwJ6oXnXAK3yQurKHnYZ44NICxoqm",
      "status": "pending",
      "token": "79ETTJzY7nCik4em1ljlLsiUmWRfdb2U"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/aBe5qSW0PvgCJn5DE8QjbnmcoLWcEirx/J2h0BAyGYMlytI93IUZBUSz4CwN4QNcW",
      "status": "pending",
      "token": "79ETTJzY7nCik4em1ljlLsiUmWRfdb2U"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "wire.example.com"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 13. fetch a nonce from wire-server
```http request
GET http://localhost:59549/clients/token/nonce

```
#### 14. get wire-server nonce
```http request
200

```
```json
"cjhYaFk3WHROZkg1aEZpWjNmSHFCcmprWnFac0RJQjg"
```
#### 15. create the client Dpop token with both nonces
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoicThYLWxnMlczaEoyeW9vZnNxWFppOURCNl9iYVZnVUdZY0xtRHQzc0Q5YyIsInkiOiJJSlpWZzc3aXVuVUZ4UXA5OWZVQ213ZkVzelBmc2dFNXNHVGl1aDAwdFM4In19.eyJpYXQiOjE2NzM0MzkxODUsImV4cCI6MTY3MzUyNTU4NSwibmJmIjoxNjczNDM5MTg1LCJzdWIiOiJpbTp3aXJlYXBwOllUZ3haamMxTWpJMU1qRTJOREpsWldFeE56UTVOV0kyT0RGaU5UUmtNalkvNTI3MzU2MzgyYjY3MWJhZUB3aXJlLmNvbSIsImp0aSI6IjkyMWM1MzU3LWMzZmUtNGM3NC04MmUyLTUwNzk5Zjg2MWQ3MyIsIm5vbmNlIjoiY2poWWFGazNXSFJPWmtnMWFFWnBXak5tU0hGQ2NtcHJXbkZhYzBSSlFqZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjU5NTQ5L2NsaWVudHMvNTk0MTE4NzEzMjY3ODE1MTA4Ni9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiekR4QlpGVHRTN3JZUGI0UUdGRldXbWZTZ1lMMkpwVnEifQ.DU2JsG3arKK-OIF4f-xha-JiQM2wWzLljUpO0Kuj8PtnRAxtqV23BUFTNj7lOeKxWBqJz6jt5v5qIx4IcyIfYA)
```http request
POST http://localhost:59549/clients/5941187132678151086/access-token

```
#### 16. get a Dpop access token from wire-server
```http request
200

```
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkdMa1o4RzJXbkdPdG5odjdsX2JYMWRibG9rTVIwQ2NrT01JU1ItcWtSQnciLCJ5IjoiWkV2QWJud1lRSkZOa1FPN1B6dkt2cEJqQXl1Y3RNSHo2b3V0Y2ptZXNQWSJ9fQ.eyJpYXQiOjE2NzM0MzkxODUsImV4cCI6MTY4MTIxNTE4NSwibmJmIjoxNjczNDM5MTg1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5NTQ5L2NsaWVudHMvNTk0MTE4NzEzMjY3ODE1MTA4Ni9hY2Nlc3MtdG9rZW4iLCJzdWIiOiJpbTp3aXJlYXBwOllUZ3haamMxTWpJMU1qRTJOREpsWldFeE56UTVOV0kyT0RGaU5UUmtNalkvNTI3MzU2MzgyYjY3MWJhZUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTk1NDkvY2xpZW50cy81OTQxMTg3MTMyNjc4MTUxMDg2L2FjY2Vzcy10b2tlbiIsImp0aSI6ImNhNjEwZjk4LWNlOTgtNDI0Yi1hMDNlLTM1OWNjZWZhOWY3MyIsIm5vbmNlIjoiY2poWWFGazNXSFJPWmtnMWFFWnBXak5tU0hGQ2NtcHJXbkZhYzBSSlFqZyIsImNoYWwiOiJ6RHhCWkZUdFM3cllQYjRRR0ZGV1dtZlNnWUwySnBWcSIsImNuZiI6eyJraWQiOiI2Q1VoYndYTFRmenBVUWRRNW8xcjdrQTRQenpDTUsxWURrWXV0QU9zZnJFIn0sInByb29mIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2ljVGhZTFd4bk1sY3phRW95ZVc5dlpuTnhXRnBwT1VSQ05sOWlZVlpuVlVkWlkweHRSSFF6YzBRNVl5SXNJbmtpT2lKSlNscFdaemMzYVhWdVZVWjRVWEE1T1daVlEyMTNaa1Z6ZWxCbWMyZEZOWE5IVkdsMWFEQXdkRk00SW4xOS5leUpwWVhRaU9qRTJOek0wTXpreE9EVXNJbVY0Y0NJNk1UWTNNelV5TlRVNE5Td2libUptSWpveE5qY3pORE01TVRnMUxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd09sbFVaM2hhYW1NeFRXcEpNVTFxUlRKT1JFcHNXbGRGZUU1NlVUVk9WMGt5VDBSR2FVNVVVbXROYWxrdk5USTNNelUyTXpneVlqWTNNV0poWlVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpreU1XTTFNelUzTFdNelptVXROR00zTkMwNE1tVXlMVFV3TnprNVpqZzJNV1EzTXlJc0ltNXZibU5sSWpvaVkycG9XV0ZHYXpOWFNGSlBXbXRuTVdGRlduQlhhazV0VTBoR1EyTnRjSEpYYmtaaFl6QlNTbEZxWnlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmJHOWpZV3hvYjNOME9qVTVOVFE1TDJOc2FXVnVkSE12TlRrME1URTROekV6TWpZM09ERTFNVEE0Tmk5aFkyTmxjM010ZEc5clpXNGlMQ0pqYUdGc0lqb2lla1I0UWxwR1ZIUlROM0paVUdJMFVVZEdSbGRYYldaVFoxbE1Na3B3Vm5FaWZRLkRVMkpzRzNhcktLLU9JRjRmLXhoYS1KaVFNMndXekxsalVwTzBLdWo4UHRuUkF4dHFWMjNCVUZUTmo3bE9lS3hXQnFKejZqdDV2NXFJeDRJY3lJZllBIiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcDpZVGd4WmpjMU1qSTFNakUyTkRKbFpXRXhOelE1TldJMk9ERmlOVFJrTWpZLzUyNzM1NjM4MmI2NzFiYWVAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6Mywic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.qt4oRn7qUOVM5VsS4D7QySrIy_SJheV7dyMk819PUfzrdGgoyG2w1ypQJTedcI13P6_7vZ1zbG89rpSnrzAnbg)
### Client provides access token
#### 17. send DPoP access token to acme server to have it validated
```http request
POST https://localhost:55979/acme/wire-acme/challenge/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc/F7Q2EzodGFphmO5ZSLgCFkOlyDMI6eaX
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvaTlMMHc1SFFSN0pFQzhqMVNyT1dJa0dCV1hLQXJxUjciLCJ0eXAiOiJKV1QiLCJub25jZSI6IlExQkphRlZIWVhOWmFFRTNRVWx0Wm1aeVJrSkdRbUZpWTNoMlVFaE1SbUkiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9jaGFsbGVuZ2UvMEJZYXg2bklhM3hxUmZqV3RiRkNEa1pUdlVwSUtXWGMvRjdRMkV6b2RHRnBobU81WlNMZ0NGa09seURNSTZlYVgifQ",
  "payload": "",
  "signature": "moq7BAaNfvVYujY0gAllbwYV-wVKw_SpGbRRpk_6XwviIZlFgzZPgyEli7FOfQe-qtCtdDjK8XUrdUuzWGKWwg"
}
```
#### 18. acme server verifies client-id with an http challenge
```http request
GET http://wire.com/.well-known/acme-challenge/zDxBZFTtS7rYPb4QGFFWWmfSgYL2JpVq

```

#### 19. acme server verifies handle + display-name with an OIDC challenge
```http request
GET http://wire.com/.well-known/acme-challenge/79ETTJzY7nCik4em1ljlLsiUmWRfdb2U

```

#### 20. both challenges are valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
link: <https://localhost:55979/acme/wire-acme/authz/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc>;rel="up"
location: https://localhost:55979/acme/wire-acme/challenge/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc/F7Q2EzodGFphmO5ZSLgCFkOlyDMI6eaX
replay-nonce: N3A2V2RwclA1Zm9TbmRSc2d2Sm9BZHJKWnloSVNkR1k
```
```json
{
  "type": "http-01",
  "url": "https://localhost:55979/acme/wire-acme/challenge/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc/F7Q2EzodGFphmO5ZSLgCFkOlyDMI6eaX",
  "status": "valid",
  "token": "zDxBZFTtS7rYPb4QGFFWWmfSgYL2JpVq"
}
```
### Client presents a CSR and gets its certificate
#### 21. verify the status of the order
```http request
POST https://localhost:55979/acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvaTlMMHc1SFFSN0pFQzhqMVNyT1dJa0dCV1hLQXJxUjciLCJ0eXAiOiJKV1QiLCJub25jZSI6IlNFWnRjVGRhVUhsbmJVdzBiRTV4TVdoak5YRmxjVVpPZVZOV2NtdEdRMmciLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9vcmRlci9zMzJkSndsNUVrT1NPcm56cUNJZ3hqYWRVMkFHclZrayJ9",
  "payload": "",
  "signature": "3EH0qOm8DGwJikCqAb61Kc-B-YmcV2FvM07V2YFipfvMpHjhWUKbGvkIbdJGsveTWghI4cBXLm5KR5LFV5OPOQ"
}
```
#### 22. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk
replay-nonce: ekEzeFNHeEFvS2E1VE1WV01PZWNNZERzbTBXU1B3Y1Q
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55979/acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55979/acme/wire-acme/authz/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc",
    "https://localhost:55979/acme/wire-acme/authz/aBe5qSW0PvgCJn5DE8QjbnmcoLWcEirx"
  ],
  "expires": "2023-01-12T12:13:05Z",
  "notBefore": "2023-01-11T12:13:05.151207Z",
  "notAfter": "2023-01-11T13:13:05.151207Z"
}
```
#### 23. create a CSR and call finalize url
```http request
POST https://localhost:55979/acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvaTlMMHc1SFFSN0pFQzhqMVNyT1dJa0dCV1hLQXJxUjciLCJ0eXAiOiJKV1QiLCJub25jZSI6ImVrRXplRk5IZUVGdlMyRTFWRTFXVjAxUFpXTk5aRVJ6YlRCWFUxQjNZMVEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9vcmRlci9zMzJkSndsNUVrT1NPcm56cUNJZ3hqYWRVMkFHclZray9maW5hbGl6ZSJ9",
  "payload": "eyJjc3IiOiJNSUg2TUlHaEFnRUFNQUF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVNyeGY2V0RaYmVFbmJLaWgteXBkbUwwTUhyOXRwV0JRWmh3dVlPM2V3UDF5Q1dWWU8tNHJwMUJjVUtmZlgxQXBzSHhMTXozN0lCT2JCazRyb2ROTFV2b0Q4d1BRWUpLb1pJaHZjTkFRa09NVEF3TGpBc0JnTlZIUkVFSlRBamdoQjNhWEpsTG1WNFlXMXdiR1V1WTI5dGdnOXBaSEF1WlhoaGJYQnNaUzVqYjIwd0NnWUlLb1pJemowRUF3SURTQUF3UlFJZ1NDZjFkeDZwSDFNNVJlcENIQnRXdWVIUEE2VzZyeE1KdXV0cC1TVmRkbkFDSVFES1h2V0tnejVad0ZwUm5zY0d2TXJrNnQ5WWFrQnNwalVzeTNkdmtDWF9QdyJ9",
  "signature": "ELwl4iGUVaMkA9hVAqBCtMGVivtJFrzJuVtloYTTPeFHSGIJ8b1gbmRjC_AHkw3jedA35kyuPc3qaqiBvIRFSA"
}
...decoded...
{
  "protected": {
    "alg": "ES256",
    "kid": "https://localhost:55979/acme/wire-acme/account/i9L0w5HQR7JEC8j1SrOWIkGBWXKArqR7",
    "typ": "JWT",
    "nonce": "ekEzeFNHeEFvS2E1VE1WV01PZWNNZERzbTBXU1B3Y1Q",
    "url": "https://localhost:55979/acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk/finalize"
  },
  "payload": {
    "csr": "MIH6MIGhAgEAMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASrxf6WDZbeEnbKih-ypdmL0MHr9tpWBQZhwuYO3ewP1yCWVYO-4rp1BcUKffX1ApsHxLMz37IBObBk4rodNLUvoD8wPQYJKoZIhvcNAQkOMTAwLjAsBgNVHREEJTAjghB3aXJlLmV4YW1wbGUuY29tgg9pZHAuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIgSCf1dx6pH1M5RepCHBtWueHPA6W6rxMJuutp-SVddnACIQDKXvWKgz5ZwFpRnscGvMrk6t9YakBspjUsy3dvkCX_Pw"
  }
}
```
#### 24. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk
replay-nonce: aWF2TjJqM2w3T2VQU1VRTHFCUlJMQ0cxQjVHM1ZIVjg
```
```json
{
  "certificate": "https://localhost:55979/acme/wire-acme/certificate/bkhkN4kUVJbQnJFUEB8J7AqUglmJPIFW",
  "status": "valid",
  "finalize": "https://localhost:55979/acme/wire-acme/order/s32dJwl5EkOSOrnzqCIgxjadU2AGrVkk/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55979/acme/wire-acme/authz/0BYax6nIa3xqRfjWtbFCDkZTvUpIKWXc",
    "https://localhost:55979/acme/wire-acme/authz/aBe5qSW0PvgCJn5DE8QjbnmcoLWcEirx"
  ],
  "expires": "2023-01-12T12:13:05Z",
  "notBefore": "2023-01-11T12:13:05.151207Z",
  "notAfter": "2023-01-11T13:13:05.151207Z"
}
```
#### 25. fetch the certificate
```http request
POST https://localhost:55979/acme/wire-acme/certificate/bkhkN4kUVJbQnJFUEB8J7AqUglmJPIFW
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvaTlMMHc1SFFSN0pFQzhqMVNyT1dJa0dCV1hLQXJxUjciLCJ0eXAiOiJKV1QiLCJub25jZSI6ImFXRjJUakpxTTJ3M1QyVlFVMVZSVEhGQ1VsSk1RMGN4UWpWSE0xWklWamciLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9jZXJ0aWZpY2F0ZS9ia2hrTjRrVVZKYlFuSkZVRUI4SjdBcVVnbG1KUElGVyJ9",
  "payload": "",
  "signature": "NZox85KSWsMf40-HUmZwevAklreY6XWtamccBHp5HIiDMBdl1JgqpWuHUBEbR1DIk4nZlpvC9eZ4bCuFDvKHqQ"
}
```
#### 26. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
replay-nonce: b010OTVkUkhkemdlTHZuak85UVc0WW00Umt1SkhwRFA
```
```json
[
  "MIIB9DCCAZugAwIBAgIRAIWlpSUcSKZfC2bSLCWJ0BUwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwMTExMTIxMzA1WhcNMjMwMTExMTMxMzA1WjAAMFkwEwYHKoZIzj0CAQYIKoZI\nzj0DAQcDQgAEq8X+lg2W3hJ2yoofsqXZi9DB6/baVgUGYcLmDt3sD9cgllWDvuK6\ndQXFCn319QKbB8SzM9+yATmwZOK6HTS1L6OBxzCBxDAOBgNVHQ8BAf8EBAMCB4Aw\nHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBRy0AX1Izd5\nBuKNZ6NUS3Lq7t71djAfBgNVHSMEGDAWgBRfioUEdEH5erzMyvRrhhkWnEaFSzAv\nBgNVHREBAf8EJTAjgg9pZHAuZXhhbXBsZS5jb22CEHdpcmUuZXhhbXBsZS5jb20w\nIgYMKwYBBAGCpGTGKEABBBIwEAIBBgQJd2lyZS1hY21lBAAwCgYIKoZIzj0EAwID\nRwAwRAIgOzSz/9agF8b38vyVb+pkRBVxh7CpnNdn9QkNfYBN/mECIG/Zoxa6MMVo\ngK6ntvRHMLfRhbbwg3X+SDWj+rvaYDpl",
  "MIIBtzCCAV6gAwIBAgIQfAscdxcfDXHMAFasqdNBPDAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMTExMTIx\nMjU3WhcNMzMwMTA4MTIxMjU3WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFWD\ntLq8ovTIgEdoVOPgU/BgUDFE0V48EusREV1BXcLueyV9N8er+vQdLcr19RK6oWnl\nb2wIsxiILoda6LQTIdKjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBRfioUEdEH5erzMyvRrhhkWnEaFSzAfBgNVHSMEGDAW\ngBTjq3jLTiX2rPKMnFbgtu6MXTaC7jAKBggqhkjOPQQDAgNHADBEAiAViOrHFnxH\nDf6QMpv5yyx7PBrYu+JQebVYjZUbNl7uvQIgN1YgmiPdj2pO8hUW7rgfTIqrk/H4\n9rp3jmjHk4kXjK4="
]
```
P384 - SHA384
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/wire-acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/wire-acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/authz/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/authz/X19D9zLfg0L4UhD0Lln4EXdtwcrS96La
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST /clients/2179698508749488607/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/challenge/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5/Vv15Gs5wYSU8syT3dfurmLYRRPfDqbsJ
    acme-server->>+wire-server: GET /.well-known/acme-challenge/1L2gYzBa8Neh3MNBKlYd6bwLp0Qp8Gc0
    wire-server->>-acme-server: 200
    acme-server->>+wire-server: GET /.well-known/acme-challenge/6OZvnZVwdUGpEvsb4gQYOiHXok87XtMy
    wire-server->>-acme-server: 200
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/certificate/jXAs1Rstrh6bNGZazOX6UhSWwHlMwBJr
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55979/acme/wire-acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55979/acme/wire-acme/new-nonce",
  "newAccount": "https://localhost:55979/acme/wire-acme/new-account",
  "newOrder": "https://localhost:55979/acme/wire-acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55979/acme/wire-acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
replay-nonce: a1ZlN2lkSGpiRk1vclRTanVyd3Q1Uk5HU1NFSGRtUVc
```
```json
"a1ZlN2lkSGpiRk1vclRTanVyd3Q1Uk5HU1NFSGRtUVc"
```
#### 5. create a new account
```http request
POST https://localhost:55979/acme/wire-acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6Ing1TWdQX01ZcktSc0RZYkpVMWJ5UHZHY3RpbVFvcTdJbVhHQUM0S1huQTRkZU5naG1zeXVyM21mOFZVa1ZvTFciLCJ5IjoiWURLS00ySmZpRENETDIyR1RLZEhzS0E4TnBzX3ZrUTh4TG9tZE56VTRiUjJyaTNiVU56LXJnSWExLUI5TkR2YSJ9LCJub25jZSI6ImExWmxOMmxrU0dwaVJrMXZjbFJUYW5WeWQzUTFVazVIVTFORlNHUnRVVmMiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9uZXctYWNjb3VudCJ9",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "aNzE9SnQOqamUYNEt_6WJ3Y_VOHekPVPGy_ozVsvRZThj_u_tuh87a0cDke22SjpHu5kvSYVEVZg9Aw7ZsLh3DFQxUsI6YJW9JiPbptgxMA0Y3WPZrcREkCbx77AP-n6"
}
...decoded...
{
  "protected": {
    "alg": "ES384",
    "typ": "JWT",
    "jwk": {
      "kty": "EC",
      "crv": "P-384",
      "x": "x5MgP_MYrKRsDYbJU1byPvGctimQoq7ImXGAC4KXnA4deNghmsyur3mf8VUkVoLW",
      "y": "YDKKM2JfiDCDL22GTKdHsKA8Nps_vkQ8xLomdNzU4bR2ri3bUNz-rgIa1-B9NDva"
    },
    "nonce": "a1ZlN2lkSGpiRk1vclRTanVyd3Q1Uk5HU1NFSGRtUVc",
    "url": "https://localhost:55979/acme/wire-acme/new-account"
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
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/account/saCE1uDI8ZybBmlKLk1WLEieFM1ZG6d4
replay-nonce: dW1FM0p3bVN6V3JsY0dYR2dpcm5BS1dvdDNkNkFDSWo
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55979/acme/wire-acme/account/saCE1uDI8ZybBmlKLk1WLEieFM1ZG6d4/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55979/acme/wire-acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvc2FDRTF1REk4WnliQm1sS0xrMVdMRWllRk0xWkc2ZDQiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImRXMUZNMHAzYlZONlYzSnNZMGRZUjJkcGNtNUJTMWR2ZEROa05rRkRTV28iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9uZXctb3JkZXIifQ",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaWRwLmV4YW1wbGUuY29tIn0seyJ0eXBlIjoiZG5zIiwidmFsdWUiOiJ3aXJlLmV4YW1wbGUuY29tIn1dLCJub3RCZWZvcmUiOiIyMDIzLTAxLTExVDEyOjEzOjA4LjUwMTE1NVoiLCJub3RBZnRlciI6IjIwMjMtMDEtMTFUMTM6MTM6MDguNTAxMTU1WiJ9",
  "signature": "pBrSqGvLLbgz_ciMlF51EX1DukLqDynky2u4uFCzpxrMRgnMXS7nocNlJglUxeWSgpi_BmqEWK3MDo1Z67QbdR3R9jVuZdrmznEDO4DTsmXlCujr0bsoVfbEaggvn8Gk"
}
...decoded...
{
  "protected": {
    "alg": "ES384",
    "kid": "https://localhost:55979/acme/wire-acme/account/saCE1uDI8ZybBmlKLk1WLEieFM1ZG6d4",
    "typ": "JWT",
    "nonce": "dW1FM0p3bVN6V3JsY0dYR2dpcm5BS1dvdDNkNkFDSWo",
    "url": "https://localhost:55979/acme/wire-acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "dns",
        "value": "idp.example.com"
      },
      {
        "type": "dns",
        "value": "wire.example.com"
      }
    ],
    "notBefore": "2023-01-11T12:13:08.501155Z",
    "notAfter": "2023-01-11T13:13:08.501155Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD
replay-nonce: cERlaWUxZ09tc0NhVmRjUlNFc1ZRZkQ5bnR0NE9mU3Y
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55979/acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55979/acme/wire-acme/authz/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5",
    "https://localhost:55979/acme/wire-acme/authz/X19D9zLfg0L4UhD0Lln4EXdtwcrS96La"
  ],
  "expires": "2023-01-12T12:13:08Z",
  "notBefore": "2023-01-11T12:13:08.501155Z",
  "notAfter": "2023-01-11T13:13:08.501155Z"
}
```
### Display-name and handle already authorized
#### 9. fetch first challenge
```http request
POST https://localhost:55979/acme/wire-acme/authz/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvc2FDRTF1REk4WnliQm1sS0xrMVdMRWllRk0xWkc2ZDQiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImNFUmxhV1V4WjA5dGMwTmhWbVJqVWxORmMxWlJaa1E1Ym5SME5FOW1VM1kiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9hdXRoei94cGV6ZXJqc2Q3ZE9nSDcxRVlHclVJeUpOYnNtTUdSNSJ9",
  "payload": "",
  "signature": "jiHPWLpPRaBLrVEqGrxQpf1cPEoh8jZsXsIR6_vsosnncwN33BTIbc4OTlAUVxCx909m6GxZ_5SdbOLfxnOkEQIv8G3YE-s1goE6-J0qLX6hyM6XT6GtzYupbjC0XEk7"
}
```
#### 10. get back first challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/authz/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5
replay-nonce: bU91YlZqUUdBNTFKZWp6RVE4TVI2TElSbnRyNnZ6WEw
```
```json
{
  "status": "pending",
  "expires": "2023-01-12T12:13:08Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5/p96R7B1jS7RSrVSlSNUPeOwvIO5ylRPr",
      "status": "pending",
      "token": "1L2gYzBa8Neh3MNBKlYd6bwLp0Qp8Gc0"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5/Vv15Gs5wYSU8syT3dfurmLYRRPfDqbsJ",
      "status": "pending",
      "token": "1L2gYzBa8Neh3MNBKlYd6bwLp0Qp8Gc0"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5/ECEDi82oFocaz2GeO0UQ62D3FXDv76h1",
      "status": "pending",
      "token": "1L2gYzBa8Neh3MNBKlYd6bwLp0Qp8Gc0"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "idp.example.com"
  }
}
```
### ACME provides a Wire client ID challenge
#### 11. fetch second challenge
```http request
POST https://localhost:55979/acme/wire-acme/authz/X19D9zLfg0L4UhD0Lln4EXdtwcrS96La
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvc2FDRTF1REk4WnliQm1sS0xrMVdMRWllRk0xWkc2ZDQiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImJVOTFZbFpxVVVkQk5URktaV3A2UlZFNFRWSTJURWxTYm5SeU5uWjZXRXciLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9hdXRoei9YMTlEOXpMZmcwTDRVaEQwTGxuNEVYZHR3Y3JTOTZMYSJ9",
  "payload": "",
  "signature": "PG00qvkcV3_harhr87LEadSwOcf1CUOoY05LnPMimVZg_oPRpkanl2KGgoJlQI1PQHbygJW-k9njOIOMAAyB1P7QRL_e4kk4gH6J2tuLBUcaaTugCaLUayeowaX7QGXA"
}
```
#### 12. get back second challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/authz/X19D9zLfg0L4UhD0Lln4EXdtwcrS96La
replay-nonce: TnRVYWZZeWtLa245SngwOUg2Tll6QVcwQUVHdjVNN3M
```
```json
{
  "status": "pending",
  "expires": "2023-01-12T12:13:08Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/X19D9zLfg0L4UhD0Lln4EXdtwcrS96La/vRgmgzeBoajqpk4v8Yjtz5QBxv5jPMFi",
      "status": "pending",
      "token": "6OZvnZVwdUGpEvsb4gQYOiHXok87XtMy"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/X19D9zLfg0L4UhD0Lln4EXdtwcrS96La/04lhlGXkaMQNq7WFzZZ9KPJYzqDolsQA",
      "status": "pending",
      "token": "6OZvnZVwdUGpEvsb4gQYOiHXok87XtMy"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55979/acme/wire-acme/challenge/X19D9zLfg0L4UhD0Lln4EXdtwcrS96La/V6XrjX0gIlWKzJN01CzI5aB5gJnZK4cj",
      "status": "pending",
      "token": "6OZvnZVwdUGpEvsb4gQYOiHXok87XtMy"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "wire.example.com"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 13. fetch a nonce from wire-server
```http request
GET http://localhost:59549/clients/token/nonce

```
#### 14. get wire-server nonce
```http request
200

```
```json
"eTNzR25qTkJqSzZOV1JmRXJ6RWJheHhvM1JIS2kwSlg"
```
#### 15. create the client Dpop token with both nonces
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzM4NCIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0zODQiLCJ4IjoieDVNZ1BfTVlyS1JzRFliSlUxYnlQdkdjdGltUW9xN0ltWEdBQzRLWG5BNGRlTmdobXN5dXIzbWY4VlVrVm9MVyIsInkiOiJZREtLTTJKZmlEQ0RMMjJHVEtkSHNLQThOcHNfdmtROHhMb21kTnpVNGJSMnJpM2JVTnotcmdJYTEtQjlORHZhIn19.eyJpYXQiOjE2NzM0MzkxODgsImV4cCI6MTY3MzUyNTU4OCwibmJmIjoxNjczNDM5MTg4LCJzdWIiOiJpbTp3aXJlYXBwOlpETTBZelF6T1RobU4yTXlORGcwTkdJM1kyWXpORFV5TlRSak5UTXpOekkvMWUzZmQ4M2VjMzc2NDFkZkB3aXJlLmNvbSIsImp0aSI6Ijg5ODA2MTRkLWFkZTgtNDQ3ZC05OTM3LTY0NWE5N2U3NmNlMSIsIm5vbmNlIjoiZVROelIyNXFUa0pxU3paT1YxSm1SWEo2UldKaGVIaHZNMUpJUzJrd1NsZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjU5NTQ5L2NsaWVudHMvMjE3OTY5ODUwODc0OTQ4ODYwNy9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiMUwyZ1l6QmE4TmVoM01OQktsWWQ2YndMcDBRcDhHYzAifQ.Y5PPv3TjuLpWjDPrcEtjFRAZkL3BS67oTr-UrgX8Dr-srhYWisVWOoAVoZfQ-s91rxzguqsuaZ5kYSKXpn8cDsXrAp4A-aXMgnCKNzn4BVcC5Hcm8uChPeoXc6UcPsJR)
```http request
POST http://localhost:59549/clients/2179698508749488607/access-token

```
#### 16. get a Dpop access token from wire-server
```http request
200

```
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzM4NCIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6IlVQWXB0aWkwNV9YejNPcWJXVjJmWFpuZFgtVEFELWwtOTBiQXpjcmRValBCclJlTVFySFhPdVpOdlJnVFFlU0IiLCJ5Ijoib003TXlzVzZGTFJ6emZjMW1aak92Rlc2dFRKUndQZ3NJbk9pZmhxWG5sblFHVFJDQVlWV0dGTENQbncwS1ZvdSJ9fQ.eyJpYXQiOjE2NzM0MzkxODgsImV4cCI6MTY4MTIxNTE4OCwibmJmIjoxNjczNDM5MTg4LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5NTQ5L2NsaWVudHMvMjE3OTY5ODUwODc0OTQ4ODYwNy9hY2Nlc3MtdG9rZW4iLCJzdWIiOiJpbTp3aXJlYXBwOlpETTBZelF6T1RobU4yTXlORGcwTkdJM1kyWXpORFV5TlRSak5UTXpOekkvMWUzZmQ4M2VjMzc2NDFkZkB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTk1NDkvY2xpZW50cy8yMTc5Njk4NTA4NzQ5NDg4NjA3L2FjY2Vzcy10b2tlbiIsImp0aSI6ImIxZjc3YTU1LTc0OTUtNGNkMC1iNmRiLWRjY2VjNzU0MTVjNyIsIm5vbmNlIjoiZVROelIyNXFUa0pxU3paT1YxSm1SWEo2UldKaGVIaHZNMUpJUzJrd1NsZyIsImNoYWwiOiIxTDJnWXpCYThOZWgzTU5CS2xZZDZid0xwMFFwOEdjMCIsImNuZiI6eyJraWQiOiJsblMwcmFCb3pNM2IzSk10aFl3TWJ0OF9hRll4WlBnYk9ZdkZ0UWlxMmMzbjlOWW9sdW1hTEUzNGlkd3NlRGx2In0sInByb29mIjoiZXlKaGJHY2lPaUpGVXpNNE5DSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHpPRFFpTENKNElqb2llRFZOWjFCZlRWbHlTMUp6UkZsaVNsVXhZbmxRZGtkamRHbHRVVzl4TjBsdFdFZEJRelJMV0c1Qk5HUmxUbWRvYlhONWRYSXpiV1k0VmxWclZtOU1WeUlzSW5raU9pSlpSRXRMVFRKS1ptbEVRMFJNTWpKSFZFdGtTSE5MUVRoT2NITmZkbXRST0hoTWIyMWtUbnBWTkdKU01uSnBNMkpWVG5vdGNtZEpZVEV0UWpsT1JIWmhJbjE5LmV5SnBZWFFpT2pFMk56TTBNemt4T0Rnc0ltVjRjQ0k2TVRZM016VXlOVFU0T0N3aWJtSm1Jam94Tmpjek5ETTVNVGc0TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3T2xwRVRUQlplbEY2VDFSb2JVNHlUWGxPUkdjd1RrZEpNMWt5V1hwT1JGVjVUbFJTYWs1VVRYcE9la2t2TVdVelptUTRNMlZqTXpjMk5ERmtaa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJamc1T0RBMk1UUmtMV0ZrWlRndE5EUTNaQzA1T1RNM0xUWTBOV0U1TjJVM05tTmxNU0lzSW01dmJtTmxJam9pWlZST2VsSXlOWEZVYTBweFUzcGFUMVl4U20xU1dFbzJVbGRLYUdWSWFIWk5NVXBKVXpKcmQxTnNaeUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2Ykc5allXeG9iM04wT2pVNU5UUTVMMk5zYVdWdWRITXZNakUzT1RZNU9EVXdPRGMwT1RRNE9EWXdOeTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaU1Vd3laMWw2UW1FNFRtVm9NMDFPUWt0c1dXUTJZbmRNY0RCUmNEaEhZekFpZlEuWTVQUHYzVGp1THBXakRQcmNFdGpGUkFaa0wzQlM2N29Uci1VcmdYOERyLXNyaFlXaXNWV09vQVZvWmZRLXM5MXJ4emd1cXN1YVo1a1lTS1hwbjhjRHNYckFwNEEtYVhNZ25DS056bjRCVmNDNUhjbTh1Q2hQZW9YYzZVY1BzSlIiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwOlpETTBZelF6T1RobU4yTXlORGcwTkdJM1kyWXpORFV5TlRSak5UTXpOekkvMWUzZmQ4M2VjMzc2NDFkZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.gT2DBuw8JIrfQEQ3iashM7BTnqxs3ojb2S_MVkHWsnrTn_-EDxMCybekitqzzyr9NiMSAuhpbv2PZX6bO-NIsQOnbT7gF7xpTlyYVzC08-fHyUXsHMtp4RurB6hCjFdv)
### Client provides access token
#### 17. send DPoP access token to acme server to have it validated
```http request
POST https://localhost:55979/acme/wire-acme/challenge/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5/Vv15Gs5wYSU8syT3dfurmLYRRPfDqbsJ
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvc2FDRTF1REk4WnliQm1sS0xrMVdMRWllRk0xWkc2ZDQiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlRuUlZZV1paZVd0TGEyNDVTbmd3T1VnMlRsbDZRVmN3UVVWSGRqVk5OM00iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9jaGFsbGVuZ2UveHBlemVyanNkN2RPZ0g3MUVZR3JVSXlKTmJzbU1HUjUvVnYxNUdzNXdZU1U4c3lUM2RmdXJtTFlSUlBmRHFic0oifQ",
  "payload": "",
  "signature": "--vrvZd2x3lZelrmm-V4D15FVAgnE8v7A2KLibWPGsfQTVEzAjUosuYv1P7C_yd5ZsrOzl9SgbBW-vSXVj5HArItoLYwRbn8WRIkmuvYoHbrIe8A-5VUtTwDXwLgZft8"
}
```
#### 18. acme server verifies client-id with an http challenge
```http request
GET http://wire.com/.well-known/acme-challenge/1L2gYzBa8Neh3MNBKlYd6bwLp0Qp8Gc0

```

#### 19. acme server verifies handle + display-name with an OIDC challenge
```http request
GET http://wire.com/.well-known/acme-challenge/6OZvnZVwdUGpEvsb4gQYOiHXok87XtMy

```

#### 20. both challenges are valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
link: <https://localhost:55979/acme/wire-acme/authz/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5>;rel="up"
location: https://localhost:55979/acme/wire-acme/challenge/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5/Vv15Gs5wYSU8syT3dfurmLYRRPfDqbsJ
replay-nonce: SE0xZXlmWlR2UkRZOWUxcDg5bm1MQThtUTMyOU55Zms
```
```json
{
  "type": "http-01",
  "url": "https://localhost:55979/acme/wire-acme/challenge/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5/Vv15Gs5wYSU8syT3dfurmLYRRPfDqbsJ",
  "status": "valid",
  "token": "1L2gYzBa8Neh3MNBKlYd6bwLp0Qp8Gc0"
}
```
### Client presents a CSR and gets its certificate
#### 21. verify the status of the order
```http request
POST https://localhost:55979/acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvc2FDRTF1REk4WnliQm1sS0xrMVdMRWllRk0xWkc2ZDQiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImVGYzBWRFJsTm5kWWJ6RmlUMHBvYVhGMVVqbG5UVmxzYUdKeVozZERkVk0iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9vcmRlci84bEtQcUlGa0RwbUFSeDFqdUc1WFFlUFpGYld4T09qRCJ9",
  "payload": "",
  "signature": "TBijhxJS6nrUX2zVgdfXP8AQoR7YeiB7YMLXm7oZ7jMfqHkGnu-0--kG8OtbT73SyJQeL5xZDDE9SHCnHvF4pLx96yUvgLUiBjgUiwdCWyRSUJ2y9USuE6Terdcfi5bz"
}
```
#### 22. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD
replay-nonce: b2cyWEljWndaY1Vjc05lcU1EUGRicDc2Q2lWZHBzM3A
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55979/acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55979/acme/wire-acme/authz/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5",
    "https://localhost:55979/acme/wire-acme/authz/X19D9zLfg0L4UhD0Lln4EXdtwcrS96La"
  ],
  "expires": "2023-01-12T12:13:08Z",
  "notBefore": "2023-01-11T12:13:08.501155Z",
  "notAfter": "2023-01-11T13:13:08.501155Z"
}
```
#### 23. create a CSR and call finalize url
```http request
POST https://localhost:55979/acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvc2FDRTF1REk4WnliQm1sS0xrMVdMRWllRk0xWkc2ZDQiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImIyY3lXRWxqV25kYVkxVmpjMDVsY1UxRVVHUmljRGMyUTJsV1pIQnpNM0EiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9vcmRlci84bEtQcUlGa0RwbUFSeDFqdUc1WFFlUFpGYld4T09qRC9maW5hbGl6ZSJ9",
  "payload": "eyJjc3IiOiJNSUlCTnpDQnZnSUJBREFBTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUV4NU1nUF9NWXJLUnNEWWJKVTFieVB2R2N0aW1Rb3E3SW1YR0FDNEtYbkE0ZGVOZ2htc3l1cjNtZjhWVWtWb0xXWURLS00ySmZpRENETDIyR1RLZEhzS0E4TnBzX3ZrUTh4TG9tZE56VTRiUjJyaTNiVU56LXJnSWExLUI5TkR2YW9EOHdQUVlKS29aSWh2Y05BUWtPTVRBd0xqQXNCZ05WSFJFRUpUQWpnaEIzYVhKbExtVjRZVzF3YkdVdVkyOXRnZzlwWkhBdVpYaGhiWEJzWlM1amIyMHdDZ1lJS29aSXpqMEVBd01EYUFBd1pRSXhBT2xwWWhKTE81TXhmVUZRRVptdFVXTGJpMlQwYnhOX3gxRjFyR1gzeUhFbEhlMDJGQlZNZlc5c3pXak1YNmhjUGdJd1JScmc0N3BFMnd0cjMxTnBId25NUWRFdTR4NlN0QkE1dDU4X2lhVWdDbURqOFZGZmlMWVUzbUduLXRwc3V2bVAifQ",
  "signature": "2o-aGJ_cHc93nMVL5lgl-UQk4GnIkmZX6oY-j0P4adpT8xioGTXI6eGfw772sajItbn8u3ZS9BuV6cNAnO1jX5lg7AZD3UhZ9sEfMJfFf02e3PH6IPsC-d8HxKfFENXd"
}
...decoded...
{
  "protected": {
    "alg": "ES384",
    "kid": "https://localhost:55979/acme/wire-acme/account/saCE1uDI8ZybBmlKLk1WLEieFM1ZG6d4",
    "typ": "JWT",
    "nonce": "b2cyWEljWndaY1Vjc05lcU1EUGRicDc2Q2lWZHBzM3A",
    "url": "https://localhost:55979/acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD/finalize"
  },
  "payload": {
    "csr": "MIIBNzCBvgIBADAAMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEx5MgP_MYrKRsDYbJU1byPvGctimQoq7ImXGAC4KXnA4deNghmsyur3mf8VUkVoLWYDKKM2JfiDCDL22GTKdHsKA8Nps_vkQ8xLomdNzU4bR2ri3bUNz-rgIa1-B9NDvaoD8wPQYJKoZIhvcNAQkOMTAwLjAsBgNVHREEJTAjghB3aXJlLmV4YW1wbGUuY29tgg9pZHAuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwMDaAAwZQIxAOlpYhJLO5MxfUFQEZmtUWLbi2T0bxN_x1F1rGX3yHElHe02FBVMfW9szWjMX6hcPgIwRRrg47pE2wtr31NpHwnMQdEu4x6StBA5t58_iaUgCmDj8VFfiLYU3mGn-tpsuvmP"
  }
}
```
#### 24. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
location: https://localhost:55979/acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD
replay-nonce: emVsNXl2NmozUUQ3UVFDcEs4ZG5FREhzRXFjeFhJME0
```
```json
{
  "certificate": "https://localhost:55979/acme/wire-acme/certificate/jXAs1Rstrh6bNGZazOX6UhSWwHlMwBJr",
  "status": "valid",
  "finalize": "https://localhost:55979/acme/wire-acme/order/8lKPqIFkDpmARx1juG5XQePZFbWxOOjD/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55979/acme/wire-acme/authz/xpezerjsd7dOgH71EYGrUIyJNbsmMGR5",
    "https://localhost:55979/acme/wire-acme/authz/X19D9zLfg0L4UhD0Lln4EXdtwcrS96La"
  ],
  "expires": "2023-01-12T12:13:08Z",
  "notBefore": "2023-01-11T12:13:08.501155Z",
  "notAfter": "2023-01-11T13:13:08.501155Z"
}
```
#### 25. fetch the certificate
```http request
POST https://localhost:55979/acme/wire-acme/certificate/jXAs1Rstrh6bNGZazOX6UhSWwHlMwBJr
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1OTc5L2FjbWUvd2lyZS1hY21lL2FjY291bnQvc2FDRTF1REk4WnliQm1sS0xrMVdMRWllRk0xWkc2ZDQiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImVtVnNOWGwyTm1velVVUTNVVkZEY0VzNFpHNUZSRWh6UlhGamVGaEpNRTAiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTk3OS9hY21lL3dpcmUtYWNtZS9jZXJ0aWZpY2F0ZS9qWEFzMVJzdHJoNmJOR1phek9YNlVoU1d3SGxNd0JKciJ9",
  "payload": "",
  "signature": "1zqYVfWUPLNHfTjrtS1U_37vMHwDPfMWOl60iovGl5AJY3DG3alhdO3TXt9_xegmqTC-_3C13ceTIKOcVW58atz5ZjgTbnuonzI-FHxS5QJqn7BIw_vIZXuweY0V7E9L"
}
```
#### 26. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55979/acme/wire-acme/directory>;rel="index"
replay-nonce: UVNURnlpekVVazJoRVlFZGJJRGxNdkNZelcyRlVDZGE
```
```json
[
  "MIICEDCCAbegAwIBAgIQfovFKqxioQIAsRn6vcJDtzAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzAxMTExMjEzMDhaFw0yMzAxMTExMzEzMDhaMAAwdjAQBgcqhkjOPQIBBgUrgQQA\nIgNiAATHkyA/8xispGwNhslTVvI+8Zy2KZCirsiZcYALgpecDh142CGazK6veZ/x\nVSRWgtZgMoozYl+IMIMvbYZMp0ewoDw2mz++RDzEuiZ03NThtHauLdtQ3P6uAhrX\n4H00O9qjgccwgcQwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMB\nBggrBgEFBQcDAjAdBgNVHQ4EFgQUs1EFbiRt3ZJoXqZLKbohMImrXbMwHwYDVR0j\nBBgwFoAUX4qFBHRB+Xq8zMr0a4YZFpxGhUswLwYDVR0RAQH/BCUwI4IPaWRwLmV4\nYW1wbGUuY29tghB3aXJlLmV4YW1wbGUuY29tMCIGDCsGAQQBgqRkxihAAQQSMBAC\nAQYECXdpcmUtYWNtZQQAMAoGCCqGSM49BAMCA0cAMEQCIBai/Jd5Ru1g6mebr2sy\nB4rHb6SxUZAx/k0R5z5UlSKlAiA9Eud6QG2css7e6IjwrakwwCg7v6HsiV5WFkOt\nMfCtOQ==",
  "MIIBtzCCAV6gAwIBAgIQfAscdxcfDXHMAFasqdNBPDAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMTExMTIx\nMjU3WhcNMzMwMTA4MTIxMjU3WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFWD\ntLq8ovTIgEdoVOPgU/BgUDFE0V48EusREV1BXcLueyV9N8er+vQdLcr19RK6oWnl\nb2wIsxiILoda6LQTIdKjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBRfioUEdEH5erzMyvRrhhkWnEaFSzAfBgNVHSMEGDAW\ngBTjq3jLTiX2rPKMnFbgtu6MXTaC7jAKBggqhkjOPQQDAgNHADBEAiAViOrHFnxH\nDf6QMpv5yyx7PBrYu+JQebVYjZUbNl7uvQIgN1YgmiPdj2pO8hUW7rgfTIqrk/H4\n9rp3jmjHk4kXjK4="
]
```