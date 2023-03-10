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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/5512380144665194603/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/HhFufnzfL9abzJzpUNeblQGthEcrac9J
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
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/wimvHnzRMq5quCx5oGME98k21k0HEtyI
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/C6BUkXe2ZQbPzbWJGQWN0lhwQlhjf31Y
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:56174/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:56174/acme/wire/new-nonce",
  "newAccount": "https://stepca:56174/acme/wire/new-account",
  "newOrder": "https://stepca:56174/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:56174/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:56174/acme/wire/directory>;rel="index"
replay-nonce: Wm0wNHl5VmJJcm1RRTA3UHJvUzNYT29kNjFoa0FnUTM
```
```text
Wm0wNHl5VmJJcm1RRTA3UHJvUzNYT29kNjFoa0FnUTM
```
#### 5. create a new account
```http request
POST https://stepca:56174/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjduUEVUOTdGQUxWQWJMTGwyQWRSdlNsMW56c0YxTklDR3h4LUFEN3E0Q3MifSwibm9uY2UiOiJXbTB3TkhsNVZtSkpjbTFSUlRBM1VISnZVek5ZVDI5a05qRm9hMEZuVVRNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYxNzQvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "ZAs8TC6UkPFjmEIAcICeKpQhIKgIzx34Mr8HuNXkwHyCSwqC8KgnMgsUAU9n-1e1WG2etJbZzNcbn5yyizKEDg"
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
      "x": "7nPET97FALVAbLLl2AdRvSl1nzsF1NICGxx-AD7q4Cs"
    },
    "nonce": "Wm0wNHl5VmJJcm1RRTA3UHJvUzNYT29kNjFoa0FnUTM",
    "url": "https://stepca:56174/acme/wire/new-account"
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
link: <https://stepca:56174/acme/wire/directory>;rel="index"
location: https://stepca:56174/acme/wire/account/1pajXcmM0Q2pGlvNuYMVDfArKKXE4R8k
replay-nonce: YzVnZUh3Q2Q2MnJsbzljQnZIV084TGpIeWJ0V0hCVks
```
```json
{
  "status": "valid",
  "orders": "https://stepca:56174/acme/wire/account/1pajXcmM0Q2pGlvNuYMVDfArKKXE4R8k/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:56174/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MTc0L2FjbWUvd2lyZS9hY2NvdW50LzFwYWpYY21NMFEycEdsdk51WU1WRGZBcktLWEU0UjhrIiwidHlwIjoiSldUIiwibm9uY2UiOiJZelZuWlVoM1EyUTJNbkpzYnpsalFuWklWMDg0VEdwSWVXSjBWMGhDVmtzIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYxNzQvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIlNtaXRoLCBBbGljZSBNIChRQSlcIixcImRvbWFpblwiOlwid2lyZS5jb21cIixcImNsaWVudC1pZFwiOlwiaW06d2lyZWFwcD1OVFkxT0RJeFpETTJOVEUyTkRJMk9HRmtPV1EwTnpWak0yVTFNR1kzT1dFLzRjN2ZlODg5MjVhZjcwNmJAd2lyZS5jb21cIixcImhhbmRsZVwiOlwiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wMy0xMFQxNDoyNTozMC44MTg0MTZaIiwibm90QWZ0ZXIiOiIyMDIzLTAzLTEwVDE1OjI1OjMwLjgxODQxNloifQ",
  "signature": "DzZKjTKRp3k360gArQWT-tmuTZ2kgzEyFY1UMNABvVh48y65YOxCAObFPrHazfVVouruc7B-dfpNkU_OsvNeDg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56174/acme/wire/account/1pajXcmM0Q2pGlvNuYMVDfArKKXE4R8k",
    "typ": "JWT",
    "nonce": "YzVnZUh3Q2Q2MnJsbzljQnZIV084TGpIeWJ0V0hCVks",
    "url": "https://stepca:56174/acme/wire/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NTY1ODIxZDM2NTE2NDI2OGFkOWQ0NzVjM2U1MGY3OWE/4c7fe88925af706b@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
      }
    ],
    "notBefore": "2023-03-10T14:25:30.818416Z",
    "notAfter": "2023-03-10T15:25:30.818416Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:56174/acme/wire/directory>;rel="index"
location: https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1
replay-nonce: MjFuSEdsb2VXMVozY3Y2djFFMW9VcjlldlN4NXdsZzY
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NTY1ODIxZDM2NTE2NDI2OGFkOWQ0NzVjM2U1MGY3OWE/4c7fe88925af706b@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56174/acme/wire/authz/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD"
  ],
  "expires": "2023-03-11T14:25:30Z",
  "notBefore": "2023-03-10T14:25:30.818416Z",
  "notAfter": "2023-03-10T15:25:30.818416Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:56174/acme/wire/authz/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MTc0L2FjbWUvd2lyZS9hY2NvdW50LzFwYWpYY21NMFEycEdsdk51WU1WRGZBcktLWEU0UjhrIiwidHlwIjoiSldUIiwibm9uY2UiOiJNakZ1U0Vkc2IyVlhNVm96WTNZMmRqRkZNVzlWY2psbGRsTjROWGRzWnpZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYxNzQvYWNtZS93aXJlL2F1dGh6L3Y0eGJESk5Oa29qbmlNOFBpS0w5QnpwR3RWWk10MWdEIn0",
  "payload": "",
  "signature": "SbAQFaeDS6oBtC7Pt_3a_V-OAPlHXdQVKXJpwtxf40uQ0f4Ci6QA9QKFonzF-9LNmJ5jCEdQyZApPIw9yHJhDw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56174/acme/wire/account/1pajXcmM0Q2pGlvNuYMVDfArKKXE4R8k",
    "typ": "JWT",
    "nonce": "MjFuSEdsb2VXMVozY3Y2djFFMW9VcjlldlN4NXdsZzY",
    "url": "https://stepca:56174/acme/wire/authz/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD"
  },
  "payload": {}
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56174/acme/wire/directory>;rel="index"
location: https://stepca:56174/acme/wire/authz/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD
replay-nonce: Y3lHbTVwT2VHY04zdTZEbXdTYWhQQVI2b0tuT0Y0Wlk
```
```json
{
  "status": "pending",
  "expires": "2023-03-11T14:25:30Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/wimvHnzRMq5quCx5oGME98k21k0HEtyI",
      "status": "pending",
      "token": "KiiBV21e0RqtqqgjVtKWSRJKGjQZJvkq"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/HhFufnzfL9abzJzpUNeblQGthEcrac9J",
      "status": "pending",
      "token": "KiiBV21e0RqtqqgjVtKWSRJKGjQZJvkq"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NTY1ODIxZDM2NTE2NDI2OGFkOWQ0NzVjM2U1MGY3OWE/4c7fe88925af706b@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:22059/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
S01MZm9FSzkyWlZxMEdOazMxMnVZQ25IQ25JbVpiUTA
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiN25QRVQ5N0ZBTFZBYkxMbDJBZFJ2U2wxbnpzRjFOSUNHeHgtQUQ3cTRDcyJ9fQ.eyJpYXQiOjE2Nzg0NTgzMzAsImV4cCI6MTY3ODU0NDczMCwibmJmIjoxNjc4NDU4MzMwLCJzdWIiOiJpbTp3aXJlYXBwPU5UWTFPREl4WkRNMk5URTJOREkyT0dGa09XUTBOelZqTTJVMU1HWTNPV0UvNGM3ZmU4ODkyNWFmNzA2YkB3aXJlLmNvbSIsImp0aSI6IjM4NWEyMDc5LTdlZDAtNDYyMS1hY2EwLWY0N2IzNTY0OGRkOCIsIm5vbmNlIjoiUzAxTVptOUZTemt5V2xaeE1FZE9hek14TW5WWlEyNUlRMjVKYlZwaVVUQSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjIwNTkvIiwiY2hhbCI6IktpaUJWMjFlMFJxdHFxZ2pWdEtXU1JKS0dqUVpKdmtxIn0.4mMGocS8eKJM1_JFp06Fyr8gq4IP4Ho18Tv9kshKH5-fK8DYIDKYLlAQ_5E2qpgn9qDO0Ima6esSx0DKXPMBDg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiN25QRVQ5N0ZBTFZBYkxMbDJBZFJ2U2wx
bnpzRjFOSUNHeHgtQUQ3cTRDcyJ9fQ.eyJpYXQiOjE2Nzg0NTgzMzAsImV4cCI6M
TY3ODU0NDczMCwibmJmIjoxNjc4NDU4MzMwLCJzdWIiOiJpbTp3aXJlYXBwPU5UW
TFPREl4WkRNMk5URTJOREkyT0dGa09XUTBOelZqTTJVMU1HWTNPV0UvNGM3ZmU4O
DkyNWFmNzA2YkB3aXJlLmNvbSIsImp0aSI6IjM4NWEyMDc5LTdlZDAtNDYyMS1hY
2EwLWY0N2IzNTY0OGRkOCIsIm5vbmNlIjoiUzAxTVptOUZTemt5V2xaeE1FZE9he
k14TW5WWlEyNUlRMjVKYlZwaVVUQSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MjIwNTkvIiwiY2hhbCI6IktpaUJWMjFlMFJxdHFxZ2pWdEtXU
1JKS0dqUVpKdmtxIn0.4mMGocS8eKJM1_JFp06Fyr8gq4IP4Ho18Tv9kshKH5-fK
8DYIDKYLlAQ_5E2qpgn9qDO0Ima6esSx0DKXPMBDg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "7nPET97FALVAbLLl2AdRvSl1nzsF1NICGxx-AD7q4Cs"
  }
}
```

```json
{
  "iat": 1678458330,
  "exp": 1678544730,
  "nbf": 1678458330,
  "sub": "im:wireapp=NTY1ODIxZDM2NTE2NDI2OGFkOWQ0NzVjM2U1MGY3OWE/4c7fe88925af706b@wire.com",
  "jti": "385a2079-7ed0-4621-aca0-f47b35648dd8",
  "nonce": "S01MZm9FSzkyWlZxMEdOazMxMnVZQ25IQ25JbVpiUTA",
  "htm": "POST",
  "htu": "http://wire.com:22059/",
  "chal": "KiiBV21e0RqtqqgjVtKWSRJKGjQZJvkq"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIN+ksseZ2FFrFvVJPPz1bjP2HhpMLKDbvwfYQ21ltWRk
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA7nPET97FALVAbLLl2AdRvSl1nzsF1NICGxx+AD7q4Cs=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:22059/clients/5512380144665194603/access-token
                          /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTjI1UVJWUTVOMFpCVEZaQllreE1iREpCWkZKMlUyd3hibnB6UmpGT1NVTkhlSGd0UVVRM2NUUkRjeUo5ZlEuZXlKcFlYUWlPakUyTnpnME5UZ3pNekFzSW1WNGNDSTZNVFkzT0RVME5EY3pNQ3dpYm1KbUlqb3hOamM0TkRVNE16TXdMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVVV1RGUFJFbDRXa1JOTWs1VVJUSk9SRWt5VDBkR2EwOVhVVEJPZWxacVRUSlZNVTFIV1ROUFYwVXZOR00zWm1VNE9Ea3lOV0ZtTnpBMllrQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqTTROV0V5TURjNUxUZGxaREF0TkRZeU1TMWhZMkV3TFdZME4ySXpOVFkwT0dSa09DSXNJbTV2Ym1ObElqb2lVekF4VFZwdE9VWlRlbXQ1VjJ4YWVFMUZaRTloZWsxNFRXNVdXbEV5TlVsUk1qVktZbFp3YVZWVVFTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakl3TlRrdklpd2lZMmhoYkNJNklrdHBhVUpXTWpGbE1GSnhkSEZ4WjJwV2RFdFhVMUpLUzBkcVVWcEtkbXR4SW4wLjRtTUdvY1M4ZUtKTTFfSkZwMDZGeXI4Z3E0SVA0SG8xOFR2OWtzaEtINS1mSzhEWUlES1lMbEFRXzVFMnFwZ245cURPMEltYTZlc1N4MERLWFBNQkRn
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InhYM1JCNDFpTU1FMEJ3dWtENWRHbkFoc1NnV09fdEVZSkRwejdWU2EtM2cifX0.eyJpYXQiOjE2Nzg0NTgzMzAsImV4cCI6MTY4NjIzNDMzMCwibmJmIjoxNjc4NDU4MzMwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjIwNTkvIiwic3ViIjoiaW06d2lyZWFwcD1OVFkxT0RJeFpETTJOVEUyTkRJMk9HRmtPV1EwTnpWak0yVTFNR1kzT1dFLzRjN2ZlODg5MjVhZjcwNmJAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjIwNTkvIiwianRpIjoiMjMxOWFiODktZTVkMS00MzAxLWJlMWMtM2FiNjFhNGIwMzI3Iiwibm9uY2UiOiJTMDFNWm05RlN6a3lXbFp4TUVkT2F6TXhNblZaUTI1SVEyNUpiVnBpVVRBIiwiY2hhbCI6IktpaUJWMjFlMFJxdHFxZ2pWdEtXU1JKS0dqUVpKdmtxIiwiY25mIjp7ImtpZCI6Im9hRU9XdjVHdTBUTFRwRDVyUmxoODc2TGFrNE0yWFFhMjYzV3FHSVBkX1kifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lOMjVRUlZRNU4wWkJURlpCWWt4TWJESkJaRkoyVTJ3eGJucHpSakZPU1VOSGVIZ3RRVVEzY1RSRGN5SjlmUS5leUpwWVhRaU9qRTJOemcwTlRnek16QXNJbVY0Y0NJNk1UWTNPRFUwTkRjek1Dd2libUptSWpveE5qYzRORFU0TXpNd0xDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BVNVVXVEZQUkVsNFdrUk5NazVVUlRKT1JFa3lUMGRHYTA5WFVUQk9lbFpxVFRKVk1VMUhXVE5QVjBVdk5HTTNabVU0T0RreU5XRm1OekEyWWtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpNNE5XRXlNRGM1TFRkbFpEQXRORFl5TVMxaFkyRXdMV1kwTjJJek5UWTBPR1JrT0NJc0ltNXZibU5sSWpvaVV6QXhUVnB0T1VaVGVtdDVWMnhhZUUxRlpFOWhlazE0VFc1V1dsRXlOVWxSTWpWS1lsWndhVlZVUVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qSXdOVGt2SWl3aVkyaGhiQ0k2SWt0cGFVSldNakZsTUZKeGRIRnhaMnBXZEV0WFUxSktTMGRxVVZwS2RtdHhJbjAuNG1NR29jUzhlS0pNMV9KRnAwNkZ5cjhncTRJUDRIbzE4VHY5a3NoS0g1LWZLOERZSURLWUxsQVFfNUUycXBnbjlxRE8wSW1hNmVzU3gwREtYUE1CRGciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5UWTFPREl4WkRNMk5URTJOREkyT0dGa09XUTBOelZqTTJVMU1HWTNPV0UvNGM3ZmU4ODkyNWFmNzA2YkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.UPaQcsPNwaxpGS_eOt-NMOjlUkNiL05Lshr5NGgXmmksQoYsgq5UX6TQG6UPHNrv78b1jfIfxcLb0U37BaRACA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InhYM1JCNDFpTU1FMEJ3dWtENWRHbkFoc1NnV09fdEVZSkRwejdWU2EtM2cifX0.eyJpYXQiOjE2Nzg0NTgzMzAsImV4cCI6MTY4NjIzNDMzMCwibmJmIjoxNjc4NDU4MzMwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjIwNTkvIiwic3ViIjoiaW06d2lyZWFwcD1OVFkxT0RJeFpETTJOVEUyTkRJMk9HRmtPV1EwTnpWak0yVTFNR1kzT1dFLzRjN2ZlODg5MjVhZjcwNmJAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjIwNTkvIiwianRpIjoiMjMxOWFiODktZTVkMS00MzAxLWJlMWMtM2FiNjFhNGIwMzI3Iiwibm9uY2UiOiJTMDFNWm05RlN6a3lXbFp4TUVkT2F6TXhNblZaUTI1SVEyNUpiVnBpVVRBIiwiY2hhbCI6IktpaUJWMjFlMFJxdHFxZ2pWdEtXU1JKS0dqUVpKdmtxIiwiY25mIjp7ImtpZCI6Im9hRU9XdjVHdTBUTFRwRDVyUmxoODc2TGFrNE0yWFFhMjYzV3FHSVBkX1kifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lOMjVRUlZRNU4wWkJURlpCWWt4TWJESkJaRkoyVTJ3eGJucHpSakZPU1VOSGVIZ3RRVVEzY1RSRGN5SjlmUS5leUpwWVhRaU9qRTJOemcwTlRnek16QXNJbVY0Y0NJNk1UWTNPRFUwTkRjek1Dd2libUptSWpveE5qYzRORFU0TXpNd0xDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BVNVVXVEZQUkVsNFdrUk5NazVVUlRKT1JFa3lUMGRHYTA5WFVUQk9lbFpxVFRKVk1VMUhXVE5QVjBVdk5HTTNabVU0T0RreU5XRm1OekEyWWtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpNNE5XRXlNRGM1TFRkbFpEQXRORFl5TVMxaFkyRXdMV1kwTjJJek5UWTBPR1JrT0NJc0ltNXZibU5sSWpvaVV6QXhUVnB0T1VaVGVtdDVWMnhhZUUxRlpFOWhlazE0VFc1V1dsRXlOVWxSTWpWS1lsWndhVlZVUVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qSXdOVGt2SWl3aVkyaGhiQ0k2SWt0cGFVSldNakZsTUZKeGRIRnhaMnBXZEV0WFUxSktTMGRxVVZwS2RtdHhJbjAuNG1NR29jUzhlS0pNMV9KRnAwNkZ5cjhncTRJUDRIbzE4VHY5a3NoS0g1LWZLOERZSURLWUxsQVFfNUUycXBnbjlxRE8wSW1hNmVzU3gwREtYUE1CRGciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5UWTFPREl4WkRNMk5URTJOREkyT0dGa09XUTBOelZqTTJVMU1HWTNPV0UvNGM3ZmU4ODkyNWFmNzA2YkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.UPaQcsPNwaxpGS_eOt-NMOjlUkNiL05Lshr5NGgXmmksQoYsgq5UX6TQG6UPHNrv78b1jfIfxcLb0U37BaRACA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InhYM1JCNDFpTU1FMEJ3dWtENWRHbkFoc1Nn
V09fdEVZSkRwejdWU2EtM2cifX0.eyJpYXQiOjE2Nzg0NTgzMzAsImV4cCI6MTY4
NjIzNDMzMCwibmJmIjoxNjc4NDU4MzMwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjIwNTkvIiwic3ViIjoiaW06d2lyZWFwcD1OVFkxT0RJeFpETTJOVEUyTkRJMk9H
RmtPV1EwTnpWak0yVTFNR1kzT1dFLzRjN2ZlODg5MjVhZjcwNmJAd2lyZS5jb20i
LCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjIwNTkvIiwianRpIjoiMjMxOWFiODkt
ZTVkMS00MzAxLWJlMWMtM2FiNjFhNGIwMzI3Iiwibm9uY2UiOiJTMDFNWm05RlN6
a3lXbFp4TUVkT2F6TXhNblZaUTI1SVEyNUpiVnBpVVRBIiwiY2hhbCI6IktpaUJW
MjFlMFJxdHFxZ2pWdEtXU1JKS0dqUVpKdmtxIiwiY25mIjp7ImtpZCI6Im9hRU9X
djVHdTBUTFRwRDVyUmxoODc2TGFrNE0yWFFhMjYzV3FHSVBkX1kifSwicHJvb2Yi
OiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFu
ZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElq
b2lOMjVRUlZRNU4wWkJURlpCWWt4TWJESkJaRkoyVTJ3eGJucHpSakZPU1VOSGVI
Z3RRVVEzY1RSRGN5SjlmUS5leUpwWVhRaU9qRTJOemcwTlRnek16QXNJbVY0Y0NJ
Nk1UWTNPRFUwTkRjek1Dd2libUptSWpveE5qYzRORFU0TXpNd0xDSnpkV0lpT2lK
cGJUcDNhWEpsWVhCd1BVNVVXVEZQUkVsNFdrUk5NazVVUlRKT1JFa3lUMGRHYTA5
WFVUQk9lbFpxVFRKVk1VMUhXVE5QVjBVdk5HTTNabVU0T0RreU5XRm1OekEyWWtC
M2FYSmxMbU52YlNJc0ltcDBhU0k2SWpNNE5XRXlNRGM1TFRkbFpEQXRORFl5TVMx
aFkyRXdMV1kwTjJJek5UWTBPR1JrT0NJc0ltNXZibU5sSWpvaVV6QXhUVnB0T1Va
VGVtdDVWMnhhZUUxRlpFOWhlazE0VFc1V1dsRXlOVWxSTWpWS1lsWndhVlZVUVNJ
c0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIw
Nk1qSXdOVGt2SWl3aVkyaGhiQ0k2SWt0cGFVSldNakZsTUZKeGRIRnhaMnBXZEV0
WFUxSktTMGRxVVZwS2RtdHhJbjAuNG1NR29jUzhlS0pNMV9KRnAwNkZ5cjhncTRJ
UDRIbzE4VHY5a3NoS0g1LWZLOERZSURLWUxsQVFfNUUycXBnbjlxRE8wSW1hNmVz
U3gwREtYUE1CRGciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5UWTFPREl4WkRN
Mk5URTJOREkyT0dGa09XUTBOelZqTTJVMU1HWTNPV0UvNGM3ZmU4ODkyNWFmNzA2
YkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50
X2lkIn0.UPaQcsPNwaxpGS_eOt-NMOjlUkNiL05Lshr5NGgXmmksQoYsgq5UX6TQ
G6UPHNrv78b1jfIfxcLb0U37BaRACA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "at+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "xX3RB41iMME0BwukD5dGnAhsSgWO_tEYJDpz7VSa-3g"
  }
}
```

```json
{
  "iat": 1678458330,
  "exp": 1686234330,
  "nbf": 1678458330,
  "iss": "http://wire.com:22059/",
  "sub": "im:wireapp=NTY1ODIxZDM2NTE2NDI2OGFkOWQ0NzVjM2U1MGY3OWE/4c7fe88925af706b@wire.com",
  "aud": "http://wire.com:22059/",
  "jti": "2319ab89-e5d1-4301-be1c-3ab61a4b0327",
  "nonce": "S01MZm9FSzkyWlZxMEdOazMxMnVZQ25IQ25JbVpiUTA",
  "chal": "KiiBV21e0RqtqqgjVtKWSRJKGjQZJvkq",
  "cnf": {
    "kid": "oaEOWv5Gu0TLTpD5rRlh876Lak4M2XQa263WqGIPd_Y"
  },
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiN25QRVQ5N0ZBTFZBYkxMbDJBZFJ2U2wxbnpzRjFOSUNHeHgtQUQ3cTRDcyJ9fQ.eyJpYXQiOjE2Nzg0NTgzMzAsImV4cCI6MTY3ODU0NDczMCwibmJmIjoxNjc4NDU4MzMwLCJzdWIiOiJpbTp3aXJlYXBwPU5UWTFPREl4WkRNMk5URTJOREkyT0dGa09XUTBOelZqTTJVMU1HWTNPV0UvNGM3ZmU4ODkyNWFmNzA2YkB3aXJlLmNvbSIsImp0aSI6IjM4NWEyMDc5LTdlZDAtNDYyMS1hY2EwLWY0N2IzNTY0OGRkOCIsIm5vbmNlIjoiUzAxTVptOUZTemt5V2xaeE1FZE9hek14TW5WWlEyNUlRMjVKYlZwaVVUQSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjIwNTkvIiwiY2hhbCI6IktpaUJWMjFlMFJxdHFxZ2pWdEtXU1JKS0dqUVpKdmtxIn0.4mMGocS8eKJM1_JFp06Fyr8gq4IP4Ho18Tv9kshKH5-fK8DYIDKYLlAQ_5E2qpgn9qDO0Ima6esSx0DKXPMBDg",
  "client_id": "im:wireapp=NTY1ODIxZDM2NTE2NDI2OGFkOWQ0NzVjM2U1MGY3OWE/4c7fe88925af706b@wire.com",
  "api_version": 3,
  "scope": "wire_client_id"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIBml61q/M1JIzgKzLkuivjclsclyoJQLMT2tn1vhh2Cn
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAxX3RB41iMME0BwukD5dGnAhsSgWO/tEYJDpz7VSa+3g=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/HhFufnzfL9abzJzpUNeblQGthEcrac9J
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MTc0L2FjbWUvd2lyZS9hY2NvdW50LzFwYWpYY21NMFEycEdsdk51WU1WRGZBcktLWEU0UjhrIiwidHlwIjoiSldUIiwibm9uY2UiOiJZM2xIYlRWd1QyVkhZMDR6ZFRaRWJYZFRZV2hRUVZJMmIwdHVUMFkwV2xrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYxNzQvYWNtZS93aXJlL2NoYWxsZW5nZS92NHhiREpOTmtvam5pTThQaUtMOUJ6cEd0VlpNdDFnRC9IaEZ1Zm56Zkw5YWJ6SnpwVU5lYmxRR3RoRWNyYWM5SiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluaFlNMUpDTkRGcFRVMUZNRUozZFd0RU5XUkhia0ZvYzFOblYwOWZkRVZaU2tSd2VqZFdVMkV0TTJjaWZYMC5leUpwWVhRaU9qRTJOemcwTlRnek16QXNJbVY0Y0NJNk1UWTROakl6TkRNek1Dd2libUptSWpveE5qYzRORFU0TXpNd0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJd05Ua3ZJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFPVkZreFQwUkplRnBFVFRKT1ZFVXlUa1JKTWs5SFJtdFBWMUV3VG5wV2FrMHlWVEZOUjFrelQxZEZMelJqTjJabE9EZzVNalZoWmpjd05tSkFkMmx5WlM1amIyMGlMQ0poZFdRaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qSXdOVGt2SWl3aWFuUnBJam9pTWpNeE9XRmlPRGt0WlRWa01TMDBNekF4TFdKbE1XTXRNMkZpTmpGaE5HSXdNekkzSWl3aWJtOXVZMlVpT2lKVE1ERk5XbTA1UmxONmEzbFhiRnA0VFVWa1QyRjZUWGhOYmxaYVVUSTFTVkV5TlVwaVZuQnBWVlJCSWl3aVkyaGhiQ0k2SWt0cGFVSldNakZsTUZKeGRIRnhaMnBXZEV0WFUxSktTMGRxVVZwS2RtdHhJaXdpWTI1bUlqcDdJbXRwWkNJNkltOWhSVTlYZGpWSGRUQlVURlJ3UkRWeVVteG9PRGMyVEdGck5FMHlXRkZoTWpZelYzRkhTVkJrWDFraWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsT01qVlJVbFpSTlU0d1drSlVSbHBDV1d0NFRXSkVTa0phUmtveVZUSjNlR0p1Y0hwU2FrWlBVMVZPU0dWSVozUlJWVkV6WTFSU1JHTjVTamxtVVM1bGVVcHdXVmhSYVU5cVJUSk9lbWN3VGxSbmVrMTZRWE5KYlZZMFkwTkpOazFVV1ROUFJGVXdUa1JqZWsxRGQybGliVXB0U1dwdmVFNXFZelJPUkZVMFRYcE5kMHhEU25wa1YwbHBUMmxLY0dKVWNETmhXRXBzV1ZoQ2QxQlZOVlZYVkVaUVVrVnNORmRyVWs1TmF6VlZVbFJLVDFKRmEzbFVNR1JIWVRBNVdGVlVRazlsYkZweFZGUktWazFWTVVoWFZFNVFWakJWZGs1SFRUTmFiVlUwVDBScmVVNVhSbTFPZWtFeVdXdENNMkZZU214TWJVNTJZbE5KYzBsdGNEQmhVMGsyU1dwTk5FNVhSWGxOUkdNMVRGUmtiRnBFUVhST1JGbDVUVk14YUZreVJYZE1WMWt3VGpKSmVrNVVXVEJQUjFKclQwTkpjMGx0TlhaaWJVNXNTV3B2YVZWNlFYaFVWbkIwVDFWYVZHVnRkRFZXTW5oaFpVVXhSbHBGT1dobGF6RTBWRmMxVjFkc1JYbE9WV3hTVFdwV1MxbHNXbmRoVmxaVlVWTkpjMGx0YURCaVUwazJTV3hDVUZVeFVXbE1RMHB2WkVoVmFVOXBTbTlrU0ZKM1QyazRkbVF5YkhsYVV6VnFZakl3TmsxcVNYZE9WR3QyU1dsM2FWa3lhR2hpUTBrMlNXdDBjR0ZWU2xkTmFrWnNUVVpLZUdSSVJuaGFNbkJYWkVWMFdGVXhTa3RUTUdSeFZWWndTMlJ0ZEhoSmJqQXVORzFOUjI5alV6aGxTMHBOTVY5S1JuQXdOa1o1Y2pobmNUUkpVRFJJYnpFNFZIWTVhM05vUzBnMUxXWkxPRVJaU1VSTFdVeHNRVkZmTlVVeWNYQm5iamx4UkU4d1NXMWhObVZ6VTNnd1JFdFlVRTFDUkdjaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFU1VVdURlBSRWw0V2tSTk1rNVVSVEpPUkVreVQwZEdhMDlYVVRCT2VsWnFUVEpWTVUxSFdUTlBWMFV2TkdNM1ptVTRPRGt5TldGbU56QTJZa0IzYVhKbExtTnZiU0lzSW1Gd2FWOTJaWEp6YVc5dUlqb3pMQ0p6WTI5d1pTSTZJbmRwY21WZlkyeHBaVzUwWDJsa0luMC5VUGFRY3NQTndheHBHU19lT3QtTk1PamxVa05pTDA1THNocjVOR2dYbW1rc1FvWXNncTVVWDZUUUc2VVBITnJ2NzhiMWpmSWZ4Y0xiMFUzN0JhUkFDQSJ9",
  "signature": "BD0vDPvaulMwUcbp99MUduvHcuJM0q6w-aJJ0s0gWSAu_G8j2zZxPQVhSDnmxG-LI5BXFnZxTOnCVv15-orNDA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56174/acme/wire/account/1pajXcmM0Q2pGlvNuYMVDfArKKXE4R8k",
    "typ": "JWT",
    "nonce": "Y3lHbTVwT2VHY04zdTZEbXdTYWhQQVI2b0tuT0Y0Wlk",
    "url": "https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/HhFufnzfL9abzJzpUNeblQGthEcrac9J"
  },
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InhYM1JCNDFpTU1FMEJ3dWtENWRHbkFoc1NnV09fdEVZSkRwejdWU2EtM2cifX0.eyJpYXQiOjE2Nzg0NTgzMzAsImV4cCI6MTY4NjIzNDMzMCwibmJmIjoxNjc4NDU4MzMwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjIwNTkvIiwic3ViIjoiaW06d2lyZWFwcD1OVFkxT0RJeFpETTJOVEUyTkRJMk9HRmtPV1EwTnpWak0yVTFNR1kzT1dFLzRjN2ZlODg5MjVhZjcwNmJAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjIwNTkvIiwianRpIjoiMjMxOWFiODktZTVkMS00MzAxLWJlMWMtM2FiNjFhNGIwMzI3Iiwibm9uY2UiOiJTMDFNWm05RlN6a3lXbFp4TUVkT2F6TXhNblZaUTI1SVEyNUpiVnBpVVRBIiwiY2hhbCI6IktpaUJWMjFlMFJxdHFxZ2pWdEtXU1JKS0dqUVpKdmtxIiwiY25mIjp7ImtpZCI6Im9hRU9XdjVHdTBUTFRwRDVyUmxoODc2TGFrNE0yWFFhMjYzV3FHSVBkX1kifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lOMjVRUlZRNU4wWkJURlpCWWt4TWJESkJaRkoyVTJ3eGJucHpSakZPU1VOSGVIZ3RRVVEzY1RSRGN5SjlmUS5leUpwWVhRaU9qRTJOemcwTlRnek16QXNJbVY0Y0NJNk1UWTNPRFUwTkRjek1Dd2libUptSWpveE5qYzRORFU0TXpNd0xDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BVNVVXVEZQUkVsNFdrUk5NazVVUlRKT1JFa3lUMGRHYTA5WFVUQk9lbFpxVFRKVk1VMUhXVE5QVjBVdk5HTTNabVU0T0RreU5XRm1OekEyWWtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpNNE5XRXlNRGM1TFRkbFpEQXRORFl5TVMxaFkyRXdMV1kwTjJJek5UWTBPR1JrT0NJc0ltNXZibU5sSWpvaVV6QXhUVnB0T1VaVGVtdDVWMnhhZUUxRlpFOWhlazE0VFc1V1dsRXlOVWxSTWpWS1lsWndhVlZVUVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qSXdOVGt2SWl3aVkyaGhiQ0k2SWt0cGFVSldNakZsTUZKeGRIRnhaMnBXZEV0WFUxSktTMGRxVVZwS2RtdHhJbjAuNG1NR29jUzhlS0pNMV9KRnAwNkZ5cjhncTRJUDRIbzE4VHY5a3NoS0g1LWZLOERZSURLWUxsQVFfNUUycXBnbjlxRE8wSW1hNmVzU3gwREtYUE1CRGciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5UWTFPREl4WkRNMk5URTJOREkyT0dGa09XUTBOelZqTTJVMU1HWTNPV0UvNGM3ZmU4ODkyNWFmNzA2YkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.UPaQcsPNwaxpGS_eOt-NMOjlUkNiL05Lshr5NGgXmmksQoYsgq5UX6TQG6UPHNrv78b1jfIfxcLb0U37BaRACA"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56174/acme/wire/directory>;rel="index"
link: <https://stepca:56174/acme/wire/authz/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD>;rel="up"
location: https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/HhFufnzfL9abzJzpUNeblQGthEcrac9J
replay-nonce: aXR5S1dSNE02QU5jVUJqbjBmckRPdTB5QzBmbUZiMk8
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/HhFufnzfL9abzJzpUNeblQGthEcrac9J",
  "status": "valid",
  "token": "KiiBV21e0RqtqqgjVtKWSRJKGjQZJvkq"
}
```
### Authenticate end user using Open ID Connect implicit flow
#### 18. Client clicks login button
```http request
GET http://wire.com/login
accept: */*
host: wire.com:22059
```
#### 19. Resource server generates Verifier & Challenge Codes

```text
code_verifier=B3_EoPiu80bdkKM-xaG7y8uulHHGUlK4j4baZTir-TE&code_challenge=Qd08I3QywmT-hymmgKvNgv11tW3eaNXBq-zVJ5IdwEQ
```
#### 20. Resource server calls authorize url
```http request
GET http://dex:18165/dex/auth?response_type=code&client_id=wireapp&state=bzr-5Kp9OmXvwb2ZFbRzUw&code_challenge=Qd08I3QywmT-hymmgKvNgv11tW3eaNXBq-zVJ5IdwEQ&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A22059%2Fcallback&scope=openid+profile&nonce=fyH6ZnfiJyPvxPoLXRjmdg
```
#### 21. Authorization server redirects to login prompt


```text
200 http://dex:18165/dex/auth/ldap/login?back=&state=huekzfdrooccycexo42p65p43
{
    "date": "Fri, 10 Mar 2023 14:25:30 GMT",
    "content-type": "text/html",
    "content-length": "1525",
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
  <form method="post" action="/dex/auth/ldap/login?back=&amp;state=huekzfdrooccycexo42p65p43">
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
POST http://dex:18165/dex/auth/ldap/login?back=&state=huekzfdrooccycexo42p65p43
content-type: application/x-www-form-urlencoded
```
```text
password=foo&login=alicesmith%40wire.com
```
#### 23. (Optional) Authorization server presents consent form to client


```text
200 http://dex:18165/dex/approval?req=huekzfdrooccycexo42p65p43&hmac=T66PQEH6RPhMF6G5gieief8UXHH6sGT5uw_Anekthck
{
    "date": "Fri, 10 Mar 2023 14:25:31 GMT",
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
        <input type="hidden" name="req" value="huekzfdrooccycexo42p65p43"/>
        <input type="hidden" name="approval" value="approve">
        <button type="submit" class="dex-btn theme-btn--success">
            <span class="dex-btn-text">Grant Access</span>
        </button>
      </form>
    </div>
    <div class="theme-form-row">
      <form method="post">
        <input type="hidden" name="req" value="huekzfdrooccycexo42p65p43"/>
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
POST http://dex:18165/dex/approval?req=huekzfdrooccycexo42p65p43&hmac=T66PQEH6RPhMF6G5gieief8UXHH6sGT5uw_Anekthck
content-type: application/x-www-form-urlencoded
```
```text
approval=approve&req=huekzfdrooccycexo42p65p43
```
#### 25. Authorization server calls callback url with authorization code
```http request
GET http://wire.com/callback
accept: */*
referer: http://dex:18165/dex/approval?req=huekzfdrooccycexo42p65p43&hmac=T66PQEH6RPhMF6G5gieief8UXHH6sGT5uw_Anekthck
host: wire.com:22059
```
#### 26. Resource server call /oauth/token to get Id token
```http request
POST http://dex:18165/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpUbFpFY3pGMFlWRnBRVFpCV0hsV2EzbEplRWRhT1ZOWQ==
```
```text
grant_type=authorization_code&code=exevplhvka4vng5vvdw7dzobj&code_verifier=B3_EoPiu80bdkKM-xaG7y8uulHHGUlK4j4baZTir-TE&redirect_uri=http%3A%2F%2Fwire.com%3A22059%2Fcallback
```
#### 27. Authorization server validates Verifier & Challenge Codes

```text
code_verifier=B3_EoPiu80bdkKM-xaG7y8uulHHGUlK4j4baZTir-TE&code_challenge=Qd08I3QywmT-hymmgKvNgv11tW3eaNXBq-zVJ5IdwEQ
```
#### 28. Authorization server returns Access & Id token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0YjhjNmE3NDdlZWZkODhhMTg3NzExNGRjNWVlZmFlNTlmY2QzOGUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTY1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVVV1RGUFJFbDRXa1JOTWs1VVJUSk9SRWt5VDBkR2EwOVhVVEJPZWxacVRUSlZNVTFIV1ROUFYwVXZOR00zWm1VNE9Ea3lOV0ZtTnpBMllrQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4NTQ0NzMxLCJpYXQiOjE2Nzg0NTgzMzEsIm5vbmNlIjoiZnlINlpuZmlKeVB2eFBvTFhSam1kZyIsImF0X2hhc2giOiI4TEI3S282VHBCNEJsXzNLZWEteTBnIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Uuc21pdGgucWFAd2lyZS5jb20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIn0.VozYP2G3cub9Ebtemr2soq-kNh7cnd1dUUioOACMwq6-xHDtukrumZU3NnBh4Q4EsSLmdu6Wvw255HUS7nXa9hvXjd51Ukqg1yXw_1q77ojHJszooE5iUqfePrKW5fOQMnjrCrp1nZgW5Lmc8h9hEXd7xcvhv5xlIyBgKMVFIwX4R_D8p61gy1rUIk1LS8-Iwv4lzyHt4bLA58TSgKVEzbesjqbNH1sbwCGRshsOmeWwe9m89iqEUU7n-hy6CSzysD6OiWCZA9UQ09WC0v8nswq7Wjff-dvbR2et-Ad372a5ht-lyow-8Wn1O0j3lgQe6Z4qjOohouWJXuDPyLRASA",
  "token_type": "bearer",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0YjhjNmE3NDdlZWZkODhhMTg3NzExNGRjNWVlZmFlNTlmY2QzOGUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTY1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVVV1RGUFJFbDRXa1JOTWs1VVJUSk9SRWt5VDBkR2EwOVhVVEJPZWxacVRUSlZNVTFIV1ROUFYwVXZOR00zWm1VNE9Ea3lOV0ZtTnpBMllrQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4NTQ0NzMxLCJpYXQiOjE2Nzg0NTgzMzEsIm5vbmNlIjoiZnlINlpuZmlKeVB2eFBvTFhSam1kZyIsImF0X2hhc2giOiJtYmV6dmtOZ1A3cFItYlNkMW50b3VBIiwiY19oYXNoIjoibVRheU1ERTFvTnpmUnN3WVJFM05wZyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.LIUquCfeokMqgoL8AC5q-5NQ4iOfahiIovvx5CkkRwiULnkXYSu5nOEG6zuYkShsW_Ml-3VyQ8AkQCihvcdKvZBiltKZWwS6erEOqtk_Nvd6aLAdcCUGB12JRcPcedoqR1XbMlHENmHCvV0_cqgtANyNOlR14ZVjO1mazWkMEI4D7TVhaR8IuWWsyHhrTatxvUvx1Dk38TJrgyh7nGrj5Tn5SinEHc1YKPZfVBaAaNpIr0RCzV4OfQJzPNNhvoDmA5zGKSgoZNyk1yWvp_vNIMd8MEUamJTyD367IqIrEin1ZCFiJXw1_e1c-5iuWiyVGe0Gl3Ch1s0T73JxtVQn8w"
}
```
#### 29. Resource server returns Id token to client

```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0YjhjNmE3NDdlZWZkODhhMTg3NzExNGRjNWVlZmFlNTlmY2QzOGUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTY1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVVV1RGUFJFbDRXa1JOTWs1VVJUSk9SRWt5VDBkR2EwOVhVVEJPZWxacVRUSlZNVTFIV1ROUFYwVXZOR00zWm1VNE9Ea3lOV0ZtTnpBMllrQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4NTQ0NzMxLCJpYXQiOjE2Nzg0NTgzMzEsIm5vbmNlIjoiZnlINlpuZmlKeVB2eFBvTFhSam1kZyIsImF0X2hhc2giOiJtYmV6dmtOZ1A3cFItYlNkMW50b3VBIiwiY19oYXNoIjoibVRheU1ERTFvTnpmUnN3WVJFM05wZyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.LIUquCfeokMqgoL8AC5q-5NQ4iOfahiIovvx5CkkRwiULnkXYSu5nOEG6zuYkShsW_Ml-3VyQ8AkQCihvcdKvZBiltKZWwS6erEOqtk_Nvd6aLAdcCUGB12JRcPcedoqR1XbMlHENmHCvV0_cqgtANyNOlR14ZVjO1mazWkMEI4D7TVhaR8IuWWsyHhrTatxvUvx1Dk38TJrgyh7nGrj5Tn5SinEHc1YKPZfVBaAaNpIr0RCzV4OfQJzPNNhvoDmA5zGKSgoZNyk1yWvp_vNIMd8MEUamJTyD367IqIrEin1ZCFiJXw1_e1c-5iuWiyVGe0Gl3Ch1s0T73JxtVQn8w
```
#### 30. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0YjhjNmE3NDdlZWZkODhhMTg3NzExNGRjNWVlZmFlNTlmY2QzOGUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTY1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVVV1RGUFJFbDRXa1JOTWs1VVJUSk9SRWt5VDBkR2EwOVhVVEJPZWxacVRUSlZNVTFIV1ROUFYwVXZOR00zWm1VNE9Ea3lOV0ZtTnpBMllrQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4NTQ0NzMxLCJpYXQiOjE2Nzg0NTgzMzEsIm5vbmNlIjoiZnlINlpuZmlKeVB2eFBvTFhSam1kZyIsImF0X2hhc2giOiJtYmV6dmtOZ1A3cFItYlNkMW50b3VBIiwiY19oYXNoIjoibVRheU1ERTFvTnpmUnN3WVJFM05wZyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.LIUquCfeokMqgoL8AC5q-5NQ4iOfahiIovvx5CkkRwiULnkXYSu5nOEG6zuYkShsW_Ml-3VyQ8AkQCihvcdKvZBiltKZWwS6erEOqtk_Nvd6aLAdcCUGB12JRcPcedoqR1XbMlHENmHCvV0_cqgtANyNOlR14ZVjO1mazWkMEI4D7TVhaR8IuWWsyHhrTatxvUvx1Dk38TJrgyh7nGrj5Tn5SinEHc1YKPZfVBaAaNpIr0RCzV4OfQJzPNNhvoDmA5zGKSgoZNyk1yWvp_vNIMd8MEUamJTyD367IqIrEin1ZCFiJXw1_e1c-5iuWiyVGe0Gl3Ch1s0T73JxtVQn8w)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0YjhjNmE3NDdlZWZkODhhMTg3NzExNGRj
NWVlZmFlNTlmY2QzOGUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTY1L2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVVV1RGUFJFbDRXa1JOTWs1VVJUSk9SR
Wt5VDBkR2EwOVhVVEJPZWxacVRUSlZNVTFIV1ROUFYwVXZOR00zWm1VNE9Ea3lOV
0ZtTnpBMllrQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjc4NTQ0NzMxLCJpYXQiOjE2Nzg0NTgzMzEsIm5vbmNlIjoiZnlINlpuZ
mlKeVB2eFBvTFhSam1kZyIsImF0X2hhc2giOiJtYmV6dmtOZ1A3cFItYlNkMW50b
3VBIiwiY19oYXNoIjoibVRheU1ERTFvTnpmUnN3WVJFM05wZyIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZ
XJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.LIUquCfeokMqgoL8AC5q-5NQ
4iOfahiIovvx5CkkRwiULnkXYSu5nOEG6zuYkShsW_Ml-3VyQ8AkQCihvcdKvZBi
ltKZWwS6erEOqtk_Nvd6aLAdcCUGB12JRcPcedoqR1XbMlHENmHCvV0_cqgtANyN
OlR14ZVjO1mazWkMEI4D7TVhaR8IuWWsyHhrTatxvUvx1Dk38TJrgyh7nGrj5Tn5
SinEHc1YKPZfVBaAaNpIr0RCzV4OfQJzPNNhvoDmA5zGKSgoZNyk1yWvp_vNIMd8
MEUamJTyD367IqIrEin1ZCFiJXw1_e1c-5iuWiyVGe0Gl3Ch1s0T73JxtVQn8w
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "24b8c6a747eefd88a1877114dc5eefae59fcd38e"
}
```

```json
{
  "iss": "http://dex:18165/dex",
  "sub": "ClBpbTp3aXJlYXBwPU5UWTFPREl4WkRNMk5URTJOREkyT0dGa09XUTBOelZqTTJVMU1HWTNPV0UvNGM3ZmU4ODkyNWFmNzA2YkB3aXJlLmNvbRIEbGRhcA",
  "aud": "wireapp",
  "exp": 1678544731,
  "iat": 1678458331,
  "nonce": "fyH6ZnfiJyPvxPoLXRjmdg",
  "at_hash": "mbezvkNgP7pR-bSd1ntouA",
  "c_hash": "mTayMDE1oNzfRswYRE3Npg",
  "name": "im:wireapp=alice.smith.qa@wire.com",
  "preferred_username": "Smith, Alice M (QA)"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1rWQQAvuiah87LOEqUGe
i9jDxL+EzkkrkH0DFnaSXkyfB97nV4GtTwmC5cPkZwAG/3OWqEzlOoxKMvjLbHQz
AaC1n6ZpOxpIlok03oIxsFsPbdmOYCYWQm04iaKLqw/xHirCYNHAsZOe8ku7pEvq
1BFEDBvGvHH9wD0FEcEznN3WRenu3GmNzSTXlQq942AjCzP6KLLGoyR31P1I70uu
NZgKXSx+b8ZzkCm6+xtFTcKqWflowyKmZ0bpCpdHeoHhw2/H613PRmbuC39PjmUA
uBkrwNDp2c57dXGfRXtqXbCb6/qGXD1Q11hnnH+7cR6FnjrlMTmjM95cSKk5puC7
dwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/wimvHnzRMq5quCx5oGME98k21k0HEtyI
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MTc0L2FjbWUvd2lyZS9hY2NvdW50LzFwYWpYY21NMFEycEdsdk51WU1WRGZBcktLWEU0UjhrIiwidHlwIjoiSldUIiwibm9uY2UiOiJhWFI1UzFkU05FMDJRVTVqVlVKcWJqQm1ja1JQZFRCNVF6Qm1iVVppTWs4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYxNzQvYWNtZS93aXJlL2NoYWxsZW5nZS92NHhiREpOTmtvam5pTThQaUtMOUJ6cEd0VlpNdDFnRC93aW12SG56Uk1xNXF1Q3g1b0dNRTk4azIxazBIRXR5SSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJakkwWWpoak5tRTNORGRsWldaa09EaGhNVGczTnpFeE5HUmpOV1ZsWm1GbE5UbG1ZMlF6T0dVaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTRNVFkxTDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZUVlZWMVJHVUZKRmJEUlhhMUpPVFdzMVZWSlVTazlTUld0NVZEQmtSMkV3T1ZoVlZFSlBaV3hhY1ZSVVNsWk5WVEZJVjFST1VGWXdWWFpPUjAweldtMVZORTlFYTNsT1YwWnRUbnBCTWxsclFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qYzROVFEwTnpNeExDSnBZWFFpT2pFMk56ZzBOVGd6TXpFc0ltNXZibU5sSWpvaVpubElObHB1Wm1sS2VWQjJlRkJ2VEZoU2FtMWtaeUlzSW1GMFgyaGhjMmdpT2lKdFltVjZkbXRPWjFBM2NGSXRZbE5rTVc1MGIzVkJJaXdpWTE5b1lYTm9Jam9pYlZSaGVVMUVSVEZ2VG5wbVVuTjNXVkpGTTA1d1p5SXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObExuTnRhWFJvTG5GaFFIZHBjbVV1WTI5dElpd2ljSEpsWm1WeWNtVmtYM1Z6WlhKdVlXMWxJam9pVTIxcGRHZ3NJRUZzYVdObElFMGdLRkZCS1NKOS5MSVVxdUNmZW9rTXFnb0w4QUM1cS01TlE0aU9mYWhpSW92dng1Q2trUndpVUxua1hZU3U1bk9FRzZ6dVlrU2hzV19NbC0zVnlROEFrUUNpaHZjZEt2WkJpbHRLWld3UzZlckVPcXRrX052ZDZhTEFkY0NVR0IxMkpSY1BjZWRvcVIxWGJNbEhFTm1IQ3ZWMF9jcWd0QU55Tk9sUjE0WlZqTzFtYXpXa01FSTREN1RWaGFSOEl1V1dzeUhoclRhdHh2VXZ4MURrMzhUSnJneWg3bkdyajVUbjVTaW5FSGMxWUtQWmZWQmFBYU5wSXIwUkN6VjRPZlFKelBOTmh2b0RtQTV6R0tTZ29aTnlrMXlXdnBfdk5JTWQ4TUVVYW1KVHlEMzY3SXFJckVpbjFaQ0ZpSlh3MV9lMWMtNWl1V2l5VkdlMEdsM0NoMXMwVDczSnh0VlFuOHciLCJrZXlhdXRoIjoiS2lpQlYyMWUwUnF0cXFnalZ0S1dTUkpLR2pRWkp2a3EublFLWVBSZzY1YTFHRXFIdU1Kd0pCTjA1cnBWS2VxblcxTnlvdkVBcVB5QSJ9",
  "signature": "0ZM1fVpwaeLGw_eorKs0L-cEC1pPKTHF6b7xZwRw632wc5he-96pteeFiRFWKYcFNfX2TV14OXnXsqS0PWSnAw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56174/acme/wire/account/1pajXcmM0Q2pGlvNuYMVDfArKKXE4R8k",
    "typ": "JWT",
    "nonce": "aXR5S1dSNE02QU5jVUJqbjBmckRPdTB5QzBmbUZiMk8",
    "url": "https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/wimvHnzRMq5quCx5oGME98k21k0HEtyI"
  },
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjI0YjhjNmE3NDdlZWZkODhhMTg3NzExNGRjNWVlZmFlNTlmY2QzOGUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTY1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTVVV1RGUFJFbDRXa1JOTWs1VVJUSk9SRWt5VDBkR2EwOVhVVEJPZWxacVRUSlZNVTFIV1ROUFYwVXZOR00zWm1VNE9Ea3lOV0ZtTnpBMllrQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjc4NTQ0NzMxLCJpYXQiOjE2Nzg0NTgzMzEsIm5vbmNlIjoiZnlINlpuZmlKeVB2eFBvTFhSam1kZyIsImF0X2hhc2giOiJtYmV6dmtOZ1A3cFItYlNkMW50b3VBIiwiY19oYXNoIjoibVRheU1ERTFvTnpmUnN3WVJFM05wZyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.LIUquCfeokMqgoL8AC5q-5NQ4iOfahiIovvx5CkkRwiULnkXYSu5nOEG6zuYkShsW_Ml-3VyQ8AkQCihvcdKvZBiltKZWwS6erEOqtk_Nvd6aLAdcCUGB12JRcPcedoqR1XbMlHENmHCvV0_cqgtANyNOlR14ZVjO1mazWkMEI4D7TVhaR8IuWWsyHhrTatxvUvx1Dk38TJrgyh7nGrj5Tn5SinEHc1YKPZfVBaAaNpIr0RCzV4OfQJzPNNhvoDmA5zGKSgoZNyk1yWvp_vNIMd8MEUamJTyD367IqIrEin1ZCFiJXw1_e1c-5iuWiyVGe0Gl3Ch1s0T73JxtVQn8w",
    "keyauth": "KiiBV21e0RqtqqgjVtKWSRJKGjQZJvkq.nQKYPRg65a1GEqHuMJwJBN05rpVKeqnW1NyovEAqPyA"
  }
}
```
#### 31. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56174/acme/wire/directory>;rel="index"
link: <https://stepca:56174/acme/wire/authz/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD>;rel="up"
location: https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/wimvHnzRMq5quCx5oGME98k21k0HEtyI
replay-nonce: Uk05dXJ6UHVobGtYR1FzWURWMWUxWEZ2RHhCSlRMUjk
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:56174/acme/wire/challenge/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD/wimvHnzRMq5quCx5oGME98k21k0HEtyI",
  "status": "valid",
  "token": "KiiBV21e0RqtqqgjVtKWSRJKGjQZJvkq"
}
```
### Client presents a CSR and gets its certificate
#### 32. verify the status of the order
```http request
POST https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MTc0L2FjbWUvd2lyZS9hY2NvdW50LzFwYWpYY21NMFEycEdsdk51WU1WRGZBcktLWEU0UjhrIiwidHlwIjoiSldUIiwibm9uY2UiOiJVazA1ZFhKNlVIVm9iR3RZUjFGeldVUldNV1V4V0VaMlJIaENTbFJNVWprIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYxNzQvYWNtZS93aXJlL29yZGVyL3l1aUVqTzVGb1lQN1oyck9UUERETkVPekx1UE10OFIxIn0",
  "payload": "",
  "signature": "5WO87kQmLRemaS7EjDV00OHxxNYTtYlphNhbi4HSHVBCrWvZ_EpDjHod00-LixpjOA8KijWOayCPZiWsaXZPCw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56174/acme/wire/account/1pajXcmM0Q2pGlvNuYMVDfArKKXE4R8k",
    "typ": "JWT",
    "nonce": "Uk05dXJ6UHVobGtYR1FzWURWMWUxWEZ2RHhCSlRMUjk",
    "url": "https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1"
  },
  "payload": {}
}
```
#### 33. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56174/acme/wire/directory>;rel="index"
location: https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1
replay-nonce: UllrTmVmMUUxUDZpSE0wb2xIVHRqbWNBQ1kzVVZUUFc
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NTY1ODIxZDM2NTE2NDI2OGFkOWQ0NzVjM2U1MGY3OWE/4c7fe88925af706b@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56174/acme/wire/authz/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD"
  ],
  "expires": "2023-03-11T14:25:30Z",
  "notBefore": "2023-03-10T14:25:30.818416Z",
  "notAfter": "2023-03-10T15:25:30.818416Z"
}
```
#### 34. create a CSR and call finalize url
```http request
POST https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MTc0L2FjbWUvd2lyZS9hY2NvdW50LzFwYWpYY21NMFEycEdsdk51WU1WRGZBcktLWEU0UjhrIiwidHlwIjoiSldUIiwibm9uY2UiOiJVbGxyVG1WbU1VVXhVRFpwU0Uwd2IyeElWSFJxYldOQlExa3pWVlpVVUZjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYxNzQvYWNtZS93aXJlL29yZGVyL3l1aUVqTzVGb1lQN1oyck9UUERETkVPekx1UE10OFIxL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCVURDQ0FRSUNBUUF3T1RFa01DSUdDMkNHU0FHRy1FSURBWUZ4REJOVGJXbDBhQ3dnUVd4cFkyVWdUU0FvVVVFcE1SRXdEd1lEVlFRS0RBaDNhWEpsTG1OdmJUQXFNQVVHQXl0bGNBTWhBTzV6eEVfZXhRQzFRR3l5NWRnSFViMHBkWjg3QmRUU0Foc2NmZ0EtNnVBcm9JR1ZNSUdTQmdrcWhraUc5dzBCQ1E0eGdZUXdnWUV3ZndZRFZSMFJCSGd3ZG9aUWFXMDZkMmx5WldGd2NEMXVkSGt4YjJScGVIcGtiVEp1ZEdVeWJtUnBNbTluWm10dmQzRXdibnAyYW0weWRURnRaM2t6YjNkbEx6UmpOMlpsT0RnNU1qVmhaamN3Tm1KQWQybHlaUzVqYjIyR0ltbHRPbmRwY21WaGNIQTlZV3hwWTJVdWMyMXBkR2d1Y1dGQWQybHlaUzVqYjIwd0JRWURLMlZ3QTBFQUxENnplSHpBOHRvNXNwY09OTVItS1FYWTA0X21RbEFCV3VqRDh3b0wzdDFQejVBYXU1MVNvMEJyelRseDl1eXZPS0ZqRjlycW5oSm9XbEdmb1dkOEFBIn0",
  "signature": "zjJTG4FauzAeblGs-rwbteT14W68Fpd0Q1dwn_1mIHe3BkzMwN63zNpJipHQsFvfOiSPCiFgQEYiYpveJXIQAA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56174/acme/wire/account/1pajXcmM0Q2pGlvNuYMVDfArKKXE4R8k",
    "typ": "JWT",
    "nonce": "UllrTmVmMUUxUDZpSE0wb2xIVHRqbWNBQ1kzVVZUUFc",
    "url": "https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1/finalize"
  },
  "payload": {
    "csr": "MIIBUDCCAQICAQAwOTEkMCIGC2CGSAGG-EIDAYFxDBNTbWl0aCwgQWxpY2UgTSAoUUEpMREwDwYDVQQKDAh3aXJlLmNvbTAqMAUGAytlcAMhAO5zxE_exQC1QGyy5dgHUb0pdZ87BdTSAhscfgA-6uAroIGVMIGSBgkqhkiG9w0BCQ4xgYQwgYEwfwYDVR0RBHgwdoZQaW06d2lyZWFwcD1udHkxb2RpeHpkbTJudGUybmRpMm9nZmtvd3Ewbnp2am0ydTFtZ3kzb3dlLzRjN2ZlODg5MjVhZjcwNmJAd2lyZS5jb22GImltOndpcmVhcHA9YWxpY2Uuc21pdGgucWFAd2lyZS5jb20wBQYDK2VwA0EALD6zeHzA8to5spcONMR-KQXY04_mQlABWujD8woL3t1Pz5Aau51So0BrzTlx9uyvOKFjF9rqnhJoWlGfoWd8AA"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBUDCCAQICAQAwOTEkMCIGC2CGSAGG+EIDAYFxDBNTbWl0aCwgQWxpY2UgTSAo
UUEpMREwDwYDVQQKDAh3aXJlLmNvbTAqMAUGAytlcAMhACzutjeSaTOZGwppuaNL
4CX6JJLiLLDY/CTYARti7GVIoIGVMIGSBgkqhkiG9w0BCQ4xgYQwgYEwfwYDVR0R
BHgwdoZQaW06d2lyZWFwcD1udHkxb2RpeHpkbTJudGUybmRpMm9nZmtvd3Ewbnp2
am0ydTFtZ3kzb3dlLzRjN2ZlODg5MjVhZjcwNmJAd2lyZS5jb22GImltOndpcmVh
cHA9YWxpY2Uuc21pdGgucWFAd2lyZS5jb20wBQYDK2VwA0EAbRCqvToqRfRAmRn1
AwOft/zH5SHq6lBOlPbj3S16k1MUsxgwK0eMLt/c5qlSMyZXlDi0DCCNiztH8dbc
bf2nBA==
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
                    2c:ee:b6:37:92:69:33:99:1b:0a:69:b9:a3:4b:e0:
                    25:fa:24:92:e2:2c:b0:d8:fc:24:d8:01:1b:62:ec:
                    65:48
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=nty1odixzdm2nte2ndi2ogfkowq0nzvjm2u1mgy3owe/4c7fe88925af706b@wire.com, URI:im:wireapp=alice.smith.qa@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        6d:10:aa:bd:3a:2a:45:f4:40:99:19:f5:03:03:9f:b7:fc:c7:
        e5:21:ea:ea:50:4e:94:f6:e3:dd:2d:7a:93:53:14:b3:18:30:
        2b:47:8c:2e:df:dc:e6:a9:52:33:26:57:94:38:b4:0c:20:8d:
        8b:3b:47:f1:d6:dc:6d:fd:a7:04

```

#### 35. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56174/acme/wire/directory>;rel="index"
location: https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1
replay-nonce: ZFptT2xiSHRUa0VYV2pJUGJrWWdjT0sxbGI0UXNNUFk
```
```json
{
  "certificate": "https://stepca:56174/acme/wire/certificate/C6BUkXe2ZQbPzbWJGQWN0lhwQlhjf31Y",
  "status": "valid",
  "finalize": "https://stepca:56174/acme/wire/order/yuiEjO5FoYP7Z2rOTPDDNEOzLuPMt8R1/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NTY1ODIxZDM2NTE2NDI2OGFkOWQ0NzVjM2U1MGY3OWE/4c7fe88925af706b@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56174/acme/wire/authz/v4xbDJNNkojniM8PiKL9BzpGtVZMt1gD"
  ],
  "expires": "2023-03-11T14:25:30Z",
  "notBefore": "2023-03-10T14:25:30.818416Z",
  "notAfter": "2023-03-10T15:25:30.818416Z"
}
```
#### 36. fetch the certificate
```http request
POST https://stepca:56174/acme/wire/certificate/C6BUkXe2ZQbPzbWJGQWN0lhwQlhjf31Y
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MTc0L2FjbWUvd2lyZS9hY2NvdW50LzFwYWpYY21NMFEycEdsdk51WU1WRGZBcktLWEU0UjhrIiwidHlwIjoiSldUIiwibm9uY2UiOiJaRnB0VDJ4aVNIUlVhMFZZVjJwSlVHSnJXV2RqVDBzeGJHSTBVWE5OVUZrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYxNzQvYWNtZS93aXJlL2NlcnRpZmljYXRlL0M2QlVrWGUyWlFiUHpiV0pHUVdOMGxod1FsaGpmMzFZIn0",
  "payload": "",
  "signature": "aQ6ZKT_10NJ7Dxd1JVPUIVb7JgzqxdppBa2jzAZU3EiDSVMIGsnOnpX9HgRLq_vjCE6alVOtisPlErhzC7bUCA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56174/acme/wire/account/1pajXcmM0Q2pGlvNuYMVDfArKKXE4R8k",
    "typ": "JWT",
    "nonce": "ZFptT2xiSHRUa0VYV2pJUGJrWWdjT0sxbGI0UXNNUFk",
    "url": "https://stepca:56174/acme/wire/certificate/C6BUkXe2ZQbPzbWJGQWN0lhwQlhjf31Y"
  },
  "payload": {}
}
```
#### 37. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:56174/acme/wire/directory>;rel="index"
replay-nonce: Zklad2N4SXBTejNMSjRUWEhRczZxYmJqeW1JRHVsaTI
```
```json
[
  "MIICQjCCAemgAwIBAgIQauc/szmug2UeuQ++F7wHkTAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzAzMTAxNDI1MzBaFw0yMzAzMTAxNTI1MzBaMDExETAPBgNVBAoTCHdpcmUuY29t\nMRwwGgYDVQQDExNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEA7nPET97F\nALVAbLLl2AdRvSl1nzsF1NICGxx+AD7q4CujggETMIIBDzAOBgNVHQ8BAf8EBAMC\nB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBSbpb/z\nlTTEQ+hf+v9Fp8rnN7e0HDAfBgNVHSMEGDAWgBQ2o1Ed9kvLld5UNeOHbpoGHrSg\nODB/BgNVHREEeDB2hiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29t\nhlBpbTp3aXJlYXBwPW50eTFvZGl4emRtMm50ZTJuZGkyb2dma293cTBuenZqbTJ1\nMW1neTNvd2UvNGM3ZmU4ODkyNWFmNzA2YkB3aXJlLmNvbTAdBgwrBgEEAYKkZMYo\nQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgAk2y+hH3IuPgvqVU\nMqk75P7bx5WK1e/+XJiTL876RckCIF3oZypaWt2jfryEiZgCIrlt+lvXKhcwohQe\nP0USu+JH",
  "MIIBuDCCAV6gAwIBAgIQWuwbXT9P2dGehuG4yN4QbzAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMzEwMTQy\nNTI2WhcNMzMwMzA3MTQyNTI2WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDzD\nGaocGuIyleFg1HUrFuvwFXx3JyZya/MbabqcnySHQYvBAykfhbxfergavo1vN3P4\nCSjOM79sKl3zRlfsO6yjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBQ2o1Ed9kvLld5UNeOHbpoGHrSgODAfBgNVHSMEGDAW\ngBSWK0xz7lHIHXSwcAekr6L7ITUhETAKBggqhkjOPQQDAgNIADBFAiBhzO6wqzqM\nXXysWIhnuxetkYZuctVdSgbOanhWdh0FjgIhAJX3+MibsoIHDoNtfE0bgkSbc3ub\nuHZg3cRULTngBaaW"
]
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICQjCCAemgAwIBAgIQauc/szmug2UeuQ++F7wHkTAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzAzMTAxNDI1MzBaFw0yMzAzMTAxNTI1MzBaMDExETAPBgNVBAoTCHdpcmUuY29t
MRwwGgYDVQQDExNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEA7nPET97F
ALVAbLLl2AdRvSl1nzsF1NICGxx+AD7q4CujggETMIIBDzAOBgNVHQ8BAf8EBAMC
B4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBSbpb/z
lTTEQ+hf+v9Fp8rnN7e0HDAfBgNVHSMEGDAWgBQ2o1Ed9kvLld5UNeOHbpoGHrSg
ODB/BgNVHREEeDB2hiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29t
hlBpbTp3aXJlYXBwPW50eTFvZGl4emRtMm50ZTJuZGkyb2dma293cTBuenZqbTJ1
MW1neTNvd2UvNGM3ZmU4ODkyNWFmNzA2YkB3aXJlLmNvbTAdBgwrBgEEAYKkZMYo
QAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgAk2y+hH3IuPgvqVU
Mqk75P7bx5WK1e/+XJiTL876RckCIF3oZypaWt2jfryEiZgCIrlt+lvXKhcwohQe
P0USu+JH
-----END CERTIFICATE-----
```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6a:e7:3f:b3:39:ae:83:65:1e:b9:0f:be:17:bc:07:91
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Mar 10 14:25:30 2023 GMT
            Not After : Mar 10 15:25:30 2023 GMT
        Subject: O = wire.com, CN = "Smith, Alice M (QA)"
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    ee:73:c4:4f:de:c5:00:b5:40:6c:b2:e5:d8:07:51:
                    bd:29:75:9f:3b:05:d4:d2:02:1b:1c:7e:00:3e:ea:
                    e0:2b
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                9B:A5:BF:F3:95:34:C4:43:E8:5F:FA:FF:45:A7:CA:E7:37:B7:B4:1C
            X509v3 Authority Key Identifier: 
                36:A3:51:1D:F6:4B:CB:95:DE:54:35:E3:87:6E:9A:06:1E:B4:A0:38
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice.smith.qa@wire.com, URI:im:wireapp=nty1odixzdm2nte2ndi2ogfkowq0nzvjm2u1mgy3owe/4c7fe88925af706b@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:02:4d:b2:fa:11:f7:22:e3:e0:be:a5:54:32:a9:
        3b:e4:fe:db:c7:95:8a:d5:ef:fe:5c:98:93:2f:ce:fa:45:c9:
        02:20:5d:e8:67:2a:5a:5a:dd:a3:7e:bc:84:89:98:02:22:b9:
        6d:fa:5b:d7:2a:17:30:a2:14:1e:3f:45:12:bb:e2:47

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQWuwbXT9P2dGehuG4yN4QbzAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMzEwMTQy
NTI2WhcNMzMwMzA3MTQyNTI2WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABDzD
GaocGuIyleFg1HUrFuvwFXx3JyZya/MbabqcnySHQYvBAykfhbxfergavo1vN3P4
CSjOM79sKl3zRlfsO6yjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQ2o1Ed9kvLld5UNeOHbpoGHrSgODAfBgNVHSMEGDAW
gBSWK0xz7lHIHXSwcAekr6L7ITUhETAKBggqhkjOPQQDAgNIADBFAiBhzO6wqzqM
XXysWIhnuxetkYZuctVdSgbOanhWdh0FjgIhAJX3+MibsoIHDoNtfE0bgkSbc3ub
uHZg3cRULTngBaaW
-----END CERTIFICATE-----
```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5a:ec:1b:5d:3f:4f:d9:d1:9e:86:e1:b8:c8:de:10:6f
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Mar 10 14:25:26 2023 GMT
            Not After : Mar  7 14:25:26 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:3c:c3:19:aa:1c:1a:e2:32:95:e1:60:d4:75:2b:
                    16:eb:f0:15:7c:77:27:26:72:6b:f3:1b:69:ba:9c:
                    9f:24:87:41:8b:c1:03:29:1f:85:bc:5f:7a:b8:1a:
                    be:8d:6f:37:73:f8:09:28:ce:33:bf:6c:2a:5d:f3:
                    46:57:ec:3b:ac
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                36:A3:51:1D:F6:4B:CB:95:DE:54:35:E3:87:6E:9A:06:1E:B4:A0:38
            X509v3 Authority Key Identifier: 
                96:2B:4C:73:EE:51:C8:1D:74:B0:70:07:A4:AF:A2:FB:21:35:21:11
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:61:cc:ee:b0:ab:3a:8c:5d:7c:ac:58:88:67:bb:
        17:ad:91:86:6e:72:d5:5d:4a:06:ce:6a:78:56:76:1d:05:8e:
        02:21:00:95:f7:f8:c8:9b:b2:82:07:0e:83:6d:7c:4d:1b:82:
        44:9b:73:7b:9b:b8:76:60:dd:c4:54:2d:39:e0:05:a6:96

```
