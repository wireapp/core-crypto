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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/90a45c284f5e25f/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/BdYBA1ntwD5VatMRYgEYwQRryZUKLwvK
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/fa3UmXfWNXh4SoDHJwSrFCBgdwFKktQK
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/xk6atIgQ09ffjXNqoPOXyceb4QR1NGt2
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:33369/acme/wire/directory
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
  "newNonce": "https://stepca:33369/acme/wire/new-nonce",
  "newAccount": "https://stepca:33369/acme/wire/new-account",
  "newOrder": "https://stepca:33369/acme/wire/new-order",
  "revokeCert": "https://stepca:33369/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:33369/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:33369/acme/wire/directory>;rel="index"
replay-nonce: QmpmdXh0R25EZ2JwSU9TUDZXMkp5VW83VTRaekhCenM
vary: Origin
```
```text
QmpmdXh0R25EZ2JwSU9TUDZXMkp5VW83VTRaekhCenM
```
#### 5. create a new account
```http request
POST https://stepca:33369/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImxBZ3VxZTBIeGNLZmFSYTZtZ3F2Q0hjR1hQNXRXYldjNU1BdXVkdVdTYUUifSwibm9uY2UiOiJRbXBtZFhoMFIyNUVaMkp3U1U5VFVEWlhNa3A1Vlc4M1ZUUmFla2hDZW5NIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMzNjkvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "KOhyAxsi34zEJNvzGQ4aVnhF88UIpaNSLO4NRp5xYO57PU8DT5qHVaOcVLTEHAJBn18YJYzFW4Cg9MWWPiy7Dg"
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
      "x": "lAguqe0HxcKfaRa6mgqvCHcGXP5tWbWc5MAuuduWSaE"
    },
    "nonce": "QmpmdXh0R25EZ2JwSU9TUDZXMkp5VW83VTRaekhCenM",
    "typ": "JWT",
    "url": "https://stepca:33369/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33369/acme/wire/directory>;rel="index"
location: https://stepca:33369/acme/wire/account/J49CmzbrdKRocGWunnZVFWV1zQvuXxAN
replay-nonce: R1l4WjV0eGxXc3dUOUdpU2NKcEdZcWF6dm5VdjA1bE4
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:33369/acme/wire/account/J49CmzbrdKRocGWunnZVFWV1zQvuXxAN/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:33369/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMzY5L2FjbWUvd2lyZS9hY2NvdW50L0o0OUNtemJyZEtSb2NHV3VublpWRldWMXpRdnVYeEFOIiwidHlwIjoiSldUIiwibm9uY2UiOiJSMWw0V2pWMGVHeFhjM2RVT1VkcFUyTktjRWRaY1dGNmRtNVZkakExYkU0IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMzNjkvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9TkUzX19zVnRUMDY2Z0d5YS1fMjh4Zy85MGE0NWMyODRmNWUyNWZAd2lyZS5jb21cIixcImhhbmRsZVwiOlwiaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tXCJ9In1dLCJub3RCZWZvcmUiOiIyMDIzLTExLTI0VDExOjQwOjIwLjU5MjU5NFoiLCJub3RBZnRlciI6IjIwMzMtMTEtMjFUMTE6NDA6MjAuNTkyNTk0WiJ9",
  "signature": "V-Hd1I4RrT6t-uDirCg2BCBbOal-gcxb8UxoNzQqkzEuF35tkrYGxGA-D8Ngmyn1KT5OnF04eMDuoNEd286XCQ"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2033-11-21T11:40:20.592594Z",
    "notBefore": "2023-11-24T11:40:20.592594Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33369/acme/wire/account/J49CmzbrdKRocGWunnZVFWV1zQvuXxAN",
    "nonce": "R1l4WjV0eGxXc3dUOUdpU2NKcEdZcWF6dm5VdjA1bE4",
    "typ": "JWT",
    "url": "https://stepca:33369/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33369/acme/wire/directory>;rel="index"
location: https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW
replay-nonce: M1J6TDJWamoxWko1cFhEVFFNUUtqb2F6aTFlWmFqTTA
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33369/acme/wire/authz/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u"
  ],
  "expires": "2023-11-25T11:40:20Z",
  "notBefore": "2023-11-24T11:40:20.592594Z",
  "notAfter": "2033-11-21T11:40:20.592594Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:33369/acme/wire/authz/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMzY5L2FjbWUvd2lyZS9hY2NvdW50L0o0OUNtemJyZEtSb2NHV3VublpWRldWMXpRdnVYeEFOIiwidHlwIjoiSldUIiwibm9uY2UiOiJNMUo2VERKV2Ftb3hXa28xY0ZoRVZGRk5VVXRxYjJGNmFURmxXbUZxVFRBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMzNjkvYWNtZS93aXJlL2F1dGh6L3Q1aWxhbHhxd3pQend5QzMxYWJxZ1hoN2JnZGhUeDB1In0",
  "payload": "",
  "signature": "c4sae59W_EzQv1xiJRGRJEQWSb8CJGHgYHbSxkt7xGKgg6qY5BZsfjdoEXaRXWvMlgieqjo-Gw0CTvewDCHbCQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33369/acme/wire/account/J49CmzbrdKRocGWunnZVFWV1zQvuXxAN",
    "nonce": "M1J6TDJWamoxWko1cFhEVFFNUUtqb2F6aTFlWmFqTTA",
    "typ": "JWT",
    "url": "https://stepca:33369/acme/wire/authz/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33369/acme/wire/directory>;rel="index"
location: https://stepca:33369/acme/wire/authz/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u
replay-nonce: enNZU2RzdEREWjR1UWxNdUZPSFA4RFIyaG1RbGdBU1I
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2023-11-25T11:40:20Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/fa3UmXfWNXh4SoDHJwSrFCBgdwFKktQK",
      "status": "pending",
      "token": "GahsvWKAafofzI2uzNGD9z78htyJBbgY",
      "target": "http://dex:15731/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/BdYBA1ntwD5VatMRYgEYwQRryZUKLwvK",
      "status": "pending",
      "token": "GahsvWKAafofzI2uzNGD9z78htyJBbgY",
      "target": "http://wire.com:21320/clients/90a45c284f5e25f/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:21320/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
S2lGQzVwMzc5R0ZxYkRNYVRUaWV4M1NvOW5vNVZTSzk
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoibEFndXFlMEh4Y0tmYVJhNm1ncXZDSGNHWFA1dFdiV2M1TUF1dWR1V1NhRSJ9fQ.eyJpYXQiOjE3MDA4MjI0MjAsImV4cCI6MTcwMDgyOTYyMCwibmJmIjoxNzAwODIyNDIwLCJzdWIiOiJpbTp3aXJlYXBwPU5FM19fc1Z0VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUuY29tIiwianRpIjoiOWI0YzcxMTAtZmRiNy00MDYyLThkYjEtMDUxM2EzNzQ3YjlkIiwibm9uY2UiOiJTMmxHUXpWd016YzVSMFp4WWtSTllWUlVhV1Y0TTFOdk9XNXZOVlpUU3prIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMTMyMC9jbGllbnRzLzkwYTQ1YzI4NGY1ZTI1Zi9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiR2Foc3ZXS0FhZm9mekkydXpOR0Q5ejc4aHR5SkJiZ1kiLCJoYW5kbGUiOiJpbTp3aXJlYXBwPSU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.wqwM9OqRar2s83hIzg0rU6A758M85LuL441WIu_v7yLcx-JznZnjIPxsfzadJqYDmBhcFlQ8x_7MB7k1Z0nECA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoibEFndXFlMEh4Y0tmYVJhNm1ncXZDSGNH
WFA1dFdiV2M1TUF1dWR1V1NhRSJ9fQ.eyJpYXQiOjE3MDA4MjI0MjAsImV4cCI6M
TcwMDgyOTYyMCwibmJmIjoxNzAwODIyNDIwLCJzdWIiOiJpbTp3aXJlYXBwPU5FM
19fc1Z0VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUuY29tIiwia
nRpIjoiOWI0YzcxMTAtZmRiNy00MDYyLThkYjEtMDUxM2EzNzQ3YjlkIiwibm9uY
2UiOiJTMmxHUXpWd016YzVSMFp4WWtSTllWUlVhV1Y0TTFOdk9XNXZOVlpUU3prI
iwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMTMyMC9jbGllb
nRzLzkwYTQ1YzI4NGY1ZTI1Zi9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiR2Foc3ZXS
0FhZm9mekkydXpOR0Q5ejc4aHR5SkJiZ1kiLCJoYW5kbGUiOiJpbTp3aXJlYXBwP
SU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.wqwM9OqRar2s
83hIzg0rU6A758M85LuL441WIu_v7yLcx-JznZnjIPxsfzadJqYDmBhcFlQ8x_7M
B7k1Z0nECA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "lAguqe0HxcKfaRa6mgqvCHcGXP5tWbWc5MAuuduWSaE"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "GahsvWKAafofzI2uzNGD9z78htyJBbgY",
  "exp": 1700829620,
  "handle": "im:wireapp=%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:21320/clients/90a45c284f5e25f/access-token",
  "iat": 1700822420,
  "jti": "9b4c7110-fdb7-4062-8db1-0513a3747b9d",
  "nbf": 1700822420,
  "nonce": "S2lGQzVwMzc5R0ZxYkRNYVRUaWV4M1NvOW5vNVZTSzk",
  "sub": "im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPipl0Pm4cetkusmBYuLn4/xxn4YcijJ29uCUSj0WVv1
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAlAguqe0HxcKfaRa6mgqvCHcGXP5tWbWc5MAuuduWSaE=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:21320/clients/90a45c284f5e25f/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pYkVGbmRYRmxNRWg0WTB0bVlWSmhObTFuY1haRFNHTkhXRkExZEZkaVYyTTFUVUYxZFdSMVYxTmhSU0o5ZlEuZXlKcFlYUWlPakUzTURBNE1qSTBNakFzSW1WNGNDSTZNVGN3TURneU9UWXlNQ3dpYm1KbUlqb3hOekF3T0RJeU5ESXdMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVGTTE5ZmMxWjBWREEyTm1kSGVXRXRYekk0ZUdjdk9UQmhORFZqTWpnMFpqVmxNalZtUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pT1dJMFl6Y3hNVEF0Wm1SaU55MDBNRFl5TFRoa1lqRXRNRFV4TTJFek56UTNZamxrSWl3aWJtOXVZMlVpT2lKVE1teEhVWHBXZDAxNll6VlNNRnA0V1d0U1RsbFdVbFZoVjFZMFRURk9kazlYTlhaT1ZscFVVM3BySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1UTXlNQzlqYkdsbGJuUnpMemt3WVRRMVl6STROR1kxWlRJMVppOWhZMk5sYzNNdGRHOXJaVzRpTENKamFHRnNJam9pUjJGb2MzWlhTMEZoWm05bWVra3lkWHBPUjBRNWVqYzRhSFI1U2tKaVoxa2lMQ0pvWVc1a2JHVWlPaUpwYlRwM2FYSmxZWEJ3UFNVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS53cXdNOU9xUmFyMnM4M2hJemcwclU2QTc1OE04NUx1TDQ0MVdJdV92N3lMY3gtSnpuWm5qSVB4c2Z6YWRKcVlEbUJoY0ZsUTh4XzdNQjdrMVowbkVDQQ
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ikptc3pTSUpSZDhIM2FtNHg1dzdJX09LVHh6d0dMbHVMenJWVzMzX1JPYkUifX0.eyJpYXQiOjE3MDA4MjI0MjAsImV4cCI6MTcwMDgyNjM4MCwibmJmIjoxNzAwODIyNDIwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjEzMjAvY2xpZW50cy85MGE0NWMyODRmNWUyNWYvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcD1ORTNfX3NWdFQwNjZnR3lhLV8yOHhnLzkwYTQ1YzI4NGY1ZTI1ZkB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMTMyMC9jbGllbnRzLzkwYTQ1YzI4NGY1ZTI1Zi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJjYTE4NjEwYy1iNzBlLTRhMDEtYTg3Yy1hYjUyN2M3Y2UxZDIiLCJub25jZSI6IlMybEdRelZ3TXpjNVIwWnhZa1JOWVZSVWFXVjRNMU52T1c1dk5WWlRTemsiLCJjaGFsIjoiR2Foc3ZXS0FhZm9mekkydXpOR0Q5ejc4aHR5SkJiZ1kiLCJjbmYiOnsia2lkIjoiUkdsanhVN2lCbEUxVWp2X000VV9VeFNPX1B3b0hDNWtCR2FIWEZzbzBtbyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWJFRm5kWEZsTUVoNFkwdG1ZVkpoTm0xbmNYWkRTR05IV0ZBMWRGZGlWMk0xVFVGMWRXUjFWMU5oUlNKOWZRLmV5SnBZWFFpT2pFM01EQTRNakkwTWpBc0ltVjRjQ0k2TVRjd01EZ3lPVFl5TUN3aWJtSm1Jam94TnpBd09ESXlOREl3TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1Rk0xOWZjMVowVkRBMk5tZEhlV0V0WHpJNGVHY3ZPVEJoTkRWak1qZzBaalZsTWpWbVFIZHBjbVV1WTI5dElpd2lhblJwSWpvaU9XSTBZemN4TVRBdFptUmlOeTAwTURZeUxUaGtZakV0TURVeE0yRXpOelEzWWpsa0lpd2libTl1WTJVaU9pSlRNbXhIVVhwV2QwMTZZelZTTUZwNFdXdFNUbGxXVWxWaFYxWTBUVEZPZGs5WE5YWk9WbHBVVTNwcklpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJbWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNVE15TUM5amJHbGxiblJ6THprd1lUUTFZekk0TkdZMVpUSTFaaTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVIyRm9jM1pYUzBGaFptOW1la2t5ZFhwT1IwUTVlamM0YUhSNVNrSmlaMWtpTENKb1lXNWtiR1VpT2lKcGJUcDNhWEpsWVhCd1BTVTBNR0ZzYVdObFgzZHBjbVZBZDJseVpTNWpiMjBpTENKMFpXRnRJam9pZDJseVpTSjkud3F3TTlPcVJhcjJzODNoSXpnMHJVNkE3NThNODVMdUw0NDFXSXVfdjd5TGN4LUp6blpuaklQeHNmemFkSnFZRG1CaGNGbFE4eF83TUI3azFaMG5FQ0EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5FM19fc1Z0VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.KrGQ9pa4BWPb0kcfxOSACGI33VeygsINMn3UUnDxCv1fjMWC5Vi_VUCE9Ntggjbc3ljkXjiIFjfpR22FROuNDw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ikptc3pTSUpSZDhIM2FtNHg1dzdJX09LVHh6d0dMbHVMenJWVzMzX1JPYkUifX0.eyJpYXQiOjE3MDA4MjI0MjAsImV4cCI6MTcwMDgyNjM4MCwibmJmIjoxNzAwODIyNDIwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjEzMjAvY2xpZW50cy85MGE0NWMyODRmNWUyNWYvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcD1ORTNfX3NWdFQwNjZnR3lhLV8yOHhnLzkwYTQ1YzI4NGY1ZTI1ZkB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMTMyMC9jbGllbnRzLzkwYTQ1YzI4NGY1ZTI1Zi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJjYTE4NjEwYy1iNzBlLTRhMDEtYTg3Yy1hYjUyN2M3Y2UxZDIiLCJub25jZSI6IlMybEdRelZ3TXpjNVIwWnhZa1JOWVZSVWFXVjRNMU52T1c1dk5WWlRTemsiLCJjaGFsIjoiR2Foc3ZXS0FhZm9mekkydXpOR0Q5ejc4aHR5SkJiZ1kiLCJjbmYiOnsia2lkIjoiUkdsanhVN2lCbEUxVWp2X000VV9VeFNPX1B3b0hDNWtCR2FIWEZzbzBtbyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWJFRm5kWEZsTUVoNFkwdG1ZVkpoTm0xbmNYWkRTR05IV0ZBMWRGZGlWMk0xVFVGMWRXUjFWMU5oUlNKOWZRLmV5SnBZWFFpT2pFM01EQTRNakkwTWpBc0ltVjRjQ0k2TVRjd01EZ3lPVFl5TUN3aWJtSm1Jam94TnpBd09ESXlOREl3TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1Rk0xOWZjMVowVkRBMk5tZEhlV0V0WHpJNGVHY3ZPVEJoTkRWak1qZzBaalZsTWpWbVFIZHBjbVV1WTI5dElpd2lhblJwSWpvaU9XSTBZemN4TVRBdFptUmlOeTAwTURZeUxUaGtZakV0TURVeE0yRXpOelEzWWpsa0lpd2libTl1WTJVaU9pSlRNbXhIVVhwV2QwMTZZelZTTUZwNFdXdFNUbGxXVWxWaFYxWTBUVEZPZGs5WE5YWk9WbHBVVTNwcklpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJbWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNVE15TUM5amJHbGxiblJ6THprd1lUUTFZekk0TkdZMVpUSTFaaTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVIyRm9jM1pYUzBGaFptOW1la2t5ZFhwT1IwUTVlamM0YUhSNVNrSmlaMWtpTENKb1lXNWtiR1VpT2lKcGJUcDNhWEpsWVhCd1BTVTBNR0ZzYVdObFgzZHBjbVZBZDJseVpTNWpiMjBpTENKMFpXRnRJam9pZDJseVpTSjkud3F3TTlPcVJhcjJzODNoSXpnMHJVNkE3NThNODVMdUw0NDFXSXVfdjd5TGN4LUp6blpuaklQeHNmemFkSnFZRG1CaGNGbFE4eF83TUI3azFaMG5FQ0EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5FM19fc1Z0VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.KrGQ9pa4BWPb0kcfxOSACGI33VeygsINMn3UUnDxCv1fjMWC5Vi_VUCE9Ntggjbc3ljkXjiIFjfpR22FROuNDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6Ikptc3pTSUpSZDhIM2FtNHg1dzdJX09LVHh6
d0dMbHVMenJWVzMzX1JPYkUifX0.eyJpYXQiOjE3MDA4MjI0MjAsImV4cCI6MTcw
MDgyNjM4MCwibmJmIjoxNzAwODIyNDIwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjEzMjAvY2xpZW50cy85MGE0NWMyODRmNWUyNWYvYWNjZXNzLXRva2VuIiwic3Vi
IjoiaW06d2lyZWFwcD1ORTNfX3NWdFQwNjZnR3lhLV8yOHhnLzkwYTQ1YzI4NGY1
ZTI1ZkB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMTMyMC9jbGll
bnRzLzkwYTQ1YzI4NGY1ZTI1Zi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJjYTE4NjEw
Yy1iNzBlLTRhMDEtYTg3Yy1hYjUyN2M3Y2UxZDIiLCJub25jZSI6IlMybEdRelZ3
TXpjNVIwWnhZa1JOWVZSVWFXVjRNMU52T1c1dk5WWlRTemsiLCJjaGFsIjoiR2Fo
c3ZXS0FhZm9mekkydXpOR0Q5ejc4aHR5SkJiZ1kiLCJjbmYiOnsia2lkIjoiUkds
anhVN2lCbEUxVWp2X000VV9VeFNPX1B3b0hDNWtCR2FIWEZzbzBtbyJ9LCJwcm9v
ZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdp
YW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0
SWpvaWJFRm5kWEZsTUVoNFkwdG1ZVkpoTm0xbmNYWkRTR05IV0ZBMWRGZGlWMk0x
VFVGMWRXUjFWMU5oUlNKOWZRLmV5SnBZWFFpT2pFM01EQTRNakkwTWpBc0ltVjRj
Q0k2TVRjd01EZ3lPVFl5TUN3aWJtSm1Jam94TnpBd09ESXlOREl3TENKemRXSWlP
aUpwYlRwM2FYSmxZWEJ3UFU1Rk0xOWZjMVowVkRBMk5tZEhlV0V0WHpJNGVHY3ZP
VEJoTkRWak1qZzBaalZsTWpWbVFIZHBjbVV1WTI5dElpd2lhblJwSWpvaU9XSTBZ
emN4TVRBdFptUmlOeTAwTURZeUxUaGtZakV0TURVeE0yRXpOelEzWWpsa0lpd2li
bTl1WTJVaU9pSlRNbXhIVVhwV2QwMTZZelZTTUZwNFdXdFNUbGxXVWxWaFYxWTBU
VEZPZGs5WE5YWk9WbHBVVTNwcklpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJ
bWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNVE15TUM5amJHbGxiblJ6THprd1lUUTFZ
ekk0TkdZMVpUSTFaaTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVIyRm9j
M1pYUzBGaFptOW1la2t5ZFhwT1IwUTVlamM0YUhSNVNrSmlaMWtpTENKb1lXNWti
R1VpT2lKcGJUcDNhWEpsWVhCd1BTVTBNR0ZzYVdObFgzZHBjbVZBZDJseVpTNWpi
MjBpTENKMFpXRnRJam9pZDJseVpTSjkud3F3TTlPcVJhcjJzODNoSXpnMHJVNkE3
NThNODVMdUw0NDFXSXVfdjd5TGN4LUp6blpuaklQeHNmemFkSnFZRG1CaGNGbFE4
eF83TUI3azFaMG5FQ0EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5FM19fc1Z0
VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUuY29tIiwiYXBpX3Zl
cnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.KrGQ9pa4BWPb0kcfx
OSACGI33VeygsINMn3UUnDxCv1fjMWC5Vi_VUCE9Ntggjbc3ljkXjiIFjfpR22FR
OuNDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "JmszSIJRd8H3am4x5w7I_OKTxzwGLluLzrVW33_RObE"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:21320/clients/90a45c284f5e25f/access-token",
  "chal": "GahsvWKAafofzI2uzNGD9z78htyJBbgY",
  "client_id": "im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com",
  "cnf": {
    "kid": "RGljxU7iBlE1Ujv_M4U_UxSO_PwoHC5kBGaHXFso0mo"
  },
  "exp": 1700826380,
  "iat": 1700822420,
  "iss": "http://wire.com:21320/clients/90a45c284f5e25f/access-token",
  "jti": "ca18610c-b70e-4a01-a87c-ab527c7ce1d2",
  "nbf": 1700822420,
  "nonce": "S2lGQzVwMzc5R0ZxYkRNYVRUaWV4M1NvOW5vNVZTSzk",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoibEFndXFlMEh4Y0tmYVJhNm1ncXZDSGNHWFA1dFdiV2M1TUF1dWR1V1NhRSJ9fQ.eyJpYXQiOjE3MDA4MjI0MjAsImV4cCI6MTcwMDgyOTYyMCwibmJmIjoxNzAwODIyNDIwLCJzdWIiOiJpbTp3aXJlYXBwPU5FM19fc1Z0VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUuY29tIiwianRpIjoiOWI0YzcxMTAtZmRiNy00MDYyLThkYjEtMDUxM2EzNzQ3YjlkIiwibm9uY2UiOiJTMmxHUXpWd016YzVSMFp4WWtSTllWUlVhV1Y0TTFOdk9XNXZOVlpUU3prIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMTMyMC9jbGllbnRzLzkwYTQ1YzI4NGY1ZTI1Zi9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiR2Foc3ZXS0FhZm9mekkydXpOR0Q5ejc4aHR5SkJiZ1kiLCJoYW5kbGUiOiJpbTp3aXJlYXBwPSU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.wqwM9OqRar2s83hIzg0rU6A758M85LuL441WIu_v7yLcx-JznZnjIPxsfzadJqYDmBhcFlQ8x_7MB7k1Z0nECA",
  "scope": "wire_client_id",
  "sub": "im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIi+GcxUli1N3rZfQoiF946jQ/9Lk+D5pMJZfFpy+quN
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJmszSIJRd8H3am4x5w7I/OKTxzwGLluLzrVW33/RObE=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/BdYBA1ntwD5VatMRYgEYwQRryZUKLwvK
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMzY5L2FjbWUvd2lyZS9hY2NvdW50L0o0OUNtemJyZEtSb2NHV3VublpWRldWMXpRdnVYeEFOIiwidHlwIjoiSldUIiwibm9uY2UiOiJlbk5aVTJSemRFUkVXalIxVVd4TmRVWlBTRkE0UkZJeWFHMVJiR2RCVTFJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMzNjkvYWNtZS93aXJlL2NoYWxsZW5nZS90NWlsYWx4cXd6UHp3eUMzMWFicWdYaDdiZ2RoVHgwdS9CZFlCQTFudHdENVZhdE1SWWdFWXdRUnJ5WlVLTHd2SyJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrcHRjM3BUU1VwU1pEaElNMkZ0TkhnMWR6ZEpYMDlMVkhoNmQwZE1iSFZNZW5KV1Z6TXpYMUpQWWtVaWZYMC5leUpwWVhRaU9qRTNNREE0TWpJME1qQXNJbVY0Y0NJNk1UY3dNRGd5TmpNNE1Dd2libUptSWpveE56QXdPREl5TkRJd0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpFek1qQXZZMnhwWlc1MGN5ODVNR0UwTldNeU9EUm1OV1V5TldZdllXTmpaWE56TFhSdmEyVnVJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFPUlROZlgzTldkRlF3TmpablIzbGhMVjh5T0hobkx6a3dZVFExWXpJNE5HWTFaVEkxWmtCM2FYSmxMbU52YlNJc0ltRjFaQ0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95TVRNeU1DOWpiR2xsYm5Sekx6a3dZVFExWXpJNE5HWTFaVEkxWmk5aFkyTmxjM010ZEc5clpXNGlMQ0pxZEdraU9pSmpZVEU0TmpFd1l5MWlOekJsTFRSaE1ERXRZVGczWXkxaFlqVXlOMk0zWTJVeFpESWlMQ0p1YjI1alpTSTZJbE15YkVkUmVsWjNUWHBqTlZJd1duaFphMUpPV1ZaU1ZXRlhWalJOTVU1MlQxYzFkazVXV2xSVGVtc2lMQ0pqYUdGc0lqb2lSMkZvYzNaWFMwRmhabTltZWtreWRYcE9SMFE1ZWpjNGFIUjVTa0ppWjFraUxDSmpibVlpT25zaWEybGtJam9pVWtkc2FuaFZOMmxDYkVVeFZXcDJYMDAwVlY5VmVGTlBYMUIzYjBoRE5XdENSMkZJV0VaemJ6QnRieUo5TENKd2NtOXZaaUk2SW1WNVNtaGlSMk5wVDJsS1JscEZVbFJSVTBselNXNVNOV05EU1RaSmJWSjNZak5CY21GdVpEQkphWGRwWVc1a2NrbHFjRGRKYlhRd1pWTkpOa2xyT1V4VlEwbHpTVzFPZVdScFNUWkphMVpyVFdwVk1VMVVhMmxNUTBvMFNXcHZhV0pGUm01a1dFWnNUVVZvTkZrd2RHMVpWa3BvVG0weGJtTllXa1JUUjA1SVYwWkJNV1JHWkdsV01rMHhWRlZHTVdSWFVqRldNVTVvVWxOS09XWlJMbVY1U25CWldGRnBUMnBGTTAxRVFUUk5ha2t3VFdwQmMwbHRWalJqUTBrMlRWUmpkMDFFWjNsUFZGbDVUVU4zYVdKdFNtMUphbTk0VG5wQmQwOUVTWGxPUkVsM1RFTktlbVJYU1dsUGFVcHdZbFJ3TTJGWVNteFpXRUozVUZVMVJrMHhPV1pqTVZvd1ZrUkJNazV0WkVobFYwVjBXSHBKTkdWSFkzWlBWRUpvVGtSV2FrMXFaekJhYWxac1RXcFdiVkZJWkhCamJWVjFXVEk1ZEVscGQybGhibEp3U1dwdmFVOVhTVEJaZW1ONFRWUkJkRnB0VW1sT2VUQXdUVVJaZVV4VWFHdFpha1YwVFVSVmVFMHlSWHBPZWxFeldXcHNhMGxwZDJsaWJUbDFXVEpWYVU5cFNsUk5iWGhJVlZod1YyUXdNVFpaZWxaVFRVWndORmRYZEZOVWJHeFhWV3hXYUZZeFdUQlVWRVpQWkdzNVdFNVlXazlXYkhCVlZUTndja2xwZDJsaFNGSjBTV3B2YVZWRk9WUldRMGx6U1cxb01HUlRTVFpKYldnd1pFaEJOa3g1T1ROaFdFcHNURzFPZG1KVWIzbE5WRTE1VFVNNWFtSkhiR3hpYmxKNlRIcHJkMWxVVVRGWmVrazBUa2RaTVZwVVNURmFhVGxvV1RKT2JHTXpUWFJrUnpseVdsYzBhVXhEU21waFIwWnpTV3B2YVZJeVJtOWpNMXBZVXpCR2FGcHRPVzFsYTJ0NVpGaHdUMUl3VVRWbGFtTTBZVWhTTlZOclNtbGFNV3RwVEVOS2IxbFhOV3RpUjFWcFQybEtjR0pVY0ROaFdFcHNXVmhDZDFCVFZUQk5SMFp6WVZkT2JGZ3paSEJqYlZaQlpESnNlVnBUTldwaU1qQnBURU5LTUZwWFJuUkphbTlwWkRKc2VWcFRTamt1ZDNGM1RUbFBjVkpoY2pKek9ETm9TWHBuTUhKVk5rRTNOVGhOT0RWTWRVdzBOREZYU1hWZmRqZDVUR040TFVwNmJscHVha2xRZUhObWVtRmtTbkZaUkcxQ2FHTkdiRkU0ZUY4M1RVSTNhekZhTUc1RlEwRWlMQ0pqYkdsbGJuUmZhV1FpT2lKcGJUcDNhWEpsWVhCd1BVNUZNMTlmYzFaMFZEQTJObWRIZVdFdFh6STRlR2N2T1RCaE5EVmpNamcwWmpWbE1qVm1RSGRwY21VdVkyOXRJaXdpWVhCcFgzWmxjbk5wYjI0aU9qVXNJbk5qYjNCbElqb2lkMmx5WlY5amJHbGxiblJmYVdRaWZRLktyR1E5cGE0QldQYjBrY2Z4T1NBQ0dJMzNWZXlnc0lOTW4zVVVuRHhDdjFmak1XQzVWaV9WVUNFOU50Z2dqYmMzbGprWGppSUZqZnBSMjJGUk91TkR3In0",
  "signature": "WKkEQ5NXRFsbmwvCcZZkM9IF7C8mLNPkX9lM0e03ORCtp6sbb4voCeTOvcQ41EJREQ09iRiJPzWw4yI9qZ1iAQ"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ikptc3pTSUpSZDhIM2FtNHg1dzdJX09LVHh6d0dMbHVMenJWVzMzX1JPYkUifX0.eyJpYXQiOjE3MDA4MjI0MjAsImV4cCI6MTcwMDgyNjM4MCwibmJmIjoxNzAwODIyNDIwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjEzMjAvY2xpZW50cy85MGE0NWMyODRmNWUyNWYvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcD1ORTNfX3NWdFQwNjZnR3lhLV8yOHhnLzkwYTQ1YzI4NGY1ZTI1ZkB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMTMyMC9jbGllbnRzLzkwYTQ1YzI4NGY1ZTI1Zi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJjYTE4NjEwYy1iNzBlLTRhMDEtYTg3Yy1hYjUyN2M3Y2UxZDIiLCJub25jZSI6IlMybEdRelZ3TXpjNVIwWnhZa1JOWVZSVWFXVjRNMU52T1c1dk5WWlRTemsiLCJjaGFsIjoiR2Foc3ZXS0FhZm9mekkydXpOR0Q5ejc4aHR5SkJiZ1kiLCJjbmYiOnsia2lkIjoiUkdsanhVN2lCbEUxVWp2X000VV9VeFNPX1B3b0hDNWtCR2FIWEZzbzBtbyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWJFRm5kWEZsTUVoNFkwdG1ZVkpoTm0xbmNYWkRTR05IV0ZBMWRGZGlWMk0xVFVGMWRXUjFWMU5oUlNKOWZRLmV5SnBZWFFpT2pFM01EQTRNakkwTWpBc0ltVjRjQ0k2TVRjd01EZ3lPVFl5TUN3aWJtSm1Jam94TnpBd09ESXlOREl3TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1Rk0xOWZjMVowVkRBMk5tZEhlV0V0WHpJNGVHY3ZPVEJoTkRWak1qZzBaalZsTWpWbVFIZHBjbVV1WTI5dElpd2lhblJwSWpvaU9XSTBZemN4TVRBdFptUmlOeTAwTURZeUxUaGtZakV0TURVeE0yRXpOelEzWWpsa0lpd2libTl1WTJVaU9pSlRNbXhIVVhwV2QwMTZZelZTTUZwNFdXdFNUbGxXVWxWaFYxWTBUVEZPZGs5WE5YWk9WbHBVVTNwcklpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJbWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNVE15TUM5amJHbGxiblJ6THprd1lUUTFZekk0TkdZMVpUSTFaaTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVIyRm9jM1pYUzBGaFptOW1la2t5ZFhwT1IwUTVlamM0YUhSNVNrSmlaMWtpTENKb1lXNWtiR1VpT2lKcGJUcDNhWEpsWVhCd1BTVTBNR0ZzYVdObFgzZHBjbVZBZDJseVpTNWpiMjBpTENKMFpXRnRJam9pZDJseVpTSjkud3F3TTlPcVJhcjJzODNoSXpnMHJVNkE3NThNODVMdUw0NDFXSXVfdjd5TGN4LUp6blpuaklQeHNmemFkSnFZRG1CaGNGbFE4eF83TUI3azFaMG5FQ0EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5FM19fc1Z0VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.KrGQ9pa4BWPb0kcfxOSACGI33VeygsINMn3UUnDxCv1fjMWC5Vi_VUCE9Ntggjbc3ljkXjiIFjfpR22FROuNDw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33369/acme/wire/account/J49CmzbrdKRocGWunnZVFWV1zQvuXxAN",
    "nonce": "enNZU2RzdEREWjR1UWxNdUZPSFA4RFIyaG1RbGdBU1I",
    "typ": "JWT",
    "url": "https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/BdYBA1ntwD5VatMRYgEYwQRryZUKLwvK"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33369/acme/wire/directory>;rel="index"
link: <https://stepca:33369/acme/wire/authz/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u>;rel="up"
location: https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/BdYBA1ntwD5VatMRYgEYwQRryZUKLwvK
replay-nonce: YWNzT2JSNzBiNnUzeHZXMVJCYkNnZnlpWGZ1WDNmTmI
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/BdYBA1ntwD5VatMRYgEYwQRryZUKLwvK",
  "status": "valid",
  "token": "GahsvWKAafofzI2uzNGD9z78htyJBbgY",
  "target": "http://wire.com:21320/clients/90a45c284f5e25f/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=PlUcr8UPV6fnN-_HvfRWNgMk7Kts38zYhxEBXTgDTf0&code_challenge=sGEpGm5j2RHigLnU3_VtUkYFda04LK3jn3akjEOpV6E
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:15731/dex/auth?response_type=code&client_id=wireapp&state=vUoyzizZNFUja_UISqG06g&code_challenge=sGEpGm5j2RHigLnU3_VtUkYFda04LK3jn3akjEOpV6E&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A21320%2Fcallback&scope=openid+profile&nonce=blVz6_TLXhgbZoX_P7_X0A
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:15731/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpiRTFqVGpCc09EWk9jRmhOU0V0SGFFbHlaM28wUkdaNQ==
```
```text
grant_type=authorization_code&code=sidgkqf4sjfnlakgptq6bryw3&code_verifier=PlUcr8UPV6fnN-_HvfRWNgMk7Kts38zYhxEBXTgDTf0&redirect_uri=http%3A%2F%2Fwire.com%3A21320%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjVlNGMwYmM4ZmZiNzMxYzU3MTk1MTY5MDExYWUwMjlkN2MwNjI3YzgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NzMxL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVTVGTTE5ZmMxWjBWREEyTm1kSGVXRXRYekk0ZUdjdk9UQmhORFZqTWpnMFpqVmxNalZtUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzAwOTEyNDIwLCJpYXQiOjE3MDA4MjYwMjAsIm5vbmNlIjoiYmxWejZfVExYaGdiWm9YX1A3X1gwQSIsImF0X2hhc2giOiJacnplTkdKUk03QlJlWk11UnQ2aWh3IiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.Wq09y1efF8BisYVgSH7C6-YuPsJygFomRQ6ulE9vHgFonJaNHaytD5VLAe5tBGcJrnyvu8ulw3PBdVGk3HqBJ_zTO9nsahyvhinJ9Rba2yFAl8R2v-HiBduul9APk6AOVnb3efiuDvosVJ2nuM2eaSRcJuXjyac-gzNMO7IgEnI57Ij564xeiGi0rHzNAdFb3wr7_SmutigEHQ9zK-wSmZaYvy4CaGNXp6UfmY_pgZ7t6WLRwnAPtALfsSE2omoIjCoBmrS6lzvoEAtlXbwzEzZwQfpbDO7qcrJJuOvMxSNZEfuz8LvzFQMTQpclXh1X7oVXz3tlxQ0o0ypVmN8cvQ",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjVlNGMwYmM4ZmZiNzMxYzU3MTk1MTY5MDExYWUwMjlkN2MwNjI3YzgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NzMxL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVTVGTTE5ZmMxWjBWREEyTm1kSGVXRXRYekk0ZUdjdk9UQmhORFZqTWpnMFpqVmxNalZtUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzAwOTEyNDIwLCJpYXQiOjE3MDA4MjYwMjAsIm5vbmNlIjoiYmxWejZfVExYaGdiWm9YX1A3X1gwQSIsImF0X2hhc2giOiJtdmVTUFpIZG55T1YxTjI4dlFCYUxBIiwiY19oYXNoIjoiczdHcUFvcG0zbklOejJ5Q2RyMVYydyIsIm5hbWUiOiJpbTp3aXJlYXBwPSU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.Qbd8g-NdLVPMNw8itfwYTubktLQ8x7ktNvaIEkdPYEIqdvN2l9oPnHp3GxEeDjCJb1IIrAItWXjcGC6Wx16AI-yKw9M1kWgVUmmsM6SbBZLMwSIZGR0kkRYTYmYAAv-gdK-WBreOPTMtd9zUTpC88H9m5A6mxrImkTXjVTt59n6TKFeENTJnfsXE_8H2BIoEDCeg4T9hiOXsRUZO2hgzWveeNMaFa2UEsYs78BK-vomQkcI06n2iked_udzBGJIrDWucNH_BOzfovPZImZk2c5_pbsfzEms-OZxQ8R6XifEmHULjyXmTq34gYD_TVNUdGxcmFo4ielbF3MwABipdkw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjVlNGMwYmM4ZmZiNzMxYzU3MTk1MTY5MDExYWUwMjlkN2MwNjI3YzgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NzMxL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVTVGTTE5ZmMxWjBWREEyTm1kSGVXRXRYekk0ZUdjdk9UQmhORFZqTWpnMFpqVmxNalZtUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzAwOTEyNDIwLCJpYXQiOjE3MDA4MjYwMjAsIm5vbmNlIjoiYmxWejZfVExYaGdiWm9YX1A3X1gwQSIsImF0X2hhc2giOiJtdmVTUFpIZG55T1YxTjI4dlFCYUxBIiwiY19oYXNoIjoiczdHcUFvcG0zbklOejJ5Q2RyMVYydyIsIm5hbWUiOiJpbTp3aXJlYXBwPSU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.Qbd8g-NdLVPMNw8itfwYTubktLQ8x7ktNvaIEkdPYEIqdvN2l9oPnHp3GxEeDjCJb1IIrAItWXjcGC6Wx16AI-yKw9M1kWgVUmmsM6SbBZLMwSIZGR0kkRYTYmYAAv-gdK-WBreOPTMtd9zUTpC88H9m5A6mxrImkTXjVTt59n6TKFeENTJnfsXE_8H2BIoEDCeg4T9hiOXsRUZO2hgzWveeNMaFa2UEsYs78BK-vomQkcI06n2iked_udzBGJIrDWucNH_BOzfovPZImZk2c5_pbsfzEms-OZxQ8R6XifEmHULjyXmTq34gYD_TVNUdGxcmFo4ielbF3MwABipdkw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjVlNGMwYmM4ZmZiNzMxYzU3MTk1MTY5MDExYWUwMjlkN2MwNjI3YzgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NzMxL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVTVGTTE5ZmMxWjBWREEyTm1kSGVXRXRYekk0ZUdjdk9UQmhORFZqTWpnMFpqVmxNalZtUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzAwOTEyNDIwLCJpYXQiOjE3MDA4MjYwMjAsIm5vbmNlIjoiYmxWejZfVExYaGdiWm9YX1A3X1gwQSIsImF0X2hhc2giOiJtdmVTUFpIZG55T1YxTjI4dlFCYUxBIiwiY19oYXNoIjoiczdHcUFvcG0zbklOejJ5Q2RyMVYydyIsIm5hbWUiOiJpbTp3aXJlYXBwPSU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.Qbd8g-NdLVPMNw8itfwYTubktLQ8x7ktNvaIEkdPYEIqdvN2l9oPnHp3GxEeDjCJb1IIrAItWXjcGC6Wx16AI-yKw9M1kWgVUmmsM6SbBZLMwSIZGR0kkRYTYmYAAv-gdK-WBreOPTMtd9zUTpC88H9m5A6mxrImkTXjVTt59n6TKFeENTJnfsXE_8H2BIoEDCeg4T9hiOXsRUZO2hgzWveeNMaFa2UEsYs78BK-vomQkcI06n2iked_udzBGJIrDWucNH_BOzfovPZImZk2c5_pbsfzEms-OZxQ8R6XifEmHULjyXmTq34gYD_TVNUdGxcmFo4ielbF3MwABipdkw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjVlNGMwYmM4ZmZiNzMxYzU3MTk1MTY5MDEx
YWUwMjlkN2MwNjI3YzgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NzMxL2RleCIsI
nN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVTVGTTE5ZmMxWjBWREEyTm1kSGVXRXRYe
kk0ZUdjdk9UQmhORFZqTWpnMFpqVmxNalZtUUhkcGNtVXVZMjl0RWdSc1pHRnciL
CJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzAwOTEyNDIwLCJpYXQiOjE3MDA4MjYwM
jAsIm5vbmNlIjoiYmxWejZfVExYaGdiWm9YX1A3X1gwQSIsImF0X2hhc2giOiJtd
mVTUFpIZG55T1YxTjI4dlFCYUxBIiwiY19oYXNoIjoiczdHcUFvcG0zbklOejJ5Q
2RyMVYydyIsIm5hbWUiOiJpbTp3aXJlYXBwPSU0MGFsaWNlX3dpcmVAd2lyZS5jb
20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.Qbd8g-NdLVPM
Nw8itfwYTubktLQ8x7ktNvaIEkdPYEIqdvN2l9oPnHp3GxEeDjCJb1IIrAItWXjc
GC6Wx16AI-yKw9M1kWgVUmmsM6SbBZLMwSIZGR0kkRYTYmYAAv-gdK-WBreOPTMt
d9zUTpC88H9m5A6mxrImkTXjVTt59n6TKFeENTJnfsXE_8H2BIoEDCeg4T9hiOXs
RUZO2hgzWveeNMaFa2UEsYs78BK-vomQkcI06n2iked_udzBGJIrDWucNH_BOzfo
vPZImZk2c5_pbsfzEms-OZxQ8R6XifEmHULjyXmTq34gYD_TVNUdGxcmFo4ielbF
3MwABipdkw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "5e4c0bc8ffb731c57195169011ae029d7c0627c8"
}
```

```json
{
  "at_hash": "mveSPZHdnyOV1N28vQBaLA",
  "aud": "wireapp",
  "c_hash": "s7GqAopm3nINz2yCdr1V2w",
  "exp": 1700912420,
  "iat": 1700826020,
  "iss": "http://dex:15731/dex",
  "name": "im:wireapp=%40alice_wire@wire.com",
  "nonce": "blVz6_TLXhgbZoX_P7_X0A",
  "preferred_username": "Alice Smith",
  "sub": "CjppbTp3aXJlYXBwPU5FM19fc1Z0VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUuY29tEgRsZGFw"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArHscsC+1Bk4lzrKInRfc
IQkbW+n3BDFqLUbGnxGA7BLikeRAUXzS4bipUf1Ll6D7DqguBOTdwNL3fEaQNjLF
n8mgETq9+4y0XrLefjgt5GdIM1/3M+rnP6QvBYAA6Q+df3flSW6kTsjzvuFi8m4i
8xBi2uCA4ye+7/Hc2feSF+x3PqXwk3ZzDFWw4Ic46sUrRaT4s25WNRUkWhugLr8B
OimEPQ9k1eEMllFS/mXAP0XMGjDCdr48elhLzlFwsDO1tjujo7jFDOikmX+9fDbu
am3nyIGVniU5tVxdcEnUjRS9W4EH3MUY9/jGchG0nGUIrTyN+3oSLwMWyRKHPxed
YwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/fa3UmXfWNXh4SoDHJwSrFCBgdwFKktQK
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMzY5L2FjbWUvd2lyZS9hY2NvdW50L0o0OUNtemJyZEtSb2NHV3VublpWRldWMXpRdnVYeEFOIiwidHlwIjoiSldUIiwibm9uY2UiOiJZV056VDJKU056QmlOblV6ZUhaWE1WSkNZa05uWm5scFdHWjFXRE5tVG1JIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMzNjkvYWNtZS93aXJlL2NoYWxsZW5nZS90NWlsYWx4cXd6UHp3eUMzMWFicWdYaDdiZ2RoVHgwdS9mYTNVbVhmV05YaDRTb0RISndTckZDQmdkd0ZLa3RRSyJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJalZsTkdNd1ltTTRabVppTnpNeFl6VTNNVGsxTVRZNU1ERXhZV1V3TWpsa04yTXdOakkzWXpnaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTFOek14TDJSbGVDSXNJbk4xWWlJNklrTnFjSEJpVkhBellWaEtiRmxZUW5kUVZUVkdUVEU1Wm1NeFdqQldSRUV5VG0xa1NHVlhSWFJZZWtrMFpVZGpkazlVUW1oT1JGWnFUV3BuTUZwcVZteE5hbFp0VVVoa2NHTnRWWFZaTWpsMFJXZFNjMXBIUm5jaUxDSmhkV1FpT2lKM2FYSmxZWEJ3SWl3aVpYaHdJam94TnpBd09URXlOREl3TENKcFlYUWlPakUzTURBNE1qWXdNakFzSW01dmJtTmxJam9pWW14V2VqWmZWRXhZYUdkaVdtOVlYMUEzWDFnd1FTSXNJbUYwWDJoaGMyZ2lPaUp0ZG1WVFVGcElaRzU1VDFZeFRqSTRkbEZDWVV4Qklpd2lZMTlvWVhOb0lqb2ljemRIY1VGdmNHMHpia2xPZWpKNVEyUnlNVll5ZHlJc0ltNWhiV1VpT2lKcGJUcDNhWEpsWVhCd1BTVTBNR0ZzYVdObFgzZHBjbVZBZDJseVpTNWpiMjBpTENKd2NtVm1aWEp5WldSZmRYTmxjbTVoYldVaU9pSkJiR2xqWlNCVGJXbDBhQ0o5LlFiZDhnLU5kTFZQTU53OGl0ZndZVHVia3RMUTh4N2t0TnZhSUVrZFBZRUlxZHZOMmw5b1BuSHAzR3hFZURqQ0piMUlJckFJdFdYamNHQzZXeDE2QUkteUt3OU0xa1dnVlVtbXNNNlNiQlpMTXdTSVpHUjBra1JZVFltWUFBdi1nZEstV0JyZU9QVE10ZDl6VVRwQzg4SDltNUE2bXhySW1rVFhqVlR0NTluNlRLRmVFTlRKbmZzWEVfOEgyQklvRURDZWc0VDloaU9Yc1JVWk8yaGd6V3ZlZU5NYUZhMlVFc1lzNzhCSy12b21Ra2NJMDZuMmlrZWRfdWR6QkdKSXJEV3VjTkhfQk96Zm92UFpJbVprMmM1X3Bic2Z6RW1zLU9aeFE4UjZYaWZFbUhVTGp5WG1UcTM0Z1lEX1RWTlVkR3hjbUZvNGllbGJGM013QUJpcGRrdyIsImtleWF1dGgiOiJHYWhzdldLQWFmb2Z6STJ1ek5HRDl6NzhodHlKQmJnWS5SR2xqeFU3aUJsRTFVanZfTTRVX1V4U09fUHdvSEM1a0JHYUhYRnNvMG1vIn0",
  "signature": "dlIouAKDetxW6I_b4uPgH_WWDI4NbK_yKA7U4yKSexV7HusfBXTLuIWZqwJxIIKX46MtdKxQ591twIvGJSHADw"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjVlNGMwYmM4ZmZiNzMxYzU3MTk1MTY5MDExYWUwMjlkN2MwNjI3YzgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NzMxL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVTVGTTE5ZmMxWjBWREEyTm1kSGVXRXRYekk0ZUdjdk9UQmhORFZqTWpnMFpqVmxNalZtUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzAwOTEyNDIwLCJpYXQiOjE3MDA4MjYwMjAsIm5vbmNlIjoiYmxWejZfVExYaGdiWm9YX1A3X1gwQSIsImF0X2hhc2giOiJtdmVTUFpIZG55T1YxTjI4dlFCYUxBIiwiY19oYXNoIjoiczdHcUFvcG0zbklOejJ5Q2RyMVYydyIsIm5hbWUiOiJpbTp3aXJlYXBwPSU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.Qbd8g-NdLVPMNw8itfwYTubktLQ8x7ktNvaIEkdPYEIqdvN2l9oPnHp3GxEeDjCJb1IIrAItWXjcGC6Wx16AI-yKw9M1kWgVUmmsM6SbBZLMwSIZGR0kkRYTYmYAAv-gdK-WBreOPTMtd9zUTpC88H9m5A6mxrImkTXjVTt59n6TKFeENTJnfsXE_8H2BIoEDCeg4T9hiOXsRUZO2hgzWveeNMaFa2UEsYs78BK-vomQkcI06n2iked_udzBGJIrDWucNH_BOzfovPZImZk2c5_pbsfzEms-OZxQ8R6XifEmHULjyXmTq34gYD_TVNUdGxcmFo4ielbF3MwABipdkw",
    "keyauth": "GahsvWKAafofzI2uzNGD9z78htyJBbgY.RGljxU7iBlE1Ujv_M4U_UxSO_PwoHC5kBGaHXFso0mo"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33369/acme/wire/account/J49CmzbrdKRocGWunnZVFWV1zQvuXxAN",
    "nonce": "YWNzT2JSNzBiNnUzeHZXMVJCYkNnZnlpWGZ1WDNmTmI",
    "typ": "JWT",
    "url": "https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/fa3UmXfWNXh4SoDHJwSrFCBgdwFKktQK"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33369/acme/wire/directory>;rel="index"
link: <https://stepca:33369/acme/wire/authz/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u>;rel="up"
location: https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/fa3UmXfWNXh4SoDHJwSrFCBgdwFKktQK
replay-nonce: b3F0NURiM1IxRVprWDlYR2ZidnYycnhqQ2RzQmF2bEI
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:33369/acme/wire/challenge/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u/fa3UmXfWNXh4SoDHJwSrFCBgdwFKktQK",
  "status": "valid",
  "token": "GahsvWKAafofzI2uzNGD9z78htyJBbgY",
  "target": "http://dex:15731/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMzY5L2FjbWUvd2lyZS9hY2NvdW50L0o0OUNtemJyZEtSb2NHV3VublpWRldWMXpRdnVYeEFOIiwidHlwIjoiSldUIiwibm9uY2UiOiJiM0YwTlVSaU0xSXhSVnByV0RsWVIyWmlkbll5Y25ocVEyUnpRbUYyYkVJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMzNjkvYWNtZS93aXJlL29yZGVyL3BqbTQ4ZDFVV3BZWmtFNldubEFTR2RuWEFSN0ExdUNXIn0",
  "payload": "",
  "signature": "VsOQa4eM6K6sNlMJ8NgJk1LHdafV-OTgY4iEKQcjBXh-V-E5xKMw2PEaQGu1Uw1_NHchk9VB0oS98rm96ChGAg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33369/acme/wire/account/J49CmzbrdKRocGWunnZVFWV1zQvuXxAN",
    "nonce": "b3F0NURiM1IxRVprWDlYR2ZidnYycnhqQ2RzQmF2bEI",
    "typ": "JWT",
    "url": "https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33369/acme/wire/directory>;rel="index"
location: https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW
replay-nonce: UnV1WG8xMlZjUHVDWElXVVZEZ3laWGFKNXFKWWFvVTc
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33369/acme/wire/authz/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u"
  ],
  "expires": "2023-11-25T11:40:20Z",
  "notBefore": "2023-11-24T11:40:20.592594Z",
  "notAfter": "2033-11-21T11:40:20.592594Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMzY5L2FjbWUvd2lyZS9hY2NvdW50L0o0OUNtemJyZEtSb2NHV3VublpWRldWMXpRdnVYeEFOIiwidHlwIjoiSldUIiwibm9uY2UiOiJVblYxV0c4eE1sWmpVSFZEV0VsWFZWWkVaM2xhV0dGS05YRktXV0Z2VlRjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMzNjkvYWNtZS93aXJlL29yZGVyL3BqbTQ4ZDFVV3BZWmtFNldubEFTR2RuWEFSN0ExdUNXL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTERDQjN3SUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBSlFJTHFudEI4WENuMmtXdXBvS3J3aDNCbHotYlZtMW5PVEFMcm5ibGttaG9Ic3dlUVlKS29aSWh2Y05BUWtPTVd3d2FqQm9CZ05WSFJFRVlUQmZoanBwYlRwM2FYSmxZWEJ3UFU1Rk0xOWZjMVowVkRBMk5tZEhlV0V0WHpJNGVHY3ZPVEJoTkRWak1qZzBaalZsTWpWbVFIZHBjbVV1WTI5dGhpRnBiVHAzYVhKbFlYQndQU1UwTUdGc2FXTmxYM2RwY21WQWQybHlaUzVqYjIwd0JRWURLMlZ3QTBFQVM0Tm5famgyU0FOVHNIUGViTzZpdjltN2hEaVRWSHRzbUREZ194LW1tM2d6d1FIVlhzTm5NS3V3ZzA2alB1S05kWkZaYjlsazd6V3dDT1BKMDlkTEN3In0",
  "signature": "csDz6xxO4ZhKpSCQLzN4s7iiUsFf18-lSmDDrC6crdLwt5lOV8v_3UWlEXDywXHdyTwWirjLP0zI6iF6cWPRDw"
}
```
```json
{
  "payload": {
    "csr": "MIIBLDCB3wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAJQILqntB8XCn2kWupoKrwh3Blz-bVm1nOTALrnblkmhoHsweQYJKoZIhvcNAQkOMWwwajBoBgNVHREEYTBfhjppbTp3aXJlYXBwPU5FM19fc1Z0VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUuY29thiFpbTp3aXJlYXBwPSU0MGFsaWNlX3dpcmVAd2lyZS5jb20wBQYDK2VwA0EAS4Nn_jh2SANTsHPebO6iv9m7hDiTVHtsmDDg_x-mm3gzwQHVXsNnMKuwg06jPuKNdZFZb9lk7zWwCOPJ09dLCw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33369/acme/wire/account/J49CmzbrdKRocGWunnZVFWV1zQvuXxAN",
    "nonce": "UnV1WG8xMlZjUHVDWElXVVZEZ3laWGFKNXFKWWFvVTc",
    "typ": "JWT",
    "url": "https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBLDCB3wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAJQILqntB8XCn2kWupoKrwh3Blz+bVm1
nOTALrnblkmhoHsweQYJKoZIhvcNAQkOMWwwajBoBgNVHREEYTBfhjppbTp3aXJl
YXBwPU5FM19fc1Z0VDA2NmdHeWEtXzI4eGcvOTBhNDVjMjg0ZjVlMjVmQHdpcmUu
Y29thiFpbTp3aXJlYXBwPSU0MGFsaWNlX3dpcmVAd2lyZS5jb20wBQYDK2VwA0EA
S4Nn/jh2SANTsHPebO6iv9m7hDiTVHtsmDDg/x+mm3gzwQHVXsNnMKuwg06jPuKN
dZFZb9lk7zWwCOPJ09dLCw==
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
                    94:08:2e:a9:ed:07:c5:c2:9f:69:16:ba:9a:0a:af:
                    08:77:06:5c:fe:6d:59:b5:9c:e4:c0:2e:b9:db:96:
                    49:a1
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com, URI:im:wireapp=%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        4b:83:67:fe:38:76:48:03:53:b0:73:de:6c:ee:a2:bf:d9:bb:
        84:38:93:54:7b:6c:98:30:e0:ff:1f:a6:9b:78:33:c1:01:d5:
        5e:c3:67:30:ab:b0:83:4e:a3:3e:e2:8d:75:91:59:6f:d9:64:
        ef:35:b0:08:e3:c9:d3:d7:4b:0b

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33369/acme/wire/directory>;rel="index"
location: https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW
replay-nonce: dnRlTUlEeU5KU1lxV29pOHpHaFdnbXVTa0NmTDJ3aFA
vary: Origin
```
```json
{
  "certificate": "https://stepca:33369/acme/wire/certificate/xk6atIgQ09ffjXNqoPOXyceb4QR1NGt2",
  "status": "valid",
  "finalize": "https://stepca:33369/acme/wire/order/pjm48d1UWpYZkE6WnlASGdnXAR7A1uCW/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33369/acme/wire/authz/t5ilalxqwzPzwyC31abqgXh7bgdhTx0u"
  ],
  "expires": "2023-11-25T11:40:20Z",
  "notBefore": "2023-11-24T11:40:20.592594Z",
  "notAfter": "2033-11-21T11:40:20.592594Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:33369/acme/wire/certificate/xk6atIgQ09ffjXNqoPOXyceb4QR1NGt2
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMzY5L2FjbWUvd2lyZS9hY2NvdW50L0o0OUNtemJyZEtSb2NHV3VublpWRldWMXpRdnVYeEFOIiwidHlwIjoiSldUIiwibm9uY2UiOiJkblJsVFVsRWVVNUtVMWx4VjI5cE9IcEhhRmRuYlhWVGEwTm1UREozYUZBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMzNjkvYWNtZS93aXJlL2NlcnRpZmljYXRlL3hrNmF0SWdRMDlmZmpYTnFvUE9YeWNlYjRRUjFOR3QyIn0",
  "payload": "",
  "signature": "btb_R1qs3RktE4qaESwfaNU7RNPjEHht7A_howg1UBcuRwhiGUl69Y5yrTMTCR2YIekNR4YdfuoiMekXf4EMAw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33369/acme/wire/account/J49CmzbrdKRocGWunnZVFWV1zQvuXxAN",
    "nonce": "dnRlTUlEeU5KU1lxV29pOHpHaFdnbXVTa0NmTDJ3aFA",
    "typ": "JWT",
    "url": "https://stepca:33369/acme/wire/certificate/xk6atIgQ09ffjXNqoPOXyceb4QR1NGt2"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:33369/acme/wire/directory>;rel="index"
replay-nonce: clJQdW5pa0diWXJvcXo5MDJXeEFReFZWZVY4SnVjRjg
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAb+gAwIBAgIRAKsx0PLu8CWQYe80oI/3RbAwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMxMTI0MTE0MDIwWhcNMzMxMTIxMTE0MDIwWjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCUCC6p7QfFwp9pFrqa\nCq8IdwZc/m1ZtZzkwC6525ZJoaOB8TCB7jAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFAJt9Z9p0cWhiCy3A2kAgcpWjLTvMB8G\nA1UdIwQYMBaAFKP/WkfzxudsL1iAv1aidI4XbbqLMGgGA1UdEQRhMF+GIWltOndp\ncmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY6aW06d2lyZWFwcD1ORTNfX3NW\ndFQwNjZnR3lhLV8yOHhnLzkwYTQ1YzI4NGY1ZTI1ZkB3aXJlLmNvbTAdBgwrBgEE\nAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSQAwRgIhALat5/K5\ngR1cjDzrqdZaiXrExdDzZOF+kYcUNAGLSF9JAiEAsYptKJuQeoVKQZYZOtn+44Ox\nnsfcUAlY+rJo53nRpGA=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV6gAwIBAgIQG6HB0uQrEnYf241WRjfmzDAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMTI0MTE0\nMDE4WhcNMzMxMTIxMTE0MDE4WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHC7\nljMF0ix77XsaPZxVJnaDjVA4rlCCwzUhPmTl13y9h9y3CMCPD/dPoN3AgIuLDxn1\npM6QAajFa/ECaoo4xb+jZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBSj/1pH88bnbC9YgL9WonSOF226izAfBgNVHSMEGDAW\ngBSM5TpWIdBtQ48aRzlXb9LqUUsjAjAKBggqhkjOPQQDAgNJADBGAiEAifecvDNn\n9U2TG7mFNvlgnaF/PO+EiCwxiq/NKM9DpscCIQCvKwY+XMijHDOF4LuRC6++wB2S\nJTUEZ1lxQQZWGwWTPg==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICGjCCAb+gAwIBAgIRAKsx0PLu8CWQYe80oI/3RbAwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMxMTI0MTE0MDIwWhcNMzMxMTIxMTE0MDIwWjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCUCC6p7QfFwp9pFrqa
Cq8IdwZc/m1ZtZzkwC6525ZJoaOB8TCB7jAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFAJt9Z9p0cWhiCy3A2kAgcpWjLTvMB8G
A1UdIwQYMBaAFKP/WkfzxudsL1iAv1aidI4XbbqLMGgGA1UdEQRhMF+GIWltOndp
cmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY6aW06d2lyZWFwcD1ORTNfX3NW
dFQwNjZnR3lhLV8yOHhnLzkwYTQ1YzI4NGY1ZTI1ZkB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSQAwRgIhALat5/K5
gR1cjDzrqdZaiXrExdDzZOF+kYcUNAGLSF9JAiEAsYptKJuQeoVKQZYZOtn+44Ox
nsfcUAlY+rJo53nRpGA=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ab:31:d0:f2:ee:f0:25:90:61:ef:34:a0:8f:f7:45:b0
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Nov 24 11:40:20 2023 GMT
            Not After : Nov 21 11:40:20 2033 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    94:08:2e:a9:ed:07:c5:c2:9f:69:16:ba:9a:0a:af:
                    08:77:06:5c:fe:6d:59:b5:9c:e4:c0:2e:b9:db:96:
                    49:a1
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                02:6D:F5:9F:69:D1:C5:A1:88:2C:B7:03:69:00:81:CA:56:8C:B4:EF
            X509v3 Authority Key Identifier: 
                A3:FF:5A:47:F3:C6:E7:6C:2F:58:80:BF:56:A2:74:8E:17:6D:BA:8B
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=%40alice_wire@wire.com, URI:im:wireapp=NE3__sVtT066gGya-_28xg/90a45c284f5e25f@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:b6:ad:e7:f2:b9:81:1d:5c:8c:3c:eb:a9:d6:
        5a:89:7a:c4:c5:d0:f3:64:e1:7e:91:87:14:34:01:8b:48:5f:
        49:02:21:00:b1:8a:6d:28:9b:90:7a:85:4a:41:96:19:3a:d9:
        fe:e3:83:b1:9e:c7:dc:50:09:58:fa:b2:68:e7:79:d1:a4:60

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV6gAwIBAgIQG6HB0uQrEnYf241WRjfmzDAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMTI0MTE0
MDE4WhcNMzMxMTIxMTE0MDE4WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABHC7
ljMF0ix77XsaPZxVJnaDjVA4rlCCwzUhPmTl13y9h9y3CMCPD/dPoN3AgIuLDxn1
pM6QAajFa/ECaoo4xb+jZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBSj/1pH88bnbC9YgL9WonSOF226izAfBgNVHSMEGDAW
gBSM5TpWIdBtQ48aRzlXb9LqUUsjAjAKBggqhkjOPQQDAgNJADBGAiEAifecvDNn
9U2TG7mFNvlgnaF/PO+EiCwxiq/NKM9DpscCIQCvKwY+XMijHDOF4LuRC6++wB2S
JTUEZ1lxQQZWGwWTPg==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1b:a1:c1:d2:e4:2b:12:76:1f:db:8d:56:46:37:e6:cc
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Nov 24 11:40:18 2023 GMT
            Not After : Nov 21 11:40:18 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:70:bb:96:33:05:d2:2c:7b:ed:7b:1a:3d:9c:55:
                    26:76:83:8d:50:38:ae:50:82:c3:35:21:3e:64:e5:
                    d7:7c:bd:87:dc:b7:08:c0:8f:0f:f7:4f:a0:dd:c0:
                    80:8b:8b:0f:19:f5:a4:ce:90:01:a8:c5:6b:f1:02:
                    6a:8a:38:c5:bf
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                A3:FF:5A:47:F3:C6:E7:6C:2F:58:80:BF:56:A2:74:8E:17:6D:BA:8B
            X509v3 Authority Key Identifier: 
                8C:E5:3A:56:21:D0:6D:43:8F:1A:47:39:57:6F:D2:EA:51:4B:23:02
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:89:f7:9c:bc:33:67:f5:4d:93:1b:b9:85:36:
        f9:60:9d:a1:7f:3c:ef:84:88:2c:31:8a:af:cd:28:cf:43:a6:
        c7:02:21:00:af:2b:06:3e:5c:c8:a3:1c:33:85:e0:bb:91:0b:
        af:be:c0:1d:92:25:35:04:67:59:71:41:06:56:1b:05:93:3e

```
