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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/a338e9ea9e87fec/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/BDm3kVbFrMDWRhq5WTv3RQ7e6ttNK79d
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/pFY3f2cRMc1iDw0iXT4JGKDqPnqhsICQ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/jjGGoNn2k2gMMmXaePtUoncjnNFkHVBV
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32795/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32795/acme/wire/new-nonce",
  "newAccount": "https://stepca:32795/acme/wire/new-account",
  "newOrder": "https://stepca:32795/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32795/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32795/acme/wire/directory>;rel="index"
replay-nonce: Q0hpNkJ4dWhSeDN2VExNRzMyazU1QUx4N3F5Ymxzb28
```
```text
Q0hpNkJ4dWhSeDN2VExNRzMyazU1QUx4N3F5Ymxzb28
```
#### 5. create a new account
```http request
POST https://stepca:32795/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkJmNFdiNzVrWkZqTTZtZVkxQzV4aWp2c3ZCdjFjX3FKWDA1SjVPM1BfQ0kifSwibm9uY2UiOiJRMGhwTmtKNGRXaFNlRE4yVkV4TlJ6TXlhelUxUVV4NE4zRjVZbXh6YjI4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "fNMe01Jeh16wEVuokWVV40ywOb7TbSjv6UmKyordEWXk5M-xmJ5DTRpuzrUMBZM_AeKemD0Dz7niaAP2KajuDg"
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
      "x": "Bf4Wb75kZFjM6meY1C5xijvsvBv1c_qJX05J5O3P_CI"
    },
    "nonce": "Q0hpNkJ4dWhSeDN2VExNRzMyazU1QUx4N3F5Ymxzb28",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
location: https://stepca:32795/acme/wire/account/kOiCdXwzmvQeKrPcdcGqopCNsSy6ghr4
replay-nonce: TUcwajZSZjB2eDNHaFp4VW14MHdtTzQ4NDhNRm5EeXc
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32795/acme/wire/account/kOiCdXwzmvQeKrPcdcGqopCNsSy6ghr4/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32795/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L2tPaUNkWHd6bXZRZUtyUGNkY0dxb3BDTnNTeTZnaHI0IiwidHlwIjoiSldUIiwibm9uY2UiOiJUVWN3YWpaU1pqQjJlRE5IYUZwNFZXMTRNSGR0VHpRNE5EaE5SbTVFZVhjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9VDRDb3k0dmRSemlhbndmT2dYcG42QS9hMzM4ZTllYTllODdmZWNAd2lyZS5jb21cIixcImhhbmRsZVwiOlwiaW06d2lyZWFwcD1hbGljZV93aXJlXCJ9In1dLCJub3RCZWZvcmUiOiIyMDIzLTA3LTMxVDE0OjAyOjA4LjI1NjQ4N1oiLCJub3RBZnRlciI6IjIwMzMtMDctMjhUMTQ6MDI6MDguMjU2NDg3WiJ9",
  "signature": "tJf0d7QzcNZaI19b7RbRXCuqhW_yYi0H8TeFvl7hYwOplAK0pVb0fBxDEFJjT4zYnWQp1xSnCAVSxRq44UKuCw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2033-07-28T14:02:08.256487Z",
    "notBefore": "2023-07-31T14:02:08.256487Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/kOiCdXwzmvQeKrPcdcGqopCNsSy6ghr4",
    "nonce": "TUcwajZSZjB2eDNHaFp4VW14MHdtTzQ4NDhNRm5EeXc",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
location: https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY
replay-nonce: YTM1a243aTBaYU5nMklKNTFDOElaTFZEV1lyRlZsbFo
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32795/acme/wire/authz/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx"
  ],
  "expires": "2023-08-01T14:02:08Z",
  "notBefore": "2023-07-31T14:02:08.256487Z",
  "notAfter": "2033-07-28T14:02:08.256487Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32795/acme/wire/authz/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L2tPaUNkWHd6bXZRZUtyUGNkY0dxb3BDTnNTeTZnaHI0IiwidHlwIjoiSldUIiwibm9uY2UiOiJZVE0xYTI0M2FUQmFZVTVuTWtsS05URkRPRWxhVEZaRVYxbHlSbFpzYkZvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL2F1dGh6L0JIOWxnbkd4S2t3RDJKeVREaXpwVUtFZzZqWmJzd2Z4In0",
  "payload": "",
  "signature": "7uadazRTb33r4tPHLuMEHEsuGD3xfOC8qcLkml7-Cf6WT9A0VUvWUWmZOtjlc8zd7HeXRas-X0wt0bO32LJQAw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/kOiCdXwzmvQeKrPcdcGqopCNsSy6ghr4",
    "nonce": "YTM1a243aTBaYU5nMklKNTFDOElaTFZEV1lyRlZsbFo",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/authz/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
location: https://stepca:32795/acme/wire/authz/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx
replay-nonce: RVNhWEs4aE5VOEVkNWlxQm9Tbmd4WTh2dnZFcDNqVlc
```
```json
{
  "status": "pending",
  "expires": "2023-08-01T14:02:08Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/pFY3f2cRMc1iDw0iXT4JGKDqPnqhsICQ",
      "status": "pending",
      "token": "AJ7meGAWJmfjXbfzDWddvufdjdIASoXV",
      "target": "http://dex:24582/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/BDm3kVbFrMDWRhq5WTv3RQ7e6ttNK79d",
      "status": "pending",
      "token": "AJ7meGAWJmfjXbfzDWddvufdjdIASoXV",
      "target": "http://wire.com:23247/clients/a338e9ea9e87fec/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:23247/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
NlN3RHRrcGdHZ1FDODg5c0w3dmRINHc0SFZ6aloyUXg
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiQmY0V2I3NWtaRmpNNm1lWTFDNXhpanZzdkJ2MWNfcUpYMDVKNU8zUF9DSSJ9fQ.eyJpYXQiOjE2OTA4MTIxMjgsImV4cCI6MTY5MDgxNTcyOCwibmJmIjoxNjkwODEyMTIzLCJzdWIiOiJpbTp3aXJlYXBwPVQ0Q295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVjQHdpcmUuY29tIiwianRpIjoiYWJmMzA1ZmUtZjQwMy00OTRlLTgzOTYtMjBjMDIyZDgyNzEyIiwibm9uY2UiOiJObE4zUkhScmNHZEhaMUZET0RnNWMwdzNkbVJJTkhjMFNGWjZhbG95VVhnIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzI0Ny9jbGllbnRzL2EzMzhlOWVhOWU4N2ZlYy9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiQUo3bWVHQVdKbWZqWGJmekRXZGR2dWZkamRJQVNvWFYifQ.GuK8xMj93aF7MffKRdVMEWZMps_n_L-fKU9HLDyonRDKv2KXVoNFVp8Pl0_PZpD2uij3rIIdS_zPwQe4uJAfBg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiQmY0V2I3NWtaRmpNNm1lWTFDNXhpanZz
dkJ2MWNfcUpYMDVKNU8zUF9DSSJ9fQ.eyJpYXQiOjE2OTA4MTIxMjgsImV4cCI6M
TY5MDgxNTcyOCwibmJmIjoxNjkwODEyMTIzLCJzdWIiOiJpbTp3aXJlYXBwPVQ0Q
295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVjQHdpcmUuY29tIiwia
nRpIjoiYWJmMzA1ZmUtZjQwMy00OTRlLTgzOTYtMjBjMDIyZDgyNzEyIiwibm9uY
2UiOiJObE4zUkhScmNHZEhaMUZET0RnNWMwdzNkbVJJTkhjMFNGWjZhbG95VVhnI
iwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzI0Ny9jbGllb
nRzL2EzMzhlOWVhOWU4N2ZlYy9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiQUo3bWVHQ
VdKbWZqWGJmekRXZGR2dWZkamRJQVNvWFYifQ.GuK8xMj93aF7MffKRdVMEWZMps
_n_L-fKU9HLDyonRDKv2KXVoNFVp8Pl0_PZpD2uij3rIIdS_zPwQe4uJAfBg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "Bf4Wb75kZFjM6meY1C5xijvsvBv1c_qJX05J5O3P_CI"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "AJ7meGAWJmfjXbfzDWddvufdjdIASoXV",
  "exp": 1690815728,
  "htm": "POST",
  "htu": "http://wire.com:23247/clients/a338e9ea9e87fec/access-token",
  "iat": 1690812128,
  "jti": "abf305fe-f403-494e-8396-20c022d82712",
  "nbf": 1690812123,
  "nonce": "NlN3RHRrcGdHZ1FDODg5c0w3dmRINHc0SFZ6aloyUXg",
  "sub": "im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFRwM+2ULMc2Ah8aDmkMaXrSR0fzj4Xfu9HVVHBGP1I/
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEABf4Wb75kZFjM6meY1C5xijvsvBv1c/qJX05J5O3P/CI=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:23247/clients/a338e9ea9e87fec/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pUW1ZMFYySTNOV3RhUm1wTk5tMWxXVEZETlhocGFuWnpka0oyTVdOZmNVcFlNRFZLTlU4elVGOURTU0o5ZlEuZXlKcFlYUWlPakUyT1RBNE1USXhNamdzSW1WNGNDSTZNVFk1TURneE5UY3lPQ3dpYm1KbUlqb3hOamt3T0RFeU1USXpMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVlEwUTI5NU5IWmtVbnBwWVc1M1prOW5XSEJ1TmtFdllUTXpPR1U1WldFNVpUZzNabVZqUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWVdKbU16QTFabVV0WmpRd015MDBPVFJsTFRnek9UWXRNakJqTURJeVpEZ3lOekV5SWl3aWJtOXVZMlVpT2lKT2JFNHpVa2hTY21OSFpFaGFNVVpFVDBSbk5XTXdkek5rYlZKSlRraGpNRk5HV2paaGJHOTVWVmhuSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU16STBOeTlqYkdsbGJuUnpMMkV6TXpobE9XVmhPV1U0TjJabFl5OWhZMk5sYzNNdGRHOXJaVzRpTENKamFHRnNJam9pUVVvM2JXVkhRVmRLYldacVdHSm1la1JYWkdSMmRXWmthbVJKUVZOdldGWWlmUS5HdUs4eE1qOTNhRjdNZmZLUmRWTUVXWk1wc19uX0wtZktVOUhMRHlvblJES3YyS1hWb05GVnA4UGwwX1BacEQydWlqM3JJSWRTX3pQd1FlNHVKQWZCZw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InBmNkYyekNHSmxQOGRNOGZ0dzFMaldsUld2OHRQQ0dOQnMwUTJPLVRUSEEifX0.eyJpYXQiOjE2OTA4MTIxMjgsImV4cCI6MTY5ODU4ODEyOCwibmJmIjoxNjkwODEyMTIzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjMyNDcvY2xpZW50cy9hMzM4ZTllYTllODdmZWMvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcD1UNENveTR2ZFJ6aWFud2ZPZ1hwbjZBL2EzMzhlOWVhOWU4N2ZlY0B3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzI0Ny9jbGllbnRzL2EzMzhlOWVhOWU4N2ZlYy9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI3YWY4NDkwMC1mMTkzLTRkZDEtYWUwOC1lMmE4MDBiZWE5MDEiLCJub25jZSI6Ik5sTjNSSFJyY0dkSFoxRkRPRGc1YzB3M2RtUklOSGMwU0ZaNmFsb3lVWGciLCJjaGFsIjoiQUo3bWVHQVdKbWZqWGJmekRXZGR2dWZkamRJQVNvWFYiLCJjbmYiOnsia2lkIjoiYktJOVNWMVNtTlVDQVlBeEpUVE53NEIzSHdPeDl5NDJiMkZrWHk2UjQ5USJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVFtWTBWMkkzTld0YVJtcE5ObTFsV1RGRE5YaHBhblp6ZGtKMk1XTmZjVXBZTURWS05VOHpVRjlEU1NKOWZRLmV5SnBZWFFpT2pFMk9UQTRNVEl4TWpnc0ltVjRjQ0k2TVRZNU1EZ3hOVGN5T0N3aWJtSm1Jam94Tmprd09ERXlNVEl6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFZRMFEyOTVOSFprVW5wcFlXNTNaazluV0hCdU5rRXZZVE16T0dVNVpXRTVaVGczWm1WalFIZHBjbVV1WTI5dElpd2lhblJwSWpvaVlXSm1NekExWm1VdFpqUXdNeTAwT1RSbExUZ3pPVFl0TWpCak1ESXlaRGd5TnpFeUlpd2libTl1WTJVaU9pSk9iRTR6VWtoU2NtTkhaRWhhTVVaRVQwUm5OV013ZHpOa2JWSkpUa2hqTUZOR1dqWmhiRzk1VlZobklpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJbWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNekkwTnk5amJHbGxiblJ6TDJFek16aGxPV1ZoT1dVNE4yWmxZeTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVFVbzNiV1ZIUVZkS2JXWnFXR0ptZWtSWFpHUjJkV1prYW1SSlFWTnZXRllpZlEuR3VLOHhNajkzYUY3TWZmS1JkVk1FV1pNcHNfbl9MLWZLVTlITER5b25SREt2MktYVm9ORlZwOFBsMF9QWnBEMnVpajNySUlkU196UHdRZTR1SkFmQmciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVQ0Q295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVjQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.4wGFFEPgAkbTYWPMcLsZJgJpH7fz4kMiJTYw9DI4bVKem4xRKWMUv6mNuCnwPpOdLxsabOEvWKYIW2NblUMuCg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InBmNkYyekNHSmxQOGRNOGZ0dzFMaldsUld2OHRQQ0dOQnMwUTJPLVRUSEEifX0.eyJpYXQiOjE2OTA4MTIxMjgsImV4cCI6MTY5ODU4ODEyOCwibmJmIjoxNjkwODEyMTIzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjMyNDcvY2xpZW50cy9hMzM4ZTllYTllODdmZWMvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcD1UNENveTR2ZFJ6aWFud2ZPZ1hwbjZBL2EzMzhlOWVhOWU4N2ZlY0B3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzI0Ny9jbGllbnRzL2EzMzhlOWVhOWU4N2ZlYy9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI3YWY4NDkwMC1mMTkzLTRkZDEtYWUwOC1lMmE4MDBiZWE5MDEiLCJub25jZSI6Ik5sTjNSSFJyY0dkSFoxRkRPRGc1YzB3M2RtUklOSGMwU0ZaNmFsb3lVWGciLCJjaGFsIjoiQUo3bWVHQVdKbWZqWGJmekRXZGR2dWZkamRJQVNvWFYiLCJjbmYiOnsia2lkIjoiYktJOVNWMVNtTlVDQVlBeEpUVE53NEIzSHdPeDl5NDJiMkZrWHk2UjQ5USJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVFtWTBWMkkzTld0YVJtcE5ObTFsV1RGRE5YaHBhblp6ZGtKMk1XTmZjVXBZTURWS05VOHpVRjlEU1NKOWZRLmV5SnBZWFFpT2pFMk9UQTRNVEl4TWpnc0ltVjRjQ0k2TVRZNU1EZ3hOVGN5T0N3aWJtSm1Jam94Tmprd09ERXlNVEl6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFZRMFEyOTVOSFprVW5wcFlXNTNaazluV0hCdU5rRXZZVE16T0dVNVpXRTVaVGczWm1WalFIZHBjbVV1WTI5dElpd2lhblJwSWpvaVlXSm1NekExWm1VdFpqUXdNeTAwT1RSbExUZ3pPVFl0TWpCak1ESXlaRGd5TnpFeUlpd2libTl1WTJVaU9pSk9iRTR6VWtoU2NtTkhaRWhhTVVaRVQwUm5OV013ZHpOa2JWSkpUa2hqTUZOR1dqWmhiRzk1VlZobklpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJbWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNekkwTnk5amJHbGxiblJ6TDJFek16aGxPV1ZoT1dVNE4yWmxZeTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVFVbzNiV1ZIUVZkS2JXWnFXR0ptZWtSWFpHUjJkV1prYW1SSlFWTnZXRllpZlEuR3VLOHhNajkzYUY3TWZmS1JkVk1FV1pNcHNfbl9MLWZLVTlITER5b25SREt2MktYVm9ORlZwOFBsMF9QWnBEMnVpajNySUlkU196UHdRZTR1SkFmQmciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVQ0Q295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVjQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.4wGFFEPgAkbTYWPMcLsZJgJpH7fz4kMiJTYw9DI4bVKem4xRKWMUv6mNuCnwPpOdLxsabOEvWKYIW2NblUMuCg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InBmNkYyekNHSmxQOGRNOGZ0dzFMaldsUld2
OHRQQ0dOQnMwUTJPLVRUSEEifX0.eyJpYXQiOjE2OTA4MTIxMjgsImV4cCI6MTY5
ODU4ODEyOCwibmJmIjoxNjkwODEyMTIzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjMyNDcvY2xpZW50cy9hMzM4ZTllYTllODdmZWMvYWNjZXNzLXRva2VuIiwic3Vi
IjoiaW06d2lyZWFwcD1UNENveTR2ZFJ6aWFud2ZPZ1hwbjZBL2EzMzhlOWVhOWU4
N2ZlY0B3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzI0Ny9jbGll
bnRzL2EzMzhlOWVhOWU4N2ZlYy9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI3YWY4NDkw
MC1mMTkzLTRkZDEtYWUwOC1lMmE4MDBiZWE5MDEiLCJub25jZSI6Ik5sTjNSSFJy
Y0dkSFoxRkRPRGc1YzB3M2RtUklOSGMwU0ZaNmFsb3lVWGciLCJjaGFsIjoiQUo3
bWVHQVdKbWZqWGJmekRXZGR2dWZkamRJQVNvWFYiLCJjbmYiOnsia2lkIjoiYktJ
OVNWMVNtTlVDQVlBeEpUVE53NEIzSHdPeDl5NDJiMkZrWHk2UjQ5USJ9LCJwcm9v
ZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdp
YW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0
SWpvaVFtWTBWMkkzTld0YVJtcE5ObTFsV1RGRE5YaHBhblp6ZGtKMk1XTmZjVXBZ
TURWS05VOHpVRjlEU1NKOWZRLmV5SnBZWFFpT2pFMk9UQTRNVEl4TWpnc0ltVjRj
Q0k2TVRZNU1EZ3hOVGN5T0N3aWJtSm1Jam94Tmprd09ERXlNVEl6TENKemRXSWlP
aUpwYlRwM2FYSmxZWEJ3UFZRMFEyOTVOSFprVW5wcFlXNTNaazluV0hCdU5rRXZZ
VE16T0dVNVpXRTVaVGczWm1WalFIZHBjbVV1WTI5dElpd2lhblJwSWpvaVlXSm1N
ekExWm1VdFpqUXdNeTAwT1RSbExUZ3pPVFl0TWpCak1ESXlaRGd5TnpFeUlpd2li
bTl1WTJVaU9pSk9iRTR6VWtoU2NtTkhaRWhhTVVaRVQwUm5OV013ZHpOa2JWSkpU
a2hqTUZOR1dqWmhiRzk1VlZobklpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJ
bWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNekkwTnk5amJHbGxiblJ6TDJFek16aGxP
V1ZoT1dVNE4yWmxZeTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVFVbzNi
V1ZIUVZkS2JXWnFXR0ptZWtSWFpHUjJkV1prYW1SSlFWTnZXRllpZlEuR3VLOHhN
ajkzYUY3TWZmS1JkVk1FV1pNcHNfbl9MLWZLVTlITER5b25SREt2MktYVm9ORlZw
OFBsMF9QWnBEMnVpajNySUlkU196UHdRZTR1SkFmQmciLCJjbGllbnRfaWQiOiJp
bTp3aXJlYXBwPVQ0Q295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVj
QHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRf
aWQifQ.4wGFFEPgAkbTYWPMcLsZJgJpH7fz4kMiJTYw9DI4bVKem4xRKWMUv6mNu
CnwPpOdLxsabOEvWKYIW2NblUMuCg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "pf6F2zCGJlP8dM8ftw1LjWlRWv8tPCGNBs0Q2O-TTHA"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:23247/clients/a338e9ea9e87fec/access-token",
  "chal": "AJ7meGAWJmfjXbfzDWddvufdjdIASoXV",
  "client_id": "im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com",
  "cnf": {
    "kid": "bKI9SV1SmNUCAYAxJTTNw4B3HwOx9y42b2FkXy6R49Q"
  },
  "exp": 1698588128,
  "iat": 1690812128,
  "iss": "http://wire.com:23247/clients/a338e9ea9e87fec/access-token",
  "jti": "7af84900-f193-4dd1-ae08-e2a800bea901",
  "nbf": 1690812123,
  "nonce": "NlN3RHRrcGdHZ1FDODg5c0w3dmRINHc0SFZ6aloyUXg",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiQmY0V2I3NWtaRmpNNm1lWTFDNXhpanZzdkJ2MWNfcUpYMDVKNU8zUF9DSSJ9fQ.eyJpYXQiOjE2OTA4MTIxMjgsImV4cCI6MTY5MDgxNTcyOCwibmJmIjoxNjkwODEyMTIzLCJzdWIiOiJpbTp3aXJlYXBwPVQ0Q295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVjQHdpcmUuY29tIiwianRpIjoiYWJmMzA1ZmUtZjQwMy00OTRlLTgzOTYtMjBjMDIyZDgyNzEyIiwibm9uY2UiOiJObE4zUkhScmNHZEhaMUZET0RnNWMwdzNkbVJJTkhjMFNGWjZhbG95VVhnIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzI0Ny9jbGllbnRzL2EzMzhlOWVhOWU4N2ZlYy9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiQUo3bWVHQVdKbWZqWGJmekRXZGR2dWZkamRJQVNvWFYifQ.GuK8xMj93aF7MffKRdVMEWZMps_n_L-fKU9HLDyonRDKv2KXVoNFVp8Pl0_PZpD2uij3rIIdS_zPwQe4uJAfBg",
  "scope": "wire_client_id",
  "sub": "im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDliifZgFwSw/GY5GBTs0T3A1J+Ifi7HByU6U/qNimAr
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApf6F2zCGJlP8dM8ftw1LjWlRWv8tPCGNBs0Q2O+TTHA=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/BDm3kVbFrMDWRhq5WTv3RQ7e6ttNK79d
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L2tPaUNkWHd6bXZRZUtyUGNkY0dxb3BDTnNTeTZnaHI0IiwidHlwIjoiSldUIiwibm9uY2UiOiJSVk5oV0VzNGFFNVZPRVZrTldseFFtOVRibWQ0V1RoMmRuWkZjRE5xVmxjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL2NoYWxsZW5nZS9CSDlsZ25HeEtrd0QySnlURGl6cFVLRWc2alpic3dmeC9CRG0za1ZiRnJNRFdSaHE1V1R2M1JRN2U2dHROSzc5ZCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluQm1Oa1l5ZWtOSFNteFFPR1JOT0daMGR6Rk1hbGRzVWxkMk9IUlFRMGRPUW5Nd1VUSlBMVlJVU0VFaWZYMC5leUpwWVhRaU9qRTJPVEE0TVRJeE1qZ3NJbVY0Y0NJNk1UWTVPRFU0T0RFeU9Dd2libUptSWpveE5qa3dPREV5TVRJekxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNeU5EY3ZZMnhwWlc1MGN5OWhNek00WlRsbFlUbGxPRGRtWldNdllXTmpaWE56TFhSdmEyVnVJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFVTkVOdmVUUjJaRko2YVdGdWQyWlBaMWh3YmpaQkwyRXpNemhsT1dWaE9XVTROMlpsWTBCM2FYSmxMbU52YlNJc0ltRjFaQ0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95TXpJME55OWpiR2xsYm5SekwyRXpNemhsT1dWaE9XVTROMlpsWXk5aFkyTmxjM010ZEc5clpXNGlMQ0pxZEdraU9pSTNZV1k0TkRrd01DMW1NVGt6TFRSa1pERXRZV1V3T0MxbE1tRTRNREJpWldFNU1ERWlMQ0p1YjI1alpTSTZJazVzVGpOU1NGSnlZMGRrU0ZveFJrUlBSR2MxWXpCM00yUnRVa2xPU0dNd1UwWmFObUZzYjNsVldHY2lMQ0pqYUdGc0lqb2lRVW8zYldWSFFWZEtiV1pxV0dKbWVrUlhaR1IyZFdaa2FtUkpRVk52V0ZZaUxDSmpibVlpT25zaWEybGtJam9pWWt0Sk9WTldNVk50VGxWRFFWbEJlRXBVVkU1M05FSXpTSGRQZURsNU5ESmlNa1pyV0hrMlVqUTVVU0o5TENKd2NtOXZaaUk2SW1WNVNtaGlSMk5wVDJsS1JscEZVbFJSVTBselNXNVNOV05EU1RaSmJWSjNZak5CY21GdVpEQkphWGRwWVc1a2NrbHFjRGRKYlhRd1pWTkpOa2xyT1V4VlEwbHpTVzFPZVdScFNUWkphMVpyVFdwVk1VMVVhMmxNUTBvMFNXcHZhVkZ0V1RCV01ra3pUbGQwWVZKdGNFNU9iVEZzVjFSR1JFNVlhSEJoYmxwNlpHdEtNazFYVG1aalZYQlpUVVJXUzA1Vk9IcFZSamxFVTFOS09XWlJMbVY1U25CWldGRnBUMnBGTWs5VVFUUk5WRWw0VFdwbmMwbHRWalJqUTBrMlRWUlpOVTFFWjNoT1ZHTjVUME4zYVdKdFNtMUphbTk0VG1wcmQwOUVSWGxOVkVsNlRFTktlbVJYU1dsUGFVcHdZbFJ3TTJGWVNteFpXRUozVUZaUk1GRXlPVFZPU0ZwclZXNXdjRmxYTlROYWF6bHVWMGhDZFU1clJYWlpWRTE2VDBkVk5WcFhSVFZhVkdjeldtMVdhbEZJWkhCamJWVjFXVEk1ZEVscGQybGhibEp3U1dwdmFWbFhTbTFOZWtFeFdtMVZkRnBxVVhkTmVUQXdUMVJTYkV4VVozcFBWRmwwVFdwQ2FrMUVTWGxhUkdkNVRucEZlVWxwZDJsaWJUbDFXVEpWYVU5cFNrOWlSVFI2Vld0b1UyTnRUa2hhUldoaFRWVmFSVlF3VW01T1YwMTNaSHBPYTJKV1NrcFVhMmhxVFVaT1IxZHFXbWhpUnprMVZsWm9ia2xwZDJsaFNGSjBTV3B2YVZWRk9WUldRMGx6U1cxb01HUlRTVFpKYldnd1pFaEJOa3g1T1ROaFdFcHNURzFPZG1KVWIzbE5la2t3VG5rNWFtSkhiR3hpYmxKNlRESkZlazE2YUd4UFYxWm9UMWRWTkU0eVdteFplVGxvV1RKT2JHTXpUWFJrUnpseVdsYzBhVXhEU21waFIwWnpTV3B2YVZGVmJ6TmlWMVpJVVZaa1MySlhXbkZYUjBwdFpXdFNXRnBIVWpKa1YxcHJZVzFTU2xGV1RuWlhSbGxwWmxFdVIzVkxPSGhOYWprellVWTNUV1ptUzFKa1ZrMUZWMXBOY0hOZmJsOU1MV1pMVlRsSVRFUjViMjVTUkV0Mk1rdFlWbTlPUmxad09GQnNNRjlRV25CRU1uVnBhak55U1Vsa1UxOTZVSGRSWlRSMVNrRm1RbWNpTENKamJHbGxiblJmYVdRaU9pSnBiVHAzYVhKbFlYQndQVlEwUTI5NU5IWmtVbnBwWVc1M1prOW5XSEJ1TmtFdllUTXpPR1U1WldFNVpUZzNabVZqUUhkcGNtVXVZMjl0SWl3aVlYQnBYM1psY25OcGIyNGlPak1zSW5OamIzQmxJam9pZDJseVpWOWpiR2xsYm5SZmFXUWlmUS40d0dGRkVQZ0FrYlRZV1BNY0xzWkpnSnBIN2Z6NGtNaUpUWXc5REk0YlZLZW00eFJLV01VdjZtTnVDbndQcE9kTHhzYWJPRXZXS1lJVzJOYmxVTXVDZyJ9",
  "signature": "_gFmEmJdo7B_pZ1HoyGRYOqZkIAq2rsBYOYvGAUaSKdVq4-ej3WmB2lMGWJxk_jV6hhvA_nalMnHrXT-8hDuBg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InBmNkYyekNHSmxQOGRNOGZ0dzFMaldsUld2OHRQQ0dOQnMwUTJPLVRUSEEifX0.eyJpYXQiOjE2OTA4MTIxMjgsImV4cCI6MTY5ODU4ODEyOCwibmJmIjoxNjkwODEyMTIzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjMyNDcvY2xpZW50cy9hMzM4ZTllYTllODdmZWMvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcD1UNENveTR2ZFJ6aWFud2ZPZ1hwbjZBL2EzMzhlOWVhOWU4N2ZlY0B3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzI0Ny9jbGllbnRzL2EzMzhlOWVhOWU4N2ZlYy9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI3YWY4NDkwMC1mMTkzLTRkZDEtYWUwOC1lMmE4MDBiZWE5MDEiLCJub25jZSI6Ik5sTjNSSFJyY0dkSFoxRkRPRGc1YzB3M2RtUklOSGMwU0ZaNmFsb3lVWGciLCJjaGFsIjoiQUo3bWVHQVdKbWZqWGJmekRXZGR2dWZkamRJQVNvWFYiLCJjbmYiOnsia2lkIjoiYktJOVNWMVNtTlVDQVlBeEpUVE53NEIzSHdPeDl5NDJiMkZrWHk2UjQ5USJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVFtWTBWMkkzTld0YVJtcE5ObTFsV1RGRE5YaHBhblp6ZGtKMk1XTmZjVXBZTURWS05VOHpVRjlEU1NKOWZRLmV5SnBZWFFpT2pFMk9UQTRNVEl4TWpnc0ltVjRjQ0k2TVRZNU1EZ3hOVGN5T0N3aWJtSm1Jam94Tmprd09ERXlNVEl6TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFZRMFEyOTVOSFprVW5wcFlXNTNaazluV0hCdU5rRXZZVE16T0dVNVpXRTVaVGczWm1WalFIZHBjbVV1WTI5dElpd2lhblJwSWpvaVlXSm1NekExWm1VdFpqUXdNeTAwT1RSbExUZ3pPVFl0TWpCak1ESXlaRGd5TnpFeUlpd2libTl1WTJVaU9pSk9iRTR6VWtoU2NtTkhaRWhhTVVaRVQwUm5OV013ZHpOa2JWSkpUa2hqTUZOR1dqWmhiRzk1VlZobklpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJbWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNekkwTnk5amJHbGxiblJ6TDJFek16aGxPV1ZoT1dVNE4yWmxZeTloWTJObGMzTXRkRzlyWlc0aUxDSmphR0ZzSWpvaVFVbzNiV1ZIUVZkS2JXWnFXR0ptZWtSWFpHUjJkV1prYW1SSlFWTnZXRllpZlEuR3VLOHhNajkzYUY3TWZmS1JkVk1FV1pNcHNfbl9MLWZLVTlITER5b25SREt2MktYVm9ORlZwOFBsMF9QWnBEMnVpajNySUlkU196UHdRZTR1SkFmQmciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVQ0Q295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVjQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.4wGFFEPgAkbTYWPMcLsZJgJpH7fz4kMiJTYw9DI4bVKem4xRKWMUv6mNuCnwPpOdLxsabOEvWKYIW2NblUMuCg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/kOiCdXwzmvQeKrPcdcGqopCNsSy6ghr4",
    "nonce": "RVNhWEs4aE5VOEVkNWlxQm9Tbmd4WTh2dnZFcDNqVlc",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/BDm3kVbFrMDWRhq5WTv3RQ7e6ttNK79d"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
link: <https://stepca:32795/acme/wire/authz/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx>;rel="up"
location: https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/BDm3kVbFrMDWRhq5WTv3RQ7e6ttNK79d
replay-nonce: MDNxZHd6Z0pVM28xR1dwcHg2dUJ5RWlUMzdHdXducnk
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/BDm3kVbFrMDWRhq5WTv3RQ7e6ttNK79d",
  "status": "valid",
  "token": "AJ7meGAWJmfjXbfzDWddvufdjdIASoXV",
  "target": "http://wire.com:23247/clients/a338e9ea9e87fec/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=5nM3PLTvZuIkCUV5IoDgOO7VqvCjxzFT1akfxQ7CP1s&code_challenge=ybi1YnDa09Qa8LKf_kBfzpSGQazvsDmpl4juiJDfX5s
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:24582/dex/auth?response_type=code&client_id=wireapp&state=k0NGorbPz-AuOQO8KWNzuQ&code_challenge=ybi1YnDa09Qa8LKf_kBfzpSGQazvsDmpl4juiJDfX5s&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A23247%2Fcallback&scope=openid+profile&nonce=Z9oC7EnD2IS9_9WhfbOK2w
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:24582/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpNa0pNU3pkdFNYVklVbEpFVGxjd1VtMVFhRlZZY21kWg==
```
```text
grant_type=authorization_code&code=dogvpuwk2pnv3pbx26kvczmj2&code_verifier=5nM3PLTvZuIkCUV5IoDgOO7VqvCjxzFT1akfxQ7CP1s&redirect_uri=http%3A%2F%2Fwire.com%3A23247%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0MzFmM2VlN2QxZjQ2MmY4ZWVmMGQ5YTc0NWQ0ZWY3OTJhMjFlZjAifQ.eyJpc3MiOiJodHRwOi8vZGV4OjI0NTgyL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVlEwUTI5NU5IWmtVbnBwWVc1M1prOW5XSEJ1TmtFdllUTXpPR1U1WldFNVpUZzNabVZqUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjkwODk4NTI4LCJpYXQiOjE2OTA4MTIxMjgsIm5vbmNlIjoiWjlvQzdFbkQySVM5XzlXaGZiT0sydyIsImF0X2hhc2giOiJaejNfd2x3aTdaR3F0NFp6bnV0WDhnIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.fBzGVf2TowxNW4013JoUFlbITBZNMBVSE_5Jw_jG10NnWzNTp3w8NH97ImjofXk787o9Bf3LfXsW9OEiMmseppfk3mpi_tX-kSFsLQcGrobLZCKKa1wsB8uRxYS08JrnfuU-5lzKODKyicaApV1fMbqZSwkZvzk0PyBZy4d9vd38cg8m4_e3mRZQzRnB-NBvHnRYwP_o5G49VHU-0I-KiA351O3s56dq18S0Sueji3TlHPc2GGZ3MJaNJ4x73vexYEZIKJIPUzWsvciDJmZPmAgBHdOMPdrILg5FHKWY-32NqNjmHlxZ96uU1aj3lmx_Oksrx5qgWwX-XZ4u4LEDfw",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0MzFmM2VlN2QxZjQ2MmY4ZWVmMGQ5YTc0NWQ0ZWY3OTJhMjFlZjAifQ.eyJpc3MiOiJodHRwOi8vZGV4OjI0NTgyL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVlEwUTI5NU5IWmtVbnBwWVc1M1prOW5XSEJ1TmtFdllUTXpPR1U1WldFNVpUZzNabVZqUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjkwODk4NTI4LCJpYXQiOjE2OTA4MTIxMjgsIm5vbmNlIjoiWjlvQzdFbkQySVM5XzlXaGZiT0sydyIsImF0X2hhc2giOiJIV3ZlQTRtRjlROWIwOUhnUVJiR09RIiwiY19oYXNoIjoic1RRdlN4cEdOVmsxaV9hT29VWG83dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.RHL7y70ikhSr6BiAi1Azj43-6GPpLWX9Vt7CkIky7ulP1BoigKo9YPQHoWAr0dk0MBqorCARxO7sYDwo1hffb3EZu8ieS35CMjIP2YPGEVjcwVs4a6cA60ehCrAEAMn7dz_6E4lucRMBQdQsn0eaB1CxBPkzLHAR4fvsf9j7O4NmaVnD9P8LUASWrwGdhp3EvMsVlkZ-X7CuPxxp_YiJ5rbBY1eu3snaateLWYWfiTt_H6NT50s3QFImZqA79hoDoknKfdfBjeMKiB20WPAkpAKQHcWpSHY_T_M7x36c234L7CgL-aRuFm8YXLAuDef6SLvCvta7-i2yUN4dfYU7yw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0MzFmM2VlN2QxZjQ2MmY4ZWVmMGQ5YTc0NWQ0ZWY3OTJhMjFlZjAifQ.eyJpc3MiOiJodHRwOi8vZGV4OjI0NTgyL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVlEwUTI5NU5IWmtVbnBwWVc1M1prOW5XSEJ1TmtFdllUTXpPR1U1WldFNVpUZzNabVZqUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjkwODk4NTI4LCJpYXQiOjE2OTA4MTIxMjgsIm5vbmNlIjoiWjlvQzdFbkQySVM5XzlXaGZiT0sydyIsImF0X2hhc2giOiJIV3ZlQTRtRjlROWIwOUhnUVJiR09RIiwiY19oYXNoIjoic1RRdlN4cEdOVmsxaV9hT29VWG83dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.RHL7y70ikhSr6BiAi1Azj43-6GPpLWX9Vt7CkIky7ulP1BoigKo9YPQHoWAr0dk0MBqorCARxO7sYDwo1hffb3EZu8ieS35CMjIP2YPGEVjcwVs4a6cA60ehCrAEAMn7dz_6E4lucRMBQdQsn0eaB1CxBPkzLHAR4fvsf9j7O4NmaVnD9P8LUASWrwGdhp3EvMsVlkZ-X7CuPxxp_YiJ5rbBY1eu3snaateLWYWfiTt_H6NT50s3QFImZqA79hoDoknKfdfBjeMKiB20WPAkpAKQHcWpSHY_T_M7x36c234L7CgL-aRuFm8YXLAuDef6SLvCvta7-i2yUN4dfYU7yw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0MzFmM2VlN2QxZjQ2MmY4ZWVmMGQ5YTc0NWQ0ZWY3OTJhMjFlZjAifQ.eyJpc3MiOiJodHRwOi8vZGV4OjI0NTgyL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVlEwUTI5NU5IWmtVbnBwWVc1M1prOW5XSEJ1TmtFdllUTXpPR1U1WldFNVpUZzNabVZqUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjkwODk4NTI4LCJpYXQiOjE2OTA4MTIxMjgsIm5vbmNlIjoiWjlvQzdFbkQySVM5XzlXaGZiT0sydyIsImF0X2hhc2giOiJIV3ZlQTRtRjlROWIwOUhnUVJiR09RIiwiY19oYXNoIjoic1RRdlN4cEdOVmsxaV9hT29VWG83dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.RHL7y70ikhSr6BiAi1Azj43-6GPpLWX9Vt7CkIky7ulP1BoigKo9YPQHoWAr0dk0MBqorCARxO7sYDwo1hffb3EZu8ieS35CMjIP2YPGEVjcwVs4a6cA60ehCrAEAMn7dz_6E4lucRMBQdQsn0eaB1CxBPkzLHAR4fvsf9j7O4NmaVnD9P8LUASWrwGdhp3EvMsVlkZ-X7CuPxxp_YiJ5rbBY1eu3snaateLWYWfiTt_H6NT50s3QFImZqA79hoDoknKfdfBjeMKiB20WPAkpAKQHcWpSHY_T_M7x36c234L7CgL-aRuFm8YXLAuDef6SLvCvta7-i2yUN4dfYU7yw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0MzFmM2VlN2QxZjQ2MmY4ZWVmMGQ5YTc0
NWQ0ZWY3OTJhMjFlZjAifQ.eyJpc3MiOiJodHRwOi8vZGV4OjI0NTgyL2RleCIsI
nN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVlEwUTI5NU5IWmtVbnBwWVc1M1prOW5XS
EJ1TmtFdllUTXpPR1U1WldFNVpUZzNabVZqUUhkcGNtVXVZMjl0RWdSc1pHRnciL
CJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjkwODk4NTI4LCJpYXQiOjE2OTA4MTIxM
jgsIm5vbmNlIjoiWjlvQzdFbkQySVM5XzlXaGZiT0sydyIsImF0X2hhc2giOiJIV
3ZlQTRtRjlROWIwOUhnUVJiR09RIiwiY19oYXNoIjoic1RRdlN4cEdOVmsxaV9hT
29VWG83dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZ
WRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.RHL7y70ikhSr6BiAi1Azj43-6GPp
LWX9Vt7CkIky7ulP1BoigKo9YPQHoWAr0dk0MBqorCARxO7sYDwo1hffb3EZu8ie
S35CMjIP2YPGEVjcwVs4a6cA60ehCrAEAMn7dz_6E4lucRMBQdQsn0eaB1CxBPkz
LHAR4fvsf9j7O4NmaVnD9P8LUASWrwGdhp3EvMsVlkZ-X7CuPxxp_YiJ5rbBY1eu
3snaateLWYWfiTt_H6NT50s3QFImZqA79hoDoknKfdfBjeMKiB20WPAkpAKQHcWp
SHY_T_M7x36c234L7CgL-aRuFm8YXLAuDef6SLvCvta7-i2yUN4dfYU7yw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "f431f3ee7d1f462f8eef0d9a745d4ef792a21ef0"
}
```

```json
{
  "at_hash": "HWveA4mF9Q9b09HgQRbGOQ",
  "aud": "wireapp",
  "c_hash": "sTQvSxpGNVk1i_aOoUXo7w",
  "exp": 1690898528,
  "iat": 1690812128,
  "iss": "http://dex:24582/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "Z9oC7EnD2IS9_9WhfbOK2w",
  "preferred_username": "Alice Smith",
  "sub": "CjppbTp3aXJlYXBwPVQ0Q295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVjQHdpcmUuY29tEgRsZGFw"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzA4rjCQar2CSb6Mnw9RU
H/6V6IJO4qX3V7ecC4o33QRLNFvHS5SJfAgoDY9OjkvNg/LWaSqufqHJuexk5UQc
hiGKfgv/BpVPso1YrVDiSceTonyiNNBD2tUZdkLd6huq174ROMnaaDVvvClHDyB4
hGENiu9N2OSV0q6tGBJ68RjMUhCvodirj+IBDnyE5/JS6r2JvVKtB/gjz113xujM
n8wctIGYW82SpgFvQg5vW/zuDI1h7tFdqsomtJt/4GHL7i7jX/2N/jvlkgRerZBq
aoGym+F+eyK7XnNg+DPYR41yezM/WN8uKZ9HSkdJGYdDRIMc1nRLEK1mc2wbrNzz
AQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/pFY3f2cRMc1iDw0iXT4JGKDqPnqhsICQ
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L2tPaUNkWHd6bXZRZUtyUGNkY0dxb3BDTnNTeTZnaHI0IiwidHlwIjoiSldUIiwibm9uY2UiOiJNRE54WkhkNlowcFZNMjh4UjFkd2NIZzJkVUo1UldsVU16ZEhkWGR1Y25rIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL2NoYWxsZW5nZS9CSDlsZ25HeEtrd0QySnlURGl6cFVLRWc2alpic3dmeC9wRlkzZjJjUk1jMWlEdzBpWFQ0SkdLRHFQbnFoc0lDUSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJbVkwTXpGbU0yVmxOMlF4WmpRMk1tWTRaV1ZtTUdRNVlUYzBOV1EwWldZM09USmhNakZsWmpBaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSTBOVGd5TDJSbGVDSXNJbk4xWWlJNklrTnFjSEJpVkhBellWaEtiRmxZUW5kUVZsRXdVVEk1TlU1SVdtdFZibkJ3V1ZjMU0xcHJPVzVYU0VKMVRtdEZkbGxVVFhwUFIxVTFXbGRGTlZwVVp6TmFiVlpxVVVoa2NHTnRWWFZaTWpsMFJXZFNjMXBIUm5jaUxDSmhkV1FpT2lKM2FYSmxZWEJ3SWl3aVpYaHdJam94Tmprd09EazROVEk0TENKcFlYUWlPakUyT1RBNE1USXhNamdzSW01dmJtTmxJam9pV2psdlF6ZEZia1F5U1ZNNVh6bFhhR1ppVDBzeWR5SXNJbUYwWDJoaGMyZ2lPaUpJVjNabFFUUnRSamxST1dJd09VaG5VVkppUjA5Uklpd2lZMTlvWVhOb0lqb2ljMVJSZGxONGNFZE9WbXN4YVY5aFQyOVZXRzgzZHlJc0ltNWhiV1VpT2lKcGJUcDNhWEpsWVhCd1BXRnNhV05sWDNkcGNtVWlMQ0p3Y21WbVpYSnlaV1JmZFhObGNtNWhiV1VpT2lKQmJHbGpaU0JUYldsMGFDSjkuUkhMN3k3MGlraFNyNkJpQWkxQXpqNDMtNkdQcExXWDlWdDdDa0lreTd1bFAxQm9pZ0tvOVlQUUhvV0FyMGRrME1CcW9yQ0FSeE83c1lEd28xaGZmYjNFWnU4aWVTMzVDTWpJUDJZUEdFVmpjd1ZzNGE2Y0E2MGVoQ3JBRUFNbjdkel82RTRsdWNSTUJRZFFzbjBlYUIxQ3hCUGt6TEhBUjRmdnNmOWo3TzRObWFWbkQ5UDhMVUFTV3J3R2RocDNFdk1zVmxrWi1YN0N1UHh4cF9ZaUo1cmJCWTFldTNzbmFhdGVMV1lXZmlUdF9INk5UNTBzM1FGSW1acUE3OWhvRG9rbktmZGZCamVNS2lCMjBXUEFrcEFLUUhjV3BTSFlfVF9NN3gzNmMyMzRMN0NnTC1hUnVGbThZWExBdURlZjZTTHZDdnRhNy1pMnlVTjRkZllVN3l3Iiwia2V5YXV0aCI6IkFKN21lR0FXSm1malhiZnpEV2RkdnVmZGpkSUFTb1hWLmJLSTlTVjFTbU5VQ0FZQXhKVFROdzRCM0h3T3g5eTQyYjJGa1h5NlI0OVEifQ",
  "signature": "obRpUdwdWUzaBje2gBv24xm0P_oNAHO0hskacz5jfI3Lzjp9ApQIrzNczWADVw59IQioiPMp_HER8NrrDSMqBQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImY0MzFmM2VlN2QxZjQ2MmY4ZWVmMGQ5YTc0NWQ0ZWY3OTJhMjFlZjAifQ.eyJpc3MiOiJodHRwOi8vZGV4OjI0NTgyL2RleCIsInN1YiI6IkNqcHBiVHAzYVhKbFlYQndQVlEwUTI5NU5IWmtVbnBwWVc1M1prOW5XSEJ1TmtFdllUTXpPR1U1WldFNVpUZzNabVZqUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjkwODk4NTI4LCJpYXQiOjE2OTA4MTIxMjgsIm5vbmNlIjoiWjlvQzdFbkQySVM5XzlXaGZiT0sydyIsImF0X2hhc2giOiJIV3ZlQTRtRjlROWIwOUhnUVJiR09RIiwiY19oYXNoIjoic1RRdlN4cEdOVmsxaV9hT29VWG83dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.RHL7y70ikhSr6BiAi1Azj43-6GPpLWX9Vt7CkIky7ulP1BoigKo9YPQHoWAr0dk0MBqorCARxO7sYDwo1hffb3EZu8ieS35CMjIP2YPGEVjcwVs4a6cA60ehCrAEAMn7dz_6E4lucRMBQdQsn0eaB1CxBPkzLHAR4fvsf9j7O4NmaVnD9P8LUASWrwGdhp3EvMsVlkZ-X7CuPxxp_YiJ5rbBY1eu3snaateLWYWfiTt_H6NT50s3QFImZqA79hoDoknKfdfBjeMKiB20WPAkpAKQHcWpSHY_T_M7x36c234L7CgL-aRuFm8YXLAuDef6SLvCvta7-i2yUN4dfYU7yw",
    "keyauth": "AJ7meGAWJmfjXbfzDWddvufdjdIASoXV.bKI9SV1SmNUCAYAxJTTNw4B3HwOx9y42b2FkXy6R49Q"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/kOiCdXwzmvQeKrPcdcGqopCNsSy6ghr4",
    "nonce": "MDNxZHd6Z0pVM28xR1dwcHg2dUJ5RWlUMzdHdXducnk",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/pFY3f2cRMc1iDw0iXT4JGKDqPnqhsICQ"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
link: <https://stepca:32795/acme/wire/authz/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx>;rel="up"
location: https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/pFY3f2cRMc1iDw0iXT4JGKDqPnqhsICQ
replay-nonce: ZThyY3hSWmtuY2dYQzBDbUQySHVBcjZ3bWtKM1lNUDc
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32795/acme/wire/challenge/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx/pFY3f2cRMc1iDw0iXT4JGKDqPnqhsICQ",
  "status": "valid",
  "token": "AJ7meGAWJmfjXbfzDWddvufdjdIASoXV",
  "target": "http://dex:24582/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L2tPaUNkWHd6bXZRZUtyUGNkY0dxb3BDTnNTeTZnaHI0IiwidHlwIjoiSldUIiwibm9uY2UiOiJaVGh5WTNoU1dtdHVZMmRZUXpCRGJVUXlTSFZCY2paM2JXdEtNMWxOVURjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL29yZGVyL0Jhd3ZBclVDcWRSbzlFU0Yxam1vYXBZWWRqM2FxeFJZIn0",
  "payload": "",
  "signature": "UUiFzck6cqI2vrsNaj4RL485GHQpLiBKkAkLpkdqPLnWaQCzKRew6iIJacivzWQfU9XLf_G_xH1N1ISFEdoRBQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/kOiCdXwzmvQeKrPcdcGqopCNsSy6ghr4",
    "nonce": "ZThyY3hSWmtuY2dYQzBDbUQySHVBcjZ3bWtKM1lNUDc",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
location: https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY
replay-nonce: Mk83SG5TQ0RyMHlsdTJBa0lWV01GbEZTYm1Qb2Vjak0
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32795/acme/wire/authz/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx"
  ],
  "expires": "2023-08-01T14:02:08Z",
  "notBefore": "2023-07-31T14:02:08.256487Z",
  "notAfter": "2033-07-28T14:02:08.256487Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L2tPaUNkWHd6bXZRZUtyUGNkY0dxb3BDTnNTeTZnaHI0IiwidHlwIjoiSldUIiwibm9uY2UiOiJNazgzU0c1VFEwUnlNSGxzZFRKQmEwbFdWMDFHYkVaVFltMVFiMlZqYWswIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL29yZGVyL0Jhd3ZBclVDcWRSbzlFU0Yxam1vYXBZWWRqM2FxeFJZL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCSURDQjB3SUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBQVgtRm0tLVpHUll6T3BubU5RdWNZbzc3THdiOVhQNmlWOU9TZVR0el93aW9HOHdiUVlKS29aSWh2Y05BUWtPTVdBd1hqQmNCZ05WSFJFRVZUQlRoanBwYlRwM2FYSmxZWEJ3UFZRMFEyOTVOSFprVW5wcFlXNTNaazluV0hCdU5rRXZZVE16T0dVNVpXRTVaVGczWm1WalFIZHBjbVV1WTI5dGhoVnBiVHAzYVhKbFlYQndQV0ZzYVdObFgzZHBjbVV3QlFZREsyVndBMEVBazB2M2VCZzNDRHRpQV9od2d2d3J5YktYaThBeVMzbXBVOFV4MkkxOWpmd201VTFaNUFSeXkwbjhIYWJsNzI1OEYzVGlITVBNa1N1U0lHZGZEWUgxQ1EifQ",
  "signature": "35kOqZsuxWKCvHpUGVAN8tFjVCJJxC_kqk4YImDfore2N6i2eOFzmetJ2FyC1-N7FjISQ--o15VHiVVC9Jg0AA"
}
```
```json
{
  "payload": {
    "csr": "MIIBIDCB0wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAAX-Fm--ZGRYzOpnmNQucYo77Lwb9XP6iV9OSeTtz_wioG8wbQYJKoZIhvcNAQkOMWAwXjBcBgNVHREEVTBThjppbTp3aXJlYXBwPVQ0Q295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVjQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dpcmUwBQYDK2VwA0EAk0v3eBg3CDtiA_hwgvwrybKXi8AyS3mpU8Ux2I19jfwm5U1Z5ARyy0n8Habl7258F3TiHMPMkSuSIGdfDYH1CQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/kOiCdXwzmvQeKrPcdcGqopCNsSy6ghr4",
    "nonce": "Mk83SG5TQ0RyMHlsdTJBa0lWV01GbEZTYm1Qb2Vjak0",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBIDCB0wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAAX+Fm++ZGRYzOpnmNQucYo77Lwb9XP6
iV9OSeTtz/wioG8wbQYJKoZIhvcNAQkOMWAwXjBcBgNVHREEVTBThjppbTp3aXJl
YXBwPVQ0Q295NHZkUnppYW53Zk9nWHBuNkEvYTMzOGU5ZWE5ZTg3ZmVjQHdpcmUu
Y29thhVpbTp3aXJlYXBwPWFsaWNlX3dpcmUwBQYDK2VwA0EAk0v3eBg3CDtiA/hw
gvwrybKXi8AyS3mpU8Ux2I19jfwm5U1Z5ARyy0n8Habl7258F3TiHMPMkSuSIGdf
DYH1CQ==
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
                    05:fe:16:6f:be:64:64:58:cc:ea:67:98:d4:2e:71:
                    8a:3b:ec:bc:1b:f5:73:fa:89:5f:4e:49:e4:ed:cf:
                    fc:22
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        93:4b:f7:78:18:37:08:3b:62:03:f8:70:82:fc:2b:c9:b2:97:
        8b:c0:32:4b:79:a9:53:c5:31:d8:8d:7d:8d:fc:26:e5:4d:59:
        e4:04:72:cb:49:fc:1d:a6:e5:ef:6e:7c:17:74:e2:1c:c3:cc:
        91:2b:92:20:67:5f:0d:81:f5:09

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
location: https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY
replay-nonce: emxGT2RVZWh6UEJLNmpoZmN1clB6VzFsRkRBdklrR2o
```
```json
{
  "certificate": "https://stepca:32795/acme/wire/certificate/jjGGoNn2k2gMMmXaePtUoncjnNFkHVBV",
  "status": "valid",
  "finalize": "https://stepca:32795/acme/wire/order/BawvArUCqdRo9ESF1jmoapYYdj3aqxRY/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32795/acme/wire/authz/BH9lgnGxKkwD2JyTDizpUKEg6jZbswfx"
  ],
  "expires": "2023-08-01T14:02:08Z",
  "notBefore": "2023-07-31T14:02:08.256487Z",
  "notAfter": "2033-07-28T14:02:08.256487Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32795/acme/wire/certificate/jjGGoNn2k2gMMmXaePtUoncjnNFkHVBV
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L2tPaUNkWHd6bXZRZUtyUGNkY0dxb3BDTnNTeTZnaHI0IiwidHlwIjoiSldUIiwibm9uY2UiOiJlbXhHVDJSVlpXaDZVRUpMTm1wb1ptTjFjbEI2VnpGc1JrUkJka2xyUjJvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL2NlcnRpZmljYXRlL2pqR0dvTm4yazJnTU1tWGFlUHRVb25jam5ORmtIVkJWIn0",
  "payload": "",
  "signature": "iSkqEWwVkU9trozuCa9KglP69C7vSM-9w1xAgRzJEyNvU3YYatVBbZZDXFuA3rR3lQvhsO5CcPgpi-BLkJ9oCw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/kOiCdXwzmvQeKrPcdcGqopCNsSy6ghr4",
    "nonce": "emxGT2RVZWh6UEJLNmpoZmN1clB6VzFsRkRBdklrR2o",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/certificate/jjGGoNn2k2gMMmXaePtUoncjnNFkHVBV"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32795/acme/wire/directory>;rel="index"
replay-nonce: TWpsWHdsTzVkQ24xSFBUUGM0a2JzckN0QUE4MlNmclM
```
```json
"-----BEGIN CERTIFICATE-----\nMIICDDCCAbOgAwIBAgIRAPByYiuFhbbYasW+GKz5FBkwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwNzMxMTQwMjA4WhcNMzMwNzI4MTQwMjA4WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQAF/hZvvmRkWMzqZ5jU\nLnGKO+y8G/Vz+olfTknk7c/8IqOB5TCB4jAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFGhAhRlgprn/FUxPfL+ehHvvAigpMB8G\nA1UdIwQYMBaAFB81Yl+jcBh8rnCo9MJtkZ+2vq5YMFwGA1UdEQRVMFOGFWltOndp\ncmVhcHA9YWxpY2Vfd2lyZYY6aW06d2lyZWFwcD1UNENveTR2ZFJ6aWFud2ZPZ1hw\nbjZBL2EzMzhlOWVhOWU4N2ZlY0B3aXJlLmNvbTAdBgwrBgEEAYKkZMYoQAEEDTAL\nAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgCP+OnliYCy7PKs3rt+x4zUuF\ne2grybnLl5fsak6lFPUCIE4T8ZMlKkOZ9xeYdTlrUPT67hc++ZRAtcU03Kqiz8sm\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV6gAwIBAgIQfYC2CCR4Uw9GPkJ2nSq8ATAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNzMxMTQw\nMjA2WhcNMzMwNzI4MTQwMjA2WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCOc\nsqiFG9+GHjqHP26inah0Vyxt8IoZykStaLLskp2IDB8/px2k6TbNV5areq09+g26\nQTxTzlaBWUE/Y9rCoqmjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBQfNWJfo3AYfK5wqPTCbZGftr6uWDAfBgNVHSMEGDAW\ngBQgDq04Td1mq9ala953Mito5QHARjAKBggqhkjOPQQDAgNJADBGAiEA+MIEAiG2\nDxMYFdlfpS2zs/Ed+1Co/pkE3iTlbhcQK6ACIQD1Xhg2dteHl4bILtK0aVH1BRtD\njHdSVZh5wt4eD7IMag==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICDDCCAbOgAwIBAgIRAPByYiuFhbbYasW+GKz5FBkwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwNzMxMTQwMjA4WhcNMzMwNzI4MTQwMjA4WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQAF/hZvvmRkWMzqZ5jU
LnGKO+y8G/Vz+olfTknk7c/8IqOB5TCB4jAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFGhAhRlgprn/FUxPfL+ehHvvAigpMB8G
A1UdIwQYMBaAFB81Yl+jcBh8rnCo9MJtkZ+2vq5YMFwGA1UdEQRVMFOGFWltOndp
cmVhcHA9YWxpY2Vfd2lyZYY6aW06d2lyZWFwcD1UNENveTR2ZFJ6aWFud2ZPZ1hw
bjZBL2EzMzhlOWVhOWU4N2ZlY0B3aXJlLmNvbTAdBgwrBgEEAYKkZMYoQAEEDTAL
AgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgCP+OnliYCy7PKs3rt+x4zUuF
e2grybnLl5fsak6lFPUCIE4T8ZMlKkOZ9xeYdTlrUPT67hc++ZRAtcU03Kqiz8sm
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f0:72:62:2b:85:85:b6:d8:6a:c5:be:18:ac:f9:14:19
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Jul 31 14:02:08 2023 GMT
            Not After : Jul 28 14:02:08 2033 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    05:fe:16:6f:be:64:64:58:cc:ea:67:98:d4:2e:71:
                    8a:3b:ec:bc:1b:f5:73:fa:89:5f:4e:49:e4:ed:cf:
                    fc:22
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                68:40:85:19:60:A6:B9:FF:15:4C:4F:7C:BF:9E:84:7B:EF:02:28:29
            X509v3 Authority Key Identifier: 
                1F:35:62:5F:A3:70:18:7C:AE:70:A8:F4:C2:6D:91:9F:B6:BE:AE:58
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice_wire, URI:im:wireapp=T4Coy4vdRzianwfOgXpn6A/a338e9ea9e87fec@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:08:ff:8e:9e:58:98:0b:2e:cf:2a:cd:eb:b7:ec:
        78:cd:4b:85:7b:68:2b:c9:b9:cb:97:97:ec:6a:4e:a5:14:f5:
        02:20:4e:13:f1:93:25:2a:43:99:f7:17:98:75:39:6b:50:f4:
        fa:ee:17:3e:f9:94:40:b5:c5:34:dc:aa:a2:cf:cb:26

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV6gAwIBAgIQfYC2CCR4Uw9GPkJ2nSq8ATAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNzMxMTQw
MjA2WhcNMzMwNzI4MTQwMjA2WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABCOc
sqiFG9+GHjqHP26inah0Vyxt8IoZykStaLLskp2IDB8/px2k6TbNV5areq09+g26
QTxTzlaBWUE/Y9rCoqmjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBQfNWJfo3AYfK5wqPTCbZGftr6uWDAfBgNVHSMEGDAW
gBQgDq04Td1mq9ala953Mito5QHARjAKBggqhkjOPQQDAgNJADBGAiEA+MIEAiG2
DxMYFdlfpS2zs/Ed+1Co/pkE3iTlbhcQK6ACIQD1Xhg2dteHl4bILtK0aVH1BRtD
jHdSVZh5wt4eD7IMag==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7d:80:b6:08:24:78:53:0f:46:3e:42:76:9d:2a:bc:01
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Jul 31 14:02:06 2023 GMT
            Not After : Jul 28 14:02:06 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:23:9c:b2:a8:85:1b:df:86:1e:3a:87:3f:6e:a2:
                    9d:a8:74:57:2c:6d:f0:8a:19:ca:44:ad:68:b2:ec:
                    92:9d:88:0c:1f:3f:a7:1d:a4:e9:36:cd:57:96:ab:
                    7a:ad:3d:fa:0d:ba:41:3c:53:ce:56:81:59:41:3f:
                    63:da:c2:a2:a9
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                1F:35:62:5F:A3:70:18:7C:AE:70:A8:F4:C2:6D:91:9F:B6:BE:AE:58
            X509v3 Authority Key Identifier: 
                20:0E:AD:38:4D:DD:66:AB:D6:A5:6B:DE:77:32:2B:68:E5:01:C0:46
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:f8:c2:04:02:21:b6:0f:13:18:15:d9:5f:a5:
        2d:b3:b3:f1:1d:fb:50:a8:fe:99:04:de:24:e5:6e:17:10:2b:
        a0:02:21:00:f5:5e:18:36:76:d7:87:97:86:c8:2e:d2:b4:69:
        51:f5:05:1b:43:8c:77:52:55:98:79:c2:de:1e:0f:b2:0c:6a

```
