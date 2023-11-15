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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/7e79723a8bdc694f/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/q7hy0z2jop2HweyInjvkgLNSQUDqV5PR
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/SDJQ76rdWuofetahvzpgljsuhCZL2pzv
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/SovyprYoMfROGmEbACsGVLwvn2A0h5j9
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32865/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32865/acme/wire/new-nonce",
  "newAccount": "https://stepca:32865/acme/wire/new-account",
  "newOrder": "https://stepca:32865/acme/wire/new-order",
  "revokeCert": "https://stepca:32865/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32865/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32865/acme/wire/directory>;rel="index"
replay-nonce: Y0MzcXpVbzFlYkFiMFJqbk1QZXNBYXlQYlpSUDZmb0c
```
```text
Y0MzcXpVbzFlYkFiMFJqbk1QZXNBYXlQYlpSUDZmb0c
```
#### 5. create a new account
```http request
POST https://stepca:32865/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjJZY3J1c2c0dFdHUC0tWXFZcldwNkx3T2l2d3U3OFU4NmRlWW90a1lxdDgifSwibm9uY2UiOiJZME16Y1hwVmJ6RmxZa0ZpTUZKcWJrMVFaWE5CWVhsUVlscFNVRFptYjBjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NjUvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "dOasRoIwxbbHLFydwUy-kfGvwaGUdIWkVgoj__LTqawx-K7muirWt_5iCC7FSLuR3qBhwwt-qTKXHIJ55LfNDg"
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
      "x": "2Ycrusg4tWGP--YqYrWp6LwOivwu78U86deYotkYqt8"
    },
    "nonce": "Y0MzcXpVbzFlYkFiMFJqbk1QZXNBYXlQYlpSUDZmb0c",
    "typ": "JWT",
    "url": "https://stepca:32865/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32865/acme/wire/directory>;rel="index"
location: https://stepca:32865/acme/wire/account/QAsrvmXogvcXjtocOwpPNtIgf9lg1qMF
replay-nonce: Q3RFRWJvNFJpQ3E1c09JM2dmcHpUQW5WVHZ6aGY1OFE
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32865/acme/wire/account/QAsrvmXogvcXjtocOwpPNtIgf9lg1qMF/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32865/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODY1L2FjbWUvd2lyZS9hY2NvdW50L1FBc3J2bVhvZ3ZjWGp0b2NPd3BQTnRJZ2Y5bGcxcU1GIiwidHlwIjoiSldUIiwibm9uY2UiOiJRM1JGUldKdk5GSnBRM0UxYzA5Sk0yZG1jSHBVUVc1V1ZIWjZhR1kxT0ZFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NjUvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9eWwtOEFfd1pTZmFTMnVWOFZ1TUVCdy83ZTc5NzIzYThiZGM2OTRmQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0xMS0xNlQxMDozNzoyNi4zMzQ5NTZaIiwibm90QWZ0ZXIiOiIyMDMzLTExLTEzVDEwOjM3OjI2LjMzNDk1NloifQ",
  "signature": "H2kWe-7FlkioXhNyDTPOieomP1TXfc7CqWBcyMz0Jt1Brl5ir6cB3l__iYePNI0HdP-hApqzeyRRCwizZhLjBg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2033-11-13T10:37:26.334956Z",
    "notBefore": "2023-11-16T10:37:26.334956Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32865/acme/wire/account/QAsrvmXogvcXjtocOwpPNtIgf9lg1qMF",
    "nonce": "Q3RFRWJvNFJpQ3E1c09JM2dmcHpUQW5WVHZ6aGY1OFE",
    "typ": "JWT",
    "url": "https://stepca:32865/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32865/acme/wire/directory>;rel="index"
location: https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn
replay-nonce: U1FDdUdjNWUyQmRwM1RsbkFMYTZRZUp2U1ZaaHE3eXM
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32865/acme/wire/authz/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki"
  ],
  "expires": "2023-11-17T10:37:26Z",
  "notBefore": "2023-11-16T10:37:26.334956Z",
  "notAfter": "2033-11-13T10:37:26.334956Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32865/acme/wire/authz/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODY1L2FjbWUvd2lyZS9hY2NvdW50L1FBc3J2bVhvZ3ZjWGp0b2NPd3BQTnRJZ2Y5bGcxcU1GIiwidHlwIjoiSldUIiwibm9uY2UiOiJVMUZEZFVkak5XVXlRbVJ3TTFSc2JrRk1ZVFpSWlVwMlUxWmFhSEUzZVhNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NjUvYWNtZS93aXJlL2F1dGh6L1psckI5aUs2cTc1Smx2S0dKMFNuSUNwUk1SSTFVZ2tpIn0",
  "payload": "",
  "signature": "6BlZ0gjB9GA42yNHUhZ_956-aWnREct-uZBVxs1ypTk6Xe1O77p2W0dc3Nxt6CmkLtTNuMXudhREeNL8jW6KAg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32865/acme/wire/account/QAsrvmXogvcXjtocOwpPNtIgf9lg1qMF",
    "nonce": "U1FDdUdjNWUyQmRwM1RsbkFMYTZRZUp2U1ZaaHE3eXM",
    "typ": "JWT",
    "url": "https://stepca:32865/acme/wire/authz/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32865/acme/wire/directory>;rel="index"
location: https://stepca:32865/acme/wire/authz/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki
replay-nonce: aHd2bExMa1dvSW51R3RpQVdycFhGdlB1U2t6R0JxanU
```
```json
{
  "status": "pending",
  "expires": "2023-11-17T10:37:26Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/SDJQ76rdWuofetahvzpgljsuhCZL2pzv",
      "status": "pending",
      "token": "NWcjk8D8F3lduoWZGNHSYZCq5UgQmHbv",
      "target": "http://dex:21491/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/q7hy0z2jop2HweyInjvkgLNSQUDqV5PR",
      "status": "pending",
      "token": "NWcjk8D8F3lduoWZGNHSYZCq5UgQmHbv",
      "target": "http://wire.com:19814/clients/7e79723a8bdc694f/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:19814/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
ejdUMW13ZHliemtDZVgwaE1WQmlyWlJrZFJXT3U3MzM
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMlljcnVzZzR0V0dQLS1ZcVlyV3A2THdPaXZ3dTc4VTg2ZGVZb3RrWXF0OCJ9fQ.eyJpYXQiOjE3MDAxMjc0NDYsImV4cCI6MTcwMDEzNDY0NiwibmJmIjoxNzAwMTI3NDQ2LCJzdWIiOiJpbTp3aXJlYXBwPXlsLThBX3daU2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJlLmNvbSIsImp0aSI6IjQyMjQzODgwLWYyZmQtNDFkMi04NTA5LWU4YmU5NjFiYTg5NSIsIm5vbmNlIjoiZWpkVU1XMTNaSGxpZW10RFpWZ3dhRTFXUW1seVdsSnJaRkpYVDNVM016TSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTk4MTQvY2xpZW50cy83ZTc5NzIzYThiZGM2OTRmL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJOV2NqazhEOEYzbGR1b1daR05IU1laQ3E1VWdRbUhidiJ9.5LS1-r8eIr9LwC4ekyjMd55UY-8dBi7K8KtCK9LQW0BmCE7CJ292svbuZGvNsUHPXU_UQwitfdobvTkhPzmXAQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMlljcnVzZzR0V0dQLS1ZcVlyV3A2THdP
aXZ3dTc4VTg2ZGVZb3RrWXF0OCJ9fQ.eyJpYXQiOjE3MDAxMjc0NDYsImV4cCI6M
TcwMDEzNDY0NiwibmJmIjoxNzAwMTI3NDQ2LCJzdWIiOiJpbTp3aXJlYXBwPXlsL
ThBX3daU2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJlLmNvbSIsI
mp0aSI6IjQyMjQzODgwLWYyZmQtNDFkMi04NTA5LWU4YmU5NjFiYTg5NSIsIm5vb
mNlIjoiZWpkVU1XMTNaSGxpZW10RFpWZ3dhRTFXUW1seVdsSnJaRkpYVDNVM016T
SIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTk4MTQvY2xpZ
W50cy83ZTc5NzIzYThiZGM2OTRmL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJOV2Nqa
zhEOEYzbGR1b1daR05IU1laQ3E1VWdRbUhidiJ9.5LS1-r8eIr9LwC4ekyjMd55U
Y-8dBi7K8KtCK9LQW0BmCE7CJ292svbuZGvNsUHPXU_UQwitfdobvTkhPzmXAQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "2Ycrusg4tWGP--YqYrWp6LwOivwu78U86deYotkYqt8"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "NWcjk8D8F3lduoWZGNHSYZCq5UgQmHbv",
  "exp": 1700134646,
  "htm": "POST",
  "htu": "http://wire.com:19814/clients/7e79723a8bdc694f/access-token",
  "iat": 1700127446,
  "jti": "42243880-f2fd-41d2-8509-e8be961ba895",
  "nbf": 1700127446,
  "nonce": "ejdUMW13ZHliemtDZVgwaE1WQmlyWlJrZFJXT3U3MzM",
  "sub": "im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIE7XLqe2M1O8K+hx5yXekpw95IQKTlzUKC1iSyxAjxen
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA2Ycrusg4tWGP++YqYrWp6LwOivwu78U86deYotkYqt8=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:19814/clients/7e79723a8bdc694f/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTWxsamNuVnpaelIwVjBkUUxTMVpjVmx5VjNBMlRIZFBhWFozZFRjNFZUZzJaR1ZaYjNScldYRjBPQ0o5ZlEuZXlKcFlYUWlPakUzTURBeE1qYzBORFlzSW1WNGNDSTZNVGN3TURFek5EWTBOaXdpYm1KbUlqb3hOekF3TVRJM05EUTJMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQWGxzTFRoQlgzZGFVMlpoVXpKMVZqaFdkVTFGUW5jdk4yVTNPVGN5TTJFNFltUmpOamswWmtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpReU1qUXpPRGd3TFdZeVptUXROREZrTWkwNE5UQTVMV1U0WW1VNU5qRmlZVGc1TlNJc0ltNXZibU5sSWpvaVpXcGtWVTFYTVROYVNHeHBaVzEwUkZwV1ozZGhSVEZYVVcxc2VWZHNTbkphUmtwWVZETlZNMDE2VFNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1UazRNVFF2WTJ4cFpXNTBjeTgzWlRjNU56SXpZVGhpWkdNMk9UUm1MMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lKT1YyTnFhemhFT0VZemJHUjFiMWRhUjA1SVUxbGFRM0UxVldkUmJVaGlkaUo5LjVMUzEtcjhlSXI5THdDNGVreWpNZDU1VVktOGRCaTdLOEt0Q0s5TFFXMEJtQ0U3Q0oyOTJzdmJ1Wkd2TnNVSFBYVV9VUXdpdGZkb2J2VGtoUHptWEFR
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ild2NUM4VUU0aFYzZks1Y0JYTEUzdjUzM2lOT0VJUUVFZllyQlRnZDZuRXcifX0.eyJpYXQiOjE3MDAxMjc0NDYsImV4cCI6MTcwMDEzMTQwNiwibmJmIjoxNzAwMTI3NDQ2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTk4MTQvY2xpZW50cy83ZTc5NzIzYThiZGM2OTRmL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9eWwtOEFfd1pTZmFTMnVWOFZ1TUVCdy83ZTc5NzIzYThiZGM2OTRmQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE5ODE0L2NsaWVudHMvN2U3OTcyM2E4YmRjNjk0Zi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI4NDZiYzAyMi03NzNlLTQyYTMtYmU2OS03NzE0YmIwMDE5MTUiLCJub25jZSI6ImVqZFVNVzEzWkhsaWVtdERaVmd3YUUxV1FtbHlXbEpyWkZKWFQzVTNNek0iLCJjaGFsIjoiTldjams4RDhGM2xkdW9XWkdOSFNZWkNxNVVnUW1IYnYiLCJjbmYiOnsia2lkIjoiM2VpYi1zZDRsM28wWmFLV1dLeXlKTEpMeFFQT2laWTdCMHR5LWFsWUVrdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaU1sbGpjblZ6WnpSMFYwZFFMUzFaY1ZseVYzQTJUSGRQYVhaM2RUYzRWVGcyWkdWWmIzUnJXWEYwT0NKOWZRLmV5SnBZWFFpT2pFM01EQXhNamMwTkRZc0ltVjRjQ0k2TVRjd01ERXpORFkwTml3aWJtSm1Jam94TnpBd01USTNORFEyTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFhsc0xUaEJYM2RhVTJaaFV6SjFWamhXZFUxRlFuY3ZOMlUzT1RjeU0yRTRZbVJqTmprMFprQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqUXlNalF6T0Rnd0xXWXlabVF0TkRGa01pMDROVEE1TFdVNFltVTVOakZpWVRnNU5TSXNJbTV2Ym1ObElqb2laV3BrVlUxWE1UTmFTR3hwWlcxMFJGcFdaM2RoUlRGWFVXMXNlVmRzU25KYVJrcFlWRE5WTTAxNlRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVGs0TVRRdlkyeHBaVzUwY3k4M1pUYzVOekl6WVRoaVpHTTJPVFJtTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSk9WMk5xYXpoRU9FWXpiR1IxYjFkYVIwNUlVMWxhUTNFMVZXZFJiVWhpZGlKOS41TFMxLXI4ZUlyOUx3QzRla3lqTWQ1NVVZLThkQmk3SzhLdENLOUxRVzBCbUNFN0NKMjkyc3ZidVpHdk5zVUhQWFVfVVF3aXRmZG9idlRraFB6bVhBUSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA9eWwtOEFfd1pTZmFTMnVWOFZ1TUVCdy83ZTc5NzIzYThiZGM2OTRmQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.5wwU5jI0D6Rvk-vZHOuivGREDtSVUAIipn3VKrG-X4yCpSwJ1d1AHcH7SttQIawlJNFcTf8k9QiPTxCAM-8ECw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ild2NUM4VUU0aFYzZks1Y0JYTEUzdjUzM2lOT0VJUUVFZllyQlRnZDZuRXcifX0.eyJpYXQiOjE3MDAxMjc0NDYsImV4cCI6MTcwMDEzMTQwNiwibmJmIjoxNzAwMTI3NDQ2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTk4MTQvY2xpZW50cy83ZTc5NzIzYThiZGM2OTRmL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9eWwtOEFfd1pTZmFTMnVWOFZ1TUVCdy83ZTc5NzIzYThiZGM2OTRmQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE5ODE0L2NsaWVudHMvN2U3OTcyM2E4YmRjNjk0Zi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI4NDZiYzAyMi03NzNlLTQyYTMtYmU2OS03NzE0YmIwMDE5MTUiLCJub25jZSI6ImVqZFVNVzEzWkhsaWVtdERaVmd3YUUxV1FtbHlXbEpyWkZKWFQzVTNNek0iLCJjaGFsIjoiTldjams4RDhGM2xkdW9XWkdOSFNZWkNxNVVnUW1IYnYiLCJjbmYiOnsia2lkIjoiM2VpYi1zZDRsM28wWmFLV1dLeXlKTEpMeFFQT2laWTdCMHR5LWFsWUVrdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaU1sbGpjblZ6WnpSMFYwZFFMUzFaY1ZseVYzQTJUSGRQYVhaM2RUYzRWVGcyWkdWWmIzUnJXWEYwT0NKOWZRLmV5SnBZWFFpT2pFM01EQXhNamMwTkRZc0ltVjRjQ0k2TVRjd01ERXpORFkwTml3aWJtSm1Jam94TnpBd01USTNORFEyTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFhsc0xUaEJYM2RhVTJaaFV6SjFWamhXZFUxRlFuY3ZOMlUzT1RjeU0yRTRZbVJqTmprMFprQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqUXlNalF6T0Rnd0xXWXlabVF0TkRGa01pMDROVEE1TFdVNFltVTVOakZpWVRnNU5TSXNJbTV2Ym1ObElqb2laV3BrVlUxWE1UTmFTR3hwWlcxMFJGcFdaM2RoUlRGWFVXMXNlVmRzU25KYVJrcFlWRE5WTTAxNlRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVGs0TVRRdlkyeHBaVzUwY3k4M1pUYzVOekl6WVRoaVpHTTJPVFJtTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSk9WMk5xYXpoRU9FWXpiR1IxYjFkYVIwNUlVMWxhUTNFMVZXZFJiVWhpZGlKOS41TFMxLXI4ZUlyOUx3QzRla3lqTWQ1NVVZLThkQmk3SzhLdENLOUxRVzBCbUNFN0NKMjkyc3ZidVpHdk5zVUhQWFVfVVF3aXRmZG9idlRraFB6bVhBUSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA9eWwtOEFfd1pTZmFTMnVWOFZ1TUVCdy83ZTc5NzIzYThiZGM2OTRmQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.5wwU5jI0D6Rvk-vZHOuivGREDtSVUAIipn3VKrG-X4yCpSwJ1d1AHcH7SttQIawlJNFcTf8k9QiPTxCAM-8ECw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6Ild2NUM4VUU0aFYzZks1Y0JYTEUzdjUzM2lO
T0VJUUVFZllyQlRnZDZuRXcifX0.eyJpYXQiOjE3MDAxMjc0NDYsImV4cCI6MTcw
MDEzMTQwNiwibmJmIjoxNzAwMTI3NDQ2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MTk4MTQvY2xpZW50cy83ZTc5NzIzYThiZGM2OTRmL2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9eWwtOEFfd1pTZmFTMnVWOFZ1TUVCdy83ZTc5NzIzYThi
ZGM2OTRmQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE5ODE0L2Ns
aWVudHMvN2U3OTcyM2E4YmRjNjk0Zi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI4NDZi
YzAyMi03NzNlLTQyYTMtYmU2OS03NzE0YmIwMDE5MTUiLCJub25jZSI6ImVqZFVN
VzEzWkhsaWVtdERaVmd3YUUxV1FtbHlXbEpyWkZKWFQzVTNNek0iLCJjaGFsIjoi
Tldjams4RDhGM2xkdW9XWkdOSFNZWkNxNVVnUW1IYnYiLCJjbmYiOnsia2lkIjoi
M2VpYi1zZDRsM28wWmFLV1dLeXlKTEpMeFFQT2laWTdCMHR5LWFsWUVrdyJ9LCJw
cm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJ
aXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lM
Q0o0SWpvaU1sbGpjblZ6WnpSMFYwZFFMUzFaY1ZseVYzQTJUSGRQYVhaM2RUYzRW
VGcyWkdWWmIzUnJXWEYwT0NKOWZRLmV5SnBZWFFpT2pFM01EQXhNamMwTkRZc0lt
VjRjQ0k2TVRjd01ERXpORFkwTml3aWJtSm1Jam94TnpBd01USTNORFEyTENKemRX
SWlPaUpwYlRwM2FYSmxZWEJ3UFhsc0xUaEJYM2RhVTJaaFV6SjFWamhXZFUxRlFu
Y3ZOMlUzT1RjeU0yRTRZbVJqTmprMFprQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklq
UXlNalF6T0Rnd0xXWXlabVF0TkRGa01pMDROVEE1TFdVNFltVTVOakZpWVRnNU5T
SXNJbTV2Ym1ObElqb2laV3BrVlUxWE1UTmFTR3hwWlcxMFJGcFdaM2RoUlRGWFVX
MXNlVmRzU25KYVJrcFlWRE5WTTAxNlRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RI
VWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVGs0TVRRdlkyeHBaVzUwY3k4M1pU
YzVOekl6WVRoaVpHTTJPVFJtTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9p
Sk9WMk5xYXpoRU9FWXpiR1IxYjFkYVIwNUlVMWxhUTNFMVZXZFJiVWhpZGlKOS41
TFMxLXI4ZUlyOUx3QzRla3lqTWQ1NVVZLThkQmk3SzhLdENLOUxRVzBCbUNFN0NK
Mjkyc3ZidVpHdk5zVUhQWFVfVVF3aXRmZG9idlRraFB6bVhBUSIsImNsaWVudF9p
ZCI6ImltOndpcmVhcHA9eWwtOEFfd1pTZmFTMnVWOFZ1TUVCdy83ZTc5NzIzYThi
ZGM2OTRmQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9j
bGllbnRfaWQifQ.5wwU5jI0D6Rvk-vZHOuivGREDtSVUAIipn3VKrG-X4yCpSwJ1
d1AHcH7SttQIawlJNFcTf8k9QiPTxCAM-8ECw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "Wv5C8UE4hV3fK5cBXLE3v533iNOEIQEEfYrBTgd6nEw"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:19814/clients/7e79723a8bdc694f/access-token",
  "chal": "NWcjk8D8F3lduoWZGNHSYZCq5UgQmHbv",
  "client_id": "im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com",
  "cnf": {
    "kid": "3eib-sd4l3o0ZaKWWKyyJLJLxQPOiZY7B0ty-alYEkw"
  },
  "exp": 1700131406,
  "iat": 1700127446,
  "iss": "http://wire.com:19814/clients/7e79723a8bdc694f/access-token",
  "jti": "846bc022-773e-42a3-be69-7714bb001915",
  "nbf": 1700127446,
  "nonce": "ejdUMW13ZHliemtDZVgwaE1WQmlyWlJrZFJXT3U3MzM",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMlljcnVzZzR0V0dQLS1ZcVlyV3A2THdPaXZ3dTc4VTg2ZGVZb3RrWXF0OCJ9fQ.eyJpYXQiOjE3MDAxMjc0NDYsImV4cCI6MTcwMDEzNDY0NiwibmJmIjoxNzAwMTI3NDQ2LCJzdWIiOiJpbTp3aXJlYXBwPXlsLThBX3daU2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJlLmNvbSIsImp0aSI6IjQyMjQzODgwLWYyZmQtNDFkMi04NTA5LWU4YmU5NjFiYTg5NSIsIm5vbmNlIjoiZWpkVU1XMTNaSGxpZW10RFpWZ3dhRTFXUW1seVdsSnJaRkpYVDNVM016TSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTk4MTQvY2xpZW50cy83ZTc5NzIzYThiZGM2OTRmL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJOV2NqazhEOEYzbGR1b1daR05IU1laQ3E1VWdRbUhidiJ9.5LS1-r8eIr9LwC4ekyjMd55UY-8dBi7K8KtCK9LQW0BmCE7CJ292svbuZGvNsUHPXU_UQwitfdobvTkhPzmXAQ",
  "scope": "wire_client_id",
  "sub": "im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAGGBAguoUtTvyaP+kgd6XmrafRRrCrTAJKaAA/TNscR
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAWv5C8UE4hV3fK5cBXLE3v533iNOEIQEEfYrBTgd6nEw=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/q7hy0z2jop2HweyInjvkgLNSQUDqV5PR
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODY1L2FjbWUvd2lyZS9hY2NvdW50L1FBc3J2bVhvZ3ZjWGp0b2NPd3BQTnRJZ2Y5bGcxcU1GIiwidHlwIjoiSldUIiwibm9uY2UiOiJhSGQyYkV4TWExZHZTVzUxUjNScFFWZHljRmhHZGxCMVUydDZSMEp4YW5VIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NjUvYWNtZS93aXJlL2NoYWxsZW5nZS9abHJCOWlLNnE3NUpsdktHSjBTbklDcFJNUkkxVWdraS9xN2h5MHoyam9wMkh3ZXlJbmp2a2dMTlNRVURxVjVQUiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklsZDJOVU00VlVVMGFGWXpaa3MxWTBKWVRFVXpkalV6TTJsT1QwVkpVVVZGWmxseVFsUm5aRFp1UlhjaWZYMC5leUpwWVhRaU9qRTNNREF4TWpjME5EWXNJbVY0Y0NJNk1UY3dNREV6TVRRd05pd2libUptSWpveE56QXdNVEkzTkRRMkxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRrNE1UUXZZMnhwWlc1MGN5ODNaVGM1TnpJellUaGlaR00yT1RSbUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5ZVd3dE9FRmZkMXBUWm1GVE1uVldPRloxVFVWQ2R5ODNaVGM1TnpJellUaGlaR00yT1RSbVFIZHBjbVV1WTI5dElpd2lZWFZrSWpvaWFIUjBjRG92TDNkcGNtVXVZMjl0T2pFNU9ERTBMMk5zYVdWdWRITXZOMlUzT1RjeU0yRTRZbVJqTmprMFppOWhZMk5sYzNNdGRHOXJaVzRpTENKcWRHa2lPaUk0TkRaaVl6QXlNaTAzTnpObExUUXlZVE10WW1VMk9TMDNOekUwWW1Jd01ERTVNVFVpTENKdWIyNWpaU0k2SW1WcVpGVk5WekV6V2toc2FXVnRkRVJhVm1kM1lVVXhWMUZ0YkhsWGJFcHlXa1pLV0ZRelZUTk5lazBpTENKamFHRnNJam9pVGxkamFtczRSRGhHTTJ4a2RXOVhXa2RPU0ZOWldrTnhOVlZuVVcxSVluWWlMQ0pqYm1ZaU9uc2lhMmxrSWpvaU0yVnBZaTF6WkRSc00yOHdXbUZMVjFkTGVYbEtURXBNZUZGUVQybGFXVGRDTUhSNUxXRnNXVVZyZHlKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVUxc2JHcGpibFo2V25wU01GWXdaRkZNVXpGYVkxWnNlVll6UVRKVVNHUlFZVmhhTTJSVVl6UldWR2N5V2tkV1dtSXpVbkpYV0VZd1QwTktPV1pSTG1WNVNuQlpXRkZwVDJwRk0wMUVRWGhOYW1Nd1RrUlpjMGx0VmpSalEwazJUVlJqZDAxRVJYcE9SRmt3VG1sM2FXSnRTbTFKYW05NFRucEJkMDFVU1ROT1JGRXlURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGaHNjMHhVYUVKWU0yUmhWVEphYUZWNlNqRldhbWhYWkZVeFJsRnVZM1pPTWxVelQxUmplVTB5UlRSWmJWSnFUbXByTUZwclFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2xxVVhsTmFsRjZUMFJuZDB4WFdYbGFiVkYwVGtSR2EwMXBNRFJPVkVFMVRGZFZORmx0VlRWT2FrWnBXVlJuTlU1VFNYTkpiVFYyWW0xT2JFbHFiMmxhVjNCclZsVXhXRTFVVG1GVFIzaHdXbGN4TUZKR2NGZGFNMlJvVWxSR1dGVlhNWE5sVm1SelUyNUtZVkpyY0ZsV1JFNVdUVEF4TmxSVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOVkdzMFRWUlJkbGt5ZUhCYVZ6VXdZM2s0TTFwVVl6Vk9la2w2V1ZSb2FWcEhUVEpQVkZKdFRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTazlXTWs1eFlYcG9SVTlGV1hwaVIxSXhZakZrWVZJd05VbFZNV3hoVVRORk1WWlhaRkppVldocFpHbEtPUzQxVEZNeExYSTRaVWx5T1V4M1F6UmxhM2xxVFdRMU5WVlpMVGhrUW1rM1N6aExkRU5MT1V4UlZ6QkNiVU5GTjBOS01qa3ljM1ppZFZwSGRrNXpWVWhRV0ZWZlZWRjNhWFJtWkc5aWRsUnJhRkI2YlZoQlVTSXNJbU5zYVdWdWRGOXBaQ0k2SW1sdE9uZHBjbVZoY0hBOWVXd3RPRUZmZDFwVFptRlRNblZXT0ZaMVRVVkNkeTgzWlRjNU56SXpZVGhpWkdNMk9UUm1RSGRwY21VdVkyOXRJaXdpWVhCcFgzWmxjbk5wYjI0aU9qVXNJbk5qYjNCbElqb2lkMmx5WlY5amJHbGxiblJmYVdRaWZRLjV3d1U1akkwRDZSdmstdlpIT3VpdkdSRUR0U1ZVQUlpcG4zVktyRy1YNHlDcFN3SjFkMUFIY0g3U3R0UUlhd2xKTkZjVGY4azlRaVBUeENBTS04RUN3In0",
  "signature": "NgTumXzIyNQWYTbB156vR4gU1F-IZYc1NmgpBfKZU7TezLBMb9YYjxfFZGDJ_LhellvEz1jJiTc9GCaPTHhJDg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ild2NUM4VUU0aFYzZks1Y0JYTEUzdjUzM2lOT0VJUUVFZllyQlRnZDZuRXcifX0.eyJpYXQiOjE3MDAxMjc0NDYsImV4cCI6MTcwMDEzMTQwNiwibmJmIjoxNzAwMTI3NDQ2LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTk4MTQvY2xpZW50cy83ZTc5NzIzYThiZGM2OTRmL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9eWwtOEFfd1pTZmFTMnVWOFZ1TUVCdy83ZTc5NzIzYThiZGM2OTRmQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE5ODE0L2NsaWVudHMvN2U3OTcyM2E4YmRjNjk0Zi9hY2Nlc3MtdG9rZW4iLCJqdGkiOiI4NDZiYzAyMi03NzNlLTQyYTMtYmU2OS03NzE0YmIwMDE5MTUiLCJub25jZSI6ImVqZFVNVzEzWkhsaWVtdERaVmd3YUUxV1FtbHlXbEpyWkZKWFQzVTNNek0iLCJjaGFsIjoiTldjams4RDhGM2xkdW9XWkdOSFNZWkNxNVVnUW1IYnYiLCJjbmYiOnsia2lkIjoiM2VpYi1zZDRsM28wWmFLV1dLeXlKTEpMeFFQT2laWTdCMHR5LWFsWUVrdyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaU1sbGpjblZ6WnpSMFYwZFFMUzFaY1ZseVYzQTJUSGRQYVhaM2RUYzRWVGcyWkdWWmIzUnJXWEYwT0NKOWZRLmV5SnBZWFFpT2pFM01EQXhNamMwTkRZc0ltVjRjQ0k2TVRjd01ERXpORFkwTml3aWJtSm1Jam94TnpBd01USTNORFEyTENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFhsc0xUaEJYM2RhVTJaaFV6SjFWamhXZFUxRlFuY3ZOMlUzT1RjeU0yRTRZbVJqTmprMFprQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqUXlNalF6T0Rnd0xXWXlabVF0TkRGa01pMDROVEE1TFdVNFltVTVOakZpWVRnNU5TSXNJbTV2Ym1ObElqb2laV3BrVlUxWE1UTmFTR3hwWlcxMFJGcFdaM2RoUlRGWFVXMXNlVmRzU25KYVJrcFlWRE5WTTAxNlRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVGs0TVRRdlkyeHBaVzUwY3k4M1pUYzVOekl6WVRoaVpHTTJPVFJtTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSk9WMk5xYXpoRU9FWXpiR1IxYjFkYVIwNUlVMWxhUTNFMVZXZFJiVWhpZGlKOS41TFMxLXI4ZUlyOUx3QzRla3lqTWQ1NVVZLThkQmk3SzhLdENLOUxRVzBCbUNFN0NKMjkyc3ZidVpHdk5zVUhQWFVfVVF3aXRmZG9idlRraFB6bVhBUSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA9eWwtOEFfd1pTZmFTMnVWOFZ1TUVCdy83ZTc5NzIzYThiZGM2OTRmQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.5wwU5jI0D6Rvk-vZHOuivGREDtSVUAIipn3VKrG-X4yCpSwJ1d1AHcH7SttQIawlJNFcTf8k9QiPTxCAM-8ECw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32865/acme/wire/account/QAsrvmXogvcXjtocOwpPNtIgf9lg1qMF",
    "nonce": "aHd2bExMa1dvSW51R3RpQVdycFhGdlB1U2t6R0JxanU",
    "typ": "JWT",
    "url": "https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/q7hy0z2jop2HweyInjvkgLNSQUDqV5PR"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32865/acme/wire/directory>;rel="index"
link: <https://stepca:32865/acme/wire/authz/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki>;rel="up"
location: https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/q7hy0z2jop2HweyInjvkgLNSQUDqV5PR
replay-nonce: SGlEc3MzQ3lUWjZhcWhoV3gwMW82Nk1KYzYzUkJXWEQ
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/q7hy0z2jop2HweyInjvkgLNSQUDqV5PR",
  "status": "valid",
  "token": "NWcjk8D8F3lduoWZGNHSYZCq5UgQmHbv",
  "target": "http://wire.com:19814/clients/7e79723a8bdc694f/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=0kBEjyRJ75veatbbZff4EY_28TRbqWhHfj4IcvVz5Xg&code_challenge=52n0eoMinfGIsOYTVHZygTO0aqYvmCBFNVmUJTA4ZvA
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:21491/dex/auth?response_type=code&client_id=wireapp&state=j6NYppHtn7eBJd1JM7CIrA&code_challenge=52n0eoMinfGIsOYTVHZygTO0aqYvmCBFNVmUJTA4ZvA&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A19814%2Fcallback&scope=openid+profile&nonce=REQyyne9UjP6K0MwFPEbVA
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:21491/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpWVEJvVmxOWlZEazFlWEZtU1V0S1JYVlpZelpWUWxSeQ==
```
```text
grant_type=authorization_code&code=s43qgxcl7jqkhwhhwdpm3smhl&code_verifier=0kBEjyRJ75veatbbZff4EY_28TRbqWhHfj4IcvVz5Xg&redirect_uri=http%3A%2F%2Fwire.com%3A19814%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJkOTQ5ZDVjZWFjMzU1MTJlNDliMWU3YzE5MTBhM2UxZjZjMjcyYzkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxNDkxL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWGxzTFRoQlgzZGFVMlpoVXpKMVZqaFdkVTFGUW5jdk4yVTNPVGN5TTJFNFltUmpOamswWmtCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDAyMTc0NDYsImlhdCI6MTcwMDEzMTA0Niwibm9uY2UiOiJSRVF5eW5lOVVqUDZLME13RlBFYlZBIiwiYXRfaGFzaCI6ImR0T3doVFY3a1JtSkRDUGRLMFgwYkEiLCJuYW1lIjoiaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.HhjZcj4__Uvg-JcS6v9MLAgAvsiKLVmBO-NXlu7l0IhGAqJElvU-Sl_cY49wq68la45arX9BazWwvk5PPb1uOmSsnwkRijnOA8oEJcEJ_30HzxXbzRmvYUk5B_f-45d1MQcsPjkewe75I4JGCM9qxPyylqmjobw4IH5rGPhGNOXBv_kxC1WdFW24xym1vIo2gClmXF8GTOyr_afU7ahWWEXHNRBhpD7k0RCuMtr-mRMsVn98eo0kV1HIrwEJwGtP2qOUdUXVga0kxGISfFVOlQLbVh5bfbUAT9aMMaVWIsdmdfhU2WPUVlUxM8dQaXGNITpZqBP9U7Zpjod4IbNJHg",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJkOTQ5ZDVjZWFjMzU1MTJlNDliMWU3YzE5MTBhM2UxZjZjMjcyYzkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxNDkxL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWGxzTFRoQlgzZGFVMlpoVXpKMVZqaFdkVTFGUW5jdk4yVTNPVGN5TTJFNFltUmpOamswWmtCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDAyMTc0NDYsImlhdCI6MTcwMDEzMTA0Niwibm9uY2UiOiJSRVF5eW5lOVVqUDZLME13RlBFYlZBIiwiYXRfaGFzaCI6IlpVNlRPbzdrd1hmVy1oNTZyNXBGQlEiLCJjX2hhc2giOiJjbzJ3amRDWDBOZEhudHpkTDNXR1FBIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.yfevAqKN_8K3UGriUoMWboA72J8Izru8uXhFiott2LwAN8I0SExdvnLrDQpgq0plXITRjzfSPlOGBpnS-tT55Uh1mqxw6YxfDFqhuUFf471q_uWjuEte5zGJ8u3G_1dXqvu5UueX7Y9oh0S0GdbVY3GCv6wugta0cDfOeBkWpNT5eXq6PU4wj8whA_op7HlCnMNxmWvimX5TMqtrFBMhpHuhbeCQYICE2sL39tR3MP9armEDX13tNKjlUFuxKv8-HrYYNneDmKplyCSmAAi2j8XIBW7qs7Hc1ZEBjmCoikFfi_Iw2yCGvsC1JXyB_VGOr_ak1RXCRGbBVG-VmfibHw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImJkOTQ5ZDVjZWFjMzU1MTJlNDliMWU3YzE5MTBhM2UxZjZjMjcyYzkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxNDkxL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWGxzTFRoQlgzZGFVMlpoVXpKMVZqaFdkVTFGUW5jdk4yVTNPVGN5TTJFNFltUmpOamswWmtCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDAyMTc0NDYsImlhdCI6MTcwMDEzMTA0Niwibm9uY2UiOiJSRVF5eW5lOVVqUDZLME13RlBFYlZBIiwiYXRfaGFzaCI6IlpVNlRPbzdrd1hmVy1oNTZyNXBGQlEiLCJjX2hhc2giOiJjbzJ3amRDWDBOZEhudHpkTDNXR1FBIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.yfevAqKN_8K3UGriUoMWboA72J8Izru8uXhFiott2LwAN8I0SExdvnLrDQpgq0plXITRjzfSPlOGBpnS-tT55Uh1mqxw6YxfDFqhuUFf471q_uWjuEte5zGJ8u3G_1dXqvu5UueX7Y9oh0S0GdbVY3GCv6wugta0cDfOeBkWpNT5eXq6PU4wj8whA_op7HlCnMNxmWvimX5TMqtrFBMhpHuhbeCQYICE2sL39tR3MP9armEDX13tNKjlUFuxKv8-HrYYNneDmKplyCSmAAi2j8XIBW7qs7Hc1ZEBjmCoikFfi_Iw2yCGvsC1JXyB_VGOr_ak1RXCRGbBVG-VmfibHw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImJkOTQ5ZDVjZWFjMzU1MTJlNDliMWU3YzE5MTBhM2UxZjZjMjcyYzkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxNDkxL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWGxzTFRoQlgzZGFVMlpoVXpKMVZqaFdkVTFGUW5jdk4yVTNPVGN5TTJFNFltUmpOamswWmtCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDAyMTc0NDYsImlhdCI6MTcwMDEzMTA0Niwibm9uY2UiOiJSRVF5eW5lOVVqUDZLME13RlBFYlZBIiwiYXRfaGFzaCI6IlpVNlRPbzdrd1hmVy1oNTZyNXBGQlEiLCJjX2hhc2giOiJjbzJ3amRDWDBOZEhudHpkTDNXR1FBIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.yfevAqKN_8K3UGriUoMWboA72J8Izru8uXhFiott2LwAN8I0SExdvnLrDQpgq0plXITRjzfSPlOGBpnS-tT55Uh1mqxw6YxfDFqhuUFf471q_uWjuEte5zGJ8u3G_1dXqvu5UueX7Y9oh0S0GdbVY3GCv6wugta0cDfOeBkWpNT5eXq6PU4wj8whA_op7HlCnMNxmWvimX5TMqtrFBMhpHuhbeCQYICE2sL39tR3MP9armEDX13tNKjlUFuxKv8-HrYYNneDmKplyCSmAAi2j8XIBW7qs7Hc1ZEBjmCoikFfi_Iw2yCGvsC1JXyB_VGOr_ak1RXCRGbBVG-VmfibHw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImJkOTQ5ZDVjZWFjMzU1MTJlNDliMWU3YzE5
MTBhM2UxZjZjMjcyYzkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxNDkxL2RleCIsI
nN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWGxzTFRoQlgzZGFVMlpoVXpKMVZqaFdkV
TFGUW5jdk4yVTNPVGN5TTJFNFltUmpOamswWmtCM2FYSmxMbU52YlJJRWJHUmhjQ
SIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDAyMTc0NDYsImlhdCI6MTcwMDEzM
TA0Niwibm9uY2UiOiJSRVF5eW5lOVVqUDZLME13RlBFYlZBIiwiYXRfaGFzaCI6I
lpVNlRPbzdrd1hmVy1oNTZyNXBGQlEiLCJjX2hhc2giOiJjbzJ3amRDWDBOZEhud
HpkTDNXR1FBIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlL
mNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.yfevAqKN_
8K3UGriUoMWboA72J8Izru8uXhFiott2LwAN8I0SExdvnLrDQpgq0plXITRjzfSP
lOGBpnS-tT55Uh1mqxw6YxfDFqhuUFf471q_uWjuEte5zGJ8u3G_1dXqvu5UueX7
Y9oh0S0GdbVY3GCv6wugta0cDfOeBkWpNT5eXq6PU4wj8whA_op7HlCnMNxmWvim
X5TMqtrFBMhpHuhbeCQYICE2sL39tR3MP9armEDX13tNKjlUFuxKv8-HrYYNneDm
KplyCSmAAi2j8XIBW7qs7Hc1ZEBjmCoikFfi_Iw2yCGvsC1JXyB_VGOr_ak1RXCR
GbBVG-VmfibHw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "bd949d5ceac35512e49b1e7c1910a3e1f6c272c9"
}
```

```json
{
  "at_hash": "ZU6TOo7kwXfW-h56r5pFBQ",
  "aud": "wireapp",
  "c_hash": "co2wjdCX0NdHntzdL3WGQA",
  "exp": 1700217446,
  "iat": 1700131046,
  "iss": "http://dex:21491/dex",
  "name": "im:wireapp=%40alice_wire@wire.com",
  "nonce": "REQyyne9UjP6K0MwFPEbVA",
  "preferred_username": "Alice Smith",
  "sub": "CjtpbTp3aXJlYXBwPXlsLThBX3daU2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1ZKVEL7JymOS2UXrUdZh
MktwgTszV+cLLcgz79/T3CSaAOdSWqWaG7cvBzYj5R5mdEpu90Cfs1gWQinlpFKD
KlCx2LNYcYxWG35hPO7VdMwXNf35KMeaWa/YnQukYGNqrNCc8proZjq6HVEmGqDC
0wMM940tIs2gfhOgO7qEJFuTUC2iSKnBX6O68wxEEpXcCWBfvs2xuKFcRdLPZzgb
INBGryMkIEy/mAAB4BDHaykC/AQipiilIWwbltgpsawl6o8UE4ebhQ/IKip0rVbY
SLudZeo0FTC9vpnRZbVuBJfe3y1dYl95WQ+SdfcF7EXE4BprZpIw2kMpqX0x9OpQ
VQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/SDJQ76rdWuofetahvzpgljsuhCZL2pzv
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODY1L2FjbWUvd2lyZS9hY2NvdW50L1FBc3J2bVhvZ3ZjWGp0b2NPd3BQTnRJZ2Y5bGcxcU1GIiwidHlwIjoiSldUIiwibm9uY2UiOiJTR2xFYzNNelEzbFVXalpoY1dob1YzZ3dNVzgyTmsxS1l6WXpVa0pYV0VRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NjUvYWNtZS93aXJlL2NoYWxsZW5nZS9abHJCOWlLNnE3NUpsdktHSjBTbklDcFJNUkkxVWdraS9TREpRNzZyZFd1b2ZldGFodnpwZ2xqc3VoQ1pMMnB6diJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJbUprT1RRNVpEVmpaV0ZqTXpVMU1USmxORGxpTVdVM1l6RTVNVEJoTTJVeFpqWmpNamN5WXpraWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSXhORGt4TDJSbGVDSXNJbk4xWWlJNklrTnFkSEJpVkhBellWaEtiRmxZUW5kUVdHeHpURlJvUWxnelpHRlZNbHBvVlhwS01WWnFhRmRrVlRGR1VXNWpkazR5VlROUFZHTjVUVEpGTkZsdFVtcE9hbXN3V210Q00yRllTbXhNYlU1MllsSkpSV0pIVW1oalFTSXNJbUYxWkNJNkluZHBjbVZoY0hBaUxDSmxlSEFpT2pFM01EQXlNVGMwTkRZc0ltbGhkQ0k2TVRjd01ERXpNVEEwTml3aWJtOXVZMlVpT2lKU1JWRjVlVzVsT1ZWcVVEWkxNRTEzUmxCRllsWkJJaXdpWVhSZmFHRnphQ0k2SWxwVk5sUlBiemRyZDFobVZ5MW9OVFp5TlhCR1FsRWlMQ0pqWDJoaGMyZ2lPaUpqYnpKM2FtUkRXREJPWkVodWRIcGtURE5YUjFGQklpd2libUZ0WlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJa0ZzYVdObElGTnRhWFJvSW4wLnlmZXZBcUtOXzhLM1VHcmlVb01XYm9BNzJKOEl6cnU4dVhoRmlvdHQyTHdBTjhJMFNFeGR2bkxyRFFwZ3EwcGxYSVRSanpmU1BsT0dCcG5TLXRUNTVVaDFtcXh3Nll4ZkRGcWh1VUZmNDcxcV91V2p1RXRlNXpHSjh1M0dfMWRYcXZ1NVV1ZVg3WTlvaDBTMEdkYlZZM0dDdjZ3dWd0YTBjRGZPZUJrV3BOVDVlWHE2UFU0d2o4d2hBX29wN0hsQ25NTnhtV3ZpbVg1VE1xdHJGQk1ocEh1aGJlQ1FZSUNFMnNMMzl0UjNNUDlhcm1FRFgxM3ROS2psVUZ1eEt2OC1IcllZTm5lRG1LcGx5Q1NtQUFpMmo4WElCVzdxczdIYzFaRUJqbUNvaWtGZmlfSXcyeUNHdnNDMUpYeUJfVkdPcl9hazFSWENSR2JCVkctVm1maWJIdyIsImtleWF1dGgiOiJOV2NqazhEOEYzbGR1b1daR05IU1laQ3E1VWdRbUhidi4zZWliLXNkNGwzbzBaYUtXV0t5eUpMSkx4UVBPaVpZN0IwdHktYWxZRWt3In0",
  "signature": "aTsNPk2C4rSe0wbW6PzLWdXMtiww8kQ6rokYNRtWc-QOEONhEZ4eKeMCI-kJ43eGQceTm0KjJtBYk-ar9RLqCA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImJkOTQ5ZDVjZWFjMzU1MTJlNDliMWU3YzE5MTBhM2UxZjZjMjcyYzkifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxNDkxL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQWGxzTFRoQlgzZGFVMlpoVXpKMVZqaFdkVTFGUW5jdk4yVTNPVGN5TTJFNFltUmpOamswWmtCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDAyMTc0NDYsImlhdCI6MTcwMDEzMTA0Niwibm9uY2UiOiJSRVF5eW5lOVVqUDZLME13RlBFYlZBIiwiYXRfaGFzaCI6IlpVNlRPbzdrd1hmVy1oNTZyNXBGQlEiLCJjX2hhc2giOiJjbzJ3amRDWDBOZEhudHpkTDNXR1FBIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.yfevAqKN_8K3UGriUoMWboA72J8Izru8uXhFiott2LwAN8I0SExdvnLrDQpgq0plXITRjzfSPlOGBpnS-tT55Uh1mqxw6YxfDFqhuUFf471q_uWjuEte5zGJ8u3G_1dXqvu5UueX7Y9oh0S0GdbVY3GCv6wugta0cDfOeBkWpNT5eXq6PU4wj8whA_op7HlCnMNxmWvimX5TMqtrFBMhpHuhbeCQYICE2sL39tR3MP9armEDX13tNKjlUFuxKv8-HrYYNneDmKplyCSmAAi2j8XIBW7qs7Hc1ZEBjmCoikFfi_Iw2yCGvsC1JXyB_VGOr_ak1RXCRGbBVG-VmfibHw",
    "keyauth": "NWcjk8D8F3lduoWZGNHSYZCq5UgQmHbv.3eib-sd4l3o0ZaKWWKyyJLJLxQPOiZY7B0ty-alYEkw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32865/acme/wire/account/QAsrvmXogvcXjtocOwpPNtIgf9lg1qMF",
    "nonce": "SGlEc3MzQ3lUWjZhcWhoV3gwMW82Nk1KYzYzUkJXWEQ",
    "typ": "JWT",
    "url": "https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/SDJQ76rdWuofetahvzpgljsuhCZL2pzv"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32865/acme/wire/directory>;rel="index"
link: <https://stepca:32865/acme/wire/authz/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki>;rel="up"
location: https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/SDJQ76rdWuofetahvzpgljsuhCZL2pzv
replay-nonce: RU5lbjZxVzVLbW1KMlJ0Tnc3R0NmRzBmcXNDV2g3Y0Y
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32865/acme/wire/challenge/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki/SDJQ76rdWuofetahvzpgljsuhCZL2pzv",
  "status": "valid",
  "token": "NWcjk8D8F3lduoWZGNHSYZCq5UgQmHbv",
  "target": "http://dex:21491/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODY1L2FjbWUvd2lyZS9hY2NvdW50L1FBc3J2bVhvZ3ZjWGp0b2NPd3BQTnRJZ2Y5bGcxcU1GIiwidHlwIjoiSldUIiwibm9uY2UiOiJSVTVsYmpaeFZ6VkxiVzFLTWxKMFRuYzNSME5tUnpCbWNYTkRWMmczWTBZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NjUvYWNtZS93aXJlL29yZGVyL2ZydllRa01sU0pZVWgxaXpxUDQzRU1ybTZ5azJXR3RuIn0",
  "payload": "",
  "signature": "fu9NIgfiB9fN3SKCNiRfZFkjTnZuzNmmCflxFmhbFPdFSO1RMNbFNbxSVLcycNIVGJsU-WgAIXnOhbbp1zU_CQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32865/acme/wire/account/QAsrvmXogvcXjtocOwpPNtIgf9lg1qMF",
    "nonce": "RU5lbjZxVzVLbW1KMlJ0Tnc3R0NmRzBmcXNDV2g3Y0Y",
    "typ": "JWT",
    "url": "https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32865/acme/wire/directory>;rel="index"
location: https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn
replay-nonce: MVNuQnlwTmhnMmQ5SWdBZXJqNnFtTVJUdUxMRmI5U0Q
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32865/acme/wire/authz/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki"
  ],
  "expires": "2023-11-17T10:37:26Z",
  "notBefore": "2023-11-16T10:37:26.334956Z",
  "notAfter": "2033-11-13T10:37:26.334956Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODY1L2FjbWUvd2lyZS9hY2NvdW50L1FBc3J2bVhvZ3ZjWGp0b2NPd3BQTnRJZ2Y5bGcxcU1GIiwidHlwIjoiSldUIiwibm9uY2UiOiJNVk51UW5sd1RtaG5NbVE1U1dkQlpYSnFObkZ0VFZKVWRVeE1SbUk1VTBRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NjUvYWNtZS93aXJlL29yZGVyL2ZydllRa01sU0pZVWgxaXpxUDQzRU1ybTZ5azJXR3RuL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTFRDQjRBSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTm1ISzdySU9MVmhqX3ZtS21LMXFlaThEb3I4THVfRlBPblhtS0xaR0tyZm9Id3dlZ1lKS29aSWh2Y05BUWtPTVcwd2F6QnBCZ05WSFJFRVlqQmdoanRwYlRwM2FYSmxZWEJ3UFhsc0xUaEJYM2RhVTJaaFV6SjFWamhXZFUxRlFuY3ZOMlUzT1RjeU0yRTRZbVJqTmprMFprQjNhWEpsTG1OdmJZWWhhVzA2ZDJseVpXRndjRDBsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dE1BVUdBeXRsY0FOQkFDSFBZb21weTkzLUZ5NmtwcjdKVlFPTDNaS1pQRnFPZjhfaml5S1F6MlNvUGdNbTFuejZoVXRBMTNIMmtudWxqYzlsSWlyU1JidTZvbEthNjdibFdncyJ9",
  "signature": "9bZLWvoQBIOWODf6MTc3jLAcRAbgr8i1gZeowLYRgmU9ETXp5_NDX6Y6kz0Qm8tQtumhMYOzkRJPaY3s5rmwCg"
}
```
```json
{
  "payload": {
    "csr": "MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhANmHK7rIOLVhj_vmKmK1qei8Dor8Lu_FPOnXmKLZGKrfoHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJlYXBwPXlsLThBX3daU2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJlLmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANBACHPYompy93-Fy6kpr7JVQOL3ZKZPFqOf8_jiyKQz2SoPgMm1nz6hUtA13H2knuljc9lIirSRbu6olKa67blWgs"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32865/acme/wire/account/QAsrvmXogvcXjtocOwpPNtIgf9lg1qMF",
    "nonce": "MVNuQnlwTmhnMmQ5SWdBZXJqNnFtTVJUdUxMRmI5U0Q",
    "typ": "JWT",
    "url": "https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhANmHK7rIOLVhj/vmKmK1qei8Dor8Lu/F
POnXmKLZGKrfoHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJl
YXBwPXlsLThBX3daU2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJl
LmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANB
ACHPYompy93+Fy6kpr7JVQOL3ZKZPFqOf8/jiyKQz2SoPgMm1nz6hUtA13H2knul
jc9lIirSRbu6olKa67blWgs=
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
                    d9:87:2b:ba:c8:38:b5:61:8f:fb:e6:2a:62:b5:a9:
                    e8:bc:0e:8a:fc:2e:ef:c5:3c:e9:d7:98:a2:d9:18:
                    aa:df
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com, URI:im:wireapp=%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        21:cf:62:89:a9:cb:dd:fe:17:2e:a4:a6:be:c9:55:03:8b:dd:
        92:99:3c:5a:8e:7f:cf:e3:8b:22:90:cf:64:a8:3e:03:26:d6:
        7c:fa:85:4b:40:d7:71:f6:92:7b:a5:8d:cf:65:22:2a:d2:45:
        bb:ba:a2:52:9a:eb:b6:e5:5a:0b

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32865/acme/wire/directory>;rel="index"
location: https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn
replay-nonce: S2RwalpyUmc1MEZjWnRRdTRMQ2tYcUNVbXhDY1V1Z20
```
```json
{
  "certificate": "https://stepca:32865/acme/wire/certificate/SovyprYoMfROGmEbACsGVLwvn2A0h5j9",
  "status": "valid",
  "finalize": "https://stepca:32865/acme/wire/order/frvYQkMlSJYUh1izqP43EMrm6yk2WGtn/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32865/acme/wire/authz/ZlrB9iK6q75JlvKGJ0SnICpRMRI1Ugki"
  ],
  "expires": "2023-11-17T10:37:26Z",
  "notBefore": "2023-11-16T10:37:26.334956Z",
  "notAfter": "2033-11-13T10:37:26.334956Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32865/acme/wire/certificate/SovyprYoMfROGmEbACsGVLwvn2A0h5j9
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODY1L2FjbWUvd2lyZS9hY2NvdW50L1FBc3J2bVhvZ3ZjWGp0b2NPd3BQTnRJZ2Y5bGcxcU1GIiwidHlwIjoiSldUIiwibm9uY2UiOiJTMlJ3YWxweVVtYzFNRVpqV25SUmRUUk1RMnRZY1VOVmJYaERZMVYxWjIwIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NjUvYWNtZS93aXJlL2NlcnRpZmljYXRlL1NvdnlwcllvTWZST0dtRWJBQ3NHVkx3dm4yQTBoNWo5In0",
  "payload": "",
  "signature": "cb_v7fS9OxXP878nxrb3qLL4rajrZqwX3Ol5WxCQC7cGANmRHbsDT57k4ugi2XkHRO_5dkbekktcwo6NZXQUAQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32865/acme/wire/account/QAsrvmXogvcXjtocOwpPNtIgf9lg1qMF",
    "nonce": "S2RwalpyUmc1MEZjWnRRdTRMQ2tYcUNVbXhDY1V1Z20",
    "typ": "JWT",
    "url": "https://stepca:32865/acme/wire/certificate/SovyprYoMfROGmEbACsGVLwvn2A0h5j9"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32865/acme/wire/directory>;rel="index"
replay-nonce: VXJtMU9Yd1B6SVZJeUxJRzhFY2VKZkhETkQzSUQzSUo
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGDCCAb+gAwIBAgIQHhoe3LLRoHP+EPY4KOTgATAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzExMTYxMDM3MjZaFw0zMzExMTMxMDM3MjZaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhANmHK7rIOLVhj/vmKmK1\nqei8Dor8Lu/FPOnXmKLZGKrfo4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUFlquvWRvc3MxFaLrNgzv+UdGoaswHwYD\nVR0jBBgwFoAUz40pQ/qEp4eFDfctCF0jmJB+5xswaQYDVR0RBGIwYIYhaW06d2ly\nZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29thjtpbTp3aXJlYXBwPXlsLThBX3da\nU2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJlLmNvbTAdBgwrBgEE\nAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgRqbsOAF7\nOseMTgkjrKe3UO/UjDUGzW+jlDWOGLZsh5ECIDdNastqkvwOGfbWaeh+IuM6/oBz\nflIOs9TQGOVc0YL1\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRALZ7S0CrN0AU7he5I5RE7kUwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMTExNjEw\nMzcyNFoXDTMzMTExMzEwMzcyNFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARX\nN+Bn/11sYUO48us2X+JrOBMXf/Gn9kV1D+fp1SQ3JzQl/KEwmtG3OJHB6ljtQiIF\nQTKP2xV8Zu9vK1Z8zD43o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUz40pQ/qEp4eFDfctCF0jmJB+5xswHwYDVR0jBBgw\nFoAUCseuIlZpBnsVzFcCJvAXBodYgo0wCgYIKoZIzj0EAwIDSAAwRQIgfR0sHfuG\nN2EBypbVEz5g7zRMQsbKCUxUAW5cNiEc9IICIQDCDymSCXPFRw1QNv/7WQXATH1L\nhQc4PK0oC9I4QpceyA==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICGDCCAb+gAwIBAgIQHhoe3LLRoHP+EPY4KOTgATAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
MzExMTYxMDM3MjZaFw0zMzExMTMxMDM3MjZaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhANmHK7rIOLVhj/vmKmK1
qei8Dor8Lu/FPOnXmKLZGKrfo4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUFlquvWRvc3MxFaLrNgzv+UdGoaswHwYD
VR0jBBgwFoAUz40pQ/qEp4eFDfctCF0jmJB+5xswaQYDVR0RBGIwYIYhaW06d2ly
ZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29thjtpbTp3aXJlYXBwPXlsLThBX3da
U2ZhUzJ1VjhWdU1FQncvN2U3OTcyM2E4YmRjNjk0ZkB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgRqbsOAF7
OseMTgkjrKe3UO/UjDUGzW+jlDWOGLZsh5ECIDdNastqkvwOGfbWaeh+IuM6/oBz
flIOs9TQGOVc0YL1
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1e:1a:1e:dc:b2:d1:a0:73:fe:10:f6:38:28:e4:e0:01
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Nov 16 10:37:26 2023 GMT
            Not After : Nov 13 10:37:26 2033 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    d9:87:2b:ba:c8:38:b5:61:8f:fb:e6:2a:62:b5:a9:
                    e8:bc:0e:8a:fc:2e:ef:c5:3c:e9:d7:98:a2:d9:18:
                    aa:df
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                16:5A:AE:BD:64:6F:73:73:31:15:A2:EB:36:0C:EF:F9:47:46:A1:AB
            X509v3 Authority Key Identifier: 
                CF:8D:29:43:FA:84:A7:87:85:0D:F7:2D:08:5D:23:98:90:7E:E7:1B
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=%40alice_wire@wire.com, URI:im:wireapp=yl-8A_wZSfaS2uV8VuMEBw/7e79723a8bdc694f@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:46:a6:ec:38:01:7b:3a:c7:8c:4e:09:23:ac:a7:
        b7:50:ef:d4:8c:35:06:cd:6f:a3:94:35:8e:18:b6:6c:87:91:
        02:20:37:4d:6a:cb:6a:92:fc:0e:19:f6:d6:69:e8:7e:22:e3:
        3a:fe:80:73:7e:52:0e:b3:d4:d0:18:e5:5c:d1:82:f5

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRALZ7S0CrN0AU7he5I5RE7kUwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMTExNjEw
MzcyNFoXDTMzMTExMzEwMzcyNFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARX
N+Bn/11sYUO48us2X+JrOBMXf/Gn9kV1D+fp1SQ3JzQl/KEwmtG3OJHB6ljtQiIF
QTKP2xV8Zu9vK1Z8zD43o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUz40pQ/qEp4eFDfctCF0jmJB+5xswHwYDVR0jBBgw
FoAUCseuIlZpBnsVzFcCJvAXBodYgo0wCgYIKoZIzj0EAwIDSAAwRQIgfR0sHfuG
N2EBypbVEz5g7zRMQsbKCUxUAW5cNiEc9IICIQDCDymSCXPFRw1QNv/7WQXATH1L
hQc4PK0oC9I4QpceyA==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            b6:7b:4b:40:ab:37:40:14:ee:17:b9:23:94:44:ee:45
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Nov 16 10:37:24 2023 GMT
            Not After : Nov 13 10:37:24 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:57:37:e0:67:ff:5d:6c:61:43:b8:f2:eb:36:5f:
                    e2:6b:38:13:17:7f:f1:a7:f6:45:75:0f:e7:e9:d5:
                    24:37:27:34:25:fc:a1:30:9a:d1:b7:38:91:c1:ea:
                    58:ed:42:22:05:41:32:8f:db:15:7c:66:ef:6f:2b:
                    56:7c:cc:3e:37
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                CF:8D:29:43:FA:84:A7:87:85:0D:F7:2D:08:5D:23:98:90:7E:E7:1B
            X509v3 Authority Key Identifier: 
                0A:C7:AE:22:56:69:06:7B:15:CC:57:02:26:F0:17:06:87:58:82:8D
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:7d:1d:2c:1d:fb:86:37:61:01:ca:96:d5:13:3e:
        60:ef:34:4c:42:c6:ca:09:4c:54:01:6e:5c:36:21:1c:f4:82:
        02:21:00:c2:0f:29:92:09:73:c5:47:0d:50:36:ff:fb:59:05:
        c0:4c:7d:4b:85:07:38:3c:ad:28:0b:d2:38:42:97:1e:c8

```
