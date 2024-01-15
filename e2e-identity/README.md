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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/c7ddbab1a5225de1/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/0cSO2qsiV3grbpg9VN56vlr32RB4rLf4
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/nRHOLoqoWZHI6CGGORPT3ibdevmdUEz4
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/iRBWw7qQq4v0vzo9sBGWya6v31jD5mRL
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
vary: Origin
```
```json
{
  "newNonce": "https://stepca:32795/acme/wire/new-nonce",
  "newAccount": "https://stepca:32795/acme/wire/new-account",
  "newOrder": "https://stepca:32795/acme/wire/new-order",
  "revokeCert": "https://stepca:32795/acme/wire/revoke-cert"
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
replay-nonce: MlhwTVZrOEgwN2xZTnZqQnRTR2dwVFlBdXNsSXQ4S0g
vary: Origin
```
```text
MlhwTVZrOEgwN2xZTnZqQnRTR2dwVFlBdXNsSXQ4S0g
```
#### 5. create a new account
```http request
POST https://stepca:32795/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjNXZzZEamJvWnpFZEZUdHRvVGlULWJTdUM5NzVQcWpxUlhZa2ZwU2tYbEEifSwibm9uY2UiOiJNbGh3VFZack9FZ3dOMnhaVG5acVFuUlRSMmR3VkZsQmRYTnNTWFE0UzBnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "X2Wcwe2fe_X6qcfNBkiSrKUe2sjKk1gIipHQsg23qS4QbZ-osY0CwFCZF-l-azpNDjywFZ1HNPtwf-fxBtRmDg"
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
      "x": "3Wg6DjboZzEdFTttoTiT-bSuC975PqjqRXYkfpSkXlA"
    },
    "nonce": "MlhwTVZrOEgwN2xZTnZqQnRTR2dwVFlBdXNsSXQ4S0g",
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
location: https://stepca:32795/acme/wire/account/Z9pcI6iMTzA1TELu1INslFx6EthReoVE
replay-nonce: Z2ZIbVU4SEViM0ZZMzB1UmxramMxUG5ybnRpWGlJR0M
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32795/acme/wire/account/Z9pcI6iMTzA1TELu1INslFx6EthReoVE/orders"
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
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L1o5cGNJNmlNVHpBMVRFTHUxSU5zbEZ4NkV0aFJlb1ZFIiwidHlwIjoiSldUIiwibm9uY2UiOiJaMlpJYlZVNFNFVmlNMFpaTXpCMVVteHJhbU14VUc1eWJuUnBXR2xKUjBNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9JUjBfSU10Q1RMaTNhczVFb0NCd1hnIWM3ZGRiYWIxYTUyMjVkZTFAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIn0ifV0sIm5vdEJlZm9yZSI6IjIwMjQtMDEtMTVUMTY6Mjc6MjkuMjMzNzI1WiIsIm5vdEFmdGVyIjoiMjAzNC0wMS0xMlQxNjoyNzoyOS4yMzM3MjVaIn0",
  "signature": "oKj1BZSyGxh-FpUY5b0VabgM_NW27BR4pxkzSG-w2NEsUJt3YU0cVRuPmh2J2DNyQOFFV02qraIcgDGnh_X_Dw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://IR0_IMtCTLi3as5EoCBwXg!c7ddbab1a5225de1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2034-01-12T16:27:29.233725Z",
    "notBefore": "2024-01-15T16:27:29.233725Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/Z9pcI6iMTzA1TELu1INslFx6EthReoVE",
    "nonce": "Z2ZIbVU4SEViM0ZZMzB1UmxramMxUG5ybnRpWGlJR0M",
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
location: https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV
replay-nonce: SmdsY2k2c1J4OTVGQ3F4SHc4UXR2M3BQNEJPR3ZGVU0
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://IR0_IMtCTLi3as5EoCBwXg!c7ddbab1a5225de1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32795/acme/wire/authz/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o"
  ],
  "expires": "2024-01-16T16:27:29Z",
  "notBefore": "2024-01-15T16:27:29.233725Z",
  "notAfter": "2034-01-12T16:27:29.233725Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32795/acme/wire/authz/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L1o5cGNJNmlNVHpBMVRFTHUxSU5zbEZ4NkV0aFJlb1ZFIiwidHlwIjoiSldUIiwibm9uY2UiOiJTbWRzWTJrMmMxSjRPVFZHUTNGNFNIYzRVWFIyTTNCUU5FSlBSM1pHVlUwIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL2F1dGh6L1JPMWxOMEZpWUl1ZDFyWlo2RTN1aVk1ZVJkbmpWRTBvIn0",
  "payload": "",
  "signature": "Bm1OjB1JS-BCrmpQpSyVxG4Jb7lScCO0SVQTjqpcHsmS5R3kPh1jPM0qYlHb3ZE8Ot50J2kPdj1W1g5yH9zmDQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/Z9pcI6iMTzA1TELu1INslFx6EthReoVE",
    "nonce": "SmdsY2k2c1J4OTVGQ3F4SHc4UXR2M3BQNEJPR3ZGVU0",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/authz/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
location: https://stepca:32795/acme/wire/authz/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o
replay-nonce: b3NIR3J1bkt3aUpBd3g5eHVoZ003SW9EZjlUNmp2ekE
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2024-01-16T16:27:29Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/nRHOLoqoWZHI6CGGORPT3ibdevmdUEz4",
      "status": "pending",
      "token": "25xCjZl0wgv1jCU4Iu6HdtosB6yYvuSc",
      "target": "http://dex:21126/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/0cSO2qsiV3grbpg9VN56vlr32RB4rLf4",
      "status": "pending",
      "token": "25xCjZl0wgv1jCU4Iu6HdtosB6yYvuSc",
      "target": "http://wire.com:22504/clients/c7ddbab1a5225de1/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://IR0_IMtCTLi3as5EoCBwXg!c7ddbab1a5225de1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:22504/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
b0tVOGw5dkpxcDFabWNnWEJBck5keUN2R3RzRUtLdjk
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiM1dnNkRqYm9aekVkRlR0dG9UaVQtYlN1Qzk3NVBxanFSWFlrZnBTa1hsQSJ9fQ.eyJpYXQiOjE3MDUzMzI0NDksImV4cCI6MTcwNTMzOTY0OSwibmJmIjoxNzA1MzMyNDQ5LCJzdWIiOiJ3aXJlYXBwOi8vSVIwX0lNdENUTGkzYXM1RW9DQndYZyFjN2RkYmFiMWE1MjI1ZGUxQHdpcmUuY29tIiwianRpIjoiYzhhODU4Y2YtODQzZi00NGRjLWFmZmYtNzVkMDEyZmMzZjNlIiwibm9uY2UiOiJiMHRWT0d3NWRrcHhjREZhYldObldFSkJjazVrZVVOMlIzUnpSVXRMZGprIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMjUwNC9jbGllbnRzL2M3ZGRiYWIxYTUyMjVkZTEvYWNjZXNzLXRva2VuIiwiY2hhbCI6IjI1eENqWmwwd2d2MWpDVTRJdTZIZHRvc0I2eVl2dVNjIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.MxVAvDCKEGirsVsuBSy8CR2QJScskGliZ7L7EjqOzYJlt86-SXQ8g-JJKFkHWkos_tmUo4KeN5AWermww2wYDg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiM1dnNkRqYm9aekVkRlR0dG9UaVQtYlN1
Qzk3NVBxanFSWFlrZnBTa1hsQSJ9fQ.eyJpYXQiOjE3MDUzMzI0NDksImV4cCI6M
TcwNTMzOTY0OSwibmJmIjoxNzA1MzMyNDQ5LCJzdWIiOiJ3aXJlYXBwOi8vSVIwX
0lNdENUTGkzYXM1RW9DQndYZyFjN2RkYmFiMWE1MjI1ZGUxQHdpcmUuY29tIiwia
nRpIjoiYzhhODU4Y2YtODQzZi00NGRjLWFmZmYtNzVkMDEyZmMzZjNlIiwibm9uY
2UiOiJiMHRWT0d3NWRrcHhjREZhYldObldFSkJjazVrZVVOMlIzUnpSVXRMZGprI
iwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMjUwNC9jbGllb
nRzL2M3ZGRiYWIxYTUyMjVkZTEvYWNjZXNzLXRva2VuIiwiY2hhbCI6IjI1eENqW
mwwd2d2MWpDVTRJdTZIZHRvc0I2eVl2dVNjIiwiaGFuZGxlIjoid2lyZWFwcDovL
yU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.MxVAvDCKEGir
sVsuBSy8CR2QJScskGliZ7L7EjqOzYJlt86-SXQ8g-JJKFkHWkos_tmUo4KeN5AW
ermww2wYDg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "3Wg6DjboZzEdFTttoTiT-bSuC975PqjqRXYkfpSkXlA"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "25xCjZl0wgv1jCU4Iu6HdtosB6yYvuSc",
  "exp": 1705339649,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:22504/clients/c7ddbab1a5225de1/access-token",
  "iat": 1705332449,
  "jti": "c8a858cf-843f-44dc-afff-75d012fc3f3e",
  "nbf": 1705332449,
  "nonce": "b0tVOGw5dkpxcDFabWNnWEJBck5keUN2R3RzRUtLdjk",
  "sub": "wireapp://IR0_IMtCTLi3as5EoCBwXg!c7ddbab1a5225de1@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIC2cE83MfmM/IqOCWPFNBnzNnLbYkQF6MDu6RK/5VYWI
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA3Wg6DjboZzEdFTttoTiT+bSuC975PqjqRXYkfpSkXlA=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:22504/clients/c7ddbab1a5225de1/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTTFkbk5rUnFZbTlhZWtWa1JsUjBkRzlVYVZRdFlsTjFRemszTlZCeGFuRlNXRmxyWm5CVGExaHNRU0o5ZlEuZXlKcFlYUWlPakUzTURVek16STBORGtzSW1WNGNDSTZNVGN3TlRNek9UWTBPU3dpYm1KbUlqb3hOekExTXpNeU5EUTVMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWXpoaE9EVTRZMll0T0RRelppMDBOR1JqTFdGbVptWXROelZrTURFeVptTXpaak5sSWl3aWJtOXVZMlVpT2lKaU1IUldUMGQzTldScmNIaGpSRVpoWWxkT2JsZEZTa0pqYXpWclpWVk9NbEl6VW5wU1ZYUk1aR3BySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1qVXdOQzlqYkdsbGJuUnpMMk0zWkdSaVlXSXhZVFV5TWpWa1pURXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWpJMWVFTnFXbXd3ZDJkMk1XcERWVFJKZFRaSVpIUnZjMEkyZVZsMmRWTmpJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5NeFZBdkRDS0VHaXJzVnN1QlN5OENSMlFKU2Nza0dsaVo3TDdFanFPellKbHQ4Ni1TWFE4Zy1KSktGa0hXa29zX3RtVW80S2VONUFXZXJtd3cyd1lEZw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjlydDJMVHVyeTRJQTFZZExVYU4zT1JYUzRtZVlZTmhybWMtcXVYWUcxQjAifX0.eyJpYXQiOjE3MDUzMzI0NDksImV4cCI6MTcwNTMzNjQwOSwibmJmIjoxNzA1MzMyNDQ5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjI1MDQvY2xpZW50cy9jN2RkYmFiMWE1MjI1ZGUxL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9JUjBfSU10Q1RMaTNhczVFb0NCd1hnIWM3ZGRiYWIxYTUyMjVkZTFAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjI1MDQvY2xpZW50cy9jN2RkYmFiMWE1MjI1ZGUxL2FjY2Vzcy10b2tlbiIsImp0aSI6ImI0N2MwYmFlLWM1OGMtNGI3ZC05YTA0LTVhNWFkMWVlMDhjYiIsIm5vbmNlIjoiYjB0Vk9HdzVka3B4Y0RGYWJXTm5XRUpCY2s1a2VVTjJSM1J6UlV0TGRqayIsImNoYWwiOiIyNXhDalpsMHdndjFqQ1U0SXU2SGR0b3NCNnlZdnVTYyIsImNuZiI6eyJraWQiOiJTU3htTVBJanhaWC1lRHhBa1JreDhjWEpoRE1XUlRHTGhGNXV5VmVqUDRvIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTTFkbk5rUnFZbTlhZWtWa1JsUjBkRzlVYVZRdFlsTjFRemszTlZCeGFuRlNXRmxyWm5CVGExaHNRU0o5ZlEuZXlKcFlYUWlPakUzTURVek16STBORGtzSW1WNGNDSTZNVGN3TlRNek9UWTBPU3dpYm1KbUlqb3hOekExTXpNeU5EUTVMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWXpoaE9EVTRZMll0T0RRelppMDBOR1JqTFdGbVptWXROelZrTURFeVptTXpaak5sSWl3aWJtOXVZMlVpT2lKaU1IUldUMGQzTldScmNIaGpSRVpoWWxkT2JsZEZTa0pqYXpWclpWVk9NbEl6VW5wU1ZYUk1aR3BySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1qVXdOQzlqYkdsbGJuUnpMMk0zWkdSaVlXSXhZVFV5TWpWa1pURXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWpJMWVFTnFXbXd3ZDJkMk1XcERWVFJKZFRaSVpIUnZjMEkyZVZsMmRWTmpJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5NeFZBdkRDS0VHaXJzVnN1QlN5OENSMlFKU2Nza0dsaVo3TDdFanFPellKbHQ4Ni1TWFE4Zy1KSktGa0hXa29zX3RtVW80S2VONUFXZXJtd3cyd1lEZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9JUjBfSU10Q1RMaTNhczVFb0NCd1hnIWM3ZGRiYWIxYTUyMjVkZTFAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.gn9AhrsnwaVKLnSCg3SAlClc37Ywj85Uz8P3uMlO_mpw6HUAKEkPBMMunSfnhwd3tCiynne5_u4HBcVD3HwiAA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjlydDJMVHVyeTRJQTFZZExVYU4zT1JYUzRtZVlZTmhybWMtcXVYWUcxQjAifX0.eyJpYXQiOjE3MDUzMzI0NDksImV4cCI6MTcwNTMzNjQwOSwibmJmIjoxNzA1MzMyNDQ5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjI1MDQvY2xpZW50cy9jN2RkYmFiMWE1MjI1ZGUxL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9JUjBfSU10Q1RMaTNhczVFb0NCd1hnIWM3ZGRiYWIxYTUyMjVkZTFAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjI1MDQvY2xpZW50cy9jN2RkYmFiMWE1MjI1ZGUxL2FjY2Vzcy10b2tlbiIsImp0aSI6ImI0N2MwYmFlLWM1OGMtNGI3ZC05YTA0LTVhNWFkMWVlMDhjYiIsIm5vbmNlIjoiYjB0Vk9HdzVka3B4Y0RGYWJXTm5XRUpCY2s1a2VVTjJSM1J6UlV0TGRqayIsImNoYWwiOiIyNXhDalpsMHdndjFqQ1U0SXU2SGR0b3NCNnlZdnVTYyIsImNuZiI6eyJraWQiOiJTU3htTVBJanhaWC1lRHhBa1JreDhjWEpoRE1XUlRHTGhGNXV5VmVqUDRvIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTTFkbk5rUnFZbTlhZWtWa1JsUjBkRzlVYVZRdFlsTjFRemszTlZCeGFuRlNXRmxyWm5CVGExaHNRU0o5ZlEuZXlKcFlYUWlPakUzTURVek16STBORGtzSW1WNGNDSTZNVGN3TlRNek9UWTBPU3dpYm1KbUlqb3hOekExTXpNeU5EUTVMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWXpoaE9EVTRZMll0T0RRelppMDBOR1JqTFdGbVptWXROelZrTURFeVptTXpaak5sSWl3aWJtOXVZMlVpT2lKaU1IUldUMGQzTldScmNIaGpSRVpoWWxkT2JsZEZTa0pqYXpWclpWVk9NbEl6VW5wU1ZYUk1aR3BySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1qVXdOQzlqYkdsbGJuUnpMMk0zWkdSaVlXSXhZVFV5TWpWa1pURXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWpJMWVFTnFXbXd3ZDJkMk1XcERWVFJKZFRaSVpIUnZjMEkyZVZsMmRWTmpJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5NeFZBdkRDS0VHaXJzVnN1QlN5OENSMlFKU2Nza0dsaVo3TDdFanFPellKbHQ4Ni1TWFE4Zy1KSktGa0hXa29zX3RtVW80S2VONUFXZXJtd3cyd1lEZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9JUjBfSU10Q1RMaTNhczVFb0NCd1hnIWM3ZGRiYWIxYTUyMjVkZTFAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.gn9AhrsnwaVKLnSCg3SAlClc37Ywj85Uz8P3uMlO_mpw6HUAKEkPBMMunSfnhwd3tCiynne5_u4HBcVD3HwiAA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IjlydDJMVHVyeTRJQTFZZExVYU4zT1JYUzRt
ZVlZTmhybWMtcXVYWUcxQjAifX0.eyJpYXQiOjE3MDUzMzI0NDksImV4cCI6MTcw
NTMzNjQwOSwibmJmIjoxNzA1MzMyNDQ5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjI1MDQvY2xpZW50cy9jN2RkYmFiMWE1MjI1ZGUxL2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9JUjBfSU10Q1RMaTNhczVFb0NCd1hnIWM3ZGRiYWIxYTUy
MjVkZTFAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjI1MDQvY2xp
ZW50cy9jN2RkYmFiMWE1MjI1ZGUxL2FjY2Vzcy10b2tlbiIsImp0aSI6ImI0N2Mw
YmFlLWM1OGMtNGI3ZC05YTA0LTVhNWFkMWVlMDhjYiIsIm5vbmNlIjoiYjB0Vk9H
dzVka3B4Y0RGYWJXTm5XRUpCY2s1a2VVTjJSM1J6UlV0TGRqayIsImNoYWwiOiIy
NXhDalpsMHdndjFqQ1U0SXU2SGR0b3NCNnlZdnVTYyIsImNuZiI6eyJraWQiOiJT
U3htTVBJanhaWC1lRHhBa1JreDhjWEpoRE1XUlRHTGhGNXV5VmVqUDRvIn0sInBy
b29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElp
d2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxD
SjRJam9pTTFkbk5rUnFZbTlhZWtWa1JsUjBkRzlVYVZRdFlsTjFRemszTlZCeGFu
RlNXRmxyWm5CVGExaHNRU0o5ZlEuZXlKcFlYUWlPakUzTURVek16STBORGtzSW1W
NGNDSTZNVGN3TlRNek9UWTBPU3dpYm1KbUlqb3hOekExTXpNeU5EUTVMQ0p6ZFdJ
aU9pSjNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlG
ak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWXpo
aE9EVTRZMll0T0RRelppMDBOR1JqTFdGbVptWXROelZrTURFeVptTXpaak5sSWl3
aWJtOXVZMlVpT2lKaU1IUldUMGQzTldScmNIaGpSRVpoWWxkT2JsZEZTa0pqYXpW
clpWVk9NbEl6VW5wU1ZYUk1aR3BySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJ
NkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1qVXdOQzlqYkdsbGJuUnpMMk0zWkdS
aVlXSXhZVFV5TWpWa1pURXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWpJ
MWVFTnFXbXd3ZDJkMk1XcERWVFJKZFRaSVpIUnZjMEkyZVZsMmRWTmpJaXdpYUdG
dVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1
amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5NeFZBdkRDS0VHaXJzVnN1QlN5OENS
MlFKU2Nza0dsaVo3TDdFanFPellKbHQ4Ni1TWFE4Zy1KSktGa0hXa29zX3RtVW80
S2VONUFXZXJtd3cyd1lEZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9JUjBfSU10
Q1RMaTNhczVFb0NCd1hnIWM3ZGRiYWIxYTUyMjVkZTFAd2lyZS5jb20iLCJhcGlf
dmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.gn9AhrsnwaVKLnS
Cg3SAlClc37Ywj85Uz8P3uMlO_mpw6HUAKEkPBMMunSfnhwd3tCiynne5_u4HBcV
D3HwiAA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "9rt2LTury4IA1YdLUaN3ORXS4meYYNhrmc-quXYG1B0"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:22504/clients/c7ddbab1a5225de1/access-token",
  "chal": "25xCjZl0wgv1jCU4Iu6HdtosB6yYvuSc",
  "client_id": "wireapp://IR0_IMtCTLi3as5EoCBwXg!c7ddbab1a5225de1@wire.com",
  "cnf": {
    "kid": "SSxmMPIjxZX-eDxAkRkx8cXJhDMWRTGLhF5uyVejP4o"
  },
  "exp": 1705336409,
  "iat": 1705332449,
  "iss": "http://wire.com:22504/clients/c7ddbab1a5225de1/access-token",
  "jti": "b47c0bae-c58c-4b7d-9a04-5a5ad1ee08cb",
  "nbf": 1705332449,
  "nonce": "b0tVOGw5dkpxcDFabWNnWEJBck5keUN2R3RzRUtLdjk",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiM1dnNkRqYm9aekVkRlR0dG9UaVQtYlN1Qzk3NVBxanFSWFlrZnBTa1hsQSJ9fQ.eyJpYXQiOjE3MDUzMzI0NDksImV4cCI6MTcwNTMzOTY0OSwibmJmIjoxNzA1MzMyNDQ5LCJzdWIiOiJ3aXJlYXBwOi8vSVIwX0lNdENUTGkzYXM1RW9DQndYZyFjN2RkYmFiMWE1MjI1ZGUxQHdpcmUuY29tIiwianRpIjoiYzhhODU4Y2YtODQzZi00NGRjLWFmZmYtNzVkMDEyZmMzZjNlIiwibm9uY2UiOiJiMHRWT0d3NWRrcHhjREZhYldObldFSkJjazVrZVVOMlIzUnpSVXRMZGprIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMjUwNC9jbGllbnRzL2M3ZGRiYWIxYTUyMjVkZTEvYWNjZXNzLXRva2VuIiwiY2hhbCI6IjI1eENqWmwwd2d2MWpDVTRJdTZIZHRvc0I2eVl2dVNjIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.MxVAvDCKEGirsVsuBSy8CR2QJScskGliZ7L7EjqOzYJlt86-SXQ8g-JJKFkHWkos_tmUo4KeN5AWermww2wYDg",
  "scope": "wire_client_id",
  "sub": "wireapp://IR0_IMtCTLi3as5EoCBwXg!c7ddbab1a5225de1@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIKN5EgaKqpnMIHcS7QWSZ/S0sF/e1lAX7d+caj2SLVg/
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA9rt2LTury4IA1YdLUaN3ORXS4meYYNhrmc+quXYG1B0=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/0cSO2qsiV3grbpg9VN56vlr32RB4rLf4
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L1o5cGNJNmlNVHpBMVRFTHUxSU5zbEZ4NkV0aFJlb1ZFIiwidHlwIjoiSldUIiwibm9uY2UiOiJiM05JUjNKMWJrdDNhVXBCZDNnNWVIVm9aMDAzU1c5RVpqbFVObXAyZWtFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL2NoYWxsZW5nZS9STzFsTjBGaVlJdWQxclpaNkUzdWlZNWVSZG5qVkUwby8wY1NPMnFzaVYzZ3JicGc5Vk41NnZscjMyUkI0ckxmNCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklqbHlkREpNVkhWeWVUUkpRVEZaWkV4VllVNHpUMUpZVXpSdFpWbFpUbWh5YldNdGNYVllXVWN4UWpBaWZYMC5leUpwWVhRaU9qRTNNRFV6TXpJME5Ea3NJbVY0Y0NJNk1UY3dOVE16TmpRd09Td2libUptSWpveE56QTFNek15TkRRNUxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJMU1EUXZZMnhwWlc1MGN5OWpOMlJrWW1GaU1XRTFNakkxWkdVeEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTlKVWpCZlNVMTBRMVJNYVROaGN6VkZiME5DZDFobklXTTNaR1JpWVdJeFlUVXlNalZrWlRGQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpJMU1EUXZZMnhwWlc1MGN5OWpOMlJrWW1GaU1XRTFNakkxWkdVeEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1wMGFTSTZJbUkwTjJNd1ltRmxMV00xT0dNdE5HSTNaQzA1WVRBMExUVmhOV0ZrTVdWbE1EaGpZaUlzSW01dmJtTmxJam9pWWpCMFZrOUhkelZrYTNCNFkwUkdZV0pYVG01WFJVcENZMnMxYTJWVlRqSlNNMUo2VWxWMFRHUnFheUlzSW1Ob1lXd2lPaUl5TlhoRGFscHNNSGRuZGpGcVExVTBTWFUyU0dSMGIzTkNObmxaZG5WVFl5SXNJbU51WmlJNmV5SnJhV1FpT2lKVFUzaHRUVkJKYW5oYVdDMWxSSGhCYTFKcmVEaGpXRXBvUkUxWFVsUkhUR2hHTlhWNVZtVnFVRFJ2SW4wc0luQnliMjltSWpvaVpYbEthR0pIWTJsUGFVcEdXa1ZTVkZGVFNYTkpibEkxWTBOSk5rbHRVbmRpTTBGeVlXNWtNRWxwZDJsaGJtUnlTV3B3TjBsdGREQmxVMGsyU1dzNVRGVkRTWE5KYlU1NVpHbEpOa2xyVm10TmFsVXhUVlJyYVV4RFNqUkphbTlwVFRGa2JrNXJVbkZaYlRsaFpXdFdhMUpzVWpCa1J6bFZZVlpSZEZsc1RqRlJlbXN6VGxaQ2VHRnVSbE5YUm14eVdtNUNWR0V4YUhOUlUwbzVabEV1WlhsS2NGbFlVV2xQYWtVelRVUlZlazE2U1RCT1JHdHpTVzFXTkdORFNUWk5WR04zVGxSTmVrOVVXVEJQVTNkcFltMUtiVWxxYjNoT2VrRXhUWHBOZVU1RVVUVk1RMHA2WkZkSmFVOXBTak5oV0Vwc1dWaENkMDlwT0haVFZrbDNXREJzVG1SRlRsVlVSMnQ2V1ZoTk1WSlhPVVJSYm1SWldubEdhazR5VW10WmJVWnBUVmRGTVUxcVNURmFSMVY0VVVoa2NHTnRWWFZaTWpsMFNXbDNhV0Z1VW5CSmFtOXBXWHBvYUU5RVZUUlpNbGwwVDBSUmVscHBNREJPUjFKcVRGZEdiVnB0V1hST2VsWnJUVVJGZVZwdFRYcGFhazVzU1dsM2FXSnRPWFZaTWxWcFQybEthVTFJVWxkVU1HUXpUbGRTY21OSWFHcFNSVnBvV1d4a1QySnNaRVpUYTBwcVlYcFdjbHBXVms5TmJFbDZWVzV3VTFaWVVrMWFSM0J5U1dsM2FXRklVblJKYW05cFZVVTVWRlpEU1hOSmJXZ3daRk5KTmtsdGFEQmtTRUUyVEhrNU0yRllTbXhNYlU1MllsUnZlVTFxVlhkT1F6bHFZa2RzYkdKdVVucE1NazB6V2tkU2FWbFhTWGhaVkZWNVRXcFdhMXBVUlhaWlYwNXFXbGhPZWt4WVVuWmhNbFoxU1dsM2FWa3lhR2hpUTBrMlNXcEpNV1ZGVG5GWGJYZDNaREprTWsxWGNFUldWRkpLWkZSYVNWcElVblpqTUVreVpWWnNNbVJXVG1wSmFYZHBZVWRHZFZwSGVHeEphbTlwWkRKc2VWcFhSbmRqUkc5MlRIbFZNRTFIUm5OaFYwNXNXRE5rY0dOdFZrRmtNbXg1V2xNMWFtSXlNR2xNUTBvd1dsZEdkRWxxYjJsa01teDVXbE5LT1M1TmVGWkJka1JEUzBWSGFYSnpWbk4xUWxONU9FTlNNbEZLVTJOemEwZHNhVm8zVERkRmFuRlBlbGxLYkhRNE5pMVRXRkU0WnkxS1NrdEdhMGhYYTI5elgzUnRWVzgwUzJWT05VRlhaWEp0ZDNjeWQxbEVaeUlzSW1Oc2FXVnVkRjlwWkNJNkluZHBjbVZoY0hBNkx5OUpVakJmU1UxMFExUk1hVE5oY3pWRmIwTkNkMWhuSVdNM1pHUmlZV0l4WVRVeU1qVmtaVEZBZDJseVpTNWpiMjBpTENKaGNHbGZkbVZ5YzJsdmJpSTZOU3dpYzJOdmNHVWlPaUozYVhKbFgyTnNhV1Z1ZEY5cFpDSjkuZ245QWhyc253YVZLTG5TQ2czU0FsQ2xjMzdZd2o4NVV6OFAzdU1sT19tcHc2SFVBS0VrUEJNTXVuU2ZuaHdkM3RDaXlubmU1X3U0SEJjVkQzSHdpQUEifQ",
  "signature": "w6gp-laBSv5hi-LC8lfMWlp8aJGgllMZDS_6K3WOdlknA7OWCPT98uEP8d2-rtyoYSMcR7_MWV9ZCHiUN0zYBQ"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjlydDJMVHVyeTRJQTFZZExVYU4zT1JYUzRtZVlZTmhybWMtcXVYWUcxQjAifX0.eyJpYXQiOjE3MDUzMzI0NDksImV4cCI6MTcwNTMzNjQwOSwibmJmIjoxNzA1MzMyNDQ5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjI1MDQvY2xpZW50cy9jN2RkYmFiMWE1MjI1ZGUxL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9JUjBfSU10Q1RMaTNhczVFb0NCd1hnIWM3ZGRiYWIxYTUyMjVkZTFAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjI1MDQvY2xpZW50cy9jN2RkYmFiMWE1MjI1ZGUxL2FjY2Vzcy10b2tlbiIsImp0aSI6ImI0N2MwYmFlLWM1OGMtNGI3ZC05YTA0LTVhNWFkMWVlMDhjYiIsIm5vbmNlIjoiYjB0Vk9HdzVka3B4Y0RGYWJXTm5XRUpCY2s1a2VVTjJSM1J6UlV0TGRqayIsImNoYWwiOiIyNXhDalpsMHdndjFqQ1U0SXU2SGR0b3NCNnlZdnVTYyIsImNuZiI6eyJraWQiOiJTU3htTVBJanhaWC1lRHhBa1JreDhjWEpoRE1XUlRHTGhGNXV5VmVqUDRvIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTTFkbk5rUnFZbTlhZWtWa1JsUjBkRzlVYVZRdFlsTjFRemszTlZCeGFuRlNXRmxyWm5CVGExaHNRU0o5ZlEuZXlKcFlYUWlPakUzTURVek16STBORGtzSW1WNGNDSTZNVGN3TlRNek9UWTBPU3dpYm1KbUlqb3hOekExTXpNeU5EUTVMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWXpoaE9EVTRZMll0T0RRelppMDBOR1JqTFdGbVptWXROelZrTURFeVptTXpaak5sSWl3aWJtOXVZMlVpT2lKaU1IUldUMGQzTldScmNIaGpSRVpoWWxkT2JsZEZTa0pqYXpWclpWVk9NbEl6VW5wU1ZYUk1aR3BySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1qVXdOQzlqYkdsbGJuUnpMMk0zWkdSaVlXSXhZVFV5TWpWa1pURXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWpJMWVFTnFXbXd3ZDJkMk1XcERWVFJKZFRaSVpIUnZjMEkyZVZsMmRWTmpJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5NeFZBdkRDS0VHaXJzVnN1QlN5OENSMlFKU2Nza0dsaVo3TDdFanFPellKbHQ4Ni1TWFE4Zy1KSktGa0hXa29zX3RtVW80S2VONUFXZXJtd3cyd1lEZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9JUjBfSU10Q1RMaTNhczVFb0NCd1hnIWM3ZGRiYWIxYTUyMjVkZTFAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.gn9AhrsnwaVKLnSCg3SAlClc37Ywj85Uz8P3uMlO_mpw6HUAKEkPBMMunSfnhwd3tCiynne5_u4HBcVD3HwiAA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/Z9pcI6iMTzA1TELu1INslFx6EthReoVE",
    "nonce": "b3NIR3J1bkt3aUpBd3g5eHVoZ003SW9EZjlUNmp2ekE",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/0cSO2qsiV3grbpg9VN56vlr32RB4rLf4"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
link: <https://stepca:32795/acme/wire/authz/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o>;rel="up"
location: https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/0cSO2qsiV3grbpg9VN56vlr32RB4rLf4
replay-nonce: czdDNEJXWWoyNXdiUldqVUNXdng0YTVDNlJ0eW52Slo
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/0cSO2qsiV3grbpg9VN56vlr32RB4rLf4",
  "status": "valid",
  "token": "25xCjZl0wgv1jCU4Iu6HdtosB6yYvuSc",
  "target": "http://wire.com:22504/clients/c7ddbab1a5225de1/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=R9M_8bjvKVlELoFzn0nDATKPgXYUMDRCoSUisjvhIXk&code_challenge=ZjX5sfDha3sGLAHczVPzdOjpbiQU85hu71U6EwbNLCA
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:21126/dex/auth?response_type=code&client_id=wireapp&state=VFQsumy7yscaorqVgf2b2A&code_challenge=ZjX5sfDha3sGLAHczVPzdOjpbiQU85hu71U6EwbNLCA&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A22504%2Fcallback&scope=openid+profile&nonce=qPoDAGmqqAsndPvQNRWrBw
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:21126/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpRa3B2Y25aQ2JYcExOVFJ0ZFZkRVZ6bFNibmd4WTI1NA==
```
```text
grant_type=authorization_code&code=ssp7ad5qmucretayb33r5ojun&code_verifier=R9M_8bjvKVlELoFzn0nDATKPgXYUMDRCoSUisjvhIXk&redirect_uri=http%3A%2F%2Fwire.com%3A22504%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc5NmJkOTFkMGUwMWY2NmNjMDQyM2ZjZGRjYjEzZTIzZjIxNTJmMDMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMTI2L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA1NDIyNDQ5LCJpYXQiOjE3MDUzMzYwNDksIm5vbmNlIjoicVBvREFHbXFxQXNuZFB2UU5SV3JCdyIsImF0X2hhc2giOiJrc3hwUXZRYU9FcFhRQXI2N2hoLXZRIiwibmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.UgDXIQKTjbeDzGps5sQKHk96QtiI2d2LNJsvfRbfMQCJ9-ZCQiC3WnGm98a5xLYovG8D7o-A8vNhyHrjpU_001wdm5wiu7vfUM5RqZKP7vVqLgTrVtXWiD4--tOxJRnw7VR3HkeURMC7djjsqxqAb6HnRw-43AWZzlDn5Fd5I9Qv3xx4KuUGTaqVkGaXX452AEUhFT5MmZriQw9SLRKVhSc0RyWbW7hZzKxD3iH2yaasjnDU1JqUwAbeGABAbprsd7rjLP2F_YtEbouEzrL8v2ByQMsQ6K6KIYyUhV-mCmYYrMS9sDgFq9dXSicyPbl9yrgEQLwJMDo0wwtg5LRiqw",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc5NmJkOTFkMGUwMWY2NmNjMDQyM2ZjZGRjYjEzZTIzZjIxNTJmMDMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMTI2L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA1NDIyNDQ5LCJpYXQiOjE3MDUzMzYwNDksIm5vbmNlIjoicVBvREFHbXFxQXNuZFB2UU5SV3JCdyIsImF0X2hhc2giOiIwWmNucDVyWTN5ZDJVU1ZzbHV4TTVnIiwiY19oYXNoIjoiZUVGN3RKNmY0dmVzOGlYaXc3RVVwZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.D0TBJC-aR9h_KvyGzZbRL9FMfO3k_A5Sx7v_uYPwIQzA8H7-Xp0UKUiDSGChdiukpoyv0OIYTGpn99b-8Nu756rquZr-Dp0w5LeWgrQ4I7PTOvoxhcvYd6yNpLIUfgNqpCF7SdDppLTdpZpMyzmoESuz9qLgQQaas5S44o767ls2L_qn8xm_FST1G0tbn6UufdZtCiI2jog75A7JKAHfKqpv4ecmoCErz_7LXi9btBeXmeBWv69sjsw1sOdUNgL_mEJeZHZ75L7KjMZu2NiTVDtUFNs0vx1oyfKv0xwN40L_Igm8o9iS_GTNXLzK9Hb3Yw4ivd9NBsp9FPRSr7-rGw",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc5NmJkOTFkMGUwMWY2NmNjMDQyM2ZjZGRjYjEzZTIzZjIxNTJmMDMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMTI2L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA1NDIyNDQ5LCJpYXQiOjE3MDUzMzYwNDksIm5vbmNlIjoicVBvREFHbXFxQXNuZFB2UU5SV3JCdyIsImF0X2hhc2giOiIwWmNucDVyWTN5ZDJVU1ZzbHV4TTVnIiwiY19oYXNoIjoiZUVGN3RKNmY0dmVzOGlYaXc3RVVwZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.D0TBJC-aR9h_KvyGzZbRL9FMfO3k_A5Sx7v_uYPwIQzA8H7-Xp0UKUiDSGChdiukpoyv0OIYTGpn99b-8Nu756rquZr-Dp0w5LeWgrQ4I7PTOvoxhcvYd6yNpLIUfgNqpCF7SdDppLTdpZpMyzmoESuz9qLgQQaas5S44o767ls2L_qn8xm_FST1G0tbn6UufdZtCiI2jog75A7JKAHfKqpv4ecmoCErz_7LXi9btBeXmeBWv69sjsw1sOdUNgL_mEJeZHZ75L7KjMZu2NiTVDtUFNs0vx1oyfKv0xwN40L_Igm8o9iS_GTNXLzK9Hb3Yw4ivd9NBsp9FPRSr7-rGw
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc5NmJkOTFkMGUwMWY2NmNjMDQyM2ZjZGRjYjEzZTIzZjIxNTJmMDMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMTI2L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA1NDIyNDQ5LCJpYXQiOjE3MDUzMzYwNDksIm5vbmNlIjoicVBvREFHbXFxQXNuZFB2UU5SV3JCdyIsImF0X2hhc2giOiIwWmNucDVyWTN5ZDJVU1ZzbHV4TTVnIiwiY19oYXNoIjoiZUVGN3RKNmY0dmVzOGlYaXc3RVVwZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.D0TBJC-aR9h_KvyGzZbRL9FMfO3k_A5Sx7v_uYPwIQzA8H7-Xp0UKUiDSGChdiukpoyv0OIYTGpn99b-8Nu756rquZr-Dp0w5LeWgrQ4I7PTOvoxhcvYd6yNpLIUfgNqpCF7SdDppLTdpZpMyzmoESuz9qLgQQaas5S44o767ls2L_qn8xm_FST1G0tbn6UufdZtCiI2jog75A7JKAHfKqpv4ecmoCErz_7LXi9btBeXmeBWv69sjsw1sOdUNgL_mEJeZHZ75L7KjMZu2NiTVDtUFNs0vx1oyfKv0xwN40L_Igm8o9iS_GTNXLzK9Hb3Yw4ivd9NBsp9FPRSr7-rGw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc5NmJkOTFkMGUwMWY2NmNjMDQyM2ZjZGRj
YjEzZTIzZjIxNTJmMDMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMTI2L2RleCIsI
nN1YiI6IkNqcDNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRb
mRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0RWdSc1pHRnciL
CJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA1NDIyNDQ5LCJpYXQiOjE3MDUzMzYwN
DksIm5vbmNlIjoicVBvREFHbXFxQXNuZFB2UU5SV3JCdyIsImF0X2hhc2giOiIwW
mNucDVyWTN5ZDJVU1ZzbHV4TTVnIiwiY19oYXNoIjoiZUVGN3RKNmY0dmVzOGlYa
Xc3RVVwZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvb
SIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.D0TBJC-aR9h_K
vyGzZbRL9FMfO3k_A5Sx7v_uYPwIQzA8H7-Xp0UKUiDSGChdiukpoyv0OIYTGpn9
9b-8Nu756rquZr-Dp0w5LeWgrQ4I7PTOvoxhcvYd6yNpLIUfgNqpCF7SdDppLTdp
ZpMyzmoESuz9qLgQQaas5S44o767ls2L_qn8xm_FST1G0tbn6UufdZtCiI2jog75
A7JKAHfKqpv4ecmoCErz_7LXi9btBeXmeBWv69sjsw1sOdUNgL_mEJeZHZ75L7Kj
MZu2NiTVDtUFNs0vx1oyfKv0xwN40L_Igm8o9iS_GTNXLzK9Hb3Yw4ivd9NBsp9F
PRSr7-rGw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "796bd91d0e01f66cc0423fcddcb13e23f2152f03"
}
```

```json
{
  "at_hash": "0Zcnp5rY3yd2USVsluxM5g",
  "aud": "wireapp",
  "c_hash": "eEF7tJ6f4ves8iXiw7EUpg",
  "exp": 1705422449,
  "iat": 1705336049,
  "iss": "http://dex:21126/dex",
  "name": "wireapp://%40alice_wire@wire.com",
  "nonce": "qPoDAGmqqAsndPvQNRWrBw",
  "preferred_username": "Alice Smith",
  "sub": "Cjp3aXJlYXBwOi8vSVIwX0lNdENUTGkzYXM1RW9DQndYZyFjN2RkYmFiMWE1MjI1ZGUxQHdpcmUuY29tEgRsZGFw"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs7+pXsw+DMrHK9OpLcl9
D60jRk6gXPqCd3+niRZ25QO0RSjtq1cTcAu9yN6SwZHxQsfWo+2DQEiJ6KRG2bHj
OdCHB/LNq8Og8I66j2trebZW4i8GWxKcIrhY2xo6WAxeKDfXJJsrZxAdAX9MGbW5
gvlLqwbQD+BEcO9ohu0q03rE5an2jDvXvo7JHHzQfcj4uKnjTwEBJVyvjLRQTHzU
GriXF8sV1ngF5WD3BmWbWzOJO2cib8pi2idPps0kgNXPA/ZEg97XCjYZtIBFib4W
bzrTOKi+dn/MgdgVKvdKoy2VtgpoprERKzNWdgt0hLarkbeorIClo/749gxVeQzv
ywIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/nRHOLoqoWZHI6CGGORPT3ibdevmdUEz4
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L1o5cGNJNmlNVHpBMVRFTHUxSU5zbEZ4NkV0aFJlb1ZFIiwidHlwIjoiSldUIiwibm9uY2UiOiJjemRETkVKWFdXb3lOWGRpVWxkcVZVTlhkbmcwWVRWRE5sSjBlVzUyU2xvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL2NoYWxsZW5nZS9STzFsTjBGaVlJdWQxclpaNkUzdWlZNWVSZG5qVkUwby9uUkhPTG9xb1daSEk2Q0dHT1JQVDNpYmRldm1kVUV6NCJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJamM1Tm1Ka09URmtNR1V3TVdZMk5tTmpNRFF5TTJaalpHUmpZakV6WlRJelpqSXhOVEptTURNaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSXhNVEkyTDJSbGVDSXNJbk4xWWlJNklrTnFjRE5oV0Vwc1dWaENkMDlwT0haVFZrbDNXREJzVG1SRlRsVlVSMnQ2V1ZoTk1WSlhPVVJSYm1SWldubEdhazR5VW10WmJVWnBUVmRGTVUxcVNURmFSMVY0VVVoa2NHTnRWWFZaTWpsMFJXZFNjMXBIUm5jaUxDSmhkV1FpT2lKM2FYSmxZWEJ3SWl3aVpYaHdJam94TnpBMU5ESXlORFE1TENKcFlYUWlPakUzTURVek16WXdORGtzSW01dmJtTmxJam9pY1ZCdlJFRkhiWEZ4UVhOdVpGQjJVVTVTVjNKQ2R5SXNJbUYwWDJoaGMyZ2lPaUl3V21OdWNEVnlXVE41WkRKVlUxWnpiSFY0VFRWbklpd2lZMTlvWVhOb0lqb2laVVZHTjNSS05tWTBkbVZ6T0dsWWFYYzNSVlZ3WnlJc0ltNWhiV1VpT2lKM2FYSmxZWEJ3T2k4dkpUUXdZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW5CeVpXWmxjbkpsWkY5MWMyVnlibUZ0WlNJNklrRnNhV05sSUZOdGFYUm9JbjAuRDBUQkpDLWFSOWhfS3Z5R3paYlJMOUZNZk8za19BNVN4N3ZfdVlQd0lRekE4SDctWHAwVUtVaURTR0NoZGl1a3BveXYwT0lZVEdwbjk5Yi04TnU3NTZycXVaci1EcDB3NUxlV2dyUTRJN1BUT3ZveGhjdllkNnlOcExJVWZnTnFwQ0Y3U2REcHBMVGRwWnBNeXptb0VTdXo5cUxnUVFhYXM1UzQ0bzc2N2xzMkxfcW44eG1fRlNUMUcwdGJuNlV1ZmRadENpSTJqb2c3NUE3SktBSGZLcXB2NGVjbW9DRXJ6XzdMWGk5YnRCZVhtZUJXdjY5c2pzdzFzT2RVTmdMX21FSmVaSFo3NUw3S2pNWnUyTmlUVkR0VUZOczB2eDFveWZLdjB4d040MExfSWdtOG85aVNfR1ROWEx6SzlIYjNZdzRpdmQ5TkJzcDlGUFJTcjctckd3Iiwia2V5YXV0aCI6IjI1eENqWmwwd2d2MWpDVTRJdTZIZHRvc0I2eVl2dVNjLlNTeG1NUElqeFpYLWVEeEFrUmt4OGNYSmhETVdSVEdMaEY1dXlWZWpQNG8ifQ",
  "signature": "1yUgZxNcZlM2PggKOn0Dg0_xxpQ7GBopLUbYJzZg7FzovVbdaY3ffYU0RnBsTUk6zq6XMbTiYx4PaqP8DSG-Aw"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6Ijc5NmJkOTFkMGUwMWY2NmNjMDQyM2ZjZGRjYjEzZTIzZjIxNTJmMDMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMTI2L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZTVkl3WDBsTmRFTlVUR2t6WVhNMVJXOURRbmRZWnlGak4yUmtZbUZpTVdFMU1qSTFaR1V4UUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA1NDIyNDQ5LCJpYXQiOjE3MDUzMzYwNDksIm5vbmNlIjoicVBvREFHbXFxQXNuZFB2UU5SV3JCdyIsImF0X2hhc2giOiIwWmNucDVyWTN5ZDJVU1ZzbHV4TTVnIiwiY19oYXNoIjoiZUVGN3RKNmY0dmVzOGlYaXc3RVVwZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.D0TBJC-aR9h_KvyGzZbRL9FMfO3k_A5Sx7v_uYPwIQzA8H7-Xp0UKUiDSGChdiukpoyv0OIYTGpn99b-8Nu756rquZr-Dp0w5LeWgrQ4I7PTOvoxhcvYd6yNpLIUfgNqpCF7SdDppLTdpZpMyzmoESuz9qLgQQaas5S44o767ls2L_qn8xm_FST1G0tbn6UufdZtCiI2jog75A7JKAHfKqpv4ecmoCErz_7LXi9btBeXmeBWv69sjsw1sOdUNgL_mEJeZHZ75L7KjMZu2NiTVDtUFNs0vx1oyfKv0xwN40L_Igm8o9iS_GTNXLzK9Hb3Yw4ivd9NBsp9FPRSr7-rGw",
    "keyauth": "25xCjZl0wgv1jCU4Iu6HdtosB6yYvuSc.SSxmMPIjxZX-eDxAkRkx8cXJhDMWRTGLhF5uyVejP4o"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/Z9pcI6iMTzA1TELu1INslFx6EthReoVE",
    "nonce": "czdDNEJXWWoyNXdiUldqVUNXdng0YTVDNlJ0eW52Slo",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/nRHOLoqoWZHI6CGGORPT3ibdevmdUEz4"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
link: <https://stepca:32795/acme/wire/authz/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o>;rel="up"
location: https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/nRHOLoqoWZHI6CGGORPT3ibdevmdUEz4
replay-nonce: RXlibmZJRkhkNjVvMnROVkpEOXFqNkJrdjN2cmV1RGM
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32795/acme/wire/challenge/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o/nRHOLoqoWZHI6CGGORPT3ibdevmdUEz4",
  "status": "valid",
  "token": "25xCjZl0wgv1jCU4Iu6HdtosB6yYvuSc",
  "target": "http://dex:21126/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L1o5cGNJNmlNVHpBMVRFTHUxSU5zbEZ4NkV0aFJlb1ZFIiwidHlwIjoiSldUIiwibm9uY2UiOiJSWGxpYm1aSlJraGtOalZ2TW5ST1ZrcEVPWEZxTmtKcmRqTjJjbVYxUkdNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL29yZGVyL2FWVTVtd0M4ejh0R1plUlgxam1HdEtHcGw4Q1lLRHJWIn0",
  "payload": "",
  "signature": "K3qlgB5bIKZKuqiWsJqcoXLmzFhS7JZXezPYGPEww2oIthTHey7zWYc4N4gcxzu7JyRdA1kskT_NnDvsc84GCg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/Z9pcI6iMTzA1TELu1INslFx6EthReoVE",
    "nonce": "RXlibmZJRkhkNjVvMnROVkpEOXFqNkJrdjN2cmV1RGM",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
location: https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV
replay-nonce: UHV6bDdONER0Vm1PRlZGcDltWTYxeEpJVWVKSjZzVDg
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://IR0_IMtCTLi3as5EoCBwXg!c7ddbab1a5225de1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32795/acme/wire/authz/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o"
  ],
  "expires": "2024-01-16T16:27:29Z",
  "notBefore": "2024-01-15T16:27:29.233725Z",
  "notAfter": "2034-01-12T16:27:29.233725Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L1o5cGNJNmlNVHpBMVRFTHUxSU5zbEZ4NkV0aFJlb1ZFIiwidHlwIjoiSldUIiwibm9uY2UiOiJVSFY2YkRkT05FUjBWbTFQUmxaR2NEbHRXVFl4ZUVwSlZXVktTalp6VkRnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL29yZGVyL2FWVTVtd0M4ejh0R1plUlgxam1HdEtHcGw4Q1lLRHJWL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTmFTZDlub0JrRVp0YjUwNU9ZOFpJdm5JbF9MSXhqanBZZDdPa2hHQUlOM29Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2U1ZJd1gwbE5kRU5VVEdrellYTTFSVzlEUW5kWVp5RmpOMlJrWW1GaU1XRTFNakkxWkdVeFFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFDQ2VxU21seDFtaFdXZnEwaWJIMlRYb2NWQ0RTbkdaY1lvSnEwZ2VZaDJHaVRoSzlsR05IVm82MGhxb210bXhtRWQtNE5mVnU5UXNEWHk4TEtRQTRBSyJ9",
  "signature": "vx3uMwnyHc56idl_4RtrJCRQMqn1WKRZLIt53xZUipw3ErvsYyaR4M8lYuJieKL2Bc1GFYmVorVWizj7-8ntDQ"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhANaSd9noBkEZtb505OY8ZIvnIl_LIxjjpYd7OkhGAIN3oHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vSVIwX0lNdENUTGkzYXM1RW9DQndYZyFjN2RkYmFiMWE1MjI1ZGUxQHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQCCeqSmlx1mhWWfq0ibH2TXocVCDSnGZcYoJq0geYh2GiThK9lGNHVo60hqomtmxmEd-4NfVu9QsDXy8LKQA4AK"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/Z9pcI6iMTzA1TELu1INslFx6EthReoVE",
    "nonce": "UHV6bDdONER0Vm1PRlZGcDltWTYxeEpJVWVKSjZzVDg",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhANaSd9noBkEZtb505OY8ZIvnIl/LIxjj
pYd7OkhGAIN3oHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vSVIwX0lNdENUTGkzYXM1RW9DQndYZyFjN2RkYmFiMWE1MjI1ZGUxQHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQCC
eqSmlx1mhWWfq0ibH2TXocVCDSnGZcYoJq0geYh2GiThK9lGNHVo60hqomtmxmEd
+4NfVu9QsDXy8LKQA4AK
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
                    d6:92:77:d9:e8:06:41:19:b5:be:74:e4:e6:3c:64:
                    8b:e7:22:5f:cb:23:18:e3:a5:87:7b:3a:48:46:00:
                    83:77
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://IR0_IMtCTLi3as5EoCBwXg!c7ddbab1a5225de1@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        82:7a:a4:a6:97:1d:66:85:65:9f:ab:48:9b:1f:64:d7:a1:c5:
        42:0d:29:c6:65:c6:28:26:ad:20:79:88:76:1a:24:e1:2b:d9:
        46:34:75:68:eb:48:6a:a2:6b:66:c6:61:1d:fb:83:5f:56:ef:
        50:b0:35:f2:f0:b2:90:03:80:0a

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32795/acme/wire/directory>;rel="index"
location: https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV
replay-nonce: NmNKSTRqOFJOODF5SjhSeWxIdUF2czFKSDVDUXZCUVY
vary: Origin
```
```json
{
  "certificate": "https://stepca:32795/acme/wire/certificate/iRBWw7qQq4v0vzo9sBGWya6v31jD5mRL",
  "status": "valid",
  "finalize": "https://stepca:32795/acme/wire/order/aVU5mwC8z8tGZeRX1jmGtKGpl8CYKDrV/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://IR0_IMtCTLi3as5EoCBwXg!c7ddbab1a5225de1@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32795/acme/wire/authz/RO1lN0FiYIud1rZZ6E3uiY5eRdnjVE0o"
  ],
  "expires": "2024-01-16T16:27:29Z",
  "notBefore": "2024-01-15T16:27:29.233725Z",
  "notAfter": "2034-01-12T16:27:29.233725Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32795/acme/wire/certificate/iRBWw7qQq4v0vzo9sBGWya6v31jD5mRL
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzk1L2FjbWUvd2lyZS9hY2NvdW50L1o5cGNJNmlNVHpBMVRFTHUxSU5zbEZ4NkV0aFJlb1ZFIiwidHlwIjoiSldUIiwibm9uY2UiOiJObU5LU1RScU9GSk9PREY1U2poU2VXeElkVUYyY3pGS1NEVkRVWFpDVVZZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTUvYWNtZS93aXJlL2NlcnRpZmljYXRlL2lSQld3N3FRcTR2MHZ6bzlzQkdXeWE2djMxakQ1bVJMIn0",
  "payload": "",
  "signature": "GcvUbPuI6Yu_A_xvaN1AfFxgnwHXmUO5UElKiM45VmaraVvJR6jip47beZRDjm7G53nrnfa97zjSSrUW2_qQDA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32795/acme/wire/account/Z9pcI6iMTzA1TELu1INslFx6EthReoVE",
    "nonce": "NmNKSTRqOFJOODF5SjhSeWxIdUF2czFKSDVDUXZCUVY",
    "typ": "JWT",
    "url": "https://stepca:32795/acme/wire/certificate/iRBWw7qQq4v0vzo9sBGWya6v31jD5mRL"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32795/acme/wire/directory>;rel="index"
replay-nonce: dERlM0RCeHB2ZG1wY3BLeWl2QnlhWk15OUJkd2FqZ0I
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGDCCAb+gAwIBAgIQFKrxUIOl/+stA8ohkT7CRTAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nNDAxMTUxNjI3MjlaFw0zNDAxMTIxNjI3MjlaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhANaSd9noBkEZtb505OY8\nZIvnIl/LIxjjpYd7OkhGAIN3o4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUoywPSB9g4RQwxojHhvIMhZw6y4EwHwYD\nVR0jBBgwFoAUU5Ngeiq+vNIDcWmTNeO0LYpUjdIwaQYDVR0RBGIwYIYgd2lyZWFw\ncDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9JUjBfSU10Q1RM\naTNhczVFb0NCd1hnJTIxYzdkZGJhYjFhNTIyNWRlMUB3aXJlLmNvbTAdBgwrBgEE\nAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgcVSHg0wM\nbGvOROprW0uf/YDog4+V8WXOayfi/B9WHqACIH159dt2KejVU+d7DdeYm3AXlYma\n/iwmT4PqBh7RF41G\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRANlfaayTw0MW4FeGIikyAF0wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExNTE2\nMjcyN1oXDTM0MDExMjE2MjcyN1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASM\nrvbahGvChOOs5Eqs7qqdQvfXNT9IIkP78Hxm9fNRKk4hG7UHj5x1R0Ve6kEa7X5A\ncmFYV/U9oLuDn1ZOGHljo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUU5Ngeiq+vNIDcWmTNeO0LYpUjdIwHwYDVR0jBBgw\nFoAUAc3VI5dPjzJMHbsakKImbSK26sowCgYIKoZIzj0EAwIDSAAwRQIgQeA2iFTD\nu/a46ccjZoVXtvicaXn+dUeYbxyS6PToeDICIQDBEmh6g6rlLANVHNbC5zC2wWsY\nmHvml2cv5JFGTSYdtQ==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGDCCAb+gAwIBAgIQFKrxUIOl/+stA8ohkT7CRTAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
NDAxMTUxNjI3MjlaFw0zNDAxMTIxNjI3MjlaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhANaSd9noBkEZtb505OY8
ZIvnIl/LIxjjpYd7OkhGAIN3o4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUoywPSB9g4RQwxojHhvIMhZw6y4EwHwYD
VR0jBBgwFoAUU5Ngeiq+vNIDcWmTNeO0LYpUjdIwaQYDVR0RBGIwYIYgd2lyZWFw
cDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9JUjBfSU10Q1RM
aTNhczVFb0NCd1hnJTIxYzdkZGJhYjFhNTIyNWRlMUB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDRwAwRAIgcVSHg0wM
bGvOROprW0uf/YDog4+V8WXOayfi/B9WHqACIH159dt2KejVU+d7DdeYm3AXlYma
/iwmT4PqBh7RF41G
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            14:aa:f1:50:83:a5:ff:eb:2d:03:ca:21:91:3e:c2:45
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan 15 16:27:29 2024 GMT
            Not After : Jan 12 16:27:29 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    d6:92:77:d9:e8:06:41:19:b5:be:74:e4:e6:3c:64:
                    8b:e7:22:5f:cb:23:18:e3:a5:87:7b:3a:48:46:00:
                    83:77
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                A3:2C:0F:48:1F:60:E1:14:30:C6:88:C7:86:F2:0C:85:9C:3A:CB:81
            X509v3 Authority Key Identifier: 
                53:93:60:7A:2A:BE:BC:D2:03:71:69:93:35:E3:B4:2D:8A:54:8D:D2
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://IR0_IMtCTLi3as5EoCBwXg%21c7ddbab1a5225de1@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:71:54:87:83:4c:0c:6c:6b:ce:44:ea:6b:5b:4b:
        9f:fd:80:e8:83:8f:95:f1:65:ce:6b:27:e2:fc:1f:56:1e:a0:
        02:20:7d:79:f5:db:76:29:e8:d5:53:e7:7b:0d:d7:98:9b:70:
        17:95:89:9a:fe:2c:26:4f:83:ea:06:1e:d1:17:8d:46

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRANlfaayTw0MW4FeGIikyAF0wCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExNTE2
MjcyN1oXDTM0MDExMjE2MjcyN1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASM
rvbahGvChOOs5Eqs7qqdQvfXNT9IIkP78Hxm9fNRKk4hG7UHj5x1R0Ve6kEa7X5A
cmFYV/U9oLuDn1ZOGHljo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUU5Ngeiq+vNIDcWmTNeO0LYpUjdIwHwYDVR0jBBgw
FoAUAc3VI5dPjzJMHbsakKImbSK26sowCgYIKoZIzj0EAwIDSAAwRQIgQeA2iFTD
u/a46ccjZoVXtvicaXn+dUeYbxyS6PToeDICIQDBEmh6g6rlLANVHNbC5zC2wWsY
mHvml2cv5JFGTSYdtQ==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            d9:5f:69:ac:93:c3:43:16:e0:57:86:22:29:32:00:5d
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 15 16:27:27 2024 GMT
            Not After : Jan 12 16:27:27 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:8c:ae:f6:da:84:6b:c2:84:e3:ac:e4:4a:ac:ee:
                    aa:9d:42:f7:d7:35:3f:48:22:43:fb:f0:7c:66:f5:
                    f3:51:2a:4e:21:1b:b5:07:8f:9c:75:47:45:5e:ea:
                    41:1a:ed:7e:40:72:61:58:57:f5:3d:a0:bb:83:9f:
                    56:4e:18:79:63
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                53:93:60:7A:2A:BE:BC:D2:03:71:69:93:35:E3:B4:2D:8A:54:8D:D2
            X509v3 Authority Key Identifier: 
                01:CD:D5:23:97:4F:8F:32:4C:1D:BB:1A:90:A2:26:6D:22:B6:EA:CA
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:41:e0:36:88:54:c3:bb:f6:b8:e9:c7:23:66:85:
        57:b6:f8:9c:69:79:fe:75:47:98:6f:1c:92:e8:f4:e8:78:32:
        02:21:00:c1:12:68:7a:83:aa:e5:2c:03:55:1c:d6:c2:e7:30:
        b6:c1:6b:18:98:7b:e6:97:67:2f:e4:91:46:4d:26:1d:b5

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIQNH6gnI8ByM3lcP/r0KjiyjAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTE1MTYy
NzI2WhcNMzQwMTEyMTYyNzI2WjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3
aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR4NOweoDv4pT6M
pPqsDUdgSd8tGPUzynZYq6zUvL9Tpr6yj2Xsn9pUTb9E9nb8l8IKZJx4wJMdhP2u
POBu8zdjo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd
BgNVHQ4EFgQUAc3VI5dPjzJMHbsakKImbSK26sowCgYIKoZIzj0EAwIDSAAwRQIg
J1gV4hJjvZCerYOs3EicV3CEl6aHhoQ3KbbFxc/uUUwCIQDWrCSEQvPVDNCVIcCc
9+KK5XWocbeVbAySZ3OByhsMtQ==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            34:7e:a0:9c:8f:01:c8:cd:e5:70:ff:eb:d0:a8:e2:ca
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 15 16:27:26 2024 GMT
            Not After : Jan 12 16:27:26 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:78:34:ec:1e:a0:3b:f8:a5:3e:8c:a4:fa:ac:0d:
                    47:60:49:df:2d:18:f5:33:ca:76:58:ab:ac:d4:bc:
                    bf:53:a6:be:b2:8f:65:ec:9f:da:54:4d:bf:44:f6:
                    76:fc:97:c2:0a:64:9c:78:c0:93:1d:84:fd:ae:3c:
                    e0:6e:f3:37:63
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                01:CD:D5:23:97:4F:8F:32:4C:1D:BB:1A:90:A2:26:6D:22:B6:EA:CA
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:27:58:15:e2:12:63:bd:90:9e:ad:83:ac:dc:48:
        9c:57:70:84:97:a6:87:86:84:37:29:b6:c5:c5:cf:ee:51:4c:
        02:21:00:d6:ac:24:84:42:f3:d5:0c:d0:95:21:c0:9c:f7:e2:
        8a:e5:75:a8:71:b7:95:6c:0c:92:67:73:81:ca:1b:0c:b5

```

openssl verify chain ✅