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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/2022714477916805813/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/Tom4LeMzZP64x2ttMAJ5TQHtWo9GGf42
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/U2lRA7XCmde2VaWK14iM74K8gkBcbNDQ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/ofP2iuiUFiZxCIdS5wYFPNPrZopSxnil
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:56364/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:56364/acme/wire/new-nonce",
  "newAccount": "https://stepca:56364/acme/wire/new-account",
  "newOrder": "https://stepca:56364/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:56364/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:56364/acme/wire/directory>;rel="index"
replay-nonce: M0FUVDltU2o5cWNGZUh6ZHVwNGgyY3lId2MyclgxRlc
```
```text
M0FUVDltU2o5cWNGZUh6ZHVwNGgyY3lId2MyclgxRlc
```
#### 5. create a new account
```http request
POST https://stepca:56364/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ik9oSlNCNHhPTkdQNEhNdWhsTG50cTVpWGlDNjl5YktQczVuTERVVFVCNWcifSwibm9uY2UiOiJNMEZVVkRsdFUybzVjV05HWlVoNlpIVndOR2d5WTNsSWQyTXljbGd4UmxjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNjQvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "lxuAl8KQNKIBu1sZwFYkvUGYsgX0DGHVW7hUBZZIXmLye3Fo20rH0saWghOaWBC-0O98sohZvW3Zr8QkqJ3IDQ"
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
      "x": "OhJSB4xONGP4HMuhlLntq5iXiC69ybKPs5nLDUTUB5g"
    },
    "nonce": "M0FUVDltU2o5cWNGZUh6ZHVwNGgyY3lId2MyclgxRlc",
    "typ": "JWT",
    "url": "https://stepca:56364/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:56364/acme/wire/directory>;rel="index"
location: https://stepca:56364/acme/wire/account/fLozwt9ASNMA0oYKTnfi0H1lzHh8sCzI
replay-nonce: UWlxVzFIbnU5cDk1VDBpaWMxNkdOcWpqa3ltbFlDczA
```
```json
{
  "status": "valid",
  "orders": "https://stepca:56364/acme/wire/account/fLozwt9ASNMA0oYKTnfi0H1lzHh8sCzI/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:56364/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MzY0L2FjbWUvd2lyZS9hY2NvdW50L2ZMb3p3dDlBU05NQTBvWUtUbmZpMEgxbHpIaDhzQ3pJIiwidHlwIjoiSldUIiwibm9uY2UiOiJVV2x4VnpGSWJuVTVjRGsxVkRCcGFXTXhOa2RPY1dwcWEzbHRiRmxEY3pBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNjQvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkJlbHRyYW0gTWFsZGFudFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwiLFwiY2xpZW50LWlkXCI6XCJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbVwiLFwiaGFuZGxlXCI6XCJiZWx0cmFtX3dpcmVcIn0ifV0sIm5vdEJlZm9yZSI6IjIwMjMtMDMtMzBUMTM6MzU6MzAuNjIxNDI4WiIsIm5vdEFmdGVyIjoiMjAyMy0wMy0zMFQxNDozNTozMC42MjE0MjhaIn0",
  "signature": "QzIdewRgEvRECgQ3kAEWJ4Y_wk1cS8cH0q4olVOPxeXHXcLiopU432DQoQV85yFeXrhDP0fPlU1cbrYK8TxRBw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MmFiMzk3NWJiNmVjNDc1YmE1NWJlZTg2MmMwYWNhOGU/1c122019d2455ab5@wire.com\",\"handle\":\"beltram_wire\"}"
      }
    ],
    "notAfter": "2023-03-30T14:35:30.621428Z",
    "notBefore": "2023-03-30T13:35:30.621428Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56364/acme/wire/account/fLozwt9ASNMA0oYKTnfi0H1lzHh8sCzI",
    "nonce": "UWlxVzFIbnU5cDk1VDBpaWMxNkdOcWpqa3ltbFlDczA",
    "typ": "JWT",
    "url": "https://stepca:56364/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:56364/acme/wire/directory>;rel="index"
location: https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho
replay-nonce: SlNCSGpkdzVXWXZ1OFFOdVJqTEY1bG5OWk5qMDNBdVE
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MmFiMzk3NWJiNmVjNDc1YmE1NWJlZTg2MmMwYWNhOGU/1c122019d2455ab5@wire.com\",\"handle\":\"beltram_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56364/acme/wire/authz/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO"
  ],
  "expires": "2023-03-31T13:35:30Z",
  "notBefore": "2023-03-30T13:35:30.621428Z",
  "notAfter": "2023-03-30T14:35:30.621428Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:56364/acme/wire/authz/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MzY0L2FjbWUvd2lyZS9hY2NvdW50L2ZMb3p3dDlBU05NQTBvWUtUbmZpMEgxbHpIaDhzQ3pJIiwidHlwIjoiSldUIiwibm9uY2UiOiJTbE5DU0dwa2R6VlhXWFoxT0ZGT2RWSnFURVkxYkc1T1drNXFNRE5CZFZFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNjQvYWNtZS93aXJlL2F1dGh6L2o4RnZnVFlZQ1B5R0s1NUJLc1dnVFlaTzdoTEMwdFlPIn0",
  "payload": "",
  "signature": "sWcsg_UNBhDBJkLij5DaY3efg8u8gBhuySBSwTon6CcpxVIlB4R3YBVHY0tjjSViqLDtwmG5GjthVJPhIJBTBQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56364/acme/wire/account/fLozwt9ASNMA0oYKTnfi0H1lzHh8sCzI",
    "nonce": "SlNCSGpkdzVXWXZ1OFFOdVJqTEY1bG5OWk5qMDNBdVE",
    "typ": "JWT",
    "url": "https://stepca:56364/acme/wire/authz/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO"
  }
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56364/acme/wire/directory>;rel="index"
location: https://stepca:56364/acme/wire/authz/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO
replay-nonce: NmZNVExsRDBpYXphRExWUmZtdjB3bmpsM0pGeTlGY0M
```
```json
{
  "status": "pending",
  "expires": "2023-03-31T13:35:30Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/U2lRA7XCmde2VaWK14iM74K8gkBcbNDQ",
      "status": "pending",
      "token": "P34em15IpZzAyWvUkhWePnULr7XHfAyr"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/Tom4LeMzZP64x2ttMAJ5TQHtWo9GGf42",
      "status": "pending",
      "token": "P34em15IpZzAyWvUkhWePnULr7XHfAyr"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MmFiMzk3NWJiNmVjNDc1YmE1NWJlZTg2MmMwYWNhOGU/1c122019d2455ab5@wire.com\",\"handle\":\"beltram_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:9090/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
NmhtN2NieDhuenhxbUJQUXhPUUpJMjZKVWZ6M2k4RFM
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiT2hKU0I0eE9OR1A0SE11aGxMbnRxNWlYaUM2OXliS1BzNW5MRFVUVUI1ZyJ9fQ.eyJpYXQiOjE2ODAxODMzMzAsImV4cCI6MTY4MDE4NjkzMCwibmJmIjoxNjgwMTgzMzMwLCJzdWIiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbSIsImp0aSI6IjY4NTMxNjdjLTNiNzktNDUzYi04NzRiLWZiM2NmNWRlZTY1OCIsIm5vbmNlIjoiTm1odE4yTmllRGh1ZW5oeGJVSlFVWGhQVVVwSk1qWktWV1o2TTJrNFJGTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJjaGFsIjoiUDM0ZW0xNUlwWnpBeVd2VWtoV2VQblVMcjdYSGZBeXIifQ.4L9wLRiySROzc_zY3VPwr1sAF-Jt4Pd8p98f1adG5GSUkFslALl7O0drmKDmo21d_UqyyJCDR2dorXOyGyQSAw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiT2hKU0I0eE9OR1A0SE11aGxMbnRxNWlY
aUM2OXliS1BzNW5MRFVUVUI1ZyJ9fQ.eyJpYXQiOjE2ODAxODMzMzAsImV4cCI6M
TY4MDE4NjkzMCwibmJmIjoxNjgwMTgzMzMwLCJzdWIiOiJpbTp3aXJlYXBwPU1tR
mlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwM
TlkMjQ1NWFiNUB3aXJlLmNvbSIsImp0aSI6IjY4NTMxNjdjLTNiNzktNDUzYi04N
zRiLWZiM2NmNWRlZTY1OCIsIm5vbmNlIjoiTm1odE4yTmllRGh1ZW5oeGJVSlFVW
GhQVVVwSk1qWktWV1o2TTJrNFJGTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206OTA5MC8iLCJjaGFsIjoiUDM0ZW0xNUlwWnpBeVd2VWtoV2VQb
lVMcjdYSGZBeXIifQ.4L9wLRiySROzc_zY3VPwr1sAF-Jt4Pd8p98f1adG5GSUkF
slALl7O0drmKDmo21d_UqyyJCDR2dorXOyGyQSAw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "OhJSB4xONGP4HMuhlLntq5iXiC69ybKPs5nLDUTUB5g"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "P34em15IpZzAyWvUkhWePnULr7XHfAyr",
  "exp": 1680186930,
  "htm": "POST",
  "htu": "http://wire.com:9090/",
  "iat": 1680183330,
  "jti": "6853167c-3b79-453b-874b-fb3cf5dee658",
  "nbf": 1680183330,
  "nonce": "NmhtN2NieDhuenhxbUJQUXhPUUpJMjZKVWZ6M2k4RFM",
  "sub": "im:wireapp=MmFiMzk3NWJiNmVjNDc1YmE1NWJlZTg2MmMwYWNhOGU/1c122019d2455ab5@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILkTGrA0SuDrtmwyHYSzgYRvY4nfgGuwdD6V23BTKo6q
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAOhJSB4xONGP4HMuhlLntq5iXiC69ybKPs5nLDUTUB5g=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:9090/clients/2022714477916805813/access-token
                         /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVDJoS1UwSTBlRTlPUjFBMFNFMTFhR3hNYm5SeE5XbFlhVU0yT1hsaVMxQnpOVzVNUkZWVVZVSTFaeUo5ZlEuZXlKcFlYUWlPakUyT0RBeE9ETXpNekFzSW1WNGNDSTZNVFk0TURFNE5qa3pNQ3dpYm1KbUlqb3hOamd3TVRnek16TXdMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTF0Um1sTmVtc3pUbGRLYVU1dFZtcE9SR014V1cxRk1VNVhTbXhhVkdjeVRXMU5kMWxYVG1oUFIxVXZNV014TWpJd01UbGtNalExTldGaU5VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqWTROVE14TmpkakxUTmlOemt0TkRVellpMDROelJpTFdaaU0yTm1OV1JsWlRZMU9DSXNJbTV2Ym1ObElqb2lUbTFvZEU0eVRtbGxSR2gxWlc1b2VHSlZTbEZWV0doUVZWVndTazFxV2t0V1YxbzJUVEpyTkZKR1RTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZPVEE1TUM4aUxDSmphR0ZzSWpvaVVETTBaVzB4TlVsd1ducEJlVmQyVld0b1YyVlFibFZNY2pkWVNHWkJlWElpZlEuNEw5d0xSaXlTUk96Y196WTNWUHdyMXNBRi1KdDRQZDhwOThmMWFkRzVHU1VrRnNsQUxsN08wZHJtS0RtbzIxZF9VcXl5SkNEUjJkb3JYT3lHeVFTQXc
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImxkbUw0bk9BT3RIZGxqczZWZUxCUFZ1SXVnQW5SZklDdnpHODBEcFRfT3MifX0.eyJpYXQiOjE2ODAxODMzMzAsImV4cCI6MTY4Nzk1OTMzMCwibmJmIjoxNjgwMTgzMzMwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJzdWIiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbTo5MDkwLyIsImp0aSI6IjFjYWI4ZmM2LWIxZGEtNDQwZC05MTkxLTc3MjViYmM0NGQ1ZCIsIm5vbmNlIjoiTm1odE4yTmllRGh1ZW5oeGJVSlFVWGhQVVVwSk1qWktWV1o2TTJrNFJGTSIsImNoYWwiOiJQMzRlbTE1SXBaekF5V3ZVa2hXZVBuVUxyN1hIZkF5ciIsImNuZiI6eyJraWQiOiJyWmNwb3Z2aTFXWlNjMTNvdTNxZkswNUVCZl9VRW50T3ItdDItcmVCTzc4In0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVDJoS1UwSTBlRTlPUjFBMFNFMTFhR3hNYm5SeE5XbFlhVU0yT1hsaVMxQnpOVzVNUkZWVVZVSTFaeUo5ZlEuZXlKcFlYUWlPakUyT0RBeE9ETXpNekFzSW1WNGNDSTZNVFk0TURFNE5qa3pNQ3dpYm1KbUlqb3hOamd3TVRnek16TXdMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTF0Um1sTmVtc3pUbGRLYVU1dFZtcE9SR014V1cxRk1VNVhTbXhhVkdjeVRXMU5kMWxYVG1oUFIxVXZNV014TWpJd01UbGtNalExTldGaU5VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqWTROVE14TmpkakxUTmlOemt0TkRVellpMDROelJpTFdaaU0yTm1OV1JsWlRZMU9DSXNJbTV2Ym1ObElqb2lUbTFvZEU0eVRtbGxSR2gxWlc1b2VHSlZTbEZWV0doUVZWVndTazFxV2t0V1YxbzJUVEpyTkZKR1RTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZPVEE1TUM4aUxDSmphR0ZzSWpvaVVETTBaVzB4TlVsd1ducEJlVmQyVld0b1YyVlFibFZNY2pkWVNHWkJlWElpZlEuNEw5d0xSaXlTUk96Y196WTNWUHdyMXNBRi1KdDRQZDhwOThmMWFkRzVHU1VrRnNsQUxsN08wZHJtS0RtbzIxZF9VcXl5SkNEUjJkb3JYT3lHeVFTQXciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.JuWpnTnl7R2wPGtRe0U7SwylooJZUFuRjbHAsi9PoZZDz2AJ_m-7ihDiYjPYUEOcED_PrWlJbLLayZQuxskYDw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImxkbUw0bk9BT3RIZGxqczZWZUxCUFZ1SXVnQW5SZklDdnpHODBEcFRfT3MifX0.eyJpYXQiOjE2ODAxODMzMzAsImV4cCI6MTY4Nzk1OTMzMCwibmJmIjoxNjgwMTgzMzMwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJzdWIiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbTo5MDkwLyIsImp0aSI6IjFjYWI4ZmM2LWIxZGEtNDQwZC05MTkxLTc3MjViYmM0NGQ1ZCIsIm5vbmNlIjoiTm1odE4yTmllRGh1ZW5oeGJVSlFVWGhQVVVwSk1qWktWV1o2TTJrNFJGTSIsImNoYWwiOiJQMzRlbTE1SXBaekF5V3ZVa2hXZVBuVUxyN1hIZkF5ciIsImNuZiI6eyJraWQiOiJyWmNwb3Z2aTFXWlNjMTNvdTNxZkswNUVCZl9VRW50T3ItdDItcmVCTzc4In0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVDJoS1UwSTBlRTlPUjFBMFNFMTFhR3hNYm5SeE5XbFlhVU0yT1hsaVMxQnpOVzVNUkZWVVZVSTFaeUo5ZlEuZXlKcFlYUWlPakUyT0RBeE9ETXpNekFzSW1WNGNDSTZNVFk0TURFNE5qa3pNQ3dpYm1KbUlqb3hOamd3TVRnek16TXdMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTF0Um1sTmVtc3pUbGRLYVU1dFZtcE9SR014V1cxRk1VNVhTbXhhVkdjeVRXMU5kMWxYVG1oUFIxVXZNV014TWpJd01UbGtNalExTldGaU5VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqWTROVE14TmpkakxUTmlOemt0TkRVellpMDROelJpTFdaaU0yTm1OV1JsWlRZMU9DSXNJbTV2Ym1ObElqb2lUbTFvZEU0eVRtbGxSR2gxWlc1b2VHSlZTbEZWV0doUVZWVndTazFxV2t0V1YxbzJUVEpyTkZKR1RTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZPVEE1TUM4aUxDSmphR0ZzSWpvaVVETTBaVzB4TlVsd1ducEJlVmQyVld0b1YyVlFibFZNY2pkWVNHWkJlWElpZlEuNEw5d0xSaXlTUk96Y196WTNWUHdyMXNBRi1KdDRQZDhwOThmMWFkRzVHU1VrRnNsQUxsN08wZHJtS0RtbzIxZF9VcXl5SkNEUjJkb3JYT3lHeVFTQXciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.JuWpnTnl7R2wPGtRe0U7SwylooJZUFuRjbHAsi9PoZZDz2AJ_m-7ihDiYjPYUEOcED_PrWlJbLLayZQuxskYDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6ImxkbUw0bk9BT3RIZGxqczZWZUxCUFZ1SXVn
QW5SZklDdnpHODBEcFRfT3MifX0.eyJpYXQiOjE2ODAxODMzMzAsImV4cCI6MTY4
Nzk1OTMzMCwibmJmIjoxNjgwMTgzMzMwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
OTA5MC8iLCJzdWIiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1F
MU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbSIs
ImF1ZCI6Imh0dHA6Ly93aXJlLmNvbTo5MDkwLyIsImp0aSI6IjFjYWI4ZmM2LWIx
ZGEtNDQwZC05MTkxLTc3MjViYmM0NGQ1ZCIsIm5vbmNlIjoiTm1odE4yTmllRGh1
ZW5oeGJVSlFVWGhQVVVwSk1qWktWV1o2TTJrNFJGTSIsImNoYWwiOiJQMzRlbTE1
SXBaekF5V3ZVa2hXZVBuVUxyN1hIZkF5ciIsImNuZiI6eyJraWQiOiJyWmNwb3Z2
aTFXWlNjMTNvdTNxZkswNUVCZl9VRW50T3ItdDItcmVCTzc4In0sInByb29mIjoi
ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRy
SWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9p
VDJoS1UwSTBlRTlPUjFBMFNFMTFhR3hNYm5SeE5XbFlhVU0yT1hsaVMxQnpOVzVN
UkZWVVZVSTFaeUo5ZlEuZXlKcFlYUWlPakUyT0RBeE9ETXpNekFzSW1WNGNDSTZN
VFk0TURFNE5qa3pNQ3dpYm1KbUlqb3hOamd3TVRnek16TXdMQ0p6ZFdJaU9pSnBi
VHAzYVhKbFlYQndQVTF0Um1sTmVtc3pUbGRLYVU1dFZtcE9SR014V1cxRk1VNVhT
bXhhVkdjeVRXMU5kMWxYVG1oUFIxVXZNV014TWpJd01UbGtNalExTldGaU5VQjNh
WEpsTG1OdmJTSXNJbXAwYVNJNklqWTROVE14TmpkakxUTmlOemt0TkRVellpMDRO
elJpTFdaaU0yTm1OV1JsWlRZMU9DSXNJbTV2Ym1ObElqb2lUbTFvZEU0eVRtbGxS
R2gxWlc1b2VHSlZTbEZWV0doUVZWVndTazFxV2t0V1YxbzJUVEpyTkZKR1RTSXNJ
bWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZP
VEE1TUM4aUxDSmphR0ZzSWpvaVVETTBaVzB4TlVsd1ducEJlVmQyVld0b1YyVlFi
bFZNY2pkWVNHWkJlWElpZlEuNEw5d0xSaXlTUk96Y196WTNWUHdyMXNBRi1KdDRQ
ZDhwOThmMWFkRzVHU1VrRnNsQUxsN08wZHJtS0RtbzIxZF9VcXl5SkNEUjJkb3JY
T3lHeVFTQXciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5t
VmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3
aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lk
In0.JuWpnTnl7R2wPGtRe0U7SwylooJZUFuRjbHAsi9PoZZDz2AJ_m-7ihDiYjPY
UEOcED_PrWlJbLLayZQuxskYDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "ldmL4nOAOtHdljs6VeLBPVuIugAnRfICvzG80DpT_Os"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:9090/",
  "chal": "P34em15IpZzAyWvUkhWePnULr7XHfAyr",
  "client_id": "im:wireapp=MmFiMzk3NWJiNmVjNDc1YmE1NWJlZTg2MmMwYWNhOGU/1c122019d2455ab5@wire.com",
  "cnf": {
    "kid": "rZcpovvi1WZSc13ou3qfK05EBf_UEntOr-t2-reBO78"
  },
  "exp": 1687959330,
  "iat": 1680183330,
  "iss": "http://wire.com:9090/",
  "jti": "1cab8fc6-b1da-440d-9191-7725bbc44d5d",
  "nbf": 1680183330,
  "nonce": "NmhtN2NieDhuenhxbUJQUXhPUUpJMjZKVWZ6M2k4RFM",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiT2hKU0I0eE9OR1A0SE11aGxMbnRxNWlYaUM2OXliS1BzNW5MRFVUVUI1ZyJ9fQ.eyJpYXQiOjE2ODAxODMzMzAsImV4cCI6MTY4MDE4NjkzMCwibmJmIjoxNjgwMTgzMzMwLCJzdWIiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbSIsImp0aSI6IjY4NTMxNjdjLTNiNzktNDUzYi04NzRiLWZiM2NmNWRlZTY1OCIsIm5vbmNlIjoiTm1odE4yTmllRGh1ZW5oeGJVSlFVWGhQVVVwSk1qWktWV1o2TTJrNFJGTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJjaGFsIjoiUDM0ZW0xNUlwWnpBeVd2VWtoV2VQblVMcjdYSGZBeXIifQ.4L9wLRiySROzc_zY3VPwr1sAF-Jt4Pd8p98f1adG5GSUkFslALl7O0drmKDmo21d_UqyyJCDR2dorXOyGyQSAw",
  "scope": "wire_client_id",
  "sub": "im:wireapp=MmFiMzk3NWJiNmVjNDc1YmE1NWJlZTg2MmMwYWNhOGU/1c122019d2455ab5@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDIT92xbeZ5Yvyt4lqnJmuJGSS8Q+KigO2W6KdZ4Yn6b
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAldmL4nOAOtHdljs6VeLBPVuIugAnRfICvzG80DpT/Os=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/Tom4LeMzZP64x2ttMAJ5TQHtWo9GGf42
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MzY0L2FjbWUvd2lyZS9hY2NvdW50L2ZMb3p3dDlBU05NQTBvWUtUbmZpMEgxbHpIaDhzQ3pJIiwidHlwIjoiSldUIiwibm9uY2UiOiJObVpOVkV4c1JEQnBZWHBoUkV4V1VtWnRkakIzYm1wc00wcEdlVGxHWTBNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNjQvYWNtZS93aXJlL2NoYWxsZW5nZS9qOEZ2Z1RZWUNQeUdLNTVCS3NXZ1RZWk83aExDMHRZTy9Ub200TGVNelpQNjR4MnR0TUFKNVRRSHRXbzlHR2Y0MiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklteGtiVXcwYms5QlQzUklaR3hxY3paV1pVeENVRloxU1hWblFXNVNaa2xEZG5wSE9EQkVjRlJmVDNNaWZYMC5leUpwWVhRaU9qRTJPREF4T0RNek16QXNJbVY0Y0NJNk1UWTROemsxT1RNek1Dd2libUptSWpveE5qZ3dNVGd6TXpNd0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2T1RBNU1DOGlMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTF0Um1sTmVtc3pUbGRLYVU1dFZtcE9SR014V1cxRk1VNVhTbXhhVkdjeVRXMU5kMWxYVG1oUFIxVXZNV014TWpJd01UbGtNalExTldGaU5VQjNhWEpsTG1OdmJTSXNJbUYxWkNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRvNU1Ea3dMeUlzSW1wMGFTSTZJakZqWVdJNFptTTJMV0l4WkdFdE5EUXdaQzA1TVRreExUYzNNalZpWW1NME5HUTFaQ0lzSW01dmJtTmxJam9pVG0xb2RFNHlUbWxsUkdoMVpXNW9lR0pWU2xGVldHaFFWVlZ3U2sxcVdrdFdWMW8yVFRKck5GSkdUU0lzSW1Ob1lXd2lPaUpRTXpSbGJURTFTWEJhZWtGNVYzWlZhMmhYWlZCdVZVeHlOMWhJWmtGNWNpSXNJbU51WmlJNmV5SnJhV1FpT2lKeVdtTndiM1oyYVRGWFdsTmpNVE52ZFROeFprc3dOVVZDWmw5VlJXNTBUM0l0ZERJdGNtVkNUemM0SW4wc0luQnliMjltSWpvaVpYbEthR0pIWTJsUGFVcEdXa1ZTVkZGVFNYTkpibEkxWTBOSk5rbHRVbmRpTTBGeVlXNWtNRWxwZDJsaGJtUnlTV3B3TjBsdGREQmxVMGsyU1dzNVRGVkRTWE5KYlU1NVpHbEpOa2xyVm10TmFsVXhUVlJyYVV4RFNqUkphbTlwVkRKb1MxVXdTVEJsUlRsUFVqRkJNRk5GTVRGaFIzaE5ZbTVTZUU1WGJGbGhWVTB5VDFoc2FWTXhRbnBPVnpWTlVrWldWVlpWU1RGYWVVbzVabEV1WlhsS2NGbFlVV2xQYWtVeVQwUkJlRTlFVFhwTmVrRnpTVzFXTkdORFNUWk5WRmswVFVSRk5FNXFhM3BOUTNkcFltMUtiVWxxYjNoT2FtZDNUVlJuZWsxNlRYZE1RMHA2WkZkSmFVOXBTbkJpVkhBellWaEtiRmxZUW5kUVZURjBVbTFzVG1WdGMzcFViR1JMWVZVMWRGWnRjRTlTUjAxNFYxY3hSazFWTlZoVGJYaGhWa2RqZVZSWE1VNWtNV3hZVkcxb1VGSXhWWFpOVjAxNFRXcEpkMDFVYkd0TmFsRXhUbGRHYVU1VlFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2xxV1RST1ZFMTRUbXBrYWt4VVRtbE9lbXQwVGtSVmVsbHBNRFJPZWxKcFRGZGFhVTB5VG0xT1YxSnNXbFJaTVU5RFNYTkpiVFYyWW0xT2JFbHFiMmxVYlRGdlpFVTBlVlJ0Ykd4U1IyZ3hXbGMxYjJWSFNsWlRiRVpXVjBkb1VWWldWbmRUYXpGeFYydDBWMVl4YnpKVVZFcHlUa1pLUjFSVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpQVkVFMVRVTTRhVXhEU21waFIwWnpTV3B2YVZWRVRUQmFWekI0VGxWc2QxZHVjRUpsVm1ReVZsZDBiMVl5VmxGaWJGWk5ZMnBrV1ZOSFdrSmxXRWxwWmxFdU5FdzVkMHhTYVhsVFVrOTZZMTk2V1ROV1VIZHlNWE5CUmkxS2REUlFaRGh3T1RobU1XRmtSelZIVTFWclJuTnNRVXhzTjA4d1pISnRTMFJ0YnpJeFpGOVZjWGw1U2tORVVqSmtiM0pZVDNsSGVWRlRRWGNpTENKamJHbGxiblJmYVdRaU9pSnBiVHAzYVhKbFlYQndQVTF0Um1sTmVtc3pUbGRLYVU1dFZtcE9SR014V1cxRk1VNVhTbXhhVkdjeVRXMU5kMWxYVG1oUFIxVXZNV014TWpJd01UbGtNalExTldGaU5VQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvekxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLkp1V3BuVG5sN1Iyd1BHdFJlMFU3U3d5bG9vSlpVRnVSamJIQXNpOVBvWlpEejJBSl9tLTdpaERpWWpQWVVFT2NFRF9QcldsSmJMTGF5WlF1eHNrWUR3In0",
  "signature": "p9TqAGRAx3IvmosOqgqHzf5Cbuj8XzFNbpAqIWn8yZOA_HLP7pm-jQzEF8w1C3n0vnau3zgtWfCBaHy9hYKyBw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImxkbUw0bk9BT3RIZGxqczZWZUxCUFZ1SXVnQW5SZklDdnpHODBEcFRfT3MifX0.eyJpYXQiOjE2ODAxODMzMzAsImV4cCI6MTY4Nzk1OTMzMCwibmJmIjoxNjgwMTgzMzMwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJzdWIiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbTo5MDkwLyIsImp0aSI6IjFjYWI4ZmM2LWIxZGEtNDQwZC05MTkxLTc3MjViYmM0NGQ1ZCIsIm5vbmNlIjoiTm1odE4yTmllRGh1ZW5oeGJVSlFVWGhQVVVwSk1qWktWV1o2TTJrNFJGTSIsImNoYWwiOiJQMzRlbTE1SXBaekF5V3ZVa2hXZVBuVUxyN1hIZkF5ciIsImNuZiI6eyJraWQiOiJyWmNwb3Z2aTFXWlNjMTNvdTNxZkswNUVCZl9VRW50T3ItdDItcmVCTzc4In0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVDJoS1UwSTBlRTlPUjFBMFNFMTFhR3hNYm5SeE5XbFlhVU0yT1hsaVMxQnpOVzVNUkZWVVZVSTFaeUo5ZlEuZXlKcFlYUWlPakUyT0RBeE9ETXpNekFzSW1WNGNDSTZNVFk0TURFNE5qa3pNQ3dpYm1KbUlqb3hOamd3TVRnek16TXdMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTF0Um1sTmVtc3pUbGRLYVU1dFZtcE9SR014V1cxRk1VNVhTbXhhVkdjeVRXMU5kMWxYVG1oUFIxVXZNV014TWpJd01UbGtNalExTldGaU5VQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqWTROVE14TmpkakxUTmlOemt0TkRVellpMDROelJpTFdaaU0yTm1OV1JsWlRZMU9DSXNJbTV2Ym1ObElqb2lUbTFvZEU0eVRtbGxSR2gxWlc1b2VHSlZTbEZWV0doUVZWVndTazFxV2t0V1YxbzJUVEpyTkZKR1RTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZPVEE1TUM4aUxDSmphR0ZzSWpvaVVETTBaVzB4TlVsd1ducEJlVmQyVld0b1YyVlFibFZNY2pkWVNHWkJlWElpZlEuNEw5d0xSaXlTUk96Y196WTNWUHdyMXNBRi1KdDRQZDhwOThmMWFkRzVHU1VrRnNsQUxsN08wZHJtS0RtbzIxZF9VcXl5SkNEUjJkb3JYT3lHeVFTQXciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU1tRmlNemszTldKaU5tVmpORGMxWW1FMU5XSmxaVGcyTW1Nd1lXTmhPR1UvMWMxMjIwMTlkMjQ1NWFiNUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.JuWpnTnl7R2wPGtRe0U7SwylooJZUFuRjbHAsi9PoZZDz2AJ_m-7ihDiYjPYUEOcED_PrWlJbLLayZQuxskYDw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56364/acme/wire/account/fLozwt9ASNMA0oYKTnfi0H1lzHh8sCzI",
    "nonce": "NmZNVExsRDBpYXphRExWUmZtdjB3bmpsM0pGeTlGY0M",
    "typ": "JWT",
    "url": "https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/Tom4LeMzZP64x2ttMAJ5TQHtWo9GGf42"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56364/acme/wire/directory>;rel="index"
link: <https://stepca:56364/acme/wire/authz/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO>;rel="up"
location: https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/Tom4LeMzZP64x2ttMAJ5TQHtWo9GGf42
replay-nonce: c1dMNElpT2VTV2hsMGxIWFFsaEV5OEoxb0doRU45cjA
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/Tom4LeMzZP64x2ttMAJ5TQHtWo9GGf42",
  "status": "valid",
  "token": "P34em15IpZzAyWvUkhWePnULr7XHfAyr"
}
```
#### 18. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhYWU4ZDdjOTIwNThiNWVlYTQ1Njg5NWJmODkwODQ1NzFlMzA2ZjMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI5NjcyNjk4OTk2NDc4NTY2MzgiLCJoZCI6IndpcmUuY29tIiwiZW1haWwiOiJiZWx0cmFtLm1hbGRhbnRAd2lyZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6Ii1LUFhEeTFwSEZnWWJmVlhVbHR4UXciLCJub25jZSI6IjFtNGJUN1MzUDRPT2hWTEFkWnZXdnciLCJuYW1lIjoiQmVsdHJhbSBNYWxkYW50IiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eGJsZmNWc3REOGRMVElSdUViSXUwU1Q2eElFTHk2Qkp3ZTNfTTNlPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkJlbHRyYW0iLCJmYW1pbHlfbmFtZSI6Ik1hbGRhbnQiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY4MDE4MzMzNCwiZXhwIjoxNjgwMTg2OTM0fQ.N-a9I8GAqd9Y7Hx0W14WA9mmGqwSXnc4g5ZAhISe5Cu7vG-yXc_QmydmrPwZmzI_GGgFZ6YkACjIBIvNS0SKiyfr1-3XW1cAB7E0bMBFr3HT3vV8MTpQVlNMscZOYdgFqyNpU8nFNyp-kBmpv4CRyrBHsEcBf-hiQptEhtx-G9EwHCjs1p0t7Z8QtKKKifocf3ctLOhsltrzVh_sCSIG4BhIcrkGujyz4d9DZr3fGMBMPHpXhdcb2pbmvAJ4n-HINYXlFHktEVvyWn4f3ubrN6PHRQrSyFL2-DF_0mBh7CeYODJKX51DyU03hYxF8LpyjvLKu1dM_PtZuKthpdU6gQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhYWU4ZDdjOTIwNThiNWVlYTQ1Njg5NWJm
ODkwODQ1NzFlMzA2ZjMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY
291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzb
XIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb
20iLCJhdWQiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpb
WVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI5N
jcyNjk4OTk2NDc4NTY2MzgiLCJoZCI6IndpcmUuY29tIiwiZW1haWwiOiJiZWx0c
mFtLm1hbGRhbnRAd2lyZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfa
GFzaCI6Ii1LUFhEeTFwSEZnWWJmVlhVbHR4UXciLCJub25jZSI6IjFtNGJUN1MzU
DRPT2hWTEFkWnZXdnciLCJuYW1lIjoiQmVsdHJhbSBNYWxkYW50IiwicGljdHVyZ
SI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eGJsZ
mNWc3REOGRMVElSdUViSXUwU1Q2eElFTHk2Qkp3ZTNfTTNlPXM5Ni1jIiwiZ2l2Z
W5fbmFtZSI6IkJlbHRyYW0iLCJmYW1pbHlfbmFtZSI6Ik1hbGRhbnQiLCJsb2Nhb
GUiOiJlbiIsImlhdCI6MTY4MDE4MzMzNCwiZXhwIjoxNjgwMTg2OTM0fQ.N-a9I8
GAqd9Y7Hx0W14WA9mmGqwSXnc4g5ZAhISe5Cu7vG-yXc_QmydmrPwZmzI_GGgFZ6
YkACjIBIvNS0SKiyfr1-3XW1cAB7E0bMBFr3HT3vV8MTpQVlNMscZOYdgFqyNpU8
nFNyp-kBmpv4CRyrBHsEcBf-hiQptEhtx-G9EwHCjs1p0t7Z8QtKKKifocf3ctLO
hsltrzVh_sCSIG4BhIcrkGujyz4d9DZr3fGMBMPHpXhdcb2pbmvAJ4n-HINYXlFH
ktEVvyWn4f3ubrN6PHRQrSyFL2-DF_0mBh7CeYODJKX51DyU03hYxF8LpyjvLKu1
dM_PtZuKthpdU6gQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "1aae8d7c92058b5eea456895bf89084571e306f3",
  "typ": "JWT"
}
```

```json
{
  "at_hash": "-KPXDy1pHFgYbfVXUltxQw",
  "aud": "338888153072-ktbh66pv3mr0ua0dn64sphgimeo0p7ss.apps.googleusercontent.com",
  "azp": "338888153072-ktbh66pv3mr0ua0dn64sphgimeo0p7ss.apps.googleusercontent.com",
  "email": "beltram.maldant@wire.com",
  "email_verified": true,
  "exp": 1680186934,
  "family_name": "Maldant",
  "given_name": "Beltram",
  "hd": "wire.com",
  "iat": 1680183334,
  "iss": "https://accounts.google.com",
  "locale": "en",
  "name": "Beltram Maldant",
  "nonce": "1m4bT7S3P4OOhVLAdZvWvw",
  "picture": "https://lh3.googleusercontent.com/a/AGNmyxblfcVstD8dLTIRuEbIu0ST6xIELy6BJwe3_M3e=s96-c",
  "sub": "112967269899647856638"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAonb+s1Mvbpti06Sp+ZsH
H5eeJxdvMhRgfmx5zK7cVlcAajI/0rKu8ylU2CkfgPlMe9+8W5ayozm1h2yx2ToS
7P7qoR1sMINXbKxobu8xy9zOBuFAr3WvEoor6lo0Qp747/4bN1sVU6GBEBEXLjb8
vHN+o/yoBv8NSB/yP7XbEaS3U5MJ4V2s5o7LziIIRP9PtzF0m3kWm7DuyEzGvCaW
8s9bOiMd3eZyXXyfKjlBB727eBXgwqcV+PttECRw6JCLO+11//lmqfKIj5CBw18P
b4ZrNwBa+XrGXfHSSAJXFkR4LR7Bj24sWzlOcKXN2Ew4h3WDJfxtN/StNSYoagya
FQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/U2lRA7XCmde2VaWK14iM74K8gkBcbNDQ
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MzY0L2FjbWUvd2lyZS9hY2NvdW50L2ZMb3p3dDlBU05NQTBvWUtUbmZpMEgxbHpIaDhzQ3pJIiwidHlwIjoiSldUIiwibm9uY2UiOiJjMWRNTkVscFQyVlRWMmhzTUd4SVdGRnNhRVY1T0VveGIwZG9SVTQ1Y2pBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNjQvYWNtZS93aXJlL2NoYWxsZW5nZS9qOEZ2Z1RZWUNQeUdLNTVCS3NXZ1RZWk83aExDMHRZTy9VMmxSQTdYQ21kZTJWYVdLMTRpTTc0Szhna0JjYk5EUSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJakZoWVdVNFpEZGpPVEl3TlRoaU5XVmxZVFExTmpnNU5XSm1PRGt3T0RRMU56RmxNekEyWmpNaUxDSjBlWEFpT2lKS1YxUWlmUS5leUpwYzNNaU9pSm9kSFJ3Y3pvdkwyRmpZMjkxYm5SekxtZHZiMmRzWlM1amIyMGlMQ0poZW5BaU9pSXpNemc0T0RneE5UTXdOekl0YTNSaWFEWTJjSFl6YlhJd2RXRXdaRzQyTkhOd2FHZHBiV1Z2TUhBM2MzTXVZWEJ3Y3k1bmIyOW5iR1YxYzJWeVkyOXVkR1Z1ZEM1amIyMGlMQ0poZFdRaU9pSXpNemc0T0RneE5UTXdOekl0YTNSaWFEWTJjSFl6YlhJd2RXRXdaRzQyTkhOd2FHZHBiV1Z2TUhBM2MzTXVZWEJ3Y3k1bmIyOW5iR1YxYzJWeVkyOXVkR1Z1ZEM1amIyMGlMQ0p6ZFdJaU9pSXhNVEk1TmpjeU5qazRPVGsyTkRjNE5UWTJNemdpTENKb1pDSTZJbmRwY21VdVkyOXRJaXdpWlcxaGFXd2lPaUppWld4MGNtRnRMbTFoYkdSaGJuUkFkMmx5WlM1amIyMGlMQ0psYldGcGJGOTJaWEpwWm1sbFpDSTZkSEoxWlN3aVlYUmZhR0Z6YUNJNklpMUxVRmhFZVRGd1NFWm5XV0ptVmxoVmJIUjRVWGNpTENKdWIyNWpaU0k2SWpGdE5HSlVOMU16VURSUFQyaFdURUZrV25aWGRuY2lMQ0p1WVcxbElqb2lRbVZzZEhKaGJTQk5ZV3hrWVc1MElpd2ljR2xqZEhWeVpTSTZJbWgwZEhCek9pOHZiR2d6TG1kdmIyZHNaWFZ6WlhKamIyNTBaVzUwTG1OdmJTOWhMMEZIVG0xNWVHSnNabU5XYzNSRU9HUk1WRWxTZFVWaVNYVXdVMVEyZUVsRlRIazJRa3AzWlROZlRUTmxQWE01Tmkxaklpd2laMmwyWlc1ZmJtRnRaU0k2SWtKbGJIUnlZVzBpTENKbVlXMXBiSGxmYm1GdFpTSTZJazFoYkdSaGJuUWlMQ0pzYjJOaGJHVWlPaUpsYmlJc0ltbGhkQ0k2TVRZNE1ERTRNek16TkN3aVpYaHdJam94Tmpnd01UZzJPVE0wZlEuTi1hOUk4R0FxZDlZN0h4MFcxNFdBOW1tR3F3U1huYzRnNVpBaElTZTVDdTd2Ry15WGNfUW15ZG1yUHdabXpJX0dHZ0ZaNllrQUNqSUJJdk5TMFNLaXlmcjEtM1hXMWNBQjdFMGJNQkZyM0hUM3ZWOE1UcFFWbE5Nc2NaT1lkZ0ZxeU5wVThuRk55cC1rQm1wdjRDUnlyQkhzRWNCZi1oaVFwdEVodHgtRzlFd0hDanMxcDB0N1o4UXRLS0tpZm9jZjNjdExPaHNsdHJ6Vmhfc0NTSUc0QmhJY3JrR3VqeXo0ZDlEWnIzZkdNQk1QSHBYaGRjYjJwYm12QUo0bi1ISU5ZWGxGSGt0RVZ2eVduNGYzdWJyTjZQSFJRclN5RkwyLURGXzBtQmg3Q2VZT0RKS1g1MUR5VTAzaFl4RjhMcHlqdkxLdTFkTV9QdFp1S3RocGRVNmdRIiwia2V5YXV0aCI6IlAzNGVtMTVJcFp6QXlXdlVraFdlUG5VTHI3WEhmQXlyLnFwX1Q2SGJfb0QwMTNibjNJbTNiNDZscGEyTnNvbXFPOU14S3FtM0VzQU0ifQ",
  "signature": "_1h-LahcADC_p-5us4Mu_7HyCJDxjzT8MdgOOv74mWYKRCKDfzlyDVntC14Qu-zQflyYwg5UKog2BgbzVLJHCQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjFhYWU4ZDdjOTIwNThiNWVlYTQ1Njg5NWJmODkwODQ1NzFlMzA2ZjMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI5NjcyNjk4OTk2NDc4NTY2MzgiLCJoZCI6IndpcmUuY29tIiwiZW1haWwiOiJiZWx0cmFtLm1hbGRhbnRAd2lyZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6Ii1LUFhEeTFwSEZnWWJmVlhVbHR4UXciLCJub25jZSI6IjFtNGJUN1MzUDRPT2hWTEFkWnZXdnciLCJuYW1lIjoiQmVsdHJhbSBNYWxkYW50IiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eGJsZmNWc3REOGRMVElSdUViSXUwU1Q2eElFTHk2Qkp3ZTNfTTNlPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkJlbHRyYW0iLCJmYW1pbHlfbmFtZSI6Ik1hbGRhbnQiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY4MDE4MzMzNCwiZXhwIjoxNjgwMTg2OTM0fQ.N-a9I8GAqd9Y7Hx0W14WA9mmGqwSXnc4g5ZAhISe5Cu7vG-yXc_QmydmrPwZmzI_GGgFZ6YkACjIBIvNS0SKiyfr1-3XW1cAB7E0bMBFr3HT3vV8MTpQVlNMscZOYdgFqyNpU8nFNyp-kBmpv4CRyrBHsEcBf-hiQptEhtx-G9EwHCjs1p0t7Z8QtKKKifocf3ctLOhsltrzVh_sCSIG4BhIcrkGujyz4d9DZr3fGMBMPHpXhdcb2pbmvAJ4n-HINYXlFHktEVvyWn4f3ubrN6PHRQrSyFL2-DF_0mBh7CeYODJKX51DyU03hYxF8LpyjvLKu1dM_PtZuKthpdU6gQ",
    "keyauth": "P34em15IpZzAyWvUkhWePnULr7XHfAyr.qp_T6Hb_oD013bn3Im3b46lpa2NsomqO9MxKqm3EsAM"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56364/acme/wire/account/fLozwt9ASNMA0oYKTnfi0H1lzHh8sCzI",
    "nonce": "c1dMNElpT2VTV2hsMGxIWFFsaEV5OEoxb0doRU45cjA",
    "typ": "JWT",
    "url": "https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/U2lRA7XCmde2VaWK14iM74K8gkBcbNDQ"
  }
}
```
#### 19. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56364/acme/wire/directory>;rel="index"
link: <https://stepca:56364/acme/wire/authz/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO>;rel="up"
location: https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/U2lRA7XCmde2VaWK14iM74K8gkBcbNDQ
replay-nonce: bWpvSnV0bWVkT1FYQlBmbVJzQU9ZU2Vkc2hpMjVlbTc
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:56364/acme/wire/challenge/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO/U2lRA7XCmde2VaWK14iM74K8gkBcbNDQ",
  "status": "valid",
  "token": "P34em15IpZzAyWvUkhWePnULr7XHfAyr"
}
```
### Client presents a CSR and gets its certificate
#### 20. verify the status of the order
```http request
POST https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MzY0L2FjbWUvd2lyZS9hY2NvdW50L2ZMb3p3dDlBU05NQTBvWUtUbmZpMEgxbHpIaDhzQ3pJIiwidHlwIjoiSldUIiwibm9uY2UiOiJiV3B2U25WMGJXVmtUMUZZUWxCbWJWSnpRVTlaVTJWa2MyaHBNalZsYlRjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNjQvYWNtZS93aXJlL29yZGVyL1FDZWZ2VkR0aTVqWlpOamR1cUxjQnJBa1VLZDBZbmhvIn0",
  "payload": "",
  "signature": "-z0enwfkyeIPZAYVmcVIqRsTfn7ecxw9u8o5Q_hnbPiSTC-P-Gkp0lj4Vjaajl2U1p8f2OuvRLhtijdn7_x8DQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56364/acme/wire/account/fLozwt9ASNMA0oYKTnfi0H1lzHh8sCzI",
    "nonce": "bWpvSnV0bWVkT1FYQlBmbVJzQU9ZU2Vkc2hpMjVlbTc",
    "typ": "JWT",
    "url": "https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho"
  }
}
```
#### 21. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56364/acme/wire/directory>;rel="index"
location: https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho
replay-nonce: VElGTU13T3RtR21nVUtNTjd2RUEzbTFqSDNxR1RHVGQ
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MmFiMzk3NWJiNmVjNDc1YmE1NWJlZTg2MmMwYWNhOGU/1c122019d2455ab5@wire.com\",\"handle\":\"beltram_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56364/acme/wire/authz/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO"
  ],
  "expires": "2023-03-31T13:35:30Z",
  "notBefore": "2023-03-30T13:35:30.621428Z",
  "notAfter": "2023-03-30T14:35:30.621428Z"
}
```
#### 22. create a CSR and call finalize url
```http request
POST https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MzY0L2FjbWUvd2lyZS9hY2NvdW50L2ZMb3p3dDlBU05NQTBvWUtUbmZpMEgxbHpIaDhzQ3pJIiwidHlwIjoiSldUIiwibm9uY2UiOiJWRWxHVFUxM1QzUnRSMjFuVlV0TlRqZDJSVUV6YlRGcVNETnhSMVJIVkdRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNjQvYWNtZS93aXJlL29yZGVyL1FDZWZ2VkR0aTVqWlpOamR1cUxjQnJBa1VLZDBZbmhvL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTVRDQjVBSUJBREExTVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFZ01CNEdDMkNHU0FHRy1FSURBWUZ4REE5Q1pXeDBjbUZ0SUUxaGJHUmhiblF3S2pBRkJnTXJaWEFESVFBNkVsSUhqRTQwWV9nY3k2R1V1ZTJybUplSUxyM0pzby16bWNzTlJOUUhtS0I4TUhvR0NTcUdTSWIzRFFFSkRqRnRNR3N3YVFZRFZSMFJCR0l3WUlaUWFXMDZkMmx5WldGd2NEMXRiV1pwYlhwck0yNTNhbWx1YlhacWJtUmpNWGx0WlRGdWQycHNlblJuTW0xdGJYZDVkMjVvYjJkMUx6RmpNVEl5TURFNVpESTBOVFZoWWpWQWQybHlaUzVqYjIyR0RHSmxiSFJ5WVcxZmQybHlaVEFGQmdNclpYQURRUUJuVkY4QmhtRUNYQng3d1B5S25FVTJSQUlDckNiM2RqOVRWSXU5UFVRN2NOcGZJeVZ5a1dXWGpHbzc3cG8wUXNjMjQ2VXg0bGRZRUU2V1NYcllGNlVNIn0",
  "signature": "416k_jpgiaA9YvwCtLekj-E8NCeouUVIrTq0mQNdbe1nYB4TMgaEnRGCJpUcdzZeWbsR9EeSKikeHRVQQRr1AA"
}
```
```json
{
  "payload": {
    "csr": "MIIBMTCB5AIBADA1MREwDwYDVQQKDAh3aXJlLmNvbTEgMB4GC2CGSAGG-EIDAYFxDA9CZWx0cmFtIE1hbGRhbnQwKjAFBgMrZXADIQA6ElIHjE40Y_gcy6GUue2rmJeILr3Jso-zmcsNRNQHmKB8MHoGCSqGSIb3DQEJDjFtMGswaQYDVR0RBGIwYIZQaW06d2lyZWFwcD1tbWZpbXprM253amlubXZqbmRjMXltZTFud2psenRnMm1tbXd5d25ob2d1LzFjMTIyMDE5ZDI0NTVhYjVAd2lyZS5jb22GDGJlbHRyYW1fd2lyZTAFBgMrZXADQQBnVF8BhmECXBx7wPyKnEU2RAICrCb3dj9TVIu9PUQ7cNpfIyVykWWXjGo77po0Qsc246Ux4ldYEE6WSXrYF6UM"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56364/acme/wire/account/fLozwt9ASNMA0oYKTnfi0H1lzHh8sCzI",
    "nonce": "VElGTU13T3RtR21nVUtNTjd2RUEzbTFqSDNxR1RHVGQ",
    "typ": "JWT",
    "url": "https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBMTCB5AIBADA1MREwDwYDVQQKDAh3aXJlLmNvbTEgMB4GC2CGSAGG+EIDAYFx
DA9CZWx0cmFtIE1hbGRhbnQwKjAFBgMrZXADIQA6ElIHjE40Y/gcy6GUue2rmJeI
Lr3Jso+zmcsNRNQHmKB8MHoGCSqGSIb3DQEJDjFtMGswaQYDVR0RBGIwYIZQaW06
d2lyZWFwcD1tbWZpbXprM253amlubXZqbmRjMXltZTFud2psenRnMm1tbXd5d25o
b2d1LzFjMTIyMDE5ZDI0NTVhYjVAd2lyZS5jb22GDGJlbHRyYW1fd2lyZTAFBgMr
ZXADQQBnVF8BhmECXBx7wPyKnEU2RAICrCb3dj9TVIu9PUQ7cNpfIyVykWWXjGo7
7po0Qsc246Ux4ldYEE6WSXrYF6UM
-----END CERTIFICATE REQUEST-----

```
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = wire.com, 2.16.840.1.113730.3.1.241 = Beltram Maldant
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    3a:12:52:07:8c:4e:34:63:f8:1c:cb:a1:94:b9:ed:
                    ab:98:97:88:2e:bd:c9:b2:8f:b3:99:cb:0d:44:d4:
                    07:98
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=mmfimzk3nwjinmvjndc1yme1nwjlztg2mmmwywnhogu/1c122019d2455ab5@wire.com, URI:beltram_wire
    Signature Algorithm: ED25519
    Signature Value:
        67:54:5f:01:86:61:02:5c:1c:7b:c0:fc:8a:9c:45:36:44:02:
        02:ac:26:f7:76:3f:53:54:8b:bd:3d:44:3b:70:da:5f:23:25:
        72:91:65:97:8c:6a:3b:ee:9a:34:42:c7:36:e3:a5:31:e2:57:
        58:10:4e:96:49:7a:d8:17:a5:0c

```

#### 23. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56364/acme/wire/directory>;rel="index"
location: https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho
replay-nonce: ODg5Skd2TjFWYTVFOE02dURJYk5vZVVhQkdYVmxGZFE
```
```json
{
  "certificate": "https://stepca:56364/acme/wire/certificate/ofP2iuiUFiZxCIdS5wYFPNPrZopSxnil",
  "status": "valid",
  "finalize": "https://stepca:56364/acme/wire/order/QCefvVDti5jZZNjduqLcBrAkUKd0Ynho/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=MmFiMzk3NWJiNmVjNDc1YmE1NWJlZTg2MmMwYWNhOGU/1c122019d2455ab5@wire.com\",\"handle\":\"beltram_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56364/acme/wire/authz/j8FvgTYYCPyGK55BKsWgTYZO7hLC0tYO"
  ],
  "expires": "2023-03-31T13:35:30Z",
  "notBefore": "2023-03-30T13:35:30.621428Z",
  "notAfter": "2023-03-30T14:35:30.621428Z"
}
```
#### 24. fetch the certificate
```http request
POST https://stepca:56364/acme/wire/certificate/ofP2iuiUFiZxCIdS5wYFPNPrZopSxnil
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MzY0L2FjbWUvd2lyZS9hY2NvdW50L2ZMb3p3dDlBU05NQTBvWUtUbmZpMEgxbHpIaDhzQ3pJIiwidHlwIjoiSldUIiwibm9uY2UiOiJPRGc1U2tkMlRqRldZVFZGT0UwMmRVUkpZazV2WlZWaFFrZFlWbXhHWkZFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYzNjQvYWNtZS93aXJlL2NlcnRpZmljYXRlL29mUDJpdWlVRmlaeENJZFM1d1lGUE5QclpvcFN4bmlsIn0",
  "payload": "",
  "signature": "aeL3Hg53YJU0vdSnF61jUTEECynOeDYuIucjmKvQ5AEdvcN283adQKLbXMj82FMCanGfHdXZo46x1IMFY824Dw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56364/acme/wire/account/fLozwt9ASNMA0oYKTnfi0H1lzHh8sCzI",
    "nonce": "ODg5Skd2TjFWYTVFOE02dURJYk5vZVVhQkdYVmxGZFE",
    "typ": "JWT",
    "url": "https://stepca:56364/acme/wire/certificate/ofP2iuiUFiZxCIdS5wYFPNPrZopSxnil"
  }
}
```
#### 25. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:56364/acme/wire/directory>;rel="index"
replay-nonce: ZThKYkEyMktHZWtpQXBOSGdZaGh0V3VTTnpjODNuRms
```
```json
"-----BEGIN CERTIFICATE-----\nMIICKDCCAc6gAwIBAgIRAPRyxJTBF43cFW5lzaxK1AcwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwMzMwMTMzNTMwWhcNMjMwMzMwMTQzNTMwWjAtMREwDwYDVQQKEwh3aXJlLmNv\nbTEYMBYGA1UEAxMPQmVsdHJhbSBNYWxkYW50MCowBQYDK2VwAyEAOhJSB4xONGP4\nHMuhlLntq5iXiC69ybKPs5nLDUTUB5ijgfwwgfkwDgYDVR0PAQH/BAQDAgeAMB0G\nA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU6/ip/G5R/7NR\nieoJ8gL02Xlp66cwHwYDVR0jBBgwFoAU7kGG3aFGgM8O+0aN3vvEsXIdDkYwaQYD\nVR0RBGIwYIYMYmVsdHJhbV93aXJlhlBpbTp3aXJlYXBwPW1tZmltemszbndqaW5t\ndmpuZGMxeW1lMW53amx6dGcybW1td3l3bmhvZ3UvMWMxMjIwMTlkMjQ1NWFiNUB3\naXJlLmNvbTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0E\nAwIDSAAwRQIhAMBnaOwR2r9xF8TRHx1j1bYWV3H0GndGEBIclW/SDVDJAiA+XL8C\nJ7wW/jmY1Vpz7QkG0nXyZnV+9PjBIdKACUG7Wg==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBujCCAV+gAwIBAgIRAJKpUiPVytYYZmX0nU6DHRMwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMzMDEz\nMzUyOFoXDTMzMDMyNzEzMzUyOFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATA\nbL1VPcLSdD4V0zUjBTurCx45AMr9Hn/G0zR1kM3P2bJG6kW323XTA7lcrC8o57VF\n900E9ohThTyVjgUwLoOyo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQU7kGG3aFGgM8O+0aN3vvEsXIdDkYwHwYDVR0jBBgw\nFoAUmzhnyFRwFiHkq4Uu4ssufwDB0JowCgYIKoZIzj0EAwIDSQAwRgIhAJjSYkpZ\n8ZtYzc+1UDc0HWKmKA8k4X5cVCd61Z57f9rkAiEAw24oCzADWa92KceTMSot10yl\nJ2tgZJHMfy0c+Rq3E/c=\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICKDCCAc6gAwIBAgIRAPRyxJTBF43cFW5lzaxK1AcwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwMzMwMTMzNTMwWhcNMjMwMzMwMTQzNTMwWjAtMREwDwYDVQQKEwh3aXJlLmNv
bTEYMBYGA1UEAxMPQmVsdHJhbSBNYWxkYW50MCowBQYDK2VwAyEAOhJSB4xONGP4
HMuhlLntq5iXiC69ybKPs5nLDUTUB5ijgfwwgfkwDgYDVR0PAQH/BAQDAgeAMB0G
A1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU6/ip/G5R/7NR
ieoJ8gL02Xlp66cwHwYDVR0jBBgwFoAU7kGG3aFGgM8O+0aN3vvEsXIdDkYwaQYD
VR0RBGIwYIYMYmVsdHJhbV93aXJlhlBpbTp3aXJlYXBwPW1tZmltemszbndqaW5t
dmpuZGMxeW1lMW53amx6dGcybW1td3l3bmhvZ3UvMWMxMjIwMTlkMjQ1NWFiNUB3
aXJlLmNvbTAdBgwrBgEEAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0E
AwIDSAAwRQIhAMBnaOwR2r9xF8TRHx1j1bYWV3H0GndGEBIclW/SDVDJAiA+XL8C
J7wW/jmY1Vpz7QkG0nXyZnV+9PjBIdKACUG7Wg==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f4:72:c4:94:c1:17:8d:dc:15:6e:65:cd:ac:4a:d4:07
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Mar 30 13:35:30 2023 GMT
            Not After : Mar 30 14:35:30 2023 GMT
        Subject: O = wire.com, CN = Beltram Maldant
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    3a:12:52:07:8c:4e:34:63:f8:1c:cb:a1:94:b9:ed:
                    ab:98:97:88:2e:bd:c9:b2:8f:b3:99:cb:0d:44:d4:
                    07:98
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                EB:F8:A9:FC:6E:51:FF:B3:51:89:EA:09:F2:02:F4:D9:79:69:EB:A7
            X509v3 Authority Key Identifier: 
                EE:41:86:DD:A1:46:80:CF:0E:FB:46:8D:DE:FB:C4:B1:72:1D:0E:46
            X509v3 Subject Alternative Name: 
                URI:beltram_wire, URI:im:wireapp=mmfimzk3nwjinmvjndc1yme1nwjlztg2mmmwywnhogu/1c122019d2455ab5@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:c0:67:68:ec:11:da:bf:71:17:c4:d1:1f:1d:
        63:d5:b6:16:57:71:f4:1a:77:46:10:12:1c:95:6f:d2:0d:50:
        c9:02:20:3e:5c:bf:02:27:bc:16:fe:39:98:d5:5a:73:ed:09:
        06:d2:75:f2:66:75:7e:f4:f8:c1:21:d2:80:09:41:bb:5a

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBujCCAV+gAwIBAgIRAJKpUiPVytYYZmX0nU6DHRMwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMzMDEz
MzUyOFoXDTMzMDMyNzEzMzUyOFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATA
bL1VPcLSdD4V0zUjBTurCx45AMr9Hn/G0zR1kM3P2bJG6kW323XTA7lcrC8o57VF
900E9ohThTyVjgUwLoOyo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQU7kGG3aFGgM8O+0aN3vvEsXIdDkYwHwYDVR0jBBgw
FoAUmzhnyFRwFiHkq4Uu4ssufwDB0JowCgYIKoZIzj0EAwIDSQAwRgIhAJjSYkpZ
8ZtYzc+1UDc0HWKmKA8k4X5cVCd61Z57f9rkAiEAw24oCzADWa92KceTMSot10yl
J2tgZJHMfy0c+Rq3E/c=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            92:a9:52:23:d5:ca:d6:18:66:65:f4:9d:4e:83:1d:13
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Mar 30 13:35:28 2023 GMT
            Not After : Mar 27 13:35:28 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:c0:6c:bd:55:3d:c2:d2:74:3e:15:d3:35:23:05:
                    3b:ab:0b:1e:39:00:ca:fd:1e:7f:c6:d3:34:75:90:
                    cd:cf:d9:b2:46:ea:45:b7:db:75:d3:03:b9:5c:ac:
                    2f:28:e7:b5:45:f7:4d:04:f6:88:53:85:3c:95:8e:
                    05:30:2e:83:b2
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                EE:41:86:DD:A1:46:80:CF:0E:FB:46:8D:DE:FB:C4:B1:72:1D:0E:46
            X509v3 Authority Key Identifier: 
                9B:38:67:C8:54:70:16:21:E4:AB:85:2E:E2:CB:2E:7F:00:C1:D0:9A
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:98:d2:62:4a:59:f1:9b:58:cd:cf:b5:50:37:
        34:1d:62:a6:28:0f:24:e1:7e:5c:54:27:7a:d5:9e:7b:7f:da:
        e4:02:21:00:c3:6e:28:0b:30:03:59:af:76:29:c7:93:31:2a:
        2d:d7:4c:a5:27:6b:60:64:91:cc:7f:2d:1c:f9:1a:b7:13:f7

```
