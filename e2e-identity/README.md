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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/769af11dfc839c66/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/g4sJld2cxRudkJectAoKa3hvF9RTV4Cd
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/mSD0HjaIvyqLeX5jBxnKESMQn1KyhUkT
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/TynMCllENE0jGp1pLgylFm9525LwiTGu
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:33578/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:33578/acme/wire/new-nonce",
  "newAccount": "https://stepca:33578/acme/wire/new-account",
  "newOrder": "https://stepca:33578/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:33578/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:33578/acme/wire/directory>;rel="index"
replay-nonce: cDdJeW5xVFFEaGFmc1pXcnluNVNIeHBjMzlaVXdRUGQ
```
```text
cDdJeW5xVFFEaGFmc1pXcnluNVNIeHBjMzlaVXdRUGQ
```
#### 5. create a new account
```http request
POST https://stepca:33578/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlFWWURvZ0pnaEEtakRtNC13WC1GTGduU3NTR2JoQVE0RmdVTU0tQWFOVjAifSwibm9uY2UiOiJjRGRKZVc1eFZGRkVhR0ZtYzFwWGNubHVOVk5JZUhCak16bGFWWGRSVUdRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM1NzgvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "1wrRbHphxuSH-r1tbV1QSXWOwUfYinGDueMDe4fMBgW9sry08eZgxHAakHaimCtenzTB1CQxX6no5vPfUJmPDg"
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
      "x": "QVYDogJghA-jDm4-wX-FLgnSsSGbhAQ4FgUMM-AaNV0"
    },
    "nonce": "cDdJeW5xVFFEaGFmc1pXcnluNVNIeHBjMzlaVXdRUGQ",
    "typ": "JWT",
    "url": "https://stepca:33578/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33578/acme/wire/directory>;rel="index"
location: https://stepca:33578/acme/wire/account/A9EyASaIJk5sJjFMtwW6H7pVEvAD3Jqn
replay-nonce: R0t1eWk2NjYwTzJZYkJ5Ukw4Y2FUNVM5QUI2MHJJWGQ
```
```json
{
  "status": "valid",
  "orders": "https://stepca:33578/acme/wire/account/A9EyASaIJk5sJjFMtwW6H7pVEvAD3Jqn/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:33578/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNTc4L2FjbWUvd2lyZS9hY2NvdW50L0E5RXlBU2FJSms1c0pqRk10d1c2SDdwVkV2QUQzSnFuIiwidHlwIjoiSldUIiwibm9uY2UiOiJSMHQxZVdrMk5qWXdUekpaWWtKNVVrdzRZMkZVTlZNNVFVSTJNSEpKV0dRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM1NzgvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9T0dFME1ERTNNVFUzWTJFMU5EUTRPR0ZsTldWaE9EUmxOVEEwTVRJMU5qTS83NjlhZjExZGZjODM5YzY2QHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9YWxpY2Vfd2lyZVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wNS0xN1QxMjo0NDoyNi4xMjMyMTVaIiwibm90QWZ0ZXIiOiIyMDIzLTA1LTE3VDEzOjQ0OjI2LjEyMzIxNVoifQ",
  "signature": "1N09Si8vjLgaYSWLBSaURs5e5TgXL97XMx-JQRY5KmeN3QS7ie-xGqy3kiUIq_iG5ecMt8XBXoDxX_lCY0zoCw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2023-05-17T13:44:26.123215Z",
    "notBefore": "2023-05-17T12:44:26.123215Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33578/acme/wire/account/A9EyASaIJk5sJjFMtwW6H7pVEvAD3Jqn",
    "nonce": "R0t1eWk2NjYwTzJZYkJ5Ukw4Y2FUNVM5QUI2MHJJWGQ",
    "typ": "JWT",
    "url": "https://stepca:33578/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33578/acme/wire/directory>;rel="index"
location: https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut
replay-nonce: eTNJMFVrVkF6SkVBYVdLSTZMbDI1MG1VZEdDM3RveDY
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33578/acme/wire/authz/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK"
  ],
  "expires": "2023-05-18T12:44:26Z",
  "notBefore": "2023-05-17T12:44:26.123215Z",
  "notAfter": "2023-05-17T13:44:26.123215Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:33578/acme/wire/authz/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNTc4L2FjbWUvd2lyZS9hY2NvdW50L0E5RXlBU2FJSms1c0pqRk10d1c2SDdwVkV2QUQzSnFuIiwidHlwIjoiSldUIiwibm9uY2UiOiJlVE5KTUZWclZrRjZTa1ZCWVZkTFNUWk1iREkxTUcxVlpFZERNM1J2ZURZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM1NzgvYWNtZS93aXJlL2F1dGh6L1J3dWNCZjU3QVo0cFdReVpCY0s4YTVhemZaSnFIM2lLIn0",
  "payload": "",
  "signature": "tJ-ZGpkR8YTvKqgBOeaQdpGkNd3JSu4Ga4_qgUC7lUzXCgRh8FysAj2XZjmKbjwyGPtrwgNzdg3Oq5i4gFNFBw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33578/acme/wire/account/A9EyASaIJk5sJjFMtwW6H7pVEvAD3Jqn",
    "nonce": "eTNJMFVrVkF6SkVBYVdLSTZMbDI1MG1VZEdDM3RveDY",
    "typ": "JWT",
    "url": "https://stepca:33578/acme/wire/authz/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33578/acme/wire/directory>;rel="index"
location: https://stepca:33578/acme/wire/authz/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK
replay-nonce: ZldNd25iQ09UWFd5Um5sNHQxeVdrNWdtZExaM2owM3A
```
```json
{
  "status": "pending",
  "expires": "2023-05-18T12:44:26Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/mSD0HjaIvyqLeX5jBxnKESMQn1KyhUkT",
      "status": "pending",
      "token": "ZpmXUhdOMAy0OnKQ76YW5YOL7w8vgJMC",
      "target": "http://dex:18395/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/g4sJld2cxRudkJectAoKa3hvF9RTV4Cd",
      "status": "pending",
      "token": "ZpmXUhdOMAy0OnKQ76YW5YOL7w8vgJMC",
      "target": "http://wire.com:15647/clients/769af11dfc839c66/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:15647/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
YzJ4Q0o3M2dSZGZtSlZrNERsWENhMk5tNGI0TzB0UGk
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUVZZRG9nSmdoQS1qRG00LXdYLUZMZ25Tc1NHYmhBUTRGZ1VNTS1BYU5WMCJ9fQ.eyJpYXQiOjE2ODQzMjc0NjYsImV4cCI6MTY4NDMzMTA2NiwibmJmIjoxNjg0MzI3NDYxLCJzdWIiOiJpbTp3aXJlYXBwPU9HRTBNREUzTVRVM1kyRTFORFE0T0dGbE5XVmhPRFJsTlRBME1USTFOak0vNzY5YWYxMWRmYzgzOWM2NkB3aXJlLmNvbSIsImp0aSI6ImY1ZjllMzM0LWVhZGMtNDgzYi1hZGFjLWZkZDU1OWI4ZTIwZCIsIm5vbmNlIjoiWXpKNFEwbzNNMmRTWkdadFNsWnJORVJzV0VOaE1rNXROR0kwVHpCMFVHayIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTU2NDcvY2xpZW50cy83NjlhZjExZGZjODM5YzY2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJacG1YVWhkT01BeTBPbktRNzZZVzVZT0w3dzh2Z0pNQyJ9.lWBagMb0_0GHlKQAgqR_jbEWUrzp1JTAorcquKFnjnueH-6upDnhNzPDxlY9LOV9E02LvvS8vu4_K6Di4lrZCA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUVZZRG9nSmdoQS1qRG00LXdYLUZMZ25T
c1NHYmhBUTRGZ1VNTS1BYU5WMCJ9fQ.eyJpYXQiOjE2ODQzMjc0NjYsImV4cCI6M
TY4NDMzMTA2NiwibmJmIjoxNjg0MzI3NDYxLCJzdWIiOiJpbTp3aXJlYXBwPU9HR
TBNREUzTVRVM1kyRTFORFE0T0dGbE5XVmhPRFJsTlRBME1USTFOak0vNzY5YWYxM
WRmYzgzOWM2NkB3aXJlLmNvbSIsImp0aSI6ImY1ZjllMzM0LWVhZGMtNDgzYi1hZ
GFjLWZkZDU1OWI4ZTIwZCIsIm5vbmNlIjoiWXpKNFEwbzNNMmRTWkdadFNsWnJOR
VJzV0VOaE1rNXROR0kwVHpCMFVHayIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MTU2NDcvY2xpZW50cy83NjlhZjExZGZjODM5YzY2L2FjY2Vzc
y10b2tlbiIsImNoYWwiOiJacG1YVWhkT01BeTBPbktRNzZZVzVZT0w3dzh2Z0pNQ
yJ9.lWBagMb0_0GHlKQAgqR_jbEWUrzp1JTAorcquKFnjnueH-6upDnhNzPDxlY9
LOV9E02LvvS8vu4_K6Di4lrZCA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "QVYDogJghA-jDm4-wX-FLgnSsSGbhAQ4FgUMM-AaNV0"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "ZpmXUhdOMAy0OnKQ76YW5YOL7w8vgJMC",
  "exp": 1684331066,
  "htm": "POST",
  "htu": "http://wire.com:15647/clients/769af11dfc839c66/access-token",
  "iat": 1684327466,
  "jti": "f5f9e334-eadc-483b-adac-fdd559b8e20d",
  "nbf": 1684327461,
  "nonce": "YzJ4Q0o3M2dSZGZtSlZrNERsWENhMk5tNGI0TzB0UGk",
  "sub": "im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIF3NAe8S0Ed9PJP0UDaGg2Igq6Qpoq7yKpIVIEpWnBsQ
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAQVYDogJghA+jDm4+wX+FLgnSsSGbhAQ4FgUMM+AaNV0=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:15647/clients/769af11dfc839c66/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVVZaWlJHOW5TbWRvUVMxcVJHMDBMWGRZTFVaTVoyNVRjMU5IWW1oQlVUUkdaMVZOVFMxQllVNVdNQ0o5ZlEuZXlKcFlYUWlPakUyT0RRek1qYzBOallzSW1WNGNDSTZNVFk0TkRNek1UQTJOaXdpYm1KbUlqb3hOamcwTXpJM05EWXhMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTlIUlRCTlJFVXpUVlJWTTFreVJURk9SRkUwVDBkR2JFNVhWbWhQUkZKc1RsUkJNRTFVU1RGT2FrMHZOelk1WVdZeE1XUm1Zemd6T1dNMk5rQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltWTFaamxsTXpNMExXVmhaR010TkRnellpMWhaR0ZqTFdaa1pEVTFPV0k0WlRJd1pDSXNJbTV2Ym1ObElqb2lXWHBLTkZFd2J6Tk5NbVJUV2tkYWRGTnNXbkpPUlZKelYwVk9hRTFyTlhST1Iwa3dWSHBDTUZWSGF5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFUyTkRjdlkyeHBaVzUwY3k4M05qbGhaakV4Wkdaak9ETTVZelkyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSmFjRzFZVldoa1QwMUJlVEJQYmt0Uk56WlpWelZaVDB3M2R6aDJaMHBOUXlKOS5sV0JhZ01iMF8wR0hsS1FBZ3FSX2piRVdVcnpwMUpUQW9yY3F1S0Zuam51ZUgtNnVwRG5oTnpQRHhsWTlMT1Y5RTAyTHZ2Uzh2dTRfSzZEaTRsclpDQQ
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJfeEdqN3dQXzlIa2JRczhVaDMxa3NIU2l3eUdjUE9ibk16a0h5MzBCM0EifX0.eyJpYXQiOjE2ODQzMjc0NjYsImV4cCI6MTY5MjEwMzQ2NiwibmJmIjoxNjg0MzI3NDYxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTU2NDcvY2xpZW50cy83NjlhZjExZGZjODM5YzY2L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9T0dFME1ERTNNVFUzWTJFMU5EUTRPR0ZsTldWaE9EUmxOVEEwTVRJMU5qTS83NjlhZjExZGZjODM5YzY2QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE1NjQ3L2NsaWVudHMvNzY5YWYxMWRmYzgzOWM2Ni9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJiNzhlMTM5Ny03MmM5LTQ4ODEtOWFmNi1kMzIwZWU2YzVmODciLCJub25jZSI6Ill6SjRRMG8zTTJkU1pHWnRTbFpyTkVSc1dFTmhNazV0TkdJMFR6QjBVR2siLCJjaGFsIjoiWnBtWFVoZE9NQXkwT25LUTc2WVc1WU9MN3c4dmdKTUMiLCJjbmYiOnsia2lkIjoiRHNuZlhlckFDM2lLZXRLSHBsdFYxV2dvdmpFRUozUlRXUUFBeTB2R1o1ZyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVVWWlpSRzluU21kb1FTMXFSRzAwTFhkWUxVWk1aMjVUYzFOSFltaEJVVFJHWjFWTlRTMUJZVTVXTUNKOWZRLmV5SnBZWFFpT2pFMk9EUXpNamMwTmpZc0ltVjRjQ0k2TVRZNE5ETXpNVEEyTml3aWJtSm1Jam94TmpnME16STNORFl4TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5SFJUQk5SRVV6VFZSVk0xa3lSVEZPUkZFMFQwZEdiRTVYVm1oUFJGSnNUbFJCTUUxVVNURk9hazB2TnpZNVlXWXhNV1JtWXpnek9XTTJOa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJbVkxWmpsbE16TTBMV1ZoWkdNdE5EZ3pZaTFoWkdGakxXWmtaRFUxT1dJNFpUSXdaQ0lzSW01dmJtTmxJam9pV1hwS05GRXdiek5OTW1SVFdrZGFkRk5zV25KT1JWSnpWMFZPYUUxck5YUk9SMGt3VkhwQ01GVkhheUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk5EY3ZZMnhwWlc1MGN5ODNOamxoWmpFeFpHWmpPRE01WXpZMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUphY0cxWVZXaGtUMDFCZVRCUGJrdFJOelpaVnpWWlQwdzNkemgyWjBwTlF5SjkubFdCYWdNYjBfMEdIbEtRQWdxUl9qYkVXVXJ6cDFKVEFvcmNxdUtGbmpudWVILTZ1cERuaE56UER4bFk5TE9WOUUwMkx2dlM4dnU0X0s2RGk0bHJaQ0EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU9HRTBNREUzTVRVM1kyRTFORFE0T0dGbE5XVmhPRFJsTlRBME1USTFOak0vNzY5YWYxMWRmYzgzOWM2NkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.8nWn5C5zZ1-wdUyPfCe3pcT7NUUyXwH-aiTVfoTGY3trT6cZCdDSyrRcTQ97M4eeNSHOiKg1BTek9jM1p1cyCA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJfeEdqN3dQXzlIa2JRczhVaDMxa3NIU2l3eUdjUE9ibk16a0h5MzBCM0EifX0.eyJpYXQiOjE2ODQzMjc0NjYsImV4cCI6MTY5MjEwMzQ2NiwibmJmIjoxNjg0MzI3NDYxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTU2NDcvY2xpZW50cy83NjlhZjExZGZjODM5YzY2L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9T0dFME1ERTNNVFUzWTJFMU5EUTRPR0ZsTldWaE9EUmxOVEEwTVRJMU5qTS83NjlhZjExZGZjODM5YzY2QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE1NjQ3L2NsaWVudHMvNzY5YWYxMWRmYzgzOWM2Ni9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJiNzhlMTM5Ny03MmM5LTQ4ODEtOWFmNi1kMzIwZWU2YzVmODciLCJub25jZSI6Ill6SjRRMG8zTTJkU1pHWnRTbFpyTkVSc1dFTmhNazV0TkdJMFR6QjBVR2siLCJjaGFsIjoiWnBtWFVoZE9NQXkwT25LUTc2WVc1WU9MN3c4dmdKTUMiLCJjbmYiOnsia2lkIjoiRHNuZlhlckFDM2lLZXRLSHBsdFYxV2dvdmpFRUozUlRXUUFBeTB2R1o1ZyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVVWWlpSRzluU21kb1FTMXFSRzAwTFhkWUxVWk1aMjVUYzFOSFltaEJVVFJHWjFWTlRTMUJZVTVXTUNKOWZRLmV5SnBZWFFpT2pFMk9EUXpNamMwTmpZc0ltVjRjQ0k2TVRZNE5ETXpNVEEyTml3aWJtSm1Jam94TmpnME16STNORFl4TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5SFJUQk5SRVV6VFZSVk0xa3lSVEZPUkZFMFQwZEdiRTVYVm1oUFJGSnNUbFJCTUUxVVNURk9hazB2TnpZNVlXWXhNV1JtWXpnek9XTTJOa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJbVkxWmpsbE16TTBMV1ZoWkdNdE5EZ3pZaTFoWkdGakxXWmtaRFUxT1dJNFpUSXdaQ0lzSW01dmJtTmxJam9pV1hwS05GRXdiek5OTW1SVFdrZGFkRk5zV25KT1JWSnpWMFZPYUUxck5YUk9SMGt3VkhwQ01GVkhheUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk5EY3ZZMnhwWlc1MGN5ODNOamxoWmpFeFpHWmpPRE01WXpZMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUphY0cxWVZXaGtUMDFCZVRCUGJrdFJOelpaVnpWWlQwdzNkemgyWjBwTlF5SjkubFdCYWdNYjBfMEdIbEtRQWdxUl9qYkVXVXJ6cDFKVEFvcmNxdUtGbmpudWVILTZ1cERuaE56UER4bFk5TE9WOUUwMkx2dlM4dnU0X0s2RGk0bHJaQ0EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU9HRTBNREUzTVRVM1kyRTFORFE0T0dGbE5XVmhPRFJsTlRBME1USTFOak0vNzY5YWYxMWRmYzgzOWM2NkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.8nWn5C5zZ1-wdUyPfCe3pcT7NUUyXwH-aiTVfoTGY3trT6cZCdDSyrRcTQ97M4eeNSHOiKg1BTek9jM1p1cyCA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InJfeEdqN3dQXzlIa2JRczhVaDMxa3NIU2l3
eUdjUE9ibk16a0h5MzBCM0EifX0.eyJpYXQiOjE2ODQzMjc0NjYsImV4cCI6MTY5
MjEwMzQ2NiwibmJmIjoxNjg0MzI3NDYxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MTU2NDcvY2xpZW50cy83NjlhZjExZGZjODM5YzY2L2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9T0dFME1ERTNNVFUzWTJFMU5EUTRPR0ZsTldWaE9EUmxO
VEEwTVRJMU5qTS83NjlhZjExZGZjODM5YzY2QHdpcmUuY29tIiwiYXVkIjoiaHR0
cDovL3dpcmUuY29tOjE1NjQ3L2NsaWVudHMvNzY5YWYxMWRmYzgzOWM2Ni9hY2Nl
c3MtdG9rZW4iLCJqdGkiOiJiNzhlMTM5Ny03MmM5LTQ4ODEtOWFmNi1kMzIwZWU2
YzVmODciLCJub25jZSI6Ill6SjRRMG8zTTJkU1pHWnRTbFpyTkVSc1dFTmhNazV0
TkdJMFR6QjBVR2siLCJjaGFsIjoiWnBtWFVoZE9NQXkwT25LUTc2WVc1WU9MN3c4
dmdKTUMiLCJjbmYiOnsia2lkIjoiRHNuZlhlckFDM2lLZXRLSHBsdFYxV2dvdmpF
RUozUlRXUUFBeTB2R1o1ZyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lz
SW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lz
SW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVVWWlpSRzluU21kb1FTMXFSRzAw
TFhkWUxVWk1aMjVUYzFOSFltaEJVVFJHWjFWTlRTMUJZVTVXTUNKOWZRLmV5SnBZ
WFFpT2pFMk9EUXpNamMwTmpZc0ltVjRjQ0k2TVRZNE5ETXpNVEEyTml3aWJtSm1J
am94TmpnME16STNORFl4TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5SFJUQk5S
RVV6VFZSVk0xa3lSVEZPUkZFMFQwZEdiRTVYVm1oUFJGSnNUbFJCTUUxVVNURk9h
azB2TnpZNVlXWXhNV1JtWXpnek9XTTJOa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJ
bVkxWmpsbE16TTBMV1ZoWkdNdE5EZ3pZaTFoWkdGakxXWmtaRFUxT1dJNFpUSXda
Q0lzSW01dmJtTmxJam9pV1hwS05GRXdiek5OTW1SVFdrZGFkRk5zV25KT1JWSnpW
MFZPYUUxck5YUk9SMGt3VkhwQ01GVkhheUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9k
SFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk5EY3ZZMnhwWlc1MGN5ODNO
amxoWmpFeFpHWmpPRE01WXpZMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lP
aUphY0cxWVZXaGtUMDFCZVRCUGJrdFJOelpaVnpWWlQwdzNkemgyWjBwTlF5Sjku
bFdCYWdNYjBfMEdIbEtRQWdxUl9qYkVXVXJ6cDFKVEFvcmNxdUtGbmpudWVILTZ1
cERuaE56UER4bFk5TE9WOUUwMkx2dlM4dnU0X0s2RGk0bHJaQ0EiLCJjbGllbnRf
aWQiOiJpbTp3aXJlYXBwPU9HRTBNREUzTVRVM1kyRTFORFE0T0dGbE5XVmhPRFJs
TlRBME1USTFOak0vNzY5YWYxMWRmYzgzOWM2NkB3aXJlLmNvbSIsImFwaV92ZXJz
aW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.8nWn5C5zZ1-wdUyPfCe3
pcT7NUUyXwH-aiTVfoTGY3trT6cZCdDSyrRcTQ97M4eeNSHOiKg1BTek9jM1p1cy
CA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "r_xGj7wP_9HkbQs8Uh31ksHSiwyGcPObnMzkHy30B3A"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:15647/clients/769af11dfc839c66/access-token",
  "chal": "ZpmXUhdOMAy0OnKQ76YW5YOL7w8vgJMC",
  "client_id": "im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com",
  "cnf": {
    "kid": "DsnfXerAC3iKetKHpltV1WgovjEEJ3RTWQAAy0vGZ5g"
  },
  "exp": 1692103466,
  "iat": 1684327466,
  "iss": "http://wire.com:15647/clients/769af11dfc839c66/access-token",
  "jti": "b78e1397-72c9-4881-9af6-d320ee6c5f87",
  "nbf": 1684327461,
  "nonce": "YzJ4Q0o3M2dSZGZtSlZrNERsWENhMk5tNGI0TzB0UGk",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUVZZRG9nSmdoQS1qRG00LXdYLUZMZ25Tc1NHYmhBUTRGZ1VNTS1BYU5WMCJ9fQ.eyJpYXQiOjE2ODQzMjc0NjYsImV4cCI6MTY4NDMzMTA2NiwibmJmIjoxNjg0MzI3NDYxLCJzdWIiOiJpbTp3aXJlYXBwPU9HRTBNREUzTVRVM1kyRTFORFE0T0dGbE5XVmhPRFJsTlRBME1USTFOak0vNzY5YWYxMWRmYzgzOWM2NkB3aXJlLmNvbSIsImp0aSI6ImY1ZjllMzM0LWVhZGMtNDgzYi1hZGFjLWZkZDU1OWI4ZTIwZCIsIm5vbmNlIjoiWXpKNFEwbzNNMmRTWkdadFNsWnJORVJzV0VOaE1rNXROR0kwVHpCMFVHayIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTU2NDcvY2xpZW50cy83NjlhZjExZGZjODM5YzY2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJacG1YVWhkT01BeTBPbktRNzZZVzVZT0w3dzh2Z0pNQyJ9.lWBagMb0_0GHlKQAgqR_jbEWUrzp1JTAorcquKFnjnueH-6upDnhNzPDxlY9LOV9E02LvvS8vu4_K6Di4lrZCA",
  "scope": "wire_client_id",
  "sub": "im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOafq/H72rAOgr58enk6wCOamS/OE+GnrUJFj2XlbDjS
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAr/xGj7wP/9HkbQs8Uh31ksHSiwyGcPObnMzkHy30B3A=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/g4sJld2cxRudkJectAoKa3hvF9RTV4Cd
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNTc4L2FjbWUvd2lyZS9hY2NvdW50L0E5RXlBU2FJSms1c0pqRk10d1c2SDdwVkV2QUQzSnFuIiwidHlwIjoiSldUIiwibm9uY2UiOiJabGROZDI1aVEwOVVXRmQ1VW01c05IUXhlVmRyTldkdFpFeGFNMm93TTNBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM1NzgvYWNtZS93aXJlL2NoYWxsZW5nZS9Sd3VjQmY1N0FaNHBXUXlaQmNLOGE1YXpmWkpxSDNpSy9nNHNKbGQyY3hSdWRrSmVjdEFvS2EzaHZGOVJUVjRDZCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluSmZlRWRxTjNkUVh6bElhMkpSY3poVmFETXhhM05JVTJsM2VVZGpVRTlpYmsxNmEwaDVNekJDTTBFaWZYMC5leUpwWVhRaU9qRTJPRFF6TWpjME5qWXNJbVY0Y0NJNk1UWTVNakV3TXpRMk5pd2libUptSWpveE5qZzBNekkzTkRZeExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk5EY3ZZMnhwWlc1MGN5ODNOamxoWmpFeFpHWmpPRE01WXpZMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5VDBkRk1FMUVSVE5OVkZVeldUSkZNVTVFVVRSUFIwWnNUbGRXYUU5RVVteE9WRUV3VFZSSk1VNXFUUzgzTmpsaFpqRXhaR1pqT0RNNVl6WTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0RvdkwzZHBjbVV1WTI5dE9qRTFOalEzTDJOc2FXVnVkSE12TnpZNVlXWXhNV1JtWXpnek9XTTJOaTloWTJObGMzTXRkRzlyWlc0aUxDSnFkR2tpT2lKaU56aGxNVE01TnkwM01tTTVMVFE0T0RFdE9XRm1OaTFrTXpJd1pXVTJZelZtT0RjaUxDSnViMjVqWlNJNklsbDZTalJSTUc4elRUSmtVMXBIV25SVGJGcHlUa1ZTYzFkRlRtaE5helYwVGtkSk1GUjZRakJWUjJzaUxDSmphR0ZzSWpvaVduQnRXRlZvWkU5TlFYa3dUMjVMVVRjMldWYzFXVTlNTjNjNGRtZEtUVU1pTENKamJtWWlPbnNpYTJsa0lqb2lSSE51WmxobGNrRkRNMmxMWlhSTFNIQnNkRll4VjJkdmRtcEZSVW96VWxSWFVVRkJlVEIyUjFvMVp5SjlMQ0p3Y205dlppSTZJbVY1U21oaVIyTnBUMmxLUmxwRlVsUlJVMGx6U1c1U05XTkRTVFpKYlZKM1lqTkJjbUZ1WkRCSmFYZHBZVzVrY2tscWNEZEpiWFF3WlZOSk5rbHJPVXhWUTBselNXMU9lV1JwU1RaSmExWnJUV3BWTVUxVWEybE1RMG8wU1dwdmFWVldXbHBTUnpsdVUyMWtiMUZUTVhGU1J6QXdURmhrV1V4VldrMWFNalZVWXpGT1NGbHRhRUpWVkZKSFdqRldUbFJUTVVKWlZUVlhUVU5LT1daUkxtVjVTbkJaV0ZGcFQycEZNazlFVVhwTmFtTXdUbXBaYzBsdFZqUmpRMGsyVFZSWk5FNUVUWHBOVkVFeVRtbDNhV0p0U20xSmFtOTRUbXBuTUUxNlNUTk9SRmw0VEVOS2VtUlhTV2xQYVVwd1lsUndNMkZZU214WldFSjNVRlU1U0ZKVVFrNVNSVlY2VkZaU1ZrMHhhM2xTVkVaUFVrWkZNRlF3WkVkaVJUVllWbTFvVUZKR1NuTlViRkpDVFVVeFZWTlVSazloYXpCMlRucFpOVmxYV1hoTlYxSnRXWHBuZWs5WFRUSk9hMEl6WVZoS2JFeHRUblppVTBselNXMXdNR0ZUU1RaSmJWa3hXbXBzYkUxNlRUQk1WMVpvV2tkTmRFNUVaM3BaYVRGb1drZEdha3hYV210YVJGVXhUMWRKTkZwVVNYZGFRMGx6U1cwMWRtSnRUbXhKYW05cFYxaHdTMDVHUlhkaWVrNU9UVzFTVkZkclpHRmtSazV6VjI1S1QxSldTbnBXTUZaUFlVVXhjazVZVWs5U01HdDNWa2h3UTAxR1ZraGhlVWx6U1cxb01HSlRTVFpKYkVKUVZURlJhVXhEU205a1NGVnBUMmxLYjJSSVVuZFBhVGgyWkRKc2VWcFROV3BpTWpBMlRWUlZNazVFWTNaWk1uaHdXbGMxTUdONU9ETk9hbXhvV21wRmVGcEhXbXBQUkUwMVdYcFpNa3d5Um1wWk1sWjZZM2t4TUdJeWRHeGlhVWx6U1cxT2IxbFhkMmxQYVVwaFkwY3hXVlpYYUd0VU1ERkNaVlJDVUdKcmRGSk9lbHBhVm5wV1dsUXdkek5rZW1neVdqQndUbEY1U2prdWJGZENZV2ROWWpCZk1FZEliRXRSUVdkeFVsOXFZa1ZYVlhKNmNERktWRUZ2Y21OeGRVdEdibXB1ZFdWSUxUWjFjRVJ1YUU1NlVFUjRiRms1VEU5V09VVXdNa3gyZGxNNGRuVTBYMHMyUkdrMGJISmFRMEVpTENKamJHbGxiblJmYVdRaU9pSnBiVHAzYVhKbFlYQndQVTlIUlRCTlJFVXpUVlJWTTFreVJURk9SRkUwVDBkR2JFNVhWbWhQUkZKc1RsUkJNRTFVU1RGT2FrMHZOelk1WVdZeE1XUm1Zemd6T1dNMk5rQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvekxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLjhuV241QzV6WjEtd2RVeVBmQ2UzcGNUN05VVXlYd0gtYWlUVmZvVEdZM3RyVDZjWkNkRFN5clJjVFE5N000ZWVOU0hPaUtnMUJUZWs5ak0xcDFjeUNBIn0",
  "signature": "G-I9AIs6BCortG3aokHr6sIRSMb6NldMbI0HToZLhw2iDGrYxKZDZuLkQKYT6SShLBKfuP1rV8b3FgG2cCWGCQ"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InJfeEdqN3dQXzlIa2JRczhVaDMxa3NIU2l3eUdjUE9ibk16a0h5MzBCM0EifX0.eyJpYXQiOjE2ODQzMjc0NjYsImV4cCI6MTY5MjEwMzQ2NiwibmJmIjoxNjg0MzI3NDYxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTU2NDcvY2xpZW50cy83NjlhZjExZGZjODM5YzY2L2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9T0dFME1ERTNNVFUzWTJFMU5EUTRPR0ZsTldWaE9EUmxOVEEwTVRJMU5qTS83NjlhZjExZGZjODM5YzY2QHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjE1NjQ3L2NsaWVudHMvNzY5YWYxMWRmYzgzOWM2Ni9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJiNzhlMTM5Ny03MmM5LTQ4ODEtOWFmNi1kMzIwZWU2YzVmODciLCJub25jZSI6Ill6SjRRMG8zTTJkU1pHWnRTbFpyTkVSc1dFTmhNazV0TkdJMFR6QjBVR2siLCJjaGFsIjoiWnBtWFVoZE9NQXkwT25LUTc2WVc1WU9MN3c4dmdKTUMiLCJjbmYiOnsia2lkIjoiRHNuZlhlckFDM2lLZXRLSHBsdFYxV2dvdmpFRUozUlRXUUFBeTB2R1o1ZyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVVWWlpSRzluU21kb1FTMXFSRzAwTFhkWUxVWk1aMjVUYzFOSFltaEJVVFJHWjFWTlRTMUJZVTVXTUNKOWZRLmV5SnBZWFFpT2pFMk9EUXpNamMwTmpZc0ltVjRjQ0k2TVRZNE5ETXpNVEEyTml3aWJtSm1Jam94TmpnME16STNORFl4TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU5SFJUQk5SRVV6VFZSVk0xa3lSVEZPUkZFMFQwZEdiRTVYVm1oUFJGSnNUbFJCTUUxVVNURk9hazB2TnpZNVlXWXhNV1JtWXpnek9XTTJOa0IzYVhKbExtTnZiU0lzSW1wMGFTSTZJbVkxWmpsbE16TTBMV1ZoWkdNdE5EZ3pZaTFoWkdGakxXWmtaRFUxT1dJNFpUSXdaQ0lzSW01dmJtTmxJam9pV1hwS05GRXdiek5OTW1SVFdrZGFkRk5zV25KT1JWSnpWMFZPYUUxck5YUk9SMGt3VkhwQ01GVkhheUlzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRVMk5EY3ZZMnhwWlc1MGN5ODNOamxoWmpFeFpHWmpPRE01WXpZMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUphY0cxWVZXaGtUMDFCZVRCUGJrdFJOelpaVnpWWlQwdzNkemgyWjBwTlF5SjkubFdCYWdNYjBfMEdIbEtRQWdxUl9qYkVXVXJ6cDFKVEFvcmNxdUtGbmpudWVILTZ1cERuaE56UER4bFk5TE9WOUUwMkx2dlM4dnU0X0s2RGk0bHJaQ0EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU9HRTBNREUzTVRVM1kyRTFORFE0T0dGbE5XVmhPRFJsTlRBME1USTFOak0vNzY5YWYxMWRmYzgzOWM2NkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.8nWn5C5zZ1-wdUyPfCe3pcT7NUUyXwH-aiTVfoTGY3trT6cZCdDSyrRcTQ97M4eeNSHOiKg1BTek9jM1p1cyCA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33578/acme/wire/account/A9EyASaIJk5sJjFMtwW6H7pVEvAD3Jqn",
    "nonce": "ZldNd25iQ09UWFd5Um5sNHQxeVdrNWdtZExaM2owM3A",
    "typ": "JWT",
    "url": "https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/g4sJld2cxRudkJectAoKa3hvF9RTV4Cd"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33578/acme/wire/directory>;rel="index"
link: <https://stepca:33578/acme/wire/authz/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK>;rel="up"
location: https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/g4sJld2cxRudkJectAoKa3hvF9RTV4Cd
replay-nonce: ZVhWTFBoSFdUelU0U1BiaVl1TWdsRUZVemNBam43TlY
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/g4sJld2cxRudkJectAoKa3hvF9RTV4Cd",
  "status": "valid",
  "token": "ZpmXUhdOMAy0OnKQ76YW5YOL7w8vgJMC",
  "target": "http://wire.com:15647/clients/769af11dfc839c66/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=EOWFoKw9nSIcKfgaN5BCIlcdzrCstuoIdsJjNRSYYZQ&code_challenge=98ZNxB1oOcksZNKy6KOffnVIdXzOHJLujm9JReHGHN0
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:18395/dex/auth?response_type=code&client_id=wireapp&state=ex1d7T3VmF_xcxnPjb8l8g&code_challenge=98ZNxB1oOcksZNKy6KOffnVIdXzOHJLujm9JReHGHN0&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A15647%2Fcallback&scope=openid+profile&nonce=q1kL9GT7wUq3zSGKuOeoqw
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:18395/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpOVmh4TW1WNk1FNXdlVE5PYlV3MVVGbFFXWFJyTldRNA==
```
```text
grant_type=authorization_code&code=h5org3bmmdc7suvggacko2tqn&code_verifier=EOWFoKw9nSIcKfgaN5BCIlcdzrCstuoIdsJjNRSYYZQ&redirect_uri=http%3A%2F%2Fwire.com%3A15647%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5NmUyOWQ2MzE1ZjNjYzkyYzZkMWMzNWM2MmM0ZjI5NDRjYTczYzEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4Mzk1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIUlRCTlJFVXpUVlJWTTFreVJURk9SRkUwVDBkR2JFNVhWbWhQUkZKc1RsUkJNRTFVU1RGT2FrMHZOelk1WVdZeE1XUm1Zemd6T1dNMk5rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0NDEzODY2LCJpYXQiOjE2ODQzMjc0NjYsIm5vbmNlIjoicTFrTDlHVDd3VXEzelNHS3VPZW9xdyIsImF0X2hhc2giOiJlbkR6NV8tOWdMNW1aMThRWUs5ZURBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.H2so6SGKH1yItQIAvc7-xsrEdAXbGGs_8wlTl2xxLdgPP_fCKjheSOCo_G5x_RsTjVMtRSwQlRNuUYWmQzvBmTYSsq9-UQi_9-gQqTCqTn7pKw6Voy4afZzgz8TAu6qpb0V15bu7-WfYtrNCgKtkBZegs_BhKv-jaF6xHuPHet6DCJdShkonJf47AmrXFObrdrlzehzaInoFkYqfC5GCBm0blcVBN-_TMJPxAQ7f4o3JJSe1Hd7m_YZSFWc5F0xoqOsFeXsJnTSRSj4GPWv6pme9bKTrqy7l0C_PzRNKnRlhZ3xmXXdpRVQaZuyOsUqV-FuHt1IFiiogJdJ9msqSvw",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5NmUyOWQ2MzE1ZjNjYzkyYzZkMWMzNWM2MmM0ZjI5NDRjYTczYzEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4Mzk1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIUlRCTlJFVXpUVlJWTTFreVJURk9SRkUwVDBkR2JFNVhWbWhQUkZKc1RsUkJNRTFVU1RGT2FrMHZOelk1WVdZeE1XUm1Zemd6T1dNMk5rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0NDEzODY2LCJpYXQiOjE2ODQzMjc0NjYsIm5vbmNlIjoicTFrTDlHVDd3VXEzelNHS3VPZW9xdyIsImF0X2hhc2giOiJMNnZmczRRdW54MTJfdHg0b2hXa2dnIiwiY19oYXNoIjoicXF2WGFYY0tlY0RBZ0daM1N0QWxNQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.gFxsx-lq-Q58JoG_f7iHqtVeScKHqKpQPMvQu6G3o2aiApk3fqw3vofafwyrWClswrPmdP2IpAVdSOs5zpqQoNmaAzuuan59OLm1xkd61WCeBGf3xFsDkw7p9YyGQ8JDcSEyyCgXMu2LPdcpkhoWxUBjEjkRASG1dGTNo5X54RwOV1FeAQv6z2kTiMWs69jh5k20s-a0jI3mazGCUCUQI4kFY7_C5ZCs3Tk1DwZ4kd4MaJNIA6947sgC6aLgJET0-sEthYPO-BSRoTYX7wARUx4vNuqf5o_aTmUQ0Sj-iFfgrv4gMyewpM4Ar5QcsznPO-sYJZjW4w4reoakbnVBZA",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5NmUyOWQ2MzE1ZjNjYzkyYzZkMWMzNWM2MmM0ZjI5NDRjYTczYzEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4Mzk1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIUlRCTlJFVXpUVlJWTTFreVJURk9SRkUwVDBkR2JFNVhWbWhQUkZKc1RsUkJNRTFVU1RGT2FrMHZOelk1WVdZeE1XUm1Zemd6T1dNMk5rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0NDEzODY2LCJpYXQiOjE2ODQzMjc0NjYsIm5vbmNlIjoicTFrTDlHVDd3VXEzelNHS3VPZW9xdyIsImF0X2hhc2giOiJMNnZmczRRdW54MTJfdHg0b2hXa2dnIiwiY19oYXNoIjoicXF2WGFYY0tlY0RBZ0daM1N0QWxNQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.gFxsx-lq-Q58JoG_f7iHqtVeScKHqKpQPMvQu6G3o2aiApk3fqw3vofafwyrWClswrPmdP2IpAVdSOs5zpqQoNmaAzuuan59OLm1xkd61WCeBGf3xFsDkw7p9YyGQ8JDcSEyyCgXMu2LPdcpkhoWxUBjEjkRASG1dGTNo5X54RwOV1FeAQv6z2kTiMWs69jh5k20s-a0jI3mazGCUCUQI4kFY7_C5ZCs3Tk1DwZ4kd4MaJNIA6947sgC6aLgJET0-sEthYPO-BSRoTYX7wARUx4vNuqf5o_aTmUQ0Sj-iFfgrv4gMyewpM4Ar5QcsznPO-sYJZjW4w4reoakbnVBZA
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5NmUyOWQ2MzE1ZjNjYzkyYzZkMWMzNWM2MmM0ZjI5NDRjYTczYzEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4Mzk1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIUlRCTlJFVXpUVlJWTTFreVJURk9SRkUwVDBkR2JFNVhWbWhQUkZKc1RsUkJNRTFVU1RGT2FrMHZOelk1WVdZeE1XUm1Zemd6T1dNMk5rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0NDEzODY2LCJpYXQiOjE2ODQzMjc0NjYsIm5vbmNlIjoicTFrTDlHVDd3VXEzelNHS3VPZW9xdyIsImF0X2hhc2giOiJMNnZmczRRdW54MTJfdHg0b2hXa2dnIiwiY19oYXNoIjoicXF2WGFYY0tlY0RBZ0daM1N0QWxNQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.gFxsx-lq-Q58JoG_f7iHqtVeScKHqKpQPMvQu6G3o2aiApk3fqw3vofafwyrWClswrPmdP2IpAVdSOs5zpqQoNmaAzuuan59OLm1xkd61WCeBGf3xFsDkw7p9YyGQ8JDcSEyyCgXMu2LPdcpkhoWxUBjEjkRASG1dGTNo5X54RwOV1FeAQv6z2kTiMWs69jh5k20s-a0jI3mazGCUCUQI4kFY7_C5ZCs3Tk1DwZ4kd4MaJNIA6947sgC6aLgJET0-sEthYPO-BSRoTYX7wARUx4vNuqf5o_aTmUQ0Sj-iFfgrv4gMyewpM4Ar5QcsznPO-sYJZjW4w4reoakbnVBZA)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5NmUyOWQ2MzE1ZjNjYzkyYzZkMWMzNWM2
MmM0ZjI5NDRjYTczYzEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4Mzk1L2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIUlRCTlJFVXpUVlJWTTFreVJURk9SR
kUwVDBkR2JFNVhWbWhQUkZKc1RsUkJNRTFVU1RGT2FrMHZOelk1WVdZeE1XUm1Ze
md6T1dNMk5rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjg0NDEzODY2LCJpYXQiOjE2ODQzMjc0NjYsIm5vbmNlIjoicTFrTDlHV
Dd3VXEzelNHS3VPZW9xdyIsImF0X2hhc2giOiJMNnZmczRRdW54MTJfdHg0b2hXa
2dnIiwiY19oYXNoIjoicXF2WGFYY0tlY0RBZ0daM1N0QWxNQSIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZ
SBTbWl0aCJ9.gFxsx-lq-Q58JoG_f7iHqtVeScKHqKpQPMvQu6G3o2aiApk3fqw3
vofafwyrWClswrPmdP2IpAVdSOs5zpqQoNmaAzuuan59OLm1xkd61WCeBGf3xFsD
kw7p9YyGQ8JDcSEyyCgXMu2LPdcpkhoWxUBjEjkRASG1dGTNo5X54RwOV1FeAQv6
z2kTiMWs69jh5k20s-a0jI3mazGCUCUQI4kFY7_C5ZCs3Tk1DwZ4kd4MaJNIA694
7sgC6aLgJET0-sEthYPO-BSRoTYX7wARUx4vNuqf5o_aTmUQ0Sj-iFfgrv4gMyew
pM4Ar5QcsznPO-sYJZjW4w4reoakbnVBZA
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "596e29d6315f3cc92c6d1c35c62c4f2944ca73c1"
}
```

```json
{
  "at_hash": "L6vfs4Qunx12_tx4ohWkgg",
  "aud": "wireapp",
  "c_hash": "qqvXaXcKecDAgGZ3StAlMA",
  "exp": 1684413866,
  "iat": 1684327466,
  "iss": "http://dex:18395/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "q1kL9GT7wUq3zSGKuOeoqw",
  "preferred_username": "Alice Smith",
  "sub": "ClBpbTp3aXJlYXBwPU9HRTBNREUzTVRVM1kyRTFORFE0T0dGbE5XVmhPRFJsTlRBME1USTFOak0vNzY5YWYxMWRmYzgzOWM2NkB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2kzQkxGz3EOJhNcIxFjZ
u84rxQnhRPmj/wR/jNROnby0FJOuBjpuMDJisDqbYc0JlCzedZKUNWdq0Pcyg5N3
9SqYa5R33m5nHOIdRmotJPSO7ka1zfmhXbLnoHt6HC9gQiQAs+xyXG5DQTb7juze
Rj9V95jOgJZsl1KYYxBERc58lB3o7uBr1Yf3EPgRByKhTY3wuYrFEvsyZxW1lo3D
1aNR1s1XBqk/VEeUJfSkYjp3UeHN1JSkgGmhGIS25jEyfcg74ekLbylwr+2MveHA
dXRwSqO49s9GC5jWs6q2twmaIYCJ+Jr6j45CmNMzn8vyZQV6c+ikIve2T9ZmVqa3
5QIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/mSD0HjaIvyqLeX5jBxnKESMQn1KyhUkT
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNTc4L2FjbWUvd2lyZS9hY2NvdW50L0E5RXlBU2FJSms1c0pqRk10d1c2SDdwVkV2QUQzSnFuIiwidHlwIjoiSldUIiwibm9uY2UiOiJaVmhXVEZCb1NGZFVlbFUwVTFCaWFWbDFUV2RzUlVaVmVtTkJhbTQzVGxZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM1NzgvYWNtZS93aXJlL2NoYWxsZW5nZS9Sd3VjQmY1N0FaNHBXUXlaQmNLOGE1YXpmWkpxSDNpSy9tU0QwSGphSXZ5cUxlWDVqQnhuS0VTTVFuMUt5aFVrVCJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJalU1Tm1VeU9XUTJNekUxWmpOall6a3lZelprTVdNek5XTTJNbU0wWmpJNU5EUmpZVGN6WXpFaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTRNemsxTDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZUbElVbFJDVGxKRlZYcFVWbEpXVFRGcmVWSlVSazlTUmtVd1ZEQmtSMkpGTlZoV2JXaFFVa1pLYzFSc1VrSk5SVEZWVTFSR1QyRnJNSFpPZWxrMVdWZFplRTFYVW0xWmVtZDZUMWROTWs1clFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qZzBOREV6T0RZMkxDSnBZWFFpT2pFMk9EUXpNamMwTmpZc0ltNXZibU5sSWpvaWNURnJURGxIVkRkM1ZYRXplbE5IUzNWUFpXOXhkeUlzSW1GMFgyaGhjMmdpT2lKTU5uWm1jelJSZFc1NE1USmZkSGcwYjJoWGEyZG5JaXdpWTE5b1lYTm9Jam9pY1hGMldHRllZMHRsWTBSQlowZGFNMU4wUVd4TlFTSXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObFgzZHBjbVVpTENKd2NtVm1aWEp5WldSZmRYTmxjbTVoYldVaU9pSkJiR2xqWlNCVGJXbDBhQ0o5LmdGeHN4LWxxLVE1OEpvR19mN2lIcXRWZVNjS0hxS3BRUE12UXU2RzNvMmFpQXBrM2ZxdzN2b2ZhZnd5cldDbHN3clBtZFAySXBBVmRTT3M1enBxUW9ObWFBenV1YW41OU9MbTF4a2Q2MVdDZUJHZjN4RnNEa3c3cDlZeUdROEpEY1NFeXlDZ1hNdTJMUGRjcGtob1d4VUJqRWprUkFTRzFkR1RObzVYNTRSd09WMUZlQVF2Nnoya1RpTVdzNjlqaDVrMjBzLWEwakkzbWF6R0NVQ1VRSTRrRlk3X0M1WkNzM1RrMUR3WjRrZDRNYUpOSUE2OTQ3c2dDNmFMZ0pFVDAtc0V0aFlQTy1CU1JvVFlYN3dBUlV4NHZOdXFmNW9fYVRtVVEwU2otaUZmZ3J2NGdNeWV3cE00QXI1UWNzem5QTy1zWUpaalc0dzRyZW9ha2JuVkJaQSIsImtleWF1dGgiOiJacG1YVWhkT01BeTBPbktRNzZZVzVZT0w3dzh2Z0pNQy5JTUhVN2tsOU5Nb1p3bHdobUFXTU5JWW1jN1NhS0J0SUVDS25xZFVvOEw0In0",
  "signature": "qStB8nzEKAbzlC2qJ_vQxcglB-VnKHx7VlqyMjtPP42tpkIO_H5UI9oEeRsSIQZV7JTn_Zedx6lMcUGXJPfrAA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5NmUyOWQ2MzE1ZjNjYzkyYzZkMWMzNWM2MmM0ZjI5NDRjYTczYzEifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4Mzk1L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVTlIUlRCTlJFVXpUVlJWTTFreVJURk9SRkUwVDBkR2JFNVhWbWhQUkZKc1RsUkJNRTFVU1RGT2FrMHZOelk1WVdZeE1XUm1Zemd6T1dNMk5rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjg0NDEzODY2LCJpYXQiOjE2ODQzMjc0NjYsIm5vbmNlIjoicTFrTDlHVDd3VXEzelNHS3VPZW9xdyIsImF0X2hhc2giOiJMNnZmczRRdW54MTJfdHg0b2hXa2dnIiwiY19oYXNoIjoicXF2WGFYY0tlY0RBZ0daM1N0QWxNQSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.gFxsx-lq-Q58JoG_f7iHqtVeScKHqKpQPMvQu6G3o2aiApk3fqw3vofafwyrWClswrPmdP2IpAVdSOs5zpqQoNmaAzuuan59OLm1xkd61WCeBGf3xFsDkw7p9YyGQ8JDcSEyyCgXMu2LPdcpkhoWxUBjEjkRASG1dGTNo5X54RwOV1FeAQv6z2kTiMWs69jh5k20s-a0jI3mazGCUCUQI4kFY7_C5ZCs3Tk1DwZ4kd4MaJNIA6947sgC6aLgJET0-sEthYPO-BSRoTYX7wARUx4vNuqf5o_aTmUQ0Sj-iFfgrv4gMyewpM4Ar5QcsznPO-sYJZjW4w4reoakbnVBZA",
    "keyauth": "ZpmXUhdOMAy0OnKQ76YW5YOL7w8vgJMC.IMHU7kl9NMoZwlwhmAWMNIYmc7SaKBtIECKnqdUo8L4"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33578/acme/wire/account/A9EyASaIJk5sJjFMtwW6H7pVEvAD3Jqn",
    "nonce": "ZVhWTFBoSFdUelU0U1BiaVl1TWdsRUZVemNBam43TlY",
    "typ": "JWT",
    "url": "https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/mSD0HjaIvyqLeX5jBxnKESMQn1KyhUkT"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33578/acme/wire/directory>;rel="index"
link: <https://stepca:33578/acme/wire/authz/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK>;rel="up"
location: https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/mSD0HjaIvyqLeX5jBxnKESMQn1KyhUkT
replay-nonce: Zng0NnV0VWpzdWp4RXljOTV2bm9ERFBPeVVLd2xvbVk
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:33578/acme/wire/challenge/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK/mSD0HjaIvyqLeX5jBxnKESMQn1KyhUkT",
  "status": "valid",
  "token": "ZpmXUhdOMAy0OnKQ76YW5YOL7w8vgJMC",
  "target": "http://dex:18395/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNTc4L2FjbWUvd2lyZS9hY2NvdW50L0E5RXlBU2FJSms1c0pqRk10d1c2SDdwVkV2QUQzSnFuIiwidHlwIjoiSldUIiwibm9uY2UiOiJabmcwTm5WMFZXcHpkV3A0Ulhsak9UVjJibTlFUkZCUGVWVkxkMnh2YlZrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM1NzgvYWNtZS93aXJlL29yZGVyLzczNzJYeVE3SmRmTTJIWnM4aUNiTGd1QzBzcWFGeHV0In0",
  "payload": "",
  "signature": "QcrBrLAbXfS4Wl31PyDNqHn25JaWILbtersjGCFlKL8CAVKobDDBtWbZYxFh1elexdSjnQDEIIGURTONnDGpCA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33578/acme/wire/account/A9EyASaIJk5sJjFMtwW6H7pVEvAD3Jqn",
    "nonce": "Zng0NnV0VWpzdWp4RXljOTV2bm9ERFBPeVVLd2xvbVk",
    "typ": "JWT",
    "url": "https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33578/acme/wire/directory>;rel="index"
location: https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut
replay-nonce: cjBTVVZPRE0wbUNQV0JiTGFHaVFJUHh5Y0VvamlZaGY
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33578/acme/wire/authz/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK"
  ],
  "expires": "2023-05-18T12:44:26Z",
  "notBefore": "2023-05-17T12:44:26.123215Z",
  "notAfter": "2023-05-17T13:44:26.123215Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNTc4L2FjbWUvd2lyZS9hY2NvdW50L0E5RXlBU2FJSms1c0pqRk10d1c2SDdwVkV2QUQzSnFuIiwidHlwIjoiSldUIiwibm9uY2UiOiJjakJUVlZaUFJFMHdiVU5RVjBKaVRHRkhhVkZKVUhoNVkwVnZhbWxaYUdZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM1NzgvYWNtZS93aXJlL29yZGVyLzczNzJYeVE3SmRmTTJIWnM4aUNiTGd1QzBzcWFGeHV0L2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCT0RDQjZ3SUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBRUZXQTZJQ1lJUVBvdzV1UHNGX2hTNEowckVobTRRRU9CWUZERFBnR2pWZG9JR0dNSUdEQmdrcWhraUc5dzBCQ1E0eGRqQjBNSElHQTFVZEVRUnJNR21HVUdsdE9uZHBjbVZoY0hBOVQwZEZNRTFFUlROTlZGVXpXVEpGTVU1RVVUUlBSMFpzVGxkV2FFOUVVbXhPVkVFd1RWUkpNVTVxVFM4M05qbGhaakV4Wkdaak9ETTVZelkyUUhkcGNtVXVZMjl0aGhWcGJUcDNhWEpsWVhCd1BXRnNhV05sWDNkcGNtVXdCUVlESzJWd0EwRUFkUnVvTlpFd3NDVURUdHBUMjhXX2N4NUJTWFptcE5XS1V4VUhaS3M3WEZud1hRbGNlZGZLY2F6SVNiYk5DRG52c21qSDI5MTFtbWpuclh3SURtYUFCQSJ9",
  "signature": "3ZM5k0fUTCnB9LI3ZB3xFK95cu4nyt8aPXGaqP5TMxc_nm9VSaVfMWEIYMAYsj30P_KYHNGb5Evadh7Hkd6mCA"
}
```
```json
{
  "payload": {
    "csr": "MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAEFWA6ICYIQPow5uPsF_hS4J0rEhm4QEOBYFDDPgGjVdoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndpcmVhcHA9T0dFME1ERTNNVFUzWTJFMU5EUTRPR0ZsTldWaE9EUmxOVEEwTVRJMU5qTS83NjlhZjExZGZjODM5YzY2QHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dpcmUwBQYDK2VwA0EAdRuoNZEwsCUDTtpT28W_cx5BSXZmpNWKUxUHZKs7XFnwXQlcedfKcazISbbNCDnvsmjH2911mmjnrXwIDmaABA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33578/acme/wire/account/A9EyASaIJk5sJjFMtwW6H7pVEvAD3Jqn",
    "nonce": "cjBTVVZPRE0wbUNQV0JiTGFHaVFJUHh5Y0VvamlZaGY",
    "typ": "JWT",
    "url": "https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAEFWA6ICYIQPow5uPsF/hS4J0rEhm4QE
OBYFDDPgGjVdoIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndp
cmVhcHA9T0dFME1ERTNNVFUzWTJFMU5EUTRPR0ZsTldWaE9EUmxOVEEwTVRJMU5q
TS83NjlhZjExZGZjODM5YzY2QHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dp
cmUwBQYDK2VwA0EAdRuoNZEwsCUDTtpT28W/cx5BSXZmpNWKUxUHZKs7XFnwXQlc
edfKcazISbbNCDnvsmjH2911mmjnrXwIDmaABA==
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
                    41:56:03:a2:02:60:84:0f:a3:0e:6e:3e:c1:7f:85:
                    2e:09:d2:b1:21:9b:84:04:38:16:05:0c:33:e0:1a:
                    35:5d
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        75:1b:a8:35:91:30:b0:25:03:4e:da:53:db:c5:bf:73:1e:41:
        49:76:66:a4:d5:8a:53:15:07:64:ab:3b:5c:59:f0:5d:09:5c:
        79:d7:ca:71:ac:c8:49:b6:cd:08:39:ef:b2:68:c7:db:dd:75:
        9a:68:e7:ad:7c:08:0e:66:80:04

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33578/acme/wire/directory>;rel="index"
location: https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut
replay-nonce: bGtTWk5WQnZEOXA3TEhDWFp2aFRiQVZ4OVRLenlKS1g
```
```json
{
  "certificate": "https://stepca:33578/acme/wire/certificate/TynMCllENE0jGp1pLgylFm9525LwiTGu",
  "status": "valid",
  "finalize": "https://stepca:33578/acme/wire/order/7372XyQ7JdfM2HZs8iCbLguC0sqaFxut/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33578/acme/wire/authz/RwucBf57AZ4pWQyZBcK8a5azfZJqH3iK"
  ],
  "expires": "2023-05-18T12:44:26Z",
  "notBefore": "2023-05-17T12:44:26.123215Z",
  "notAfter": "2023-05-17T13:44:26.123215Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:33578/acme/wire/certificate/TynMCllENE0jGp1pLgylFm9525LwiTGu
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNTc4L2FjbWUvd2lyZS9hY2NvdW50L0E5RXlBU2FJSms1c0pqRk10d1c2SDdwVkV2QUQzSnFuIiwidHlwIjoiSldUIiwibm9uY2UiOiJiR3RUV2s1V1FuWkVPWEEzVEVoRFdGcDJhRlJpUVZaNE9WUkxlbmxLUzFnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM1NzgvYWNtZS93aXJlL2NlcnRpZmljYXRlL1R5bk1DbGxFTkUwakdwMXBMZ3lsRm05NTI1THdpVEd1In0",
  "payload": "",
  "signature": "I07x_PvjGYzWr9ixJUwOvy5iG_8VJ7fdWEEIkEc-ExBC-K3HhabUKgvxoU8YCVB6ABnjZOsDXXrKcnPhj-9WBg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33578/acme/wire/account/A9EyASaIJk5sJjFMtwW6H7pVEvAD3Jqn",
    "nonce": "bGtTWk5WQnZEOXA3TEhDWFp2aFRiQVZ4OVRLenlKS1g",
    "typ": "JWT",
    "url": "https://stepca:33578/acme/wire/certificate/TynMCllENE0jGp1pLgylFm9525LwiTGu"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:33578/acme/wire/directory>;rel="index"
replay-nonce: R1ZOTUpMdUVwdnl0TWljS3VqQU12R0ttWmxXQVYyRkc
```
```json
"-----BEGIN CERTIFICATE-----\nMIICLjCCAdWgAwIBAgIRAKLtZXxpSs6C6Y2Q46YyEJgwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwNTE3MTI0NDI2WhcNMjMwNTE3MTM0NDI2WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQBBVgOiAmCED6MObj7B\nf4UuCdKxIZuEBDgWBQwz4Bo1XaOCAQYwggECMA4GA1UdDwEB/wQEAwIHgDAdBgNV\nHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFAV3dw6SJWWiaEJM\n0PaF4mrAyYkvMB8GA1UdIwQYMBaAFESQj2UEIReEtbv/Szr1KNKmPtIYMHIGA1Ud\nEQRrMGmGUGltOndpcmVhcHA9T0dFME1ERTNNVFUzWTJFMU5EUTRPR0ZsTldWaE9E\nUmxOVEEwTVRJMU5qTS83NjlhZjExZGZjODM5YzY2QHdpcmUuY29thhVpbTp3aXJl\nYXBwPWFsaWNlX3dpcmUwHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoG\nCCqGSM49BAMCA0cAMEQCIADxWJSLYyYtqj+8Fa1Zl27UV2xhwUhdxoiGSpbAj7ls\nAiBo+5ZzN26/NsA0iiZ63oE+Y5uyRrIG+95dnVvG4wmYrg==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAIZmE++HmdwvkYFavklpAMAwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDUxNzEy\nNDQyM1oXDTMzMDUxNDEyNDQyM1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARf\nXXsu99LWVYyhnREmQlB5v81fS4hFKAtIEfrmw+pK1MLEsKMIfpKg5L94yAfMKlP0\nVXA6FWMLNgSyeASG70n4o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQURJCPZQQhF4S1u/9LOvUo0qY+0hgwHwYDVR0jBBgw\nFoAUXwVUJaHK5zWfokfYn3IcHvUQta0wCgYIKoZIzj0EAwIDSAAwRQIhAOxh92k7\nYZZ5mt0gfJXeFwPcA8uWFY32ybMwyXXP+eLBAiBQHlhRbmzxkB5CtIK+emTpyWQN\nug7XqJX5h/bUM9M0hA==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICLjCCAdWgAwIBAgIRAKLtZXxpSs6C6Y2Q46YyEJgwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwNTE3MTI0NDI2WhcNMjMwNTE3MTM0NDI2WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQBBVgOiAmCED6MObj7B
f4UuCdKxIZuEBDgWBQwz4Bo1XaOCAQYwggECMA4GA1UdDwEB/wQEAwIHgDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFAV3dw6SJWWiaEJM
0PaF4mrAyYkvMB8GA1UdIwQYMBaAFESQj2UEIReEtbv/Szr1KNKmPtIYMHIGA1Ud
EQRrMGmGUGltOndpcmVhcHA9T0dFME1ERTNNVFUzWTJFMU5EUTRPR0ZsTldWaE9E
UmxOVEEwTVRJMU5qTS83NjlhZjExZGZjODM5YzY2QHdpcmUuY29thhVpbTp3aXJl
YXBwPWFsaWNlX3dpcmUwHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoG
CCqGSM49BAMCA0cAMEQCIADxWJSLYyYtqj+8Fa1Zl27UV2xhwUhdxoiGSpbAj7ls
AiBo+5ZzN26/NsA0iiZ63oE+Y5uyRrIG+95dnVvG4wmYrg==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            a2:ed:65:7c:69:4a:ce:82:e9:8d:90:e3:a6:32:10:98
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: May 17 12:44:26 2023 GMT
            Not After : May 17 13:44:26 2023 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    41:56:03:a2:02:60:84:0f:a3:0e:6e:3e:c1:7f:85:
                    2e:09:d2:b1:21:9b:84:04:38:16:05:0c:33:e0:1a:
                    35:5d
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                05:77:77:0E:92:25:65:A2:68:42:4C:D0:F6:85:E2:6A:C0:C9:89:2F
            X509v3 Authority Key Identifier: 
                44:90:8F:65:04:21:17:84:B5:BB:FF:4B:3A:F5:28:D2:A6:3E:D2:18
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=OGE0MDE3MTU3Y2E1NDQ4OGFlNWVhODRlNTA0MTI1NjM/769af11dfc839c66@wire.com, URI:im:wireapp=alice_wire
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:00:f1:58:94:8b:63:26:2d:aa:3f:bc:15:ad:59:
        97:6e:d4:57:6c:61:c1:48:5d:c6:88:86:4a:96:c0:8f:b9:6c:
        02:20:68:fb:96:73:37:6e:bf:36:c0:34:8a:26:7a:de:81:3e:
        63:9b:b2:46:b2:06:fb:de:5d:9d:5b:c6:e3:09:98:ae

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAIZmE++HmdwvkYFavklpAMAwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDUxNzEy
NDQyM1oXDTMzMDUxNDEyNDQyM1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARf
XXsu99LWVYyhnREmQlB5v81fS4hFKAtIEfrmw+pK1MLEsKMIfpKg5L94yAfMKlP0
VXA6FWMLNgSyeASG70n4o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQURJCPZQQhF4S1u/9LOvUo0qY+0hgwHwYDVR0jBBgw
FoAUXwVUJaHK5zWfokfYn3IcHvUQta0wCgYIKoZIzj0EAwIDSAAwRQIhAOxh92k7
YZZ5mt0gfJXeFwPcA8uWFY32ybMwyXXP+eLBAiBQHlhRbmzxkB5CtIK+emTpyWQN
ug7XqJX5h/bUM9M0hA==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            86:66:13:ef:87:99:dc:2f:91:81:5a:be:49:69:00:c0
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: May 17 12:44:23 2023 GMT
            Not After : May 14 12:44:23 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:5f:5d:7b:2e:f7:d2:d6:55:8c:a1:9d:11:26:42:
                    50:79:bf:cd:5f:4b:88:45:28:0b:48:11:fa:e6:c3:
                    ea:4a:d4:c2:c4:b0:a3:08:7e:92:a0:e4:bf:78:c8:
                    07:cc:2a:53:f4:55:70:3a:15:63:0b:36:04:b2:78:
                    04:86:ef:49:f8
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                44:90:8F:65:04:21:17:84:B5:BB:FF:4B:3A:F5:28:D2:A6:3E:D2:18
            X509v3 Authority Key Identifier: 
                5F:05:54:25:A1:CA:E7:35:9F:A2:47:D8:9F:72:1C:1E:F5:10:B5:AD
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:ec:61:f7:69:3b:61:96:79:9a:dd:20:7c:95:
        de:17:03:dc:03:cb:96:15:8d:f6:c9:b3:30:c9:75:cf:f9:e2:
        c1:02:20:50:1e:58:51:6e:6c:f1:90:1e:42:b4:82:be:7a:64:
        e9:c9:64:0d:ba:0e:d7:a8:95:f9:87:f6:d4:33:d3:34:84

```
