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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/ff65cc9492cb86e6/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/i45h6J6Tg1muxDYCZcTliGIdHzjQ3vRQ
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32891/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32891/acme/wire/new-nonce",
  "newAccount": "https://stepca:32891/acme/wire/new-account",
  "newOrder": "https://stepca:32891/acme/wire/new-order",
  "revokeCert": "https://stepca:32891/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32891/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32891/acme/wire/directory>;rel="index"
replay-nonce: VHNpY0xyeWVPdlFCb1BVZ1lVeWQ4TGRUM3RyUXUyWko
```
```text
VHNpY0xyeWVPdlFCb1BVZ1lVeWQ4TGRUM3RyUXUyWko
```
#### 5. create a new account
```http request
POST https://stepca:32891/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjAwejNJM3ctUVBXbUF4QzdEaHR4aVFXdElpeWR2a1Nnekd2dlNtdmN3VnMifSwibm9uY2UiOiJWSE5wWTB4eWVXVlBkbEZDYjFCVloxbFZlV1E0VEdSVU0zUnlVWFV5V2tvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "ohsFpfhGZFgXV8AIviCZhDu-CEiUvIZ0u_0uKrRLIXN3aeaNidR5oH0ZfqSghppB1o0B_8HyjaM1pv6PjO3-Bg"
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
      "x": "00z3I3w-QPWmAxC7DhtxiQWtIiydvkSgzGvvSmvcwVs"
    },
    "nonce": "VHNpY0xyeWVPdlFCb1BVZ1lVeWQ4TGRUM3RyUXUyWko",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR
replay-nonce: U1BwRDM4NFVMc1Vtd3B6dUd6eXJkZjl4VG1oUlRRb2w
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32891/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJVMUJ3UkRNNE5GVk1jMVZ0ZDNCNmRVZDZlWEprWmpsNFZHMW9VbFJSYjJ3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMi0xNFQxNjo0MzoyNC42MzE3NjlaIiwibm90QWZ0ZXIiOiIyMDM0LTAyLTExVDE2OjQzOjI0LjYzMTc2OVoifQ",
  "signature": "uWfDrfP-ZE8ODZJFYYXyODE6S9uQkWeoyi60w25ivfUwkr0DGYjNeuQMsRi_bZ1qYCAhQB-KLgML-93wlK2cBA"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2034-02-11T16:43:24.631769Z",
    "notBefore": "2024-02-14T16:43:24.631769Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "U1BwRDM4NFVMc1Vtd3B6dUd6eXJkZjl4VG1oUlRRb2w",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
replay-nonce: Nk1GUW1lMjBIbTVvRjRTb0FjWTcycDh1OXpRWjJlaFo
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y",
    "https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS"
  ],
  "expires": "2024-02-15T16:43:24Z",
  "notBefore": "2024-02-14T16:43:24.631769Z",
  "notAfter": "2034-02-11T16:43:24.631769Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJOazFHVVcxbE1qQkliVFZ2UmpSVGIwRmpXVGN5Y0RoMU9YcFJXakpsYUZvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2F1dGh6L1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZIn0",
  "payload": "",
  "signature": "Ih0aj_yA37iAz1jzREeQCy6pk-4w5Rt6284aPsvic8rSN6qFTLTvro5_pMkaCBLG3KewZe084aH59lJt9gNcBA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "Nk1GUW1lMjBIbTVvRjRTb0FjWTcycDh1OXpRWjJlaFo",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y
replay-nonce: SmE5UEFWNGQ1UE40bHd0MXN0Z1RSMVo0MURzQmhMWVM
```
```json
{
  "status": "pending",
  "expires": "2024-02-15T16:43:24Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M",
      "status": "pending",
      "token": "uDweLiHzAB74sHkE9RQiuHJx2XrUmhGA",
      "target": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJTbUU1VUVGV05HUTFVRTQwYkhkME1YTjBaMVJTTVZvME1VUnpRbWhNV1ZNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2F1dGh6L3VuRk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTIn0",
  "payload": "",
  "signature": "WsrOvFC12jYa_9FqJnm9pGnmXIiU_vC2PUEiPJ9EY78VFo_W7w5mi_NgGC_OHtaC-_LNhX11M6NLz2Bar3zCBw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "SmE5UEFWNGQ1UE40bHd0MXN0Z1RSMVo0MURzQmhMWVM",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS"
  }
}
```
#### 11. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS
replay-nonce: MTV2SUdpdDZrcEU5S1Uza25Ccmdja09xbHY5MzNTMGQ
```
```json
{
  "status": "pending",
  "expires": "2024-02-15T16:43:24Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ",
      "status": "pending",
      "token": "7r2Oy9RBPZe7Zmndstr1bzx2QMSkKtUy",
      "target": "http://keycloak:18585/realms/master"
    }
  ],
  "identifier": {
    "type": "wireapp-user",
    "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 12. fetch a nonce from wire-server
```http request
GET http://wire.com:24844/clients/token/nonce
```
#### 13. get wire-server nonce
```http request
200

```
```text
NTNCcDFKb0tLWUFOdTRQZFFiRDc3WXpHNG8xQUxrVUE
```
#### 14. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMDB6M0kzdy1RUFdtQXhDN0RodHhpUVd0SWl5ZHZrU2d6R3Z2U212Y3dWcyJ9fQ.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkzMjYwNCwibmJmIjoxNzA3OTI1NDA0LCJzdWIiOiJ3aXJlYXBwOi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS9YQVlmT2NyQWQ3QldOWTJyRncwWENOWFJsY2JudWYzWS9senBYbDZSOXM1cDdZS0JVVzhoTE9pUHJFd1YwVHM0TSIsImp0aSI6IjZlMzJjM2QyLTJiMTItNGYxYy04ZGNlLWI2MTA1OGEzMDU3NyIsIm5vbmNlIjoiTlROQ2NERktiMHRMV1VGT2RUUlFaRkZpUkRjM1dYcEhORzh4UVV4clZVRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJ1RHdlTGlIekFCNzRzSGtFOVJRaXVISngyWHJVbWhHQSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.F-3iKzDtG658aipTFPZyPYnzV8AqYgz3yc2juUuIrot33uTyY2IEC6HPdyNyLR3MuZtgVI2yGEC9LOyIm6TyAw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMDB6M0kzdy1RUFdtQXhDN0RodHhpUVd0
SWl5ZHZrU2d6R3Z2U212Y3dWcyJ9fQ.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6M
TcwNzkzMjYwNCwibmJmIjoxNzA3OTI1NDA0LCJzdWIiOiJ3aXJlYXBwOi8vLUFHb
Th1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS9YQ
VlmT2NyQWQ3QldOWTJyRncwWENOWFJsY2JudWYzWS9senBYbDZSOXM1cDdZS0JVV
zhoTE9pUHJFd1YwVHM0TSIsImp0aSI6IjZlMzJjM2QyLTJiMTItNGYxYy04ZGNlL
WI2MTA1OGEzMDU3NyIsIm5vbmNlIjoiTlROQ2NERktiMHRMV1VGT2RUUlFaRkZpU
kRjM1dYcEhORzh4UVV4clZVRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b
2tlbiIsImNoYWwiOiJ1RHdlTGlIekFCNzRzSGtFOVJRaXVISngyWHJVbWhHQSIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUifQ.F-3iKzDtG658aipTFPZyPYnzV8AqYgz3yc2juUuIrot33uTyY2
IEC6HPdyNyLR3MuZtgVI2yGEC9LOyIm6TyAw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "00z3I3w-QPWmAxC7DhtxiQWtIiydvkSgzGvvSmvcwVs"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M",
  "chal": "uDweLiHzAB74sHkE9RQiuHJx2XrUmhGA",
  "exp": 1707932604,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token",
  "iat": 1707925404,
  "jti": "6e32c3d2-2b12-4f1c-8dce-b61058a30577",
  "nbf": 1707925404,
  "nonce": "NTNCcDFKb0tLWUFOdTRQZFFiRDc3WXpHNG8xQUxrVUE",
  "sub": "wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICXKf2Zu5a1F0NfMYenEYp/FuOudMii72btMXUQ4D3qj
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA00z3I3w+QPWmAxC7DhtxiQWtIiydvkSgzGvvSmvcwVs=
-----END PUBLIC KEY-----
```

</details>


#### 15. trade client DPoP token for an access token
```http request
POST http://wire.com:24844/clients/ff65cc9492cb86e6/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTURCNk0wa3pkeTFSVUZkdFFYaEROMFJvZEhocFVWZDBTV2w1WkhaclUyZDZSM1oyVTIxMlkzZFdjeUo5ZlEuZXlKcFlYUWlPakUzTURjNU1qVTBNRFFzSW1WNGNDSTZNVGN3Tnprek1qWXdOQ3dpYm1KbUlqb3hOekEzT1RJMU5EQTBMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZMVUZIYlRoMU5uRlJSVzFuUkRNeGVqaDBVemgyWnlGbVpqWTFZMk01TkRreVkySTRObVUyUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekk0T1RFdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOVlRVmxtVDJOeVFXUTNRbGRPV1RKeVJuY3dXRU5PV0ZKc1kySnVkV1l6V1M5c2VuQlliRFpTT1hNMWNEZFpTMEpWVnpob1RFOXBVSEpGZDFZd1ZITTBUU0lzSW1wMGFTSTZJalpsTXpKak0yUXlMVEppTVRJdE5HWXhZeTA0WkdObExXSTJNVEExT0dFek1EVTNOeUlzSW01dmJtTmxJam9pVGxST1EyTkVSa3RpTUhSTVYxVkdUMlJVVWxGYVJrWnBVa1JqTTFkWWNFaE9Semg0VVZWNGNsWlZSU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRNE5EUXZZMnhwWlc1MGN5OW1aalkxWTJNNU5Ea3lZMkk0Tm1VMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUoxUkhkbFRHbElla0ZDTnpSelNHdEZPVkpSYVhWSVNuZ3lXSEpWYldoSFFTSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpZlEuRi0zaUt6RHRHNjU4YWlwVEZQWnlQWW56VjhBcVlnejN5YzJqdVV1SXJvdDMzdVR5WTJJRUM2SFBkeU55TFIzTXVadGdWSTJ5R0VDOUxPeUltNlR5QXc
```
#### 16. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZVQjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkyOTM2NCwibmJmIjoxNzA3OTI1NDA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZL2x6cFhsNlI5czVwN1lLQlVXOGhMT2lQckV3VjBUczRNIiwianRpIjoiODQ4Yzc1MTQtOGY3MC00NzRhLWEyZGItMTMzZGRjNDMxOGQ4Iiwibm9uY2UiOiJOVE5DY0RGS2IwdExXVUZPZFRSUVpGRmlSRGMzV1hwSE5HOHhRVXhyVlVFIiwiY2hhbCI6InVEd2VMaUh6QUI3NHNIa0U5UlFpdUhKeDJYclVtaEdBIiwiY25mIjp7ImtpZCI6IjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJkNlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0Y0NJNk1UY3dOemt6TWpZd05Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZtWmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5WVFWbG1UMk55UVdRM1FsZE9XVEp5Um5jd1dFTk9XRkpzWTJKdWRXWXpXUzlzZW5CWWJEWlNPWE0xY0RkWlMwSlZWemhvVEU5cFVISkZkMVl3VkhNMFRTSXNJbXAwYVNJNklqWmxNekpqTTJReUxUSmlNVEl0TkdZeFl5MDRaR05sTFdJMk1UQTFPR0V6TURVM055SXNJbTV2Ym1ObElqb2lUbFJPUTJORVJrdGlNSFJNVjFWR1QyUlVVbEZhUmtacFVrUmpNMWRZY0VoT1J6aDRVVlY0Y2xaVlJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUwY3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjFSSGRsVEdsSWVrRkNOelJ6U0d0Rk9WSlJhWFZJU25neVdISlZiV2hIUVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5GLTNpS3pEdEc2NThhaXBURlBaeVBZbnpWOEFxWWd6M3ljMmp1VXVJcm90MzN1VHlZMklFQzZIUGR5TnlMUjNNdVp0Z1ZJMnlHRUM5TE95SW02VHlBdyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.zmNPxi69hsXt7mg1K94SCo-VhY1AuSAqmKjk6X_QF136voJ7aZnYUPIbHLPqykZcXUISMJj9VZaeeoSkfRRvDw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZVQjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkyOTM2NCwibmJmIjoxNzA3OTI1NDA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZL2x6cFhsNlI5czVwN1lLQlVXOGhMT2lQckV3VjBUczRNIiwianRpIjoiODQ4Yzc1MTQtOGY3MC00NzRhLWEyZGItMTMzZGRjNDMxOGQ4Iiwibm9uY2UiOiJOVE5DY0RGS2IwdExXVUZPZFRSUVpGRmlSRGMzV1hwSE5HOHhRVXhyVlVFIiwiY2hhbCI6InVEd2VMaUh6QUI3NHNIa0U5UlFpdUhKeDJYclVtaEdBIiwiY25mIjp7ImtpZCI6IjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJkNlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0Y0NJNk1UY3dOemt6TWpZd05Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZtWmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5WVFWbG1UMk55UVdRM1FsZE9XVEp5Um5jd1dFTk9XRkpzWTJKdWRXWXpXUzlzZW5CWWJEWlNPWE0xY0RkWlMwSlZWemhvVEU5cFVISkZkMVl3VkhNMFRTSXNJbXAwYVNJNklqWmxNekpqTTJReUxUSmlNVEl0TkdZeFl5MDRaR05sTFdJMk1UQTFPR0V6TURVM055SXNJbTV2Ym1ObElqb2lUbFJPUTJORVJrdGlNSFJNVjFWR1QyUlVVbEZhUmtacFVrUmpNMWRZY0VoT1J6aDRVVlY0Y2xaVlJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUwY3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjFSSGRsVEdsSWVrRkNOelJ6U0d0Rk9WSlJhWFZJU25neVdISlZiV2hIUVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5GLTNpS3pEdEc2NThhaXBURlBaeVBZbnpWOEFxWWd6M3ljMmp1VXVJcm90MzN1VHlZMklFQzZIUGR5TnlMUjNNdVp0Z1ZJMnlHRUM5TE95SW02VHlBdyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.zmNPxi69hsXt7mg1K94SCo-VhY1AuSAqmKjk6X_QF136voJ7aZnYUPIbHLPqykZcXUISMJj9VZaeeoSkfRRvDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZV
QjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcw
NzkyOTM2NCwibmJmIjoxNzA3OTI1NDA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJj
Yjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21l
L3dpcmUvY2hhbGxlbmdlL1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZ
L2x6cFhsNlI5czVwN1lLQlVXOGhMT2lQckV3VjBUczRNIiwianRpIjoiODQ4Yzc1
MTQtOGY3MC00NzRhLWEyZGItMTMzZGRjNDMxOGQ4Iiwibm9uY2UiOiJOVE5DY0RG
S2IwdExXVUZPZFRSUVpGRmlSRGMzV1hwSE5HOHhRVXhyVlVFIiwiY2hhbCI6InVE
d2VMaUh6QUI3NHNIa0U5UlFpdUhKeDJYclVtaEdBIiwiY25mIjp7ImtpZCI6IjFY
bWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJk
NlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0
Y0NJNk1UY3dOemt6TWpZd05Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZt
WmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM5WVFWbG1UMk55UVdRM1FsZE9XVEp5Um5jd1dFTk9XRkpzWTJKdWRXWXpXUzlz
ZW5CWWJEWlNPWE0xY0RkWlMwSlZWemhvVEU5cFVISkZkMVl3VkhNMFRTSXNJbXAw
YVNJNklqWmxNekpqTTJReUxUSmlNVEl0TkdZeFl5MDRaR05sTFdJMk1UQTFPR0V6
TURVM055SXNJbTV2Ym1ObElqb2lUbFJPUTJORVJrdGlNSFJNVjFWR1QyUlVVbEZh
UmtacFVrUmpNMWRZY0VoT1J6aDRVVlY0Y2xaVlJTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUw
Y3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSjFSSGRsVEdsSWVrRkNOelJ6U0d0Rk9WSlJhWFZJU25neVdISlZiV2hI
UVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5GLTNpS3pEdEc2NThh
aXBURlBaeVBZbnpWOEFxWWd6M3ljMmp1VXVJcm90MzN1VHlZMklFQzZIUGR5TnlM
UjNNdVp0Z1ZJMnlHRUM5TE95SW02VHlBdyIsImNsaWVudF9pZCI6IndpcmVhcHA6
Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5j
b20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.zmN
Pxi69hsXt7mg1K94SCo-VhY1AuSAqmKjk6X_QF136voJ7aZnYUPIbHLPqykZcXUI
SMJj9VZaeeoSkfRRvDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "p297i1tJkAdaOLMnpxugMQoAFUB9HTM0CvdjGjlJYzY"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M",
  "chal": "uDweLiHzAB74sHkE9RQiuHJx2XrUmhGA",
  "client_id": "wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com",
  "cnf": {
    "kid": "1XmccI-BrrPKX4tCQ0Nas1GIMhckkypVmR5mcITgRAI"
  },
  "exp": 1707929364,
  "iat": 1707925404,
  "iss": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token",
  "jti": "848c7514-8f70-474a-a2db-133ddc4318d8",
  "nbf": 1707925404,
  "nonce": "NTNCcDFKb0tLWUFOdTRQZFFiRDc3WXpHNG8xQUxrVUE",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMDB6M0kzdy1RUFdtQXhDN0RodHhpUVd0SWl5ZHZrU2d6R3Z2U212Y3dWcyJ9fQ.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkzMjYwNCwibmJmIjoxNzA3OTI1NDA0LCJzdWIiOiJ3aXJlYXBwOi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS9YQVlmT2NyQWQ3QldOWTJyRncwWENOWFJsY2JudWYzWS9senBYbDZSOXM1cDdZS0JVVzhoTE9pUHJFd1YwVHM0TSIsImp0aSI6IjZlMzJjM2QyLTJiMTItNGYxYy04ZGNlLWI2MTA1OGEzMDU3NyIsIm5vbmNlIjoiTlROQ2NERktiMHRMV1VGT2RUUlFaRkZpUkRjM1dYcEhORzh4UVV4clZVRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJ1RHdlTGlIekFCNzRzSGtFOVJRaXVISngyWHJVbWhHQSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.F-3iKzDtG658aipTFPZyPYnzV8AqYgz3yc2juUuIrot33uTyY2IEC6HPdyNyLR3MuZtgVI2yGEC9LOyIm6TyAw",
  "scope": "wire_client_id",
  "sub": "wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJatwIEJkQb2JTfifGXoh49zXUOBSvkByqeHY4XBJQf1
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAp297i1tJkAdaOLMnpxugMQoAFUB9HTM0CvdjGjlJYzY=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 17. validate Dpop challenge (clientId)
```http request
POST https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJNVFYyU1VkcGREWnJjRVU1UzFVemEyNUNjbWRqYTA5eGJIWTVNek5UTUdRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS9YQVlmT2NyQWQ3QldOWTJyRncwWENOWFJsY2JudWYzWS9senBYbDZSOXM1cDdZS0JVVzhoTE9pUHJFd1YwVHM0TSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluQXlPVGRwTVhSS2EwRmtZVTlNVFc1d2VIVm5UVkZ2UVVaVlFqbElWRTB3UTNaa2FrZHFiRXBaZWxraWZYMC5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0Y0NJNk1UY3dOemt5T1RNMk5Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRNE5EUXZZMnhwWlc1MGN5OW1aalkxWTJNNU5Ea3lZMkk0Tm1VMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTh0UVVkdE9IVTJjVkZGYldkRU16RjZPSFJUT0habklXWm1OalZqWXprME9USmpZamcyWlRaQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpnNU1TOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMWhCV1daUFkzSkJaRGRDVjA1Wk1uSkdkekJZUTA1WVVteGpZbTUxWmpOWkwyeDZjRmhzTmxJNWN6VndOMWxMUWxWWE9HaE1UMmxRY2tWM1ZqQlVjelJOSWl3aWFuUnBJam9pT0RRNFl6YzFNVFF0T0dZM01DMDBOelJoTFdFeVpHSXRNVE16WkdSak5ETXhPR1E0SWl3aWJtOXVZMlVpT2lKT1ZFNURZMFJHUzJJd2RFeFhWVVpQWkZSU1VWcEdSbWxTUkdNelYxaHdTRTVIT0hoUlZYaHlWbFZGSWl3aVkyaGhiQ0k2SW5WRWQyVk1hVWg2UVVJM05ITklhMFU1VWxGcGRVaEtlREpZY2xWdGFFZEJJaXdpWTI1bUlqcDdJbXRwWkNJNklqRlliV05qU1MxQ2NuSlFTMWcwZEVOUk1FNWhjekZIU1Uxb1kydHJlWEJXYlZJMWJXTkpWR2RTUVVraWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsTlJFSTJUVEJyZW1SNU1WSlZSbVIwVVZob1JFNHdVbTlrU0dod1ZWWmtNRk5YYkRWYVNGcHlWVEprTmxJeldqSlZNakV5V1ROa1YyTjVTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5SR00xVFdwVk1FMUVVWE5KYlZZMFkwTkpOazFVWTNkT2VtdDZUV3BaZDA1RGQybGliVXB0U1dwdmVFNTZRVE5QVkVreFRrUkJNRXhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRreFZSa2hpVkdneFRtNUdVbEpYTVc1U1JFMTRaV3BvTUZWNmFESmFlVVp0V21wWk1Wa3lUVFZPUkd0NVdUSkpORTV0VlRKUlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUUlBWRVYyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE01V1ZGV2JHMVVNazU1VVZkUk0xRnNaRTlYVkVwNVVtNWpkMWRGVGs5WFJrcHpXVEpLZFdSWFdYcFhVemx6Wlc1Q1dXSkVXbE5QV0UweFkwUmtXbE13U2xaV2VtaHZWRVU1Y0ZWSVNrWmtNVmwzVmtoTk1GUlRTWE5KYlhBd1lWTkpOa2xxV214TmVrcHFUVEpSZVV4VVNtbE5WRWwwVGtkWmVGbDVNRFJhUjA1c1RGZEpNazFVUVRGUFIwVjZUVVJWTTA1NVNYTkpiVFYyWW0xT2JFbHFiMmxVYkZKUFVUSk9SVkpyZEdsTlNGSk5WakZXUjFReVVsVlZiRVpoVW10YWNGVnJVbXBOTVdSWlkwVm9UMUo2YURSVlZsWTBZMnhhVmxKVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxFMFRrUlJkbGt5ZUhCYVZ6VXdZM2s1YlZwcVdURlpNazAxVGtScmVWa3lTVFJPYlZVeVRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTakZTU0dSc1ZFZHNTV1ZyUmtOT2VsSjZVMGQwUms5V1NsSmhXRlpKVTI1bmVWZElTbFppVjJoSVVWTkpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsbVVTNUdMVE5wUzNwRWRFYzJOVGhoYVhCVVJsQmFlVkJaYm5wV09FRnhXV2Q2TTNsak1tcDFWWFZKY205ME16TjFWSGxaTWtsRlF6WklVR1I1VG5sTVVqTk5kVnAwWjFaSk1ubEhSVU01VEU5NVNXMDJWSGxCZHlJc0ltTnNhV1Z1ZEY5cFpDSTZJbmRwY21WaGNIQTZMeTh0UVVkdE9IVTJjVkZGYldkRU16RjZPSFJUT0habklXWm1OalZqWXprME9USmpZamcyWlRaQWQybHlaUzVqYjIwaUxDSmhjR2xmZG1WeWMybHZiaUk2TlN3aWMyTnZjR1VpT2lKM2FYSmxYMk5zYVdWdWRGOXBaQ0o5LnptTlB4aTY5aHNYdDdtZzFLOTRTQ28tVmhZMUF1U0FxbUtqazZYX1FGMTM2dm9KN2FabllVUEliSExQcXlrWmNYVUlTTUpqOVZaYWVlb1NrZlJSdkR3In0",
  "signature": "Qfa3q4qAdaiEFvDWwCXIZIUw0rIXcTF6hWonPUcOwoLplUH3uokMgPqs8S51OBglmyyNNVep6dMZHxUVwml2Bw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZVQjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkyOTM2NCwibmJmIjoxNzA3OTI1NDA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZL2x6cFhsNlI5czVwN1lLQlVXOGhMT2lQckV3VjBUczRNIiwianRpIjoiODQ4Yzc1MTQtOGY3MC00NzRhLWEyZGItMTMzZGRjNDMxOGQ4Iiwibm9uY2UiOiJOVE5DY0RGS2IwdExXVUZPZFRSUVpGRmlSRGMzV1hwSE5HOHhRVXhyVlVFIiwiY2hhbCI6InVEd2VMaUh6QUI3NHNIa0U5UlFpdUhKeDJYclVtaEdBIiwiY25mIjp7ImtpZCI6IjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJkNlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0Y0NJNk1UY3dOemt6TWpZd05Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZtWmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5WVFWbG1UMk55UVdRM1FsZE9XVEp5Um5jd1dFTk9XRkpzWTJKdWRXWXpXUzlzZW5CWWJEWlNPWE0xY0RkWlMwSlZWemhvVEU5cFVISkZkMVl3VkhNMFRTSXNJbXAwYVNJNklqWmxNekpqTTJReUxUSmlNVEl0TkdZeFl5MDRaR05sTFdJMk1UQTFPR0V6TURVM055SXNJbTV2Ym1ObElqb2lUbFJPUTJORVJrdGlNSFJNVjFWR1QyUlVVbEZhUmtacFVrUmpNMWRZY0VoT1J6aDRVVlY0Y2xaVlJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUwY3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjFSSGRsVEdsSWVrRkNOelJ6U0d0Rk9WSlJhWFZJU25neVdISlZiV2hIUVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5GLTNpS3pEdEc2NThhaXBURlBaeVBZbnpWOEFxWWd6M3ljMmp1VXVJcm90MzN1VHlZMklFQzZIUGR5TnlMUjNNdVp0Z1ZJMnlHRUM5TE95SW02VHlBdyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.zmNPxi69hsXt7mg1K94SCo-VhY1AuSAqmKjk6X_QF136voJ7aZnYUPIbHLPqykZcXUISMJj9VZaeeoSkfRRvDw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "MTV2SUdpdDZrcEU5S1Uza25Ccmdja09xbHY5MzNTMGQ",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M"
  }
}
```
#### 18. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
link: <https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y>;rel="up"
location: https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M
replay-nonce: YXhRdjRNcUVkQ0IxUVZZakE5RWJYSEl2VHN5YkdZWDA
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M",
  "status": "valid",
  "token": "uDweLiHzAB74sHkE9RQiuHJx2XrUmhGA",
  "target": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 19. OAUTH authorization request

```text
code_verifier=fOtvQb_ZkK24F9FNIeyJAAR0fuv_jg8mIEcj9zd-KiQ&code_challenge=aZDR1y7XyMxQyvLDqBMQFQHUF8n2438XiRdPVWMPq18
```
#### 20. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:18585/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=1oNo4ntGyAOJIOJZhylw1A&code_challenge=aZDR1y7XyMxQyvLDqBMQFQHUF8n2438XiRdPVWMPq18&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A24844%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32891%2Facme%2Fwire%2Fchallenge%2FunFMk5gyMbhqWZbE4KgYw7vwomA3lPtS%2FTkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%227r2Oy9RBPZe7Zmndstr1bzx2QMSkKtUy.1XmccI-BrrPKX4tCQ0Nas1GIMhckkypVmR5mcITgRAI%22%7D%7D%7D&nonce=mZjNt5ygsZyBgfXCj7g27A
```

#### 21. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:18585/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=d4fb1ef4-e361-4526-872c-fbb576e5844d.6cf522f6-5d7b-4123-9530-76ba2b709d1b.9d89ab9b-e2e4-4684-bbfc-de800651596e&code_verifier=fOtvQb_ZkK24F9FNIeyJAAR0fuv_jg8mIEcj9zd-KiQ&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A24844%2Fcallback
```
#### 22. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiIxYjMyOGE0Yy00YTY4LTQ0MTgtYjljYy1kMzhiZDU4NDgzZDgiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOdDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0ODQ0Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.fG3BhAdWhOZfv-rCrco1Up8yuPy2Y4xFFLn3dyobbKoIEXveg1_7dekeZpHeBGJXQmXHWQ1j8MBkS6enOsJ6az_1Us9nVNTTEJceMElr6UodE5PI2Fu0TL-Y5qm9o80ntY6vjwVSJG4d8dpll8RtVp3X9-uucgj1bksOCqAyzcOjD_Vnp5OCmL-xXNairT1-5Cy5e8HhTJr2vY0Rb2XHKaumJvYR9OI6SHVDNec4oZebNX6yw2xMk7DGTrdrndKvzpZl9940j7NNs6NRP763N-HTHiSKtwx6gJbU3MbKgPJ5S9fBH1bFUMqL-PlpepNdm9dUCgD_7TMAtEkHh4M6Aw",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiJkZDcyMjRjNS1lYmZmLTRhN2YtOTkwZi1mYzQ5Y2YxMWU1ZDAiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXlnc1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6Ikk4RXZYbWlKTmpERWExSFhhTU44VGciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3VuRk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTL1RrQXJ3TWUzRXNWT2lPYURwQjQxY09RTEdjYnEwc0pKIiwia2V5YXV0aCI6IjdyMk95OVJCUFplN1ptbmRzdHIxYnp4MlFNU2tLdFV5LjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.psCqA_vY9GbouC1y4ykMfGGHHpuJ6gcZswOBlAUdekoGD-SRybaaCxQRjg4NmdpuIoTUN3PcJytBbyffiwYPgvl9MFTrt9wcG8OcWjzE4bedkZ5tFIiDGENkljH_QN_sjXDakuMRC9yVCFBEfGhtV1NLaGKlmzo008405sTSKOssz9kgljT19ySi4symK7yFu-LltoNjT6SToyHj0SJdVWftYZqWEQRr6yTEdfpe-m7TsZCupwlDMnzkRgXfYcDEhndaBWnEnRaxfHFSOsykUNvhtIKGtogxk-lebKm2l4xpHQcabyN10E3wLgiMfmNjCQnEcsEWu00xs287cYISjw",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjZWUzMjgwZC00NTdhLTRlZTItYjVlMS0xMWU0Y2ZiY2E3NjAifQ.eyJleHAiOjE3MDc5MzA4MDQsImlhdCI6MTcwNzkyOTAwNCwianRpIjoiYmY0OGYwNTYtNWExZS00MDg1LWFmZDAtMDhlYzIwODE2ZGM4IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE4NTg1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsInN1YiI6IjI1NzUxY2MzLTMyMzgtNDJiMC1hYTBhLTQ1Y2M5ZTQ3NmEwMiIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOdDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiI2Y2Y1MjJmNi01ZDdiLTQxMjMtOTUzMC03NmJhMmI3MDlkMWIifQ.gNgJU6gvhMgQA7uAQLOK3BtxXgu8YfssAmPZKx3XYEM",
  "scope": "openid email profile",
  "session_state": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiIxYjMyOGE0Yy00YTY4LTQ0MTgtYjljYy1kMzhiZDU4NDgzZDgiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOdDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0ODQ0Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.fG3BhAdWhOZfv-rCrco1Up8yuPy2Y4xFFLn3dyobbKoIEXveg1_7dekeZpHeBGJXQmXHWQ1j8MBkS6enOsJ6az_1Us9nVNTTEJceMElr6UodE5PI2Fu0TL-Y5qm9o80ntY6vjwVSJG4d8dpll8RtVp3X9-uucgj1bksOCqAyzcOjD_Vnp5OCmL-xXNairT1-5Cy5e8HhTJr2vY0Rb2XHKaumJvYR9OI6SHVDNec4oZebNX6yw2xMk7DGTrdrndKvzpZl9940j7NNs6NRP763N-HTHiSKtwx6gJbU3MbKgPJ5S9fBH1bFUMqL-PlpepNdm9dUCgD_7TMAtEkHh4M6Aw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2
bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5
MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJq
dGkiOiIxYjMyOGE0Yy00YTY4LTQ0MTgtYjljYy1kMzhiZDU4NDgzZDgiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZh
MDIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpO
dDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVk
N2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0ODQ0Il0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBw
cm9maWxlIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5
ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdp
cmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0
aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.fG3BhAdWhOZfv-rCrco
1Up8yuPy2Y4xFFLn3dyobbKoIEXveg1_7dekeZpHeBGJXQmXHWQ1j8MBkS6enOsJ
6az_1Us9nVNTTEJceMElr6UodE5PI2Fu0TL-Y5qm9o80ntY6vjwVSJG4d8dpll8R
tVp3X9-uucgj1bksOCqAyzcOjD_Vnp5OCmL-xXNairT1-5Cy5e8HhTJr2vY0Rb2X
HKaumJvYR9OI6SHVDNec4oZebNX6yw2xMk7DGTrdrndKvzpZl9940j7NNs6NRP76
3N-HTHiSKtwx6gJbU3MbKgPJ5S9fBH1bFUMqL-PlpepNdm9dUCgD_7TMAtEkHh4M
6Aw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "pSCde4wUC6mK7qLLbZdIU_zuZjwCEl9Hqa7dWk31Qu8",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:24844"
  ],
  "aud": "account",
  "auth_time": 1707929004,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1707929064,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1707929004,
  "iss": "http://keycloak:18585/realms/master",
  "jti": "1b328a4c-4a68-4418-b9cc-d38bd58483d8",
  "name": "Alice Smith",
  "nonce": "mZjNt5ygsZyBgfXCj7g27A",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "realm_access": {
    "roles": [
      "default-roles-master",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid email profile",
  "session_state": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sid": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sub": "25751cc3-3238-42b0-aa0a-45cc9e476a02",
  "typ": "Bearer"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNjF9PPiYfefRrfl7v82
Ef35W/2DRCHkEATmgynV8BX33RJ8oEofQW9Uwoi4/yxsRNWZbQ3pD0VMqdHrM/H/
oPyLehSbOHUKFYms/JBIiKQ58f62+50gPLOFUJwoRZtbhUivG0Ue91URj9onAGXU
WVjcucJR6RCgu5uTTHpCjYES/xC89ehDTKw2GmB/4/wfdCNDowHJmkeZb5X9Er+W
rmOgsJN9q/UgFt4DvCd22VF8tmCSHpZ1FqLP4DatOyZTl+wlM87Yq++KFTZi10rH
xmMJ6jvq1Unc9xEV+JgrJHsJh4dGBQkdyb/yoT5X0huVI+tMDuNrb8IgV75mfAD+
JQIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjZWUzMjgwZC00NTdhLTRlZTItYjVlMS0xMWU0Y2ZiY2E3NjAifQ.eyJleHAiOjE3MDc5MzA4MDQsImlhdCI6MTcwNzkyOTAwNCwianRpIjoiYmY0OGYwNTYtNWExZS00MDg1LWFmZDAtMDhlYzIwODE2ZGM4IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE4NTg1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsInN1YiI6IjI1NzUxY2MzLTMyMzgtNDJiMC1hYTBhLTQ1Y2M5ZTQ3NmEwMiIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOdDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiI2Y2Y1MjJmNi01ZDdiLTQxMjMtOTUzMC03NmJhMmI3MDlkMWIifQ.gNgJU6gvhMgQA7uAQLOK3BtxXgu8YfssAmPZKx3XYEM)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjZWUzMjgwZC00
NTdhLTRlZTItYjVlMS0xMWU0Y2ZiY2E3NjAifQ.eyJleHAiOjE3MDc5MzA4MDQsI
mlhdCI6MTcwNzkyOTAwNCwianRpIjoiYmY0OGYwNTYtNWExZS00MDg1LWFmZDAtM
DhlYzIwODE2ZGM4IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE4NTg1L3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc
3RlciIsInN1YiI6IjI1NzUxY2MzLTMyMzgtNDJiMC1hYTBhLTQ1Y2M5ZTQ3NmEwM
iIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOd
DV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN
2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsInNjb3BlIjoib3BlbmlkIGVtYWlsI
HByb2ZpbGUiLCJzaWQiOiI2Y2Y1MjJmNi01ZDdiLTQxMjMtOTUzMC03NmJhMmI3M
DlkMWIifQ.gNgJU6gvhMgQA7uAQLOK3BtxXgu8YfssAmPZKx3XYEM
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "cee3280d-457a-4ee2-b5e1-11e4cfbca760",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:18585/realms/master",
  "azp": "wireapp",
  "exp": 1707930804,
  "iat": 1707929004,
  "iss": "http://keycloak:18585/realms/master",
  "jti": "bf48f056-5a1e-4085-afd0-08ec20816dc8",
  "nonce": "mZjNt5ygsZyBgfXCj7g27A",
  "scope": "openid email profile",
  "session_state": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sid": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sub": "25751cc3-3238-42b0-aa0a-45cc9e476a02",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNjF9PPiYfefRrfl7v82
Ef35W/2DRCHkEATmgynV8BX33RJ8oEofQW9Uwoi4/yxsRNWZbQ3pD0VMqdHrM/H/
oPyLehSbOHUKFYms/JBIiKQ58f62+50gPLOFUJwoRZtbhUivG0Ue91URj9onAGXU
WVjcucJR6RCgu5uTTHpCjYES/xC89ehDTKw2GmB/4/wfdCNDowHJmkeZb5X9Er+W
rmOgsJN9q/UgFt4DvCd22VF8tmCSHpZ1FqLP4DatOyZTl+wlM87Yq++KFTZi10rH
xmMJ6jvq1Unc9xEV+JgrJHsJh4dGBQkdyb/yoT5X0huVI+tMDuNrb8IgV75mfAD+
JQIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 23. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiJkZDcyMjRjNS1lYmZmLTRhN2YtOTkwZi1mYzQ5Y2YxMWU1ZDAiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXlnc1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6Ikk4RXZYbWlKTmpERWExSFhhTU44VGciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3VuRk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTL1RrQXJ3TWUzRXNWT2lPYURwQjQxY09RTEdjYnEwc0pKIiwia2V5YXV0aCI6IjdyMk95OVJCUFplN1ptbmRzdHIxYnp4MlFNU2tLdFV5LjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.psCqA_vY9GbouC1y4ykMfGGHHpuJ6gcZswOBlAUdekoGD-SRybaaCxQRjg4NmdpuIoTUN3PcJytBbyffiwYPgvl9MFTrt9wcG8OcWjzE4bedkZ5tFIiDGENkljH_QN_sjXDakuMRC9yVCFBEfGhtV1NLaGKlmzo008405sTSKOssz9kgljT19ySi4symK7yFu-LltoNjT6SToyHj0SJdVWftYZqWEQRr6yTEdfpe-m7TsZCupwlDMnzkRgXfYcDEhndaBWnEnRaxfHFSOsykUNvhtIKGtogxk-lebKm2l4xpHQcabyN10E3wLgiMfmNjCQnEcsEWu00xs287cYISjw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2
bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5
MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJq
dGkiOiJkZDcyMjRjNS1lYmZmLTRhN2YtOTkwZi1mYzQ5Y2YxMWU1ZDAiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZh
MDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXln
c1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00
MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6Ikk4RXZYbWlKTmpERWEx
SFhhTU44VGciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1
MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBh
bGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9h
dWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3Vu
Rk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTL1RrQXJ3TWUzRXNWT2lPYURw
QjQxY09RTEdjYnEwc0pKIiwia2V5YXV0aCI6IjdyMk95OVJCUFplN1ptbmRzdHIx
Ynp4MlFNU2tLdFV5LjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1
bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNt
aXRoQHdpcmUuY29tIn0.psCqA_vY9GbouC1y4ykMfGGHHpuJ6gcZswOBlAUdekoG
D-SRybaaCxQRjg4NmdpuIoTUN3PcJytBbyffiwYPgvl9MFTrt9wcG8OcWjzE4bed
kZ5tFIiDGENkljH_QN_sjXDakuMRC9yVCFBEfGhtV1NLaGKlmzo008405sTSKOss
z9kgljT19ySi4symK7yFu-LltoNjT6SToyHj0SJdVWftYZqWEQRr6yTEdfpe-m7T
sZCupwlDMnzkRgXfYcDEhndaBWnEnRaxfHFSOsykUNvhtIKGtogxk-lebKm2l4xp
HQcabyN10E3wLgiMfmNjCQnEcsEWu00xs287cYISjw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "pSCde4wUC6mK7qLLbZdIU_zuZjwCEl9Hqa7dWk31Qu8",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ",
  "acr": "1",
  "at_hash": "I8EvXmiJNjDEa1HXaMN8Tg",
  "aud": "wireapp",
  "auth_time": 1707929004,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1707929064,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1707929004,
  "iss": "http://keycloak:18585/realms/master",
  "jti": "dd7224c5-ebff-4a7f-990f-fc49cf11e5d0",
  "keyauth": "7r2Oy9RBPZe7Zmndstr1bzx2QMSkKtUy.1XmccI-BrrPKX4tCQ0Nas1GIMhckkypVmR5mcITgRAI",
  "name": "Alice Smith",
  "nonce": "mZjNt5ygsZyBgfXCj7g27A",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "session_state": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sid": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sub": "25751cc3-3238-42b0-aa0a-45cc9e476a02",
  "typ": "ID"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNjF9PPiYfefRrfl7v82
Ef35W/2DRCHkEATmgynV8BX33RJ8oEofQW9Uwoi4/yxsRNWZbQ3pD0VMqdHrM/H/
oPyLehSbOHUKFYms/JBIiKQ58f62+50gPLOFUJwoRZtbhUivG0Ue91URj9onAGXU
WVjcucJR6RCgu5uTTHpCjYES/xC89ehDTKw2GmB/4/wfdCNDowHJmkeZb5X9Er+W
rmOgsJN9q/UgFt4DvCd22VF8tmCSHpZ1FqLP4DatOyZTl+wlM87Yq++KFTZi10rH
xmMJ6jvq1Unc9xEV+JgrJHsJh4dGBQkdyb/yoT5X0huVI+tMDuNrb8IgV75mfAD+
JQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJZWGhSZGpSTmNVVmtRMEl4VVZaWmFrRTVSV0pZU0VsMlZITjVZa2RaV0RBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS91bkZNazVneU1iaHFXWmJFNEtnWXc3dndvbUEzbFB0Uy9Ua0Fyd01lM0VzVk9pT2FEcEI0MWNPUUxHY2JxMHNKSiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSndVME5rWlRSM1ZVTTJiVXMzY1V4TVlscGtTVlZmZW5WYWFuZERSV3c1U0hGaE4yUlhhek14VVhVNEluMC5leUpsZUhBaU9qRTNNRGM1TWprd05qUXNJbWxoZENJNk1UY3dOemt5T1RBd05Dd2lZWFYwYUY5MGFXMWxJam94TnpBM09USTVNREEwTENKcWRHa2lPaUprWkRjeU1qUmpOUzFsWW1abUxUUmhOMll0T1Rrd1ppMW1ZelE1WTJZeE1XVTFaREFpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNVGcxT0RVdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSXlOVGMxTVdOak15MHpNak00TFRReVlqQXRZV0V3WVMwME5XTmpPV1UwTnpaaE1ESWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJbTFhYWs1ME5YbG5jMXA1UW1kbVdFTnFOMmN5TjBFaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaU5tTm1OVEl5WmpZdE5XUTNZaTAwTVRJekxUazFNekF0TnpaaVlUSmlOekE1WkRGaUlpd2lZWFJmYUdGemFDSTZJa2s0UlhaWWJXbEtUbXBFUldFeFNGaGhUVTQ0VkdjaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaU5tTm1OVEl5WmpZdE5XUTNZaTAwTVRJekxUazFNekF0TnpaaVlUSmlOekE1WkRGaUlpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2laMmwyWlc1ZmJtRnRaU0k2SWtGc2FXTmxJaXdpWVdOdFpWOWhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpnNU1TOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMM1Z1Umsxck5XZDVUV0pvY1ZkYVlrVTBTMmRaZHpkMmQyOXRRVE5zVUhSVEwxUnJRWEozVFdVelJYTldUMmxQWVVSd1FqUXhZMDlSVEVkalluRXdjMHBLSWl3aWEyVjVZWFYwYUNJNklqZHlNazk1T1ZKQ1VGcGxOMXB0Ym1SemRISXhZbnA0TWxGTlUydExkRlY1TGpGWWJXTmpTUzFDY25KUVMxZzBkRU5STUU1aGN6RkhTVTFvWTJ0cmVYQldiVkkxYldOSlZHZFNRVWtpTENKbVlXMXBiSGxmYm1GdFpTSTZJbE50YVhSb0lpd2laVzFoYVd3aU9pSmhiR2xqWlhOdGFYUm9RSGRwY21VdVkyOXRJbjAucHNDcUFfdlk5R2JvdUMxeTR5a01mR0dISHB1SjZnY1pzd09CbEFVZGVrb0dELVNSeWJhYUN4UVJqZzRObWRwdUlvVFVOM1BjSnl0QmJ5ZmZpd1lQZ3ZsOU1GVHJ0OXdjRzhPY1dqekU0YmVka1o1dEZJaURHRU5rbGpIX1FOX3NqWERha3VNUkM5eVZDRkJFZkdodFYxTkxhR0tsbXpvMDA4NDA1c1RTS09zc3o5a2dsalQxOXlTaTRzeW1LN3lGdS1MbHRvTmpUNlNUb3lIajBTSmRWV2Z0WVpxV0VRUnI2eVRFZGZwZS1tN1RzWkN1cHdsRE1uemtSZ1hmWWNERWhuZGFCV25FblJheGZIRlNPc3lrVU52aHRJS0d0b2d4ay1sZWJLbTJsNHhwSFFjYWJ5TjEwRTN3TGdpTWZtTmpDUW5FY3NFV3UwMHhzMjg3Y1lJU2p3In0",
  "signature": "4skjBBisb9ukniRx5zYdtjQFEC2DItEhudW6wJZ-AEl7CuH6pbyHxOzsv2nM1TYFFLnqqppzrXKihYn7ICX2Cg"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiJkZDcyMjRjNS1lYmZmLTRhN2YtOTkwZi1mYzQ5Y2YxMWU1ZDAiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXlnc1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6Ikk4RXZYbWlKTmpERWExSFhhTU44VGciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3VuRk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTL1RrQXJ3TWUzRXNWT2lPYURwQjQxY09RTEdjYnEwc0pKIiwia2V5YXV0aCI6IjdyMk95OVJCUFplN1ptbmRzdHIxYnp4MlFNU2tLdFV5LjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.psCqA_vY9GbouC1y4ykMfGGHHpuJ6gcZswOBlAUdekoGD-SRybaaCxQRjg4NmdpuIoTUN3PcJytBbyffiwYPgvl9MFTrt9wcG8OcWjzE4bedkZ5tFIiDGENkljH_QN_sjXDakuMRC9yVCFBEfGhtV1NLaGKlmzo008405sTSKOssz9kgljT19ySi4symK7yFu-LltoNjT6SToyHj0SJdVWftYZqWEQRr6yTEdfpe-m7TsZCupwlDMnzkRgXfYcDEhndaBWnEnRaxfHFSOsykUNvhtIKGtogxk-lebKm2l4xpHQcabyN10E3wLgiMfmNjCQnEcsEWu00xs287cYISjw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "YXhRdjRNcUVkQ0IxUVZZakE5RWJYSEl2VHN5YkdZWDA",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ"
  }
}
```
#### 24. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
link: <https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS>;rel="up"
location: https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ
replay-nonce: d2dQUTJ5TmFvbHhmUm9UTldxNzBxa1lyZzRQWjdrSWQ
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ",
  "status": "valid",
  "token": "7r2Oy9RBPZe7Zmndstr1bzx2QMSkKtUy",
  "target": "http://keycloak:18585/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 25. verify the status of the order
```http request
POST https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJkMmRRVVRKNVRtRnZiSGhtVW05VVRsZHhOekJ4YTFseVp6UlFXamRyU1dRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL29yZGVyL0xxNXpSdHhHZHo2QVM5aWNWNDFIRURUWWxDRWFkNDJ1In0",
  "payload": "",
  "signature": "vgABP-ecywNZfS1Wp4_qdPA_kxGkp6DutWiVRAZ_ub45fqYB-GtHgmWNZqBLgsCaK8klouujK4uYnOu21gXFCA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "d2dQUTJ5TmFvbHhmUm9UTldxNzBxa1lyZzRQWjdrSWQ",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u"
  }
}
```
#### 26. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
replay-nonce: a0dSU0dxRXFZRHUyS1BlenNma2hlWXB3YkgwaTlOd3A
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y",
    "https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS"
  ],
  "expires": "2024-02-15T16:43:24Z",
  "notBefore": "2024-02-14T16:43:24.631769Z",
  "notAfter": "2034-02-11T16:43:24.631769Z"
}
```
#### 27. create a CSR and call finalize url
```http request
POST https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJhMGRTVTBkeFJYRlpSSFV5UzFCbGVuTm1hMmhsV1hCM1lrZ3dhVGxPZDNBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL29yZGVyL0xxNXpSdHhHZHo2QVM5aWNWNDFIRURUWWxDRWFkNDJ1L2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBT09TUE9UMVhwNUtBbXF2TDRFTDQtdUxUaGEtenhoaVpXM1hNTDdwRzlGRG9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2TFVGSGJUaDFObkZSUlcxblJETXhlamgwVXpoMlp5Rm1aalkxWTJNNU5Ea3lZMkk0Tm1VMlFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFBV1lSdXFPazNad3d3aVVjdzlqSUlQQTN6OFVaTDl1TXNzcURxQzUtT25mbkliLUZDeVNVWHV4MGNCZkdZZHh4NDRuQTB0X01tM0hBd2t2c3V2cmZZRCJ9",
  "signature": "HSaYP0uRI8wrWODj1IkHQSs2L4lRqbdpGBNOOb2sPlHWW8-iMafFcTZ3p6EtHUDcwxF7U0WLCe5UUya0_-1JBw"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOOSPOT1Xp5KAmqvL4EL4-uLTha-zxhiZW3XML7pG9FDoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQAWYRuqOk3ZwwwiUcw9jIIPA3z8UZL9uMssqDqC5-OnfnIb-FCySUXux0cBfGYdxx44nA0t_Mm3HAwkvsuvrfYD"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "a0dSU0dxRXFZRHUyS1BlenNma2hlWXB3YkgwaTlOd3A",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOOSPOT1Xp5KAmqvL4EL4+uLTha+zxhi
ZW3XML7pG9FDoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQAW
YRuqOk3ZwwwiUcw9jIIPA3z8UZL9uMssqDqC5+OnfnIb+FCySUXux0cBfGYdxx44
nA0t/Mm3HAwkvsuvrfYD
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
                    e3:92:3c:e4:f5:5e:9e:4a:02:6a:af:2f:81:0b:e3:
                    eb:8b:4e:16:be:cf:18:62:65:6d:d7:30:be:e9:1b:
                    d1:43
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        16:61:1b:aa:3a:4d:d9:c3:0c:22:51:cc:3d:8c:82:0f:03:7c:
        fc:51:92:fd:b8:cb:2c:a8:3a:82:e7:e3:a7:7e:72:1b:f8:50:
        b2:49:45:ee:c7:47:01:7c:66:1d:c7:1e:38:9c:0d:2d:fc:c9:
        b7:1c:0c:24:be:cb:af:ad:f6:03

```

#### 28. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
replay-nonce: blhtbm9aZ3k0NjFBYnJEdTN1d1BGRERsRm5tM2E0Qkw
```
```json
{
  "certificate": "https://stepca:32891/acme/wire/certificate/i45h6J6Tg1muxDYCZcTliGIdHzjQ3vRQ",
  "status": "valid",
  "finalize": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y",
    "https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS"
  ],
  "expires": "2024-02-15T16:43:24Z",
  "notBefore": "2024-02-14T16:43:24.631769Z",
  "notAfter": "2034-02-11T16:43:24.631769Z"
}
```
#### 29. fetch the certificate
```http request
POST https://stepca:32891/acme/wire/certificate/i45h6J6Tg1muxDYCZcTliGIdHzjQ3vRQ
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJibGh0Ym05YVozazBOakZCWW5KRWRUTjFkMUJHUkVSc1JtNXRNMkUwUWt3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NlcnRpZmljYXRlL2k0NWg2SjZUZzFtdXhEWUNaY1RsaUdJZEh6alEzdlJRIn0",
  "payload": "",
  "signature": "1HCLEL_RpyLO0z0GlSx9voIGSUNDQaCmdbMjXFR-quK8h36uWAHb5iTFVOjbY9PWyKX0uJKmdjxGrurMSTm_Bw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "blhtbm9aZ3k0NjFBYnJEdTN1d1BGRERsRm5tM2E0Qkw",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/certificate/i45h6J6Tg1muxDYCZcTliGIdHzjQ3vRQ"
  }
}
```
#### 30. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32891/acme/wire/directory>;rel="index"
replay-nonce: MFlMa1lDYXRTZEtNSTlTS3lRNGdFcGt2UWlTY0g1YzU
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAcCgAwIBAgIRAPPJLWt2K/8ZwNOoTR14m4IwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMjE0MTY0MzI0WhcNMzQwMjExMTY0MzI0WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDjkjzk9V6eSgJqry+B\nC+Pri04Wvs8YYmVt1zC+6RvRQ6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFEaPewHEHyJxHbafLfMMVxy8D2RfMB8G\nA1UdIwQYMBaAFK71u5zGiREQFiKMSmdlLblCLIXiMGkGA1UdEQRiMGCGIHdpcmVh\ncHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vLUFHbTh1NnFR\nRW1nRDMxejh0Uzh2ZyUyMWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQDpEse7\nv4afo/2rCdUdxG0MHDbpJ1dYekMQkYpHJWWKogIgdhFwiMggZ8TIirTgNDYzpaKc\n/QUtksBwYbsIvZtaimM=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAMozgWjsOcvz/3Zobz72C9wwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIxNDE2\nNDMyM1oXDTM0MDIxMTE2NDMyM1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARK\nHjjiLNTcPFVzUfgE/uVp4l9Za9kpP8JdPBtb70CaCBiZQv1W2wt6bW5IQDcdst/k\nezOTP67MzRy1Zq4+cHI5o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUrvW7nMaJERAWIoxKZ2UtuUIsheIwHwYDVR0jBBgw\nFoAUMSVwCNppa2aUboIq7dM33lempbYwCgYIKoZIzj0EAwIDSAAwRQIgCGGTq3Xn\nZKEEoqrtmwarWIb0+jaFD2Dv9Ug/BadXNRkCIQDcRnknaaGIzWA1gxrsT033SUCB\n76FrXLeIzYFbb1/ZWw==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRAPPJLWt2K/8ZwNOoTR14m4IwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMjE0MTY0MzI0WhcNMzQwMjExMTY0MzI0WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDjkjzk9V6eSgJqry+B
C+Pri04Wvs8YYmVt1zC+6RvRQ6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFEaPewHEHyJxHbafLfMMVxy8D2RfMB8G
A1UdIwQYMBaAFK71u5zGiREQFiKMSmdlLblCLIXiMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vLUFHbTh1NnFR
RW1nRDMxejh0Uzh2ZyUyMWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQDpEse7
v4afo/2rCdUdxG0MHDbpJ1dYekMQkYpHJWWKogIgdhFwiMggZ8TIirTgNDYzpaKc
/QUtksBwYbsIvZtaimM=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f3:c9:2d:6b:76:2b:ff:19:c0:d3:a8:4d:1d:78:9b:82
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Feb 14 16:43:24 2024 GMT
            Not After : Feb 11 16:43:24 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    e3:92:3c:e4:f5:5e:9e:4a:02:6a:af:2f:81:0b:e3:
                    eb:8b:4e:16:be:cf:18:62:65:6d:d7:30:be:e9:1b:
                    d1:43
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                46:8F:7B:01:C4:1F:22:71:1D:B6:9F:2D:F3:0C:57:1C:BC:0F:64:5F
            X509v3 Authority Key Identifier: 
                AE:F5:BB:9C:C6:89:11:10:16:22:8C:4A:67:65:2D:B9:42:2C:85:E2
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://-AGm8u6qQEmgD31z8tS8vg%21ff65cc9492cb86e6@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:e9:12:c7:bb:bf:86:9f:a3:fd:ab:09:d5:1d:
        c4:6d:0c:1c:36:e9:27:57:58:7a:43:10:91:8a:47:25:65:8a:
        a2:02:20:76:11:70:88:c8:20:67:c4:c8:8a:b4:e0:34:36:33:
        a5:a2:9c:fd:05:2d:92:c0:70:61:bb:08:bd:9b:5a:8a:63

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAMozgWjsOcvz/3Zobz72C9wwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIxNDE2
NDMyM1oXDTM0MDIxMTE2NDMyM1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARK
HjjiLNTcPFVzUfgE/uVp4l9Za9kpP8JdPBtb70CaCBiZQv1W2wt6bW5IQDcdst/k
ezOTP67MzRy1Zq4+cHI5o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUrvW7nMaJERAWIoxKZ2UtuUIsheIwHwYDVR0jBBgw
FoAUMSVwCNppa2aUboIq7dM33lempbYwCgYIKoZIzj0EAwIDSAAwRQIgCGGTq3Xn
ZKEEoqrtmwarWIb0+jaFD2Dv9Ug/BadXNRkCIQDcRnknaaGIzWA1gxrsT033SUCB
76FrXLeIzYFbb1/ZWw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ca:33:81:68:ec:39:cb:f3:ff:76:68:6f:3e:f6:0b:dc
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Feb 14 16:43:23 2024 GMT
            Not After : Feb 11 16:43:23 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:4a:1e:38:e2:2c:d4:dc:3c:55:73:51:f8:04:fe:
                    e5:69:e2:5f:59:6b:d9:29:3f:c2:5d:3c:1b:5b:ef:
                    40:9a:08:18:99:42:fd:56:db:0b:7a:6d:6e:48:40:
                    37:1d:b2:df:e4:7b:33:93:3f:ae:cc:cd:1c:b5:66:
                    ae:3e:70:72:39
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                AE:F5:BB:9C:C6:89:11:10:16:22:8C:4A:67:65:2D:B9:42:2C:85:E2
            X509v3 Authority Key Identifier: 
                31:25:70:08:DA:69:6B:66:94:6E:82:2A:ED:D3:37:DE:57:A6:A5:B6
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:08:61:93:ab:75:e7:64:a1:04:a2:aa:ed:9b:06:
        ab:58:86:f4:fa:36:85:0f:60:ef:f5:48:3f:05:a7:57:35:19:
        02:21:00:dc:46:79:27:69:a1:88:cd:60:35:83:1a:ec:4f:4d:
        f7:49:40:81:ef:a1:6b:5c:b7:88:cd:81:5b:6f:5f:d9:5b

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIRAJ7hMABiG5+3cynJvQ/+qpkwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIxNDE2
NDMyMloXDTM0MDIxMTE2NDMyMlowJjENMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMM
d2lyZSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjQwCn9y0Yzvd
GSq6JuW3HZqcGlH/6adAeMDj9/jt9zYADoy1zbX51i/PgqbzeqvIpGafkITmLfvF
4rSxWln6jaNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEw
HQYDVR0OBBYEFDElcAjaaWtmlG6CKu3TN95XpqW2MAoGCCqGSM49BAMCA0gAMEUC
IQD6nqKS3dXConqJUHRQFjZLYBMPC71CDd+EuGi2gEsyJAIgK/RkD6O+PatAyamY
BVAhtx004tYoC93p5wEIVECcVck=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9e:e1:30:00:62:1b:9f:b7:73:29:c9:bd:0f:fe:aa:99
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Feb 14 16:43:22 2024 GMT
            Not After : Feb 11 16:43:22 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:8d:0c:02:9f:dc:b4:63:3b:dd:19:2a:ba:26:e5:
                    b7:1d:9a:9c:1a:51:ff:e9:a7:40:78:c0:e3:f7:f8:
                    ed:f7:36:00:0e:8c:b5:cd:b5:f9:d6:2f:cf:82:a6:
                    f3:7a:ab:c8:a4:66:9f:90:84:e6:2d:fb:c5:e2:b4:
                    b1:5a:59:fa:8d
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                31:25:70:08:DA:69:6B:66:94:6E:82:2A:ED:D3:37:DE:57:A6:A5:B6
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:fa:9e:a2:92:dd:d5:c2:a2:7a:89:50:74:50:
        16:36:4b:60:13:0f:0b:bd:42:0d:df:84:b8:68:b6:80:4b:32:
        24:02:20:2b:f4:64:0f:a3:be:3d:ab:40:c9:a9:98:05:50:21:
        b7:1d:34:e2:d6:28:0b:dd:e9:e7:01:08:54:40:9c:55:c9

```

openssl verify chain ✅
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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/ff65cc9492cb86e6/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/i45h6J6Tg1muxDYCZcTliGIdHzjQ3vRQ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 GET /acme/wire/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 HEAD /acme/wire/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/new-account
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/ff65cc9492cb86e6/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG/19iRSA0lNPoQip2wmXqPuNjlt1RwrYd2
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco/N3OvFgrDNAom0pWjrPi0hp0vzfPWitoB
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/9mftsmv3zulm53CU27NqTcj18ogV6wKx
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32891/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32891/acme/wire/new-nonce",
  "newAccount": "https://stepca:32891/acme/wire/new-account",
  "newOrder": "https://stepca:32891/acme/wire/new-order",
  "revokeCert": "https://stepca:32891/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32891/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32891/acme/wire/directory>;rel="index"
replay-nonce: VHNpY0xyeWVPdlFCb1BVZ1lVeWQ4TGRUM3RyUXUyWko
```
```text
VHNpY0xyeWVPdlFCb1BVZ1lVeWQ4TGRUM3RyUXUyWko
```
#### 5. create a new account
```http request
POST https://stepca:32891/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjAwejNJM3ctUVBXbUF4QzdEaHR4aVFXdElpeWR2a1Nnekd2dlNtdmN3VnMifSwibm9uY2UiOiJWSE5wWTB4eWVXVlBkbEZDYjFCVloxbFZlV1E0VEdSVU0zUnlVWFV5V2tvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "ohsFpfhGZFgXV8AIviCZhDu-CEiUvIZ0u_0uKrRLIXN3aeaNidR5oH0ZfqSghppB1o0B_8HyjaM1pv6PjO3-Bg"
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
      "x": "00z3I3w-QPWmAxC7DhtxiQWtIiydvkSgzGvvSmvcwVs"
    },
    "nonce": "VHNpY0xyeWVPdlFCb1BVZ1lVeWQ4TGRUM3RyUXUyWko",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR
replay-nonce: U1BwRDM4NFVMc1Vtd3B6dUd6eXJkZjl4VG1oUlRRb2w
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32891/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJVMUJ3UkRNNE5GVk1jMVZ0ZDNCNmRVZDZlWEprWmpsNFZHMW9VbFJSYjJ3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMi0xNFQxNjo0MzoyNC42MzE3NjlaIiwibm90QWZ0ZXIiOiIyMDM0LTAyLTExVDE2OjQzOjI0LjYzMTc2OVoifQ",
  "signature": "uWfDrfP-ZE8ODZJFYYXyODE6S9uQkWeoyi60w25ivfUwkr0DGYjNeuQMsRi_bZ1qYCAhQB-KLgML-93wlK2cBA"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2034-02-11T16:43:24.631769Z",
    "notBefore": "2024-02-14T16:43:24.631769Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "U1BwRDM4NFVMc1Vtd3B6dUd6eXJkZjl4VG1oUlRRb2w",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
replay-nonce: Nk1GUW1lMjBIbTVvRjRTb0FjWTcycDh1OXpRWjJlaFo
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y",
    "https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS"
  ],
  "expires": "2024-02-15T16:43:24Z",
  "notBefore": "2024-02-14T16:43:24.631769Z",
  "notAfter": "2034-02-11T16:43:24.631769Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJOazFHVVcxbE1qQkliVFZ2UmpSVGIwRmpXVGN5Y0RoMU9YcFJXakpsYUZvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2F1dGh6L1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZIn0",
  "payload": "",
  "signature": "Ih0aj_yA37iAz1jzREeQCy6pk-4w5Rt6284aPsvic8rSN6qFTLTvro5_pMkaCBLG3KewZe084aH59lJt9gNcBA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "Nk1GUW1lMjBIbTVvRjRTb0FjWTcycDh1OXpRWjJlaFo",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y
replay-nonce: SmE5UEFWNGQ1UE40bHd0MXN0Z1RSMVo0MURzQmhMWVM
```
```json
{
  "status": "pending",
  "expires": "2024-02-15T16:43:24Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M",
      "status": "pending",
      "token": "uDweLiHzAB74sHkE9RQiuHJx2XrUmhGA",
      "target": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJTbUU1VUVGV05HUTFVRTQwYkhkME1YTjBaMVJTTVZvME1VUnpRbWhNV1ZNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2F1dGh6L3VuRk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTIn0",
  "payload": "",
  "signature": "WsrOvFC12jYa_9FqJnm9pGnmXIiU_vC2PUEiPJ9EY78VFo_W7w5mi_NgGC_OHtaC-_LNhX11M6NLz2Bar3zCBw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "SmE5UEFWNGQ1UE40bHd0MXN0Z1RSMVo0MURzQmhMWVM",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS"
  }
}
```
#### 11. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS
replay-nonce: MTV2SUdpdDZrcEU5S1Uza25Ccmdja09xbHY5MzNTMGQ
```
```json
{
  "status": "pending",
  "expires": "2024-02-15T16:43:24Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ",
      "status": "pending",
      "token": "7r2Oy9RBPZe7Zmndstr1bzx2QMSkKtUy",
      "target": "http://keycloak:18585/realms/master"
    }
  ],
  "identifier": {
    "type": "wireapp-user",
    "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 12. fetch a nonce from wire-server
```http request
GET http://wire.com:24844/clients/token/nonce
```
#### 13. get wire-server nonce
```http request
200

```
```text
NTNCcDFKb0tLWUFOdTRQZFFiRDc3WXpHNG8xQUxrVUE
```
#### 14. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMDB6M0kzdy1RUFdtQXhDN0RodHhpUVd0SWl5ZHZrU2d6R3Z2U212Y3dWcyJ9fQ.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkzMjYwNCwibmJmIjoxNzA3OTI1NDA0LCJzdWIiOiJ3aXJlYXBwOi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS9YQVlmT2NyQWQ3QldOWTJyRncwWENOWFJsY2JudWYzWS9senBYbDZSOXM1cDdZS0JVVzhoTE9pUHJFd1YwVHM0TSIsImp0aSI6IjZlMzJjM2QyLTJiMTItNGYxYy04ZGNlLWI2MTA1OGEzMDU3NyIsIm5vbmNlIjoiTlROQ2NERktiMHRMV1VGT2RUUlFaRkZpUkRjM1dYcEhORzh4UVV4clZVRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJ1RHdlTGlIekFCNzRzSGtFOVJRaXVISngyWHJVbWhHQSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.F-3iKzDtG658aipTFPZyPYnzV8AqYgz3yc2juUuIrot33uTyY2IEC6HPdyNyLR3MuZtgVI2yGEC9LOyIm6TyAw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMDB6M0kzdy1RUFdtQXhDN0RodHhpUVd0
SWl5ZHZrU2d6R3Z2U212Y3dWcyJ9fQ.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6M
TcwNzkzMjYwNCwibmJmIjoxNzA3OTI1NDA0LCJzdWIiOiJ3aXJlYXBwOi8vLUFHb
Th1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS9YQ
VlmT2NyQWQ3QldOWTJyRncwWENOWFJsY2JudWYzWS9senBYbDZSOXM1cDdZS0JVV
zhoTE9pUHJFd1YwVHM0TSIsImp0aSI6IjZlMzJjM2QyLTJiMTItNGYxYy04ZGNlL
WI2MTA1OGEzMDU3NyIsIm5vbmNlIjoiTlROQ2NERktiMHRMV1VGT2RUUlFaRkZpU
kRjM1dYcEhORzh4UVV4clZVRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b
2tlbiIsImNoYWwiOiJ1RHdlTGlIekFCNzRzSGtFOVJRaXVISngyWHJVbWhHQSIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUifQ.F-3iKzDtG658aipTFPZyPYnzV8AqYgz3yc2juUuIrot33uTyY2
IEC6HPdyNyLR3MuZtgVI2yGEC9LOyIm6TyAw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "00z3I3w-QPWmAxC7DhtxiQWtIiydvkSgzGvvSmvcwVs"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M",
  "chal": "uDweLiHzAB74sHkE9RQiuHJx2XrUmhGA",
  "exp": 1707932604,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token",
  "iat": 1707925404,
  "jti": "6e32c3d2-2b12-4f1c-8dce-b61058a30577",
  "nbf": 1707925404,
  "nonce": "NTNCcDFKb0tLWUFOdTRQZFFiRDc3WXpHNG8xQUxrVUE",
  "sub": "wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICXKf2Zu5a1F0NfMYenEYp/FuOudMii72btMXUQ4D3qj
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA00z3I3w+QPWmAxC7DhtxiQWtIiydvkSgzGvvSmvcwVs=
-----END PUBLIC KEY-----
```

</details>


#### 15. trade client DPoP token for an access token
```http request
POST http://wire.com:24844/clients/ff65cc9492cb86e6/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTURCNk0wa3pkeTFSVUZkdFFYaEROMFJvZEhocFVWZDBTV2w1WkhaclUyZDZSM1oyVTIxMlkzZFdjeUo5ZlEuZXlKcFlYUWlPakUzTURjNU1qVTBNRFFzSW1WNGNDSTZNVGN3Tnprek1qWXdOQ3dpYm1KbUlqb3hOekEzT1RJMU5EQTBMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZMVUZIYlRoMU5uRlJSVzFuUkRNeGVqaDBVemgyWnlGbVpqWTFZMk01TkRreVkySTRObVUyUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekk0T1RFdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOVlRVmxtVDJOeVFXUTNRbGRPV1RKeVJuY3dXRU5PV0ZKc1kySnVkV1l6V1M5c2VuQlliRFpTT1hNMWNEZFpTMEpWVnpob1RFOXBVSEpGZDFZd1ZITTBUU0lzSW1wMGFTSTZJalpsTXpKak0yUXlMVEppTVRJdE5HWXhZeTA0WkdObExXSTJNVEExT0dFek1EVTNOeUlzSW01dmJtTmxJam9pVGxST1EyTkVSa3RpTUhSTVYxVkdUMlJVVWxGYVJrWnBVa1JqTTFkWWNFaE9Semg0VVZWNGNsWlZSU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRNE5EUXZZMnhwWlc1MGN5OW1aalkxWTJNNU5Ea3lZMkk0Tm1VMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUoxUkhkbFRHbElla0ZDTnpSelNHdEZPVkpSYVhWSVNuZ3lXSEpWYldoSFFTSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpZlEuRi0zaUt6RHRHNjU4YWlwVEZQWnlQWW56VjhBcVlnejN5YzJqdVV1SXJvdDMzdVR5WTJJRUM2SFBkeU55TFIzTXVadGdWSTJ5R0VDOUxPeUltNlR5QXc
```
#### 16. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZVQjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkyOTM2NCwibmJmIjoxNzA3OTI1NDA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZL2x6cFhsNlI5czVwN1lLQlVXOGhMT2lQckV3VjBUczRNIiwianRpIjoiODQ4Yzc1MTQtOGY3MC00NzRhLWEyZGItMTMzZGRjNDMxOGQ4Iiwibm9uY2UiOiJOVE5DY0RGS2IwdExXVUZPZFRSUVpGRmlSRGMzV1hwSE5HOHhRVXhyVlVFIiwiY2hhbCI6InVEd2VMaUh6QUI3NHNIa0U5UlFpdUhKeDJYclVtaEdBIiwiY25mIjp7ImtpZCI6IjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJkNlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0Y0NJNk1UY3dOemt6TWpZd05Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZtWmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5WVFWbG1UMk55UVdRM1FsZE9XVEp5Um5jd1dFTk9XRkpzWTJKdWRXWXpXUzlzZW5CWWJEWlNPWE0xY0RkWlMwSlZWemhvVEU5cFVISkZkMVl3VkhNMFRTSXNJbXAwYVNJNklqWmxNekpqTTJReUxUSmlNVEl0TkdZeFl5MDRaR05sTFdJMk1UQTFPR0V6TURVM055SXNJbTV2Ym1ObElqb2lUbFJPUTJORVJrdGlNSFJNVjFWR1QyUlVVbEZhUmtacFVrUmpNMWRZY0VoT1J6aDRVVlY0Y2xaVlJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUwY3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjFSSGRsVEdsSWVrRkNOelJ6U0d0Rk9WSlJhWFZJU25neVdISlZiV2hIUVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5GLTNpS3pEdEc2NThhaXBURlBaeVBZbnpWOEFxWWd6M3ljMmp1VXVJcm90MzN1VHlZMklFQzZIUGR5TnlMUjNNdVp0Z1ZJMnlHRUM5TE95SW02VHlBdyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.zmNPxi69hsXt7mg1K94SCo-VhY1AuSAqmKjk6X_QF136voJ7aZnYUPIbHLPqykZcXUISMJj9VZaeeoSkfRRvDw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZVQjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkyOTM2NCwibmJmIjoxNzA3OTI1NDA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZL2x6cFhsNlI5czVwN1lLQlVXOGhMT2lQckV3VjBUczRNIiwianRpIjoiODQ4Yzc1MTQtOGY3MC00NzRhLWEyZGItMTMzZGRjNDMxOGQ4Iiwibm9uY2UiOiJOVE5DY0RGS2IwdExXVUZPZFRSUVpGRmlSRGMzV1hwSE5HOHhRVXhyVlVFIiwiY2hhbCI6InVEd2VMaUh6QUI3NHNIa0U5UlFpdUhKeDJYclVtaEdBIiwiY25mIjp7ImtpZCI6IjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJkNlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0Y0NJNk1UY3dOemt6TWpZd05Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZtWmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5WVFWbG1UMk55UVdRM1FsZE9XVEp5Um5jd1dFTk9XRkpzWTJKdWRXWXpXUzlzZW5CWWJEWlNPWE0xY0RkWlMwSlZWemhvVEU5cFVISkZkMVl3VkhNMFRTSXNJbXAwYVNJNklqWmxNekpqTTJReUxUSmlNVEl0TkdZeFl5MDRaR05sTFdJMk1UQTFPR0V6TURVM055SXNJbTV2Ym1ObElqb2lUbFJPUTJORVJrdGlNSFJNVjFWR1QyUlVVbEZhUmtacFVrUmpNMWRZY0VoT1J6aDRVVlY0Y2xaVlJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUwY3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjFSSGRsVEdsSWVrRkNOelJ6U0d0Rk9WSlJhWFZJU25neVdISlZiV2hIUVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5GLTNpS3pEdEc2NThhaXBURlBaeVBZbnpWOEFxWWd6M3ljMmp1VXVJcm90MzN1VHlZMklFQzZIUGR5TnlMUjNNdVp0Z1ZJMnlHRUM5TE95SW02VHlBdyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.zmNPxi69hsXt7mg1K94SCo-VhY1AuSAqmKjk6X_QF136voJ7aZnYUPIbHLPqykZcXUISMJj9VZaeeoSkfRRvDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZV
QjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcw
NzkyOTM2NCwibmJmIjoxNzA3OTI1NDA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJj
Yjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21l
L3dpcmUvY2hhbGxlbmdlL1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZ
L2x6cFhsNlI5czVwN1lLQlVXOGhMT2lQckV3VjBUczRNIiwianRpIjoiODQ4Yzc1
MTQtOGY3MC00NzRhLWEyZGItMTMzZGRjNDMxOGQ4Iiwibm9uY2UiOiJOVE5DY0RG
S2IwdExXVUZPZFRSUVpGRmlSRGMzV1hwSE5HOHhRVXhyVlVFIiwiY2hhbCI6InVE
d2VMaUh6QUI3NHNIa0U5UlFpdUhKeDJYclVtaEdBIiwiY25mIjp7ImtpZCI6IjFY
bWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJk
NlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0
Y0NJNk1UY3dOemt6TWpZd05Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZt
WmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM5WVFWbG1UMk55UVdRM1FsZE9XVEp5Um5jd1dFTk9XRkpzWTJKdWRXWXpXUzlz
ZW5CWWJEWlNPWE0xY0RkWlMwSlZWemhvVEU5cFVISkZkMVl3VkhNMFRTSXNJbXAw
YVNJNklqWmxNekpqTTJReUxUSmlNVEl0TkdZeFl5MDRaR05sTFdJMk1UQTFPR0V6
TURVM055SXNJbTV2Ym1ObElqb2lUbFJPUTJORVJrdGlNSFJNVjFWR1QyUlVVbEZh
UmtacFVrUmpNMWRZY0VoT1J6aDRVVlY0Y2xaVlJTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUw
Y3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSjFSSGRsVEdsSWVrRkNOelJ6U0d0Rk9WSlJhWFZJU25neVdISlZiV2hI
UVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5GLTNpS3pEdEc2NThh
aXBURlBaeVBZbnpWOEFxWWd6M3ljMmp1VXVJcm90MzN1VHlZMklFQzZIUGR5TnlM
UjNNdVp0Z1ZJMnlHRUM5TE95SW02VHlBdyIsImNsaWVudF9pZCI6IndpcmVhcHA6
Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5j
b20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.zmN
Pxi69hsXt7mg1K94SCo-VhY1AuSAqmKjk6X_QF136voJ7aZnYUPIbHLPqykZcXUI
SMJj9VZaeeoSkfRRvDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "p297i1tJkAdaOLMnpxugMQoAFUB9HTM0CvdjGjlJYzY"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M",
  "chal": "uDweLiHzAB74sHkE9RQiuHJx2XrUmhGA",
  "client_id": "wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com",
  "cnf": {
    "kid": "1XmccI-BrrPKX4tCQ0Nas1GIMhckkypVmR5mcITgRAI"
  },
  "exp": 1707929364,
  "iat": 1707925404,
  "iss": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token",
  "jti": "848c7514-8f70-474a-a2db-133ddc4318d8",
  "nbf": 1707925404,
  "nonce": "NTNCcDFKb0tLWUFOdTRQZFFiRDc3WXpHNG8xQUxrVUE",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMDB6M0kzdy1RUFdtQXhDN0RodHhpUVd0SWl5ZHZrU2d6R3Z2U212Y3dWcyJ9fQ.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkzMjYwNCwibmJmIjoxNzA3OTI1NDA0LCJzdWIiOiJ3aXJlYXBwOi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS9YQVlmT2NyQWQ3QldOWTJyRncwWENOWFJsY2JudWYzWS9senBYbDZSOXM1cDdZS0JVVzhoTE9pUHJFd1YwVHM0TSIsImp0aSI6IjZlMzJjM2QyLTJiMTItNGYxYy04ZGNlLWI2MTA1OGEzMDU3NyIsIm5vbmNlIjoiTlROQ2NERktiMHRMV1VGT2RUUlFaRkZpUkRjM1dYcEhORzh4UVV4clZVRSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJ1RHdlTGlIekFCNzRzSGtFOVJRaXVISngyWHJVbWhHQSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.F-3iKzDtG658aipTFPZyPYnzV8AqYgz3yc2juUuIrot33uTyY2IEC6HPdyNyLR3MuZtgVI2yGEC9LOyIm6TyAw",
  "scope": "wire_client_id",
  "sub": "wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJatwIEJkQb2JTfifGXoh49zXUOBSvkByqeHY4XBJQf1
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAp297i1tJkAdaOLMnpxugMQoAFUB9HTM0CvdjGjlJYzY=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 17. validate Dpop challenge (clientId)
```http request
POST https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJNVFYyU1VkcGREWnJjRVU1UzFVemEyNUNjbWRqYTA5eGJIWTVNek5UTUdRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS9YQVlmT2NyQWQ3QldOWTJyRncwWENOWFJsY2JudWYzWS9senBYbDZSOXM1cDdZS0JVVzhoTE9pUHJFd1YwVHM0TSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluQXlPVGRwTVhSS2EwRmtZVTlNVFc1d2VIVm5UVkZ2UVVaVlFqbElWRTB3UTNaa2FrZHFiRXBaZWxraWZYMC5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0Y0NJNk1UY3dOemt5T1RNMk5Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRNE5EUXZZMnhwWlc1MGN5OW1aalkxWTJNNU5Ea3lZMkk0Tm1VMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTh0UVVkdE9IVTJjVkZGYldkRU16RjZPSFJUT0habklXWm1OalZqWXprME9USmpZamcyWlRaQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpnNU1TOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMWhCV1daUFkzSkJaRGRDVjA1Wk1uSkdkekJZUTA1WVVteGpZbTUxWmpOWkwyeDZjRmhzTmxJNWN6VndOMWxMUWxWWE9HaE1UMmxRY2tWM1ZqQlVjelJOSWl3aWFuUnBJam9pT0RRNFl6YzFNVFF0T0dZM01DMDBOelJoTFdFeVpHSXRNVE16WkdSak5ETXhPR1E0SWl3aWJtOXVZMlVpT2lKT1ZFNURZMFJHUzJJd2RFeFhWVVpQWkZSU1VWcEdSbWxTUkdNelYxaHdTRTVIT0hoUlZYaHlWbFZGSWl3aVkyaGhiQ0k2SW5WRWQyVk1hVWg2UVVJM05ITklhMFU1VWxGcGRVaEtlREpZY2xWdGFFZEJJaXdpWTI1bUlqcDdJbXRwWkNJNklqRlliV05qU1MxQ2NuSlFTMWcwZEVOUk1FNWhjekZIU1Uxb1kydHJlWEJXYlZJMWJXTkpWR2RTUVVraWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsTlJFSTJUVEJyZW1SNU1WSlZSbVIwVVZob1JFNHdVbTlrU0dod1ZWWmtNRk5YYkRWYVNGcHlWVEprTmxJeldqSlZNakV5V1ROa1YyTjVTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5SR00xVFdwVk1FMUVVWE5KYlZZMFkwTkpOazFVWTNkT2VtdDZUV3BaZDA1RGQybGliVXB0U1dwdmVFNTZRVE5QVkVreFRrUkJNRXhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRreFZSa2hpVkdneFRtNUdVbEpYTVc1U1JFMTRaV3BvTUZWNmFESmFlVVp0V21wWk1Wa3lUVFZPUkd0NVdUSkpORTV0VlRKUlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUUlBWRVYyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE01V1ZGV2JHMVVNazU1VVZkUk0xRnNaRTlYVkVwNVVtNWpkMWRGVGs5WFJrcHpXVEpLZFdSWFdYcFhVemx6Wlc1Q1dXSkVXbE5QV0UweFkwUmtXbE13U2xaV2VtaHZWRVU1Y0ZWSVNrWmtNVmwzVmtoTk1GUlRTWE5KYlhBd1lWTkpOa2xxV214TmVrcHFUVEpSZVV4VVNtbE5WRWwwVGtkWmVGbDVNRFJhUjA1c1RGZEpNazFVUVRGUFIwVjZUVVJWTTA1NVNYTkpiVFYyWW0xT2JFbHFiMmxVYkZKUFVUSk9SVkpyZEdsTlNGSk5WakZXUjFReVVsVlZiRVpoVW10YWNGVnJVbXBOTVdSWlkwVm9UMUo2YURSVlZsWTBZMnhhVmxKVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxFMFRrUlJkbGt5ZUhCYVZ6VXdZM2s1YlZwcVdURlpNazAxVGtScmVWa3lTVFJPYlZVeVRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTakZTU0dSc1ZFZHNTV1ZyUmtOT2VsSjZVMGQwUms5V1NsSmhXRlpKVTI1bmVWZElTbFppVjJoSVVWTkpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsbVVTNUdMVE5wUzNwRWRFYzJOVGhoYVhCVVJsQmFlVkJaYm5wV09FRnhXV2Q2TTNsak1tcDFWWFZKY205ME16TjFWSGxaTWtsRlF6WklVR1I1VG5sTVVqTk5kVnAwWjFaSk1ubEhSVU01VEU5NVNXMDJWSGxCZHlJc0ltTnNhV1Z1ZEY5cFpDSTZJbmRwY21WaGNIQTZMeTh0UVVkdE9IVTJjVkZGYldkRU16RjZPSFJUT0habklXWm1OalZqWXprME9USmpZamcyWlRaQWQybHlaUzVqYjIwaUxDSmhjR2xmZG1WeWMybHZiaUk2TlN3aWMyTnZjR1VpT2lKM2FYSmxYMk5zYVdWdWRGOXBaQ0o5LnptTlB4aTY5aHNYdDdtZzFLOTRTQ28tVmhZMUF1U0FxbUtqazZYX1FGMTM2dm9KN2FabllVUEliSExQcXlrWmNYVUlTTUpqOVZaYWVlb1NrZlJSdkR3In0",
  "signature": "Qfa3q4qAdaiEFvDWwCXIZIUw0rIXcTF6hWonPUcOwoLplUH3uokMgPqs8S51OBglmyyNNVep6dMZHxUVwml2Bw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZVQjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDQsImV4cCI6MTcwNzkyOTM2NCwibmJmIjoxNzA3OTI1NDA0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL1hBWWZPY3JBZDdCV05ZMnJGdzBYQ05YUmxjYm51ZjNZL2x6cFhsNlI5czVwN1lLQlVXOGhMT2lQckV3VjBUczRNIiwianRpIjoiODQ4Yzc1MTQtOGY3MC00NzRhLWEyZGItMTMzZGRjNDMxOGQ4Iiwibm9uY2UiOiJOVE5DY0RGS2IwdExXVUZPZFRSUVpGRmlSRGMzV1hwSE5HOHhRVXhyVlVFIiwiY2hhbCI6InVEd2VMaUh6QUI3NHNIa0U5UlFpdUhKeDJYclVtaEdBIiwiY25mIjp7ImtpZCI6IjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJkNlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EUXNJbVY0Y0NJNk1UY3dOemt6TWpZd05Dd2libUptSWpveE56QTNPVEkxTkRBMExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZtWmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5WVFWbG1UMk55UVdRM1FsZE9XVEp5Um5jd1dFTk9XRkpzWTJKdWRXWXpXUzlzZW5CWWJEWlNPWE0xY0RkWlMwSlZWemhvVEU5cFVISkZkMVl3VkhNMFRTSXNJbXAwYVNJNklqWmxNekpqTTJReUxUSmlNVEl0TkdZeFl5MDRaR05sTFdJMk1UQTFPR0V6TURVM055SXNJbTV2Ym1ObElqb2lUbFJPUTJORVJrdGlNSFJNVjFWR1QyUlVVbEZhUmtacFVrUmpNMWRZY0VoT1J6aDRVVlY0Y2xaVlJTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUwY3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSjFSSGRsVEdsSWVrRkNOelJ6U0d0Rk9WSlJhWFZJU25neVdISlZiV2hIUVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5GLTNpS3pEdEc2NThhaXBURlBaeVBZbnpWOEFxWWd6M3ljMmp1VXVJcm90MzN1VHlZMklFQzZIUGR5TnlMUjNNdVp0Z1ZJMnlHRUM5TE95SW02VHlBdyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.zmNPxi69hsXt7mg1K94SCo-VhY1AuSAqmKjk6X_QF136voJ7aZnYUPIbHLPqykZcXUISMJj9VZaeeoSkfRRvDw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "MTV2SUdpdDZrcEU5S1Uza25Ccmdja09xbHY5MzNTMGQ",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M"
  }
}
```
#### 18. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
link: <https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y>;rel="up"
location: https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M
replay-nonce: YXhRdjRNcUVkQ0IxUVZZakE5RWJYSEl2VHN5YkdZWDA
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32891/acme/wire/challenge/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y/lzpXl6R9s5p7YKBUW8hLOiPrEwV0Ts4M",
  "status": "valid",
  "token": "uDweLiHzAB74sHkE9RQiuHJx2XrUmhGA",
  "target": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 19. OAUTH authorization request

```text
code_verifier=fOtvQb_ZkK24F9FNIeyJAAR0fuv_jg8mIEcj9zd-KiQ&code_challenge=aZDR1y7XyMxQyvLDqBMQFQHUF8n2438XiRdPVWMPq18
```
#### 20. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:18585/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=1oNo4ntGyAOJIOJZhylw1A&code_challenge=aZDR1y7XyMxQyvLDqBMQFQHUF8n2438XiRdPVWMPq18&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A24844%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32891%2Facme%2Fwire%2Fchallenge%2FunFMk5gyMbhqWZbE4KgYw7vwomA3lPtS%2FTkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%227r2Oy9RBPZe7Zmndstr1bzx2QMSkKtUy.1XmccI-BrrPKX4tCQ0Nas1GIMhckkypVmR5mcITgRAI%22%7D%7D%7D&nonce=mZjNt5ygsZyBgfXCj7g27A
```

#### 21. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:18585/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=d4fb1ef4-e361-4526-872c-fbb576e5844d.6cf522f6-5d7b-4123-9530-76ba2b709d1b.9d89ab9b-e2e4-4684-bbfc-de800651596e&code_verifier=fOtvQb_ZkK24F9FNIeyJAAR0fuv_jg8mIEcj9zd-KiQ&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A24844%2Fcallback
```
#### 22. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiIxYjMyOGE0Yy00YTY4LTQ0MTgtYjljYy1kMzhiZDU4NDgzZDgiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOdDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0ODQ0Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.fG3BhAdWhOZfv-rCrco1Up8yuPy2Y4xFFLn3dyobbKoIEXveg1_7dekeZpHeBGJXQmXHWQ1j8MBkS6enOsJ6az_1Us9nVNTTEJceMElr6UodE5PI2Fu0TL-Y5qm9o80ntY6vjwVSJG4d8dpll8RtVp3X9-uucgj1bksOCqAyzcOjD_Vnp5OCmL-xXNairT1-5Cy5e8HhTJr2vY0Rb2XHKaumJvYR9OI6SHVDNec4oZebNX6yw2xMk7DGTrdrndKvzpZl9940j7NNs6NRP763N-HTHiSKtwx6gJbU3MbKgPJ5S9fBH1bFUMqL-PlpepNdm9dUCgD_7TMAtEkHh4M6Aw",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiJkZDcyMjRjNS1lYmZmLTRhN2YtOTkwZi1mYzQ5Y2YxMWU1ZDAiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXlnc1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6Ikk4RXZYbWlKTmpERWExSFhhTU44VGciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3VuRk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTL1RrQXJ3TWUzRXNWT2lPYURwQjQxY09RTEdjYnEwc0pKIiwia2V5YXV0aCI6IjdyMk95OVJCUFplN1ptbmRzdHIxYnp4MlFNU2tLdFV5LjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.psCqA_vY9GbouC1y4ykMfGGHHpuJ6gcZswOBlAUdekoGD-SRybaaCxQRjg4NmdpuIoTUN3PcJytBbyffiwYPgvl9MFTrt9wcG8OcWjzE4bedkZ5tFIiDGENkljH_QN_sjXDakuMRC9yVCFBEfGhtV1NLaGKlmzo008405sTSKOssz9kgljT19ySi4symK7yFu-LltoNjT6SToyHj0SJdVWftYZqWEQRr6yTEdfpe-m7TsZCupwlDMnzkRgXfYcDEhndaBWnEnRaxfHFSOsykUNvhtIKGtogxk-lebKm2l4xpHQcabyN10E3wLgiMfmNjCQnEcsEWu00xs287cYISjw",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjZWUzMjgwZC00NTdhLTRlZTItYjVlMS0xMWU0Y2ZiY2E3NjAifQ.eyJleHAiOjE3MDc5MzA4MDQsImlhdCI6MTcwNzkyOTAwNCwianRpIjoiYmY0OGYwNTYtNWExZS00MDg1LWFmZDAtMDhlYzIwODE2ZGM4IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE4NTg1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsInN1YiI6IjI1NzUxY2MzLTMyMzgtNDJiMC1hYTBhLTQ1Y2M5ZTQ3NmEwMiIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOdDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiI2Y2Y1MjJmNi01ZDdiLTQxMjMtOTUzMC03NmJhMmI3MDlkMWIifQ.gNgJU6gvhMgQA7uAQLOK3BtxXgu8YfssAmPZKx3XYEM",
  "scope": "openid email profile",
  "session_state": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiIxYjMyOGE0Yy00YTY4LTQ0MTgtYjljYy1kMzhiZDU4NDgzZDgiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOdDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0ODQ0Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.fG3BhAdWhOZfv-rCrco1Up8yuPy2Y4xFFLn3dyobbKoIEXveg1_7dekeZpHeBGJXQmXHWQ1j8MBkS6enOsJ6az_1Us9nVNTTEJceMElr6UodE5PI2Fu0TL-Y5qm9o80ntY6vjwVSJG4d8dpll8RtVp3X9-uucgj1bksOCqAyzcOjD_Vnp5OCmL-xXNairT1-5Cy5e8HhTJr2vY0Rb2XHKaumJvYR9OI6SHVDNec4oZebNX6yw2xMk7DGTrdrndKvzpZl9940j7NNs6NRP763N-HTHiSKtwx6gJbU3MbKgPJ5S9fBH1bFUMqL-PlpepNdm9dUCgD_7TMAtEkHh4M6Aw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2
bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5
MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJq
dGkiOiIxYjMyOGE0Yy00YTY4LTQ0MTgtYjljYy1kMzhiZDU4NDgzZDgiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZh
MDIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpO
dDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVk
N2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0ODQ0Il0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBw
cm9maWxlIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5
ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdp
cmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0
aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.fG3BhAdWhOZfv-rCrco
1Up8yuPy2Y4xFFLn3dyobbKoIEXveg1_7dekeZpHeBGJXQmXHWQ1j8MBkS6enOsJ
6az_1Us9nVNTTEJceMElr6UodE5PI2Fu0TL-Y5qm9o80ntY6vjwVSJG4d8dpll8R
tVp3X9-uucgj1bksOCqAyzcOjD_Vnp5OCmL-xXNairT1-5Cy5e8HhTJr2vY0Rb2X
HKaumJvYR9OI6SHVDNec4oZebNX6yw2xMk7DGTrdrndKvzpZl9940j7NNs6NRP76
3N-HTHiSKtwx6gJbU3MbKgPJ5S9fBH1bFUMqL-PlpepNdm9dUCgD_7TMAtEkHh4M
6Aw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "pSCde4wUC6mK7qLLbZdIU_zuZjwCEl9Hqa7dWk31Qu8",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:24844"
  ],
  "aud": "account",
  "auth_time": 1707929004,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1707929064,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1707929004,
  "iss": "http://keycloak:18585/realms/master",
  "jti": "1b328a4c-4a68-4418-b9cc-d38bd58483d8",
  "name": "Alice Smith",
  "nonce": "mZjNt5ygsZyBgfXCj7g27A",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "realm_access": {
    "roles": [
      "default-roles-master",
      "offline_access",
      "uma_authorization"
    ]
  },
  "resource_access": {
    "account": {
      "roles": [
        "manage-account",
        "manage-account-links",
        "view-profile"
      ]
    }
  },
  "scope": "openid email profile",
  "session_state": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sid": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sub": "25751cc3-3238-42b0-aa0a-45cc9e476a02",
  "typ": "Bearer"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNjF9PPiYfefRrfl7v82
Ef35W/2DRCHkEATmgynV8BX33RJ8oEofQW9Uwoi4/yxsRNWZbQ3pD0VMqdHrM/H/
oPyLehSbOHUKFYms/JBIiKQ58f62+50gPLOFUJwoRZtbhUivG0Ue91URj9onAGXU
WVjcucJR6RCgu5uTTHpCjYES/xC89ehDTKw2GmB/4/wfdCNDowHJmkeZb5X9Er+W
rmOgsJN9q/UgFt4DvCd22VF8tmCSHpZ1FqLP4DatOyZTl+wlM87Yq++KFTZi10rH
xmMJ6jvq1Unc9xEV+JgrJHsJh4dGBQkdyb/yoT5X0huVI+tMDuNrb8IgV75mfAD+
JQIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjZWUzMjgwZC00NTdhLTRlZTItYjVlMS0xMWU0Y2ZiY2E3NjAifQ.eyJleHAiOjE3MDc5MzA4MDQsImlhdCI6MTcwNzkyOTAwNCwianRpIjoiYmY0OGYwNTYtNWExZS00MDg1LWFmZDAtMDhlYzIwODE2ZGM4IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE4NTg1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsInN1YiI6IjI1NzUxY2MzLTMyMzgtNDJiMC1hYTBhLTQ1Y2M5ZTQ3NmEwMiIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOdDV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiI2Y2Y1MjJmNi01ZDdiLTQxMjMtOTUzMC03NmJhMmI3MDlkMWIifQ.gNgJU6gvhMgQA7uAQLOK3BtxXgu8YfssAmPZKx3XYEM)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjZWUzMjgwZC00
NTdhLTRlZTItYjVlMS0xMWU0Y2ZiY2E3NjAifQ.eyJleHAiOjE3MDc5MzA4MDQsI
mlhdCI6MTcwNzkyOTAwNCwianRpIjoiYmY0OGYwNTYtNWExZS00MDg1LWFmZDAtM
DhlYzIwODE2ZGM4IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE4NTg1L3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc
3RlciIsInN1YiI6IjI1NzUxY2MzLTMyMzgtNDJiMC1hYTBhLTQ1Y2M5ZTQ3NmEwM
iIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJtWmpOd
DV5Z3NaeUJnZlhDajdnMjdBIiwic2Vzc2lvbl9zdGF0ZSI6IjZjZjUyMmY2LTVkN
2ItNDEyMy05NTMwLTc2YmEyYjcwOWQxYiIsInNjb3BlIjoib3BlbmlkIGVtYWlsI
HByb2ZpbGUiLCJzaWQiOiI2Y2Y1MjJmNi01ZDdiLTQxMjMtOTUzMC03NmJhMmI3M
DlkMWIifQ.gNgJU6gvhMgQA7uAQLOK3BtxXgu8YfssAmPZKx3XYEM
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "cee3280d-457a-4ee2-b5e1-11e4cfbca760",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:18585/realms/master",
  "azp": "wireapp",
  "exp": 1707930804,
  "iat": 1707929004,
  "iss": "http://keycloak:18585/realms/master",
  "jti": "bf48f056-5a1e-4085-afd0-08ec20816dc8",
  "nonce": "mZjNt5ygsZyBgfXCj7g27A",
  "scope": "openid email profile",
  "session_state": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sid": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sub": "25751cc3-3238-42b0-aa0a-45cc9e476a02",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNjF9PPiYfefRrfl7v82
Ef35W/2DRCHkEATmgynV8BX33RJ8oEofQW9Uwoi4/yxsRNWZbQ3pD0VMqdHrM/H/
oPyLehSbOHUKFYms/JBIiKQ58f62+50gPLOFUJwoRZtbhUivG0Ue91URj9onAGXU
WVjcucJR6RCgu5uTTHpCjYES/xC89ehDTKw2GmB/4/wfdCNDowHJmkeZb5X9Er+W
rmOgsJN9q/UgFt4DvCd22VF8tmCSHpZ1FqLP4DatOyZTl+wlM87Yq++KFTZi10rH
xmMJ6jvq1Unc9xEV+JgrJHsJh4dGBQkdyb/yoT5X0huVI+tMDuNrb8IgV75mfAD+
JQIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 23. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiJkZDcyMjRjNS1lYmZmLTRhN2YtOTkwZi1mYzQ5Y2YxMWU1ZDAiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXlnc1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6Ikk4RXZYbWlKTmpERWExSFhhTU44VGciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3VuRk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTL1RrQXJ3TWUzRXNWT2lPYURwQjQxY09RTEdjYnEwc0pKIiwia2V5YXV0aCI6IjdyMk95OVJCUFplN1ptbmRzdHIxYnp4MlFNU2tLdFV5LjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.psCqA_vY9GbouC1y4ykMfGGHHpuJ6gcZswOBlAUdekoGD-SRybaaCxQRjg4NmdpuIoTUN3PcJytBbyffiwYPgvl9MFTrt9wcG8OcWjzE4bedkZ5tFIiDGENkljH_QN_sjXDakuMRC9yVCFBEfGhtV1NLaGKlmzo008405sTSKOssz9kgljT19ySi4symK7yFu-LltoNjT6SToyHj0SJdVWftYZqWEQRr6yTEdfpe-m7TsZCupwlDMnzkRgXfYcDEhndaBWnEnRaxfHFSOsykUNvhtIKGtogxk-lebKm2l4xpHQcabyN10E3wLgiMfmNjCQnEcsEWu00xs287cYISjw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2
bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5
MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJq
dGkiOiJkZDcyMjRjNS1lYmZmLTRhN2YtOTkwZi1mYzQ5Y2YxMWU1ZDAiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZh
MDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXln
c1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00
MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6Ikk4RXZYbWlKTmpERWEx
SFhhTU44VGciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1
MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBh
bGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9h
dWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3Vu
Rk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTL1RrQXJ3TWUzRXNWT2lPYURw
QjQxY09RTEdjYnEwc0pKIiwia2V5YXV0aCI6IjdyMk95OVJCUFplN1ptbmRzdHIx
Ynp4MlFNU2tLdFV5LjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1
bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNt
aXRoQHdpcmUuY29tIn0.psCqA_vY9GbouC1y4ykMfGGHHpuJ6gcZswOBlAUdekoG
D-SRybaaCxQRjg4NmdpuIoTUN3PcJytBbyffiwYPgvl9MFTrt9wcG8OcWjzE4bed
kZ5tFIiDGENkljH_QN_sjXDakuMRC9yVCFBEfGhtV1NLaGKlmzo008405sTSKOss
z9kgljT19ySi4symK7yFu-LltoNjT6SToyHj0SJdVWftYZqWEQRr6yTEdfpe-m7T
sZCupwlDMnzkRgXfYcDEhndaBWnEnRaxfHFSOsykUNvhtIKGtogxk-lebKm2l4xp
HQcabyN10E3wLgiMfmNjCQnEcsEWu00xs287cYISjw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "pSCde4wUC6mK7qLLbZdIU_zuZjwCEl9Hqa7dWk31Qu8",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ",
  "acr": "1",
  "at_hash": "I8EvXmiJNjDEa1HXaMN8Tg",
  "aud": "wireapp",
  "auth_time": 1707929004,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1707929064,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1707929004,
  "iss": "http://keycloak:18585/realms/master",
  "jti": "dd7224c5-ebff-4a7f-990f-fc49cf11e5d0",
  "keyauth": "7r2Oy9RBPZe7Zmndstr1bzx2QMSkKtUy.1XmccI-BrrPKX4tCQ0Nas1GIMhckkypVmR5mcITgRAI",
  "name": "Alice Smith",
  "nonce": "mZjNt5ygsZyBgfXCj7g27A",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "session_state": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sid": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sub": "25751cc3-3238-42b0-aa0a-45cc9e476a02",
  "typ": "ID"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNjF9PPiYfefRrfl7v82
Ef35W/2DRCHkEATmgynV8BX33RJ8oEofQW9Uwoi4/yxsRNWZbQ3pD0VMqdHrM/H/
oPyLehSbOHUKFYms/JBIiKQ58f62+50gPLOFUJwoRZtbhUivG0Ue91URj9onAGXU
WVjcucJR6RCgu5uTTHpCjYES/xC89ehDTKw2GmB/4/wfdCNDowHJmkeZb5X9Er+W
rmOgsJN9q/UgFt4DvCd22VF8tmCSHpZ1FqLP4DatOyZTl+wlM87Yq++KFTZi10rH
xmMJ6jvq1Unc9xEV+JgrJHsJh4dGBQkdyb/yoT5X0huVI+tMDuNrb8IgV75mfAD+
JQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJZWGhSZGpSTmNVVmtRMEl4VVZaWmFrRTVSV0pZU0VsMlZITjVZa2RaV0RBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS91bkZNazVneU1iaHFXWmJFNEtnWXc3dndvbUEzbFB0Uy9Ua0Fyd01lM0VzVk9pT2FEcEI0MWNPUUxHY2JxMHNKSiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSndVME5rWlRSM1ZVTTJiVXMzY1V4TVlscGtTVlZmZW5WYWFuZERSV3c1U0hGaE4yUlhhek14VVhVNEluMC5leUpsZUhBaU9qRTNNRGM1TWprd05qUXNJbWxoZENJNk1UY3dOemt5T1RBd05Dd2lZWFYwYUY5MGFXMWxJam94TnpBM09USTVNREEwTENKcWRHa2lPaUprWkRjeU1qUmpOUzFsWW1abUxUUmhOMll0T1Rrd1ppMW1ZelE1WTJZeE1XVTFaREFpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNVGcxT0RVdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSXlOVGMxTVdOak15MHpNak00TFRReVlqQXRZV0V3WVMwME5XTmpPV1UwTnpaaE1ESWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJbTFhYWs1ME5YbG5jMXA1UW1kbVdFTnFOMmN5TjBFaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaU5tTm1OVEl5WmpZdE5XUTNZaTAwTVRJekxUazFNekF0TnpaaVlUSmlOekE1WkRGaUlpd2lZWFJmYUdGemFDSTZJa2s0UlhaWWJXbEtUbXBFUldFeFNGaGhUVTQ0VkdjaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaU5tTm1OVEl5WmpZdE5XUTNZaTAwTVRJekxUazFNekF0TnpaaVlUSmlOekE1WkRGaUlpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2laMmwyWlc1ZmJtRnRaU0k2SWtGc2FXTmxJaXdpWVdOdFpWOWhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpnNU1TOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMM1Z1Umsxck5XZDVUV0pvY1ZkYVlrVTBTMmRaZHpkMmQyOXRRVE5zVUhSVEwxUnJRWEozVFdVelJYTldUMmxQWVVSd1FqUXhZMDlSVEVkalluRXdjMHBLSWl3aWEyVjVZWFYwYUNJNklqZHlNazk1T1ZKQ1VGcGxOMXB0Ym1SemRISXhZbnA0TWxGTlUydExkRlY1TGpGWWJXTmpTUzFDY25KUVMxZzBkRU5STUU1aGN6RkhTVTFvWTJ0cmVYQldiVkkxYldOSlZHZFNRVWtpTENKbVlXMXBiSGxmYm1GdFpTSTZJbE50YVhSb0lpd2laVzFoYVd3aU9pSmhiR2xqWlhOdGFYUm9RSGRwY21VdVkyOXRJbjAucHNDcUFfdlk5R2JvdUMxeTR5a01mR0dISHB1SjZnY1pzd09CbEFVZGVrb0dELVNSeWJhYUN4UVJqZzRObWRwdUlvVFVOM1BjSnl0QmJ5ZmZpd1lQZ3ZsOU1GVHJ0OXdjRzhPY1dqekU0YmVka1o1dEZJaURHRU5rbGpIX1FOX3NqWERha3VNUkM5eVZDRkJFZkdodFYxTkxhR0tsbXpvMDA4NDA1c1RTS09zc3o5a2dsalQxOXlTaTRzeW1LN3lGdS1MbHRvTmpUNlNUb3lIajBTSmRWV2Z0WVpxV0VRUnI2eVRFZGZwZS1tN1RzWkN1cHdsRE1uemtSZ1hmWWNERWhuZGFCV25FblJheGZIRlNPc3lrVU52aHRJS0d0b2d4ay1sZWJLbTJsNHhwSFFjYWJ5TjEwRTN3TGdpTWZtTmpDUW5FY3NFV3UwMHhzMjg3Y1lJU2p3In0",
  "signature": "4skjBBisb9ukniRx5zYdtjQFEC2DItEhudW6wJZ-AEl7CuH6pbyHxOzsv2nM1TYFFLnqqppzrXKihYn7ICX2Cg"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjQsImlhdCI6MTcwNzkyOTAwNCwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiJkZDcyMjRjNS1lYmZmLTRhN2YtOTkwZi1mYzQ5Y2YxMWU1ZDAiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXlnc1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6Ikk4RXZYbWlKTmpERWExSFhhTU44VGciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3VuRk1rNWd5TWJocVdaYkU0S2dZdzd2d29tQTNsUHRTL1RrQXJ3TWUzRXNWT2lPYURwQjQxY09RTEdjYnEwc0pKIiwia2V5YXV0aCI6IjdyMk95OVJCUFplN1ptbmRzdHIxYnp4MlFNU2tLdFV5LjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.psCqA_vY9GbouC1y4ykMfGGHHpuJ6gcZswOBlAUdekoGD-SRybaaCxQRjg4NmdpuIoTUN3PcJytBbyffiwYPgvl9MFTrt9wcG8OcWjzE4bedkZ5tFIiDGENkljH_QN_sjXDakuMRC9yVCFBEfGhtV1NLaGKlmzo008405sTSKOssz9kgljT19ySi4symK7yFu-LltoNjT6SToyHj0SJdVWftYZqWEQRr6yTEdfpe-m7TsZCupwlDMnzkRgXfYcDEhndaBWnEnRaxfHFSOsykUNvhtIKGtogxk-lebKm2l4xpHQcabyN10E3wLgiMfmNjCQnEcsEWu00xs287cYISjw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "YXhRdjRNcUVkQ0IxUVZZakE5RWJYSEl2VHN5YkdZWDA",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ"
  }
}
```
#### 24. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
link: <https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS>;rel="up"
location: https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ
replay-nonce: d2dQUTJ5TmFvbHhmUm9UTldxNzBxa1lyZzRQWjdrSWQ
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32891/acme/wire/challenge/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS/TkArwMe3EsVOiOaDpB41cOQLGcbq0sJJ",
  "status": "valid",
  "token": "7r2Oy9RBPZe7Zmndstr1bzx2QMSkKtUy",
  "target": "http://keycloak:18585/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 25. verify the status of the order
```http request
POST https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJkMmRRVVRKNVRtRnZiSGhtVW05VVRsZHhOekJ4YTFseVp6UlFXamRyU1dRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL29yZGVyL0xxNXpSdHhHZHo2QVM5aWNWNDFIRURUWWxDRWFkNDJ1In0",
  "payload": "",
  "signature": "vgABP-ecywNZfS1Wp4_qdPA_kxGkp6DutWiVRAZ_ub45fqYB-GtHgmWNZqBLgsCaK8klouujK4uYnOu21gXFCA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "d2dQUTJ5TmFvbHhmUm9UTldxNzBxa1lyZzRQWjdrSWQ",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u"
  }
}
```
#### 26. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
replay-nonce: a0dSU0dxRXFZRHUyS1BlenNma2hlWXB3YkgwaTlOd3A
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y",
    "https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS"
  ],
  "expires": "2024-02-15T16:43:24Z",
  "notBefore": "2024-02-14T16:43:24.631769Z",
  "notAfter": "2034-02-11T16:43:24.631769Z"
}
```
#### 27. create a CSR and call finalize url
```http request
POST https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJhMGRTVTBkeFJYRlpSSFV5UzFCbGVuTm1hMmhsV1hCM1lrZ3dhVGxPZDNBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL29yZGVyL0xxNXpSdHhHZHo2QVM5aWNWNDFIRURUWWxDRWFkNDJ1L2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBT09TUE9UMVhwNUtBbXF2TDRFTDQtdUxUaGEtenhoaVpXM1hNTDdwRzlGRG9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2TFVGSGJUaDFObkZSUlcxblJETXhlamgwVXpoMlp5Rm1aalkxWTJNNU5Ea3lZMkk0Tm1VMlFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFBV1lSdXFPazNad3d3aVVjdzlqSUlQQTN6OFVaTDl1TXNzcURxQzUtT25mbkliLUZDeVNVWHV4MGNCZkdZZHh4NDRuQTB0X01tM0hBd2t2c3V2cmZZRCJ9",
  "signature": "HSaYP0uRI8wrWODj1IkHQSs2L4lRqbdpGBNOOb2sPlHWW8-iMafFcTZ3p6EtHUDcwxF7U0WLCe5UUya0_-1JBw"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOOSPOT1Xp5KAmqvL4EL4-uLTha-zxhiZW3XML7pG9FDoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQAWYRuqOk3ZwwwiUcw9jIIPA3z8UZL9uMssqDqC5-OnfnIb-FCySUXux0cBfGYdxx44nA0t_Mm3HAwkvsuvrfYD"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "a0dSU0dxRXFZRHUyS1BlenNma2hlWXB3YkgwaTlOd3A",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOOSPOT1Xp5KAmqvL4EL4+uLTha+zxhi
ZW3XML7pG9FDoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQAW
YRuqOk3ZwwwiUcw9jIIPA3z8UZL9uMssqDqC5+OnfnIb+FCySUXux0cBfGYdxx44
nA0t/Mm3HAwkvsuvrfYD
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
                    e3:92:3c:e4:f5:5e:9e:4a:02:6a:af:2f:81:0b:e3:
                    eb:8b:4e:16:be:cf:18:62:65:6d:d7:30:be:e9:1b:
                    d1:43
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        16:61:1b:aa:3a:4d:d9:c3:0c:22:51:cc:3d:8c:82:0f:03:7c:
        fc:51:92:fd:b8:cb:2c:a8:3a:82:e7:e3:a7:7e:72:1b:f8:50:
        b2:49:45:ee:c7:47:01:7c:66:1d:c7:1e:38:9c:0d:2d:fc:c9:
        b7:1c:0c:24:be:cb:af:ad:f6:03

```

#### 28. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u
replay-nonce: blhtbm9aZ3k0NjFBYnJEdTN1d1BGRERsRm5tM2E0Qkw
```
```json
{
  "certificate": "https://stepca:32891/acme/wire/certificate/i45h6J6Tg1muxDYCZcTliGIdHzjQ3vRQ",
  "status": "valid",
  "finalize": "https://stepca:32891/acme/wire/order/Lq5zRtxGdz6AS9icV41HEDTYlCEad42u/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32891/acme/wire/authz/XAYfOcrAd7BWNY2rFw0XCNXRlcbnuf3Y",
    "https://stepca:32891/acme/wire/authz/unFMk5gyMbhqWZbE4KgYw7vwomA3lPtS"
  ],
  "expires": "2024-02-15T16:43:24Z",
  "notBefore": "2024-02-14T16:43:24.631769Z",
  "notAfter": "2034-02-11T16:43:24.631769Z"
}
```
#### 29. fetch the certificate
```http request
POST https://stepca:32891/acme/wire/certificate/i45h6J6Tg1muxDYCZcTliGIdHzjQ3vRQ
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJibGh0Ym05YVozazBOakZCWW5KRWRUTjFkMUJHUkVSc1JtNXRNMkUwUWt3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NlcnRpZmljYXRlL2k0NWg2SjZUZzFtdXhEWUNaY1RsaUdJZEh6alEzdlJRIn0",
  "payload": "",
  "signature": "1HCLEL_RpyLO0z0GlSx9voIGSUNDQaCmdbMjXFR-quK8h36uWAHb5iTFVOjbY9PWyKX0uJKmdjxGrurMSTm_Bw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "blhtbm9aZ3k0NjFBYnJEdTN1d1BGRERsRm5tM2E0Qkw",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/certificate/i45h6J6Tg1muxDYCZcTliGIdHzjQ3vRQ"
  }
}
```
#### 30. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32891/acme/wire/directory>;rel="index"
replay-nonce: MFlMa1lDYXRTZEtNSTlTS3lRNGdFcGt2UWlTY0g1YzU
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAcCgAwIBAgIRAPPJLWt2K/8ZwNOoTR14m4IwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMjE0MTY0MzI0WhcNMzQwMjExMTY0MzI0WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDjkjzk9V6eSgJqry+B\nC+Pri04Wvs8YYmVt1zC+6RvRQ6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFEaPewHEHyJxHbafLfMMVxy8D2RfMB8G\nA1UdIwQYMBaAFK71u5zGiREQFiKMSmdlLblCLIXiMGkGA1UdEQRiMGCGIHdpcmVh\ncHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vLUFHbTh1NnFR\nRW1nRDMxejh0Uzh2ZyUyMWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQDpEse7\nv4afo/2rCdUdxG0MHDbpJ1dYekMQkYpHJWWKogIgdhFwiMggZ8TIirTgNDYzpaKc\n/QUtksBwYbsIvZtaimM=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAMozgWjsOcvz/3Zobz72C9wwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIxNDE2\nNDMyM1oXDTM0MDIxMTE2NDMyM1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARK\nHjjiLNTcPFVzUfgE/uVp4l9Za9kpP8JdPBtb70CaCBiZQv1W2wt6bW5IQDcdst/k\nezOTP67MzRy1Zq4+cHI5o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUrvW7nMaJERAWIoxKZ2UtuUIsheIwHwYDVR0jBBgw\nFoAUMSVwCNppa2aUboIq7dM33lempbYwCgYIKoZIzj0EAwIDSAAwRQIgCGGTq3Xn\nZKEEoqrtmwarWIb0+jaFD2Dv9Ug/BadXNRkCIQDcRnknaaGIzWA1gxrsT033SUCB\n76FrXLeIzYFbb1/ZWw==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRAPPJLWt2K/8ZwNOoTR14m4IwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMjE0MTY0MzI0WhcNMzQwMjExMTY0MzI0WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDjkjzk9V6eSgJqry+B
C+Pri04Wvs8YYmVt1zC+6RvRQ6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFEaPewHEHyJxHbafLfMMVxy8D2RfMB8G
A1UdIwQYMBaAFK71u5zGiREQFiKMSmdlLblCLIXiMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vLUFHbTh1NnFR
RW1nRDMxejh0Uzh2ZyUyMWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQDpEse7
v4afo/2rCdUdxG0MHDbpJ1dYekMQkYpHJWWKogIgdhFwiMggZ8TIirTgNDYzpaKc
/QUtksBwYbsIvZtaimM=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f3:c9:2d:6b:76:2b:ff:19:c0:d3:a8:4d:1d:78:9b:82
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Feb 14 16:43:24 2024 GMT
            Not After : Feb 11 16:43:24 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    e3:92:3c:e4:f5:5e:9e:4a:02:6a:af:2f:81:0b:e3:
                    eb:8b:4e:16:be:cf:18:62:65:6d:d7:30:be:e9:1b:
                    d1:43
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                46:8F:7B:01:C4:1F:22:71:1D:B6:9F:2D:F3:0C:57:1C:BC:0F:64:5F
            X509v3 Authority Key Identifier: 
                AE:F5:BB:9C:C6:89:11:10:16:22:8C:4A:67:65:2D:B9:42:2C:85:E2
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://-AGm8u6qQEmgD31z8tS8vg%21ff65cc9492cb86e6@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:e9:12:c7:bb:bf:86:9f:a3:fd:ab:09:d5:1d:
        c4:6d:0c:1c:36:e9:27:57:58:7a:43:10:91:8a:47:25:65:8a:
        a2:02:20:76:11:70:88:c8:20:67:c4:c8:8a:b4:e0:34:36:33:
        a5:a2:9c:fd:05:2d:92:c0:70:61:bb:08:bd:9b:5a:8a:63

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAMozgWjsOcvz/3Zobz72C9wwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIxNDE2
NDMyM1oXDTM0MDIxMTE2NDMyM1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARK
HjjiLNTcPFVzUfgE/uVp4l9Za9kpP8JdPBtb70CaCBiZQv1W2wt6bW5IQDcdst/k
ezOTP67MzRy1Zq4+cHI5o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUrvW7nMaJERAWIoxKZ2UtuUIsheIwHwYDVR0jBBgw
FoAUMSVwCNppa2aUboIq7dM33lempbYwCgYIKoZIzj0EAwIDSAAwRQIgCGGTq3Xn
ZKEEoqrtmwarWIb0+jaFD2Dv9Ug/BadXNRkCIQDcRnknaaGIzWA1gxrsT033SUCB
76FrXLeIzYFbb1/ZWw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ca:33:81:68:ec:39:cb:f3:ff:76:68:6f:3e:f6:0b:dc
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Feb 14 16:43:23 2024 GMT
            Not After : Feb 11 16:43:23 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:4a:1e:38:e2:2c:d4:dc:3c:55:73:51:f8:04:fe:
                    e5:69:e2:5f:59:6b:d9:29:3f:c2:5d:3c:1b:5b:ef:
                    40:9a:08:18:99:42:fd:56:db:0b:7a:6d:6e:48:40:
                    37:1d:b2:df:e4:7b:33:93:3f:ae:cc:cd:1c:b5:66:
                    ae:3e:70:72:39
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                AE:F5:BB:9C:C6:89:11:10:16:22:8C:4A:67:65:2D:B9:42:2C:85:E2
            X509v3 Authority Key Identifier: 
                31:25:70:08:DA:69:6B:66:94:6E:82:2A:ED:D3:37:DE:57:A6:A5:B6
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:08:61:93:ab:75:e7:64:a1:04:a2:aa:ed:9b:06:
        ab:58:86:f4:fa:36:85:0f:60:ef:f5:48:3f:05:a7:57:35:19:
        02:21:00:dc:46:79:27:69:a1:88:cd:60:35:83:1a:ec:4f:4d:
        f7:49:40:81:ef:a1:6b:5c:b7:88:cd:81:5b:6f:5f:d9:5b

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIRAJ7hMABiG5+3cynJvQ/+qpkwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIxNDE2
NDMyMloXDTM0MDIxMTE2NDMyMlowJjENMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMM
d2lyZSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjQwCn9y0Yzvd
GSq6JuW3HZqcGlH/6adAeMDj9/jt9zYADoy1zbX51i/PgqbzeqvIpGafkITmLfvF
4rSxWln6jaNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEw
HQYDVR0OBBYEFDElcAjaaWtmlG6CKu3TN95XpqW2MAoGCCqGSM49BAMCA0gAMEUC
IQD6nqKS3dXConqJUHRQFjZLYBMPC71CDd+EuGi2gEsyJAIgK/RkD6O+PatAyamY
BVAhtx004tYoC93p5wEIVECcVck=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9e:e1:30:00:62:1b:9f:b7:73:29:c9:bd:0f:fe:aa:99
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Feb 14 16:43:22 2024 GMT
            Not After : Feb 11 16:43:22 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:8d:0c:02:9f:dc:b4:63:3b:dd:19:2a:ba:26:e5:
                    b7:1d:9a:9c:1a:51:ff:e9:a7:40:78:c0:e3:f7:f8:
                    ed:f7:36:00:0e:8c:b5:cd:b5:f9:d6:2f:cf:82:a6:
                    f3:7a:ab:c8:a4:66:9f:90:84:e6:2d:fb:c5:e2:b4:
                    b1:5a:59:fa:8d
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                31:25:70:08:DA:69:6B:66:94:6E:82:2A:ED:D3:37:DE:57:A6:A5:B6
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:fa:9e:a2:92:dd:d5:c2:a2:7a:89:50:74:50:
        16:36:4b:60:13:0f:0b:bd:42:0d:df:84:b8:68:b6:80:4b:32:
        24:02:20:2b:f4:64:0f:a3:be:3d:ab:40:c9:a9:98:05:50:21:
        b7:1d:34:e2:d6:28:0b:dd:e9:e7:01:08:54:40:9c:55:c9

```

openssl verify chain ✅
### Initial setup with ACME server
#### 31. fetch acme directory for hyperlinks
```http request
GET https://stepca:32891/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 32. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32891/acme/wire/new-nonce",
  "newAccount": "https://stepca:32891/acme/wire/new-account",
  "newOrder": "https://stepca:32891/acme/wire/new-order",
  "revokeCert": "https://stepca:32891/acme/wire/revoke-cert"
}
```
#### 33. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32891/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 34. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32891/acme/wire/directory>;rel="index"
replay-nonce: RHNtUmdrSzRaanpDVEZ1Vk9nR2FoQjZFY3pNUEZMdXg
```
```text
RHNtUmdrSzRaanpDVEZ1Vk9nR2FoQjZFY3pNUEZMdXg
```
#### 35. create a new account
```http request
POST https://stepca:32891/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjAwejNJM3ctUVBXbUF4QzdEaHR4aVFXdElpeWR2a1Nnekd2dlNtdmN3VnMifSwibm9uY2UiOiJSSE50VW1kclN6UmFhbnBEVkVaMVZrOW5SMkZvUWpaRlkzcE5VRVpNZFhnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "6_uT2iNULIyeBMwA1o_sbEmuN8R2ZKkGYSCQp_0uNigJb8qS_V9gIGpmk5beyq4CSdtkOdevHV7AuUSUuZrECQ"
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
      "x": "00z3I3w-QPWmAxC7DhtxiQWtIiydvkSgzGvvSmvcwVs"
    },
    "nonce": "RHNtUmdrSzRaanpDVEZ1Vk9nR2FoQjZFY3pNUEZMdXg",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/new-account"
  }
}
```
#### 36. account created
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR
replay-nonce: WVgwVEJTeGg2VXlCNVNnSzJiWVBZOTMzUVZvNXNNaWM
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR/orders"
}
```
### Request a certificate with relevant identifiers
#### 37. create a new order
```http request
POST https://stepca:32891/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJXVmd3VkVKVGVHZzJWWGxDTlZOblN6SmlXVkJaT1RNelVWWnZOWE5OYVdNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMi0xNFQxNjo0MzoyNS4wNDE3MTFaIiwibm90QWZ0ZXIiOiIyMDM0LTAyLTExVDE2OjQzOjI1LjA0MTcxMVoifQ",
  "signature": "qQYOH--FXlSuNKbC7Ipi5R66mJpzg4l77H7YQ71NlmHdN8t7y8uyvr2exCIFNorZv_BJHEiDQE10IkgLj_t0Dg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2034-02-11T16:43:25.041711Z",
    "notBefore": "2024-02-14T16:43:25.041711Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "WVgwVEJTeGg2VXlCNVNnSzJiWVBZOTMzUVZvNXNNaWM",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/new-order"
  }
}
```
#### 38. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3
replay-nonce: Zm5pOTRDakVJdUlHTEJ0djY5anlUbUR6aUVmZTgzdEk
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32891/acme/wire/authz/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG",
    "https://stepca:32891/acme/wire/authz/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco"
  ],
  "expires": "2024-02-15T16:43:25Z",
  "notBefore": "2024-02-14T16:43:25.041711Z",
  "notAfter": "2034-02-11T16:43:25.041711Z"
}
```
### Display-name and handle already authorized
#### 39. create authorization and fetch challenges
```http request
POST https://stepca:32891/acme/wire/authz/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJabTVwT1RSRGFrVkpkVWxIVEVKMGRqWTVhbmxVYlVSNmFVVm1aVGd6ZEVrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2F1dGh6LzZMVUNTeDE3TmY2M2JiamplU2U3YWZsNEJnSktXVFpHIn0",
  "payload": "",
  "signature": "kgcEM9-dZIivuyGLyPRaIT2oTK6zdjBaPZRBQGZ95c9KMixo1sRrleAgf-m7tQOZff8P0rQBLOBIh1OgyDD0Bg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "Zm5pOTRDakVJdUlHTEJ0djY5anlUbUR6aUVmZTgzdEk",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/authz/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG"
  }
}
```
#### 40. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/authz/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG
replay-nonce: eVVESHlWSE11OUg2MWtiYWVoZzV3V0NQMXBTbmM5dVM
```
```json
{
  "status": "pending",
  "expires": "2024-02-15T16:43:25Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32891/acme/wire/challenge/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG/19iRSA0lNPoQip2wmXqPuNjlt1RwrYd2",
      "status": "pending",
      "token": "XVMmmfdkLeRzSWljjFf8yZagJMbMFvP1",
      "target": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:32891/acme/wire/authz/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJlVlZFU0hsV1NFMTFPVWcyTVd0aVlXVm9aelYzVjBOUU1YQlRibU01ZFZNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2F1dGh6L2cxWmlzT1BybEY5VlF5akxEa0VCMVRSTUVmWU5RWmNvIn0",
  "payload": "",
  "signature": "C-s7qwaEe1MA-Is7XeOTz62xzhMJZEuPWvL2WtZVK2Yd0CjnV_Je3j7yJe69laEoWjIAcEdrcfoHlhO19dphBQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "eVVESHlWSE11OUg2MWtiYWVoZzV3V0NQMXBTbmM5dVM",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/authz/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco"
  }
}
```
#### 41. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/authz/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco
replay-nonce: bkw3N3ZPRnBpdE52RUREOXFNaXdEOTBlUndpU1cwMnU
```
```json
{
  "status": "pending",
  "expires": "2024-02-15T16:43:25Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32891/acme/wire/challenge/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco/N3OvFgrDNAom0pWjrPi0hp0vzfPWitoB",
      "status": "pending",
      "token": "1tWEB5BJXLVQbxAJDH5kx3kxGrsyuaEP",
      "target": "http://keycloak:18585/realms/master"
    }
  ],
  "identifier": {
    "type": "wireapp-user",
    "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 42. fetch a nonce from wire-server
```http request
GET http://wire.com:24844/clients/token/nonce
```
#### 43. get wire-server nonce
```http request
200

```
```text
cEtBYjUzYzdLOFlTSlc5c3luUTV5aGFLa1dwTU05N00
```
#### 44. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMDB6M0kzdy1RUFdtQXhDN0RodHhpUVd0SWl5ZHZrU2d6R3Z2U212Y3dWcyJ9fQ.eyJpYXQiOjE3MDc5MjU0MDUsImV4cCI6MTcwNzkzMjYwNSwibmJmIjoxNzA3OTI1NDA1LCJzdWIiOiJ3aXJlYXBwOi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS82TFVDU3gxN05mNjNiYmpqZVNlN2FmbDRCZ0pLV1RaRy8xOWlSU0EwbE5Qb1FpcDJ3bVhxUHVOamx0MVJ3cllkMiIsImp0aSI6ImI1ZDk5MjkzLWQ5MWItNDc0Yi1hZjIzLTAyMjA5YWIxM2QzNyIsIm5vbmNlIjoiY0V0QllqVXpZemRMT0ZsVFNsYzVjM2x1VVRWNWFHRkxhMWR3VFUwNU4wMCIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJYVk1tbWZka0xlUnpTV2xqakZmOHlaYWdKTWJNRnZQMSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.76l3uuK-4t0StYPS78BuitxhV8BtzNYMlGQ5qTRNbZKIuk0Vd4eSXDHk49DDNyOvUSsbdIf-Rcx26vo03NsFAQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMDB6M0kzdy1RUFdtQXhDN0RodHhpUVd0
SWl5ZHZrU2d6R3Z2U212Y3dWcyJ9fQ.eyJpYXQiOjE3MDc5MjU0MDUsImV4cCI6M
TcwNzkzMjYwNSwibmJmIjoxNzA3OTI1NDA1LCJzdWIiOiJ3aXJlYXBwOi8vLUFHb
Th1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS82T
FVDU3gxN05mNjNiYmpqZVNlN2FmbDRCZ0pLV1RaRy8xOWlSU0EwbE5Qb1FpcDJ3b
VhxUHVOamx0MVJ3cllkMiIsImp0aSI6ImI1ZDk5MjkzLWQ5MWItNDc0Yi1hZjIzL
TAyMjA5YWIxM2QzNyIsIm5vbmNlIjoiY0V0QllqVXpZemRMT0ZsVFNsYzVjM2x1V
VRWNWFHRkxhMWR3VFUwNU4wMCIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b
2tlbiIsImNoYWwiOiJYVk1tbWZka0xlUnpTV2xqakZmOHlaYWdKTWJNRnZQMSIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUifQ.76l3uuK-4t0StYPS78BuitxhV8BtzNYMlGQ5qTRNbZKIuk0Vd4
eSXDHk49DDNyOvUSsbdIf-Rcx26vo03NsFAQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "00z3I3w-QPWmAxC7DhtxiQWtIiydvkSgzGvvSmvcwVs"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32891/acme/wire/challenge/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG/19iRSA0lNPoQip2wmXqPuNjlt1RwrYd2",
  "chal": "XVMmmfdkLeRzSWljjFf8yZagJMbMFvP1",
  "exp": 1707932605,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token",
  "iat": 1707925405,
  "jti": "b5d99293-d91b-474b-af23-02209ab13d37",
  "nbf": 1707925405,
  "nonce": "cEtBYjUzYzdLOFlTSlc5c3luUTV5aGFLa1dwTU05N00",
  "sub": "wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICXKf2Zu5a1F0NfMYenEYp/FuOudMii72btMXUQ4D3qj
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA00z3I3w+QPWmAxC7DhtxiQWtIiydvkSgzGvvSmvcwVs=
-----END PUBLIC KEY-----
```

</details>


#### 45. trade client DPoP token for an access token
```http request
POST http://wire.com:24844/clients/ff65cc9492cb86e6/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTURCNk0wa3pkeTFSVUZkdFFYaEROMFJvZEhocFVWZDBTV2w1WkhaclUyZDZSM1oyVTIxMlkzZFdjeUo5ZlEuZXlKcFlYUWlPakUzTURjNU1qVTBNRFVzSW1WNGNDSTZNVGN3Tnprek1qWXdOU3dpYm1KbUlqb3hOekEzT1RJMU5EQTFMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZMVUZIYlRoMU5uRlJSVzFuUkRNeGVqaDBVemgyWnlGbVpqWTFZMk01TkRreVkySTRObVUyUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekk0T1RFdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTODJURlZEVTNneE4wNW1Oak5pWW1wcVpWTmxOMkZtYkRSQ1owcExWMVJhUnk4eE9XbFNVMEV3YkU1UWIxRnBjREozYlZoeFVIVk9hbXgwTVZKM2NsbGtNaUlzSW1wMGFTSTZJbUkxWkRrNU1qa3pMV1E1TVdJdE5EYzBZaTFoWmpJekxUQXlNakE1WVdJeE0yUXpOeUlzSW01dmJtTmxJam9pWTBWMFFsbHFWWHBaZW1STVQwWnNWRk5zWXpWak0yeDFWVlJXTldGSFJreGhNV1IzVkZVd05VNHdNQ0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRNE5EUXZZMnhwWlc1MGN5OW1aalkxWTJNNU5Ea3lZMkk0Tm1VMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUpZVmsxdGJXWmthMHhsVW5wVFYyeHFha1ptT0hsYVlXZEtUV0pOUm5aUU1TSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpZlEuNzZsM3V1Sy00dDBTdFlQUzc4QnVpdHhoVjhCdHpOWU1sR1E1cVRSTmJaS0l1azBWZDRlU1hESGs0OURETnlPdlVTc2JkSWYtUmN4MjZ2bzAzTnNGQVE
```
#### 46. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZVQjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDUsImV4cCI6MTcwNzkyOTM2NSwibmJmIjoxNzA3OTI1NDA1LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlLzZMVUNTeDE3TmY2M2JiamplU2U3YWZsNEJnSktXVFpHLzE5aVJTQTBsTlBvUWlwMndtWHFQdU5qbHQxUndyWWQyIiwianRpIjoiNmEzZGM1OTItMmI1MS00Yjk3LThhYmYtZDhkYzA3Y2FhNTFhIiwibm9uY2UiOiJjRXRCWWpVell6ZExPRmxUU2xjNWMzbHVVVFY1YUdGTGExZHdUVTA1TjAwIiwiY2hhbCI6IlhWTW1tZmRrTGVSelNXbGpqRmY4eVphZ0pNYk1GdlAxIiwiY25mIjp7ImtpZCI6IjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJkNlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EVXNJbVY0Y0NJNk1UY3dOemt6TWpZd05Td2libUptSWpveE56QTNPVEkxTkRBMUxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZtWmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM4MlRGVkRVM2d4TjA1bU5qTmlZbXBxWlZObE4yRm1iRFJDWjBwTFYxUmFSeTh4T1dsU1UwRXdiRTVRYjFGcGNESjNiVmh4VUhWT2FteDBNVkozY2xsa01pSXNJbXAwYVNJNkltSTFaRGs1TWprekxXUTVNV0l0TkRjMFlpMWhaakl6TFRBeU1qQTVZV0l4TTJRek55SXNJbTV2Ym1ObElqb2lZMFYwUWxscVZYcFplbVJNVDBac1ZGTnNZelZqTTJ4MVZWUldOV0ZIUmt4aE1XUjNWRlV3TlU0d01DSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUwY3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSllWazF0Yldaa2EweGxVbnBUVjJ4cWFrWm1PSGxhWVdkS1RXSk5SblpRTVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS43NmwzdXVLLTR0MFN0WVBTNzhCdWl0eGhWOEJ0ek5ZTWxHUTVxVFJOYlpLSXVrMFZkNGVTWERIazQ5REROeU92VVNzYmRJZi1SY3gyNnZvMDNOc0ZBUSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.AnDqo8fka8FVzbMGX1X6bzoy1ovIVkhj3-5AtElwrEOyAk8bdYBbJeKODsDMQpPmZ-dSxLotYEUudghffzT-AQ",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZVQjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDUsImV4cCI6MTcwNzkyOTM2NSwibmJmIjoxNzA3OTI1NDA1LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlLzZMVUNTeDE3TmY2M2JiamplU2U3YWZsNEJnSktXVFpHLzE5aVJTQTBsTlBvUWlwMndtWHFQdU5qbHQxUndyWWQyIiwianRpIjoiNmEzZGM1OTItMmI1MS00Yjk3LThhYmYtZDhkYzA3Y2FhNTFhIiwibm9uY2UiOiJjRXRCWWpVell6ZExPRmxUU2xjNWMzbHVVVFY1YUdGTGExZHdUVTA1TjAwIiwiY2hhbCI6IlhWTW1tZmRrTGVSelNXbGpqRmY4eVphZ0pNYk1GdlAxIiwiY25mIjp7ImtpZCI6IjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJkNlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EVXNJbVY0Y0NJNk1UY3dOemt6TWpZd05Td2libUptSWpveE56QTNPVEkxTkRBMUxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZtWmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM4MlRGVkRVM2d4TjA1bU5qTmlZbXBxWlZObE4yRm1iRFJDWjBwTFYxUmFSeTh4T1dsU1UwRXdiRTVRYjFGcGNESjNiVmh4VUhWT2FteDBNVkozY2xsa01pSXNJbXAwYVNJNkltSTFaRGs1TWprekxXUTVNV0l0TkRjMFlpMWhaakl6TFRBeU1qQTVZV0l4TTJRek55SXNJbTV2Ym1ObElqb2lZMFYwUWxscVZYcFplbVJNVDBac1ZGTnNZelZqTTJ4MVZWUldOV0ZIUmt4aE1XUjNWRlV3TlU0d01DSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUwY3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSllWazF0Yldaa2EweGxVbnBUVjJ4cWFrWm1PSGxhWVdkS1RXSk5SblpRTVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS43NmwzdXVLLTR0MFN0WVBTNzhCdWl0eGhWOEJ0ek5ZTWxHUTVxVFJOYlpLSXVrMFZkNGVTWERIazQ5REROeU92VVNzYmRJZi1SY3gyNnZvMDNOc0ZBUSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.AnDqo8fka8FVzbMGX1X6bzoy1ovIVkhj3-5AtElwrEOyAk8bdYBbJeKODsDMQpPmZ-dSxLotYEUudghffzT-AQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZV
QjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDUsImV4cCI6MTcw
NzkyOTM2NSwibmJmIjoxNzA3OTI1NDA1LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJj
Yjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21l
L3dpcmUvY2hhbGxlbmdlLzZMVUNTeDE3TmY2M2JiamplU2U3YWZsNEJnSktXVFpH
LzE5aVJTQTBsTlBvUWlwMndtWHFQdU5qbHQxUndyWWQyIiwianRpIjoiNmEzZGM1
OTItMmI1MS00Yjk3LThhYmYtZDhkYzA3Y2FhNTFhIiwibm9uY2UiOiJjRXRCWWpV
ell6ZExPRmxUU2xjNWMzbHVVVFY1YUdGTGExZHdUVTA1TjAwIiwiY2hhbCI6IlhW
TW1tZmRrTGVSelNXbGpqRmY4eVphZ0pNYk1GdlAxIiwiY25mIjp7ImtpZCI6IjFY
bWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJk
NlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EVXNJbVY0
Y0NJNk1UY3dOemt6TWpZd05Td2libUptSWpveE56QTNPVEkxTkRBMUxDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZt
WmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM4MlRGVkRVM2d4TjA1bU5qTmlZbXBxWlZObE4yRm1iRFJDWjBwTFYxUmFSeTh4
T1dsU1UwRXdiRTVRYjFGcGNESjNiVmh4VUhWT2FteDBNVkozY2xsa01pSXNJbXAw
YVNJNkltSTFaRGs1TWprekxXUTVNV0l0TkRjMFlpMWhaakl6TFRBeU1qQTVZV0l4
TTJRek55SXNJbTV2Ym1ObElqb2lZMFYwUWxscVZYcFplbVJNVDBac1ZGTnNZelZq
TTJ4MVZWUldOV0ZIUmt4aE1XUjNWRlV3TlU0d01DSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUw
Y3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSllWazF0Yldaa2EweGxVbnBUVjJ4cWFrWm1PSGxhWVdkS1RXSk5SblpR
TVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS43NmwzdXVLLTR0MFN0
WVBTNzhCdWl0eGhWOEJ0ek5ZTWxHUTVxVFJOYlpLSXVrMFZkNGVTWERIazQ5RERO
eU92VVNzYmRJZi1SY3gyNnZvMDNOc0ZBUSIsImNsaWVudF9pZCI6IndpcmVhcHA6
Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5j
b20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.AnD
qo8fka8FVzbMGX1X6bzoy1ovIVkhj3-5AtElwrEOyAk8bdYBbJeKODsDMQpPmZ-d
SxLotYEUudghffzT-AQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "p297i1tJkAdaOLMnpxugMQoAFUB9HTM0CvdjGjlJYzY"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32891/acme/wire/challenge/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG/19iRSA0lNPoQip2wmXqPuNjlt1RwrYd2",
  "chal": "XVMmmfdkLeRzSWljjFf8yZagJMbMFvP1",
  "client_id": "wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com",
  "cnf": {
    "kid": "1XmccI-BrrPKX4tCQ0Nas1GIMhckkypVmR5mcITgRAI"
  },
  "exp": 1707929365,
  "iat": 1707925405,
  "iss": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token",
  "jti": "6a3dc592-2b51-4b97-8abf-d8dc07caa51a",
  "nbf": 1707925405,
  "nonce": "cEtBYjUzYzdLOFlTSlc5c3luUTV5aGFLa1dwTU05N00",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMDB6M0kzdy1RUFdtQXhDN0RodHhpUVd0SWl5ZHZrU2d6R3Z2U212Y3dWcyJ9fQ.eyJpYXQiOjE3MDc5MjU0MDUsImV4cCI6MTcwNzkzMjYwNSwibmJmIjoxNzA3OTI1NDA1LCJzdWIiOiJ3aXJlYXBwOi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS82TFVDU3gxN05mNjNiYmpqZVNlN2FmbDRCZ0pLV1RaRy8xOWlSU0EwbE5Qb1FpcDJ3bVhxUHVOamx0MVJ3cllkMiIsImp0aSI6ImI1ZDk5MjkzLWQ5MWItNDc0Yi1hZjIzLTAyMjA5YWIxM2QzNyIsIm5vbmNlIjoiY0V0QllqVXpZemRMT0ZsVFNsYzVjM2x1VVRWNWFHRkxhMWR3VFUwNU4wMCIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJYVk1tbWZka0xlUnpTV2xqakZmOHlaYWdKTWJNRnZQMSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.76l3uuK-4t0StYPS78BuitxhV8BtzNYMlGQ5qTRNbZKIuk0Vd4eSXDHk49DDNyOvUSsbdIf-Rcx26vo03NsFAQ",
  "scope": "wire_client_id",
  "sub": "wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJatwIEJkQb2JTfifGXoh49zXUOBSvkByqeHY4XBJQf1
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAp297i1tJkAdaOLMnpxugMQoAFUB9HTM0CvdjGjlJYzY=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 47. validate Dpop challenge (clientId)
```http request
POST https://stepca:32891/acme/wire/challenge/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG/19iRSA0lNPoQip2wmXqPuNjlt1RwrYd2
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJia3czTjNaUFJuQnBkRTUyUlVSRU9YRk5hWGRFT1RCbFVuZHBVMWN3TW5VIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS82TFVDU3gxN05mNjNiYmpqZVNlN2FmbDRCZ0pLV1RaRy8xOWlSU0EwbE5Qb1FpcDJ3bVhxUHVOamx0MVJ3cllkMiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluQXlPVGRwTVhSS2EwRmtZVTlNVFc1d2VIVm5UVkZ2UVVaVlFqbElWRTB3UTNaa2FrZHFiRXBaZWxraWZYMC5leUpwWVhRaU9qRTNNRGM1TWpVME1EVXNJbVY0Y0NJNk1UY3dOemt5T1RNMk5Td2libUptSWpveE56QTNPVEkxTkRBMUxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRNE5EUXZZMnhwWlc1MGN5OW1aalkxWTJNNU5Ea3lZMkk0Tm1VMkwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTh0UVVkdE9IVTJjVkZGYldkRU16RjZPSFJUT0habklXWm1OalZqWXprME9USmpZamcyWlRaQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpnNU1TOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMelpNVlVOVGVERTNUbVkyTTJKaWFtcGxVMlUzWVdac05FSm5Ta3RYVkZwSEx6RTVhVkpUUVRCc1RsQnZVV2x3TW5kdFdIRlFkVTVxYkhReFVuZHlXV1F5SWl3aWFuUnBJam9pTm1FelpHTTFPVEl0TW1JMU1TMDBZamszTFRoaFltWXRaRGhrWXpBM1kyRmhOVEZoSWl3aWJtOXVZMlVpT2lKalJYUkNXV3BWZWxsNlpFeFBSbXhVVTJ4ak5XTXpiSFZWVkZZMVlVZEdUR0V4WkhkVVZUQTFUakF3SWl3aVkyaGhiQ0k2SWxoV1RXMXRabVJyVEdWU2VsTlhiR3BxUm1ZNGVWcGhaMHBOWWsxR2RsQXhJaXdpWTI1bUlqcDdJbXRwWkNJNklqRlliV05qU1MxQ2NuSlFTMWcwZEVOUk1FNWhjekZIU1Uxb1kydHJlWEJXYlZJMWJXTkpWR2RTUVVraWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsTlJFSTJUVEJyZW1SNU1WSlZSbVIwVVZob1JFNHdVbTlrU0dod1ZWWmtNRk5YYkRWYVNGcHlWVEprTmxJeldqSlZNakV5V1ROa1YyTjVTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5SR00xVFdwVk1FMUVWWE5KYlZZMFkwTkpOazFVWTNkT2VtdDZUV3BaZDA1VGQybGliVXB0U1dwdmVFNTZRVE5QVkVreFRrUkJNVXhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRreFZSa2hpVkdneFRtNUdVbEpYTVc1U1JFMTRaV3BvTUZWNmFESmFlVVp0V21wWk1Wa3lUVFZPUkd0NVdUSkpORTV0VlRKUlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUUlBWRVYyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE00TWxSR1ZrUlZNMmQ0VGpBMWJVNXFUbWxaYlhCeFdsWk9iRTR5Um0xaVJGSkRXakJ3VEZZeFVtRlNlVGg0VDFkc1UxVXdSWGRpUlRWUllqRkdjR05FU2pOaVZtaDRWVWhXVDJGdGVEQk5Wa296WTJ4c2EwMXBTWE5KYlhBd1lWTkpOa2x0U1RGYVJHczFUV3ByZWt4WFVUVk5WMGwwVGtSak1GbHBNV2hhYWtsNlRGUkJlVTFxUVRWWlYwbDRUVEpSZWs1NVNYTkpiVFYyWW0xT2JFbHFiMmxaTUZZd1VXeHNjVlpZY0ZwbGJWSk5WREJhYzFaR1RuTlplbFpxVFRKNE1WWldVbGRPVjBaSVVtdDRhRTFYVWpOV1JsVjNUbFUwZDAxRFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxFMFRrUlJkbGt5ZUhCYVZ6VXdZM2s1YlZwcVdURlpNazAxVGtScmVWa3lTVFJPYlZVeVRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTbGxXYXpGMFlsZGFhMkV3ZUd4VmJuQlVWako0Y1dGcldtMVBTR3hoV1Zka1MxUlhTazVTYmxwUlRWTkpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsbVVTNDNObXd6ZFhWTExUUjBNRk4wV1ZCVE56aENkV2wwZUdoV09FSjBlazVaVFd4SFVUVnhWRkpPWWxwTFNYVnJNRlprTkdWVFdFUklhelE1UkVST2VVOTJWVk56WW1SSlppMVNZM2d5Tm5adk1ETk9jMFpCVVNJc0ltTnNhV1Z1ZEY5cFpDSTZJbmRwY21WaGNIQTZMeTh0UVVkdE9IVTJjVkZGYldkRU16RjZPSFJUT0habklXWm1OalZqWXprME9USmpZamcyWlRaQWQybHlaUzVqYjIwaUxDSmhjR2xmZG1WeWMybHZiaUk2TlN3aWMyTnZjR1VpT2lKM2FYSmxYMk5zYVdWdWRGOXBaQ0o5LkFuRHFvOGZrYThGVnpiTUdYMVg2YnpveTFvdklWa2hqMy01QXRFbHdyRU95QWs4YmRZQmJKZUtPRHNETVFwUG1aLWRTeExvdFlFVXVkZ2hmZnpULUFRIn0",
  "signature": "xqrw1tGnamG_HpeNVEh9pAYayYn1otguhvvHNqpopetq2c86O6VmkiBQNlRg9SYw0g3unBwAilrVfdIJOXWGAg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InAyOTdpMXRKa0FkYU9MTW5weHVnTVFvQUZVQjlIVE0wQ3ZkakdqbEpZelkifX0.eyJpYXQiOjE3MDc5MjU0MDUsImV4cCI6MTcwNzkyOTM2NSwibmJmIjoxNzA3OTI1NDA1LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ4NDQvY2xpZW50cy9mZjY1Y2M5NDkyY2I4NmU2L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlLzZMVUNTeDE3TmY2M2JiamplU2U3YWZsNEJnSktXVFpHLzE5aVJTQTBsTlBvUWlwMndtWHFQdU5qbHQxUndyWWQyIiwianRpIjoiNmEzZGM1OTItMmI1MS00Yjk3LThhYmYtZDhkYzA3Y2FhNTFhIiwibm9uY2UiOiJjRXRCWWpVell6ZExPRmxUU2xjNWMzbHVVVFY1YUdGTGExZHdUVTA1TjAwIiwiY2hhbCI6IlhWTW1tZmRrTGVSelNXbGpqRmY4eVphZ0pNYk1GdlAxIiwiY25mIjp7ImtpZCI6IjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lNREI2TTBremR5MVJVRmR0UVhoRE4wUm9kSGhwVVZkMFNXbDVaSFpyVTJkNlIzWjJVMjEyWTNkV2N5SjlmUS5leUpwWVhRaU9qRTNNRGM1TWpVME1EVXNJbVY0Y0NJNk1UY3dOemt6TWpZd05Td2libUptSWpveE56QTNPVEkxTkRBMUxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dkxVRkhiVGgxTm5GUlJXMW5SRE14ZWpoMFV6aDJaeUZtWmpZMVkyTTVORGt5WTJJNE5tVTJRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM4MlRGVkRVM2d4TjA1bU5qTmlZbXBxWlZObE4yRm1iRFJDWjBwTFYxUmFSeTh4T1dsU1UwRXdiRTVRYjFGcGNESjNiVmh4VUhWT2FteDBNVkozY2xsa01pSXNJbXAwYVNJNkltSTFaRGs1TWprekxXUTVNV0l0TkRjMFlpMWhaakl6TFRBeU1qQTVZV0l4TTJRek55SXNJbTV2Ym1ObElqb2lZMFYwUWxscVZYcFplbVJNVDBac1ZGTnNZelZqTTJ4MVZWUldOV0ZIUmt4aE1XUjNWRlV3TlU0d01DSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalE0TkRRdlkyeHBaVzUwY3k5bVpqWTFZMk01TkRreVkySTRObVUyTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSllWazF0Yldaa2EweGxVbnBUVjJ4cWFrWm1PSGxhWVdkS1RXSk5SblpRTVNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS43NmwzdXVLLTR0MFN0WVBTNzhCdWl0eGhWOEJ0ek5ZTWxHUTVxVFJOYlpLSXVrMFZkNGVTWERIazQ5REROeU92VVNzYmRJZi1SY3gyNnZvMDNOc0ZBUSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly8tQUdtOHU2cVFFbWdEMzF6OHRTOHZnIWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.AnDqo8fka8FVzbMGX1X6bzoy1ovIVkhj3-5AtElwrEOyAk8bdYBbJeKODsDMQpPmZ-dSxLotYEUudghffzT-AQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "bkw3N3ZPRnBpdE52RUREOXFNaXdEOTBlUndpU1cwMnU",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/challenge/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG/19iRSA0lNPoQip2wmXqPuNjlt1RwrYd2"
  }
}
```
#### 48. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
link: <https://stepca:32891/acme/wire/authz/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG>;rel="up"
location: https://stepca:32891/acme/wire/challenge/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG/19iRSA0lNPoQip2wmXqPuNjlt1RwrYd2
replay-nonce: NkV4MmhxeWtqRHhESzBEQlRrVGh4ZWpGb2NzUFFJMlA
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32891/acme/wire/challenge/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG/19iRSA0lNPoQip2wmXqPuNjlt1RwrYd2",
  "status": "valid",
  "token": "XVMmmfdkLeRzSWljjFf8yZagJMbMFvP1",
  "target": "http://wire.com:24844/clients/ff65cc9492cb86e6/access-token"
}
```
### Use refreshToken to retrieve idToken
#### 49. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjUsImlhdCI6MTcwNzkyOTAwNSwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiIxY2U4NGMzNi00NWMwLTRjNGYtODgxMy1jZWNmMWI0NWJhMTgiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXlnc1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6IjBQVjRXbG1SM2ZkT1JFS3BjQ1ZjQ3ciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL2cxWmlzT1BybEY5VlF5akxEa0VCMVRSTUVmWU5RWmNvL04zT3ZGZ3JETkFvbTBwV2pyUGkwaHAwdnpmUFdpdG9CIiwia2V5YXV0aCI6IjF0V0VCNUJKWExWUWJ4QUpESDVreDNreEdyc3l1YUVQLjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.mUJMSooI-optGcj4I90UKSngAgcqgxaRnCZxfzYyIz84MiCyBEXRuAasNteYqLHSxKevNBekHRbGqMq73HFk8MuBU_xVKDAioDhfHuBHh4qFqUhUsPHrvhE8UVPwEdTstCJ5nxvuaCvy-NkB1soSD-NZpYpNibauTu2jxdWq09i6-eQpI4sJUCXW475Q29rPjpsP_wArFScQQXnQy6M2myuGVwVcOAJCO7PHZH5uLavFgoSH5KIIqutmmC3j8MY8x8RfOvAShXDzIDmYZhnzyuR-ADJShU57Y8Yu_NnI-XkASNFdNK75e1Z-8Ye2cZhcXA1xXeFw-1BeqgYdSRM4CA)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2
bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5
MjkwNjUsImlhdCI6MTcwNzkyOTAwNSwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJq
dGkiOiIxY2U4NGMzNi00NWMwLTRjNGYtODgxMy1jZWNmMWI0NWJhMTgiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZh
MDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXln
c1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00
MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6IjBQVjRXbG1SM2ZkT1JF
S3BjQ1ZjQ3ciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1
MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBh
bGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9h
dWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL2cx
WmlzT1BybEY5VlF5akxEa0VCMVRSTUVmWU5RWmNvL04zT3ZGZ3JETkFvbTBwV2py
UGkwaHAwdnpmUFdpdG9CIiwia2V5YXV0aCI6IjF0V0VCNUJKWExWUWJ4QUpESDVr
eDNreEdyc3l1YUVQLjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1
bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNt
aXRoQHdpcmUuY29tIn0.mUJMSooI-optGcj4I90UKSngAgcqgxaRnCZxfzYyIz84
MiCyBEXRuAasNteYqLHSxKevNBekHRbGqMq73HFk8MuBU_xVKDAioDhfHuBHh4qF
qUhUsPHrvhE8UVPwEdTstCJ5nxvuaCvy-NkB1soSD-NZpYpNibauTu2jxdWq09i6
-eQpI4sJUCXW475Q29rPjpsP_wArFScQQXnQy6M2myuGVwVcOAJCO7PHZH5uLavF
goSH5KIIqutmmC3j8MY8x8RfOvAShXDzIDmYZhnzyuR-ADJShU57Y8Yu_NnI-XkA
SNFdNK75e1Z-8Ye2cZhcXA1xXeFw-1BeqgYdSRM4CA
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "pSCde4wUC6mK7qLLbZdIU_zuZjwCEl9Hqa7dWk31Qu8",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32891/acme/wire/challenge/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco/N3OvFgrDNAom0pWjrPi0hp0vzfPWitoB",
  "acr": "1",
  "at_hash": "0PV4WlmR3fdOREKpcCVcCw",
  "aud": "wireapp",
  "auth_time": 1707929004,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1707929065,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1707929005,
  "iss": "http://keycloak:18585/realms/master",
  "jti": "1ce84c36-45c0-4c4f-8813-cecf1b45ba18",
  "keyauth": "1tWEB5BJXLVQbxAJDH5kx3kxGrsyuaEP.1XmccI-BrrPKX4tCQ0Nas1GIMhckkypVmR5mcITgRAI",
  "name": "Alice Smith",
  "nonce": "mZjNt5ygsZyBgfXCj7g27A",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "session_state": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sid": "6cf522f6-5d7b-4123-9530-76ba2b709d1b",
  "sub": "25751cc3-3238-42b0-aa0a-45cc9e476a02",
  "typ": "ID"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvNjF9PPiYfefRrfl7v82
Ef35W/2DRCHkEATmgynV8BX33RJ8oEofQW9Uwoi4/yxsRNWZbQ3pD0VMqdHrM/H/
oPyLehSbOHUKFYms/JBIiKQ58f62+50gPLOFUJwoRZtbhUivG0Ue91URj9onAGXU
WVjcucJR6RCgu5uTTHpCjYES/xC89ehDTKw2GmB/4/wfdCNDowHJmkeZb5X9Er+W
rmOgsJN9q/UgFt4DvCd22VF8tmCSHpZ1FqLP4DatOyZTl+wlM87Yq++KFTZi10rH
xmMJ6jvq1Unc9xEV+JgrJHsJh4dGBQkdyb/yoT5X0huVI+tMDuNrb8IgV75mfAD+
JQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32891/acme/wire/challenge/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco/N3OvFgrDNAom0pWjrPi0hp0vzfPWitoB
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJOa1Y0TW1oeGVXdHFSSGhFU3pCRVFsUnJWR2g0WldwR2IyTnpVRkZKTWxBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NoYWxsZW5nZS9nMVppc09QcmxGOVZReWpMRGtFQjFUUk1FZllOUVpjby9OM092RmdyRE5Bb20wcFdqclBpMGhwMHZ6ZlBXaXRvQiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSndVME5rWlRSM1ZVTTJiVXMzY1V4TVlscGtTVlZmZW5WYWFuZERSV3c1U0hGaE4yUlhhek14VVhVNEluMC5leUpsZUhBaU9qRTNNRGM1TWprd05qVXNJbWxoZENJNk1UY3dOemt5T1RBd05Td2lZWFYwYUY5MGFXMWxJam94TnpBM09USTVNREEwTENKcWRHa2lPaUl4WTJVNE5HTXpOaTAwTldNd0xUUmpOR1l0T0RneE15MWpaV05tTVdJME5XSmhNVGdpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNVGcxT0RVdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSXlOVGMxTVdOak15MHpNak00TFRReVlqQXRZV0V3WVMwME5XTmpPV1UwTnpaaE1ESWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJbTFhYWs1ME5YbG5jMXA1UW1kbVdFTnFOMmN5TjBFaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaU5tTm1OVEl5WmpZdE5XUTNZaTAwTVRJekxUazFNekF0TnpaaVlUSmlOekE1WkRGaUlpd2lZWFJmYUdGemFDSTZJakJRVmpSWGJHMVNNMlprVDFKRlMzQmpRMVpqUTNjaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaU5tTm1OVEl5WmpZdE5XUTNZaTAwTVRJekxUazFNekF0TnpaaVlUSmlOekE1WkRGaUlpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2laMmwyWlc1ZmJtRnRaU0k2SWtGc2FXTmxJaXdpWVdOdFpWOWhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpnNU1TOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMmN4V21selQxQnliRVk1VmxGNWFreEVhMFZDTVZSU1RVVm1XVTVSV21OdkwwNHpUM1pHWjNKRVRrRnZiVEJ3VjJweVVHa3dhSEF3ZG5wbVVGZHBkRzlDSWl3aWEyVjVZWFYwYUNJNklqRjBWMFZDTlVKS1dFeFdVV0o0UVVwRVNEVnJlRE5yZUVkeWMzbDFZVVZRTGpGWWJXTmpTUzFDY25KUVMxZzBkRU5STUU1aGN6RkhTVTFvWTJ0cmVYQldiVkkxYldOSlZHZFNRVWtpTENKbVlXMXBiSGxmYm1GdFpTSTZJbE50YVhSb0lpd2laVzFoYVd3aU9pSmhiR2xqWlhOdGFYUm9RSGRwY21VdVkyOXRJbjAubVVKTVNvb0ktb3B0R2NqNEk5MFVLU25nQWdjcWd4YVJuQ1p4ZnpZeUl6ODRNaUN5QkVYUnVBYXNOdGVZcUxIU3hLZXZOQmVrSFJiR3FNcTczSEZrOE11QlVfeFZLREFpb0RoZkh1QkhoNHFGcVVoVXNQSHJ2aEU4VVZQd0VkVHN0Q0o1bnh2dWFDdnktTmtCMXNvU0QtTlpwWXBOaWJhdVR1Mmp4ZFdxMDlpNi1lUXBJNHNKVUNYVzQ3NVEyOXJQanBzUF93QXJGU2NRUVhuUXk2TTJteXVHVndWY09BSkNPN1BIWkg1dUxhdkZnb1NINUtJSXF1dG1tQzNqOE1ZOHg4UmZPdkFTaFhEeklEbVlaaG56eXVSLUFESlNoVTU3WThZdV9ObkktWGtBU05GZE5LNzVlMVotOFllMmNaaGNYQTF4WGVGdy0xQmVxZ1lkU1JNNENBIn0",
  "signature": "OcDkErnw4xS-U8ToNMHxPKbBv4XEGLQ3j--6WegHpj9qNM0VxMRNO8mRT9m8qL7YBdIFP3HAS8fGhDPwlZoDCw"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJwU0NkZTR3VUM2bUs3cUxMYlpkSVVfenVaandDRWw5SHFhN2RXazMxUXU4In0.eyJleHAiOjE3MDc5MjkwNjUsImlhdCI6MTcwNzkyOTAwNSwiYXV0aF90aW1lIjoxNzA3OTI5MDA0LCJqdGkiOiIxY2U4NGMzNi00NWMwLTRjNGYtODgxMy1jZWNmMWI0NWJhMTgiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTg1ODUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyNTc1MWNjMy0zMjM4LTQyYjAtYWEwYS00NWNjOWU0NzZhMDIiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Im1aak50NXlnc1p5QmdmWENqN2cyN0EiLCJzZXNzaW9uX3N0YXRlIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiYXRfaGFzaCI6IjBQVjRXbG1SM2ZkT1JFS3BjQ1ZjQ3ciLCJhY3IiOiIxIiwic2lkIjoiNmNmNTIyZjYtNWQ3Yi00MTIzLTk1MzAtNzZiYTJiNzA5ZDFiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjg5MS9hY21lL3dpcmUvY2hhbGxlbmdlL2cxWmlzT1BybEY5VlF5akxEa0VCMVRSTUVmWU5RWmNvL04zT3ZGZ3JETkFvbTBwV2pyUGkwaHAwdnpmUFdpdG9CIiwia2V5YXV0aCI6IjF0V0VCNUJKWExWUWJ4QUpESDVreDNreEdyc3l1YUVQLjFYbWNjSS1CcnJQS1g0dENRME5hczFHSU1oY2treXBWbVI1bWNJVGdSQUkiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.mUJMSooI-optGcj4I90UKSngAgcqgxaRnCZxfzYyIz84MiCyBEXRuAasNteYqLHSxKevNBekHRbGqMq73HFk8MuBU_xVKDAioDhfHuBHh4qFqUhUsPHrvhE8UVPwEdTstCJ5nxvuaCvy-NkB1soSD-NZpYpNibauTu2jxdWq09i6-eQpI4sJUCXW475Q29rPjpsP_wArFScQQXnQy6M2myuGVwVcOAJCO7PHZH5uLavFgoSH5KIIqutmmC3j8MY8x8RfOvAShXDzIDmYZhnzyuR-ADJShU57Y8Yu_NnI-XkASNFdNK75e1Z-8Ye2cZhcXA1xXeFw-1BeqgYdSRM4CA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "NkV4MmhxeWtqRHhESzBEQlRrVGh4ZWpGb2NzUFFJMlA",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/challenge/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco/N3OvFgrDNAom0pWjrPi0hp0vzfPWitoB"
  }
}
```
#### 50. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
link: <https://stepca:32891/acme/wire/authz/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco>;rel="up"
location: https://stepca:32891/acme/wire/challenge/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco/N3OvFgrDNAom0pWjrPi0hp0vzfPWitoB
replay-nonce: OHl2d21hYlhVMUxWdU1uUXN3aXBTU0RKb1RTRFhxU0Q
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32891/acme/wire/challenge/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco/N3OvFgrDNAom0pWjrPi0hp0vzfPWitoB",
  "status": "valid",
  "token": "1tWEB5BJXLVQbxAJDH5kx3kxGrsyuaEP",
  "target": "http://keycloak:18585/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 51. verify the status of the order
```http request
POST https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJPSGwyZDIxaFlsaFZNVXhXZFUxdVVYTjNhWEJUVTBSS2IxUlRSRmh4VTBRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL29yZGVyL0NnQjRUOXVHaHdIUGpmOUpoRGtDWEQ0dGRqZ3FCY2szIn0",
  "payload": "",
  "signature": "lQUA8XCxvkUyVAHM1F2IMbrmkQTbeaP7TZTh1lkaghQDaoeil-y-oAa1iHYF6vLEt4Rd1JaWFuxER8S7PsNUBA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "OHl2d21hYlhVMUxWdU1uUXN3aXBTU0RKb1RTRFhxU0Q",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3"
  }
}
```
#### 52. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3
replay-nonce: QlhWYjVWenYwSjlQVzUwVmdONXk4T2Zxc05ObjkwVmQ
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32891/acme/wire/authz/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG",
    "https://stepca:32891/acme/wire/authz/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco"
  ],
  "expires": "2024-02-15T16:43:25Z",
  "notBefore": "2024-02-14T16:43:25.041711Z",
  "notAfter": "2034-02-11T16:43:25.041711Z"
}
```
#### 53. create a CSR and call finalize url
```http request
POST https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJRbGhXWWpWV2VuWXdTamxRVnpVd1ZtZE9OWGs0VDJaeGMwNU9iamt3Vm1RIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL29yZGVyL0NnQjRUOXVHaHdIUGpmOUpoRGtDWEQ0dGRqZ3FCY2szL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBT09TUE9UMVhwNUtBbXF2TDRFTDQtdUxUaGEtenhoaVpXM1hNTDdwRzlGRG9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2TFVGSGJUaDFObkZSUlcxblJETXhlamgwVXpoMlp5Rm1aalkxWTJNNU5Ea3lZMkk0Tm1VMlFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFDd083OEJ1c2QwMHh5MTU0Q3Q4VjB5T1JWT3ZoQmNxc2FSbmEtenY4VWw5dkZyLUJvMklZdG9aeHpzSkEyU0sxV0RkUWxBcEhhTUxyemFLS0t3QzcwUCJ9",
  "signature": "I1YFk0vS8HXWgb3U6X1G9BHT6WZ-IEoGHME3rwgXLuNNWYcBtOmn7-C3DStMmdmnefhb8cLgVGfeoKBZxQ2yAg"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOOSPOT1Xp5KAmqvL4EL4-uLTha-zxhiZW3XML7pG9FDoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQCwO78Busd00xy154Ct8V0yORVOvhBcqsaRna-zv8Ul9vFr-Bo2IYtoZxzsJA2SK1WDdQlApHaMLrzaKKKwC70P"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "QlhWYjVWenYwSjlQVzUwVmdONXk4T2Zxc05ObjkwVmQ",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOOSPOT1Xp5KAmqvL4EL4+uLTha+zxhi
ZW3XML7pG9FDoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vLUFHbTh1NnFRRW1nRDMxejh0Uzh2ZyFmZjY1Y2M5NDkyY2I4NmU2QHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQCw
O78Busd00xy154Ct8V0yORVOvhBcqsaRna+zv8Ul9vFr+Bo2IYtoZxzsJA2SK1WD
dQlApHaMLrzaKKKwC70P
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
                    e3:92:3c:e4:f5:5e:9e:4a:02:6a:af:2f:81:0b:e3:
                    eb:8b:4e:16:be:cf:18:62:65:6d:d7:30:be:e9:1b:
                    d1:43
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        b0:3b:bf:01:ba:c7:74:d3:1c:b5:e7:80:ad:f1:5d:32:39:15:
        4e:be:10:5c:aa:c6:91:9d:af:b3:bf:c5:25:f6:f1:6b:f8:1a:
        36:21:8b:68:67:1c:ec:24:0d:92:2b:55:83:75:09:40:a4:76:
        8c:2e:bc:da:28:a2:b0:0b:bd:0f

```

#### 54. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32891/acme/wire/directory>;rel="index"
location: https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3
replay-nonce: YU9mWkNKVlpsTDEyZWFpbVZlWlQ1VE9uUW5NOGJRMXI
```
```json
{
  "certificate": "https://stepca:32891/acme/wire/certificate/9mftsmv3zulm53CU27NqTcj18ogV6wKx",
  "status": "valid",
  "finalize": "https://stepca:32891/acme/wire/order/CgB4T9uGhwHPjf9JhDkCXD4tdjgqBck3/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://-AGm8u6qQEmgD31z8tS8vg!ff65cc9492cb86e6@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32891/acme/wire/authz/6LUCSx17Nf63bbjjeSe7afl4BgJKWTZG",
    "https://stepca:32891/acme/wire/authz/g1ZisOPrlF9VQyjLDkEB1TRMEfYNQZco"
  ],
  "expires": "2024-02-15T16:43:25Z",
  "notBefore": "2024-02-14T16:43:25.041711Z",
  "notAfter": "2034-02-11T16:43:25.041711Z"
}
```
#### 55. fetch the certificate
```http request
POST https://stepca:32891/acme/wire/certificate/9mftsmv3zulm53CU27NqTcj18ogV6wKx
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODkxL2FjbWUvd2lyZS9hY2NvdW50L1pSUlJtTllvOU15ZmdhWlROOWxVb3kxRjhyMTR6T0JSIiwidHlwIjoiSldUIiwibm9uY2UiOiJZVTltV2tOS1ZscHNUREV5WldGcGJWWmxXbFExVkU5dVVXNU5PR0pSTVhJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4OTEvYWNtZS93aXJlL2NlcnRpZmljYXRlLzltZnRzbXYzenVsbTUzQ1UyN05xVGNqMThvZ1Y2d0t4In0",
  "payload": "",
  "signature": "PpI3v2fXbbQpFGXybeUM_AiGSvrrZRuKxckkcaypHR-ztwRTOaDOHqRS_kBMcsSJM7jFcmx-tGoh_4I8EsW8Cw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32891/acme/wire/account/ZRRRmNYo9MyfgaZTN9lUoy1F8r14zOBR",
    "nonce": "YU9mWkNKVlpsTDEyZWFpbVZlWlQ1VE9uUW5NOGJRMXI",
    "typ": "JWT",
    "url": "https://stepca:32891/acme/wire/certificate/9mftsmv3zulm53CU27NqTcj18ogV6wKx"
  }
}
```
#### 56. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32891/acme/wire/directory>;rel="index"
replay-nonce: YkRBNTNEVjRFR3hkZ21xd1VaamdKbHk2N3NvV3p6UTQ
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGzCCAcCgAwIBAgIRAKrO4eeonVzXGSIS1YWNxfowCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMjE0MTY0MzI1WhcNMzQwMjExMTY0MzI1WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDjkjzk9V6eSgJqry+B\nC+Pri04Wvs8YYmVt1zC+6RvRQ6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFEaPewHEHyJxHbafLfMMVxy8D2RfMB8G\nA1UdIwQYMBaAFK71u5zGiREQFiKMSmdlLblCLIXiMGkGA1UdEQRiMGCGIHdpcmVh\ncHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vLUFHbTh1NnFR\nRW1nRDMxejh0Uzh2ZyUyMWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0kAMEYCIQCvHuf5\nNBWO0wwN1oKHVRw82sqYQAohdukd/EzG92R8ygIhAOJy9qzHXPukV2G3xqBmEIw6\nNkjI/DihUbIubGv1YrJA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAMozgWjsOcvz/3Zobz72C9wwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIxNDE2\nNDMyM1oXDTM0MDIxMTE2NDMyM1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARK\nHjjiLNTcPFVzUfgE/uVp4l9Za9kpP8JdPBtb70CaCBiZQv1W2wt6bW5IQDcdst/k\nezOTP67MzRy1Zq4+cHI5o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUrvW7nMaJERAWIoxKZ2UtuUIsheIwHwYDVR0jBBgw\nFoAUMSVwCNppa2aUboIq7dM33lempbYwCgYIKoZIzj0EAwIDSAAwRQIgCGGTq3Xn\nZKEEoqrtmwarWIb0+jaFD2Dv9Ug/BadXNRkCIQDcRnknaaGIzWA1gxrsT033SUCB\n76FrXLeIzYFbb1/ZWw==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGzCCAcCgAwIBAgIRAKrO4eeonVzXGSIS1YWNxfowCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMjE0MTY0MzI1WhcNMzQwMjExMTY0MzI1WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDjkjzk9V6eSgJqry+B
C+Pri04Wvs8YYmVt1zC+6RvRQ6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFEaPewHEHyJxHbafLfMMVxy8D2RfMB8G
A1UdIwQYMBaAFK71u5zGiREQFiKMSmdlLblCLIXiMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vLUFHbTh1NnFR
RW1nRDMxejh0Uzh2ZyUyMWZmNjVjYzk0OTJjYjg2ZTZAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0kAMEYCIQCvHuf5
NBWO0wwN1oKHVRw82sqYQAohdukd/EzG92R8ygIhAOJy9qzHXPukV2G3xqBmEIw6
NkjI/DihUbIubGv1YrJA
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            aa:ce:e1:e7:a8:9d:5c:d7:19:22:12:d5:85:8d:c5:fa
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Feb 14 16:43:25 2024 GMT
            Not After : Feb 11 16:43:25 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    e3:92:3c:e4:f5:5e:9e:4a:02:6a:af:2f:81:0b:e3:
                    eb:8b:4e:16:be:cf:18:62:65:6d:d7:30:be:e9:1b:
                    d1:43
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                46:8F:7B:01:C4:1F:22:71:1D:B6:9F:2D:F3:0C:57:1C:BC:0F:64:5F
            X509v3 Authority Key Identifier: 
                AE:F5:BB:9C:C6:89:11:10:16:22:8C:4A:67:65:2D:B9:42:2C:85:E2
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://-AGm8u6qQEmgD31z8tS8vg%21ff65cc9492cb86e6@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:af:1e:e7:f9:34:15:8e:d3:0c:0d:d6:82:87:
        55:1c:3c:da:ca:98:40:0a:21:76:e9:1d:fc:4c:c6:f7:64:7c:
        ca:02:21:00:e2:72:f6:ac:c7:5c:fb:a4:57:61:b7:c6:a0:66:
        10:8c:3a:36:48:c8:fc:38:a1:51:b2:2e:6c:6b:f5:62:b2:40

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAMozgWjsOcvz/3Zobz72C9wwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIxNDE2
NDMyM1oXDTM0MDIxMTE2NDMyM1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARK
HjjiLNTcPFVzUfgE/uVp4l9Za9kpP8JdPBtb70CaCBiZQv1W2wt6bW5IQDcdst/k
ezOTP67MzRy1Zq4+cHI5o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUrvW7nMaJERAWIoxKZ2UtuUIsheIwHwYDVR0jBBgw
FoAUMSVwCNppa2aUboIq7dM33lempbYwCgYIKoZIzj0EAwIDSAAwRQIgCGGTq3Xn
ZKEEoqrtmwarWIb0+jaFD2Dv9Ug/BadXNRkCIQDcRnknaaGIzWA1gxrsT033SUCB
76FrXLeIzYFbb1/ZWw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ca:33:81:68:ec:39:cb:f3:ff:76:68:6f:3e:f6:0b:dc
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Feb 14 16:43:23 2024 GMT
            Not After : Feb 11 16:43:23 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:4a:1e:38:e2:2c:d4:dc:3c:55:73:51:f8:04:fe:
                    e5:69:e2:5f:59:6b:d9:29:3f:c2:5d:3c:1b:5b:ef:
                    40:9a:08:18:99:42:fd:56:db:0b:7a:6d:6e:48:40:
                    37:1d:b2:df:e4:7b:33:93:3f:ae:cc:cd:1c:b5:66:
                    ae:3e:70:72:39
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                AE:F5:BB:9C:C6:89:11:10:16:22:8C:4A:67:65:2D:B9:42:2C:85:E2
            X509v3 Authority Key Identifier: 
                31:25:70:08:DA:69:6B:66:94:6E:82:2A:ED:D3:37:DE:57:A6:A5:B6
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:08:61:93:ab:75:e7:64:a1:04:a2:aa:ed:9b:06:
        ab:58:86:f4:fa:36:85:0f:60:ef:f5:48:3f:05:a7:57:35:19:
        02:21:00:dc:46:79:27:69:a1:88:cd:60:35:83:1a:ec:4f:4d:
        f7:49:40:81:ef:a1:6b:5c:b7:88:cd:81:5b:6f:5f:d9:5b

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIRAJ7hMABiG5+3cynJvQ/+qpkwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIxNDE2
NDMyMloXDTM0MDIxMTE2NDMyMlowJjENMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMM
d2lyZSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjQwCn9y0Yzvd
GSq6JuW3HZqcGlH/6adAeMDj9/jt9zYADoy1zbX51i/PgqbzeqvIpGafkITmLfvF
4rSxWln6jaNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEw
HQYDVR0OBBYEFDElcAjaaWtmlG6CKu3TN95XpqW2MAoGCCqGSM49BAMCA0gAMEUC
IQD6nqKS3dXConqJUHRQFjZLYBMPC71CDd+EuGi2gEsyJAIgK/RkD6O+PatAyamY
BVAhtx004tYoC93p5wEIVECcVck=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9e:e1:30:00:62:1b:9f:b7:73:29:c9:bd:0f:fe:aa:99
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Feb 14 16:43:22 2024 GMT
            Not After : Feb 11 16:43:22 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:8d:0c:02:9f:dc:b4:63:3b:dd:19:2a:ba:26:e5:
                    b7:1d:9a:9c:1a:51:ff:e9:a7:40:78:c0:e3:f7:f8:
                    ed:f7:36:00:0e:8c:b5:cd:b5:f9:d6:2f:cf:82:a6:
                    f3:7a:ab:c8:a4:66:9f:90:84:e6:2d:fb:c5:e2:b4:
                    b1:5a:59:fa:8d
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                31:25:70:08:DA:69:6B:66:94:6E:82:2A:ED:D3:37:DE:57:A6:A5:B6
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:fa:9e:a2:92:dd:d5:c2:a2:7a:89:50:74:50:
        16:36:4b:60:13:0f:0b:bd:42:0d:df:84:b8:68:b6:80:4b:32:
        24:02:20:2b:f4:64:0f:a3:be:3d:ab:40:c9:a9:98:05:50:21:
        b7:1d:34:e2:d6:28:0b:dd:e9:e7:01:08:54:40:9c:55:c9

```

openssl verify chain ✅