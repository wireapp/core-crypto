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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/9ff0457928ebe5f4/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/9ff0457928ebe5f4/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0/pN19guj2sKZCQ3Q27w6YBAZlrbl3RogU
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA/9pTNeHI9gx4yI3kCRrJANRonSGUB3boX
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/OOtePUQ2Y9J7rhNPFsgK8WF8Oj1pIZRJ
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32791/acme/wire/directory
                        /acme/wire/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
x-request-id: a00389e2-bcfa-4436-9144-4e8374b8c0e7
```
```json
{
  "newNonce": "https://stepca:32791/acme/wire/new-nonce",
  "newAccount": "https://stepca:32791/acme/wire/new-account",
  "newOrder": "https://stepca:32791/acme/wire/new-order",
  "revokeCert": "https://stepca:32791/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32791/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32791/acme/wire/directory>;rel="index"
replay-nonce: MkQ2RTA1Rm1uWVBVN0w3b29wemFSZGpCODFNR1lEZkM
x-request-id: e12f0b89-9730-4178-ad61-8712f8692183
```
```text
MkQ2RTA1Rm1uWVBVN0w3b29wemFSZGpCODFNR1lEZkM
```
#### 5. create a new account
```http request
POST https://stepca:32791/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Ii01ekNldzkzRF9iYWhseG8yR3c1Y2VOeU5PU3FBeGNiTXVNOGRCTUkxS2cifSwibm9uY2UiOiJNa1EyUlRBMVJtMXVXVkJWTjB3M2IyOXdlbUZTWkdwQ09ERk5SMWxFWmtNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "a_kZPdB7vMtX_KWOjbxJJEUWxU4-RGVyzjCEhmhSdF6-3fOJtMoGyKFOSrZ76unnWe4N1HUviFegc590Q1gpCA"
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
      "x": "-5zCew93D_bahlxo2Gw5ceNyNOSqAxcbMuM8dBMI1Kg"
    },
    "nonce": "MkQ2RTA1Rm1uWVBVN0w3b29wemFSZGpCODFNR1lEZkM",
    "typ": "JWT",
    "url": "https://stepca:32791/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32791/acme/wire/directory>;rel="index"
location: https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji
replay-nonce: YnBKRWsxZ1RCcThld2I1ZllpVnVnNDhocklXTGdIZGc
x-request-id: d88ab1ba-5e5f-4e53-b5df-57e6a8cc5530
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32791/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzkxL2FjbWUvd2lyZS9hY2NvdW50L2ZkUUFuZnVCWE41VmxLTHpFZEdjb3RCWlRwWDV4NkppIiwidHlwIjoiSldUIiwibm9uY2UiOiJZbkJLUldzeFoxUkNjVGhsZDJJMVpsbHBWblZuTkRob2NrbFhUR2RJWkdjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly95UmJTaWxqWFNuQ2w3Ny1Ra002MzRnITlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNS0xMS0xNFQxNDoxMjoyNy44NjMzNDQ2MjZaIiwibm90QWZ0ZXIiOiIyMDM1LTExLTEyVDE0OjEyOjI3Ljg2MzM0NDYyNloifQ",
  "signature": "vOOV_BfTEn0XKp-1Mar2XXr_6WLXdFfiZALnfpTOa43AwSNgnXX4JS-a3imzdbsT27vdWFRX-JnYLhOyJxbkDQ"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://yRbSiljXSnCl77-QkM634g!9ff0457928ebe5f4@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2035-11-12T14:12:27.863344626Z",
    "notBefore": "2025-11-14T14:12:27.863344626Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji",
    "nonce": "YnBKRWsxZ1RCcThld2I1ZllpVnVnNDhocklXTGdIZGc",
    "typ": "JWT",
    "url": "https://stepca:32791/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32791/acme/wire/directory>;rel="index"
location: https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM
replay-nonce: ZGY4SU5TMFBWUXN0V2JNU29BR3NXVzFNTk5hZ042ckE
x-request-id: d6a9e632-e125-4aa6-823a-aea77c4ca5cd
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://yRbSiljXSnCl77-QkM634g!9ff0457928ebe5f4@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32791/acme/wire/authz/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0",
    "https://stepca:32791/acme/wire/authz/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA"
  ],
  "expires": "2025-11-15T14:12:27Z",
  "notBefore": "2025-11-14T14:12:27.863344626Z",
  "notAfter": "2035-11-12T14:12:27.863344626Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32791/acme/wire/authz/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzkxL2FjbWUvd2lyZS9hY2NvdW50L2ZkUUFuZnVCWE41VmxLTHpFZEdjb3RCWlRwWDV4NkppIiwidHlwIjoiSldUIiwibm9uY2UiOiJaR1k0U1U1VE1GQldVWE4wVjJKTlUyOUJSM05YVnpGTlRrNWhaMDQyY2tFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2F1dGh6L3hIUkFhakZQNEhsS1JOUGUwSXN0SXpIV3JyRFM2ZXYwIn0",
  "payload": "",
  "signature": "2ZrevR8oPS8LGE7y4HKbIvUVm117mze41zkNHqa0u544eE0qV6Q7cWllM5CmpLOk45r7O8YGSGMx8WqWWq0rBQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji",
    "nonce": "ZGY4SU5TMFBWUXN0V2JNU29BR3NXVzFNTk5hZ042ckE",
    "typ": "JWT",
    "url": "https://stepca:32791/acme/wire/authz/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32791/acme/wire/directory>;rel="index"
location: https://stepca:32791/acme/wire/authz/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0
replay-nonce: bWFTdTRSb082T0VBVkxiNXNEWkFRY3FHVUxlMzEwejU
x-request-id: 066d59dc-a77b-4295-aa94-4b637ced11de
```
```json
{
  "status": "pending",
  "expires": "2025-11-15T14:12:27Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32791/acme/wire/challenge/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0/pN19guj2sKZCQ3Q27w6YBAZlrbl3RogU",
      "status": "pending",
      "token": "OysCZNnV2iJTYfjmTUJZ6vavXXkzPFLf",
      "target": "http://wire.com:46335/clients/9ff0457928ebe5f4/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://yRbSiljXSnCl77-QkM634g!9ff0457928ebe5f4@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:32791/acme/wire/authz/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzkxL2FjbWUvd2lyZS9hY2NvdW50L2ZkUUFuZnVCWE41VmxLTHpFZEdjb3RCWlRwWDV4NkppIiwidHlwIjoiSldUIiwibm9uY2UiOiJiV0ZUZFRSU2IwODJUMFZCVmt4aU5YTkVXa0ZSWTNGSFZVeGxNekV3ZWpVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2F1dGh6L3ZrZHZHY2tNcERmUEZEd09ZTzZMWmhTQngydWpsMGZBIn0",
  "payload": "",
  "signature": "mQ-bpr7DvNt84SSs8gedgOcu_5w5hdhctckAX5ISrU7yIFQDmF99jMKvywaTzg8N5n836XPGzP-WSyIYpizpDw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji",
    "nonce": "bWFTdTRSb082T0VBVkxiNXNEWkFRY3FHVUxlMzEwejU",
    "typ": "JWT",
    "url": "https://stepca:32791/acme/wire/authz/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA"
  }
}
```
#### 11. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32791/acme/wire/directory>;rel="index"
location: https://stepca:32791/acme/wire/authz/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA
replay-nonce: bTBLUlFJMGJueFRwNTdaUjduaU5HSVI2bzVCQTJzZXA
x-request-id: 07c2f8d2-0af0-4891-aa31-084bb481c5ca
```
```json
{
  "status": "pending",
  "expires": "2025-11-15T14:12:27Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32791/acme/wire/challenge/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA/9pTNeHI9gx4yI3kCRrJANRonSGUB3boX",
      "status": "pending",
      "token": "MXwp2QZezi1xShr3wjNuqKDmmapvtnxv",
      "target": "http://keycloak:42577/realms/master"
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
GET http://wire.com:46335/clients/9ff0457928ebe5f4/nonce
```
#### 13. get wire-server nonce
```http request
200

```
```text
UhaLt4MDQpGJWKm5tvcjDQ
```
#### 14. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiLTV6Q2V3OTNEX2JhaGx4bzJHdzVjZU55Tk9TcUF4Y2JNdU04ZEJNSTFLZyJ9fQ.eyJpYXQiOjE3NjMxMjU5NDcsImV4cCI6MTc2MzEzMzE0NywibmJmIjoxNzYzMTI1OTQ3LCJzdWIiOiJ3aXJlYXBwOi8veVJiU2lsalhTbkNsNzctUWtNNjM0ZyE5ZmYwNDU3OTI4ZWJlNWY0QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NoYWxsZW5nZS94SFJBYWpGUDRIbEtSTlBlMElzdEl6SFdyckRTNmV2MC9wTjE5Z3VqMnNLWkNRM1EyN3c2WUJBWmxyYmwzUm9nVSIsImp0aSI6ImQwMTg2NmYyLWE5MDItNDUyMC04MjJiLTEwMTliMjUwZTgwOSIsIm5vbmNlIjoiVWhhTHQ0TURRcEdKV0ttNXR2Y2pEUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206NDYzMzUvY2xpZW50cy85ZmYwNDU3OTI4ZWJlNWY0L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJPeXNDWk5uVjJpSlRZZmptVFVKWjZ2YXZYWGt6UEZMZiIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.-gqTmdYBGzwozYzb9TDIpBEq-wBexQawzb9C0mJ7y7xU24qvxZ-YD__-73Cnu8G3aac8DLKj7uUvG2-03AAqDg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiLTV6Q2V3OTNEX2JhaGx4bzJHdzVjZU55
Tk9TcUF4Y2JNdU04ZEJNSTFLZyJ9fQ.eyJpYXQiOjE3NjMxMjU5NDcsImV4cCI6M
Tc2MzEzMzE0NywibmJmIjoxNzYzMTI1OTQ3LCJzdWIiOiJ3aXJlYXBwOi8veVJiU
2lsalhTbkNsNzctUWtNNjM0ZyE5ZmYwNDU3OTI4ZWJlNWY0QHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NoYWxsZW5nZS94S
FJBYWpGUDRIbEtSTlBlMElzdEl6SFdyckRTNmV2MC9wTjE5Z3VqMnNLWkNRM1EyN
3c2WUJBWmxyYmwzUm9nVSIsImp0aSI6ImQwMTg2NmYyLWE5MDItNDUyMC04MjJiL
TEwMTliMjUwZTgwOSIsIm5vbmNlIjoiVWhhTHQ0TURRcEdKV0ttNXR2Y2pEUSIsI
mh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206NDYzMzUvY2xpZW50c
y85ZmYwNDU3OTI4ZWJlNWY0L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJPeXNDWk5uV
jJpSlRZZmptVFVKWjZ2YXZYWGt6UEZMZiIsImhhbmRsZSI6IndpcmVhcHA6Ly8lN
DBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY
2UgU21pdGgifQ.-gqTmdYBGzwozYzb9TDIpBEq-wBexQawzb9C0mJ7y7xU24qvxZ
-YD__-73Cnu8G3aac8DLKj7uUvG2-03AAqDg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "-5zCew93D_bahlxo2Gw5ceNyNOSqAxcbMuM8dBMI1Kg"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32791/acme/wire/challenge/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0/pN19guj2sKZCQ3Q27w6YBAZlrbl3RogU",
  "chal": "OysCZNnV2iJTYfjmTUJZ6vavXXkzPFLf",
  "exp": 1763133147,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:46335/clients/9ff0457928ebe5f4/access-token",
  "iat": 1763125947,
  "jti": "d01866f2-a902-4520-822b-1019b250e809",
  "name": "Alice Smith",
  "nbf": 1763125947,
  "nonce": "UhaLt4MDQpGJWKm5tvcjDQ",
  "sub": "wireapp://yRbSiljXSnCl77-QkM634g!9ff0457928ebe5f4@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA+5zCew93D/bahlxo2Gw5ceNyNOSqAxcbMuM8dBMI1Kg=
-----END PUBLIC KEY-----
```

</details>


#### 15. trade client DPoP token for an access token
```http request
POST http://wire.com:46335/clients/9ff0457928ebe5f4/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTFRWNlEyVjNPVE5FWDJKaGFHeDRiekpIZHpWalpVNTVUazlUY1VGNFkySk5kVTA0WkVKTlNURkxaeUo5ZlEuZXlKcFlYUWlPakUzTmpNeE1qVTVORGNzSW1WNGNDSTZNVGMyTXpFek16RTBOeXdpYm1KbUlqb3hOell6TVRJMU9UUTNMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZlVkppVTJsc2FsaFRia05zTnpjdFVXdE5Oak0wWnlFNVptWXdORFUzT1RJNFpXSmxOV1kwUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekkzT1RFdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOTRTRkpCWVdwR1VEUkliRXRTVGxCbE1FbHpkRWw2U0ZkeWNrUlRObVYyTUM5d1RqRTVaM1ZxTW5OTFdrTlJNMUV5TjNjMldVSkJXbXh5WW13elVtOW5WU0lzSW1wMGFTSTZJbVF3TVRnMk5tWXlMV0U1TURJdE5EVXlNQzA0TWpKaUxURXdNVGxpTWpVd1pUZ3dPU0lzSW01dmJtTmxJam9pVldoaFRIUTBUVVJSY0VkS1YwdHROWFIyWTJwRVVTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZORFl6TXpVdlkyeHBaVzUwY3k4NVptWXdORFUzT1RJNFpXSmxOV1kwTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSlBlWE5EV2s1dVZqSnBTbFJaWm1wdFZGVktXaloyWVhaWVdHdDZVRVpNWmlJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuLWdxVG1kWUJHendvell6YjlURElwQkVxLXdCZXhRYXd6YjlDMG1KN3k3eFUyNHF2eFotWURfXy03M0NudThHM2FhYzhETEtqN3VVdkcyLTAzQUFxRGc
```
#### 16. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InA4Uk03a0x3cDYxa2p3Q3NmbmNFTkdPS2xmMU1aUEljRmFVZWcwWnl0cFEifX0.eyJpYXQiOjE3NjMxMjU5NDcsImV4cCI6MTc2MzEyOTkwNywibmJmIjoxNzYzMTI1OTQ3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206NDYzMzUvY2xpZW50cy85ZmYwNDU3OTI4ZWJlNWY0L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly95UmJTaWxqWFNuQ2w3Ny1Ra002MzRnITlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3hIUkFhakZQNEhsS1JOUGUwSXN0SXpIV3JyRFM2ZXYwL3BOMTlndWoyc0taQ1EzUTI3dzZZQkFabHJibDNSb2dVIiwianRpIjoiMGE1NmYxN2YtOTEyNS00OGIxLWI4MTYtZWVkOThhODQ0ODYyIiwibm9uY2UiOiJVaGFMdDRNRFFwR0pXS201dHZjakRRIiwiY2hhbCI6Ik95c0NaTm5WMmlKVFlmam1UVUpaNnZhdlhYa3pQRkxmIiwiY25mIjp7ImtpZCI6IlN0b0tiMUZ1QjU5WFdNTGpoc2RlVTk0VDk1Ul9Bb01QM3UyZzlIc2NZb2cifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lMVFY2UTJWM09UTkVYMkpoYUd4NGJ6SkhkelZqWlU1NVRrOVRjVUY0WTJKTmRVMDRaRUpOU1RGTFp5SjlmUS5leUpwWVhRaU9qRTNOak14TWpVNU5EY3NJbVY0Y0NJNk1UYzJNekV6TXpFME55d2libUptSWpveE56WXpNVEkxT1RRM0xDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmVWSmlVMmxzYWxoVGJrTnNOemN0VVd0Tk5qTTBaeUU1Wm1Zd05EVTNPVEk0WldKbE5XWTBRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5NFNGSkJZV3BHVURSSWJFdFNUbEJsTUVsemRFbDZTRmR5Y2tSVE5tVjJNQzl3VGpFNVozVnFNbk5MV2tOUk0xRXlOM2MyV1VKQldteHlZbXd6VW05blZTSXNJbXAwYVNJNkltUXdNVGcyTm1ZeUxXRTVNREl0TkRVeU1DMDRNakppTFRFd01UbGlNalV3WlRnd09TSXNJbTV2Ym1ObElqb2lWV2hoVEhRMFRVUlJjRWRLVjB0dE5YUjJZMnBFVVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk5EWXpNelV2WTJ4cFpXNTBjeTg1Wm1Zd05EVTNPVEk0WldKbE5XWTBMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lKUGVYTkRXazV1VmpKcFNsUlpabXB0VkZWS1dqWjJZWFpZV0d0NlVFWk1aaUlzSW1oaGJtUnNaU0k2SW5kcGNtVmhjSEE2THk4bE5EQmhiR2xqWlY5M2FYSmxRSGRwY21VdVkyOXRJaXdpZEdWaGJTSTZJbmRwY21VaUxDSnVZVzFsSWpvaVFXeHBZMlVnVTIxcGRHZ2lmUS4tZ3FUbWRZQkd6d296WXpiOVRESXBCRXEtd0JleFFhd3piOUMwbUo3eTd4VTI0cXZ4Wi1ZRF9fLTczQ251OEczYWFjOERMS2o3dVV2RzItMDNBQXFEZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly95UmJTaWxqWFNuQ2w3Ny1Ra002MzRnITlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.TMiVtpB4hSHeL4pTBhtMRwpQ37CWarkduaedfB6OiGdRqvZC25KcwxHMc3pSHyavmjpMAIZRLmkT9O-HRPXuBQ",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InA4Uk03a0x3cDYxa2p3Q3NmbmNFTkdPS2xmMU1aUEljRmFVZWcwWnl0cFEifX0.eyJpYXQiOjE3NjMxMjU5NDcsImV4cCI6MTc2MzEyOTkwNywibmJmIjoxNzYzMTI1OTQ3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206NDYzMzUvY2xpZW50cy85ZmYwNDU3OTI4ZWJlNWY0L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly95UmJTaWxqWFNuQ2w3Ny1Ra002MzRnITlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3hIUkFhakZQNEhsS1JOUGUwSXN0SXpIV3JyRFM2ZXYwL3BOMTlndWoyc0taQ1EzUTI3dzZZQkFabHJibDNSb2dVIiwianRpIjoiMGE1NmYxN2YtOTEyNS00OGIxLWI4MTYtZWVkOThhODQ0ODYyIiwibm9uY2UiOiJVaGFMdDRNRFFwR0pXS201dHZjakRRIiwiY2hhbCI6Ik95c0NaTm5WMmlKVFlmam1UVUpaNnZhdlhYa3pQRkxmIiwiY25mIjp7ImtpZCI6IlN0b0tiMUZ1QjU5WFdNTGpoc2RlVTk0VDk1Ul9Bb01QM3UyZzlIc2NZb2cifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lMVFY2UTJWM09UTkVYMkpoYUd4NGJ6SkhkelZqWlU1NVRrOVRjVUY0WTJKTmRVMDRaRUpOU1RGTFp5SjlmUS5leUpwWVhRaU9qRTNOak14TWpVNU5EY3NJbVY0Y0NJNk1UYzJNekV6TXpFME55d2libUptSWpveE56WXpNVEkxT1RRM0xDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmVWSmlVMmxzYWxoVGJrTnNOemN0VVd0Tk5qTTBaeUU1Wm1Zd05EVTNPVEk0WldKbE5XWTBRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5NFNGSkJZV3BHVURSSWJFdFNUbEJsTUVsemRFbDZTRmR5Y2tSVE5tVjJNQzl3VGpFNVozVnFNbk5MV2tOUk0xRXlOM2MyV1VKQldteHlZbXd6VW05blZTSXNJbXAwYVNJNkltUXdNVGcyTm1ZeUxXRTVNREl0TkRVeU1DMDRNakppTFRFd01UbGlNalV3WlRnd09TSXNJbTV2Ym1ObElqb2lWV2hoVEhRMFRVUlJjRWRLVjB0dE5YUjJZMnBFVVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk5EWXpNelV2WTJ4cFpXNTBjeTg1Wm1Zd05EVTNPVEk0WldKbE5XWTBMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lKUGVYTkRXazV1VmpKcFNsUlpabXB0VkZWS1dqWjJZWFpZV0d0NlVFWk1aaUlzSW1oaGJtUnNaU0k2SW5kcGNtVmhjSEE2THk4bE5EQmhiR2xqWlY5M2FYSmxRSGRwY21VdVkyOXRJaXdpZEdWaGJTSTZJbmRwY21VaUxDSnVZVzFsSWpvaVFXeHBZMlVnVTIxcGRHZ2lmUS4tZ3FUbWRZQkd6d296WXpiOVRESXBCRXEtd0JleFFhd3piOUMwbUo3eTd4VTI0cXZ4Wi1ZRF9fLTczQ251OEczYWFjOERMS2o3dVV2RzItMDNBQXFEZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly95UmJTaWxqWFNuQ2w3Ny1Ra002MzRnITlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.TMiVtpB4hSHeL4pTBhtMRwpQ37CWarkduaedfB6OiGdRqvZC25KcwxHMc3pSHyavmjpMAIZRLmkT9O-HRPXuBQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InA4Uk03a0x3cDYxa2p3Q3NmbmNFTkdPS2xm
MU1aUEljRmFVZWcwWnl0cFEifX0.eyJpYXQiOjE3NjMxMjU5NDcsImV4cCI6MTc2
MzEyOTkwNywibmJmIjoxNzYzMTI1OTQ3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
NDYzMzUvY2xpZW50cy85ZmYwNDU3OTI4ZWJlNWY0L2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly95UmJTaWxqWFNuQ2w3Ny1Ra002MzRnITlmZjA0NTc5Mjhl
YmU1ZjRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc5MS9hY21l
L3dpcmUvY2hhbGxlbmdlL3hIUkFhakZQNEhsS1JOUGUwSXN0SXpIV3JyRFM2ZXYw
L3BOMTlndWoyc0taQ1EzUTI3dzZZQkFabHJibDNSb2dVIiwianRpIjoiMGE1NmYx
N2YtOTEyNS00OGIxLWI4MTYtZWVkOThhODQ0ODYyIiwibm9uY2UiOiJVaGFMdDRN
RFFwR0pXS201dHZjakRRIiwiY2hhbCI6Ik95c0NaTm5WMmlKVFlmam1UVUpaNnZh
dlhYa3pQRkxmIiwiY25mIjp7ImtpZCI6IlN0b0tiMUZ1QjU5WFdNTGpoc2RlVTk0
VDk1Ul9Bb01QM3UyZzlIc2NZb2cifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJU
UVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlM
VUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lMVFY2UTJWM09UTkVYMkpo
YUd4NGJ6SkhkelZqWlU1NVRrOVRjVUY0WTJKTmRVMDRaRUpOU1RGTFp5SjlmUS5l
eUpwWVhRaU9qRTNOak14TWpVNU5EY3NJbVY0Y0NJNk1UYzJNekV6TXpFME55d2li
bUptSWpveE56WXpNVEkxT1RRM0xDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmVWSmlV
MmxzYWxoVGJrTnNOemN0VVd0Tk5qTTBaeUU1Wm1Zd05EVTNPVEk0WldKbE5XWTBR
SGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNP
VEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5NFNGSkJZV3BHVURSSWJFdFNU
bEJsTUVsemRFbDZTRmR5Y2tSVE5tVjJNQzl3VGpFNVozVnFNbk5MV2tOUk0xRXlO
M2MyV1VKQldteHlZbXd6VW05blZTSXNJbXAwYVNJNkltUXdNVGcyTm1ZeUxXRTVN
REl0TkRVeU1DMDRNakppTFRFd01UbGlNalV3WlRnd09TSXNJbTV2Ym1ObElqb2lW
V2hoVEhRMFRVUlJjRWRLVjB0dE5YUjJZMnBFVVNJc0ltaDBiU0k2SWxCUFUxUWlM
Q0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk5EWXpNelV2WTJ4cFpXNTBj
eTg1Wm1Zd05EVTNPVEk0WldKbE5XWTBMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9Z
V3dpT2lKUGVYTkRXazV1VmpKcFNsUlpabXB0VkZWS1dqWjJZWFpZV0d0NlVFWk1a
aUlzSW1oaGJtUnNaU0k2SW5kcGNtVmhjSEE2THk4bE5EQmhiR2xqWlY5M2FYSmxR
SGRwY21VdVkyOXRJaXdpZEdWaGJTSTZJbmRwY21VaUxDSnVZVzFsSWpvaVFXeHBZ
MlVnVTIxcGRHZ2lmUS4tZ3FUbWRZQkd6d296WXpiOVRESXBCRXEtd0JleFFhd3pi
OUMwbUo3eTd4VTI0cXZ4Wi1ZRF9fLTczQ251OEczYWFjOERMS2o3dVV2RzItMDNB
QXFEZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly95UmJTaWxqWFNuQ2w3Ny1Ra002
MzRnITlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwi
c2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.TMiVtpB4hSHeL4pTBhtMRwpQ37CWark
duaedfB6OiGdRqvZC25KcwxHMc3pSHyavmjpMAIZRLmkT9O-HRPXuBQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "p8RM7kLwp61kjwCsfncENGOKlf1MZPIcFaUeg0ZytpQ"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32791/acme/wire/challenge/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0/pN19guj2sKZCQ3Q27w6YBAZlrbl3RogU",
  "chal": "OysCZNnV2iJTYfjmTUJZ6vavXXkzPFLf",
  "client_id": "wireapp://yRbSiljXSnCl77-QkM634g!9ff0457928ebe5f4@wire.com",
  "cnf": {
    "kid": "StoKb1FuB59XWMLjhsdeU94T95R_AoMP3u2g9HscYog"
  },
  "exp": 1763129907,
  "iat": 1763125947,
  "iss": "http://wire.com:46335/clients/9ff0457928ebe5f4/access-token",
  "jti": "0a56f17f-9125-48b1-b816-eed98a844862",
  "nbf": 1763125947,
  "nonce": "UhaLt4MDQpGJWKm5tvcjDQ",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiLTV6Q2V3OTNEX2JhaGx4bzJHdzVjZU55Tk9TcUF4Y2JNdU04ZEJNSTFLZyJ9fQ.eyJpYXQiOjE3NjMxMjU5NDcsImV4cCI6MTc2MzEzMzE0NywibmJmIjoxNzYzMTI1OTQ3LCJzdWIiOiJ3aXJlYXBwOi8veVJiU2lsalhTbkNsNzctUWtNNjM0ZyE5ZmYwNDU3OTI4ZWJlNWY0QHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NoYWxsZW5nZS94SFJBYWpGUDRIbEtSTlBlMElzdEl6SFdyckRTNmV2MC9wTjE5Z3VqMnNLWkNRM1EyN3c2WUJBWmxyYmwzUm9nVSIsImp0aSI6ImQwMTg2NmYyLWE5MDItNDUyMC04MjJiLTEwMTliMjUwZTgwOSIsIm5vbmNlIjoiVWhhTHQ0TURRcEdKV0ttNXR2Y2pEUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206NDYzMzUvY2xpZW50cy85ZmYwNDU3OTI4ZWJlNWY0L2FjY2Vzcy10b2tlbiIsImNoYWwiOiJPeXNDWk5uVjJpSlRZZmptVFVKWjZ2YXZYWGt6UEZMZiIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.-gqTmdYBGzwozYzb9TDIpBEq-wBexQawzb9C0mJ7y7xU24qvxZ-YD__-73Cnu8G3aac8DLKj7uUvG2-03AAqDg",
  "scope": "wire_client_id",
  "sub": "wireapp://yRbSiljXSnCl77-QkM634g!9ff0457928ebe5f4@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAp8RM7kLwp61kjwCsfncENGOKlf1MZPIcFaUeg0ZytpQ=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 17. validate Dpop challenge (clientId)
```http request
POST https://stepca:32791/acme/wire/challenge/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0/pN19guj2sKZCQ3Q27w6YBAZlrbl3RogU
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzkxL2FjbWUvd2lyZS9hY2NvdW50L2ZkUUFuZnVCWE41VmxLTHpFZEdjb3RCWlRwWDV4NkppIiwidHlwIjoiSldUIiwibm9uY2UiOiJiVEJMVWxGSk1HSnVlRlJ3TlRkYVVqZHVhVTVIU1ZJMmJ6VkNRVEp6WlhBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NoYWxsZW5nZS94SFJBYWpGUDRIbEtSTlBlMElzdEl6SFdyckRTNmV2MC9wTjE5Z3VqMnNLWkNRM1EyN3c2WUJBWmxyYmwzUm9nVSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluQTRVazAzYTB4M2NEWXhhMnAzUTNObWJtTkZUa2RQUzJ4bU1VMWFVRWxqUm1GVlpXY3dXbmwwY0ZFaWZYMC5leUpwWVhRaU9qRTNOak14TWpVNU5EY3NJbVY0Y0NJNk1UYzJNekV5T1Rrd055d2libUptSWpveE56WXpNVEkxT1RRM0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TkRZek16VXZZMnhwWlc1MGN5ODVabVl3TkRVM09USTRaV0psTldZMEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTk1VW1KVGFXeHFXRk51UTJ3M055MVJhMDAyTXpSbklUbG1aakEwTlRjNU1qaGxZbVUxWmpSQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpjNU1TOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMM2hJVWtGaGFrWlFORWhzUzFKT1VHVXdTWE4wU1hwSVYzSnlSRk0yWlhZd0wzQk9NVGxuZFdveWMwdGFRMUV6VVRJM2R6WlpRa0ZhYkhKaWJETlNiMmRWSWl3aWFuUnBJam9pTUdFMU5tWXhOMll0T1RFeU5TMDBPR0l4TFdJNE1UWXRaV1ZrT1RoaE9EUTBPRFl5SWl3aWJtOXVZMlVpT2lKVmFHRk1kRFJOUkZGd1IwcFhTMjAxZEhaamFrUlJJaXdpWTJoaGJDSTZJazk1YzBOYVRtNVdNbWxLVkZsbWFtMVVWVXBhTm5aaGRsaFlhM3BRUmt4bUlpd2lZMjVtSWpwN0ltdHBaQ0k2SWxOMGIwdGlNVVoxUWpVNVdGZE5UR3BvYzJSbFZUazBWRGsxVWw5QmIwMVFNM1V5WnpsSWMyTlpiMmNpZlN3aWNISnZiMllpT2lKbGVVcG9Za2RqYVU5cFNrWmFSVkpVVVZOSmMwbHVValZqUTBrMlNXMVNkMkl6UVhKaGJtUXdTV2wzYVdGdVpISkphbkEzU1cxME1HVlRTVFpKYXpsTVZVTkpjMGx0VG5sa2FVazJTV3RXYTAxcVZURk5WR3RwVEVOS05FbHFiMmxNVkZZMlVUSldNMDlVVGtWWU1rcG9ZVWQ0TkdKNlNraGtlbFpxV2xVMU5WUnJPVlJqVlVZMFdUSktUbVJWTURSYVJVcE9VMVJHVEZwNVNqbG1VUzVsZVVwd1dWaFJhVTlxUlROT2FrMTRUV3BWTlU1RVkzTkpiVlkwWTBOSk5rMVVZekpOZWtWNlRYcEZNRTU1ZDJsaWJVcHRTV3B2ZUU1NldYcE5WRWt4VDFSUk0weERTbnBrVjBscFQybEtNMkZZU214WldFSjNUMms0ZG1WV1NtbFZNbXh6WVd4b1ZHSnJUbk5PZW1OMFZWZDBUazVxVFRCYWVVVTFXbTFaZDA1RVZUTlBWRWswV2xkS2JFNVhXVEJSU0dSd1kyMVZkVmt5T1hSSmFYZHBXVmhXYTBscWIybGhTRkl3WTBoTk5reDVPWHBrUjFaM1dUSkZOazE2U1ROUFZFVjJXVmRPZEZwVE9UTmhXRXBzVERKT2IxbFhlSE5hVnpWdVdsTTVORk5HU2tKWlYzQkhWVVJTU1dKRmRGTlViRUpzVFVWc2VtUkZiRFpUUm1SNVkydFNWRTV0VmpKTlF6bDNWR3BGTlZvelZuRk5iazVNVjJ0T1VrMHhSWGxPTTJNeVYxVktRbGR0ZUhsWmJYZDZWVzA1YmxaVFNYTkpiWEF3WVZOSk5rbHRVWGROVkdjeVRtMVplVXhYUlRWTlJFbDBUa1JWZVUxRE1EUk5ha3BwVEZSRmQwMVViR2xOYWxWM1dsUm5kMDlUU1hOSmJUVjJZbTFPYkVscWIybFdWMmhvVkVoUk1GUlZVbEpqUldSTFZqQjBkRTVZVWpKWk1uQkZWVk5KYzBsdGFEQmlVMGsyU1d4Q1VGVXhVV2xNUTBwdlpFaFZhVTlwU205a1NGSjNUMms0ZG1ReWJIbGFVelZxWWpJd05rNUVXWHBOZWxWMldUSjRjRnBYTlRCamVUZzFXbTFaZDA1RVZUTlBWRWswV2xkS2JFNVhXVEJNTWtacVdUSldlbU41TVRCaU1uUnNZbWxKYzBsdFRtOVpWM2RwVDJsS1VHVllUa1JYYXpWMVZtcEtjRk5zVWxwYWJYQjBWa1pXUzFkcVdqSlpXRnBaVjBkME5sVkZXazFhYVVselNXMW9hR0p0VW5OYVUwazJTVzVrY0dOdFZtaGpTRUUyVEhrNGJFNUVRbWhpUjJ4cVdsWTVNMkZZU214UlNHUndZMjFWZFZreU9YUkphWGRwWkVkV2FHSlRTVFpKYm1Sd1kyMVZhVXhEU25WWlZ6RnNTV3B2YVZGWGVIQlpNbFZuVlRJeGNHUkhaMmxtVVM0dFozRlViV1JaUWtkNmQyOTZXWHBpT1ZSRVNYQkNSWEV0ZDBKbGVGRmhkM3BpT1VNd2JVbzNlVGQ0VlRJMGNYWjRXaTFaUkY5ZkxUY3pRMjUxT0VjellXRmpPRVJNUzJvM2RWVjJSekl0TUROQlFYRkVaeUlzSW1Oc2FXVnVkRjlwWkNJNkluZHBjbVZoY0hBNkx5OTVVbUpUYVd4cVdGTnVRMnczTnkxUmEwMDJNelJuSVRsbVpqQTBOVGM1TWpobFltVTFaalJBZDJseVpTNWpiMjBpTENKaGNHbGZkbVZ5YzJsdmJpSTZOU3dpYzJOdmNHVWlPaUozYVhKbFgyTnNhV1Z1ZEY5cFpDSjkuVE1pVnRwQjRoU0hlTDRwVEJodE1Sd3BRMzdDV2Fya2R1YWVkZkI2T2lHZFJxdlpDMjVLY3d4SE1jM3BTSHlhdm1qcE1BSVpSTG1rVDlPLUhSUFh1QlEifQ",
  "signature": "ABF7tRMnGcpZ_lUFiNTD4TagUjwHAxvFOgUVcZHII2mBhimVLxQ04hIJ23C-TW91tC5JVq_cXlElHyjEt6ieDg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InA4Uk03a0x3cDYxa2p3Q3NmbmNFTkdPS2xmMU1aUEljRmFVZWcwWnl0cFEifX0.eyJpYXQiOjE3NjMxMjU5NDcsImV4cCI6MTc2MzEyOTkwNywibmJmIjoxNzYzMTI1OTQ3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206NDYzMzUvY2xpZW50cy85ZmYwNDU3OTI4ZWJlNWY0L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly95UmJTaWxqWFNuQ2w3Ny1Ra002MzRnITlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjc5MS9hY21lL3dpcmUvY2hhbGxlbmdlL3hIUkFhakZQNEhsS1JOUGUwSXN0SXpIV3JyRFM2ZXYwL3BOMTlndWoyc0taQ1EzUTI3dzZZQkFabHJibDNSb2dVIiwianRpIjoiMGE1NmYxN2YtOTEyNS00OGIxLWI4MTYtZWVkOThhODQ0ODYyIiwibm9uY2UiOiJVaGFMdDRNRFFwR0pXS201dHZjakRRIiwiY2hhbCI6Ik95c0NaTm5WMmlKVFlmam1UVUpaNnZhdlhYa3pQRkxmIiwiY25mIjp7ImtpZCI6IlN0b0tiMUZ1QjU5WFdNTGpoc2RlVTk0VDk1Ul9Bb01QM3UyZzlIc2NZb2cifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lMVFY2UTJWM09UTkVYMkpoYUd4NGJ6SkhkelZqWlU1NVRrOVRjVUY0WTJKTmRVMDRaRUpOU1RGTFp5SjlmUS5leUpwWVhRaU9qRTNOak14TWpVNU5EY3NJbVY0Y0NJNk1UYzJNekV6TXpFME55d2libUptSWpveE56WXpNVEkxT1RRM0xDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmVWSmlVMmxzYWxoVGJrTnNOemN0VVd0Tk5qTTBaeUU1Wm1Zd05EVTNPVEk0WldKbE5XWTBRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STNPVEV2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5NFNGSkJZV3BHVURSSWJFdFNUbEJsTUVsemRFbDZTRmR5Y2tSVE5tVjJNQzl3VGpFNVozVnFNbk5MV2tOUk0xRXlOM2MyV1VKQldteHlZbXd6VW05blZTSXNJbXAwYVNJNkltUXdNVGcyTm1ZeUxXRTVNREl0TkRVeU1DMDRNakppTFRFd01UbGlNalV3WlRnd09TSXNJbTV2Ym1ObElqb2lWV2hoVEhRMFRVUlJjRWRLVjB0dE5YUjJZMnBFVVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk5EWXpNelV2WTJ4cFpXNTBjeTg1Wm1Zd05EVTNPVEk0WldKbE5XWTBMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lKUGVYTkRXazV1VmpKcFNsUlpabXB0VkZWS1dqWjJZWFpZV0d0NlVFWk1aaUlzSW1oaGJtUnNaU0k2SW5kcGNtVmhjSEE2THk4bE5EQmhiR2xqWlY5M2FYSmxRSGRwY21VdVkyOXRJaXdpZEdWaGJTSTZJbmRwY21VaUxDSnVZVzFsSWpvaVFXeHBZMlVnVTIxcGRHZ2lmUS4tZ3FUbWRZQkd6d296WXpiOVRESXBCRXEtd0JleFFhd3piOUMwbUo3eTd4VTI0cXZ4Wi1ZRF9fLTczQ251OEczYWFjOERMS2o3dVV2RzItMDNBQXFEZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly95UmJTaWxqWFNuQ2w3Ny1Ra002MzRnITlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.TMiVtpB4hSHeL4pTBhtMRwpQ37CWarkduaedfB6OiGdRqvZC25KcwxHMc3pSHyavmjpMAIZRLmkT9O-HRPXuBQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji",
    "nonce": "bTBLUlFJMGJueFRwNTdaUjduaU5HSVI2bzVCQTJzZXA",
    "typ": "JWT",
    "url": "https://stepca:32791/acme/wire/challenge/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0/pN19guj2sKZCQ3Q27w6YBAZlrbl3RogU"
  }
}
```
#### 18. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32791/acme/wire/directory>;rel="index"
link: <https://stepca:32791/acme/wire/authz/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0>;rel="up"
location: https://stepca:32791/acme/wire/challenge/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0/pN19guj2sKZCQ3Q27w6YBAZlrbl3RogU
replay-nonce: NzJMT2JITG56TTdZbjJlSHp2cHZFUnBvMllSZmdHQXo
x-request-id: a83ababf-f8d3-4e30-bb76-992df3b11e80
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32791/acme/wire/challenge/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0/pN19guj2sKZCQ3Q27w6YBAZlrbl3RogU",
  "status": "valid",
  "token": "OysCZNnV2iJTYfjmTUJZ6vavXXkzPFLf",
  "target": "http://wire.com:46335/clients/9ff0457928ebe5f4/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 19. OAUTH authorization request

```text
code_verifier=uwCoStzXhoGBB0dm1Peh0J-lorMmnL_uKA6S6nlAVpM&code_challenge=OxKBEOiZ9ZP0AUtzcQEjbVLPfbptPzUZonFoTTmsoHU
```
#### 20. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:42577/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=yBcV8G32ZVYdOkTkp6Vpbg&code_challenge=OxKBEOiZ9ZP0AUtzcQEjbVLPfbptPzUZonFoTTmsoHU&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A46335%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32791%2Facme%2Fwire%2Fchallenge%2FvkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA%2F9pTNeHI9gx4yI3kCRrJANRonSGUB3boX%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22MXwp2QZezi1xShr3wjNuqKDmmapvtnxv.StoKb1FuB59XWMLjhsdeU94T95R_AoMP3u2g9HscYog%22%7D%7D%7D&nonce=LJY-alNUAR6jG79U81fhFg
```

#### 21. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:42577/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=e12248ed-4e6b-471c-8db5-e226efaac72b.3c7caa00-f699-4b8b-a7ea-5a44bdcd078d.2195be90-eb20-405e-a5e6-bf104dc7e59e&code_verifier=uwCoStzXhoGBB0dm1Peh0J-lorMmnL_uKA6S6nlAVpM&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A46335%2Fcallback
```
#### 22. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJEVllPLWQzNEpvWDlKQmxoN2xIaDQxSERBbmtFWE0yc21KXzh2bW00Si00In0.eyJleHAiOjE3NjMxMjk2MDgsImlhdCI6MTc2MzEyOTU0OCwiYXV0aF90aW1lIjoxNzYzMTI5NTQ4LCJqdGkiOiI4OGU2YmUwYy04NTI5LTRkOTUtOGI5Mi03ZDU5NWRlZTJjMWMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6NDI1NzcvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJkMmEyNDc2ZS1iOGZiLTQxYmUtYWRjNC1mNzFmOWM5ZDg1N2UiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiM2M3Y2FhMDAtZjY5OS00YjhiLWE3ZWEtNWE0NGJkY2QwNzhkIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vd2lyZS5jb206NDYzMzUiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWFzdGVyIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.OIq0qLrgfHW-NFNNEQvQ9AfYACPoLq2DxeOcGQTUXgO_q1D6RhjFTreXBkhMyeR0zPDysvGunzoGwJJHmveEb77BQAFu98c1adSgMoeYCV3S7g6xtfSsDbbLlDXeLEeBGM9Lm4UTbRaO4mtY1dml0pRV4xCKHtgYyY0PdHFpUr_8_pN5ulgHoyEcgSsI-DagZ9dN_VTOxJfFy34Dut9A1Zu5rVqXiDQ2QnP6wXIyYsoYUC2pFV3MX5OH9CvjnI0BdTF87BzVwKFTZmbYSrRSVS6YUJutvV1aSk85EwNDJ8uvFddc2DEXZW0tOT6_1Xs_qk1GZhz-REC28feoeXzJ-w",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJEVllPLWQzNEpvWDlKQmxoN2xIaDQxSERBbmtFWE0yc21KXzh2bW00Si00In0.eyJleHAiOjE3NjMxMjk2MDgsImlhdCI6MTc2MzEyOTU0OCwiYXV0aF90aW1lIjoxNzYzMTI5NTQ4LCJqdGkiOiI5YTY3YjBhMS05N2E5LTRhMjItYWIwMS0zZTY1OGU5YmJkYWYiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6NDI1NzcvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJkMmEyNDc2ZS1iOGZiLTQxYmUtYWRjNC1mNzFmOWM5ZDg1N2UiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IkxKWS1hbE5VQVI2akc3OVU4MWZoRmciLCJzaWQiOiIzYzdjYWEwMC1mNjk5LTRiOGItYTdlYS01YTQ0YmRjZDA3OGQiLCJhdF9oYXNoIjoiSEdDczZZQUpNd2VjQUoyTFc0OV9iQSIsImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImFjbWVfYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NoYWxsZW5nZS92a2R2R2NrTXBEZlBGRHdPWU82TFpoU0J4MnVqbDBmQS85cFROZUhJOWd4NHlJM2tDUnJKQU5Sb25TR1VCM2JvWCIsImdpdmVuX25hbWUiOiJBbGljZSIsImtleWF1dGgiOiJNWHdwMlFaZXppMXhTaHIzd2pOdXFLRG1tYXB2dG54di5TdG9LYjFGdUI1OVhXTUxqaHNkZVU5NFQ5NVJfQW9NUDN1Mmc5SHNjWW9nIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.i8PLObqq5gXxVyytoUUQr-bv2ZhMegGEXyhBFTOTsKKS3c7q4HCITS2F9k5tLHgMuCH9dAS7CKp83NvMiEoGbHkgX9kwRRqLuTkWX0vB2Oh17--qlg0py7mALgIsywjUX_ut1fZdSiL7eytlCLZPNhF-QvQmGUNOxq_vG4-qvdKCsNDIkxyqRIoAkmlv-YDLR_awDxJP_Z3eVP6fNyBzo6R71y9Q0iBLZ5kTUdUQXXA6R4wRWdzTrOIGbl8B-vbLell4gjVEzhw0BPvgrpscLUgTIrrHXz2QYIo8DlgLhlHQKnk5qRcTqtApUjTwDHrrvLOeYOaXt3qFjDcsbE1tTQ",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3NTA3ODBlNC1hNWM1LTQ3NTYtOWE3Yy1hMzMyNjNkNmFjZjIifQ.eyJleHAiOjE3NjMxMzEzNDgsImlhdCI6MTc2MzEyOTU0OCwianRpIjoiNDE3ODJmMjMtN2RhYS00ZGFmLWIwODctYjU1ZTBlMzA0ZDVhIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjQyNTc3L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6NDI1NzcvcmVhbG1zL21hc3RlciIsInN1YiI6ImQyYTI0NzZlLWI4ZmItNDFiZS1hZGM0LWY3MWY5YzlkODU3ZSIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiM2M3Y2FhMDAtZjY5OS00YjhiLWE3ZWEtNWE0NGJkY2QwNzhkIiwic2NvcGUiOiJvcGVuaWQgYmFzaWMgd2ViLW9yaWdpbnMgZW1haWwgYWNyIHByb2ZpbGUgcm9sZXMifQ.86lXx6p7_Lh4V13Rk7-LiDtANh6MjCHNDy_43Mel0ShANrean0IvRyaEsOhIFzNxKsDyAsaMIcXg0q0tyMs4Mg",
  "scope": "openid email profile",
  "session_state": "3c7caa00-f699-4b8b-a7ea-5a44bdcd078d",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJEVllPLWQzNEpvWDlKQmxoN2xIaDQxSERBbmtFWE0yc21KXzh2bW00Si00In0.eyJleHAiOjE3NjMxMjk2MDgsImlhdCI6MTc2MzEyOTU0OCwiYXV0aF90aW1lIjoxNzYzMTI5NTQ4LCJqdGkiOiI4OGU2YmUwYy04NTI5LTRkOTUtOGI5Mi03ZDU5NWRlZTJjMWMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6NDI1NzcvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJkMmEyNDc2ZS1iOGZiLTQxYmUtYWRjNC1mNzFmOWM5ZDg1N2UiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiM2M3Y2FhMDAtZjY5OS00YjhiLWE3ZWEtNWE0NGJkY2QwNzhkIiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vd2lyZS5jb206NDYzMzUiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWFzdGVyIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.OIq0qLrgfHW-NFNNEQvQ9AfYACPoLq2DxeOcGQTUXgO_q1D6RhjFTreXBkhMyeR0zPDysvGunzoGwJJHmveEb77BQAFu98c1adSgMoeYCV3S7g6xtfSsDbbLlDXeLEeBGM9Lm4UTbRaO4mtY1dml0pRV4xCKHtgYyY0PdHFpUr_8_pN5ulgHoyEcgSsI-DagZ9dN_VTOxJfFy34Dut9A1Zu5rVqXiDQ2QnP6wXIyYsoYUC2pFV3MX5OH9CvjnI0BdTF87BzVwKFTZmbYSrRSVS6YUJutvV1aSk85EwNDJ8uvFddc2DEXZW0tOT6_1Xs_qk1GZhz-REC28feoeXzJ-w)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJEVllPLWQzNEpv
WDlKQmxoN2xIaDQxSERBbmtFWE0yc21KXzh2bW00Si00In0.eyJleHAiOjE3NjMx
Mjk2MDgsImlhdCI6MTc2MzEyOTU0OCwiYXV0aF90aW1lIjoxNzYzMTI5NTQ4LCJq
dGkiOiI4OGU2YmUwYy04NTI5LTRkOTUtOGI5Mi03ZDU5NWRlZTJjMWMiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6NDI1NzcvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiJkMmEyNDc2ZS1iOGZiLTQxYmUtYWRjNC1mNzFmOWM5ZDg1
N2UiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiM2M3Y2Fh
MDAtZjY5OS00YjhiLWE3ZWEtNWE0NGJkY2QwNzhkIiwiYWNyIjoiMSIsImFsbG93
ZWQtb3JpZ2lucyI6WyJodHRwOi8vd2lyZS5jb206NDYzMzUiXSwicmVhbG1fYWNj
ZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWFzdGVyIiwib2ZmbGluZV9h
Y2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7
ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNj
b3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVt
YWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNl
IFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNv
bSIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJl
bWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.OIq0qLrgfHW-NFNNEQvQ9AfYA
CPoLq2DxeOcGQTUXgO_q1D6RhjFTreXBkhMyeR0zPDysvGunzoGwJJHmveEb77BQ
AFu98c1adSgMoeYCV3S7g6xtfSsDbbLlDXeLEeBGM9Lm4UTbRaO4mtY1dml0pRV4
xCKHtgYyY0PdHFpUr_8_pN5ulgHoyEcgSsI-DagZ9dN_VTOxJfFy34Dut9A1Zu5r
VqXiDQ2QnP6wXIyYsoYUC2pFV3MX5OH9CvjnI0BdTF87BzVwKFTZmbYSrRSVS6YU
JutvV1aSk85EwNDJ8uvFddc2DEXZW0tOT6_1Xs_qk1GZhz-REC28feoeXzJ-w
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "DVYO-d34JoX9JBlh7lHh41HDAnkEXM2smJ_8vmm4J-4",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:46335"
  ],
  "aud": "account",
  "auth_time": 1763129548,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1763129608,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1763129548,
  "iss": "http://keycloak:42577/realms/master",
  "jti": "88e6be0c-8529-4d95-8b92-7d595dee2c1c",
  "name": "Alice Smith",
  "preferred_username": "alice_wire@wire.com",
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
  "sid": "3c7caa00-f699-4b8b-a7ea-5a44bdcd078d",
  "sub": "d2a2476e-b8fb-41be-adc4-f71f9c9d857e",
  "typ": "Bearer"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsbx7YXu49LhWDjx4+A6z
uZ/hSh3W9+qcTAt/P9/lF1jgGFDX9LLr+FP2HPpbWbnxDtIpIJF18sZLZ3xzTol+
CCfzJyvtwEnJLeWA1gKSqcd/MQtim//Q0Dy/Ws0fRYn65iRbZzMME8M3YPjCF6lq
rG3Rkbc9dz/mx2/3o6SYUlSB5D3DlQguIGWI84uDyLD71H7vdRsN2X0y1ZiUqG3C
eHW7k9i5NQsPozjs+Ei3Zk6kOT36PogYV5UbRdLdzQAGo5pzi/RhdFYY5Rr8PVug
aDRZIgFJa/PYl0wqo63xSIhMh5WS1WsgVvnv0uejgGPkO79+6F+njON4iMmHJc0r
zwIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 23. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJEVllPLWQzNEpvWDlKQmxoN2xIaDQxSERBbmtFWE0yc21KXzh2bW00Si00In0.eyJleHAiOjE3NjMxMjk2MDgsImlhdCI6MTc2MzEyOTU0OCwiYXV0aF90aW1lIjoxNzYzMTI5NTQ4LCJqdGkiOiI5YTY3YjBhMS05N2E5LTRhMjItYWIwMS0zZTY1OGU5YmJkYWYiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6NDI1NzcvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJkMmEyNDc2ZS1iOGZiLTQxYmUtYWRjNC1mNzFmOWM5ZDg1N2UiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IkxKWS1hbE5VQVI2akc3OVU4MWZoRmciLCJzaWQiOiIzYzdjYWEwMC1mNjk5LTRiOGItYTdlYS01YTQ0YmRjZDA3OGQiLCJhdF9oYXNoIjoiSEdDczZZQUpNd2VjQUoyTFc0OV9iQSIsImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImFjbWVfYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NoYWxsZW5nZS92a2R2R2NrTXBEZlBGRHdPWU82TFpoU0J4MnVqbDBmQS85cFROZUhJOWd4NHlJM2tDUnJKQU5Sb25TR1VCM2JvWCIsImdpdmVuX25hbWUiOiJBbGljZSIsImtleWF1dGgiOiJNWHdwMlFaZXppMXhTaHIzd2pOdXFLRG1tYXB2dG54di5TdG9LYjFGdUI1OVhXTUxqaHNkZVU5NFQ5NVJfQW9NUDN1Mmc5SHNjWW9nIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.i8PLObqq5gXxVyytoUUQr-bv2ZhMegGEXyhBFTOTsKKS3c7q4HCITS2F9k5tLHgMuCH9dAS7CKp83NvMiEoGbHkgX9kwRRqLuTkWX0vB2Oh17--qlg0py7mALgIsywjUX_ut1fZdSiL7eytlCLZPNhF-QvQmGUNOxq_vG4-qvdKCsNDIkxyqRIoAkmlv-YDLR_awDxJP_Z3eVP6fNyBzo6R71y9Q0iBLZ5kTUdUQXXA6R4wRWdzTrOIGbl8B-vbLell4gjVEzhw0BPvgrpscLUgTIrrHXz2QYIo8DlgLhlHQKnk5qRcTqtApUjTwDHrrvLOeYOaXt3qFjDcsbE1tTQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJEVllPLWQzNEpv
WDlKQmxoN2xIaDQxSERBbmtFWE0yc21KXzh2bW00Si00In0.eyJleHAiOjE3NjMx
Mjk2MDgsImlhdCI6MTc2MzEyOTU0OCwiYXV0aF90aW1lIjoxNzYzMTI5NTQ4LCJq
dGkiOiI5YTY3YjBhMS05N2E5LTRhMjItYWIwMS0zZTY1OGU5YmJkYWYiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6NDI1NzcvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiJkMmEyNDc2ZS1iOGZiLTQxYmUtYWRjNC1mNzFmOWM5ZDg1
N2UiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IkxKWS1hbE5V
QVI2akc3OVU4MWZoRmciLCJzaWQiOiIzYzdjYWEwMC1mNjk5LTRiOGItYTdlYS01
YTQ0YmRjZDA3OGQiLCJhdF9oYXNoIjoiSEdDczZZQUpNd2VjQUoyTFc0OV9iQSIs
ImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNt
aXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIs
ImFjbWVfYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NoYWxs
ZW5nZS92a2R2R2NrTXBEZlBGRHdPWU82TFpoU0J4MnVqbDBmQS85cFROZUhJOWd4
NHlJM2tDUnJKQU5Sb25TR1VCM2JvWCIsImdpdmVuX25hbWUiOiJBbGljZSIsImtl
eWF1dGgiOiJNWHdwMlFaZXppMXhTaHIzd2pOdXFLRG1tYXB2dG54di5TdG9LYjFG
dUI1OVhXTUxqaHNkZVU5NFQ5NVJfQW9NUDN1Mmc5SHNjWW9nIiwiZmFtaWx5X25h
bWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.i8PLObq
q5gXxVyytoUUQr-bv2ZhMegGEXyhBFTOTsKKS3c7q4HCITS2F9k5tLHgMuCH9dAS
7CKp83NvMiEoGbHkgX9kwRRqLuTkWX0vB2Oh17--qlg0py7mALgIsywjUX_ut1fZ
dSiL7eytlCLZPNhF-QvQmGUNOxq_vG4-qvdKCsNDIkxyqRIoAkmlv-YDLR_awDxJ
P_Z3eVP6fNyBzo6R71y9Q0iBLZ5kTUdUQXXA6R4wRWdzTrOIGbl8B-vbLell4gjV
Ezhw0BPvgrpscLUgTIrrHXz2QYIo8DlgLhlHQKnk5qRcTqtApUjTwDHrrvLOeYOa
Xt3qFjDcsbE1tTQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "DVYO-d34JoX9JBlh7lHh41HDAnkEXM2smJ_8vmm4J-4",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32791/acme/wire/challenge/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA/9pTNeHI9gx4yI3kCRrJANRonSGUB3boX",
  "acr": "1",
  "at_hash": "HGCs6YAJMwecAJ2LW49_bA",
  "aud": "wireapp",
  "auth_time": 1763129548,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1763129608,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1763129548,
  "iss": "http://keycloak:42577/realms/master",
  "jti": "9a67b0a1-97a9-4a22-ab01-3e658e9bbdaf",
  "keyauth": "MXwp2QZezi1xShr3wjNuqKDmmapvtnxv.StoKb1FuB59XWMLjhsdeU94T95R_AoMP3u2g9HscYog",
  "name": "Alice Smith",
  "nonce": "LJY-alNUAR6jG79U81fhFg",
  "preferred_username": "alice_wire@wire.com",
  "sid": "3c7caa00-f699-4b8b-a7ea-5a44bdcd078d",
  "sub": "d2a2476e-b8fb-41be-adc4-f71f9c9d857e",
  "typ": "ID"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsbx7YXu49LhWDjx4+A6z
uZ/hSh3W9+qcTAt/P9/lF1jgGFDX9LLr+FP2HPpbWbnxDtIpIJF18sZLZ3xzTol+
CCfzJyvtwEnJLeWA1gKSqcd/MQtim//Q0Dy/Ws0fRYn65iRbZzMME8M3YPjCF6lq
rG3Rkbc9dz/mx2/3o6SYUlSB5D3DlQguIGWI84uDyLD71H7vdRsN2X0y1ZiUqG3C
eHW7k9i5NQsPozjs+Ei3Zk6kOT36PogYV5UbRdLdzQAGo5pzi/RhdFYY5Rr8PVug
aDRZIgFJa/PYl0wqo63xSIhMh5WS1WsgVvnv0uejgGPkO79+6F+njON4iMmHJc0r
zwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32791/acme/wire/challenge/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA/9pTNeHI9gx4yI3kCRrJANRonSGUB3boX
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzkxL2FjbWUvd2lyZS9hY2NvdW50L2ZkUUFuZnVCWE41VmxLTHpFZEdjb3RCWlRwWDV4NkppIiwidHlwIjoiSldUIiwibm9uY2UiOiJOekpNVDJKSVRHNTZUVGRaYmpKbFNIcDJjSFpGVW5Cdk1sbFNabWRIUVhvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NoYWxsZW5nZS92a2R2R2NrTXBEZlBGRHdPWU82TFpoU0J4MnVqbDBmQS85cFROZUhJOWd4NHlJM2tDUnJKQU5Sb25TR1VCM2JvWCJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSkVWbGxQTFdRek5FcHZXRGxLUW14b04yeElhRFF4U0VSQmJtdEZXRTB5YzIxS1h6aDJiVzAwU2kwMEluMC5leUpsZUhBaU9qRTNOak14TWprMk1EZ3NJbWxoZENJNk1UYzJNekV5T1RVME9Dd2lZWFYwYUY5MGFXMWxJam94TnpZek1USTVOVFE0TENKcWRHa2lPaUk1WVRZM1lqQmhNUzA1TjJFNUxUUmhNakl0WVdJd01TMHpaVFkxT0dVNVltSmtZV1lpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZOREkxTnpjdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSmtNbUV5TkRjMlpTMWlPR1ppTFRReFltVXRZV1JqTkMxbU56Rm1PV001WkRnMU4yVWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJa3hLV1MxaGJFNVZRVkkyYWtjM09WVTRNV1pvUm1jaUxDSnphV1FpT2lJell6ZGpZV0V3TUMxbU5qazVMVFJpT0dJdFlUZGxZUzAxWVRRMFltUmpaREEzT0dRaUxDSmhkRjlvWVhOb0lqb2lTRWREY3paWlFVcE5kMlZqUVVveVRGYzBPVjlpUVNJc0ltRmpjaUk2SWpFaUxDSmxiV0ZwYkY5MlpYSnBabWxsWkNJNmRISjFaU3dpYm1GdFpTSTZJa0ZzYVdObElGTnRhWFJvSWl3aWNISmxabVZ5Y21Wa1gzVnpaWEp1WVcxbElqb2lZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW1GamJXVmZZWFZrSWpvaWFIUjBjSE02THk5emRHVndZMkU2TXpJM09URXZZV050WlM5M2FYSmxMMk5vWVd4c1pXNW5aUzkyYTJSMlIyTnJUWEJFWmxCR1JIZFBXVTgyVEZwb1UwSjRNblZxYkRCbVFTODVjRlJPWlVoSk9XZDROSGxKTTJ0RFVuSktRVTVTYjI1VFIxVkNNMkp2V0NJc0ltZHBkbVZ1WDI1aGJXVWlPaUpCYkdsalpTSXNJbXRsZVdGMWRHZ2lPaUpOV0hkd01sRmFaWHBwTVhoVGFISXpkMnBPZFhGTFJHMXRZWEIyZEc1NGRpNVRkRzlMWWpGR2RVSTFPVmhYVFV4cWFITmtaVlU1TkZRNU5WSmZRVzlOVUROMU1tYzVTSE5qV1c5bklpd2labUZ0YVd4NVgyNWhiV1VpT2lKVGJXbDBhQ0lzSW1WdFlXbHNJam9pWVd4cFkyVnpiV2wwYUVCM2FYSmxMbU52YlNKOS5pOFBMT2JxcTVnWHhWeXl0b1VVUXItYnYyWmhNZWdHRVh5aEJGVE9Uc0tLUzNjN3E0SENJVFMyRjlrNXRMSGdNdUNIOWRBUzdDS3A4M052TWlFb0diSGtnWDlrd1JScUx1VGtXWDB2QjJPaDE3LS1xbGcwcHk3bUFMZ0lzeXdqVVhfdXQxZlpkU2lMN2V5dGxDTFpQTmhGLVF2UW1HVU5PeHFfdkc0LXF2ZEtDc05ESWt4eXFSSW9Ba21sdi1ZRExSX2F3RHhKUF9aM2VWUDZmTnlCem82UjcxeTlRMGlCTFo1a1RVZFVRWFhBNlI0d1JXZHpUck9JR2JsOEItdmJMZWxsNGdqVkV6aHcwQlB2Z3Jwc2NMVWdUSXJySFh6MlFZSW84RGxnTGhsSFFLbms1cVJjVHF0QXBValR3REhycnZMT2VZT2FYdDNxRmpEY3NiRTF0VFEifQ",
  "signature": "7WqY2200dOQpH3Txrt_CIuYa8ovT8xx66kx5cyQCKxelcTV9JWJ_EtAzHo_jZ2j-V0259l5qwr3nKzRAaI-MCw"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJEVllPLWQzNEpvWDlKQmxoN2xIaDQxSERBbmtFWE0yc21KXzh2bW00Si00In0.eyJleHAiOjE3NjMxMjk2MDgsImlhdCI6MTc2MzEyOTU0OCwiYXV0aF90aW1lIjoxNzYzMTI5NTQ4LCJqdGkiOiI5YTY3YjBhMS05N2E5LTRhMjItYWIwMS0zZTY1OGU5YmJkYWYiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6NDI1NzcvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJkMmEyNDc2ZS1iOGZiLTQxYmUtYWRjNC1mNzFmOWM5ZDg1N2UiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IkxKWS1hbE5VQVI2akc3OVU4MWZoRmciLCJzaWQiOiIzYzdjYWEwMC1mNjk5LTRiOGItYTdlYS01YTQ0YmRjZDA3OGQiLCJhdF9oYXNoIjoiSEdDczZZQUpNd2VjQUoyTFc0OV9iQSIsImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImFjbWVfYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NoYWxsZW5nZS92a2R2R2NrTXBEZlBGRHdPWU82TFpoU0J4MnVqbDBmQS85cFROZUhJOWd4NHlJM2tDUnJKQU5Sb25TR1VCM2JvWCIsImdpdmVuX25hbWUiOiJBbGljZSIsImtleWF1dGgiOiJNWHdwMlFaZXppMXhTaHIzd2pOdXFLRG1tYXB2dG54di5TdG9LYjFGdUI1OVhXTUxqaHNkZVU5NFQ5NVJfQW9NUDN1Mmc5SHNjWW9nIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.i8PLObqq5gXxVyytoUUQr-bv2ZhMegGEXyhBFTOTsKKS3c7q4HCITS2F9k5tLHgMuCH9dAS7CKp83NvMiEoGbHkgX9kwRRqLuTkWX0vB2Oh17--qlg0py7mALgIsywjUX_ut1fZdSiL7eytlCLZPNhF-QvQmGUNOxq_vG4-qvdKCsNDIkxyqRIoAkmlv-YDLR_awDxJP_Z3eVP6fNyBzo6R71y9Q0iBLZ5kTUdUQXXA6R4wRWdzTrOIGbl8B-vbLell4gjVEzhw0BPvgrpscLUgTIrrHXz2QYIo8DlgLhlHQKnk5qRcTqtApUjTwDHrrvLOeYOaXt3qFjDcsbE1tTQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji",
    "nonce": "NzJMT2JITG56TTdZbjJlSHp2cHZFUnBvMllSZmdHQXo",
    "typ": "JWT",
    "url": "https://stepca:32791/acme/wire/challenge/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA/9pTNeHI9gx4yI3kCRrJANRonSGUB3boX"
  }
}
```
#### 24. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32791/acme/wire/directory>;rel="index"
link: <https://stepca:32791/acme/wire/authz/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA>;rel="up"
location: https://stepca:32791/acme/wire/challenge/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA/9pTNeHI9gx4yI3kCRrJANRonSGUB3boX
replay-nonce: V1lSUUpTWExuMEgzdnFhcUNIQmRnNnBvZnpyb2FOSEE
x-request-id: a4eb6787-4a79-45ad-809f-a30b6a2c85b6
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32791/acme/wire/challenge/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA/9pTNeHI9gx4yI3kCRrJANRonSGUB3boX",
  "status": "valid",
  "token": "MXwp2QZezi1xShr3wjNuqKDmmapvtnxv",
  "target": "http://keycloak:42577/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 25. verify the status of the order
```http request
POST https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzkxL2FjbWUvd2lyZS9hY2NvdW50L2ZkUUFuZnVCWE41VmxLTHpFZEdjb3RCWlRwWDV4NkppIiwidHlwIjoiSldUIiwibm9uY2UiOiJWMWxTVVVwVFdFeHVNRWd6ZG5GaGNVTklRbVJuTm5CdlpucHliMkZPU0VFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL29yZGVyL05PVDZkZjhOeU43MlVVRUxXUUtmNGQ0QWpwQ0ZsZVBNIn0",
  "payload": "",
  "signature": "wUi56TqXOq1xR7PPdY0EfYbLwG9WZqBQnbKAzJ2EnSoGPfr-cHUlKbn-1cnCWGkXDWl3HkZeo_gJYA3IAO7CAA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji",
    "nonce": "V1lSUUpTWExuMEgzdnFhcUNIQmRnNnBvZnpyb2FOSEE",
    "typ": "JWT",
    "url": "https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM"
  }
}
```
#### 26. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32791/acme/wire/directory>;rel="index"
location: https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM
replay-nonce: a2ZFZEJxWUl6UEtzREgyYkZ6M2FlcnFCWHMzbGJOVHE
x-request-id: 351e1069-938e-4654-9d8b-f3f3c47abba8
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://yRbSiljXSnCl77-QkM634g!9ff0457928ebe5f4@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32791/acme/wire/authz/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0",
    "https://stepca:32791/acme/wire/authz/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA"
  ],
  "expires": "2025-11-15T14:12:27Z",
  "notBefore": "2025-11-14T14:12:27.863344626Z",
  "notAfter": "2035-11-12T14:12:27.863344626Z"
}
```
#### 27. create a CSR and call finalize url
```http request
POST https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzkxL2FjbWUvd2lyZS9hY2NvdW50L2ZkUUFuZnVCWE41VmxLTHpFZEdjb3RCWlRwWDV4NkppIiwidHlwIjoiSldUIiwibm9uY2UiOiJhMlpGWkVKeFdVbDZVRXR6UkVneVlrWjZNMkZsY25GQ1dITXpiR0pPVkhFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL29yZGVyL05PVDZkZjhOeU43MlVVRUxXUUtmNGQ0QWpwQ0ZsZVBNL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTzRTSldGNG5GSkluN1B2dlhvZVRocjlVRk1sbmhzcjRrMkJGY3ZYSWFxTm9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2ZVZKaVUybHNhbGhUYmtOc056Y3RVV3ROTmpNMFp5RTVabVl3TkRVM09USTRaV0psTldZMFFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFEUm1GYkJ5ZWZYMXJ1R3dxc1oydU5WT19KOVBNbnJvQlFXUGk3bjdYaFpKbmxEYy13ZXV4dElrcVRLSk1WU2wwTlYxVEM4a0ExWDlmUzI0dFJsRlMwRyJ9",
  "signature": "ipQoFBkLS8PJ0Ih_rsKvfXX5dS62POI4fe6mnreedsblb3ckwEeTqyg0LfpoU760uMx68cY4YOlMEHxAlbLEBA"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAO4SJWF4nFJIn7PvvXoeThr9UFMlnhsr4k2BFcvXIaqNoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8veVJiU2lsalhTbkNsNzctUWtNNjM0ZyE5ZmYwNDU3OTI4ZWJlNWY0QHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQDRmFbByefX1ruGwqsZ2uNVO_J9PMnroBQWPi7n7XhZJnlDc-weuxtIkqTKJMVSl0NV1TC8kA1X9fS24tRlFS0G"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji",
    "nonce": "a2ZFZEJxWUl6UEtzREgyYkZ6M2FlcnFCWHMzbGJOVHE",
    "typ": "JWT",
    "url": "https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAO4SJWF4nFJIn7PvvXoeThr9UFMlnhsr
4k2BFcvXIaqNoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8veVJiU2lsalhTbkNsNzctUWtNNjM0ZyE5ZmYwNDU3OTI4ZWJlNWY0QHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQDR
mFbByefX1ruGwqsZ2uNVO/J9PMnroBQWPi7n7XhZJnlDc+weuxtIkqTKJMVSl0NV
1TC8kA1X9fS24tRlFS0G
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
                    ee:12:25:61:78:9c:52:48:9f:b3:ef:bd:7a:1e:4e:
                    1a:fd:50:53:25:9e:1b:2b:e2:4d:81:15:cb:d7:21:
                    aa:8d
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://yRbSiljXSnCl77-QkM634g!9ff0457928ebe5f4@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        d1:98:56:c1:c9:e7:d7:d6:bb:86:c2:ab:19:da:e3:55:3b:f2:
        7d:3c:c9:eb:a0:14:16:3e:2e:e7:ed:78:59:26:79:43:73:ec:
        1e:bb:1b:48:92:a4:ca:24:c5:52:97:43:55:d5:30:bc:90:0d:
        57:f5:f4:b6:e2:d4:65:15:2d:06

```

#### 28. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32791/acme/wire/directory>;rel="index"
location: https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM
replay-nonce: VUkwMFJsenpYSk5UajdJbk5QRlBJcExTQnJJZnFleFQ
x-request-id: 5d2bc01d-1ec5-4df8-995c-fade02041a1f
```
```json
{
  "certificate": "https://stepca:32791/acme/wire/certificate/OOtePUQ2Y9J7rhNPFsgK8WF8Oj1pIZRJ",
  "status": "valid",
  "finalize": "https://stepca:32791/acme/wire/order/NOT6df8NyN72UUELWQKf4d4AjpCFlePM/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://yRbSiljXSnCl77-QkM634g!9ff0457928ebe5f4@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32791/acme/wire/authz/xHRAajFP4HlKRNPe0IstIzHWrrDS6ev0",
    "https://stepca:32791/acme/wire/authz/vkdvGckMpDfPFDwOYO6LZhSBx2ujl0fA"
  ],
  "expires": "2025-11-15T14:12:27Z",
  "notBefore": "2025-11-14T14:12:27.863344626Z",
  "notAfter": "2035-11-12T14:12:27.863344626Z"
}
```
#### 29. fetch the certificate
```http request
POST https://stepca:32791/acme/wire/certificate/OOtePUQ2Y9J7rhNPFsgK8WF8Oj1pIZRJ
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzkxL2FjbWUvd2lyZS9hY2NvdW50L2ZkUUFuZnVCWE41VmxLTHpFZEdjb3RCWlRwWDV4NkppIiwidHlwIjoiSldUIiwibm9uY2UiOiJWVWt3TUZKc2VucFlTazVVYWpkSmJrNVFSbEJKY0V4VFFuSkpabkZsZUZRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3OTEvYWNtZS93aXJlL2NlcnRpZmljYXRlL09PdGVQVVEyWTlKN3JoTlBGc2dLOFdGOE9qMXBJWlJKIn0",
  "payload": "",
  "signature": "u5Bdb2NA6nV5eTBj20bIOgyuQ5_O4qkEvz0tRCV6Q2Zddg6yu7pw0d4CT4kLurdGj725rhJbswwcV14jRCW9Dw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32791/acme/wire/account/fdQAnfuBXN5VlKLzEdGcotBZTpX5x6Ji",
    "nonce": "VUkwMFJsenpYSk5UajdJbk5QRlBJcExTQnJJZnFleFQ",
    "typ": "JWT",
    "url": "https://stepca:32791/acme/wire/certificate/OOtePUQ2Y9J7rhNPFsgK8WF8Oj1pIZRJ"
  }
}
```
#### 30. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32791/acme/wire/directory>;rel="index"
replay-nonce: VEtYVFQyQzdzQXdLeEJFS2hCaHFINmlRbm1mbnp0MDA
x-request-id: 9465a971-3e94-4869-afaa-be85d1995168
```
```json
"-----BEGIN CERTIFICATE-----\nMIICCjCCAbGgAwIBAgIRAJiFBj6vqw58D+GlMidLA9IwCgYIKoZIzj0EAwIwHzEd\nMBsGA1UEAxMUV2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcNMjUxMTE0MTQxMjI3WhcN\nMzUxMTEyMTQxMjI3WjApMREwDwYDVQQKEwh3aXJlLmNvbTEUMBIGA1UEAxMLQWxp\nY2UgU21pdGgwKjAFBgMrZXADIQDuEiVheJxSSJ+z7716Hk4a/VBTJZ4bK+JNgRXL\n1yGqjaOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIw\nHQYDVR0OBBYEFNcCpVyEHOaZjVAse3ShP1ILpAsXMB8GA1UdIwQYMBaAFEjEZUBA\nWASS8+3wzamM96XD0xqeMGkGA1UdEQRiMGCGIHdpcmVhcHA6Ly8lNDBhbGljZV93\naXJlQHdpcmUuY29thjx3aXJlYXBwOi8veVJiU2lsalhTbkNsNzctUWtNNjM0ZyUy\nMTlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb20wHQYMKwYBBAGCpGTGKEABBA0wCwIB\nBgQEd2lyZQQAMAoGCCqGSM49BAMCA0cAMEQCIHJ+L9nbt18wo7gfOiWGcbpsexrA\nYM2BF3rTIcOhxBZNAiATUBuax2thaGUdPLLLYbClwwESb8+Ww0+ROaSJLXLXrg==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIB0TCCAXagAwIBAgIRAIaoIK1H8avgdCupry1c3YMwCgYIKoZIzj0EAwIwFzEV\nMBMGA1UEAxMMV2lyZSBSb290IENBMB4XDTI1MTExNDE0MTIyM1oXDTM1MTExMjE0\nMTIyM1owHzEdMBsGA1UEAxMUV2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjO\nPQIBBggqhkjOPQMBBwNCAARNCjcgjfQNFq70fh4U/Gbl7ZSZh5OK/dykVVSN5L0L\n53NDnJgFNEK2/tr8uaqcZ373FhK6jgINWx9jELPvnE/Uo4GaMIGXMA4GA1UdDwEB\n/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRIxGVAQFgEkvPt\n8M2pjPelw9ManjAfBgNVHSMEGDAWgBSB5HbEaTkdlncO6b6EW4YqweW2BzAxBgNV\nHR4BAf8EJzAloCMwC4IJbG9jYWxob3N0MAiCBnN0ZXBjYTAKhgh3aXJlLmNvbTAK\nBggqhkjOPQQDAgNJADBGAiEAlKe0o5FFWLQRsFeExHl/d32dY4SyoWnqM1WkA/AH\nPAgCIQDYtXIzOVfdRuYJtUM7IZ9WtQ+SbR86MkvemDYs0Th+XQ==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICCjCCAbGgAwIBAgIRAJiFBj6vqw58D+GlMidLA9IwCgYIKoZIzj0EAwIwHzEd
MBsGA1UEAxMUV2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcNMjUxMTE0MTQxMjI3WhcN
MzUxMTEyMTQxMjI3WjApMREwDwYDVQQKEwh3aXJlLmNvbTEUMBIGA1UEAxMLQWxp
Y2UgU21pdGgwKjAFBgMrZXADIQDuEiVheJxSSJ+z7716Hk4a/VBTJZ4bK+JNgRXL
1yGqjaOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIw
HQYDVR0OBBYEFNcCpVyEHOaZjVAse3ShP1ILpAsXMB8GA1UdIwQYMBaAFEjEZUBA
WASS8+3wzamM96XD0xqeMGkGA1UdEQRiMGCGIHdpcmVhcHA6Ly8lNDBhbGljZV93
aXJlQHdpcmUuY29thjx3aXJlYXBwOi8veVJiU2lsalhTbkNsNzctUWtNNjM0ZyUy
MTlmZjA0NTc5MjhlYmU1ZjRAd2lyZS5jb20wHQYMKwYBBAGCpGTGKEABBA0wCwIB
BgQEd2lyZQQAMAoGCCqGSM49BAMCA0cAMEQCIHJ+L9nbt18wo7gfOiWGcbpsexrA
YM2BF3rTIcOhxBZNAiATUBuax2thaGUdPLLLYbClwwESb8+Ww0+ROaSJLXLXrg==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            98:85:06:3e:af:ab:0e:7c:0f:e1:a5:32:27:4b:03:d2
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Wire Intermediate CA
        Validity
            Not Before: Nov 14 14:12:27 2025 GMT
            Not After : Nov 12 14:12:27 2035 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    ee:12:25:61:78:9c:52:48:9f:b3:ef:bd:7a:1e:4e:
                    1a:fd:50:53:25:9e:1b:2b:e2:4d:81:15:cb:d7:21:
                    aa:8d
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                D7:02:A5:5C:84:1C:E6:99:8D:50:2C:7B:74:A1:3F:52:0B:A4:0B:17
            X509v3 Authority Key Identifier: 
                48:C4:65:40:40:58:04:92:F3:ED:F0:CD:A9:8C:F7:A5:C3:D3:1A:9E
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://yRbSiljXSnCl77-QkM634g%219ff0457928ebe5f4@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:72:7e:2f:d9:db:b7:5f:30:a3:b8:1f:3a:25:86:
        71:ba:6c:7b:1a:c0:60:cd:81:17:7a:d3:21:c3:a1:c4:16:4d:
        02:20:13:50:1b:9a:c7:6b:61:68:65:1d:3c:b2:cb:61:b0:a5:
        c3:01:12:6f:cf:96:c3:4f:91:39:a4:89:2d:72:d7:ae

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIB0TCCAXagAwIBAgIRAIaoIK1H8avgdCupry1c3YMwCgYIKoZIzj0EAwIwFzEV
MBMGA1UEAxMMV2lyZSBSb290IENBMB4XDTI1MTExNDE0MTIyM1oXDTM1MTExMjE0
MTIyM1owHzEdMBsGA1UEAxMUV2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAARNCjcgjfQNFq70fh4U/Gbl7ZSZh5OK/dykVVSN5L0L
53NDnJgFNEK2/tr8uaqcZ373FhK6jgINWx9jELPvnE/Uo4GaMIGXMA4GA1UdDwEB
/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBRIxGVAQFgEkvPt
8M2pjPelw9ManjAfBgNVHSMEGDAWgBSB5HbEaTkdlncO6b6EW4YqweW2BzAxBgNV
HR4BAf8EJzAloCMwC4IJbG9jYWxob3N0MAiCBnN0ZXBjYTAKhgh3aXJlLmNvbTAK
BggqhkjOPQQDAgNJADBGAiEAlKe0o5FFWLQRsFeExHl/d32dY4SyoWnqM1WkA/AH
PAgCIQDYtXIzOVfdRuYJtUM7IZ9WtQ+SbR86MkvemDYs0Th+XQ==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            86:a8:20:ad:47:f1:ab:e0:74:2b:a9:af:2d:5c:dd:83
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Wire Root CA
        Validity
            Not Before: Nov 14 14:12:23 2025 GMT
            Not After : Nov 12 14:12:23 2035 GMT
        Subject: CN=Wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:4d:0a:37:20:8d:f4:0d:16:ae:f4:7e:1e:14:fc:
                    66:e5:ed:94:99:87:93:8a:fd:dc:a4:55:54:8d:e4:
                    bd:0b:e7:73:43:9c:98:05:34:42:b6:fe:da:fc:b9:
                    aa:9c:67:7e:f7:16:12:ba:8e:02:0d:5b:1f:63:10:
                    b3:ef:9c:4f:d4
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                48:C4:65:40:40:58:04:92:F3:ED:F0:CD:A9:8C:F7:A5:C3:D3:1A:9E
            X509v3 Authority Key Identifier: 
                81:E4:76:C4:69:39:1D:96:77:0E:E9:BE:84:5B:86:2A:C1:E5:B6:07
            X509v3 Name Constraints: critical
                Permitted:
                  DNS:localhost
                  DNS:stepca
                  URI:wire.com
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:94:a7:b4:a3:91:45:58:b4:11:b0:57:84:c4:
        79:7f:77:7d:9d:63:84:b2:a1:69:ea:33:55:a4:03:f0:07:3c:
        08:02:21:00:d8:b5:72:33:39:57:dd:46:e6:09:b5:43:3b:21:
        9f:56:b5:0f:92:6d:1f:3a:32:4b:de:98:36:2c:d1:38:7e:5d

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBcTCCARegAwIBAgIQT1aC6JrwcsCR7R4IBiZbtzAKBggqhkjOPQQDAjAXMRUw
EwYDVQQDEwxXaXJlIFJvb3QgQ0EwHhcNMjUxMTE0MTQxMjIzWhcNMzUxMTEyMTQx
MjIzWjAXMRUwEwYDVQQDEwxXaXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQ2rb6+ItszsdA1r2+RUKnCg9RkssY4e8a2twEpNdlbzrr5HFTJhF1q
l+/u2ss3bBRqesCLCmvUt7/HczHbIs/oo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYD
VR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQUgeR2xGk5HZZ3Dum+hFuGKsHltgcw
CgYIKoZIzj0EAwIDSAAwRQIhAN21lzECcU3U+K9zj+bepTArPmkYXmBWqZYV7ezU
K26NAiBjBtlsE2UCKflR4t1a83AqdoEUU6HRTKGiwpOcyMIlVw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4f:56:82:e8:9a:f0:72:c0:91:ed:1e:08:06:26:5b:b7
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Wire Root CA
        Validity
            Not Before: Nov 14 14:12:23 2025 GMT
            Not After : Nov 12 14:12:23 2035 GMT
        Subject: CN=Wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:36:ad:be:be:22:db:33:b1:d0:35:af:6f:91:50:
                    a9:c2:83:d4:64:b2:c6:38:7b:c6:b6:b7:01:29:35:
                    d9:5b:ce:ba:f9:1c:54:c9:84:5d:6a:97:ef:ee:da:
                    cb:37:6c:14:6a:7a:c0:8b:0a:6b:d4:b7:bf:c7:73:
                    31:db:22:cf:e8
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                81:E4:76:C4:69:39:1D:96:77:0E:E9:BE:84:5B:86:2A:C1:E5:B6:07
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:dd:b5:97:31:02:71:4d:d4:f8:af:73:8f:e6:
        de:a5:30:2b:3e:69:18:5e:60:56:a9:96:15:ed:ec:d4:2b:6e:
        8d:02:20:63:06:d9:6c:13:65:02:29:f9:51:e2:dd:5a:f3:70:
        2a:76:81:14:53:a1:d1:4c:a1:a2:c2:93:9c:c8:c2:25:57

```

openssl verify chain ✅