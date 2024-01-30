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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/6fc3f2b1c6dfe76d/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn/qngyi7uS9D9V1cC67NYmhi5NhsKG1dOp
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex/cqdznLhIZAqBVEKx64dzvcUZmxoytZux
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/uvYjHHYIdeuFDAJGTZXYzWRpywOsWxMZ
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32856/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32856/acme/wire/new-nonce",
  "newAccount": "https://stepca:32856/acme/wire/new-account",
  "newOrder": "https://stepca:32856/acme/wire/new-order",
  "revokeCert": "https://stepca:32856/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32856/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32856/acme/wire/directory>;rel="index"
replay-nonce: Y3hQcDNjVW1oUUhMZkp4anhYcHJIZENnN2gza2d2UWI
```
```text
Y3hQcDNjVW1oUUhMZkp4anhYcHJIZENnN2gza2d2UWI
```
#### 5. create a new account
```http request
POST https://stepca:32856/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlVBZTNReVZRRjhFM0lNSko1dlotQTlJZEIxVFFkOUVJZTdqMXN4NENOTjAifSwibm9uY2UiOiJZM2hRY0ROalZXMW9VVWhNWmtwNGFuaFljSEpJWkVObk4yZ3phMmQyVVdJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "zNBBK4dFuOzReSAFvjqBcivK0W2PE_dmqzDBqQmFfnTN1HHNFnnDUq6IqOFAIErAiFSw1PejYhzpMb-mmWE8AQ"
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
      "x": "UAe3QyVQF8E3IMJJ5vZ-A9IdB1TQd9EIe7j1sx4CNN0"
    },
    "nonce": "Y3hQcDNjVW1oUUhMZkp4anhYcHJIZENnN2gza2d2UWI",
    "typ": "JWT",
    "url": "https://stepca:32856/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32856/acme/wire/directory>;rel="index"
location: https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O
replay-nonce: anJHSzUxTTJpajVacHhuWm5HS01MblBTTGtzc3U2d0g
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32856/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9hY2NvdW50L1gwTno2RkJzWHNESTNvV21TbnBkSXNCZWdMUldIdzJPIiwidHlwIjoiSldUIiwibm9uY2UiOiJhbkpIU3pVeFRUSnBhalZhY0hodVdtNUhTMDFNYmxCVFRHdHpjM1UyZDBnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly81V3VpZndJQ1RjMk1ISk1lZWVZb1hBITZmYzNmMmIxYzZkZmU3NmRAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMS0zMFQxMTo0MDo1MS44NjE2MTlaIiwibm90QWZ0ZXIiOiIyMDM0LTAxLTI3VDExOjQwOjUxLjg2MTYxOVoifQ",
  "signature": "XlgvATX8M3zXtpkBW929e66orY6aXfG8i1Tcz2PiU0r9GHRsAEKVts5BBeuOpCzoXJvbzbjehfyE56NXEQrPBw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://5WuifwICTc2MHJMeeeYoXA!6fc3f2b1c6dfe76d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2034-01-27T11:40:51.861619Z",
    "notBefore": "2024-01-30T11:40:51.861619Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O",
    "nonce": "anJHSzUxTTJpajVacHhuWm5HS01MblBTTGtzc3U2d0g",
    "typ": "JWT",
    "url": "https://stepca:32856/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32856/acme/wire/directory>;rel="index"
location: https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4
replay-nonce: RDFIaFRVU2FFRG9Ic3RxUTRzVURYS2I1NURUS3pMNkE
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://5WuifwICTc2MHJMeeeYoXA!6fc3f2b1c6dfe76d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32856/acme/wire/authz/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn",
    "https://stepca:32856/acme/wire/authz/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex"
  ],
  "expires": "2024-01-31T11:40:51Z",
  "notBefore": "2024-01-30T11:40:51.861619Z",
  "notAfter": "2034-01-27T11:40:51.861619Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32856/acme/wire/authz/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9hY2NvdW50L1gwTno2RkJzWHNESTNvV21TbnBkSXNCZWdMUldIdzJPIiwidHlwIjoiSldUIiwibm9uY2UiOiJSREZJYUZSVlUyRkZSRzlJYzNSeFVUUnpWVVJZUzJJMU5VUlVTM3BNTmtFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL2F1dGh6L1h6QmFEQXFHTmVqeUZxZGVhZnRsUkR0N2xNUm5jNnFuIn0",
  "payload": "",
  "signature": "GWp4SXa8XhHSivyhNVcUAuhXr-iINuY3xf9LbuCaX4P7hzzZez4bZaFd-Tm-yB8fSoc2Yv8mZ6vPVsxFv_31DQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O",
    "nonce": "RDFIaFRVU2FFRG9Ic3RxUTRzVURYS2I1NURUS3pMNkE",
    "typ": "JWT",
    "url": "https://stepca:32856/acme/wire/authz/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32856/acme/wire/directory>;rel="index"
location: https://stepca:32856/acme/wire/authz/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn
replay-nonce: RG1UNVVoRlFlU2U3aXAxZG9iT2lueUV0emtTMDl4Zlo
```
```json
{
  "status": "pending",
  "expires": "2024-01-31T11:40:51Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32856/acme/wire/challenge/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn/qngyi7uS9D9V1cC67NYmhi5NhsKG1dOp",
      "status": "pending",
      "token": "6mqBLQMgYulwOvY2WnF6jgCyJ9xcvgIm",
      "target": "http://wire.com:24772/clients/6fc3f2b1c6dfe76d/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://5WuifwICTc2MHJMeeeYoXA!6fc3f2b1c6dfe76d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:32856/acme/wire/authz/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9hY2NvdW50L1gwTno2RkJzWHNESTNvV21TbnBkSXNCZWdMUldIdzJPIiwidHlwIjoiSldUIiwibm9uY2UiOiJSRzFVTlZWb1JsRmxVMlUzYVhBeFpHOWlUMmx1ZVVWMGVtdFRNRGw0WmxvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL2F1dGh6L2JkQ2ZVY3FRdVNuUVAxQ0hyOTliVml4SmhRNDQ1VGV4In0",
  "payload": "",
  "signature": "PR-UdFWAlUUtLdlhLCwUWCiSL7oWFIrX4ZBPq8LF0GmJBnSYxRKeaVMFWTE0O6lpk8548e67mqI37KTfgLw6BA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O",
    "nonce": "RG1UNVVoRlFlU2U3aXAxZG9iT2lueUV0emtTMDl4Zlo",
    "typ": "JWT",
    "url": "https://stepca:32856/acme/wire/authz/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex"
  }
}
```
#### 11. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32856/acme/wire/directory>;rel="index"
location: https://stepca:32856/acme/wire/authz/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex
replay-nonce: OVBuSDEyT2tiZHhnSzQyRldwbDZwZWV6TGtNeVdEUXU
```
```json
{
  "status": "pending",
  "expires": "2024-01-31T11:40:51Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32856/acme/wire/challenge/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex/cqdznLhIZAqBVEKx64dzvcUZmxoytZux",
      "status": "pending",
      "token": "MEuAFz1BzLyTafdI9BUVLEVYqc7a9oy0",
      "target": "http://keycloak:15495/realms/master"
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
GET http://wire.com:24772/clients/token/nonce
```
#### 13. get wire-server nonce
```http request
200

```
```text
MVRleFBVMHdkdzBQaFY4aE4yaklxd0ZYUzFrOXlhS1U
```
#### 14. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiVUFlM1F5VlFGOEUzSU1KSjV2Wi1BOUlkQjFUUWQ5RUllN2oxc3g0Q05OMCJ9fQ.eyJpYXQiOjE3MDY2MTEyNTEsImV4cCI6MTcwNjYxODQ1MSwibmJmIjoxNzA2NjExMjUxLCJzdWIiOiJ3aXJlYXBwOi8vNVd1aWZ3SUNUYzJNSEpNZWVlWW9YQSE2ZmMzZjJiMWM2ZGZlNzZkQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL2NoYWxsZW5nZS9YekJhREFxR05lanlGcWRlYWZ0bFJEdDdsTVJuYzZxbi9xbmd5aTd1UzlEOVYxY0M2N05ZbWhpNU5oc0tHMWRPcCIsImp0aSI6IjMwNTJlODIxLWU4MTgtNDExOS04NTExLTM3MGZhOWI2NjY1MyIsIm5vbmNlIjoiTVZSbGVGQlZNSGRrZHpCUWFGWTRhRTR5YWtseGQwWllVekZyT1hsaFMxVSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ3NzIvY2xpZW50cy82ZmMzZjJiMWM2ZGZlNzZkL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI2bXFCTFFNZ1l1bHdPdlkyV25GNmpnQ3lKOXhjdmdJbSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.juFmNQ021L5GGgZ9PctXq8dQowzk4Eo_0YtHM1qjSdkDFglWgSzqzGnHiHweJpp21QUVBGJW2iOmm_8bCXOPDA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiVUFlM1F5VlFGOEUzSU1KSjV2Wi1BOUlk
QjFUUWQ5RUllN2oxc3g0Q05OMCJ9fQ.eyJpYXQiOjE3MDY2MTEyNTEsImV4cCI6M
TcwNjYxODQ1MSwibmJmIjoxNzA2NjExMjUxLCJzdWIiOiJ3aXJlYXBwOi8vNVd1a
WZ3SUNUYzJNSEpNZWVlWW9YQSE2ZmMzZjJiMWM2ZGZlNzZkQHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL2NoYWxsZW5nZS9Ye
kJhREFxR05lanlGcWRlYWZ0bFJEdDdsTVJuYzZxbi9xbmd5aTd1UzlEOVYxY0M2N
05ZbWhpNU5oc0tHMWRPcCIsImp0aSI6IjMwNTJlODIxLWU4MTgtNDExOS04NTExL
TM3MGZhOWI2NjY1MyIsIm5vbmNlIjoiTVZSbGVGQlZNSGRrZHpCUWFGWTRhRTR5Y
WtseGQwWllVekZyT1hsaFMxVSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MjQ3NzIvY2xpZW50cy82ZmMzZjJiMWM2ZGZlNzZkL2FjY2Vzcy10b
2tlbiIsImNoYWwiOiI2bXFCTFFNZ1l1bHdPdlkyV25GNmpnQ3lKOXhjdmdJbSIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUifQ.juFmNQ021L5GGgZ9PctXq8dQowzk4Eo_0YtHM1qjSdkDFglWgS
zqzGnHiHweJpp21QUVBGJW2iOmm_8bCXOPDA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "UAe3QyVQF8E3IMJJ5vZ-A9IdB1TQd9EIe7j1sx4CNN0"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32856/acme/wire/challenge/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn/qngyi7uS9D9V1cC67NYmhi5NhsKG1dOp",
  "chal": "6mqBLQMgYulwOvY2WnF6jgCyJ9xcvgIm",
  "exp": 1706618451,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:24772/clients/6fc3f2b1c6dfe76d/access-token",
  "iat": 1706611251,
  "jti": "3052e821-e818-4119-8511-370fa9b66653",
  "nbf": 1706611251,
  "nonce": "MVRleFBVMHdkdzBQaFY4aE4yaklxd0ZYUzFrOXlhS1U",
  "sub": "wireapp://5WuifwICTc2MHJMeeeYoXA!6fc3f2b1c6dfe76d@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINuegQI4yuCQu84uGbmFvtbNOnoRVoeFUW/xjb0H018F
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAUAe3QyVQF8E3IMJJ5vZ+A9IdB1TQd9EIe7j1sx4CNN0=
-----END PUBLIC KEY-----
```

</details>


#### 15. trade client DPoP token for an access token
```http request
POST http://wire.com:24772/clients/6fc3f2b1c6dfe76d/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVlVGbE0xRjVWbEZHT0VVelNVMUtTalYyV2kxQk9VbGtRakZVVVdRNVJVbGxOMm94YzNnMFEwNU9NQ0o5ZlEuZXlKcFlYUWlPakUzTURZMk1URXlOVEVzSW1WNGNDSTZNVGN3TmpZeE9EUTFNU3dpYm1KbUlqb3hOekEyTmpFeE1qVXhMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZOVmQxYVdaM1NVTlVZekpOU0VwTlpXVmxXVzlZUVNFMlptTXpaakppTVdNMlpHWmxOelprUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekk0TlRZdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOVlla0poUkVGeFIwNWxhbmxHY1dSbFlXWjBiRkpFZERkc1RWSnVZelp4Ymk5eGJtZDVhVGQxVXpsRU9WWXhZME0yTjA1WmJXaHBOVTVvYzB0SE1XUlBjQ0lzSW1wMGFTSTZJak13TlRKbE9ESXhMV1U0TVRndE5ERXhPUzA0TlRFeExUTTNNR1poT1dJMk5qWTFNeUlzSW01dmJtTmxJam9pVFZaU2JHVkdRbFpOU0dSclpIcENVV0ZHV1RSaFJUUjVZV3RzZUdRd1dsbFZla1p5VDFoc2FGTXhWU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRM056SXZZMnhwWlc1MGN5ODJabU16WmpKaU1XTTJaR1psTnpaa0wyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUkyYlhGQ1RGRk5aMWwxYkhkUGRsa3lWMjVHTm1wblEzbEtPWGhqZG1kSmJTSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpZlEuanVGbU5RMDIxTDVHR2daOVBjdFhxOGRRb3d6azRFb18wWXRITTFxalNka0RGZ2xXZ1N6cXpHbkhpSHdlSnBwMjFRVVZCR0pXMmlPbW1fOGJDWE9QREE
```
#### 16. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im5CSURrLWY3bW9RT0Jza01MWGUxVkhnS3Q4alQwZWZZQ3Bxdlk2Z1NZWGcifX0.eyJpYXQiOjE3MDY2MTEyNTEsImV4cCI6MTcwNjYxNTIxMSwibmJmIjoxNzA2NjExMjUxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ3NzIvY2xpZW50cy82ZmMzZjJiMWM2ZGZlNzZkL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly81V3VpZndJQ1RjMk1ISk1lZWVZb1hBITZmYzNmMmIxYzZkZmU3NmRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg1Ni9hY21lL3dpcmUvY2hhbGxlbmdlL1h6QmFEQXFHTmVqeUZxZGVhZnRsUkR0N2xNUm5jNnFuL3FuZ3lpN3VTOUQ5VjFjQzY3TlltaGk1TmhzS0cxZE9wIiwianRpIjoiMzU3YjEwMjYtZDM0Ny00ZTFlLTgyNTYtZjc5NTRmY2RiNTUyIiwibm9uY2UiOiJNVlJsZUZCVk1IZGtkekJRYUZZNGFFNHlha2x4ZDBaWVV6RnJPWGxoUzFVIiwiY2hhbCI6IjZtcUJMUU1nWXVsd092WTJXbkY2amdDeUo5eGN2Z0ltIiwiY25mIjp7ImtpZCI6ImhZVXV1V2w3QXVlblU4SVQ2czdTY2tZNi1Qc2d0MnNtZHpDTzF5ZGpnMVEifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lWVUZsTTFGNVZsRkdPRVV6U1UxS1NqVjJXaTFCT1Vsa1FqRlVVV1E1UlVsbE4yb3hjM2cwUTA1T01DSjlmUS5leUpwWVhRaU9qRTNNRFkyTVRFeU5URXNJbVY0Y0NJNk1UY3dOall4T0RRMU1Td2libUptSWpveE56QTJOakV4TWpVeExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dk5WZDFhV1ozU1VOVVl6Sk5TRXBOWldWbFdXOVlRU0UyWm1NelpqSmlNV00yWkdabE56WmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STROVFl2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5WWVrSmhSRUZ4UjA1bGFubEdjV1JsWVdaMGJGSkVkRGRzVFZKdVl6WnhiaTl4Ym1kNWFUZDFVemxFT1ZZeFkwTTJOMDVaYldocE5VNW9jMHRITVdSUGNDSXNJbXAwYVNJNklqTXdOVEpsT0RJeExXVTRNVGd0TkRFeE9TMDROVEV4TFRNM01HWmhPV0kyTmpZMU15SXNJbTV2Ym1ObElqb2lUVlpTYkdWR1FsWk5TR1JyWkhwQ1VXRkdXVFJoUlRSNVlXdHNlR1F3V2xsVmVrWnlUMWhzYUZNeFZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEzTnpJdlkyeHBaVzUwY3k4MlptTXpaakppTVdNMlpHWmxOelprTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTJiWEZDVEZGTloxbDFiSGRQZGxreVYyNUdObXBuUTNsS09YaGpkbWRKYlNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5qdUZtTlEwMjFMNUdHZ1o5UGN0WHE4ZFFvd3prNEVvXzBZdEhNMXFqU2RrREZnbFdnU3pxekduSGlId2VKcHAyMVFVVkJHSlcyaU9tbV84YkNYT1BEQSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly81V3VpZndJQ1RjMk1ISk1lZWVZb1hBITZmYzNmMmIxYzZkZmU3NmRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.YkWikwur6m7GYzluRfsd1ejz2zxKfWrk8Asuli7gsQK26xsBvWKIlbcplefbjRsRas0Im8Lu_pYmtLk0mWfKAg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im5CSURrLWY3bW9RT0Jza01MWGUxVkhnS3Q4alQwZWZZQ3Bxdlk2Z1NZWGcifX0.eyJpYXQiOjE3MDY2MTEyNTEsImV4cCI6MTcwNjYxNTIxMSwibmJmIjoxNzA2NjExMjUxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ3NzIvY2xpZW50cy82ZmMzZjJiMWM2ZGZlNzZkL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly81V3VpZndJQ1RjMk1ISk1lZWVZb1hBITZmYzNmMmIxYzZkZmU3NmRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg1Ni9hY21lL3dpcmUvY2hhbGxlbmdlL1h6QmFEQXFHTmVqeUZxZGVhZnRsUkR0N2xNUm5jNnFuL3FuZ3lpN3VTOUQ5VjFjQzY3TlltaGk1TmhzS0cxZE9wIiwianRpIjoiMzU3YjEwMjYtZDM0Ny00ZTFlLTgyNTYtZjc5NTRmY2RiNTUyIiwibm9uY2UiOiJNVlJsZUZCVk1IZGtkekJRYUZZNGFFNHlha2x4ZDBaWVV6RnJPWGxoUzFVIiwiY2hhbCI6IjZtcUJMUU1nWXVsd092WTJXbkY2amdDeUo5eGN2Z0ltIiwiY25mIjp7ImtpZCI6ImhZVXV1V2w3QXVlblU4SVQ2czdTY2tZNi1Qc2d0MnNtZHpDTzF5ZGpnMVEifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lWVUZsTTFGNVZsRkdPRVV6U1UxS1NqVjJXaTFCT1Vsa1FqRlVVV1E1UlVsbE4yb3hjM2cwUTA1T01DSjlmUS5leUpwWVhRaU9qRTNNRFkyTVRFeU5URXNJbVY0Y0NJNk1UY3dOall4T0RRMU1Td2libUptSWpveE56QTJOakV4TWpVeExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dk5WZDFhV1ozU1VOVVl6Sk5TRXBOWldWbFdXOVlRU0UyWm1NelpqSmlNV00yWkdabE56WmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STROVFl2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5WWVrSmhSRUZ4UjA1bGFubEdjV1JsWVdaMGJGSkVkRGRzVFZKdVl6WnhiaTl4Ym1kNWFUZDFVemxFT1ZZeFkwTTJOMDVaYldocE5VNW9jMHRITVdSUGNDSXNJbXAwYVNJNklqTXdOVEpsT0RJeExXVTRNVGd0TkRFeE9TMDROVEV4TFRNM01HWmhPV0kyTmpZMU15SXNJbTV2Ym1ObElqb2lUVlpTYkdWR1FsWk5TR1JyWkhwQ1VXRkdXVFJoUlRSNVlXdHNlR1F3V2xsVmVrWnlUMWhzYUZNeFZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEzTnpJdlkyeHBaVzUwY3k4MlptTXpaakppTVdNMlpHWmxOelprTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTJiWEZDVEZGTloxbDFiSGRQZGxreVYyNUdObXBuUTNsS09YaGpkbWRKYlNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5qdUZtTlEwMjFMNUdHZ1o5UGN0WHE4ZFFvd3prNEVvXzBZdEhNMXFqU2RrREZnbFdnU3pxekduSGlId2VKcHAyMVFVVkJHSlcyaU9tbV84YkNYT1BEQSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly81V3VpZndJQ1RjMk1ISk1lZWVZb1hBITZmYzNmMmIxYzZkZmU3NmRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.YkWikwur6m7GYzluRfsd1ejz2zxKfWrk8Asuli7gsQK26xsBvWKIlbcplefbjRsRas0Im8Lu_pYmtLk0mWfKAg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6Im5CSURrLWY3bW9RT0Jza01MWGUxVkhnS3Q4
alQwZWZZQ3Bxdlk2Z1NZWGcifX0.eyJpYXQiOjE3MDY2MTEyNTEsImV4cCI6MTcw
NjYxNTIxMSwibmJmIjoxNzA2NjExMjUxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQ3NzIvY2xpZW50cy82ZmMzZjJiMWM2ZGZlNzZkL2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly81V3VpZndJQ1RjMk1ISk1lZWVZb1hBITZmYzNmMmIxYzZk
ZmU3NmRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg1Ni9hY21l
L3dpcmUvY2hhbGxlbmdlL1h6QmFEQXFHTmVqeUZxZGVhZnRsUkR0N2xNUm5jNnFu
L3FuZ3lpN3VTOUQ5VjFjQzY3TlltaGk1TmhzS0cxZE9wIiwianRpIjoiMzU3YjEw
MjYtZDM0Ny00ZTFlLTgyNTYtZjc5NTRmY2RiNTUyIiwibm9uY2UiOiJNVlJsZUZC
Vk1IZGtkekJRYUZZNGFFNHlha2x4ZDBaWVV6RnJPWGxoUzFVIiwiY2hhbCI6IjZt
cUJMUU1nWXVsd092WTJXbkY2amdDeUo5eGN2Z0ltIiwiY25mIjp7ImtpZCI6ImhZ
VXV1V2w3QXVlblU4SVQ2czdTY2tZNi1Qc2d0MnNtZHpDTzF5ZGpnMVEifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lWVUZsTTFGNVZsRkdPRVV6U1UxS1NqVjJXaTFCT1Vsa1FqRlVVV1E1UlVs
bE4yb3hjM2cwUTA1T01DSjlmUS5leUpwWVhRaU9qRTNNRFkyTVRFeU5URXNJbVY0
Y0NJNk1UY3dOall4T0RRMU1Td2libUptSWpveE56QTJOakV4TWpVeExDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dk5WZDFhV1ozU1VOVVl6Sk5TRXBOWldWbFdXOVlRU0Uy
Wm1NelpqSmlNV00yWkdabE56WmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STROVFl2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM5WWVrSmhSRUZ4UjA1bGFubEdjV1JsWVdaMGJGSkVkRGRzVFZKdVl6WnhiaTl4
Ym1kNWFUZDFVemxFT1ZZeFkwTTJOMDVaYldocE5VNW9jMHRITVdSUGNDSXNJbXAw
YVNJNklqTXdOVEpsT0RJeExXVTRNVGd0TkRFeE9TMDROVEV4TFRNM01HWmhPV0ky
TmpZMU15SXNJbTV2Ym1ObElqb2lUVlpTYkdWR1FsWk5TR1JyWkhwQ1VXRkdXVFJo
UlRSNVlXdHNlR1F3V2xsVmVrWnlUMWhzYUZNeFZTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEzTnpJdlkyeHBaVzUw
Y3k4MlptTXpaakppTVdNMlpHWmxOelprTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSTJiWEZDVEZGTloxbDFiSGRQZGxreVYyNUdObXBuUTNsS09YaGpkbWRK
YlNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5qdUZtTlEwMjFMNUdH
Z1o5UGN0WHE4ZFFvd3prNEVvXzBZdEhNMXFqU2RrREZnbFdnU3pxekduSGlId2VK
cHAyMVFVVkJHSlcyaU9tbV84YkNYT1BEQSIsImNsaWVudF9pZCI6IndpcmVhcHA6
Ly81V3VpZndJQ1RjMk1ISk1lZWVZb1hBITZmYzNmMmIxYzZkZmU3NmRAd2lyZS5j
b20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.YkW
ikwur6m7GYzluRfsd1ejz2zxKfWrk8Asuli7gsQK26xsBvWKIlbcplefbjRsRas0
Im8Lu_pYmtLk0mWfKAg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "nBIDk-f7moQOBskMLXe1VHgKt8jT0efYCpqvY6gSYXg"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32856/acme/wire/challenge/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn/qngyi7uS9D9V1cC67NYmhi5NhsKG1dOp",
  "chal": "6mqBLQMgYulwOvY2WnF6jgCyJ9xcvgIm",
  "client_id": "wireapp://5WuifwICTc2MHJMeeeYoXA!6fc3f2b1c6dfe76d@wire.com",
  "cnf": {
    "kid": "hYUuuWl7AuenU8IT6s7SckY6-Psgt2smdzCO1ydjg1Q"
  },
  "exp": 1706615211,
  "iat": 1706611251,
  "iss": "http://wire.com:24772/clients/6fc3f2b1c6dfe76d/access-token",
  "jti": "357b1026-d347-4e1e-8256-f7954fcdb552",
  "nbf": 1706611251,
  "nonce": "MVRleFBVMHdkdzBQaFY4aE4yaklxd0ZYUzFrOXlhS1U",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiVUFlM1F5VlFGOEUzSU1KSjV2Wi1BOUlkQjFUUWQ5RUllN2oxc3g0Q05OMCJ9fQ.eyJpYXQiOjE3MDY2MTEyNTEsImV4cCI6MTcwNjYxODQ1MSwibmJmIjoxNzA2NjExMjUxLCJzdWIiOiJ3aXJlYXBwOi8vNVd1aWZ3SUNUYzJNSEpNZWVlWW9YQSE2ZmMzZjJiMWM2ZGZlNzZkQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL2NoYWxsZW5nZS9YekJhREFxR05lanlGcWRlYWZ0bFJEdDdsTVJuYzZxbi9xbmd5aTd1UzlEOVYxY0M2N05ZbWhpNU5oc0tHMWRPcCIsImp0aSI6IjMwNTJlODIxLWU4MTgtNDExOS04NTExLTM3MGZhOWI2NjY1MyIsIm5vbmNlIjoiTVZSbGVGQlZNSGRrZHpCUWFGWTRhRTR5YWtseGQwWllVekZyT1hsaFMxVSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ3NzIvY2xpZW50cy82ZmMzZjJiMWM2ZGZlNzZkL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI2bXFCTFFNZ1l1bHdPdlkyV25GNmpnQ3lKOXhjdmdJbSIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.juFmNQ021L5GGgZ9PctXq8dQowzk4Eo_0YtHM1qjSdkDFglWgSzqzGnHiHweJpp21QUVBGJW2iOmm_8bCXOPDA",
  "scope": "wire_client_id",
  "sub": "wireapp://5WuifwICTc2MHJMeeeYoXA!6fc3f2b1c6dfe76d@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICgqfcrH/2Lpt3nLkLYNFXzAjl0Mi/bjlqwBEIXXsoyo
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAnBIDk+f7moQOBskMLXe1VHgKt8jT0efYCpqvY6gSYXg=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 17. validate Dpop challenge (clientId)
```http request
POST https://stepca:32856/acme/wire/challenge/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn/qngyi7uS9D9V1cC67NYmhi5NhsKG1dOp
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9hY2NvdW50L1gwTno2RkJzWHNESTNvV21TbnBkSXNCZWdMUldIdzJPIiwidHlwIjoiSldUIiwibm9uY2UiOiJPVkJ1U0RFeVQydGlaSGhuU3pReVJsZHdiRFp3WldWNlRHdE5lVmRFVVhVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL2NoYWxsZW5nZS9YekJhREFxR05lanlGcWRlYWZ0bFJEdDdsTVJuYzZxbi9xbmd5aTd1UzlEOVYxY0M2N05ZbWhpNU5oc0tHMWRPcCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltNUNTVVJyTFdZM2JXOVJUMEp6YTAxTVdHVXhWa2huUzNRNGFsUXdaV1paUTNCeGRsazJaMU5aV0djaWZYMC5leUpwWVhRaU9qRTNNRFkyTVRFeU5URXNJbVY0Y0NJNk1UY3dOall4TlRJeE1Td2libUptSWpveE56QTJOakV4TWpVeExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRM056SXZZMnhwWlc1MGN5ODJabU16WmpKaU1XTTJaR1psTnpaa0wyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTgxVjNWcFpuZEpRMVJqTWsxSVNrMWxaV1ZaYjFoQklUWm1Zek5tTW1JeFl6WmtabVUzTm1SQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpnMU5pOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMWg2UW1GRVFYRkhUbVZxZVVaeFpHVmhablJzVWtSME4yeE5VbTVqTm5GdUwzRnVaM2xwTjNWVE9VUTVWakZqUXpZM1RsbHRhR2sxVG1oelMwY3haRTl3SWl3aWFuUnBJam9pTXpVM1lqRXdNall0WkRNME55MDBaVEZsTFRneU5UWXRaamM1TlRSbVkyUmlOVFV5SWl3aWJtOXVZMlVpT2lKTlZsSnNaVVpDVmsxSVpHdGtla0pSWVVaWk5HRkZOSGxoYTJ4NFpEQmFXVlY2Um5KUFdHeG9VekZWSWl3aVkyaGhiQ0k2SWpadGNVSk1VVTFuV1hWc2QwOTJXVEpYYmtZMmFtZERlVW81ZUdOMlowbHRJaXdpWTI1bUlqcDdJbXRwWkNJNkltaFpWWFYxVjJ3M1FYVmxibFU0U1ZRMmN6ZFRZMnRaTmkxUWMyZDBNbk50WkhwRFR6RjVaR3BuTVZFaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsV1ZVWnNUVEZHTlZac1JrZFBSVlY2VTFVeFMxTnFWakpYYVRGQ1QxVnNhMUZxUmxWVlYxRTFVbFZzYkU0eWIzaGpNMmN3VVRBMVQwMURTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5SRmt5VFZSRmVVNVVSWE5KYlZZMFkwTkpOazFVWTNkT2FsbDRUMFJSTVUxVGQybGliVXB0U1dwdmVFNTZRVEpPYWtWNFRXcFZlRXhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRrNVdaREZoVjFvelUxVk9WVmw2U2s1VFJYQk9XbGRXYkZkWE9WbFJVMFV5V20xTmVscHFTbWxOVjAweVdrZGFiRTU2V210UlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUUk9WRmwyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE01V1dWclNtaFNSVVo0VWpBMWJHRnViRWRqVjFKc1dWZGFNR0pHU2tWa1JHUnpWRlpLZFZsNlduaGlhVGw0WW0xa05XRlVaREZWZW14RlQxWlplRmt3VFRKT01EVmFZbGRvY0U1Vk5XOWpNSFJJVFZkU1VHTkRTWE5KYlhBd1lWTkpOa2xxVFhkT1ZFcHNUMFJKZUV4WFZUUk5WR2QwVGtSRmVFOVRNRFJPVkVWNFRGUk5NMDFIV21oUFYwa3lUbXBaTVUxNVNYTkpiVFYyWW0xT2JFbHFiMmxVVmxwVFlrZFdSMUZzV2s1VFIxSnlXa2h3UTFWWFJrZFhWRkpvVWxSU05WbFhkSE5sUjFGM1YyeHNWbVZyV25sVU1XaHpZVVpOZUZaVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxFelRucEpkbGt5ZUhCYVZ6VXdZM2s0TWxwdFRYcGFha3BwVFZkTk1scEhXbXhPZWxwclRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTVEppV0VaRFZFWkdUbG94YkRGaVNHUlFaR3hyZVZZeU5VZE9iWEJ1VVROc1MwOVlhR3BrYldSS1lsTkpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsbVVTNXFkVVp0VGxFd01qRk1OVWRIWjFvNVVHTjBXSEU0WkZGdmQzcHJORVZ2WHpCWmRFaE5NWEZxVTJSclJFWm5iRmRuVTNweGVrZHVTR2xJZDJWS2NIQXlNVkZWVmtKSFNsY3lhVTl0YlY4NFlrTllUMUJFUVNJc0ltTnNhV1Z1ZEY5cFpDSTZJbmRwY21WaGNIQTZMeTgxVjNWcFpuZEpRMVJqTWsxSVNrMWxaV1ZaYjFoQklUWm1Zek5tTW1JeFl6WmtabVUzTm1SQWQybHlaUzVqYjIwaUxDSmhjR2xmZG1WeWMybHZiaUk2TlN3aWMyTnZjR1VpT2lKM2FYSmxYMk5zYVdWdWRGOXBaQ0o5LllrV2lrd3VyNm03R1l6bHVSZnNkMWVqejJ6eEtmV3JrOEFzdWxpN2dzUUsyNnhzQnZXS0lsYmNwbGVmYmpSc1JhczBJbThMdV9wWW10TGswbVdmS0FnIn0",
  "signature": "BdAzzdN6Oye-YuaqNBfMS9hdoMO805ZRRi3joAXW7fq2Zrs7kpX4j-yauooLSB-GWiYHOcLByw_mr7tDWmdfAQ"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im5CSURrLWY3bW9RT0Jza01MWGUxVkhnS3Q4alQwZWZZQ3Bxdlk2Z1NZWGcifX0.eyJpYXQiOjE3MDY2MTEyNTEsImV4cCI6MTcwNjYxNTIxMSwibmJmIjoxNzA2NjExMjUxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ3NzIvY2xpZW50cy82ZmMzZjJiMWM2ZGZlNzZkL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly81V3VpZndJQ1RjMk1ISk1lZWVZb1hBITZmYzNmMmIxYzZkZmU3NmRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjg1Ni9hY21lL3dpcmUvY2hhbGxlbmdlL1h6QmFEQXFHTmVqeUZxZGVhZnRsUkR0N2xNUm5jNnFuL3FuZ3lpN3VTOUQ5VjFjQzY3TlltaGk1TmhzS0cxZE9wIiwianRpIjoiMzU3YjEwMjYtZDM0Ny00ZTFlLTgyNTYtZjc5NTRmY2RiNTUyIiwibm9uY2UiOiJNVlJsZUZCVk1IZGtkekJRYUZZNGFFNHlha2x4ZDBaWVV6RnJPWGxoUzFVIiwiY2hhbCI6IjZtcUJMUU1nWXVsd092WTJXbkY2amdDeUo5eGN2Z0ltIiwiY25mIjp7ImtpZCI6ImhZVXV1V2w3QXVlblU4SVQ2czdTY2tZNi1Qc2d0MnNtZHpDTzF5ZGpnMVEifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lWVUZsTTFGNVZsRkdPRVV6U1UxS1NqVjJXaTFCT1Vsa1FqRlVVV1E1UlVsbE4yb3hjM2cwUTA1T01DSjlmUS5leUpwWVhRaU9qRTNNRFkyTVRFeU5URXNJbVY0Y0NJNk1UY3dOall4T0RRMU1Td2libUptSWpveE56QTJOakV4TWpVeExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dk5WZDFhV1ozU1VOVVl6Sk5TRXBOWldWbFdXOVlRU0UyWm1NelpqSmlNV00yWkdabE56WmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STROVFl2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5WWVrSmhSRUZ4UjA1bGFubEdjV1JsWVdaMGJGSkVkRGRzVFZKdVl6WnhiaTl4Ym1kNWFUZDFVemxFT1ZZeFkwTTJOMDVaYldocE5VNW9jMHRITVdSUGNDSXNJbXAwYVNJNklqTXdOVEpsT0RJeExXVTRNVGd0TkRFeE9TMDROVEV4TFRNM01HWmhPV0kyTmpZMU15SXNJbTV2Ym1ObElqb2lUVlpTYkdWR1FsWk5TR1JyWkhwQ1VXRkdXVFJoUlRSNVlXdHNlR1F3V2xsVmVrWnlUMWhzYUZNeFZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEzTnpJdlkyeHBaVzUwY3k4MlptTXpaakppTVdNMlpHWmxOelprTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTJiWEZDVEZGTloxbDFiSGRQZGxreVYyNUdObXBuUTNsS09YaGpkbWRKYlNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5qdUZtTlEwMjFMNUdHZ1o5UGN0WHE4ZFFvd3prNEVvXzBZdEhNMXFqU2RrREZnbFdnU3pxekduSGlId2VKcHAyMVFVVkJHSlcyaU9tbV84YkNYT1BEQSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly81V3VpZndJQ1RjMk1ISk1lZWVZb1hBITZmYzNmMmIxYzZkZmU3NmRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.YkWikwur6m7GYzluRfsd1ejz2zxKfWrk8Asuli7gsQK26xsBvWKIlbcplefbjRsRas0Im8Lu_pYmtLk0mWfKAg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O",
    "nonce": "OVBuSDEyT2tiZHhnSzQyRldwbDZwZWV6TGtNeVdEUXU",
    "typ": "JWT",
    "url": "https://stepca:32856/acme/wire/challenge/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn/qngyi7uS9D9V1cC67NYmhi5NhsKG1dOp"
  }
}
```
#### 18. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32856/acme/wire/directory>;rel="index"
link: <https://stepca:32856/acme/wire/authz/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn>;rel="up"
location: https://stepca:32856/acme/wire/challenge/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn/qngyi7uS9D9V1cC67NYmhi5NhsKG1dOp
replay-nonce: c1hNZVp2S2tGaDVWVURwVXVNSUtSYnMwWXh0NUV3a1U
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32856/acme/wire/challenge/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn/qngyi7uS9D9V1cC67NYmhi5NhsKG1dOp",
  "status": "valid",
  "token": "6mqBLQMgYulwOvY2WnF6jgCyJ9xcvgIm",
  "target": "http://wire.com:24772/clients/6fc3f2b1c6dfe76d/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 19. OAUTH authorization request

```text
code_verifier=MA5hHkPE0M6I4TgvPdk2AV3Ft127-DMRLXG6x0SbVQw&code_challenge=q1QMaOvB-QkPdrdGMFWyGzIYPpcMw1dqtEE_p_zH_BE
```
#### 20. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:15495/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=KVPQQM4t_c8Qx_tUfkQrfQ&code_challenge=q1QMaOvB-QkPdrdGMFWyGzIYPpcMw1dqtEE_p_zH_BE&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A24772%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32856%2Facme%2Fwire%2Fchallenge%2FbdCfUcqQuSnQP1CHr99bVixJhQ445Tex%2FcqdznLhIZAqBVEKx64dzvcUZmxoytZux%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22MEuAFz1BzLyTafdI9BUVLEVYqc7a9oy0.hYUuuWl7AuenU8IT6s7SckY6-Psgt2smdzCO1ydjg1Q%22%7D%7D%7D&nonce=y4itf8NNw7xgv7kBJ601LQ
```

#### 21. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:15495/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=2bb03572-8fcd-47d1-8572-4b4cf5658b6e.6349940c-6aef-4427-9bd7-3b5bfe8a11e1.68ee266c-621a-4a0e-9a23-b288cb4a66f1&code_verifier=MA5hHkPE0M6I4TgvPdk2AV3Ft127-DMRLXG6x0SbVQw&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A24772%2Fcallback
```
#### 22. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUcXRWQVZlYUxLa0tnQU1MeWlFUXlhU2FFUjRqQnRMM2M0QjdndU85RWRJIn0.eyJleHAiOjE3MDY2MTQ5MTIsImlhdCI6MTcwNjYxNDg1MiwiYXV0aF90aW1lIjoxNzA2NjE0ODUyLCJqdGkiOiI4NWZhZWVjMC1hM2M1LTQ5NDgtOGY3OC1hY2Q4NDRmZWRhYmQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI3OTEzY2Q3NS0zYWNmLTQxYzAtODIwYy03NDM2YzljZDczNGYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ5NGl0ZjhOTnc3eGd2N2tCSjYwMUxRIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNDk5NDBjLTZhZWYtNDQyNy05YmQ3LTNiNWJmZThhMTFlMSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0NzcyIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiNjM0OTk0MGMtNmFlZi00NDI3LTliZDctM2I1YmZlOGExMWUxIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.NP_mu77q6JbL0atXqj6DGVcbAzH21lnV8ft48Nhu2pswYLDE8arFBcwvXwlB2CFiuvbtHxh3g3g-sQDc4xCiZDDv7kdudZ8qo048BBMJt87Wi0mTTxXTex__39VUWC_JEXK_R4xih9GrXEyfXVgz3RkskL_QZut-dmIgflXdq1MMl-g4UCBni0Egbxk888oCCpTBiUr_NkD1a58XIHWkToxbFmLtpgQh7KZsEx7KfShfNdyUrzio1qkAo7u-TEM_pOi-zwKjugFeue9KWOUyyYtwMlPB4cCC6cPL2DNwBRyrM9dqD5Cf7o7NWxnKZPMakZD4I6_dyfmzgweayvlDgQ",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUcXRWQVZlYUxLa0tnQU1MeWlFUXlhU2FFUjRqQnRMM2M0QjdndU85RWRJIn0.eyJleHAiOjE3MDY2MTQ5MTIsImlhdCI6MTcwNjYxNDg1MiwiYXV0aF90aW1lIjoxNzA2NjE0ODUyLCJqdGkiOiI4MzBiZTlhNy04OTRmLTQxMzMtODU5YS00MGIwZDkxYzc3ZWQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiI3OTEzY2Q3NS0zYWNmLTQxYzAtODIwYy03NDM2YzljZDczNGYiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ink0aXRmOE5Odzd4Z3Y3a0JKNjAxTFEiLCJzZXNzaW9uX3N0YXRlIjoiNjM0OTk0MGMtNmFlZi00NDI3LTliZDctM2I1YmZlOGExMWUxIiwiYXRfaGFzaCI6IjhKcHhhYjgyMmJNY2t3OEJ5bUhlMGciLCJhY3IiOiIxIiwic2lkIjoiNjM0OTk0MGMtNmFlZi00NDI3LTliZDctM2I1YmZlOGExMWUxIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6Ik1FdUFGejFCekx5VGFmZEk5QlVWTEVWWXFjN2E5b3kwLmhZVXV1V2w3QXVlblU4SVQ2czdTY2tZNi1Qc2d0MnNtZHpDTzF5ZGpnMVEiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9jaGFsbGVuZ2UvYmRDZlVjcVF1U25RUDFDSHI5OWJWaXhKaFE0NDVUZXgvY3Fkem5MaElaQXFCVkVLeDY0ZHp2Y1VabXhveXRadXgiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.g1P1oQQRjrfIFWQpi-mGbHUXQJYfB9lhKYs-Vn588_V5c-7fi1HsJJw59jNTTB9HGffQ8NJJlSW5dOzOe8a0lsUSLjB2JhSUK5i5WCmAWviG9uRke2nCVC6qI2Y5NukwJKggDjHF2YEBIAKlJE1-perhDlMpnnoY8BB9at1_MREtldjkz58XcLNPkK3vj8kVzyWWTjgc9u3DOWtI17KcwrGuJo276NlHV6PHxU-WLgfaCIjhcCV_0Oz6hLaFdUGa-LmjS3StLHJYzgKn3w2h5mzZUIkp9ldR6-UtLxbcv4iXqxVtyZ1j4KrCne_fTlTKoe66LgQ8zmmoYE8hHDlwSA",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjMTJmNDQzYi0yOTg3LTRmYWItODg1Yi02ZDNlNWEyZDFhNTEifQ.eyJleHAiOjE3MDY2MTY2NTIsImlhdCI6MTcwNjYxNDg1MiwianRpIjoiNmRjMWFjNWEtMzE2My00Mjc5LThkM2QtZWIyZThmZDM3ZDlkIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE1NDk1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc3RlciIsInN1YiI6Ijc5MTNjZDc1LTNhY2YtNDFjMC04MjBjLTc0MzZjOWNkNzM0ZiIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ5NGl0ZjhOTnc3eGd2N2tCSjYwMUxRIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNDk5NDBjLTZhZWYtNDQyNy05YmQ3LTNiNWJmZThhMTFlMSIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiI2MzQ5OTQwYy02YWVmLTQ0MjctOWJkNy0zYjViZmU4YTExZTEifQ.FkK9kjLuNTUtjkY6sSHJJ-APHOOtQf6rdVpnTDlZNTI",
  "scope": "openid email profile",
  "session_state": "6349940c-6aef-4427-9bd7-3b5bfe8a11e1",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUcXRWQVZlYUxLa0tnQU1MeWlFUXlhU2FFUjRqQnRMM2M0QjdndU85RWRJIn0.eyJleHAiOjE3MDY2MTQ5MTIsImlhdCI6MTcwNjYxNDg1MiwiYXV0aF90aW1lIjoxNzA2NjE0ODUyLCJqdGkiOiI4NWZhZWVjMC1hM2M1LTQ5NDgtOGY3OC1hY2Q4NDRmZWRhYmQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI3OTEzY2Q3NS0zYWNmLTQxYzAtODIwYy03NDM2YzljZDczNGYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ5NGl0ZjhOTnc3eGd2N2tCSjYwMUxRIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNDk5NDBjLTZhZWYtNDQyNy05YmQ3LTNiNWJmZThhMTFlMSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0NzcyIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiNjM0OTk0MGMtNmFlZi00NDI3LTliZDctM2I1YmZlOGExMWUxIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.NP_mu77q6JbL0atXqj6DGVcbAzH21lnV8ft48Nhu2pswYLDE8arFBcwvXwlB2CFiuvbtHxh3g3g-sQDc4xCiZDDv7kdudZ8qo048BBMJt87Wi0mTTxXTex__39VUWC_JEXK_R4xih9GrXEyfXVgz3RkskL_QZut-dmIgflXdq1MMl-g4UCBni0Egbxk888oCCpTBiUr_NkD1a58XIHWkToxbFmLtpgQh7KZsEx7KfShfNdyUrzio1qkAo7u-TEM_pOi-zwKjugFeue9KWOUyyYtwMlPB4cCC6cPL2DNwBRyrM9dqD5Cf7o7NWxnKZPMakZD4I6_dyfmzgweayvlDgQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUcXRWQVZlYUxL
a0tnQU1MeWlFUXlhU2FFUjRqQnRMM2M0QjdndU85RWRJIn0.eyJleHAiOjE3MDY2
MTQ5MTIsImlhdCI6MTcwNjYxNDg1MiwiYXV0aF90aW1lIjoxNzA2NjE0ODUyLCJq
dGkiOiI4NWZhZWVjMC1hM2M1LTQ5NDgtOGY3OC1hY2Q4NDRmZWRhYmQiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiI3OTEzY2Q3NS0zYWNmLTQxYzAtODIwYy03NDM2YzljZDcz
NGYiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ5NGl0
ZjhOTnc3eGd2N2tCSjYwMUxRIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNDk5NDBjLTZh
ZWYtNDQyNy05YmQ3LTNiNWJmZThhMTFlMSIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjI0NzcyIl0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBw
cm9maWxlIiwic2lkIjoiNjM0OTk0MGMtNmFlZi00NDI3LTliZDctM2I1YmZlOGEx
MWUxIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdp
cmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0
aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.NP_mu77q6JbL0atXqj6
DGVcbAzH21lnV8ft48Nhu2pswYLDE8arFBcwvXwlB2CFiuvbtHxh3g3g-sQDc4xC
iZDDv7kdudZ8qo048BBMJt87Wi0mTTxXTex__39VUWC_JEXK_R4xih9GrXEyfXVg
z3RkskL_QZut-dmIgflXdq1MMl-g4UCBni0Egbxk888oCCpTBiUr_NkD1a58XIHW
kToxbFmLtpgQh7KZsEx7KfShfNdyUrzio1qkAo7u-TEM_pOi-zwKjugFeue9KWOU
yyYtwMlPB4cCC6cPL2DNwBRyrM9dqD5Cf7o7NWxnKZPMakZD4I6_dyfmzgweayvl
DgQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "TqtVAVeaLKkKgAMLyiEQyaSaER4jBtL3c4B7guO9EdI",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:24772"
  ],
  "aud": "account",
  "auth_time": 1706614852,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1706614912,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1706614852,
  "iss": "http://keycloak:15495/realms/master",
  "jti": "85faeec0-a3c5-4948-8f78-acd844fedabd",
  "name": "Alice Smith",
  "nonce": "y4itf8NNw7xgv7kBJ601LQ",
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
  "session_state": "6349940c-6aef-4427-9bd7-3b5bfe8a11e1",
  "sid": "6349940c-6aef-4427-9bd7-3b5bfe8a11e1",
  "sub": "7913cd75-3acf-41c0-820c-7436c9cd734f",
  "typ": "Bearer"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArXg9dCZgTdQdenw+pVRY
YEcS4pkGoaf1T6HhBRuA7Xz++rxSaUEPRYPFdHCwfh18d77RhTsizIxt284qcLNn
qDdy8trzC+gsmP8thZMcvul1ZJA1MrSfDsPpyL7vJwGYv6VOG8GdJKfMVHqTkmJk
3H3xpw73PZTO7SmZekjuokIJOZB8hXcoMvvjXcVJ9IYndhwRhgRLHAqrgFiCxYSs
uboUppqLCo/ntqarnkH7BVNERXFjgrZeN4PUsyM+FV4144rgFN/2lC9ORIpTXy8D
siHU1aqaQUo1Y85YjPUzz81CE4NXfzZACy/PX86pHvLm+/4W7DKETlFGhH7GFPbb
NQIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjMTJmNDQzYi0yOTg3LTRmYWItODg1Yi02ZDNlNWEyZDFhNTEifQ.eyJleHAiOjE3MDY2MTY2NTIsImlhdCI6MTcwNjYxNDg1MiwianRpIjoiNmRjMWFjNWEtMzE2My00Mjc5LThkM2QtZWIyZThmZDM3ZDlkIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE1NDk1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc3RlciIsInN1YiI6Ijc5MTNjZDc1LTNhY2YtNDFjMC04MjBjLTc0MzZjOWNkNzM0ZiIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ5NGl0ZjhOTnc3eGd2N2tCSjYwMUxRIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNDk5NDBjLTZhZWYtNDQyNy05YmQ3LTNiNWJmZThhMTFlMSIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiI2MzQ5OTQwYy02YWVmLTQ0MjctOWJkNy0zYjViZmU4YTExZTEifQ.FkK9kjLuNTUtjkY6sSHJJ-APHOOtQf6rdVpnTDlZNTI)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJjMTJmNDQzYi0y
OTg3LTRmYWItODg1Yi02ZDNlNWEyZDFhNTEifQ.eyJleHAiOjE3MDY2MTY2NTIsI
mlhdCI6MTcwNjYxNDg1MiwianRpIjoiNmRjMWFjNWEtMzE2My00Mjc5LThkM2QtZ
WIyZThmZDM3ZDlkIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE1NDk1L3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc
3RlciIsInN1YiI6Ijc5MTNjZDc1LTNhY2YtNDFjMC04MjBjLTc0MzZjOWNkNzM0Z
iIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ5NGl0Z
jhOTnc3eGd2N2tCSjYwMUxRIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNDk5NDBjLTZhZ
WYtNDQyNy05YmQ3LTNiNWJmZThhMTFlMSIsInNjb3BlIjoib3BlbmlkIGVtYWlsI
HByb2ZpbGUiLCJzaWQiOiI2MzQ5OTQwYy02YWVmLTQ0MjctOWJkNy0zYjViZmU4Y
TExZTEifQ.FkK9kjLuNTUtjkY6sSHJJ-APHOOtQf6rdVpnTDlZNTI
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "c12f443b-2987-4fab-885b-6d3e5a2d1a51",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:15495/realms/master",
  "azp": "wireapp",
  "exp": 1706616652,
  "iat": 1706614852,
  "iss": "http://keycloak:15495/realms/master",
  "jti": "6dc1ac5a-3163-4279-8d3d-eb2e8fd37d9d",
  "nonce": "y4itf8NNw7xgv7kBJ601LQ",
  "scope": "openid email profile",
  "session_state": "6349940c-6aef-4427-9bd7-3b5bfe8a11e1",
  "sid": "6349940c-6aef-4427-9bd7-3b5bfe8a11e1",
  "sub": "7913cd75-3acf-41c0-820c-7436c9cd734f",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArXg9dCZgTdQdenw+pVRY
YEcS4pkGoaf1T6HhBRuA7Xz++rxSaUEPRYPFdHCwfh18d77RhTsizIxt284qcLNn
qDdy8trzC+gsmP8thZMcvul1ZJA1MrSfDsPpyL7vJwGYv6VOG8GdJKfMVHqTkmJk
3H3xpw73PZTO7SmZekjuokIJOZB8hXcoMvvjXcVJ9IYndhwRhgRLHAqrgFiCxYSs
uboUppqLCo/ntqarnkH7BVNERXFjgrZeN4PUsyM+FV4144rgFN/2lC9ORIpTXy8D
siHU1aqaQUo1Y85YjPUzz81CE4NXfzZACy/PX86pHvLm+/4W7DKETlFGhH7GFPbb
NQIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 23. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUcXRWQVZlYUxLa0tnQU1MeWlFUXlhU2FFUjRqQnRMM2M0QjdndU85RWRJIn0.eyJleHAiOjE3MDY2MTQ5MTIsImlhdCI6MTcwNjYxNDg1MiwiYXV0aF90aW1lIjoxNzA2NjE0ODUyLCJqdGkiOiI4MzBiZTlhNy04OTRmLTQxMzMtODU5YS00MGIwZDkxYzc3ZWQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiI3OTEzY2Q3NS0zYWNmLTQxYzAtODIwYy03NDM2YzljZDczNGYiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ink0aXRmOE5Odzd4Z3Y3a0JKNjAxTFEiLCJzZXNzaW9uX3N0YXRlIjoiNjM0OTk0MGMtNmFlZi00NDI3LTliZDctM2I1YmZlOGExMWUxIiwiYXRfaGFzaCI6IjhKcHhhYjgyMmJNY2t3OEJ5bUhlMGciLCJhY3IiOiIxIiwic2lkIjoiNjM0OTk0MGMtNmFlZi00NDI3LTliZDctM2I1YmZlOGExMWUxIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6Ik1FdUFGejFCekx5VGFmZEk5QlVWTEVWWXFjN2E5b3kwLmhZVXV1V2w3QXVlblU4SVQ2czdTY2tZNi1Qc2d0MnNtZHpDTzF5ZGpnMVEiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9jaGFsbGVuZ2UvYmRDZlVjcVF1U25RUDFDSHI5OWJWaXhKaFE0NDVUZXgvY3Fkem5MaElaQXFCVkVLeDY0ZHp2Y1VabXhveXRadXgiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.g1P1oQQRjrfIFWQpi-mGbHUXQJYfB9lhKYs-Vn588_V5c-7fi1HsJJw59jNTTB9HGffQ8NJJlSW5dOzOe8a0lsUSLjB2JhSUK5i5WCmAWviG9uRke2nCVC6qI2Y5NukwJKggDjHF2YEBIAKlJE1-perhDlMpnnoY8BB9at1_MREtldjkz58XcLNPkK3vj8kVzyWWTjgc9u3DOWtI17KcwrGuJo276NlHV6PHxU-WLgfaCIjhcCV_0Oz6hLaFdUGa-LmjS3StLHJYzgKn3w2h5mzZUIkp9ldR6-UtLxbcv4iXqxVtyZ1j4KrCne_fTlTKoe66LgQ8zmmoYE8hHDlwSA)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUcXRWQVZlYUxL
a0tnQU1MeWlFUXlhU2FFUjRqQnRMM2M0QjdndU85RWRJIn0.eyJleHAiOjE3MDY2
MTQ5MTIsImlhdCI6MTcwNjYxNDg1MiwiYXV0aF90aW1lIjoxNzA2NjE0ODUyLCJq
dGkiOiI4MzBiZTlhNy04OTRmLTQxMzMtODU5YS00MGIwZDkxYzc3ZWQiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiI3OTEzY2Q3NS0zYWNmLTQxYzAtODIwYy03NDM2YzljZDcz
NGYiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ink0aXRmOE5O
dzd4Z3Y3a0JKNjAxTFEiLCJzZXNzaW9uX3N0YXRlIjoiNjM0OTk0MGMtNmFlZi00
NDI3LTliZDctM2I1YmZlOGExMWUxIiwiYXRfaGFzaCI6IjhKcHhhYjgyMmJNY2t3
OEJ5bUhlMGciLCJhY3IiOiIxIiwic2lkIjoiNjM0OTk0MGMtNmFlZi00NDI3LTli
ZDctM2I1YmZlOGExMWUxIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBh
bGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6Ik1FdUFGejFCekx5VGFmZEk5
QlVWTEVWWXFjN2E5b3kwLmhZVXV1V2w3QXVlblU4SVQ2czdTY2tZNi1Qc2d0MnNt
ZHpDTzF5ZGpnMVEiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0
dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9jaGFsbGVuZ2UvYmRDZlVjcVF1
U25RUDFDSHI5OWJWaXhKaFE0NDVUZXgvY3Fkem5MaElaQXFCVkVLeDY0ZHp2Y1Va
bXhveXRadXgiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNt
aXRoQHdpcmUuY29tIn0.g1P1oQQRjrfIFWQpi-mGbHUXQJYfB9lhKYs-Vn588_V5
c-7fi1HsJJw59jNTTB9HGffQ8NJJlSW5dOzOe8a0lsUSLjB2JhSUK5i5WCmAWviG
9uRke2nCVC6qI2Y5NukwJKggDjHF2YEBIAKlJE1-perhDlMpnnoY8BB9at1_MREt
ldjkz58XcLNPkK3vj8kVzyWWTjgc9u3DOWtI17KcwrGuJo276NlHV6PHxU-WLgfa
CIjhcCV_0Oz6hLaFdUGa-LmjS3StLHJYzgKn3w2h5mzZUIkp9ldR6-UtLxbcv4iX
qxVtyZ1j4KrCne_fTlTKoe66LgQ8zmmoYE8hHDlwSA
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "TqtVAVeaLKkKgAMLyiEQyaSaER4jBtL3c4B7guO9EdI",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32856/acme/wire/challenge/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex/cqdznLhIZAqBVEKx64dzvcUZmxoytZux",
  "acr": "1",
  "at_hash": "8Jpxab822bMckw8BymHe0g",
  "aud": "wireapp",
  "auth_time": 1706614852,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1706614912,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1706614852,
  "iss": "http://keycloak:15495/realms/master",
  "jti": "830be9a7-894f-4133-859a-40b0d91c77ed",
  "keyauth": "MEuAFz1BzLyTafdI9BUVLEVYqc7a9oy0.hYUuuWl7AuenU8IT6s7SckY6-Psgt2smdzCO1ydjg1Q",
  "name": "Alice Smith",
  "nonce": "y4itf8NNw7xgv7kBJ601LQ",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "session_state": "6349940c-6aef-4427-9bd7-3b5bfe8a11e1",
  "sid": "6349940c-6aef-4427-9bd7-3b5bfe8a11e1",
  "sub": "7913cd75-3acf-41c0-820c-7436c9cd734f",
  "typ": "ID"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArXg9dCZgTdQdenw+pVRY
YEcS4pkGoaf1T6HhBRuA7Xz++rxSaUEPRYPFdHCwfh18d77RhTsizIxt284qcLNn
qDdy8trzC+gsmP8thZMcvul1ZJA1MrSfDsPpyL7vJwGYv6VOG8GdJKfMVHqTkmJk
3H3xpw73PZTO7SmZekjuokIJOZB8hXcoMvvjXcVJ9IYndhwRhgRLHAqrgFiCxYSs
uboUppqLCo/ntqarnkH7BVNERXFjgrZeN4PUsyM+FV4144rgFN/2lC9ORIpTXy8D
siHU1aqaQUo1Y85YjPUzz81CE4NXfzZACy/PX86pHvLm+/4W7DKETlFGhH7GFPbb
NQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32856/acme/wire/challenge/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex/cqdznLhIZAqBVEKx64dzvcUZmxoytZux
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9hY2NvdW50L1gwTno2RkJzWHNESTNvV21TbnBkSXNCZWdMUldIdzJPIiwidHlwIjoiSldUIiwibm9uY2UiOiJjMWhOWlZwMlMydEdhRFZXVlVSd1ZYVk5TVXRTWW5Nd1dYaDBOVVYzYTFVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL2NoYWxsZW5nZS9iZENmVWNxUXVTblFQMUNIcjk5YlZpeEpoUTQ0NVRleC9jcWR6bkxoSVpBcUJWRUt4NjRkenZjVVpteG95dFp1eCJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSlVjWFJXUVZabFlVeExhMHRuUVUxTWVXbEZVWGxoVTJGRlVqUnFRblJNTTJNMFFqZG5kVTg1UldSSkluMC5leUpsZUhBaU9qRTNNRFkyTVRRNU1USXNJbWxoZENJNk1UY3dOall4TkRnMU1pd2lZWFYwYUY5MGFXMWxJam94TnpBMk5qRTBPRFV5TENKcWRHa2lPaUk0TXpCaVpUbGhOeTA0T1RSbUxUUXhNek10T0RVNVlTMDBNR0l3WkRreFl6YzNaV1FpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNVFUwT1RVdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSTNPVEV6WTJRM05TMHpZV05tTFRReFl6QXRPREl3WXkwM05ETTJZemxqWkRjek5HWWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJbmswYVhSbU9FNU9kemQ0WjNZM2EwSktOakF4VEZFaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaU5qTTBPVGswTUdNdE5tRmxaaTAwTkRJM0xUbGlaRGN0TTJJMVltWmxPR0V4TVdVeElpd2lZWFJmYUdGemFDSTZJamhLY0hoaFlqZ3lNbUpOWTJ0M09FSjViVWhsTUdjaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaU5qTTBPVGswTUdNdE5tRmxaaTAwTkRJM0xUbGlaRGN0TTJJMVltWmxPR0V4TVdVeElpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lhMlY1WVhWMGFDSTZJazFGZFVGR2VqRkNla3g1VkdGbVpFazVRbFZXVEVWV1dYRmpOMkU1YjNrd0xtaFpWWFYxVjJ3M1FYVmxibFU0U1ZRMmN6ZFRZMnRaTmkxUWMyZDBNbk50WkhwRFR6RjVaR3BuTVZFaUxDSm5hWFpsYmw5dVlXMWxJam9pUVd4cFkyVWlMQ0poWTIxbFgyRjFaQ0k2SW1oMGRIQnpPaTh2YzNSbGNHTmhPak15T0RVMkwyRmpiV1V2ZDJseVpTOWphR0ZzYkdWdVoyVXZZbVJEWmxWamNWRjFVMjVSVURGRFNISTVPV0pXYVhoS2FGRTBORFZVWlhndlkzRmtlbTVNYUVsYVFYRkNWa1ZMZURZMFpIcDJZMVZhYlhodmVYUmFkWGdpTENKbVlXMXBiSGxmYm1GdFpTSTZJbE50YVhSb0lpd2laVzFoYVd3aU9pSmhiR2xqWlhOdGFYUm9RSGRwY21VdVkyOXRJbjAuZzFQMW9RUVJqcmZJRldRcGktbUdiSFVYUUpZZkI5bGhLWXMtVm41ODhfVjVjLTdmaTFIc0pKdzU5ak5UVEI5SEdmZlE4TkpKbFNXNWRPek9lOGEwbHNVU0xqQjJKaFNVSzVpNVdDbUFXdmlHOXVSa2UybkNWQzZxSTJZNU51a3dKS2dnRGpIRjJZRUJJQUtsSkUxLXBlcmhEbE1wbm5vWThCQjlhdDFfTVJFdGxkamt6NThYY0xOUGtLM3ZqOGtWenlXV1RqZ2M5dTNET1d0STE3S2N3ckd1Sm8yNzZObEhWNlBIeFUtV0xnZmFDSWpoY0NWXzBPejZoTGFGZFVHYS1MbWpTM1N0TEhKWXpnS24zdzJoNW16WlVJa3A5bGRSNi1VdEx4YmN2NGlYcXhWdHlaMWo0S3JDbmVfZlRsVEtvZTY2TGdROHptbW9ZRThoSERsd1NBIn0",
  "signature": "slhr1BGybxNHJxOZKKPpUeKM4ioyfmX12I-Dli3v3lklkC0YBUqh67Pbspl-70DM2YIBPFZrMXq4W9LezQrPAA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJUcXRWQVZlYUxLa0tnQU1MeWlFUXlhU2FFUjRqQnRMM2M0QjdndU85RWRJIn0.eyJleHAiOjE3MDY2MTQ5MTIsImlhdCI6MTcwNjYxNDg1MiwiYXV0aF90aW1lIjoxNzA2NjE0ODUyLCJqdGkiOiI4MzBiZTlhNy04OTRmLTQxMzMtODU5YS00MGIwZDkxYzc3ZWQiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTU0OTUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiI3OTEzY2Q3NS0zYWNmLTQxYzAtODIwYy03NDM2YzljZDczNGYiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ink0aXRmOE5Odzd4Z3Y3a0JKNjAxTFEiLCJzZXNzaW9uX3N0YXRlIjoiNjM0OTk0MGMtNmFlZi00NDI3LTliZDctM2I1YmZlOGExMWUxIiwiYXRfaGFzaCI6IjhKcHhhYjgyMmJNY2t3OEJ5bUhlMGciLCJhY3IiOiIxIiwic2lkIjoiNjM0OTk0MGMtNmFlZi00NDI3LTliZDctM2I1YmZlOGExMWUxIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6Ik1FdUFGejFCekx5VGFmZEk5QlVWTEVWWXFjN2E5b3kwLmhZVXV1V2w3QXVlblU4SVQ2czdTY2tZNi1Qc2d0MnNtZHpDTzF5ZGpnMVEiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9jaGFsbGVuZ2UvYmRDZlVjcVF1U25RUDFDSHI5OWJWaXhKaFE0NDVUZXgvY3Fkem5MaElaQXFCVkVLeDY0ZHp2Y1VabXhveXRadXgiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.g1P1oQQRjrfIFWQpi-mGbHUXQJYfB9lhKYs-Vn588_V5c-7fi1HsJJw59jNTTB9HGffQ8NJJlSW5dOzOe8a0lsUSLjB2JhSUK5i5WCmAWviG9uRke2nCVC6qI2Y5NukwJKggDjHF2YEBIAKlJE1-perhDlMpnnoY8BB9at1_MREtldjkz58XcLNPkK3vj8kVzyWWTjgc9u3DOWtI17KcwrGuJo276NlHV6PHxU-WLgfaCIjhcCV_0Oz6hLaFdUGa-LmjS3StLHJYzgKn3w2h5mzZUIkp9ldR6-UtLxbcv4iXqxVtyZ1j4KrCne_fTlTKoe66LgQ8zmmoYE8hHDlwSA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O",
    "nonce": "c1hNZVp2S2tGaDVWVURwVXVNSUtSYnMwWXh0NUV3a1U",
    "typ": "JWT",
    "url": "https://stepca:32856/acme/wire/challenge/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex/cqdznLhIZAqBVEKx64dzvcUZmxoytZux"
  }
}
```
#### 24. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32856/acme/wire/directory>;rel="index"
link: <https://stepca:32856/acme/wire/authz/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex>;rel="up"
location: https://stepca:32856/acme/wire/challenge/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex/cqdznLhIZAqBVEKx64dzvcUZmxoytZux
replay-nonce: Q3I1VmE4SXNYaTBjN1RTZVMzOHJCaXFhTmF1TVdwbFQ
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32856/acme/wire/challenge/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex/cqdznLhIZAqBVEKx64dzvcUZmxoytZux",
  "status": "valid",
  "token": "MEuAFz1BzLyTafdI9BUVLEVYqc7a9oy0",
  "target": "http://keycloak:15495/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 25. verify the status of the order
```http request
POST https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9hY2NvdW50L1gwTno2RkJzWHNESTNvV21TbnBkSXNCZWdMUldIdzJPIiwidHlwIjoiSldUIiwibm9uY2UiOiJRM0kxVm1FNFNYTllhVEJqTjFSVFpWTXpPSEpDYVhGaFRtRjFUVmR3YkZRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL29yZGVyL0IwMWxxVnNMSkxINnNoczJZOWF6WWVQMXVOZ1RzbWs0In0",
  "payload": "",
  "signature": "3gxUzgtyIxzVviNpKzfnwvuv133NhjPjxcbx4j4Vr7qjXWLLIkddjnBY5mEvFcV2z-B6B9Z72SKBJpuqjw2RAw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O",
    "nonce": "Q3I1VmE4SXNYaTBjN1RTZVMzOHJCaXFhTmF1TVdwbFQ",
    "typ": "JWT",
    "url": "https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4"
  }
}
```
#### 26. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32856/acme/wire/directory>;rel="index"
location: https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4
replay-nonce: V21NMll6ZWh0S2JjekVYN2h6OUtsUE82dzFzcWpPZWY
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://5WuifwICTc2MHJMeeeYoXA!6fc3f2b1c6dfe76d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32856/acme/wire/authz/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn",
    "https://stepca:32856/acme/wire/authz/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex"
  ],
  "expires": "2024-01-31T11:40:51Z",
  "notBefore": "2024-01-30T11:40:51.861619Z",
  "notAfter": "2034-01-27T11:40:51.861619Z"
}
```
#### 27. create a CSR and call finalize url
```http request
POST https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9hY2NvdW50L1gwTno2RkJzWHNESTNvV21TbnBkSXNCZWdMUldIdzJPIiwidHlwIjoiSldUIiwibm9uY2UiOiJWMjFOTWxsNlpXaDBTMkpqZWtWWU4yaDZPVXRzVUU4MmR6RnpjV3BQWldZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL29yZGVyL0IwMWxxVnNMSkxINnNoczJZOWF6WWVQMXVOZ1RzbWs0L2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTE5NRlNYTmtOV1I5T0xzNXFqbkhLUGw2ZU1UcjRTLWo2MU1xa2hZNzJGaW9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2TlZkMWFXWjNTVU5VWXpKTlNFcE5aV1ZsV1c5WVFTRTJabU16WmpKaU1XTTJaR1psTnpaa1FIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFCaHY0N2xVMmN3SkZ3NjIzdk5TM0FuOU4zcUFrOVUzb1lweWdWcnY4ZXl6OVdjMG1lUzZUX0lldU9pSzlqZU45YlFRT0F0cElBMDVqcDNxVlJHX2RRSiJ9",
  "signature": "0bMhUKTOPtm1bhbsx4tnKoIw26BnKpa_5P3a49ETT-7Px9v_cHkPzqya14fE_bQvj2cNPBsRw7F6bApE2w-WCw"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhALNMFSXNkNWR9OLs5qjnHKPl6eMTr4S-j61MqkhY72FioHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vNVd1aWZ3SUNUYzJNSEpNZWVlWW9YQSE2ZmMzZjJiMWM2ZGZlNzZkQHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQBhv47lU2cwJFw623vNS3An9N3qAk9U3oYpygVrv8eyz9Wc0meS6T_IeuOiK9jeN9bQQOAtpIA05jp3qVRG_dQJ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O",
    "nonce": "V21NMll6ZWh0S2JjekVYN2h6OUtsUE82dzFzcWpPZWY",
    "typ": "JWT",
    "url": "https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhALNMFSXNkNWR9OLs5qjnHKPl6eMTr4S+
j61MqkhY72FioHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vNVd1aWZ3SUNUYzJNSEpNZWVlWW9YQSE2ZmMzZjJiMWM2ZGZlNzZkQHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQBh
v47lU2cwJFw623vNS3An9N3qAk9U3oYpygVrv8eyz9Wc0meS6T/IeuOiK9jeN9bQ
QOAtpIA05jp3qVRG/dQJ
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
                    b3:4c:15:25:cd:90:d5:91:f4:e2:ec:e6:a8:e7:1c:
                    a3:e5:e9:e3:13:af:84:be:8f:ad:4c:aa:48:58:ef:
                    61:62
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://5WuifwICTc2MHJMeeeYoXA!6fc3f2b1c6dfe76d@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        61:bf:8e:e5:53:67:30:24:5c:3a:db:7b:cd:4b:70:27:f4:dd:
        ea:02:4f:54:de:86:29:ca:05:6b:bf:c7:b2:cf:d5:9c:d2:67:
        92:e9:3f:c8:7a:e3:a2:2b:d8:de:37:d6:d0:40:e0:2d:a4:80:
        34:e6:3a:77:a9:54:46:fd:d4:09

```

#### 28. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32856/acme/wire/directory>;rel="index"
location: https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4
replay-nonce: aGNnbjB3QTlzZndCY3p1eWdhY29GcmFiWDgyRElsQkw
```
```json
{
  "certificate": "https://stepca:32856/acme/wire/certificate/uvYjHHYIdeuFDAJGTZXYzWRpywOsWxMZ",
  "status": "valid",
  "finalize": "https://stepca:32856/acme/wire/order/B01lqVsLJLH6shs2Y9azYeP1uNgTsmk4/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://5WuifwICTc2MHJMeeeYoXA!6fc3f2b1c6dfe76d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32856/acme/wire/authz/XzBaDAqGNejyFqdeaftlRDt7lMRnc6qn",
    "https://stepca:32856/acme/wire/authz/bdCfUcqQuSnQP1CHr99bVixJhQ445Tex"
  ],
  "expires": "2024-01-31T11:40:51Z",
  "notBefore": "2024-01-30T11:40:51.861619Z",
  "notAfter": "2034-01-27T11:40:51.861619Z"
}
```
#### 29. fetch the certificate
```http request
POST https://stepca:32856/acme/wire/certificate/uvYjHHYIdeuFDAJGTZXYzWRpywOsWxMZ
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODU2L2FjbWUvd2lyZS9hY2NvdW50L1gwTno2RkJzWHNESTNvV21TbnBkSXNCZWdMUldIdzJPIiwidHlwIjoiSldUIiwibm9uY2UiOiJhR05uYmpCM1FUbHpabmRDWTNwMWVXZGhZMjlHY21GaVdEZ3lSRWxzUWt3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4NTYvYWNtZS93aXJlL2NlcnRpZmljYXRlL3V2WWpISFlJZGV1RkRBSkdUWlhZeldScHl3T3NXeE1aIn0",
  "payload": "",
  "signature": "9EwgZzIYZQA627lRiVtlLm_SX9FE9ZgZveVDW_1IfWydO4avyvyYj5FAHPiqVpJ2OStdUXC-VsbIRh7nldppAg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32856/acme/wire/account/X0Nz6FBsXsDI3oWmSnpdIsBegLRWHw2O",
    "nonce": "aGNnbjB3QTlzZndCY3p1eWdhY29GcmFiWDgyRElsQkw",
    "typ": "JWT",
    "url": "https://stepca:32856/acme/wire/certificate/uvYjHHYIdeuFDAJGTZXYzWRpywOsWxMZ"
  }
}
```
#### 30. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32856/acme/wire/directory>;rel="index"
replay-nonce: TjJ0Z2s0WjhuRkl6V3hlbzg3cGxBcHg0RURGSkF6bks
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAcCgAwIBAgIRAJURNdzVyqsIFpXiqXsdjWgwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMTMwMTE0MDUxWhcNMzQwMTI3MTE0MDUxWjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCzTBUlzZDVkfTi7Oao\n5xyj5enjE6+Evo+tTKpIWO9hYqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFIaBRzchz29nAg3eZIHhv09mbyLDMB8G\nA1UdIwQYMBaAFGzNE2+03MJ0G15s9x5vM6KSGrbAMGkGA1UdEQRiMGCGIHdpcmVh\ncHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vNVd1aWZ3SUNU\nYzJNSEpNZWVlWW9YQSUyMTZmYzNmMmIxYzZkZmU3NmRAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIBNyd32N\nbZpg9x75vuI36vnR7r5rLj4RN3Q0QkkYvAbrAiEA57P4cItYZcoSMHV5dtC9naym\n65z++/G4iFOSYPya8y4=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV6gAwIBAgIQMjdcLIo3foVBOfTpVQcKcDAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTMwMTE0\nMDUwWhcNMzQwMTI3MTE0MDUwWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOjM\nlRB9Dr+frDtLZF5VWf/XZ7/KnBj+gTZ/C2/15xd7cu8FR3fkv9PtWeA6+bM0ev6u\n3lcy75KGqozJDT5NLCmjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBRszRNvtNzCdBtebPcebzOikhq2wDAfBgNVHSMEGDAW\ngBRI5yJdhpSPmdXFf/ENSY07hTOVNDAKBggqhkjOPQQDAgNIADBFAiEAuAntqNmF\nj+p71D2X5qETd7oh+78xgT3lCxNIgAHit2cCIGV54SF6p4KA8majLONeuUGO7nw1\nTPxP2Vgq5Bp3y7zC\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRAJURNdzVyqsIFpXiqXsdjWgwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMTMwMTE0MDUxWhcNMzQwMTI3MTE0MDUxWjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCzTBUlzZDVkfTi7Oao
5xyj5enjE6+Evo+tTKpIWO9hYqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFIaBRzchz29nAg3eZIHhv09mbyLDMB8G
A1UdIwQYMBaAFGzNE2+03MJ0G15s9x5vM6KSGrbAMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vNVd1aWZ3SUNU
YzJNSEpNZWVlWW9YQSUyMTZmYzNmMmIxYzZkZmU3NmRAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIBNyd32N
bZpg9x75vuI36vnR7r5rLj4RN3Q0QkkYvAbrAiEA57P4cItYZcoSMHV5dtC9naym
65z++/G4iFOSYPya8y4=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            95:11:35:dc:d5:ca:ab:08:16:95:e2:a9:7b:1d:8d:68
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan 30 11:40:51 2024 GMT
            Not After : Jan 27 11:40:51 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    b3:4c:15:25:cd:90:d5:91:f4:e2:ec:e6:a8:e7:1c:
                    a3:e5:e9:e3:13:af:84:be:8f:ad:4c:aa:48:58:ef:
                    61:62
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                86:81:47:37:21:CF:6F:67:02:0D:DE:64:81:E1:BF:4F:66:6F:22:C3
            X509v3 Authority Key Identifier: 
                6C:CD:13:6F:B4:DC:C2:74:1B:5E:6C:F7:1E:6F:33:A2:92:1A:B6:C0
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://5WuifwICTc2MHJMeeeYoXA%216fc3f2b1c6dfe76d@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:13:72:77:7d:8d:6d:9a:60:f7:1e:f9:be:e2:37:
        ea:f9:d1:ee:be:6b:2e:3e:11:37:74:34:42:49:18:bc:06:eb:
        02:21:00:e7:b3:f8:70:8b:58:65:ca:12:30:75:79:76:d0:bd:
        9d:ac:a6:eb:9c:fe:fb:f1:b8:88:53:92:60:fc:9a:f3:2e

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQMjdcLIo3foVBOfTpVQcKcDAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTMwMTE0
MDUwWhcNMzQwMTI3MTE0MDUwWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOjM
lRB9Dr+frDtLZF5VWf/XZ7/KnBj+gTZ/C2/15xd7cu8FR3fkv9PtWeA6+bM0ev6u
3lcy75KGqozJDT5NLCmjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBRszRNvtNzCdBtebPcebzOikhq2wDAfBgNVHSMEGDAW
gBRI5yJdhpSPmdXFf/ENSY07hTOVNDAKBggqhkjOPQQDAgNIADBFAiEAuAntqNmF
j+p71D2X5qETd7oh+78xgT3lCxNIgAHit2cCIGV54SF6p4KA8majLONeuUGO7nw1
TPxP2Vgq5Bp3y7zC
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            32:37:5c:2c:8a:37:7e:85:41:39:f4:e9:55:07:0a:70
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 30 11:40:50 2024 GMT
            Not After : Jan 27 11:40:50 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:e8:cc:95:10:7d:0e:bf:9f:ac:3b:4b:64:5e:55:
                    59:ff:d7:67:bf:ca:9c:18:fe:81:36:7f:0b:6f:f5:
                    e7:17:7b:72:ef:05:47:77:e4:bf:d3:ed:59:e0:3a:
                    f9:b3:34:7a:fe:ae:de:57:32:ef:92:86:aa:8c:c9:
                    0d:3e:4d:2c:29
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                6C:CD:13:6F:B4:DC:C2:74:1B:5E:6C:F7:1E:6F:33:A2:92:1A:B6:C0
            X509v3 Authority Key Identifier: 
                48:E7:22:5D:86:94:8F:99:D5:C5:7F:F1:0D:49:8D:3B:85:33:95:34
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:b8:09:ed:a8:d9:85:8f:ea:7b:d4:3d:97:e6:
        a1:13:77:ba:21:fb:bf:31:81:3d:e5:0b:13:48:80:01:e2:b7:
        67:02:20:65:79:e1:21:7a:a7:82:80:f2:66:a3:2c:e3:5e:b9:
        41:8e:ee:7c:35:4c:fc:4f:d9:58:2a:e4:1a:77:cb:bc:c2

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIQe6b6u7cLlgMU4rBdZqNGrzAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTMwMTE0
MDQ5WhcNMzQwMTI3MTE0MDQ5WjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3
aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARVkfejQwpAXoNo
nmMlPIp4F4d20i0Wlg0VkqAH8JxiV2K8UVRrZIDaHQoChNNxcQDeGev6RIc2uXlH
8ioHmFgJo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd
BgNVHQ4EFgQUSOciXYaUj5nVxX/xDUmNO4UzlTQwCgYIKoZIzj0EAwIDSAAwRQIg
VyXXroiPM5mkMfA+2kXSbdQhtp+b1CkQyEAHF4nX0FYCIQCfIZq33t1P/t/cikfP
hJ17DvmGWFgDe2baASp8blntpg==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7b:a6:fa:bb:b7:0b:96:03:14:e2:b0:5d:66:a3:46:af
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 30 11:40:49 2024 GMT
            Not After : Jan 27 11:40:49 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:55:91:f7:a3:43:0a:40:5e:83:68:9e:63:25:3c:
                    8a:78:17:87:76:d2:2d:16:96:0d:15:92:a0:07:f0:
                    9c:62:57:62:bc:51:54:6b:64:80:da:1d:0a:02:84:
                    d3:71:71:00:de:19:eb:fa:44:87:36:b9:79:47:f2:
                    2a:07:98:58:09
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                48:E7:22:5D:86:94:8F:99:D5:C5:7F:F1:0D:49:8D:3B:85:33:95:34
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:57:25:d7:ae:88:8f:33:99:a4:31:f0:3e:da:45:
        d2:6d:d4:21:b6:9f:9b:d4:29:10:c8:40:07:17:89:d7:d0:56:
        02:21:00:9f:21:9a:b7:de:dd:4f:fe:df:dc:8a:47:cf:84:9d:
        7b:0e:f9:86:58:58:03:7b:66:da:01:2a:7c:6e:59:ed:a6

```

openssl verify chain ✅