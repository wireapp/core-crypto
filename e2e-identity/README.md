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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/781baa183806b54d/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc/6iDpuGVpuih5Uv2LCGK4WfMRyVduTTLs
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV/EC9cx2K9EV8tfZmDkeklxb8naEQS38mQ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/JAj8oVqst0yDBIAz3sNpmBLXsjxyLn46
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32817/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32817/acme/wire/new-nonce",
  "newAccount": "https://stepca:32817/acme/wire/new-account",
  "newOrder": "https://stepca:32817/acme/wire/new-order",
  "revokeCert": "https://stepca:32817/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32817/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32817/acme/wire/directory>;rel="index"
replay-nonce: dGtNQkNtQ0NaRk96VEg0bmlyS25PcDNJUlcza2dsMnE
```
```text
dGtNQkNtQ0NaRk96VEg0bmlyS25PcDNJUlcza2dsMnE
```
#### 5. create a new account
```http request
POST https://stepca:32817/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InlfTDZuWHlNN0hsNU1nR3c2WXE1Mm45Rl83WDNveFQ4NXBxVFIyTld6ZzgifSwibm9uY2UiOiJkR3ROUWtOdFEwTmFSazk2VkVnMGJtbHlTMjVQY0ROSlVsY3phMmRzTW5FIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "90gsWgnhUheJxqE5mld1oOZd_8ina6Pq9M-r7tbudOv5MZpRMtdYJIdlK7W3GivIm1kT69fo0DvyMYdmfhn9Bg"
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
      "x": "y_L6nXyM7Hl5MgGw6Yq52n9F_7X3oxT85pqTR2NWzg8"
    },
    "nonce": "dGtNQkNtQ0NaRk96VEg0bmlyS25PcDNJUlcza2dsMnE",
    "typ": "JWT",
    "url": "https://stepca:32817/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32817/acme/wire/directory>;rel="index"
location: https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e
replay-nonce: MkczYTlVSVJGTzFXa3FTMHRXODk0bWFycTYwQ1ZjR2g
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32817/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9hY2NvdW50L0FKRXNLWEpDdnpVSXFRRlQ0NlkxR1M0dHIwbEpTcjllIiwidHlwIjoiSldUIiwibm9uY2UiOiJNa2N6WVRsVlNWSkdUekZYYTNGVE1IUlhPRGswYldGeWNUWXdRMVpqUjJnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9id1pKU3cyZVFMSzRxRzlHRW9GbGpnITc4MWJhYTE4MzgwNmI1NGRAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMi0yNlQwOTozNDozNy43MDIwMjVaIiwibm90QWZ0ZXIiOiIyMDM0LTAyLTIzVDA5OjM0OjM3LjcwMjAyNVoifQ",
  "signature": "aHd9uFk-ty7LvWAUCGeVP0nMs9BEcft5bfo4vkjkUCFKdFBXJKbEyUKlFmzGx9zPyWFb2HByUXIQoQ9JeeuxDg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://bwZJSw2eQLK4qG9GEoFljg!781baa183806b54d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2034-02-23T09:34:37.702025Z",
    "notBefore": "2024-02-26T09:34:37.702025Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e",
    "nonce": "MkczYTlVSVJGTzFXa3FTMHRXODk0bWFycTYwQ1ZjR2g",
    "typ": "JWT",
    "url": "https://stepca:32817/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32817/acme/wire/directory>;rel="index"
location: https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx
replay-nonce: QjR3UGlDWVJVRGtFcEQ1UEpreE41YmVJVjFCeDVtbmI
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://bwZJSw2eQLK4qG9GEoFljg!781baa183806b54d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32817/acme/wire/authz/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc",
    "https://stepca:32817/acme/wire/authz/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV"
  ],
  "expires": "2024-02-27T09:34:37Z",
  "notBefore": "2024-02-26T09:34:37.702025Z",
  "notAfter": "2034-02-23T09:34:37.702025Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32817/acme/wire/authz/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9hY2NvdW50L0FKRXNLWEpDdnpVSXFRRlQ0NlkxR1M0dHIwbEpTcjllIiwidHlwIjoiSldUIiwibm9uY2UiOiJRalIzVUdsRFdWSlZSR3RGY0VRMVVFcHJlRTQxWW1WSlZqRkNlRFZ0Ym1JIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL2F1dGh6L2NPNWxEZ0d2Y1RNdjFhaFRHUmQ0SjEwc0tWbXNwbFljIn0",
  "payload": "",
  "signature": "3XzXRaqrLX1O_O57dRwwA4Ml3QltiGikSjZQTUCQ89sNAQomuDmhPL_is10YxLexwdEXBxZK1_cli3rAe_qMAA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e",
    "nonce": "QjR3UGlDWVJVRGtFcEQ1UEpreE41YmVJVjFCeDVtbmI",
    "typ": "JWT",
    "url": "https://stepca:32817/acme/wire/authz/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32817/acme/wire/directory>;rel="index"
location: https://stepca:32817/acme/wire/authz/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc
replay-nonce: ZnpET21NNGt4VThHVlB0VTFYcmNwTVRZdkgyNTFITkk
```
```json
{
  "status": "pending",
  "expires": "2024-02-27T09:34:37Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32817/acme/wire/challenge/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc/6iDpuGVpuih5Uv2LCGK4WfMRyVduTTLs",
      "status": "pending",
      "token": "HVh2k5vkteXwhNSMn7tmwdTKL03f8KlD",
      "target": "http://wire.com:16957/clients/781baa183806b54d/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://bwZJSw2eQLK4qG9GEoFljg!781baa183806b54d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:32817/acme/wire/authz/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9hY2NvdW50L0FKRXNLWEpDdnpVSXFRRlQ0NlkxR1M0dHIwbEpTcjllIiwidHlwIjoiSldUIiwibm9uY2UiOiJabnBFVDIxTk5HdDRWVGhIVmxCMFZURlljbU53VFZSWmRrZ3lOVEZJVGtrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL2F1dGh6L2pmYlZ0d25JS1B6Q0diNHVsUnBWajVNb3lrZThMYXRWIn0",
  "payload": "",
  "signature": "mvkX2M1GdP-LhiigQFJL008aUoey39Q2JVciouu5lu45_aeLu2gt3wmtRJsUr_7SZZ_KvKroAK79RiJ4q2OXBw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e",
    "nonce": "ZnpET21NNGt4VThHVlB0VTFYcmNwTVRZdkgyNTFITkk",
    "typ": "JWT",
    "url": "https://stepca:32817/acme/wire/authz/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV"
  }
}
```
#### 11. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32817/acme/wire/directory>;rel="index"
location: https://stepca:32817/acme/wire/authz/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV
replay-nonce: aVU3UGxJWkEyZ3FPemVhUm1QVmc1ZW9kTGVySGdDdDk
```
```json
{
  "status": "pending",
  "expires": "2024-02-27T09:34:37Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32817/acme/wire/challenge/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV/EC9cx2K9EV8tfZmDkeklxb8naEQS38mQ",
      "status": "pending",
      "token": "6FQSO5JkCuRZRPhVmi7XA9NolB1TfsDo",
      "target": "http://keycloak:16327/realms/master"
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
GET http://wire.com:16957/clients/token/nonce
```
#### 13. get wire-server nonce
```http request
200

```
```text
YnQxdFpIaGJYMnE1b3JkaVY1N2lXQW9XcmVHblZpRjM
```
#### 14. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieV9MNm5YeU03SGw1TWdHdzZZcTUybjlGXzdYM294VDg1cHFUUjJOV3pnOCJ9fQ.eyJpYXQiOjE3MDg5MzY0NzcsImV4cCI6MTcwODk0MzY3NywibmJmIjoxNzA4OTM2NDc3LCJzdWIiOiJ3aXJlYXBwOi8vYndaSlN3MmVRTEs0cUc5R0VvRmxqZyE3ODFiYWExODM4MDZiNTRkQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL2NoYWxsZW5nZS9jTzVsRGdHdmNUTXYxYWhUR1JkNEoxMHNLVm1zcGxZYy82aURwdUdWcHVpaDVVdjJMQ0dLNFdmTVJ5VmR1VFRMcyIsImp0aSI6IjAxMTdiY2E2LTFlNzItNDJlZC1iMDUyLTUzNTRmMTZiYzNhOSIsIm5vbmNlIjoiWW5ReGRGcElhR0pZTW5FMWIzSmthVlkxTjJsWFFXOVhjbVZIYmxacFJqTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTY5NTcvY2xpZW50cy83ODFiYWExODM4MDZiNTRkL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJIVmgyazV2a3RlWHdoTlNNbjd0bXdkVEtMMDNmOEtsRCIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.QA2ljjlpvNeKvxMGlnrOtREBm8uxuZGtXDKNHqyW-4ijkbmUwT5LXis3ccs7jcwlkMcvdRM3Ugj1fWG45SU-Aw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieV9MNm5YeU03SGw1TWdHdzZZcTUybjlG
XzdYM294VDg1cHFUUjJOV3pnOCJ9fQ.eyJpYXQiOjE3MDg5MzY0NzcsImV4cCI6M
TcwODk0MzY3NywibmJmIjoxNzA4OTM2NDc3LCJzdWIiOiJ3aXJlYXBwOi8vYndaS
lN3MmVRTEs0cUc5R0VvRmxqZyE3ODFiYWExODM4MDZiNTRkQHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL2NoYWxsZW5nZS9jT
zVsRGdHdmNUTXYxYWhUR1JkNEoxMHNLVm1zcGxZYy82aURwdUdWcHVpaDVVdjJMQ
0dLNFdmTVJ5VmR1VFRMcyIsImp0aSI6IjAxMTdiY2E2LTFlNzItNDJlZC1iMDUyL
TUzNTRmMTZiYzNhOSIsIm5vbmNlIjoiWW5ReGRGcElhR0pZTW5FMWIzSmthVlkxT
jJsWFFXOVhjbVZIYmxacFJqTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MTY5NTcvY2xpZW50cy83ODFiYWExODM4MDZiNTRkL2FjY2Vzcy10b
2tlbiIsImNoYWwiOiJIVmgyazV2a3RlWHdoTlNNbjd0bXdkVEtMMDNmOEtsRCIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.QA2ljjlpvNeKvxMGlnrOtR
EBm8uxuZGtXDKNHqyW-4ijkbmUwT5LXis3ccs7jcwlkMcvdRM3Ugj1fWG45SU-Aw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "y_L6nXyM7Hl5MgGw6Yq52n9F_7X3oxT85pqTR2NWzg8"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32817/acme/wire/challenge/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc/6iDpuGVpuih5Uv2LCGK4WfMRyVduTTLs",
  "chal": "HVh2k5vkteXwhNSMn7tmwdTKL03f8KlD",
  "exp": 1708943677,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:16957/clients/781baa183806b54d/access-token",
  "iat": 1708936477,
  "jti": "0117bca6-1e72-42ed-b052-5354f16bc3a9",
  "name": "Alice Smith",
  "nbf": 1708936477,
  "nonce": "YnQxdFpIaGJYMnE1b3JkaVY1N2lXQW9XcmVHblZpRjM",
  "sub": "wireapp://bwZJSw2eQLK4qG9GEoFljg!781baa183806b54d@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAzzNcTN/teAyN4i90+pVUyG4BHR8CNP+CsC+i2f40ra
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAy/L6nXyM7Hl5MgGw6Yq52n9F/7X3oxT85pqTR2NWzg8=
-----END PUBLIC KEY-----
```

</details>


#### 15. trade client DPoP token for an access token
```http request
POST http://wire.com:16957/clients/781baa183806b54d/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZVY5TU5tNVllVTAzU0d3MVRXZEhkelpaY1RVeWJqbEdYemRZTTI5NFZEZzFjSEZVVWpKT1YzcG5PQ0o5ZlEuZXlKcFlYUWlPakUzTURnNU16WTBOemNzSW1WNGNDSTZNVGN3T0RrME16WTNOeXdpYm1KbUlqb3hOekE0T1RNMk5EYzNMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZZbmRhU2xOM01tVlJURXMwY1VjNVIwVnZSbXhxWnlFM09ERmlZV0V4T0RNNE1EWmlOVFJrUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekk0TVRjdllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOWpUelZzUkdkSGRtTlVUWFl4WVdoVVIxSmtORW94TUhOTFZtMXpjR3haWXk4MmFVUndkVWRXY0hWcGFEVlZkakpNUTBkTE5GZG1UVko1Vm1SMVZGUk1jeUlzSW1wMGFTSTZJakF4TVRkaVkyRTJMVEZsTnpJdE5ESmxaQzFpTURVeUxUVXpOVFJtTVRaaVl6TmhPU0lzSW01dmJtTmxJam9pV1c1UmVHUkdjRWxoUjBwWlRXNUZNV0l6U210aFZsa3hUakpzV0ZGWE9WaGpiVlpJWW14YWNGSnFUU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRZNU5UY3ZZMnhwWlc1MGN5ODNPREZpWVdFeE9ETTRNRFppTlRSa0wyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUpJVm1neWF6VjJhM1JsV0hkb1RsTk5iamQwYlhka1ZFdE1NRE5tT0V0c1JDSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpTENKdVlXMWxJam9pUVd4cFkyVWdVMjFwZEdnaWZRLlFBMmxqamxwdk5lS3Z4TUdsbnJPdFJFQm04dXh1Wkd0WERLTkhxeVctNGlqa2JtVXdUNUxYaXMzY2NzN2pjd2xrTWN2ZFJNM1VnajFmV0c0NVNVLUF3
```
#### 16. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjBabUplMGlQUDRHZXRzNl9aaWF3T3lpb1Y2b21BWlBPR2NySzlINlNPNjgifX0.eyJpYXQiOjE3MDg5MzY0NzcsImV4cCI6MTcwODk0MDQzNywibmJmIjoxNzA4OTM2NDc3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTY5NTcvY2xpZW50cy83ODFiYWExODM4MDZiNTRkL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9id1pKU3cyZVFMSzRxRzlHRW9GbGpnITc4MWJhYTE4MzgwNmI1NGRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjgxNy9hY21lL3dpcmUvY2hhbGxlbmdlL2NPNWxEZ0d2Y1RNdjFhaFRHUmQ0SjEwc0tWbXNwbFljLzZpRHB1R1ZwdWloNVV2MkxDR0s0V2ZNUnlWZHVUVExzIiwianRpIjoiZTQ3Yjg5ZTktODY0Yy00YTA0LTgzNTktZmEwMWI0ZmZiN2Q2Iiwibm9uY2UiOiJZblF4ZEZwSWFHSllNbkUxYjNKa2FWWTFOMmxYUVc5WGNtVkhibFpwUmpNIiwiY2hhbCI6IkhWaDJrNXZrdGVYd2hOU01uN3Rtd2RUS0wwM2Y4S2xEIiwiY25mIjp7ImtpZCI6Im9hM2xheWs5Q0N0UWhSdVZXOFRhR3pYbzJ6NmxHSi1ZTHUzRHE5Z0NUMDAifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2llVjlNTm01WWVVMDNTR3cxVFdkSGR6WlpjVFV5YmpsR1h6ZFlNMjk0VkRnMWNIRlVVakpPVjNwbk9DSjlmUS5leUpwWVhRaU9qRTNNRGc1TXpZME56Y3NJbVY0Y0NJNk1UY3dPRGswTXpZM055d2libUptSWpveE56QTRPVE0yTkRjM0xDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dlluZGFTbE4zTW1WUlRFczBjVWM1UjBWdlJteHFaeUUzT0RGaVlXRXhPRE00TURaaU5UUmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRNVGN2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5alR6VnNSR2RIZG1OVVRYWXhZV2hVUjFKa05Fb3hNSE5MVm0xemNHeFpZeTgyYVVSd2RVZFdjSFZwYURWVmRqSk1RMGRMTkZkbVRWSjVWbVIxVkZSTWN5SXNJbXAwYVNJNklqQXhNVGRpWTJFMkxURmxOekl0TkRKbFpDMWlNRFV5TFRVek5UUm1NVFppWXpOaE9TSXNJbTV2Ym1ObElqb2lXVzVSZUdSR2NFbGhSMHBaVFc1Rk1XSXpTbXRoVmxreFRqSnNXRkZYT1ZoamJWWklZbXhhY0ZKcVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFk1TlRjdlkyeHBaVzUwY3k4M09ERmlZV0V4T0RNNE1EWmlOVFJrTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSklWbWd5YXpWMmEzUmxXSGRvVGxOTmJqZDBiWGRrVkV0TU1ETm1PRXRzUkNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuUUEybGpqbHB2TmVLdnhNR2xuck90UkVCbTh1eHVaR3RYREtOSHF5Vy00aWprYm1Vd1Q1TFhpczNjY3M3amN3bGtNY3ZkUk0zVWdqMWZXRzQ1U1UtQXciLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vYndaSlN3MmVRTEs0cUc5R0VvRmxqZyE3ODFiYWExODM4MDZiNTRkQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.mXPNxuDhx-c4kh1-iSY98_v_ofdCOnm4gdsv6olQEkAaG6KNUMTve11gNTNEFQMcR2sjrjy7jFyTtpyl-wxbBQ",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjBabUplMGlQUDRHZXRzNl9aaWF3T3lpb1Y2b21BWlBPR2NySzlINlNPNjgifX0.eyJpYXQiOjE3MDg5MzY0NzcsImV4cCI6MTcwODk0MDQzNywibmJmIjoxNzA4OTM2NDc3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTY5NTcvY2xpZW50cy83ODFiYWExODM4MDZiNTRkL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9id1pKU3cyZVFMSzRxRzlHRW9GbGpnITc4MWJhYTE4MzgwNmI1NGRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjgxNy9hY21lL3dpcmUvY2hhbGxlbmdlL2NPNWxEZ0d2Y1RNdjFhaFRHUmQ0SjEwc0tWbXNwbFljLzZpRHB1R1ZwdWloNVV2MkxDR0s0V2ZNUnlWZHVUVExzIiwianRpIjoiZTQ3Yjg5ZTktODY0Yy00YTA0LTgzNTktZmEwMWI0ZmZiN2Q2Iiwibm9uY2UiOiJZblF4ZEZwSWFHSllNbkUxYjNKa2FWWTFOMmxYUVc5WGNtVkhibFpwUmpNIiwiY2hhbCI6IkhWaDJrNXZrdGVYd2hOU01uN3Rtd2RUS0wwM2Y4S2xEIiwiY25mIjp7ImtpZCI6Im9hM2xheWs5Q0N0UWhSdVZXOFRhR3pYbzJ6NmxHSi1ZTHUzRHE5Z0NUMDAifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2llVjlNTm01WWVVMDNTR3cxVFdkSGR6WlpjVFV5YmpsR1h6ZFlNMjk0VkRnMWNIRlVVakpPVjNwbk9DSjlmUS5leUpwWVhRaU9qRTNNRGc1TXpZME56Y3NJbVY0Y0NJNk1UY3dPRGswTXpZM055d2libUptSWpveE56QTRPVE0yTkRjM0xDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dlluZGFTbE4zTW1WUlRFczBjVWM1UjBWdlJteHFaeUUzT0RGaVlXRXhPRE00TURaaU5UUmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRNVGN2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5alR6VnNSR2RIZG1OVVRYWXhZV2hVUjFKa05Fb3hNSE5MVm0xemNHeFpZeTgyYVVSd2RVZFdjSFZwYURWVmRqSk1RMGRMTkZkbVRWSjVWbVIxVkZSTWN5SXNJbXAwYVNJNklqQXhNVGRpWTJFMkxURmxOekl0TkRKbFpDMWlNRFV5TFRVek5UUm1NVFppWXpOaE9TSXNJbTV2Ym1ObElqb2lXVzVSZUdSR2NFbGhSMHBaVFc1Rk1XSXpTbXRoVmxreFRqSnNXRkZYT1ZoamJWWklZbXhhY0ZKcVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFk1TlRjdlkyeHBaVzUwY3k4M09ERmlZV0V4T0RNNE1EWmlOVFJrTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSklWbWd5YXpWMmEzUmxXSGRvVGxOTmJqZDBiWGRrVkV0TU1ETm1PRXRzUkNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuUUEybGpqbHB2TmVLdnhNR2xuck90UkVCbTh1eHVaR3RYREtOSHF5Vy00aWprYm1Vd1Q1TFhpczNjY3M3amN3bGtNY3ZkUk0zVWdqMWZXRzQ1U1UtQXciLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vYndaSlN3MmVRTEs0cUc5R0VvRmxqZyE3ODFiYWExODM4MDZiNTRkQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.mXPNxuDhx-c4kh1-iSY98_v_ofdCOnm4gdsv6olQEkAaG6KNUMTve11gNTNEFQMcR2sjrjy7jFyTtpyl-wxbBQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IjBabUplMGlQUDRHZXRzNl9aaWF3T3lpb1Y2
b21BWlBPR2NySzlINlNPNjgifX0.eyJpYXQiOjE3MDg5MzY0NzcsImV4cCI6MTcw
ODk0MDQzNywibmJmIjoxNzA4OTM2NDc3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MTY5NTcvY2xpZW50cy83ODFiYWExODM4MDZiNTRkL2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9id1pKU3cyZVFMSzRxRzlHRW9GbGpnITc4MWJhYTE4Mzgw
NmI1NGRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjgxNy9hY21l
L3dpcmUvY2hhbGxlbmdlL2NPNWxEZ0d2Y1RNdjFhaFRHUmQ0SjEwc0tWbXNwbFlj
LzZpRHB1R1ZwdWloNVV2MkxDR0s0V2ZNUnlWZHVUVExzIiwianRpIjoiZTQ3Yjg5
ZTktODY0Yy00YTA0LTgzNTktZmEwMWI0ZmZiN2Q2Iiwibm9uY2UiOiJZblF4ZEZw
SWFHSllNbkUxYjNKa2FWWTFOMmxYUVc5WGNtVkhibFpwUmpNIiwiY2hhbCI6IkhW
aDJrNXZrdGVYd2hOU01uN3Rtd2RUS0wwM2Y4S2xEIiwiY25mIjp7ImtpZCI6Im9h
M2xheWs5Q0N0UWhSdVZXOFRhR3pYbzJ6NmxHSi1ZTHUzRHE5Z0NUMDAifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2llVjlNTm01WWVVMDNTR3cxVFdkSGR6WlpjVFV5YmpsR1h6ZFlNMjk0VkRn
MWNIRlVVakpPVjNwbk9DSjlmUS5leUpwWVhRaU9qRTNNRGc1TXpZME56Y3NJbVY0
Y0NJNk1UY3dPRGswTXpZM055d2libUptSWpveE56QTRPVE0yTkRjM0xDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dlluZGFTbE4zTW1WUlRFczBjVWM1UjBWdlJteHFaeUUz
T0RGaVlXRXhPRE00TURaaU5UUmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STRNVGN2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM5alR6VnNSR2RIZG1OVVRYWXhZV2hVUjFKa05Fb3hNSE5MVm0xemNHeFpZeTgy
YVVSd2RVZFdjSFZwYURWVmRqSk1RMGRMTkZkbVRWSjVWbVIxVkZSTWN5SXNJbXAw
YVNJNklqQXhNVGRpWTJFMkxURmxOekl0TkRKbFpDMWlNRFV5TFRVek5UUm1NVFpp
WXpOaE9TSXNJbTV2Ym1ObElqb2lXVzVSZUdSR2NFbGhSMHBaVFc1Rk1XSXpTbXRo
VmxreFRqSnNXRkZYT1ZoamJWWklZbXhhY0ZKcVRTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFk1TlRjdlkyeHBaVzUw
Y3k4M09ERmlZV0V4T0RNNE1EWmlOVFJrTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSklWbWd5YXpWMmEzUmxXSGRvVGxOTmJqZDBiWGRrVkV0TU1ETm1PRXRz
UkNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hw
WTJVZ1UyMXBkR2dpZlEuUUEybGpqbHB2TmVLdnhNR2xuck90UkVCbTh1eHVaR3RY
REtOSHF5Vy00aWprYm1Vd1Q1TFhpczNjY3M3amN3bGtNY3ZkUk0zVWdqMWZXRzQ1
U1UtQXciLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vYndaSlN3MmVRTEs0cUc5R0Vv
RmxqZyE3ODFiYWExODM4MDZiNTRkQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUs
InNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.mXPNxuDhx-c4kh1-iSY98_v_ofdCO
nm4gdsv6olQEkAaG6KNUMTve11gNTNEFQMcR2sjrjy7jFyTtpyl-wxbBQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "0ZmJe0iPP4Gets6_ZiawOyioV6omAZPOGcrK9H6SO68"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32817/acme/wire/challenge/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc/6iDpuGVpuih5Uv2LCGK4WfMRyVduTTLs",
  "chal": "HVh2k5vkteXwhNSMn7tmwdTKL03f8KlD",
  "client_id": "wireapp://bwZJSw2eQLK4qG9GEoFljg!781baa183806b54d@wire.com",
  "cnf": {
    "kid": "oa3layk9CCtQhRuVW8TaGzXo2z6lGJ-YLu3Dq9gCT00"
  },
  "exp": 1708940437,
  "iat": 1708936477,
  "iss": "http://wire.com:16957/clients/781baa183806b54d/access-token",
  "jti": "e47b89e9-864c-4a04-8359-fa01b4ffb7d6",
  "nbf": 1708936477,
  "nonce": "YnQxdFpIaGJYMnE1b3JkaVY1N2lXQW9XcmVHblZpRjM",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieV9MNm5YeU03SGw1TWdHdzZZcTUybjlGXzdYM294VDg1cHFUUjJOV3pnOCJ9fQ.eyJpYXQiOjE3MDg5MzY0NzcsImV4cCI6MTcwODk0MzY3NywibmJmIjoxNzA4OTM2NDc3LCJzdWIiOiJ3aXJlYXBwOi8vYndaSlN3MmVRTEs0cUc5R0VvRmxqZyE3ODFiYWExODM4MDZiNTRkQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL2NoYWxsZW5nZS9jTzVsRGdHdmNUTXYxYWhUR1JkNEoxMHNLVm1zcGxZYy82aURwdUdWcHVpaDVVdjJMQ0dLNFdmTVJ5VmR1VFRMcyIsImp0aSI6IjAxMTdiY2E2LTFlNzItNDJlZC1iMDUyLTUzNTRmMTZiYzNhOSIsIm5vbmNlIjoiWW5ReGRGcElhR0pZTW5FMWIzSmthVlkxTjJsWFFXOVhjbVZIYmxacFJqTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTY5NTcvY2xpZW50cy83ODFiYWExODM4MDZiNTRkL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJIVmgyazV2a3RlWHdoTlNNbjd0bXdkVEtMMDNmOEtsRCIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.QA2ljjlpvNeKvxMGlnrOtREBm8uxuZGtXDKNHqyW-4ijkbmUwT5LXis3ccs7jcwlkMcvdRM3Ugj1fWG45SU-Aw",
  "scope": "wire_client_id",
  "sub": "wireapp://bwZJSw2eQLK4qG9GEoFljg!781baa183806b54d@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICjD/uyat8Sbajy0PKv5+M3uo6dhu5EitnF6kaquIhAs
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA0ZmJe0iPP4Gets6/ZiawOyioV6omAZPOGcrK9H6SO68=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 17. validate Dpop challenge (clientId)
```http request
POST https://stepca:32817/acme/wire/challenge/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc/6iDpuGVpuih5Uv2LCGK4WfMRyVduTTLs
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9hY2NvdW50L0FKRXNLWEpDdnpVSXFRRlQ0NlkxR1M0dHIwbEpTcjllIiwidHlwIjoiSldUIiwibm9uY2UiOiJhVlUzVUd4SldrRXlaM0ZQZW1WaFVtMVFWbWMxWlc5a1RHVnlTR2REZERrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL2NoYWxsZW5nZS9jTzVsRGdHdmNUTXYxYWhUR1JkNEoxMHNLVm1zcGxZYy82aURwdUdWcHVpaDVVdjJMQ0dLNFdmTVJ5VmR1VFRMcyJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklqQmFiVXBsTUdsUVVEUkhaWFJ6Tmw5YWFXRjNUM2xwYjFZMmIyMUJXbEJQUjJOeVN6bElObE5QTmpnaWZYMC5leUpwWVhRaU9qRTNNRGc1TXpZME56Y3NJbVY0Y0NJNk1UY3dPRGswTURRek55d2libUptSWpveE56QTRPVE0yTkRjM0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRZNU5UY3ZZMnhwWlc1MGN5ODNPREZpWVdFeE9ETTRNRFppTlRSa0wyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTlpZDFwS1UzY3laVkZNU3pSeFJ6bEhSVzlHYkdwbklUYzRNV0poWVRFNE16Z3dObUkxTkdSQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpneE55OWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMk5QTld4RVowZDJZMVJOZGpGaGFGUkhVbVEwU2pFd2MwdFdiWE53YkZsakx6WnBSSEIxUjFad2RXbG9OVlYyTWt4RFIwczBWMlpOVW5sV1pIVlVWRXh6SWl3aWFuUnBJam9pWlRRM1lqZzVaVGt0T0RZMFl5MDBZVEEwTFRnek5Ua3RabUV3TVdJMFptWmlOMlEySWl3aWJtOXVZMlVpT2lKWmJsRjRaRVp3U1dGSFNsbE5ia1V4WWpOS2EyRldXVEZPTW14WVVWYzVXR050VmtoaWJGcHdVbXBOSWl3aVkyaGhiQ0k2SWtoV2FESnJOWFpyZEdWWWQyaE9VMDF1TjNSdGQyUlVTMHd3TTJZNFMyeEVJaXdpWTI1bUlqcDdJbXRwWkNJNkltOWhNMnhoZVdzNVEwTjBVV2hTZFZaWE9GUmhSM3BZYnpKNk5teEhTaTFaVEhVelJIRTVaME5VTURBaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsbFZqbE5UbTAxV1dWVk1ETlRSM2N4VkZka1NHUjZXbHBqVkZWNVltcHNSMWg2WkZsTk1qazBWa1JuTVdOSVJsVlZha3BQVmpOd2JrOURTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5SR2MxVFhwWk1FNTZZM05KYlZZMFkwTkpOazFVWTNkUFJHc3dUWHBaTTA1NWQybGliVXB0U1dwdmVFNTZRVFJQVkUweVRrUmpNMHhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRsbHVaR0ZUYkU0elRXMVdVbFJGY3pCalZXTTFVakJXZGxKdGVIRmFlVVV6VDBSR2FWbFhSWGhQUkUwMFRVUmFhVTVVVW10UlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUUk5WR04yV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE01YWxSNlZuTlNSMlJJWkcxT1ZWUllXWGhaVjJoVlVqRkthMDVGYjNoTlNFNU1WbTB4ZW1OSGVGcFplVGd5WVZWU2QyUlZaRmRqU0Zad1lVUldWbVJxU2sxUk1HUk1Ua1prYlZSV1NqVldiVkl4VmtaU1RXTjVTWE5KYlhBd1lWTkpOa2xxUVhoTlZHUnBXVEpGTWt4VVJteE9la2wwVGtSS2JGcERNV2xOUkZWNVRGUlZlazVVVW0xTlZGcHBXWHBPYUU5VFNYTkpiVFYyWW0xT2JFbHFiMmxYVnpWU1pVZFNSMk5GYkdoU01IQmFWRmMxUmsxWFNYcFRiWFJvVm14cmVGUnFTbk5YUmtaWVQxWm9hbUpXV2tsWmJYaGhZMFpLY1ZSVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOVkZrMVRsUmpkbGt5ZUhCYVZ6VXdZM2s0TTA5RVJtbFpWMFY0VDBSTk5FMUVXbWxPVkZKclRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTa2xXYldkNVlYcFdNbUV6VW14WFNHUnZWR3hPVG1KcVpEQmlXR1JyVmtWMFRVMUVUbTFQUlhSelVrTkpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsTVEwcDFXVmN4YkVscWIybFJWM2h3V1RKVloxVXlNWEJrUjJkcFpsRXVVVUV5YkdwcWJIQjJUbVZMZG5oTlIyeHVjazkwVWtWQ2JUaDFlSFZhUjNSWVJFdE9TSEY1VnkwMGFXcHJZbTFWZDFRMVRGaHBjek5qWTNNM2FtTjNiR3ROWTNaa1VrMHpWV2RxTVdaWFJ6UTFVMVV0UVhjaUxDSmpiR2xsYm5SZmFXUWlPaUozYVhKbFlYQndPaTh2WW5kYVNsTjNNbVZSVEVzMGNVYzVSMFZ2Um14cVp5RTNPREZpWVdFeE9ETTRNRFppTlRSa1FIZHBjbVV1WTI5dElpd2lZWEJwWDNabGNuTnBiMjRpT2pVc0luTmpiM0JsSWpvaWQybHlaVjlqYkdsbGJuUmZhV1FpZlEubVhQTnh1RGh4LWM0a2gxLWlTWTk4X3Zfb2ZkQ09ubTRnZHN2Nm9sUUVrQWFHNktOVU1UdmUxMWdOVE5FRlFNY1Iyc2pyank3akZ5VHRweWwtd3hiQlEifQ",
  "signature": "Gcj8_KpQJuHafZHpl9IPQnkKTL-junIlkUKmjR1n3J6T5NGCOuzRddFLqnowF8W88Z5he0w7wbQClLf3GW_YBg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjBabUplMGlQUDRHZXRzNl9aaWF3T3lpb1Y2b21BWlBPR2NySzlINlNPNjgifX0.eyJpYXQiOjE3MDg5MzY0NzcsImV4cCI6MTcwODk0MDQzNywibmJmIjoxNzA4OTM2NDc3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTY5NTcvY2xpZW50cy83ODFiYWExODM4MDZiNTRkL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9id1pKU3cyZVFMSzRxRzlHRW9GbGpnITc4MWJhYTE4MzgwNmI1NGRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjgxNy9hY21lL3dpcmUvY2hhbGxlbmdlL2NPNWxEZ0d2Y1RNdjFhaFRHUmQ0SjEwc0tWbXNwbFljLzZpRHB1R1ZwdWloNVV2MkxDR0s0V2ZNUnlWZHVUVExzIiwianRpIjoiZTQ3Yjg5ZTktODY0Yy00YTA0LTgzNTktZmEwMWI0ZmZiN2Q2Iiwibm9uY2UiOiJZblF4ZEZwSWFHSllNbkUxYjNKa2FWWTFOMmxYUVc5WGNtVkhibFpwUmpNIiwiY2hhbCI6IkhWaDJrNXZrdGVYd2hOU01uN3Rtd2RUS0wwM2Y4S2xEIiwiY25mIjp7ImtpZCI6Im9hM2xheWs5Q0N0UWhSdVZXOFRhR3pYbzJ6NmxHSi1ZTHUzRHE5Z0NUMDAifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2llVjlNTm01WWVVMDNTR3cxVFdkSGR6WlpjVFV5YmpsR1h6ZFlNMjk0VkRnMWNIRlVVakpPVjNwbk9DSjlmUS5leUpwWVhRaU9qRTNNRGc1TXpZME56Y3NJbVY0Y0NJNk1UY3dPRGswTXpZM055d2libUptSWpveE56QTRPVE0yTkRjM0xDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dlluZGFTbE4zTW1WUlRFczBjVWM1UjBWdlJteHFaeUUzT0RGaVlXRXhPRE00TURaaU5UUmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRNVGN2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5alR6VnNSR2RIZG1OVVRYWXhZV2hVUjFKa05Fb3hNSE5MVm0xemNHeFpZeTgyYVVSd2RVZFdjSFZwYURWVmRqSk1RMGRMTkZkbVRWSjVWbVIxVkZSTWN5SXNJbXAwYVNJNklqQXhNVGRpWTJFMkxURmxOekl0TkRKbFpDMWlNRFV5TFRVek5UUm1NVFppWXpOaE9TSXNJbTV2Ym1ObElqb2lXVzVSZUdSR2NFbGhSMHBaVFc1Rk1XSXpTbXRoVmxreFRqSnNXRkZYT1ZoamJWWklZbXhhY0ZKcVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVFk1TlRjdlkyeHBaVzUwY3k4M09ERmlZV0V4T0RNNE1EWmlOVFJrTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSklWbWd5YXpWMmEzUmxXSGRvVGxOTmJqZDBiWGRrVkV0TU1ETm1PRXRzUkNJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuUUEybGpqbHB2TmVLdnhNR2xuck90UkVCbTh1eHVaR3RYREtOSHF5Vy00aWprYm1Vd1Q1TFhpczNjY3M3amN3bGtNY3ZkUk0zVWdqMWZXRzQ1U1UtQXciLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vYndaSlN3MmVRTEs0cUc5R0VvRmxqZyE3ODFiYWExODM4MDZiNTRkQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.mXPNxuDhx-c4kh1-iSY98_v_ofdCOnm4gdsv6olQEkAaG6KNUMTve11gNTNEFQMcR2sjrjy7jFyTtpyl-wxbBQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e",
    "nonce": "aVU3UGxJWkEyZ3FPemVhUm1QVmc1ZW9kTGVySGdDdDk",
    "typ": "JWT",
    "url": "https://stepca:32817/acme/wire/challenge/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc/6iDpuGVpuih5Uv2LCGK4WfMRyVduTTLs"
  }
}
```
#### 18. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32817/acme/wire/directory>;rel="index"
link: <https://stepca:32817/acme/wire/authz/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc>;rel="up"
location: https://stepca:32817/acme/wire/challenge/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc/6iDpuGVpuih5Uv2LCGK4WfMRyVduTTLs
replay-nonce: N09Cd0pIaHV3UGRtT25UdVFraGhoc0ZHNnlsaEc3YzM
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32817/acme/wire/challenge/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc/6iDpuGVpuih5Uv2LCGK4WfMRyVduTTLs",
  "status": "valid",
  "token": "HVh2k5vkteXwhNSMn7tmwdTKL03f8KlD",
  "target": "http://wire.com:16957/clients/781baa183806b54d/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 19. OAUTH authorization request

```text
code_verifier=0dtNKguAj9RmkC2RRnMrmpOPiZWFsxyLJMj9s7tsru8&code_challenge=fJ6W_J-LVhhFKR1hzu-hK1zAuxi5MHpmtAhDLfASk0E
```
#### 20. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:16327/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=eyfPplcKGK-TjHx9mobOvg&code_challenge=fJ6W_J-LVhhFKR1hzu-hK1zAuxi5MHpmtAhDLfASk0E&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A16957%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32817%2Facme%2Fwire%2Fchallenge%2FjfbVtwnIKPzCGb4ulRpVj5Moyke8LatV%2FEC9cx2K9EV8tfZmDkeklxb8naEQS38mQ%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%226FQSO5JkCuRZRPhVmi7XA9NolB1TfsDo.oa3layk9CCtQhRuVW8TaGzXo2z6lGJ-YLu3Dq9gCT00%22%7D%7D%7D&nonce=uObTver3YStraQ_dcKiFWg
```

#### 21. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:16327/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=bfb51f95-962c-4327-a800-3c394dc57d4d.18b1910b-6b40-48f0-94a6-ea9e280088fc.7fa56efa-0f81-49c1-bc93-969c892716e5&code_verifier=0dtNKguAj9RmkC2RRnMrmpOPiZWFsxyLJMj9s7tsru8&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A16957%2Fcallback
```
#### 22. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3cU1Bc1oza1NEUzh6Vng2S0Z5VktDMHRVRllZSGVOay0zM0hlV2gyYXNvIn0.eyJleHAiOjE3MDg5NDAxMzcsImlhdCI6MTcwODk0MDA3NywiYXV0aF90aW1lIjoxNzA4OTQwMDc3LCJqdGkiOiIwZWJlZmYyYS00ODRjLTQ0NjQtYjNmYy04MDZjMDNiM2QzZWIiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI4MGIxMGE4MC02NWVlLTQwMmQtYWZlNi03Yjg2OTI3OGFlYTAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ1T2JUdmVyM1lTdHJhUV9kY0tpRldnIiwic2Vzc2lvbl9zdGF0ZSI6IjE4YjE5MTBiLTZiNDAtNDhmMC05NGE2LWVhOWUyODAwODhmYyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE2OTU3Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiMThiMTkxMGItNmI0MC00OGYwLTk0YTYtZWE5ZTI4MDA4OGZjIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.BOZN7qRY-F_ZrAJB2u3fTAqQ5P0ZLUxgy-k3ECNy6E1fBMculgitV-Z270GzyVEP_JJXJQ0XJeyhYW5J0IbLUHMHn6CsrW8WO83WvTwuWBKjhMYvUN9hT8ZRAI-KKAx96e45U94UvXs5TLpVY0EJnBUE1MPkpYA4ZdMeF2haDyGUVqvvN9cUCnTYbmkYOkpXxrbZFLum8Za337DpvKqqSZbqUU5L6YEwl49mPT4SR7wb-BvNk7ZXAxX3gyPeDj2xjT1kStESnYUYDzmQtlw1IvN9Suc5MgcOKFSN9R-IoXeO3i3fQPRBx5hE0hnxgNxp-1COHrsFnuzl7jqwCIo7jQ",
  "expires_in": 59,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3cU1Bc1oza1NEUzh6Vng2S0Z5VktDMHRVRllZSGVOay0zM0hlV2gyYXNvIn0.eyJleHAiOjE3MDg5NDAxMzcsImlhdCI6MTcwODk0MDA3NywiYXV0aF90aW1lIjoxNzA4OTQwMDc3LCJqdGkiOiJmNzNlNjUxYy04YjVhLTRmNGItYTQxOC1lNzAxMGEzY2NhNjMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiI4MGIxMGE4MC02NWVlLTQwMmQtYWZlNi03Yjg2OTI3OGFlYTAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6InVPYlR2ZXIzWVN0cmFRX2RjS2lGV2ciLCJzZXNzaW9uX3N0YXRlIjoiMThiMTkxMGItNmI0MC00OGYwLTk0YTYtZWE5ZTI4MDA4OGZjIiwiYXRfaGFzaCI6ImlmSG5XQ1dEZHdmUFFoVDhSMkZZcXciLCJhY3IiOiIxIiwic2lkIjoiMThiMTkxMGItNmI0MC00OGYwLTk0YTYtZWE5ZTI4MDA4OGZjIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9jaGFsbGVuZ2UvamZiVnR3bklLUHpDR2I0dWxScFZqNU1veWtlOExhdFYvRUM5Y3gySzlFVjh0ZlptRGtla2x4YjhuYUVRUzM4bVEiLCJrZXlhdXRoIjoiNkZRU081SmtDdVJaUlBoVm1pN1hBOU5vbEIxVGZzRG8ub2EzbGF5azlDQ3RRaFJ1Vlc4VGFHelhvMno2bEdKLVlMdTNEcTlnQ1QwMCIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.V_VIIJLCecTjQ1xLw4LA1JKCgxD0r61Fi2r20muo6Z2f1BkfiPuqzr-PUoriIaHmQkQ8rQPqLqKsKIOOTHuV_HGZJur5FLeamvlzdjSUsn9osiz7crmFL2ix0lR70qYqgaL4bGJ24TawNjC6J_awT56MuOUj9MPE40hcQksHF0EAvJ_oReM5DjBlunq-_Eq3t-yLP6u0t8jzLs6iMbcsudTasbJR4WXCsInu6l3dglu09asMZXxYyJFv5BdXpK_fG8NXMgYp_3fHsUcJvZyZBsCkpiSykVO6-BAuKkv-jCNU8hp7-IS75Dgz0HyZHmb7iSdf4YpJXmFuBNOQxzvu2w",
  "not-before-policy": 0,
  "refresh_expires_in": 1799,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI1OGIwNDRmMi00NWNjLTQyYjItYmYxMS05NmE1NDk1OTZiMGIifQ.eyJleHAiOjE3MDg5NDE4NzcsImlhdCI6MTcwODk0MDA3NywianRpIjoiMTk1ZDkyMTQtYTYwZS00M2VjLTgxZGMtNWYzM2Q3YjY4MDllIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE2MzI3L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc3RlciIsInN1YiI6IjgwYjEwYTgwLTY1ZWUtNDAyZC1hZmU2LTdiODY5Mjc4YWVhMCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ1T2JUdmVyM1lTdHJhUV9kY0tpRldnIiwic2Vzc2lvbl9zdGF0ZSI6IjE4YjE5MTBiLTZiNDAtNDhmMC05NGE2LWVhOWUyODAwODhmYyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiIxOGIxOTEwYi02YjQwLTQ4ZjAtOTRhNi1lYTllMjgwMDg4ZmMifQ.cR-bAbZw8pMzBRJMbK-aEAd6cASrd_B_ZD_Or3wiZ4k",
  "scope": "openid profile email",
  "session_state": "18b1910b-6b40-48f0-94a6-ea9e280088fc",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3cU1Bc1oza1NEUzh6Vng2S0Z5VktDMHRVRllZSGVOay0zM0hlV2gyYXNvIn0.eyJleHAiOjE3MDg5NDAxMzcsImlhdCI6MTcwODk0MDA3NywiYXV0aF90aW1lIjoxNzA4OTQwMDc3LCJqdGkiOiIwZWJlZmYyYS00ODRjLTQ0NjQtYjNmYy04MDZjMDNiM2QzZWIiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiI4MGIxMGE4MC02NWVlLTQwMmQtYWZlNi03Yjg2OTI3OGFlYTAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ1T2JUdmVyM1lTdHJhUV9kY0tpRldnIiwic2Vzc2lvbl9zdGF0ZSI6IjE4YjE5MTBiLTZiNDAtNDhmMC05NGE2LWVhOWUyODAwODhmYyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE2OTU3Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiMThiMTkxMGItNmI0MC00OGYwLTk0YTYtZWE5ZTI4MDA4OGZjIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.BOZN7qRY-F_ZrAJB2u3fTAqQ5P0ZLUxgy-k3ECNy6E1fBMculgitV-Z270GzyVEP_JJXJQ0XJeyhYW5J0IbLUHMHn6CsrW8WO83WvTwuWBKjhMYvUN9hT8ZRAI-KKAx96e45U94UvXs5TLpVY0EJnBUE1MPkpYA4ZdMeF2haDyGUVqvvN9cUCnTYbmkYOkpXxrbZFLum8Za337DpvKqqSZbqUU5L6YEwl49mPT4SR7wb-BvNk7ZXAxX3gyPeDj2xjT1kStESnYUYDzmQtlw1IvN9Suc5MgcOKFSN9R-IoXeO3i3fQPRBx5hE0hnxgNxp-1COHrsFnuzl7jqwCIo7jQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3cU1Bc1oza1NE
Uzh6Vng2S0Z5VktDMHRVRllZSGVOay0zM0hlV2gyYXNvIn0.eyJleHAiOjE3MDg5
NDAxMzcsImlhdCI6MTcwODk0MDA3NywiYXV0aF90aW1lIjoxNzA4OTQwMDc3LCJq
dGkiOiIwZWJlZmYyYS00ODRjLTQ0NjQtYjNmYy04MDZjMDNiM2QzZWIiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiI4MGIxMGE4MC02NWVlLTQwMmQtYWZlNi03Yjg2OTI3OGFl
YTAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ1T2JU
dmVyM1lTdHJhUV9kY0tpRldnIiwic2Vzc2lvbl9zdGF0ZSI6IjE4YjE5MTBiLTZi
NDAtNDhmMC05NGE2LWVhOWUyODAwODhmYyIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE2OTU3Il0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxl
IGVtYWlsIiwic2lkIjoiMThiMTkxMGItNmI0MC00OGYwLTk0YTYtZWE5ZTI4MDA4
OGZjIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZl
bl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJh
bGljZXNtaXRoQHdpcmUuY29tIn0.BOZN7qRY-F_ZrAJB2u3fTAqQ5P0ZLUxgy-k3
ECNy6E1fBMculgitV-Z270GzyVEP_JJXJQ0XJeyhYW5J0IbLUHMHn6CsrW8WO83W
vTwuWBKjhMYvUN9hT8ZRAI-KKAx96e45U94UvXs5TLpVY0EJnBUE1MPkpYA4ZdMe
F2haDyGUVqvvN9cUCnTYbmkYOkpXxrbZFLum8Za337DpvKqqSZbqUU5L6YEwl49m
PT4SR7wb-BvNk7ZXAxX3gyPeDj2xjT1kStESnYUYDzmQtlw1IvN9Suc5MgcOKFSN
9R-IoXeO3i3fQPRBx5hE0hnxgNxp-1COHrsFnuzl7jqwCIo7jQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "wqMAsZ3kSDS8zVx6KFyVKC0tUFYYHeNk-33HeWh2aso",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:16957"
  ],
  "aud": "account",
  "auth_time": 1708940077,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1708940137,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1708940077,
  "iss": "http://keycloak:16327/realms/master",
  "jti": "0ebeff2a-484c-4464-b3fc-806c03b3d3eb",
  "name": "Alice Smith",
  "nonce": "uObTver3YStraQ_dcKiFWg",
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
  "scope": "openid profile email",
  "session_state": "18b1910b-6b40-48f0-94a6-ea9e280088fc",
  "sid": "18b1910b-6b40-48f0-94a6-ea9e280088fc",
  "sub": "80b10a80-65ee-402d-afe6-7b869278aea0",
  "typ": "Bearer"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr7igiK3sGYO2HoPWHLhT
0jF+tLUE0dZF1STnXVnow1Jn1GwotniAAfmEyB2AeLsc7D2i+yXqT4OayjLi2tHj
VeW8Hy2ZPKuSbDP0E8xXQeT/ieT+hcC9543MjYkOrtm5/RghJC0EoQjeHhP8CYgH
If7rbfTRgpiBEI01U8lj3iUptNSVOWIuhjYOsXB3tMdjUwV5d62+c2mTdCo5+m/5
Vy5aocUZ7a3P+Qx1Vlc2GBrNAqs6ccYa9UztQH8Ic3bgDxWn6FwOXzsVGT/FDrbw
DyPJwVK1GDX0D1mByBqRiBMfmBgjlpTZ9nsTgzv8boX+cNxi7v7fA4uh+RXmmNGd
GwIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI1OGIwNDRmMi00NWNjLTQyYjItYmYxMS05NmE1NDk1OTZiMGIifQ.eyJleHAiOjE3MDg5NDE4NzcsImlhdCI6MTcwODk0MDA3NywianRpIjoiMTk1ZDkyMTQtYTYwZS00M2VjLTgxZGMtNWYzM2Q3YjY4MDllIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE2MzI3L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc3RlciIsInN1YiI6IjgwYjEwYTgwLTY1ZWUtNDAyZC1hZmU2LTdiODY5Mjc4YWVhMCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ1T2JUdmVyM1lTdHJhUV9kY0tpRldnIiwic2Vzc2lvbl9zdGF0ZSI6IjE4YjE5MTBiLTZiNDAtNDhmMC05NGE2LWVhOWUyODAwODhmYyIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiIxOGIxOTEwYi02YjQwLTQ4ZjAtOTRhNi1lYTllMjgwMDg4ZmMifQ.cR-bAbZw8pMzBRJMbK-aEAd6cASrd_B_ZD_Or3wiZ4k)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI1OGIwNDRmMi00
NWNjLTQyYjItYmYxMS05NmE1NDk1OTZiMGIifQ.eyJleHAiOjE3MDg5NDE4NzcsI
mlhdCI6MTcwODk0MDA3NywianRpIjoiMTk1ZDkyMTQtYTYwZS00M2VjLTgxZGMtN
WYzM2Q3YjY4MDllIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjE2MzI3L3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc
3RlciIsInN1YiI6IjgwYjEwYTgwLTY1ZWUtNDAyZC1hZmU2LTdiODY5Mjc4YWVhM
CIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJ1T2JUd
mVyM1lTdHJhUV9kY0tpRldnIiwic2Vzc2lvbl9zdGF0ZSI6IjE4YjE5MTBiLTZiN
DAtNDhmMC05NGE2LWVhOWUyODAwODhmYyIsInNjb3BlIjoib3BlbmlkIHByb2Zpb
GUgZW1haWwiLCJzaWQiOiIxOGIxOTEwYi02YjQwLTQ4ZjAtOTRhNi1lYTllMjgwM
Dg4ZmMifQ.cR-bAbZw8pMzBRJMbK-aEAd6cASrd_B_ZD_Or3wiZ4k
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "58b044f2-45cc-42b2-bf11-96a549596b0b",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:16327/realms/master",
  "azp": "wireapp",
  "exp": 1708941877,
  "iat": 1708940077,
  "iss": "http://keycloak:16327/realms/master",
  "jti": "195d9214-a60e-43ec-81dc-5f33d7b6809e",
  "nonce": "uObTver3YStraQ_dcKiFWg",
  "scope": "openid profile email",
  "session_state": "18b1910b-6b40-48f0-94a6-ea9e280088fc",
  "sid": "18b1910b-6b40-48f0-94a6-ea9e280088fc",
  "sub": "80b10a80-65ee-402d-afe6-7b869278aea0",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr7igiK3sGYO2HoPWHLhT
0jF+tLUE0dZF1STnXVnow1Jn1GwotniAAfmEyB2AeLsc7D2i+yXqT4OayjLi2tHj
VeW8Hy2ZPKuSbDP0E8xXQeT/ieT+hcC9543MjYkOrtm5/RghJC0EoQjeHhP8CYgH
If7rbfTRgpiBEI01U8lj3iUptNSVOWIuhjYOsXB3tMdjUwV5d62+c2mTdCo5+m/5
Vy5aocUZ7a3P+Qx1Vlc2GBrNAqs6ccYa9UztQH8Ic3bgDxWn6FwOXzsVGT/FDrbw
DyPJwVK1GDX0D1mByBqRiBMfmBgjlpTZ9nsTgzv8boX+cNxi7v7fA4uh+RXmmNGd
GwIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 23. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3cU1Bc1oza1NEUzh6Vng2S0Z5VktDMHRVRllZSGVOay0zM0hlV2gyYXNvIn0.eyJleHAiOjE3MDg5NDAxMzcsImlhdCI6MTcwODk0MDA3NywiYXV0aF90aW1lIjoxNzA4OTQwMDc3LCJqdGkiOiJmNzNlNjUxYy04YjVhLTRmNGItYTQxOC1lNzAxMGEzY2NhNjMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiI4MGIxMGE4MC02NWVlLTQwMmQtYWZlNi03Yjg2OTI3OGFlYTAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6InVPYlR2ZXIzWVN0cmFRX2RjS2lGV2ciLCJzZXNzaW9uX3N0YXRlIjoiMThiMTkxMGItNmI0MC00OGYwLTk0YTYtZWE5ZTI4MDA4OGZjIiwiYXRfaGFzaCI6ImlmSG5XQ1dEZHdmUFFoVDhSMkZZcXciLCJhY3IiOiIxIiwic2lkIjoiMThiMTkxMGItNmI0MC00OGYwLTk0YTYtZWE5ZTI4MDA4OGZjIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9jaGFsbGVuZ2UvamZiVnR3bklLUHpDR2I0dWxScFZqNU1veWtlOExhdFYvRUM5Y3gySzlFVjh0ZlptRGtla2x4YjhuYUVRUzM4bVEiLCJrZXlhdXRoIjoiNkZRU081SmtDdVJaUlBoVm1pN1hBOU5vbEIxVGZzRG8ub2EzbGF5azlDQ3RRaFJ1Vlc4VGFHelhvMno2bEdKLVlMdTNEcTlnQ1QwMCIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.V_VIIJLCecTjQ1xLw4LA1JKCgxD0r61Fi2r20muo6Z2f1BkfiPuqzr-PUoriIaHmQkQ8rQPqLqKsKIOOTHuV_HGZJur5FLeamvlzdjSUsn9osiz7crmFL2ix0lR70qYqgaL4bGJ24TawNjC6J_awT56MuOUj9MPE40hcQksHF0EAvJ_oReM5DjBlunq-_Eq3t-yLP6u0t8jzLs6iMbcsudTasbJR4WXCsInu6l3dglu09asMZXxYyJFv5BdXpK_fG8NXMgYp_3fHsUcJvZyZBsCkpiSykVO6-BAuKkv-jCNU8hp7-IS75Dgz0HyZHmb7iSdf4YpJXmFuBNOQxzvu2w)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3cU1Bc1oza1NE
Uzh6Vng2S0Z5VktDMHRVRllZSGVOay0zM0hlV2gyYXNvIn0.eyJleHAiOjE3MDg5
NDAxMzcsImlhdCI6MTcwODk0MDA3NywiYXV0aF90aW1lIjoxNzA4OTQwMDc3LCJq
dGkiOiJmNzNlNjUxYy04YjVhLTRmNGItYTQxOC1lNzAxMGEzY2NhNjMiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiI4MGIxMGE4MC02NWVlLTQwMmQtYWZlNi03Yjg2OTI3OGFl
YTAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6InVPYlR2ZXIz
WVN0cmFRX2RjS2lGV2ciLCJzZXNzaW9uX3N0YXRlIjoiMThiMTkxMGItNmI0MC00
OGYwLTk0YTYtZWE5ZTI4MDA4OGZjIiwiYXRfaGFzaCI6ImlmSG5XQ1dEZHdmUFFo
VDhSMkZZcXciLCJhY3IiOiIxIiwic2lkIjoiMThiMTkxMGItNmI0MC00OGYwLTk0
YTYtZWE5ZTI4MDA4OGZjIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2ly
ZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8v
c3RlcGNhOjMyODE3L2FjbWUvd2lyZS9jaGFsbGVuZ2UvamZiVnR3bklLUHpDR2I0
dWxScFZqNU1veWtlOExhdFYvRUM5Y3gySzlFVjh0ZlptRGtla2x4YjhuYUVRUzM4
bVEiLCJrZXlhdXRoIjoiNkZRU081SmtDdVJaUlBoVm1pN1hBOU5vbEIxVGZzRG8u
b2EzbGF5azlDQ3RRaFJ1Vlc4VGFHelhvMno2bEdKLVlMdTNEcTlnQ1QwMCIsImZh
bWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20i
fQ.V_VIIJLCecTjQ1xLw4LA1JKCgxD0r61Fi2r20muo6Z2f1BkfiPuqzr-PUoriI
aHmQkQ8rQPqLqKsKIOOTHuV_HGZJur5FLeamvlzdjSUsn9osiz7crmFL2ix0lR70
qYqgaL4bGJ24TawNjC6J_awT56MuOUj9MPE40hcQksHF0EAvJ_oReM5DjBlunq-_
Eq3t-yLP6u0t8jzLs6iMbcsudTasbJR4WXCsInu6l3dglu09asMZXxYyJFv5BdXp
K_fG8NXMgYp_3fHsUcJvZyZBsCkpiSykVO6-BAuKkv-jCNU8hp7-IS75Dgz0HyZH
mb7iSdf4YpJXmFuBNOQxzvu2w
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "wqMAsZ3kSDS8zVx6KFyVKC0tUFYYHeNk-33HeWh2aso",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32817/acme/wire/challenge/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV/EC9cx2K9EV8tfZmDkeklxb8naEQS38mQ",
  "acr": "1",
  "at_hash": "ifHnWCWDdwfPQhT8R2FYqw",
  "aud": "wireapp",
  "auth_time": 1708940077,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1708940137,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1708940077,
  "iss": "http://keycloak:16327/realms/master",
  "jti": "f73e651c-8b5a-4f4b-a418-e7010a3cca63",
  "keyauth": "6FQSO5JkCuRZRPhVmi7XA9NolB1TfsDo.oa3layk9CCtQhRuVW8TaGzXo2z6lGJ-YLu3Dq9gCT00",
  "name": "Alice Smith",
  "nonce": "uObTver3YStraQ_dcKiFWg",
  "preferred_username": "alice_wire@wire.com",
  "session_state": "18b1910b-6b40-48f0-94a6-ea9e280088fc",
  "sid": "18b1910b-6b40-48f0-94a6-ea9e280088fc",
  "sub": "80b10a80-65ee-402d-afe6-7b869278aea0",
  "typ": "ID"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr7igiK3sGYO2HoPWHLhT
0jF+tLUE0dZF1STnXVnow1Jn1GwotniAAfmEyB2AeLsc7D2i+yXqT4OayjLi2tHj
VeW8Hy2ZPKuSbDP0E8xXQeT/ieT+hcC9543MjYkOrtm5/RghJC0EoQjeHhP8CYgH
If7rbfTRgpiBEI01U8lj3iUptNSVOWIuhjYOsXB3tMdjUwV5d62+c2mTdCo5+m/5
Vy5aocUZ7a3P+Qx1Vlc2GBrNAqs6ccYa9UztQH8Ic3bgDxWn6FwOXzsVGT/FDrbw
DyPJwVK1GDX0D1mByBqRiBMfmBgjlpTZ9nsTgzv8boX+cNxi7v7fA4uh+RXmmNGd
GwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32817/acme/wire/challenge/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV/EC9cx2K9EV8tfZmDkeklxb8naEQS38mQ
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9hY2NvdW50L0FKRXNLWEpDdnpVSXFRRlQ0NlkxR1M0dHIwbEpTcjllIiwidHlwIjoiSldUIiwibm9uY2UiOiJOMDlDZDBwSWFIVjNVR1J0VDI1VWRWRnJhR2hvYzBaSE5ubHNhRWMzWXpNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL2NoYWxsZW5nZS9qZmJWdHduSUtQekNHYjR1bFJwVmo1TW95a2U4TGF0Vi9FQzljeDJLOUVWOHRmWm1Ea2VrbHhiOG5hRVFTMzhtUSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSjNjVTFCYzFvemExTkVVemg2Vm5nMlMwWjVWa3RETUhSVlJsbFpTR1ZPYXkwek0waGxWMmd5WVhOdkluMC5leUpsZUhBaU9qRTNNRGc1TkRBeE16Y3NJbWxoZENJNk1UY3dPRGswTURBM055d2lZWFYwYUY5MGFXMWxJam94TnpBNE9UUXdNRGMzTENKcWRHa2lPaUptTnpObE5qVXhZeTA0WWpWaExUUm1OR0l0WVRReE9DMWxOekF4TUdFelkyTmhOak1pTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNVFl6TWpjdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSTRNR0l4TUdFNE1DMDJOV1ZsTFRRd01tUXRZV1psTmkwM1lqZzJPVEkzT0dGbFlUQWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJblZQWWxSMlpYSXpXVk4wY21GUlgyUmpTMmxHVjJjaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaU1UaGlNVGt4TUdJdE5tSTBNQzAwT0dZd0xUazBZVFl0WldFNVpUSTRNREE0T0daaklpd2lZWFJmYUdGemFDSTZJbWxtU0c1WFExZEVaSGRtVUZGb1ZEaFNNa1paY1hjaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaU1UaGlNVGt4TUdJdE5tSTBNQzAwT0dZd0xUazBZVFl0WldFNVpUSTRNREE0T0daaklpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbUZzYVdObFgzZHBjbVZBZDJseVpTNWpiMjBpTENKbmFYWmxibDl1WVcxbElqb2lRV3hwWTJVaUxDSmhZMjFsWDJGMVpDSTZJbWgwZEhCek9pOHZjM1JsY0dOaE9qTXlPREUzTDJGamJXVXZkMmx5WlM5amFHRnNiR1Z1WjJVdmFtWmlWblIzYmtsTFVIcERSMkkwZFd4U2NGWnFOVTF2ZVd0bE9FeGhkRll2UlVNNVkzZ3lTemxGVmpoMFpscHRSR3RsYTJ4NFlqaHVZVVZSVXpNNGJWRWlMQ0pyWlhsaGRYUm9Jam9pTmtaUlUwODFTbXREZFZKYVVsQm9WbTFwTjFoQk9VNXZiRUl4VkdaelJHOHViMkV6YkdGNWF6bERRM1JSYUZKMVZsYzRWR0ZIZWxodk1ubzJiRWRLTFZsTWRUTkVjVGxuUTFRd01DSXNJbVpoYldsc2VWOXVZVzFsSWpvaVUyMXBkR2dpTENKbGJXRnBiQ0k2SW1Gc2FXTmxjMjFwZEdoQWQybHlaUzVqYjIwaWZRLlZfVklJSkxDZWNUalExeEx3NExBMUpLQ2d4RDByNjFGaTJyMjBtdW82WjJmMUJrZmlQdXF6ci1QVW9yaUlhSG1Ra1E4clFQcUxxS3NLSU9PVEh1Vl9IR1pKdXI1RkxlYW12bHpkalNVc245b3Npejdjcm1GTDJpeDBsUjcwcVlxZ2FMNGJHSjI0VGF3TmpDNkpfYXdUNTZNdU9VajlNUEU0MGhjUWtzSEYwRUF2Sl9vUmVNNURqQmx1bnEtX0VxM3QteUxQNnUwdDhqekxzNmlNYmNzdWRUYXNiSlI0V1hDc0ludTZsM2RnbHUwOWFzTVpYeFl5SkZ2NUJkWHBLX2ZHOE5YTWdZcF8zZkhzVWNKdlp5WkJzQ2twaVN5a1ZPNi1CQXVLa3YtakNOVThocDctSVM3NURnejBIeVpIbWI3aVNkZjRZcEpYbUZ1Qk5PUXh6dnUydyJ9",
  "signature": "RXLKOp4tN3Oh9roQ-EsRUh4St-or9YxAxeMW2I9fZg9w87j08YTQ9s2vEX8m1GRISVuJuuDc-kHwKVlCSGvdDg"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ3cU1Bc1oza1NEUzh6Vng2S0Z5VktDMHRVRllZSGVOay0zM0hlV2gyYXNvIn0.eyJleHAiOjE3MDg5NDAxMzcsImlhdCI6MTcwODk0MDA3NywiYXV0aF90aW1lIjoxNzA4OTQwMDc3LCJqdGkiOiJmNzNlNjUxYy04YjVhLTRmNGItYTQxOC1lNzAxMGEzY2NhNjMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MTYzMjcvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiI4MGIxMGE4MC02NWVlLTQwMmQtYWZlNi03Yjg2OTI3OGFlYTAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6InVPYlR2ZXIzWVN0cmFRX2RjS2lGV2ciLCJzZXNzaW9uX3N0YXRlIjoiMThiMTkxMGItNmI0MC00OGYwLTk0YTYtZWE5ZTI4MDA4OGZjIiwiYXRfaGFzaCI6ImlmSG5XQ1dEZHdmUFFoVDhSMkZZcXciLCJhY3IiOiIxIiwic2lkIjoiMThiMTkxMGItNmI0MC00OGYwLTk0YTYtZWE5ZTI4MDA4OGZjIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6ImFsaWNlX3dpcmVAd2lyZS5jb20iLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJhY21lX2F1ZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9jaGFsbGVuZ2UvamZiVnR3bklLUHpDR2I0dWxScFZqNU1veWtlOExhdFYvRUM5Y3gySzlFVjh0ZlptRGtla2x4YjhuYUVRUzM4bVEiLCJrZXlhdXRoIjoiNkZRU081SmtDdVJaUlBoVm1pN1hBOU5vbEIxVGZzRG8ub2EzbGF5azlDQ3RRaFJ1Vlc4VGFHelhvMno2bEdKLVlMdTNEcTlnQ1QwMCIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.V_VIIJLCecTjQ1xLw4LA1JKCgxD0r61Fi2r20muo6Z2f1BkfiPuqzr-PUoriIaHmQkQ8rQPqLqKsKIOOTHuV_HGZJur5FLeamvlzdjSUsn9osiz7crmFL2ix0lR70qYqgaL4bGJ24TawNjC6J_awT56MuOUj9MPE40hcQksHF0EAvJ_oReM5DjBlunq-_Eq3t-yLP6u0t8jzLs6iMbcsudTasbJR4WXCsInu6l3dglu09asMZXxYyJFv5BdXpK_fG8NXMgYp_3fHsUcJvZyZBsCkpiSykVO6-BAuKkv-jCNU8hp7-IS75Dgz0HyZHmb7iSdf4YpJXmFuBNOQxzvu2w"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e",
    "nonce": "N09Cd0pIaHV3UGRtT25UdVFraGhoc0ZHNnlsaEc3YzM",
    "typ": "JWT",
    "url": "https://stepca:32817/acme/wire/challenge/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV/EC9cx2K9EV8tfZmDkeklxb8naEQS38mQ"
  }
}
```
#### 24. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32817/acme/wire/directory>;rel="index"
link: <https://stepca:32817/acme/wire/authz/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV>;rel="up"
location: https://stepca:32817/acme/wire/challenge/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV/EC9cx2K9EV8tfZmDkeklxb8naEQS38mQ
replay-nonce: SWdMcU9zRkFHak53TDB4U3NJcjc3cExQalo2Tk5qVTE
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32817/acme/wire/challenge/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV/EC9cx2K9EV8tfZmDkeklxb8naEQS38mQ",
  "status": "valid",
  "token": "6FQSO5JkCuRZRPhVmi7XA9NolB1TfsDo",
  "target": "http://keycloak:16327/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 25. verify the status of the order
```http request
POST https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9hY2NvdW50L0FKRXNLWEpDdnpVSXFRRlQ0NlkxR1M0dHIwbEpTcjllIiwidHlwIjoiSldUIiwibm9uY2UiOiJTV2RNY1U5elJrRkhhazUzVERCNFUzTkpjamMzY0V4UWFsbzJUazVxVlRFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL29yZGVyL3JmaGpDR1hxeUhwOUJRdjVpcm9MRER5QVdxdlBEMER4In0",
  "payload": "",
  "signature": "3Att0TVjQFjzLg3DvlaG5jUmPAPnX9UcCV38v4pk00eJDVY3SOcthncLzGc1ZDJMJJI7UfE1H4bIhVbpBf7tDw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e",
    "nonce": "SWdMcU9zRkFHak53TDB4U3NJcjc3cExQalo2Tk5qVTE",
    "typ": "JWT",
    "url": "https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx"
  }
}
```
#### 26. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32817/acme/wire/directory>;rel="index"
location: https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx
replay-nonce: Z1FJNGpOZzlpZDVobW5YMGZQZU5IMXNaSllzOElEdHo
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://bwZJSw2eQLK4qG9GEoFljg!781baa183806b54d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32817/acme/wire/authz/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc",
    "https://stepca:32817/acme/wire/authz/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV"
  ],
  "expires": "2024-02-27T09:34:37Z",
  "notBefore": "2024-02-26T09:34:37.702025Z",
  "notAfter": "2034-02-23T09:34:37.702025Z"
}
```
#### 27. create a CSR and call finalize url
```http request
POST https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9hY2NvdW50L0FKRXNLWEpDdnpVSXFRRlQ0NlkxR1M0dHIwbEpTcjllIiwidHlwIjoiSldUIiwibm9uY2UiOiJaMUZKTkdwT1p6bHBaRFZvYlc1WU1HWlFaVTVJTVhOYVNsbHpPRWxFZEhvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL29yZGVyL3JmaGpDR1hxeUhwOUJRdjVpcm9MRER5QVdxdlBEMER4L2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBQ2ExWmpORkhhV3NkUnQzUHVDb2U0U3pmalI1dmxkWWlaaFhOSHRkbzYwcm9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2WW5kYVNsTjNNbVZSVEVzMGNVYzVSMFZ2Um14cVp5RTNPREZpWVdFeE9ETTRNRFppTlRSa1FIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFBMVcxMHRmZGlUU2lsRC0xZkN3eVk2SWhWZUhhamNLcVZ2ZWxxV01PeTBGTnM2UnBsR1pBalEzLXU2R0oxQXBlUi1oOHg1UnFrM1ZpSVIxeTc5MDNzSiJ9",
  "signature": "6L10cRTYI--NvxLJ9nn1QHo1Bsufy5nyVNkljwtBnz7qN8czo5TKQHMsCr-cOraYGEbS4S7Tt3qUvqUgIqQmCQ"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhACa1ZjNFHaWsdRt3PuCoe4SzfjR5vldYiZhXNHtdo60roHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vYndaSlN3MmVRTEs0cUc5R0VvRmxqZyE3ODFiYWExODM4MDZiNTRkQHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQA1W10tfdiTSilD-1fCwyY6IhVeHajcKqVvelqWMOy0FNs6RplGZAjQ3-u6GJ1ApeR-h8x5Rqk3ViIR1y7903sJ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e",
    "nonce": "Z1FJNGpOZzlpZDVobW5YMGZQZU5IMXNaSllzOElEdHo",
    "typ": "JWT",
    "url": "https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhACa1ZjNFHaWsdRt3PuCoe4SzfjR5vldY
iZhXNHtdo60roHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vYndaSlN3MmVRTEs0cUc5R0VvRmxqZyE3ODFiYWExODM4MDZiNTRkQHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQA1
W10tfdiTSilD+1fCwyY6IhVeHajcKqVvelqWMOy0FNs6RplGZAjQ3+u6GJ1ApeR+
h8x5Rqk3ViIR1y7903sJ
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
                    26:b5:66:33:45:1d:a5:ac:75:1b:77:3e:e0:a8:7b:
                    84:b3:7e:34:79:be:57:58:89:98:57:34:7b:5d:a3:
                    ad:2b
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://bwZJSw2eQLK4qG9GEoFljg!781baa183806b54d@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        35:5b:5d:2d:7d:d8:93:4a:29:43:fb:57:c2:c3:26:3a:22:15:
        5e:1d:a8:dc:2a:a5:6f:7a:5a:96:30:ec:b4:14:db:3a:46:99:
        46:64:08:d0:df:eb:ba:18:9d:40:a5:e4:7e:87:cc:79:46:a9:
        37:56:22:11:d7:2e:fd:d3:7b:09

```

#### 28. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32817/acme/wire/directory>;rel="index"
location: https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx
replay-nonce: OVUwZzJuMzdHM3p0dkNFYUl2cG1qNDRSS29DMWNveGs
```
```json
{
  "certificate": "https://stepca:32817/acme/wire/certificate/JAj8oVqst0yDBIAz3sNpmBLXsjxyLn46",
  "status": "valid",
  "finalize": "https://stepca:32817/acme/wire/order/rfhjCGXqyHp9BQv5iroLDDyAWqvPD0Dx/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://bwZJSw2eQLK4qG9GEoFljg!781baa183806b54d@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32817/acme/wire/authz/cO5lDgGvcTMv1ahTGRd4J10sKVmsplYc",
    "https://stepca:32817/acme/wire/authz/jfbVtwnIKPzCGb4ulRpVj5Moyke8LatV"
  ],
  "expires": "2024-02-27T09:34:37Z",
  "notBefore": "2024-02-26T09:34:37.702025Z",
  "notAfter": "2034-02-23T09:34:37.702025Z"
}
```
#### 29. fetch the certificate
```http request
POST https://stepca:32817/acme/wire/certificate/JAj8oVqst0yDBIAz3sNpmBLXsjxyLn46
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE3L2FjbWUvd2lyZS9hY2NvdW50L0FKRXNLWEpDdnpVSXFRRlQ0NlkxR1M0dHIwbEpTcjllIiwidHlwIjoiSldUIiwibm9uY2UiOiJPVlV3WnpKdU16ZEhNM3AwZGtORllVbDJjRzFxTkRSU1MyOURNV052ZUdzIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTcvYWNtZS93aXJlL2NlcnRpZmljYXRlL0pBajhvVnFzdDB5REJJQXozc05wbUJMWHNqeHlMbjQ2In0",
  "payload": "",
  "signature": "C6nTT8FoiprvjocgDqAsZliVV_6xz57RR7RQDSsgRTidMXArpHD8sIGg8gCzQkOvVcXJmZbTT3go1UpcsVV7Cw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32817/acme/wire/account/AJEsKXJCvzUIqQFT46Y1GS4tr0lJSr9e",
    "nonce": "OVUwZzJuMzdHM3p0dkNFYUl2cG1qNDRSS29DMWNveGs",
    "typ": "JWT",
    "url": "https://stepca:32817/acme/wire/certificate/JAj8oVqst0yDBIAz3sNpmBLXsjxyLn46"
  }
}
```
#### 30. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32817/acme/wire/directory>;rel="index"
replay-nonce: OUZlNTVDQ1NIMlQ1VW9uUUh2VUlPQnFaWWczb2M1VjM
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGTCCAcCgAwIBAgIRALYL1O2R3JREF0yrrdJFodkwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMjI2MDkzNDM3WhcNMzQwMjIzMDkzNDM3WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQAmtWYzRR2lrHUbdz7g\nqHuEs340eb5XWImYVzR7XaOtK6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFBadtNlct8WnMG+kdPU/0h88h5aLMB8G\nA1UdIwQYMBaAFDTh5pRVg0fk8C7C0Arj3w9b/k/FMGkGA1UdEQRiMGCGIHdpcmVh\ncHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vYndaSlN3MmVR\nTEs0cUc5R0VvRmxqZyUyMTc4MWJhYTE4MzgwNmI1NGRAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0cAMEQCIAy21eYE\n6iGmQ4xIdnU0FhT9XDv1kTKZUVf9SvAhH44RAiBWtJ45Xql+lekG3epMQyyoja2t\nXkGC4pt/a6YclqRFJA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV+gAwIBAgIRAK0jq4E0RoQDLSXqWhxOO8IwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIyNjA5\nMzQzNloXDTM0MDIyMzA5MzQzNlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATR\nSM1wO+zOApEKbxng4+3MPyLThe8EyJkWN7UAiLCYY2b0qy4NhIQtFOQyo9P6nmtu\nhWbpKyLdjrcP6SXLCFmBo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUNOHmlFWDR+TwLsLQCuPfD1v+T8UwHwYDVR0jBBgw\nFoAUphlmx0pZ/MHL67QV0pA7hF/TjekwCgYIKoZIzj0EAwIDRwAwRAIgax10rext\nMBsmIjHtUSsQT4nqznx8YzkrxIysdSU9W3QCIHCTW9YGvjUpbFtpY5GmDXYM4HcR\nZyfe4JDKEWCRZIHK\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGTCCAcCgAwIBAgIRALYL1O2R3JREF0yrrdJFodkwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMjI2MDkzNDM3WhcNMzQwMjIzMDkzNDM3WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQAmtWYzRR2lrHUbdz7g
qHuEs340eb5XWImYVzR7XaOtK6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFBadtNlct8WnMG+kdPU/0h88h5aLMB8G
A1UdIwQYMBaAFDTh5pRVg0fk8C7C0Arj3w9b/k/FMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vYndaSlN3MmVR
TEs0cUc5R0VvRmxqZyUyMTc4MWJhYTE4MzgwNmI1NGRAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0cAMEQCIAy21eYE
6iGmQ4xIdnU0FhT9XDv1kTKZUVf9SvAhH44RAiBWtJ45Xql+lekG3epMQyyoja2t
XkGC4pt/a6YclqRFJA==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            b6:0b:d4:ed:91:dc:94:44:17:4c:ab:ad:d2:45:a1:d9
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Feb 26 09:34:37 2024 GMT
            Not After : Feb 23 09:34:37 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    26:b5:66:33:45:1d:a5:ac:75:1b:77:3e:e0:a8:7b:
                    84:b3:7e:34:79:be:57:58:89:98:57:34:7b:5d:a3:
                    ad:2b
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                16:9D:B4:D9:5C:B7:C5:A7:30:6F:A4:74:F5:3F:D2:1F:3C:87:96:8B
            X509v3 Authority Key Identifier: 
                34:E1:E6:94:55:83:47:E4:F0:2E:C2:D0:0A:E3:DF:0F:5B:FE:4F:C5
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://bwZJSw2eQLK4qG9GEoFljg%21781baa183806b54d@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:0c:b6:d5:e6:04:ea:21:a6:43:8c:48:76:75:34:
        16:14:fd:5c:3b:f5:91:32:99:51:57:fd:4a:f0:21:1f:8e:11:
        02:20:56:b4:9e:39:5e:a9:7e:95:e9:06:dd:ea:4c:43:2c:a8:
        8d:ad:ad:5e:41:82:e2:9b:7f:6b:a6:1c:96:a4:45:24

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV+gAwIBAgIRAK0jq4E0RoQDLSXqWhxOO8IwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDIyNjA5
MzQzNloXDTM0MDIyMzA5MzQzNlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATR
SM1wO+zOApEKbxng4+3MPyLThe8EyJkWN7UAiLCYY2b0qy4NhIQtFOQyo9P6nmtu
hWbpKyLdjrcP6SXLCFmBo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUNOHmlFWDR+TwLsLQCuPfD1v+T8UwHwYDVR0jBBgw
FoAUphlmx0pZ/MHL67QV0pA7hF/TjekwCgYIKoZIzj0EAwIDRwAwRAIgax10rext
MBsmIjHtUSsQT4nqznx8YzkrxIysdSU9W3QCIHCTW9YGvjUpbFtpY5GmDXYM4HcR
Zyfe4JDKEWCRZIHK
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ad:23:ab:81:34:46:84:03:2d:25:ea:5a:1c:4e:3b:c2
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Feb 26 09:34:36 2024 GMT
            Not After : Feb 23 09:34:36 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:d1:48:cd:70:3b:ec:ce:02:91:0a:6f:19:e0:e3:
                    ed:cc:3f:22:d3:85:ef:04:c8:99:16:37:b5:00:88:
                    b0:98:63:66:f4:ab:2e:0d:84:84:2d:14:e4:32:a3:
                    d3:fa:9e:6b:6e:85:66:e9:2b:22:dd:8e:b7:0f:e9:
                    25:cb:08:59:81
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                34:E1:E6:94:55:83:47:E4:F0:2E:C2:D0:0A:E3:DF:0F:5B:FE:4F:C5
            X509v3 Authority Key Identifier: 
                A6:19:66:C7:4A:59:FC:C1:CB:EB:B4:15:D2:90:3B:84:5F:D3:8D:E9
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:6b:1d:74:ad:ec:6d:30:1b:26:22:31:ed:51:2b:
        10:4f:89:ea:ce:7c:7c:63:39:2b:c4:8c:ac:75:25:3d:5b:74:
        02:20:70:93:5b:d6:06:be:35:29:6c:5b:69:63:91:a6:0d:76:
        0c:e0:77:11:67:27:de:e0:90:ca:11:60:91:64:81:ca

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIQdHdgbnBWCOcqt0xfERAGSzAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMjI2MDkz
NDM1WhcNMzQwMjIzMDkzNDM1WjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3
aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATWsFsKwcSDoc+n
TXX9DO6f+Nb7gtIVSKtQl2xSJDvpNpdeYUZjg6nc8GeYNUKLqnJPIQAdj9JGLnw4
Why9AK8Co0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd
BgNVHQ4EFgQUphlmx0pZ/MHL67QV0pA7hF/TjekwCgYIKoZIzj0EAwIDSAAwRQIg
Bx8ho/AKTivBDXNS3nmjzTKiTkqoJgbm1DxvPGlAaZ8CIQDHucaxDKCkYxkwMOJN
AThK4U8jq2OyiecPruKv0Cj16Q==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            74:77:60:6e:70:56:08:e7:2a:b7:4c:5f:11:10:06:4b
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Feb 26 09:34:35 2024 GMT
            Not After : Feb 23 09:34:35 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:d6:b0:5b:0a:c1:c4:83:a1:cf:a7:4d:75:fd:0c:
                    ee:9f:f8:d6:fb:82:d2:15:48:ab:50:97:6c:52:24:
                    3b:e9:36:97:5e:61:46:63:83:a9:dc:f0:67:98:35:
                    42:8b:aa:72:4f:21:00:1d:8f:d2:46:2e:7c:38:5a:
                    1c:bd:00:af:02
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                A6:19:66:C7:4A:59:FC:C1:CB:EB:B4:15:D2:90:3B:84:5F:D3:8D:E9
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:07:1f:21:a3:f0:0a:4e:2b:c1:0d:73:52:de:79:
        a3:cd:32:a2:4e:4a:a8:26:06:e6:d4:3c:6f:3c:69:40:69:9f:
        02:21:00:c7:b9:c6:b1:0c:a0:a4:63:19:30:30:e2:4d:01:38:
        4a:e1:4f:23:ab:63:b2:89:e7:0f:ae:e2:af:d0:28:f5:e9

```

openssl verify chain ✅