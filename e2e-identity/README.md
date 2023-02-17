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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/1020340586340102579/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/0H2Qr2LfBEj0SCIycIYtWJLyTcY5U4AW
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /login
    wire-server->>wire-server: verifier & challenge codes
    wire-server->>+authorization-server:  GET /dex/auth
    authorization-server->>-wire-client: 200
    wire-client->>+authorization-server:  POST /dex/auth/ldap/login
    authorization-server->>-wire-client: 200
    wire-client->>+authorization-server:  POST /dex/approval
    authorization-server->>+wire-server:  GET /callback
    wire-server->>+authorization-server:  POST /dex/token
    authorization-server->>authorization-server: verify verifier & challenge codes
    authorization-server->>-wire-server: 200
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/tlKZbv1pdNIo8WaWQq2GRtbov3TXPDui
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/HxDzSMtcRmY1avHP4iT86D0qog6Vj0tA
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:55834/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:55834/acme/wire/new-nonce",
  "newAccount": "https://stepca:55834/acme/wire/new-account",
  "newOrder": "https://stepca:55834/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:55834/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:55834/acme/wire/directory>;rel="index"
replay-nonce: ck0wNFV6d0pjb0xYR1NyYVdzWXNwU3IyQVVLNWx4MGw
```
```text
ck0wNFV6d0pjb0xYR1NyYVdzWXNwU3IyQVVLNWx4MGw
```
#### 5. create a new account
```http request
POST https://stepca:55834/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Inl4eUtWVXVBbnpiOWZ1WDBKb3VWWXhGbVRLdHJyVHNWM0ZxQWRWQUhjT2MifSwibm9uY2UiOiJjazB3TkZWNmQwcGpiMHhZUjFOeVlWZHpXWE53VTNJeVFWVkxOV3g0TUd3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTU4MzQvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "mgkvWh5OPNMS-VDROCnQOkRpMeT4bCTGtADuNv9SooXl1vRgRFnuwFfj9CB3iM_7xW_-N1OAt5LQ8h93QQCCAA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "typ": "JWT",
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "yxyKVUuAnzb9fuX0JouVYxFmTKtrrTsV3FqAdVAHcOc"
    },
    "nonce": "ck0wNFV6d0pjb0xYR1NyYVdzWXNwU3IyQVVLNWx4MGw",
    "url": "https://stepca:55834/acme/wire/new-account"
  },
  "payload": {
    "termsOfServiceAgreed": true,
    "contact": [
      "unknown@example.com"
    ],
    "onlyReturnExisting": false
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:55834/acme/wire/directory>;rel="index"
location: https://stepca:55834/acme/wire/account/M9tVubnIBqarkKabBABx7PMSB8pKNCau
replay-nonce: TE80R1g0NjQzckhYbmwyamlkTDJIVXNtbzJ1NXNhZ1g
```
```json
{
  "status": "valid",
  "orders": "https://stepca:55834/acme/wire/account/M9tVubnIBqarkKabBABx7PMSB8pKNCau/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:55834/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1ODM0L2FjbWUvd2lyZS9hY2NvdW50L005dFZ1Ym5JQnFhcmtLYWJCQUJ4N1BNU0I4cEtOQ2F1IiwidHlwIjoiSldUIiwibm9uY2UiOiJURTgwUjFnME5qUXpja2hZYm13eWFtbGtUREpJVlhOdGJ6SjFOWE5oWjFnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTU4MzQvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIlNtaXRoLCBBbGljZSBNIChRQSlcIixcImRvbWFpblwiOlwid2lyZS5jb21cIixcImNsaWVudC1pZFwiOlwiaW06d2lyZWFwcD1OR1ZoTXpCak5ESXdaVEUyTkdSalpXRXhZekZrTXpNd01XWXhNV1l6TUdVL2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbVwiLFwiaGFuZGxlXCI6XCJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tXCJ9In1dLCJub3RCZWZvcmUiOiIyMDIzLTAzLTA5VDE3OjQ1OjMxLjY5NjEwNFoiLCJub3RBZnRlciI6IjIwMjMtMDMtMDlUMTg6NDU6MzEuNjk2MTA0WiJ9",
  "signature": "EzwJT--UASnjlnrzYwARK4y7rgdg4io_Z6cbPZMVZJPk983tKBzwJAB7DZSoAXa2eGK0Ze7RDU2aFoKSzSNfBA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55834/acme/wire/account/M9tVubnIBqarkKabBABx7PMSB8pKNCau",
    "typ": "JWT",
    "nonce": "TE80R1g0NjQzckhYbmwyamlkTDJIVXNtbzJ1NXNhZ1g",
    "url": "https://stepca:55834/acme/wire/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGVhMzBjNDIwZTE2NGRjZWExYzFkMzMwMWYxMWYzMGU/e28fa5b76b731b3@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
      }
    ],
    "notBefore": "2023-03-09T17:45:31.696104Z",
    "notAfter": "2023-03-09T18:45:31.696104Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:55834/acme/wire/directory>;rel="index"
location: https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW
replay-nonce: dEVMSGtzU1c1V1FTTHFtaUxQMnU5bHZSeVFqUlNwT24
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGVhMzBjNDIwZTE2NGRjZWExYzFkMzMwMWYxMWYzMGU/e28fa5b76b731b3@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55834/acme/wire/authz/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9"
  ],
  "expires": "2023-03-10T17:45:31Z",
  "notBefore": "2023-03-09T17:45:31.696104Z",
  "notAfter": "2023-03-09T18:45:31.696104Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:55834/acme/wire/authz/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1ODM0L2FjbWUvd2lyZS9hY2NvdW50L005dFZ1Ym5JQnFhcmtLYWJCQUJ4N1BNU0I4cEtOQ2F1IiwidHlwIjoiSldUIiwibm9uY2UiOiJkRVZNU0d0elUxYzFWMUZUVEhGdGFVeFFNblU1YkhaU2VWRnFVbE53VDI0IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTU4MzQvYWNtZS93aXJlL2F1dGh6L043a0lvZnlsZ0w1M2VkaWN6UnF5UTBZRkdaM0hrb1g5In0",
  "payload": "",
  "signature": "ZrKWpYEuChEFKO8TokJmPncdPnEJ5mi7aV2g8G0i3EvQpcokyXnATx8AvzMORX_JC5UEq1o_QKviYZFbuOdrCQ"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55834/acme/wire/account/M9tVubnIBqarkKabBABx7PMSB8pKNCau",
    "typ": "JWT",
    "nonce": "dEVMSGtzU1c1V1FTTHFtaUxQMnU5bHZSeVFqUlNwT24",
    "url": "https://stepca:55834/acme/wire/authz/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9"
  },
  "payload": {}
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55834/acme/wire/directory>;rel="index"
location: https://stepca:55834/acme/wire/authz/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9
replay-nonce: NU5hMlFtSmd1T0t2M2lmM2htQjJsOVBBSnBqQ2l6eUk
```
```json
{
  "status": "pending",
  "expires": "2023-03-10T17:45:31Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/tlKZbv1pdNIo8WaWQq2GRtbov3TXPDui",
      "status": "pending",
      "token": "BZSI5HrCT40ZAZ2JbxE1lwJXxwPWMTh9"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/0H2Qr2LfBEj0SCIycIYtWJLyTcY5U4AW",
      "status": "pending",
      "token": "BZSI5HrCT40ZAZ2JbxE1lwJXxwPWMTh9"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGVhMzBjNDIwZTE2NGRjZWExYzFkMzMwMWYxMWYzMGU/e28fa5b76b731b3@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:23659/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
VkVFZ1B0Slp2eFhFWU4wVXZuMFBtWkxwTTlaY0VLOG0
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieXh5S1ZVdUFuemI5ZnVYMEpvdVZZeEZtVEt0cnJUc1YzRnFBZFZBSGNPYyJ9fQ.eyJpYXQiOjE2NzgzODM5MzEsImV4cCI6MTY3ODQ3MDMzMSwibmJmIjoxNjc4MzgzOTMxLCJzdWIiOiJpbTp3aXJlYXBwPU5HVmhNekJqTkRJd1pURTJOR1JqWldFeFl6RmtNek13TVdZeE1XWXpNR1UvZTI4ZmE1Yjc2YjczMWIzQHdpcmUuY29tIiwianRpIjoiYTA3OTdiZGYtN2I0Ny00OWE1LWJlYTUtNWMzMGYzOTkzMzA3Iiwibm9uY2UiOiJWa1ZGWjFCMFNscDJlRmhGV1U0d1ZYWnVNRkJ0V2t4d1RUbGFZMFZMT0cwIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzY1OS8iLCJjaGFsIjoiQlpTSTVIckNUNDBaQVoySmJ4RTFsd0pYeHdQV01UaDkifQ.sGsPzh9tlbr6CqYIMWc--RncO9e5dyDA4l8Xt_CMdcyT8DXVHILTNEsUEP28o1BwcP53JZWcmSVihbd8ChQsCw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieXh5S1ZVdUFuemI5ZnVYMEpvdVZZeEZt
VEt0cnJUc1YzRnFBZFZBSGNPYyJ9fQ.eyJpYXQiOjE2NzgzODM5MzEsImV4cCI6M
TY3ODQ3MDMzMSwibmJmIjoxNjc4MzgzOTMxLCJzdWIiOiJpbTp3aXJlYXBwPU5HV
mhNekJqTkRJd1pURTJOR1JqWldFeFl6RmtNek13TVdZeE1XWXpNR1UvZTI4ZmE1Y
jc2YjczMWIzQHdpcmUuY29tIiwianRpIjoiYTA3OTdiZGYtN2I0Ny00OWE1LWJlY
TUtNWMzMGYzOTkzMzA3Iiwibm9uY2UiOiJWa1ZGWjFCMFNscDJlRmhGV1U0d1ZYW
nVNRkJ0V2t4d1RUbGFZMFZMT0cwIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6L
y93aXJlLmNvbToyMzY1OS8iLCJjaGFsIjoiQlpTSTVIckNUNDBaQVoySmJ4RTFsd
0pYeHdQV01UaDkifQ.sGsPzh9tlbr6CqYIMWc--RncO9e5dyDA4l8Xt_CMdcyT8D
XVHILTNEsUEP28o1BwcP53JZWcmSVihbd8ChQsCw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "yxyKVUuAnzb9fuX0JouVYxFmTKtrrTsV3FqAdVAHcOc"
  }
}
```

```json
{
  "iat": 1678383931,
  "exp": 1678470331,
  "nbf": 1678383931,
  "sub": "im:wireapp=NGVhMzBjNDIwZTE2NGRjZWExYzFkMzMwMWYxMWYzMGU/e28fa5b76b731b3@wire.com",
  "jti": "a0797bdf-7b47-49a5-bea5-5c30f3993307",
  "nonce": "VkVFZ1B0Slp2eFhFWU4wVXZuMFBtWkxwTTlaY0VLOG0",
  "htm": "POST",
  "htu": "http://wire.com:23659/",
  "chal": "BZSI5HrCT40ZAZ2JbxE1lwJXxwPWMTh9"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFY6sSWYmflcVf67iGKDA+opq44kq1EWQo/IRyI33E6v
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAyxyKVUuAnzb9fuX0JouVYxFmTKtrrTsV3FqAdVAHcOc=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:23659/clients/1020340586340102579/access-token
                          /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZVhoNVMxWlZkVUZ1ZW1JNVpuVllNRXB2ZFZaWmVFWnRWRXQwY25KVWMxWXpSbkZCWkZaQlNHTlBZeUo5ZlEuZXlKcFlYUWlPakUyTnpnek9ETTVNekVzSW1WNGNDSTZNVFkzT0RRM01ETXpNU3dpYm1KbUlqb3hOamM0TXpnek9UTXhMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVIVm1oTmVrSnFUa1JKZDFwVVJUSk9SMUpxV2xkRmVGbDZSbXROZWsxM1RWZFplRTFYV1hwTlIxVXZaVEk0Wm1FMVlqYzJZamN6TVdJelFIZHBjbVV1WTI5dElpd2lhblJwSWpvaVlUQTNPVGRpWkdZdE4ySTBOeTAwT1dFMUxXSmxZVFV0TldNek1HWXpPVGt6TXpBM0lpd2libTl1WTJVaU9pSldhMVpHV2pGQ01GTnNjREpsUm1oR1YxVTBkMVpZV25WTlJrSjBWMnQ0ZDFSVWJHRlpNRlpNVDBjd0lpd2lhSFJ0SWpvaVVFOVRWQ0lzSW1oMGRTSTZJbWgwZEhBNkx5OTNhWEpsTG1OdmJUb3lNelkxT1M4aUxDSmphR0ZzSWpvaVFscFRTVFZJY2tOVU5EQmFRVm95U21KNFJURnNkMHBZZUhkUVYwMVVhRGtpZlEuc0dzUHpoOXRsYnI2Q3FZSU1XYy0tUm5jTzllNWR5REE0bDhYdF9DTWRjeVQ4RFhWSElMVE5Fc1VFUDI4bzFCd2NQNTNKWldjbVNWaWhiZDhDaFFzQ3c
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InRJVlV4Q0hqSnFCOGpQdFpHSXRVQzZKNV9pVjY5U0pmWktEcVlBN2ZFZUkifX0.eyJpYXQiOjE2NzgzODM5MzEsImV4cCI6MTY4NjE1OTkzMSwibmJmIjoxNjc4MzgzOTMxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2NTkvIiwic3ViIjoiaW06d2lyZWFwcD1OR1ZoTXpCak5ESXdaVEUyTkdSalpXRXhZekZrTXpNd01XWXhNV1l6TUdVL2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzY1OS8iLCJqdGkiOiJhNGNlZjAxZS00YWM0LTRjY2QtOTA3MC0wZDg5NTMwMjY5ZTYiLCJub25jZSI6IlZrVkZaMUIwU2xwMmVGaEZXVTR3VlhadU1GQnRXa3h3VFRsYVkwVkxPRzAiLCJjaGFsIjoiQlpTSTVIckNUNDBaQVoySmJ4RTFsd0pYeHdQV01UaDkiLCJjbmYiOnsia2lkIjoiLUx5eG1vRnBjR01yZzJOMHdyTVBTdW9LdFdkQkdUeWxQVmU1Y3pHOGVncyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVYaDVTMVpWZFVGdWVtSTVablZZTUVwdmRWWlplRVp0VkV0MGNuSlVjMVl6Um5GQlpGWkJTR05QWXlKOWZRLmV5SnBZWFFpT2pFMk56Z3pPRE01TXpFc0ltVjRjQ0k2TVRZM09EUTNNRE16TVN3aWJtSm1Jam94TmpjNE16Z3pPVE14TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1SFZtaE5la0pxVGtSSmQxcFVSVEpPUjFKcVdsZEZlRmw2Um10TmVrMTNUVmRaZUUxWFdYcE5SMVV2WlRJNFptRTFZamMyWWpjek1XSXpRSGRwY21VdVkyOXRJaXdpYW5ScElqb2lZVEEzT1RkaVpHWXROMkkwTnkwME9XRTFMV0psWVRVdE5XTXpNR1l6T1Rrek16QTNJaXdpYm05dVkyVWlPaUpXYTFaR1dqRkNNRk5zY0RKbFJtaEdWMVUwZDFaWVduVk5Sa0owVjJ0NGQxUlViR0ZaTUZaTVQwY3dJaXdpYUhSdElqb2lVRTlUVkNJc0ltaDBkU0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95TXpZMU9TOGlMQ0pqYUdGc0lqb2lRbHBUU1RWSWNrTlVOREJhUVZveVNtSjRSVEZzZDBwWWVIZFFWMDFVYURraWZRLnNHc1B6aDl0bGJyNkNxWUlNV2MtLVJuY085ZTVkeURBNGw4WHRfQ01kY3lUOERYVkhJTFRORXNVRVAyOG8xQndjUDUzSlpXY21TVmloYmQ4Q2hRc0N3IiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcD1OR1ZoTXpCak5ESXdaVEUyTkdSalpXRXhZekZrTXpNd01XWXhNV1l6TUdVL2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.q-CdDcc_Js1YfU1g3_eqsf8E8gR6gtLSSGurHJduoDfA9a0RBMZktYikD1vQ-89X3Ot3Q1ymEDADeW3sTcI-AQ",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InRJVlV4Q0hqSnFCOGpQdFpHSXRVQzZKNV9pVjY5U0pmWktEcVlBN2ZFZUkifX0.eyJpYXQiOjE2NzgzODM5MzEsImV4cCI6MTY4NjE1OTkzMSwibmJmIjoxNjc4MzgzOTMxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2NTkvIiwic3ViIjoiaW06d2lyZWFwcD1OR1ZoTXpCak5ESXdaVEUyTkdSalpXRXhZekZrTXpNd01XWXhNV1l6TUdVL2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzY1OS8iLCJqdGkiOiJhNGNlZjAxZS00YWM0LTRjY2QtOTA3MC0wZDg5NTMwMjY5ZTYiLCJub25jZSI6IlZrVkZaMUIwU2xwMmVGaEZXVTR3VlhadU1GQnRXa3h3VFRsYVkwVkxPRzAiLCJjaGFsIjoiQlpTSTVIckNUNDBaQVoySmJ4RTFsd0pYeHdQV01UaDkiLCJjbmYiOnsia2lkIjoiLUx5eG1vRnBjR01yZzJOMHdyTVBTdW9LdFdkQkdUeWxQVmU1Y3pHOGVncyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVYaDVTMVpWZFVGdWVtSTVablZZTUVwdmRWWlplRVp0VkV0MGNuSlVjMVl6Um5GQlpGWkJTR05QWXlKOWZRLmV5SnBZWFFpT2pFMk56Z3pPRE01TXpFc0ltVjRjQ0k2TVRZM09EUTNNRE16TVN3aWJtSm1Jam94TmpjNE16Z3pPVE14TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1SFZtaE5la0pxVGtSSmQxcFVSVEpPUjFKcVdsZEZlRmw2Um10TmVrMTNUVmRaZUUxWFdYcE5SMVV2WlRJNFptRTFZamMyWWpjek1XSXpRSGRwY21VdVkyOXRJaXdpYW5ScElqb2lZVEEzT1RkaVpHWXROMkkwTnkwME9XRTFMV0psWVRVdE5XTXpNR1l6T1Rrek16QTNJaXdpYm05dVkyVWlPaUpXYTFaR1dqRkNNRk5zY0RKbFJtaEdWMVUwZDFaWVduVk5Sa0owVjJ0NGQxUlViR0ZaTUZaTVQwY3dJaXdpYUhSdElqb2lVRTlUVkNJc0ltaDBkU0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95TXpZMU9TOGlMQ0pqYUdGc0lqb2lRbHBUU1RWSWNrTlVOREJhUVZveVNtSjRSVEZzZDBwWWVIZFFWMDFVYURraWZRLnNHc1B6aDl0bGJyNkNxWUlNV2MtLVJuY085ZTVkeURBNGw4WHRfQ01kY3lUOERYVkhJTFRORXNVRVAyOG8xQndjUDUzSlpXY21TVmloYmQ4Q2hRc0N3IiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcD1OR1ZoTXpCak5ESXdaVEUyTkdSalpXRXhZekZrTXpNd01XWXhNV1l6TUdVL2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.q-CdDcc_Js1YfU1g3_eqsf8E8gR6gtLSSGurHJduoDfA9a0RBMZktYikD1vQ-89X3Ot3Q1ymEDADeW3sTcI-AQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InRJVlV4Q0hqSnFCOGpQdFpHSXRVQzZKNV9p
VjY5U0pmWktEcVlBN2ZFZUkifX0.eyJpYXQiOjE2NzgzODM5MzEsImV4cCI6MTY4
NjE1OTkzMSwibmJmIjoxNjc4MzgzOTMxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjM2NTkvIiwic3ViIjoiaW06d2lyZWFwcD1OR1ZoTXpCak5ESXdaVEUyTkdSalpX
RXhZekZrTXpNd01XWXhNV1l6TUdVL2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbSIs
ImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzY1OS8iLCJqdGkiOiJhNGNlZjAxZS00
YWM0LTRjY2QtOTA3MC0wZDg5NTMwMjY5ZTYiLCJub25jZSI6IlZrVkZaMUIwU2xw
MmVGaEZXVTR3VlhadU1GQnRXa3h3VFRsYVkwVkxPRzAiLCJjaGFsIjoiQlpTSTVI
ckNUNDBaQVoySmJ4RTFsd0pYeHdQV01UaDkiLCJjbmYiOnsia2lkIjoiLUx5eG1v
RnBjR01yZzJOMHdyTVBTdW9LdFdkQkdUeWxQVmU1Y3pHOGVncyJ9LCJwcm9vZiI6
ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5k
cklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpv
aWVYaDVTMVpWZFVGdWVtSTVablZZTUVwdmRWWlplRVp0VkV0MGNuSlVjMVl6Um5G
QlpGWkJTR05QWXlKOWZRLmV5SnBZWFFpT2pFMk56Z3pPRE01TXpFc0ltVjRjQ0k2
TVRZM09EUTNNRE16TVN3aWJtSm1Jam94TmpjNE16Z3pPVE14TENKemRXSWlPaUpw
YlRwM2FYSmxZWEJ3UFU1SFZtaE5la0pxVGtSSmQxcFVSVEpPUjFKcVdsZEZlRmw2
Um10TmVrMTNUVmRaZUUxWFdYcE5SMVV2WlRJNFptRTFZamMyWWpjek1XSXpRSGRw
Y21VdVkyOXRJaXdpYW5ScElqb2lZVEEzT1RkaVpHWXROMkkwTnkwME9XRTFMV0ps
WVRVdE5XTXpNR1l6T1Rrek16QTNJaXdpYm05dVkyVWlPaUpXYTFaR1dqRkNNRk5z
Y0RKbFJtaEdWMVUwZDFaWVduVk5Sa0owVjJ0NGQxUlViR0ZaTUZaTVQwY3dJaXdp
YUhSdElqb2lVRTlUVkNJc0ltaDBkU0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95
TXpZMU9TOGlMQ0pqYUdGc0lqb2lRbHBUU1RWSWNrTlVOREJhUVZveVNtSjRSVEZz
ZDBwWWVIZFFWMDFVYURraWZRLnNHc1B6aDl0bGJyNkNxWUlNV2MtLVJuY085ZTVk
eURBNGw4WHRfQ01kY3lUOERYVkhJTFRORXNVRVAyOG8xQndjUDUzSlpXY21TVmlo
YmQ4Q2hRc0N3IiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcD1OR1ZoTXpCak5ESXda
VEUyTkdSalpXRXhZekZrTXpNd01XWXhNV1l6TUdVL2UyOGZhNWI3NmI3MzFiM0B3
aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lk
In0.q-CdDcc_Js1YfU1g3_eqsf8E8gR6gtLSSGurHJduoDfA9a0RBMZktYikD1vQ
-89X3Ot3Q1ymEDADeW3sTcI-AQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "at+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "tIVUxCHjJqB8jPtZGItUC6J5_iV69SJfZKDqYA7fEeI"
  }
}
```

```json
{
  "iat": 1678383931,
  "exp": 1686159931,
  "nbf": 1678383931,
  "iss": "http://wire.com:23659/",
  "sub": "im:wireapp=NGVhMzBjNDIwZTE2NGRjZWExYzFkMzMwMWYxMWYzMGU/e28fa5b76b731b3@wire.com",
  "aud": "http://wire.com:23659/",
  "jti": "a4cef01e-4ac4-4ccd-9070-0d89530269e6",
  "nonce": "VkVFZ1B0Slp2eFhFWU4wVXZuMFBtWkxwTTlaY0VLOG0",
  "chal": "BZSI5HrCT40ZAZ2JbxE1lwJXxwPWMTh9",
  "cnf": {
    "kid": "-LyxmoFpcGMrg2N0wrMPSuoKtWdBGTylPVe5czG8egs"
  },
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieXh5S1ZVdUFuemI5ZnVYMEpvdVZZeEZtVEt0cnJUc1YzRnFBZFZBSGNPYyJ9fQ.eyJpYXQiOjE2NzgzODM5MzEsImV4cCI6MTY3ODQ3MDMzMSwibmJmIjoxNjc4MzgzOTMxLCJzdWIiOiJpbTp3aXJlYXBwPU5HVmhNekJqTkRJd1pURTJOR1JqWldFeFl6RmtNek13TVdZeE1XWXpNR1UvZTI4ZmE1Yjc2YjczMWIzQHdpcmUuY29tIiwianRpIjoiYTA3OTdiZGYtN2I0Ny00OWE1LWJlYTUtNWMzMGYzOTkzMzA3Iiwibm9uY2UiOiJWa1ZGWjFCMFNscDJlRmhGV1U0d1ZYWnVNRkJ0V2t4d1RUbGFZMFZMT0cwIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzY1OS8iLCJjaGFsIjoiQlpTSTVIckNUNDBaQVoySmJ4RTFsd0pYeHdQV01UaDkifQ.sGsPzh9tlbr6CqYIMWc--RncO9e5dyDA4l8Xt_CMdcyT8DXVHILTNEsUEP28o1BwcP53JZWcmSVihbd8ChQsCw",
  "client_id": "im:wireapp=NGVhMzBjNDIwZTE2NGRjZWExYzFkMzMwMWYxMWYzMGU/e28fa5b76b731b3@wire.com",
  "api_version": 3,
  "scope": "wire_client_id"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJjmII0n1bfs1c+9UdG/tN3WZHKA/2IFSeb7Sf80pA3N
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAtIVUxCHjJqB8jPtZGItUC6J5/iV69SJfZKDqYA7fEeI=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/0H2Qr2LfBEj0SCIycIYtWJLyTcY5U4AW
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1ODM0L2FjbWUvd2lyZS9hY2NvdW50L005dFZ1Ym5JQnFhcmtLYWJCQUJ4N1BNU0I4cEtOQ2F1IiwidHlwIjoiSldUIiwibm9uY2UiOiJOVTVoTWxGdFNtZDFUMHQyTTJsbU0yaHRRakpzT1ZCQlNuQnFRMmw2ZVVrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTU4MzQvYWNtZS93aXJlL2NoYWxsZW5nZS9ON2tJb2Z5bGdMNTNlZGljelJxeVEwWUZHWjNIa29YOS8wSDJRcjJMZkJFajBTQ0l5Y0lZdFdKTHlUY1k1VTRBVyJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluUkpWbFY0UTBocVNuRkNPR3BRZEZwSFNYUlZRelpLTlY5cFZqWTVVMHBtV2t0RWNWbEJOMlpGWlVraWZYMC5leUpwWVhRaU9qRTJOemd6T0RNNU16RXNJbVY0Y0NJNk1UWTROakUxT1Rrek1Td2libUptSWpveE5qYzRNemd6T1RNeExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNMk5Ua3ZJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFPUjFab1RYcENhazVFU1hkYVZFVXlUa2RTYWxwWFJYaFpla1pyVFhwTmQwMVhXWGhOVjFsNlRVZFZMMlV5T0daaE5XSTNObUkzTXpGaU0wQjNhWEpsTG1OdmJTSXNJbUYxWkNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU16WTFPUzhpTENKcWRHa2lPaUpoTkdObFpqQXhaUzAwWVdNMExUUmpZMlF0T1RBM01DMHdaRGc1TlRNd01qWTVaVFlpTENKdWIyNWpaU0k2SWxaclZrWmFNVUl3VTJ4d01tVkdhRVpYVlRSM1ZsaGFkVTFHUW5SWGEzaDNWRlJzWVZrd1ZreFBSekFpTENKamFHRnNJam9pUWxwVFNUVklja05VTkRCYVFWb3lTbUo0UlRGc2QwcFllSGRRVjAxVWFEa2lMQ0pqYm1ZaU9uc2lhMmxrSWpvaUxVeDVlRzF2Um5CalIwMXlaekpPTUhkeVRWQlRkVzlMZEZka1FrZFVlV3hRVm1VMVkzcEhPR1ZuY3lKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVdWWWFEVlRNVnBXWkZWR2RXVnRTVFZhYmxaWlRVVndkbVJXV2xwbFJWcDBWa1YwTUdOdVNsVmpNVmw2VW01R1FscEdXa0pUUjA1UVdYbEtPV1pSTG1WNVNuQlpXRkZwVDJwRk1rNTZaM3BQUkUwMVRYcEZjMGx0VmpSalEwazJUVlJaTTA5RVVUTk5SRTE2VFZOM2FXSnRTbTFKYW05NFRtcGpORTE2WjNwUFZFMTRURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGVTFTRlp0YUU1bGEwcHhWR3RTU21ReGNGVlNWRXBQVWpGS2NWZHNaRVpsUm13MlVtMTBUbVZyTVROVVZtUmFaVVV4V0ZkWWNFNVNNVlYyV2xSSk5GcHRSVEZaYW1NeVdXcGplazFYU1hwUlNHUndZMjFWZFZreU9YUkphWGRwWVc1U2NFbHFiMmxaVkVFelQxUmthVnBIV1hST01ra3dUbmt3TUU5WFJURk1WMHBzV1ZSVmRFNVhUWHBOUjFsNlQxUnJlazE2UVROSmFYZHBZbTA1ZFZreVZXbFBhVXBYWVRGYVIxZHFSa05OUms1elkwUktiRkp0YUVkV01WVXdaREZhV1ZkdVZrNVNhMG93VmpKME5HUXhVbFZpUjBaYVRVWmFUVlF3WTNkSmFYZHBZVWhTZEVscWIybFZSVGxVVmtOSmMwbHRhREJrVTBrMlNXMW9NR1JJUVRaTWVUa3pZVmhLYkV4dFRuWmlWRzk1VFhwWk1VOVRPR2xNUTBwcVlVZEdjMGxxYjJsUmJIQlVVMVJXU1dOclRsVk9SRUpoVVZadmVWTnRTalJTVkVaelpEQndXV1ZJWkZGV01ERlZZVVJyYVdaUkxuTkhjMUI2YURsMGJHSnlOa054V1VsTlYyTXRMVkp1WTA4NVpUVmtlVVJCTkd3NFdIUmZRMDFrWTNsVU9FUllWa2hKVEZST1JYTlZSVkF5T0c4eFFuZGpVRFV6U2xwWFkyMVRWbWxvWW1RNFEyaFJjME4zSWl3aVkyeHBaVzUwWDJsa0lqb2lhVzA2ZDJseVpXRndjRDFPUjFab1RYcENhazVFU1hkYVZFVXlUa2RTYWxwWFJYaFpla1pyVFhwTmQwMVhXWGhOVjFsNlRVZFZMMlV5T0daaE5XSTNObUkzTXpGaU0wQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvekxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLnEtQ2REY2NfSnMxWWZVMWczX2Vxc2Y4RThnUjZndExTU0d1ckhKZHVvRGZBOWEwUkJNWmt0WWlrRDF2US04OVgzT3QzUTF5bUVEQURlVzNzVGNJLUFRIn0",
  "signature": "xLFkSS_xmKqUV8aAqn3UwnX-DgUXfCm71UCBXsyoN-rjG5OASJ7WHGOLys37CZlcxNsLmJuedpFeghfTpjGeCA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55834/acme/wire/account/M9tVubnIBqarkKabBABx7PMSB8pKNCau",
    "typ": "JWT",
    "nonce": "NU5hMlFtSmd1T0t2M2lmM2htQjJsOVBBSnBqQ2l6eUk",
    "url": "https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/0H2Qr2LfBEj0SCIycIYtWJLyTcY5U4AW"
  },
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InRJVlV4Q0hqSnFCOGpQdFpHSXRVQzZKNV9pVjY5U0pmWktEcVlBN2ZFZUkifX0.eyJpYXQiOjE2NzgzODM5MzEsImV4cCI6MTY4NjE1OTkzMSwibmJmIjoxNjc4MzgzOTMxLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2NTkvIiwic3ViIjoiaW06d2lyZWFwcD1OR1ZoTXpCak5ESXdaVEUyTkdSalpXRXhZekZrTXpNd01XWXhNV1l6TUdVL2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbToyMzY1OS8iLCJqdGkiOiJhNGNlZjAxZS00YWM0LTRjY2QtOTA3MC0wZDg5NTMwMjY5ZTYiLCJub25jZSI6IlZrVkZaMUIwU2xwMmVGaEZXVTR3VlhadU1GQnRXa3h3VFRsYVkwVkxPRzAiLCJjaGFsIjoiQlpTSTVIckNUNDBaQVoySmJ4RTFsd0pYeHdQV01UaDkiLCJjbmYiOnsia2lkIjoiLUx5eG1vRnBjR01yZzJOMHdyTVBTdW9LdFdkQkdUeWxQVmU1Y3pHOGVncyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWVYaDVTMVpWZFVGdWVtSTVablZZTUVwdmRWWlplRVp0VkV0MGNuSlVjMVl6Um5GQlpGWkJTR05QWXlKOWZRLmV5SnBZWFFpT2pFMk56Z3pPRE01TXpFc0ltVjRjQ0k2TVRZM09EUTNNRE16TVN3aWJtSm1Jam94TmpjNE16Z3pPVE14TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFU1SFZtaE5la0pxVGtSSmQxcFVSVEpPUjFKcVdsZEZlRmw2Um10TmVrMTNUVmRaZUUxWFdYcE5SMVV2WlRJNFptRTFZamMyWWpjek1XSXpRSGRwY21VdVkyOXRJaXdpYW5ScElqb2lZVEEzT1RkaVpHWXROMkkwTnkwME9XRTFMV0psWVRVdE5XTXpNR1l6T1Rrek16QTNJaXdpYm05dVkyVWlPaUpXYTFaR1dqRkNNRk5zY0RKbFJtaEdWMVUwZDFaWVduVk5Sa0owVjJ0NGQxUlViR0ZaTUZaTVQwY3dJaXdpYUhSdElqb2lVRTlUVkNJc0ltaDBkU0k2SW1oMGRIQTZMeTkzYVhKbExtTnZiVG95TXpZMU9TOGlMQ0pqYUdGc0lqb2lRbHBUU1RWSWNrTlVOREJhUVZveVNtSjRSVEZzZDBwWWVIZFFWMDFVYURraWZRLnNHc1B6aDl0bGJyNkNxWUlNV2MtLVJuY085ZTVkeURBNGw4WHRfQ01kY3lUOERYVkhJTFRORXNVRVAyOG8xQndjUDUzSlpXY21TVmloYmQ4Q2hRc0N3IiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcD1OR1ZoTXpCak5ESXdaVEUyTkdSalpXRXhZekZrTXpNd01XWXhNV1l6TUdVL2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.q-CdDcc_Js1YfU1g3_eqsf8E8gR6gtLSSGurHJduoDfA9a0RBMZktYikD1vQ-89X3Ot3Q1ymEDADeW3sTcI-AQ"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55834/acme/wire/directory>;rel="index"
link: <https://stepca:55834/acme/wire/authz/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9>;rel="up"
location: https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/0H2Qr2LfBEj0SCIycIYtWJLyTcY5U4AW
replay-nonce: S2dhUzBrcE82VXVVSHgwREUyVWxhV3BJbTlQZkR4YjY
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/0H2Qr2LfBEj0SCIycIYtWJLyTcY5U4AW",
  "status": "valid",
  "token": "BZSI5HrCT40ZAZ2JbxE1lwJXxwPWMTh9"
}
```
### Authenticate end user using Open ID Connect implicit flow
#### 18. Client clicks login button
```http request
GET http://wire.com/login
accept: */*
host: wire.com:23659
```
#### 19. Resource server generates Verifier & Challenge Codes

```text
code_verifier=cChEbFe3I98pUmxJU5mz16s0mZ9XKY9IDhRYla-k-0s&code_challenge=5o2QYx0Iqb8tXXMJ0yFiH4bnpqIB98dzaZwy3laTl-4
```
#### 20. Resource server calls authorize url
```http request
GET http://dex:19864/dex/auth?response_type=code&client_id=wireapp&state=0Gn02_jFb14BSXvgq7YukQ&code_challenge=5o2QYx0Iqb8tXXMJ0yFiH4bnpqIB98dzaZwy3laTl-4&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A23659%2Fcallback&scope=openid+profile&nonce=TR4lljTcDGgbie1j5ZvE3g
```
#### 21. Authorization server redirects to login prompt


```text
200 http://dex:19864/dex/auth/ldap/login?back=&state=g423eydcckmqu646op6pmebb2
{
    "content-type": "text/html",
    "content-length": "1525",
    "date": "Thu, 09 Mar 2023 17:45:31 GMT",
}
```

<details>
<summary>Html</summary>

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <title>dex</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="../../static/main.css" rel="stylesheet">
    <link href="../../theme/styles.css" rel="stylesheet">
    <link rel="icon" href="../../theme/favicon.png">
  </head>

  <body class="theme-body">
    <div class="theme-navbar">
      <div class="theme-navbar__logo-wrap">
        <img class="theme-navbar__logo" src="../../theme/logo.png">
      </div>
    </div>

    <div class="dex-container">


<div class="theme-panel">
  <h2 class="theme-heading">Log in to Your Account</h2>
  <form method="post" action="/dex/auth/ldap/login?back=&amp;state=g423eydcckmqu646op6pmebb2">
    <div class="theme-form-row">
      <div class="theme-form-label">
        <label for="userid">Email Address</label>
      </div>
	  <input tabindex="1" required id="login" name="login" type="text" class="theme-form-input" placeholder="email address"  autofocus />
    </div>
    <div class="theme-form-row">
      <div class="theme-form-label">
        <label for="password">Password</label>
      </div>
	  <input tabindex="2" required id="password" name="password" type="password" class="theme-form-input" placeholder="password" />
    </div>

    

    <button tabindex="3" id="submit-login" type="submit" class="dex-btn theme-btn--primary">Login</button>

  </form>
  
</div>

    </div>
  </body>
</html>


```

</details>


#### 22. Client submits the login form
```http request
POST http://dex:19864/dex/auth/ldap/login?back=&state=g423eydcckmqu646op6pmebb2
content-type: application/x-www-form-urlencoded
```
```text
login=alicesmith%40wire.com&password=foo
```
#### 23. (Optional) Authorization server presents consent form to client


```text
200 http://dex:19864/dex/approval?req=g423eydcckmqu646op6pmebb2&hmac=_CA4V5bc8qJ63UQGdhuIDbZDcVJ8-tw62YGfy10zsPs
{
    "date": "Thu, 09 Mar 2023 17:45:31 GMT",
    "content-length": "1713",
    "content-type": "text/html",
}
```

<details>
<summary>Html</summary>

```html
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <title>dex</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="static/main.css" rel="stylesheet">
    <link href="theme/styles.css" rel="stylesheet">
    <link rel="icon" href="theme/favicon.png">
  </head>

  <body class="theme-body">
    <div class="theme-navbar">
      <div class="theme-navbar__logo-wrap">
        <img class="theme-navbar__logo" src="theme/logo.png">
      </div>
    </div>

    <div class="dex-container">


<div class="theme-panel">
  <h2 class="theme-heading">Grant Access</h2>

  <hr class="dex-separator">
  <div>
    
    <div class="dex-subtle-text">Example App would like to:</div>
    <ul class="dex-list">
      
      <li>View basic profile information</li>
      
    </ul>
    
  </div>
  <hr class="dex-separator">

  <div>
    <div class="theme-form-row">
      <form method="post">
        <input type="hidden" name="req" value="g423eydcckmqu646op6pmebb2"/>
        <input type="hidden" name="approval" value="approve">
        <button type="submit" class="dex-btn theme-btn--success">
            <span class="dex-btn-text">Grant Access</span>
        </button>
      </form>
    </div>
    <div class="theme-form-row">
      <form method="post">
        <input type="hidden" name="req" value="g423eydcckmqu646op6pmebb2"/>
        <input type="hidden" name="approval" value="rejected">
        <button type="submit" class="dex-btn theme-btn-provider">
            <span class="dex-btn-text">Cancel</span>
        </button>
      </form>
    </div>
  </div>

</div>

    </div>
  </body>
</html>


```

</details>


#### 24. Client submits consent form
```http request
POST http://dex:19864/dex/approval?req=g423eydcckmqu646op6pmebb2&hmac=_CA4V5bc8qJ63UQGdhuIDbZDcVJ8-tw62YGfy10zsPs
content-type: application/x-www-form-urlencoded
```
```text
req=g423eydcckmqu646op6pmebb2&approval=approve
```
#### 25. Authorization server calls callback url with authorization code
```http request
GET http://wire.com/callback
accept: */*
referer: http://dex:19864/dex/approval?req=g423eydcckmqu646op6pmebb2&hmac=_CA4V5bc8qJ63UQGdhuIDbZDcVJ8-tw62YGfy10zsPs
host: wire.com:23659
```
#### 26. Resource server call /oauth/token to get Id token
```http request
POST http://dex:19864/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpTMGRUZEZoNVozRlFOMVZsYmpWaGRqRnRWM014WW1Wdw==
```
```text
grant_type=authorization_code&code=mj3bspx46xqccscxrgz4ma55a&code_verifier=cChEbFe3I98pUmxJU5mz16s0mZ9XKY9IDhRYla-k-0s&redirect_uri=http%3A%2F%2Fwire.com%3A23659%2Fcallback
```
#### 27. Authorization server validates Verifier & Challenge Codes

```text
code_verifier=cChEbFe3I98pUmxJU5mz16s0mZ9XKY9IDhRYla-k-0s&code_challenge=5o2QYx0Iqb8tXXMJ0yFiH4bnpqIB98dzaZwy3laTl-4
```
#### 28. Authorization server returns Access & Id token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5MGJlMzQ1MWMzYTYxMTgwMDU1ODE0ZWU2ZDZjNTVjZWZkMDk3NGYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5ODY0L2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVIVm1oTmVrSnFUa1JKZDFwVVJUSk9SMUpxV2xkRmVGbDZSbXROZWsxM1RWZFplRTFYV1hwTlIxVXZaVEk0Wm1FMVlqYzJZamN6TVdJelFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY3ODQ3MDMzMSwiaWF0IjoxNjc4MzgzOTMxLCJub25jZSI6IlRSNGxsalRjREdnYmllMWo1WnZFM2ciLCJhdF9oYXNoIjoiRnBjNW5NdlI1UVR3eVR3WXRKTEdyUSIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.BGP1l-Ol9Jlj61-VGQ58y6o-y2C48nLeS7O0dNiT1-PnOnb9cU-KtFBaFj6kC4nVsGi-Cm4HKI2HIrKgaTmG5W4jeZe-kGagMBEhKr1doMXkW7AQdxS4me2zLE4x8-q3jhxZatZLhfEs7j96w4YMfeigB3qGZwOI7Noa4q9xw7_PloYmFUHsIZPkFSfA3ZCWVVZWqnZe94Fqr6FC8wFvycavbWvGSzAcRCGcrbMDjMF424MPZafuLYXW_r_ERwuWyrXYCe51QCrlQVXGg3acRndPYztiBnaKU-fWji2TQnG-k3ER04xw4CCX-Cso6zp57jAQX0Vrbhc2NP75tHnS2A",
  "token_type": "bearer",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5MGJlMzQ1MWMzYTYxMTgwMDU1ODE0ZWU2ZDZjNTVjZWZkMDk3NGYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5ODY0L2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVIVm1oTmVrSnFUa1JKZDFwVVJUSk9SMUpxV2xkRmVGbDZSbXROZWsxM1RWZFplRTFYV1hwTlIxVXZaVEk0Wm1FMVlqYzJZamN6TVdJelFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY3ODQ3MDMzMSwiaWF0IjoxNjc4MzgzOTMxLCJub25jZSI6IlRSNGxsalRjREdnYmllMWo1WnZFM2ciLCJhdF9oYXNoIjoid2J3dzRBQkJMT0FqQ2VZUUE2R3FWQSIsImNfaGFzaCI6IkQ3WTBiX3QxVEx5XzIwLXlLSHZ6OUEiLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IlNtaXRoLCBBbGljZSBNIChRQSkifQ.slayWNQdWMISxWpcNefdbWsV2SDYPvGi47bADwu9kTYk59gwLOBUL5N6Qr0hnPrstFxLwo3Tr5qNROMaGwnNeGRSg9nFMO6B_ke5lUbyB4I9W6spmnL0_XMnjvDqEH1pG88vQ9B2IiuSIvIGUOW9S5WS2Y0vT6jPc3p7zUZuRQf5hqMXCzN1aFgG9tjhp0Fck321y6a7k-LCAg1oDc5yrth3egcRuicz6VCF0u9wKc1K9fij5NfpJkQTyO_a4iLpkoWVAN2jU1Uppl88yG7OZpIRuG4WYtLKuXqZ13SUpCFd52i_46d-GwkdzS4g-mpdDwHifuqflguKoaOu8y5TYA"
}
```
#### 29. Resource server returns Id token to client

```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5MGJlMzQ1MWMzYTYxMTgwMDU1ODE0ZWU2ZDZjNTVjZWZkMDk3NGYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5ODY0L2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVIVm1oTmVrSnFUa1JKZDFwVVJUSk9SMUpxV2xkRmVGbDZSbXROZWsxM1RWZFplRTFYV1hwTlIxVXZaVEk0Wm1FMVlqYzJZamN6TVdJelFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY3ODQ3MDMzMSwiaWF0IjoxNjc4MzgzOTMxLCJub25jZSI6IlRSNGxsalRjREdnYmllMWo1WnZFM2ciLCJhdF9oYXNoIjoid2J3dzRBQkJMT0FqQ2VZUUE2R3FWQSIsImNfaGFzaCI6IkQ3WTBiX3QxVEx5XzIwLXlLSHZ6OUEiLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IlNtaXRoLCBBbGljZSBNIChRQSkifQ.slayWNQdWMISxWpcNefdbWsV2SDYPvGi47bADwu9kTYk59gwLOBUL5N6Qr0hnPrstFxLwo3Tr5qNROMaGwnNeGRSg9nFMO6B_ke5lUbyB4I9W6spmnL0_XMnjvDqEH1pG88vQ9B2IiuSIvIGUOW9S5WS2Y0vT6jPc3p7zUZuRQf5hqMXCzN1aFgG9tjhp0Fck321y6a7k-LCAg1oDc5yrth3egcRuicz6VCF0u9wKc1K9fij5NfpJkQTyO_a4iLpkoWVAN2jU1Uppl88yG7OZpIRuG4WYtLKuXqZ13SUpCFd52i_46d-GwkdzS4g-mpdDwHifuqflguKoaOu8y5TYA
```
#### 30. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5MGJlMzQ1MWMzYTYxMTgwMDU1ODE0ZWU2ZDZjNTVjZWZkMDk3NGYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5ODY0L2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVIVm1oTmVrSnFUa1JKZDFwVVJUSk9SMUpxV2xkRmVGbDZSbXROZWsxM1RWZFplRTFYV1hwTlIxVXZaVEk0Wm1FMVlqYzJZamN6TVdJelFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY3ODQ3MDMzMSwiaWF0IjoxNjc4MzgzOTMxLCJub25jZSI6IlRSNGxsalRjREdnYmllMWo1WnZFM2ciLCJhdF9oYXNoIjoid2J3dzRBQkJMT0FqQ2VZUUE2R3FWQSIsImNfaGFzaCI6IkQ3WTBiX3QxVEx5XzIwLXlLSHZ6OUEiLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IlNtaXRoLCBBbGljZSBNIChRQSkifQ.slayWNQdWMISxWpcNefdbWsV2SDYPvGi47bADwu9kTYk59gwLOBUL5N6Qr0hnPrstFxLwo3Tr5qNROMaGwnNeGRSg9nFMO6B_ke5lUbyB4I9W6spmnL0_XMnjvDqEH1pG88vQ9B2IiuSIvIGUOW9S5WS2Y0vT6jPc3p7zUZuRQf5hqMXCzN1aFgG9tjhp0Fck321y6a7k-LCAg1oDc5yrth3egcRuicz6VCF0u9wKc1K9fij5NfpJkQTyO_a4iLpkoWVAN2jU1Uppl88yG7OZpIRuG4WYtLKuXqZ13SUpCFd52i_46d-GwkdzS4g-mpdDwHifuqflguKoaOu8y5TYA)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5MGJlMzQ1MWMzYTYxMTgwMDU1ODE0ZWU2
ZDZjNTVjZWZkMDk3NGYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5ODY0L2RleCIsI
nN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVIVm1oTmVrSnFUa1JKZDFwVVJUSk9SM
UpxV2xkRmVGbDZSbXROZWsxM1RWZFplRTFYV1hwTlIxVXZaVEk0Wm1FMVlqYzJZa
mN6TVdJelFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4c
CI6MTY3ODQ3MDMzMSwiaWF0IjoxNjc4MzgzOTMxLCJub25jZSI6IlRSNGxsalRjR
EdnYmllMWo1WnZFM2ciLCJhdF9oYXNoIjoid2J3dzRBQkJMT0FqQ2VZUUE2R3FWQ
SIsImNfaGFzaCI6IkQ3WTBiX3QxVEx5XzIwLXlLSHZ6OUEiLCJuYW1lIjoiaW06d
2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2Vyb
mFtZSI6IlNtaXRoLCBBbGljZSBNIChRQSkifQ.slayWNQdWMISxWpcNefdbWsV2S
DYPvGi47bADwu9kTYk59gwLOBUL5N6Qr0hnPrstFxLwo3Tr5qNROMaGwnNeGRSg9
nFMO6B_ke5lUbyB4I9W6spmnL0_XMnjvDqEH1pG88vQ9B2IiuSIvIGUOW9S5WS2Y
0vT6jPc3p7zUZuRQf5hqMXCzN1aFgG9tjhp0Fck321y6a7k-LCAg1oDc5yrth3eg
cRuicz6VCF0u9wKc1K9fij5NfpJkQTyO_a4iLpkoWVAN2jU1Uppl88yG7OZpIRuG
4WYtLKuXqZ13SUpCFd52i_46d-GwkdzS4g-mpdDwHifuqflguKoaOu8y5TYA
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "590be3451c3a61180055814ee6d6c55cefd0974f"
}
```

```json
{
  "iss": "http://dex:19864/dex",
  "sub": "Ck9pbTp3aXJlYXBwPU5HVmhNekJqTkRJd1pURTJOR1JqWldFeFl6RmtNek13TVdZeE1XWXpNR1UvZTI4ZmE1Yjc2YjczMWIzQHdpcmUuY29tEgRsZGFw",
  "aud": "wireapp",
  "exp": 1678470331,
  "iat": 1678383931,
  "nonce": "TR4lljTcDGgbie1j5ZvE3g",
  "at_hash": "wbww4ABBLOAjCeYQA6GqVA",
  "c_hash": "D7Y0b_t1TLy_20-yKHvz9A",
  "name": "im:wireapp=alice.smith.qa@wire.com",
  "preferred_username": "Smith, Alice M (QA)"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtuFjEQ9j4p3lIKvEvpgK
2wVmJ0FzFy5pKUUNgtyNu5M5yvDRf8iNdlkq1Sqq/Zrnnnaoe5T/Um/Or5eePRh9
pdCTrcv9iP4UtKXZBuK9nofxtVP/RuZ/sFn0+FF4Oaijvf5LUmcvG0BfXVqyyPQP
hPvDclKxYbt7lrjIfU8dKmXEWDlIMNoK334sRS+nPnnFpzq5iVX4WnPvMCmskLB/
8OSO69fCBS5ERLCZmbNWKpEFiPYfPQwLap/aJJoDueklUM2V9KILR71TI3wPqsXs
tYBBxOfn8SwWklFmb0NLAkkqdkrUHQSNb9PLVPncjcpCISrzeTvI1+3M3Aari1e+
nQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/tlKZbv1pdNIo8WaWQq2GRtbov3TXPDui
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1ODM0L2FjbWUvd2lyZS9hY2NvdW50L005dFZ1Ym5JQnFhcmtLYWJCQUJ4N1BNU0I4cEtOQ2F1IiwidHlwIjoiSldUIiwibm9uY2UiOiJTMmRoVXpCcmNFODJWWFZWU0hnd1JFVXlWV3hoVjNCSmJUbFFaa1I0WWpZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTU4MzQvYWNtZS93aXJlL2NoYWxsZW5nZS9ON2tJb2Z5bGdMNTNlZGljelJxeVEwWUZHWjNIa29YOS90bEtaYnYxcGROSW84V2FXUXEyR1J0Ym92M1RYUER1aSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJalU1TUdKbE16UTFNV016WVRZeE1UZ3dNRFUxT0RFMFpXVTJaRFpqTlRWalpXWmtNRGszTkdZaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTVPRFkwTDJSbGVDSXNJbk4xWWlJNklrTnJPWEJpVkhBellWaEtiRmxZUW5kUVZUVklWbTFvVG1WclNuRlVhMUpLWkRGd1ZWSlVTazlTTVVweFYyeGtSbVZHYkRaU2JYUk9aV3N4TTFSV1pGcGxSVEZZVjFod1RsSXhWWFphVkVrMFdtMUZNVmxxWXpKWmFtTjZUVmRKZWxGSVpIQmpiVlYxV1RJNWRFVm5Vbk5hUjBaM0lpd2lZWFZrSWpvaWQybHlaV0Z3Y0NJc0ltVjRjQ0k2TVRZM09EUTNNRE16TVN3aWFXRjBJam94TmpjNE16Z3pPVE14TENKdWIyNWpaU0k2SWxSU05HeHNhbFJqUkVkblltbGxNV28xV25aRk0yY2lMQ0poZEY5b1lYTm9Jam9pZDJKM2R6UkJRa0pNVDBGcVEyVlpVVUUyUjNGV1FTSXNJbU5mYUdGemFDSTZJa1EzV1RCaVgzUXhWRXg1WHpJd0xYbExTSFo2T1VFaUxDSnVZVzFsSWpvaWFXMDZkMmx5WldGd2NEMWhiR2xqWlM1emJXbDBhQzV4WVVCM2FYSmxMbU52YlNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbE50YVhSb0xDQkJiR2xqWlNCTklDaFJRU2tpZlEuc2xheVdOUWRXTUlTeFdwY05lZmRiV3NWMlNEWVB2R2k0N2JBRHd1OWtUWWs1OWd3TE9CVUw1TjZRcjBoblByc3RGeEx3bzNUcjVxTlJPTWFHd25OZUdSU2c5bkZNTzZCX2tlNWxVYnlCNEk5VzZzcG1uTDBfWE1uanZEcUVIMXBHODh2UTlCMklpdVNJdklHVU9XOVM1V1MyWTB2VDZqUGMzcDd6VVp1UlFmNWhxTVhDek4xYUZnRzl0amhwMEZjazMyMXk2YTdrLUxDQWcxb0RjNXlydGgzZWdjUnVpY3o2VkNGMHU5d0tjMUs5ZmlqNU5mcEprUVR5T19hNGlMcGtvV1ZBTjJqVTFVcHBsODh5RzdPWnBJUnVHNFdZdExLdVhxWjEzU1VwQ0ZkNTJpXzQ2ZC1Hd2tkelM0Zy1tcGREd0hpZnVxZmxndUtvYU91OHk1VFlBIiwia2V5YXV0aCI6IkJaU0k1SHJDVDQwWkFaMkpieEUxbHdKWHh3UFdNVGg5LjY5RG0wZlFGYmVTUmlxdWVmTzVlR2M1ancwRHlkbVF2OEFLZVhsLU0xQmcifQ",
  "signature": "7HAWdjLOfKlxPKiGIP_uHBZHUvSYApKl2Aj1XnUIQ5EQWInEec5N-w6zqmFuDfSZ5SYHX3TX7SAnXUb-qEavAw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55834/acme/wire/account/M9tVubnIBqarkKabBABx7PMSB8pKNCau",
    "typ": "JWT",
    "nonce": "S2dhUzBrcE82VXVVSHgwREUyVWxhV3BJbTlQZkR4YjY",
    "url": "https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/tlKZbv1pdNIo8WaWQq2GRtbov3TXPDui"
  },
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjU5MGJlMzQ1MWMzYTYxMTgwMDU1ODE0ZWU2ZDZjNTVjZWZkMDk3NGYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE5ODY0L2RleCIsInN1YiI6IkNrOXBiVHAzYVhKbFlYQndQVTVIVm1oTmVrSnFUa1JKZDFwVVJUSk9SMUpxV2xkRmVGbDZSbXROZWsxM1RWZFplRTFYV1hwTlIxVXZaVEk0Wm1FMVlqYzJZamN6TVdJelFIZHBjbVV1WTI5dEVnUnNaR0Z3IiwiYXVkIjoid2lyZWFwcCIsImV4cCI6MTY3ODQ3MDMzMSwiaWF0IjoxNjc4MzgzOTMxLCJub25jZSI6IlRSNGxsalRjREdnYmllMWo1WnZFM2ciLCJhdF9oYXNoIjoid2J3dzRBQkJMT0FqQ2VZUUE2R3FWQSIsImNfaGFzaCI6IkQ3WTBiX3QxVEx5XzIwLXlLSHZ6OUEiLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IlNtaXRoLCBBbGljZSBNIChRQSkifQ.slayWNQdWMISxWpcNefdbWsV2SDYPvGi47bADwu9kTYk59gwLOBUL5N6Qr0hnPrstFxLwo3Tr5qNROMaGwnNeGRSg9nFMO6B_ke5lUbyB4I9W6spmnL0_XMnjvDqEH1pG88vQ9B2IiuSIvIGUOW9S5WS2Y0vT6jPc3p7zUZuRQf5hqMXCzN1aFgG9tjhp0Fck321y6a7k-LCAg1oDc5yrth3egcRuicz6VCF0u9wKc1K9fij5NfpJkQTyO_a4iLpkoWVAN2jU1Uppl88yG7OZpIRuG4WYtLKuXqZ13SUpCFd52i_46d-GwkdzS4g-mpdDwHifuqflguKoaOu8y5TYA",
    "keyauth": "BZSI5HrCT40ZAZ2JbxE1lwJXxwPWMTh9.69Dm0fQFbeSRiquefO5eGc5jw0DydmQv8AKeXl-M1Bg"
  }
}
```
#### 31. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55834/acme/wire/directory>;rel="index"
link: <https://stepca:55834/acme/wire/authz/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9>;rel="up"
location: https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/tlKZbv1pdNIo8WaWQq2GRtbov3TXPDui
replay-nonce: em44SEJiblZKMEprY3dsekc0SGpsNEg4elhQS29xUkk
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:55834/acme/wire/challenge/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9/tlKZbv1pdNIo8WaWQq2GRtbov3TXPDui",
  "status": "valid",
  "token": "BZSI5HrCT40ZAZ2JbxE1lwJXxwPWMTh9"
}
```
### Client presents a CSR and gets its certificate
#### 32. verify the status of the order
```http request
POST https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1ODM0L2FjbWUvd2lyZS9hY2NvdW50L005dFZ1Ym5JQnFhcmtLYWJCQUJ4N1BNU0I4cEtOQ2F1IiwidHlwIjoiSldUIiwibm9uY2UiOiJlbTQ0U0VKaWJsWktNRXByWTNkc2VrYzBTR3BzTkVnNGVsaFFTMjl4VWtrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTU4MzQvYWNtZS93aXJlL29yZGVyL0dBQnZKUE1mN0NxYmRVcW5KVHlYOFQyRWJJemZEQ3RXIn0",
  "payload": "",
  "signature": "heNltR-aVATd6yPWCiEsDfNTXcOeZgH5y75m9tvcVE6bp4q8cGWrr4iFaEmiUOOVGUsWUYcVn4AtwbKMFA5DCw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55834/acme/wire/account/M9tVubnIBqarkKabBABx7PMSB8pKNCau",
    "typ": "JWT",
    "nonce": "em44SEJiblZKMEprY3dsekc0SGpsNEg4elhQS29xUkk",
    "url": "https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW"
  },
  "payload": {}
}
```
#### 33. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55834/acme/wire/directory>;rel="index"
location: https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW
replay-nonce: TzFMYkJyVWMyc1NLM1c0WEgwM1ltWDgxc3NKT3EyR0Q
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGVhMzBjNDIwZTE2NGRjZWExYzFkMzMwMWYxMWYzMGU/e28fa5b76b731b3@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55834/acme/wire/authz/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9"
  ],
  "expires": "2023-03-10T17:45:31Z",
  "notBefore": "2023-03-09T17:45:31.696104Z",
  "notAfter": "2023-03-09T18:45:31.696104Z"
}
```
#### 34. create a CSR and call finalize url
```http request
POST https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1ODM0L2FjbWUvd2lyZS9hY2NvdW50L005dFZ1Ym5JQnFhcmtLYWJCQUJ4N1BNU0I4cEtOQ2F1IiwidHlwIjoiSldUIiwibm9uY2UiOiJUekZNWWtKeVZXTXljMU5MTTFjMFdFZ3dNMWx0V0RneGMzTktUM0V5UjBRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTU4MzQvYWNtZS93aXJlL29yZGVyL0dBQnZKUE1mN0NxYmRVcW5KVHlYOFQyRWJJemZEQ3RXL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCVHpDQ0FRRUNBUUF3T1RFa01DSUdDMkNHU0FHRy1FSURBWUZ4REJOVGJXbDBhQ3dnUVd4cFkyVWdUU0FvVVVFcE1SRXdEd1lEVlFRS0RBaDNhWEpsTG1OdmJUQXFNQVVHQXl0bGNBTWhBTXNjaWxWTGdKODJfWDdsOUNhTGxXTVJaa3lyYTYwN0ZkeGFnSFZRQjNEbm9JR1VNSUdSQmdrcWhraUc5dzBCQ1E0eGdZTXdnWUF3ZmdZRFZSMFJCSGN3ZFlaUGFXMDZkMmx5WldGd2NEMXVaM1pvYlhwaWFtNWthWGQ2ZEdVeWJtZHlhbnAzWlhoNWVtWnJiWHB0ZDIxM2VYaHRkM2w2YldkMUwyVXlPR1poTldJM05tSTNNekZpTTBCM2FYSmxMbU52YllZaWFXMDZkMmx5WldGd2NEMWhiR2xqWlM1emJXbDBhQzV4WVVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFCQUdoejhzVDZvbWoyZUdteUJFMGo2YTl2Zm5zRW9QVmVyMFZtcVIwMmpLcXBhSHE5djFwUGJTSzg1MmVvUUVHYWdpWjRMSEpNbXRReE9oMDRyOTJNRyJ9",
  "signature": "Ufq6lFwm6uTnwKRKf56DM6hRLPEDaDuvzGfh7f2k6nwOW9jRPIBZI5XM9v0G-okpdcmhB5yYRJkivEtX9HhpAg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55834/acme/wire/account/M9tVubnIBqarkKabBABx7PMSB8pKNCau",
    "typ": "JWT",
    "nonce": "TzFMYkJyVWMyc1NLM1c0WEgwM1ltWDgxc3NKT3EyR0Q",
    "url": "https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW/finalize"
  },
  "payload": {
    "csr": "MIIBTzCCAQECAQAwOTEkMCIGC2CGSAGG-EIDAYFxDBNTbWl0aCwgQWxpY2UgTSAoUUEpMREwDwYDVQQKDAh3aXJlLmNvbTAqMAUGAytlcAMhAMscilVLgJ82_X7l9CaLlWMRZkyra607FdxagHVQB3DnoIGUMIGRBgkqhkiG9w0BCQ4xgYMwgYAwfgYDVR0RBHcwdYZPaW06d2lyZWFwcD1uZ3ZobXpiam5kaXd6dGUybmdyanp3ZXh5emZrbXptd213eXhtd3l6bWd1L2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbYYiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbTAFBgMrZXADQQBAGhz8sT6omj2eGmyBE0j6a9vfnsEoPVer0VmqR02jKqpaHq9v1pPbSK852eoQEGagiZ4LHJMmtQxOh04r92MG"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBTzCCAQECAQAwOTEkMCIGC2CGSAGG+EIDAYFxDBNTbWl0aCwgQWxpY2UgTSAo
UUEpMREwDwYDVQQKDAh3aXJlLmNvbTAqMAUGAytlcAMhAMj4HcHDGNFEVp/eC91n
zFsRgMfuTMvmtMavJ0+rQf+ooIGUMIGRBgkqhkiG9w0BCQ4xgYMwgYAwfgYDVR0R
BHcwdYZPaW06d2lyZWFwcD1uZ3ZobXpiam5kaXd6dGUybmdyanp3ZXh5emZrbXpt
d213eXhtd3l6bWd1L2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbYYiaW06d2lyZWFw
cD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbTAFBgMrZXADQQA1RE2MAQ2Je/Py6stv
E2gno7XIAzCAVSh+VmsEC27IpwNwY7X5zQKuBhvhbdfzjZJ8nqrI8oEFGxaV/1pm
k8sP
-----END CERTIFICATE REQUEST-----

```
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: 2.16.840.1.113730.3.1.241 = "Smith, Alice M (QA)", O = wire.com
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    c8:f8:1d:c1:c3:18:d1:44:56:9f:de:0b:dd:67:cc:
                    5b:11:80:c7:ee:4c:cb:e6:b4:c6:af:27:4f:ab:41:
                    ff:a8
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=ngvhmzbjndiwzte2ngrjzwexyzfkmzmwmwyxmwyzmgu/e28fa5b76b731b3@wire.com, URI:im:wireapp=alice.smith.qa@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        35:44:4d:8c:01:0d:89:7b:f3:f2:ea:cb:6f:13:68:27:a3:b5:
        c8:03:30:80:55:28:7e:56:6b:04:0b:6e:c8:a7:03:70:63:b5:
        f9:cd:02:ae:06:1b:e1:6d:d7:f3:8d:92:7c:9e:aa:c8:f2:81:
        05:1b:16:95:ff:5a:66:93:cb:0f

```

#### 35. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55834/acme/wire/directory>;rel="index"
location: https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW
replay-nonce: SGdxN3NGQjhwTTRSYk5zWXpRbDJUcUl6dDdmaDFGSFo
```
```json
{
  "certificate": "https://stepca:55834/acme/wire/certificate/HxDzSMtcRmY1avHP4iT86D0qog6Vj0tA",
  "status": "valid",
  "finalize": "https://stepca:55834/acme/wire/order/GABvJPMf7CqbdUqnJTyX8T2EbIzfDCtW/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGVhMzBjNDIwZTE2NGRjZWExYzFkMzMwMWYxMWYzMGU/e28fa5b76b731b3@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55834/acme/wire/authz/N7kIofylgL53ediczRqyQ0YFGZ3HkoX9"
  ],
  "expires": "2023-03-10T17:45:31Z",
  "notBefore": "2023-03-09T17:45:31.696104Z",
  "notAfter": "2023-03-09T18:45:31.696104Z"
}
```
#### 36. fetch the certificate
```http request
POST https://stepca:55834/acme/wire/certificate/HxDzSMtcRmY1avHP4iT86D0qog6Vj0tA
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1ODM0L2FjbWUvd2lyZS9hY2NvdW50L005dFZ1Ym5JQnFhcmtLYWJCQUJ4N1BNU0I4cEtOQ2F1IiwidHlwIjoiSldUIiwibm9uY2UiOiJTR2R4TjNOR1FqaHdUVFJTWWs1eldYcFJiREpVY1VsNmREZG1hREZHU0ZvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTU4MzQvYWNtZS93aXJlL2NlcnRpZmljYXRlL0h4RHpTTXRjUm1ZMWF2SFA0aVQ4NkQwcW9nNlZqMHRBIn0",
  "payload": "",
  "signature": "PhC3dPhIzPNv4qfQnVVky1yaSm_Kr3lkrVDwkcplbgWY9zUqgQrtj2HOJkm6f8gA5XVrXjQn1-9FicilO6MABg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55834/acme/wire/account/M9tVubnIBqarkKabBABx7PMSB8pKNCau",
    "typ": "JWT",
    "nonce": "SGdxN3NGQjhwTTRSYk5zWXpRbDJUcUl6dDdmaDFGSFo",
    "url": "https://stepca:55834/acme/wire/certificate/HxDzSMtcRmY1avHP4iT86D0qog6Vj0tA"
  },
  "payload": {}
}
```
#### 37. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:55834/acme/wire/directory>;rel="index"
replay-nonce: eDRnWkFSZkg0M0lkU2VZcDVIY1pST3d2RDNVZDJDMWQ
```
```json
[
  "MIICQzCCAemgAwIBAgIRAMjEd86A3Wdpd1O5Fqo23lEwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwMzA5MTc0NTMxWhcNMjMwMzA5MTg0NTMxWjAxMREwDwYDVQQKEwh3aXJlLmNv\nbTEcMBoGA1UEAxMTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhAMscilVL\ngJ82/X7l9CaLlWMRZkyra607FdxagHVQB3Dno4IBEjCCAQ4wDgYDVR0PAQH/BAQD\nAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU+BQ5\nwb2oq5+y+sikd6G2E0QL4JowHwYDVR0jBBgwFoAUel0wq4WPec6urBmogrwaM1xf\nzzAwfgYDVR0RBHcwdYYiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNv\nbYZPaW06d2lyZWFwcD1uZ3ZobXpiam5kaXd6dGUybmdyanp3ZXh5emZrbXptd213\neXhtd3l6bWd1L2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbTAdBgwrBgEEAYKkZMYo\nQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIhALpj+vDTy0ZhupPv\n60mm/R8FG1+WfJVurm347iTiFnwvAiBlxS2NcJ0hA2bqDOY2OjniMXqtd/33ruVx\nn7Omklha6g==",
  "MIIBujCCAV+gAwIBAgIRAJzKx+gx9Im3GaKmZHu8Vi4wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMwOTE3\nNDUyNloXDTMzMDMwNjE3NDUyNlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATA\nkL7iEjti0jZUzddvyNz7s6bz9nT9wE3i/6m3wJIUBOmmxjGtL7zei10Ug0shUAy9\nwi6gzOO2nLO8M5Ng5I2Jo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUel0wq4WPec6urBmogrwaM1xfzzAwHwYDVR0jBBgw\nFoAUTvCb6QFlsO03eCI1y6/BHRKC+x0wCgYIKoZIzj0EAwIDSQAwRgIhANblRvok\nQrGKa/Yf2LZ29J2DpnRtl9clsb9wnD/xXp+yAiEAwURTfSSMOPEKwRBRU2Ot/6R5\nPE0YTICFWBpg2Lack54="
]
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICQzCCAemgAwIBAgIRAMjEd86A3Wdpd1O5Fqo23lEwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwMzA5MTc0NTMxWhcNMjMwMzA5MTg0NTMxWjAxMREwDwYDVQQKEwh3aXJlLmNv
bTEcMBoGA1UEAxMTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhAMscilVL
gJ82/X7l9CaLlWMRZkyra607FdxagHVQB3Dno4IBEjCCAQ4wDgYDVR0PAQH/BAQD
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU+BQ5
wb2oq5+y+sikd6G2E0QL4JowHwYDVR0jBBgwFoAUel0wq4WPec6urBmogrwaM1xf
zzAwfgYDVR0RBHcwdYYiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNv
bYZPaW06d2lyZWFwcD1uZ3ZobXpiam5kaXd6dGUybmdyanp3ZXh5emZrbXptd213
eXhtd3l6bWd1L2UyOGZhNWI3NmI3MzFiM0B3aXJlLmNvbTAdBgwrBgEEAYKkZMYo
QAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIhALpj+vDTy0ZhupPv
60mm/R8FG1+WfJVurm347iTiFnwvAiBlxS2NcJ0hA2bqDOY2OjniMXqtd/33ruVx
n7Omklha6g==
-----END CERTIFICATE-----
```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            c8:c4:77:ce:80:dd:67:69:77:53:b9:16:aa:36:de:51
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Mar  9 17:45:31 2023 GMT
            Not After : Mar  9 18:45:31 2023 GMT
        Subject: O = wire.com, CN = "Smith, Alice M (QA)"
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    cb:1c:8a:55:4b:80:9f:36:fd:7e:e5:f4:26:8b:95:
                    63:11:66:4c:ab:6b:ad:3b:15:dc:5a:80:75:50:07:
                    70:e7
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                F8:14:39:C1:BD:A8:AB:9F:B2:FA:C8:A4:77:A1:B6:13:44:0B:E0:9A
            X509v3 Authority Key Identifier: 
                7A:5D:30:AB:85:8F:79:CE:AE:AC:19:A8:82:BC:1A:33:5C:5F:CF:30
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice.smith.qa@wire.com, URI:im:wireapp=ngvhmzbjndiwzte2ngrjzwexyzfkmzmwmwyxmwyzmgu/e28fa5b76b731b3@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:ba:63:fa:f0:d3:cb:46:61:ba:93:ef:eb:49:
        a6:fd:1f:05:1b:5f:96:7c:95:6e:ae:6d:f8:ee:24:e2:16:7c:
        2f:02:20:65:c5:2d:8d:70:9d:21:03:66:ea:0c:e6:36:3a:39:
        e2:31:7a:ad:77:fd:f7:ae:e5:71:9f:b3:a6:92:58:5a:ea

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBujCCAV+gAwIBAgIRAJzKx+gx9Im3GaKmZHu8Vi4wCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMwOTE3
NDUyNloXDTMzMDMwNjE3NDUyNlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATA
kL7iEjti0jZUzddvyNz7s6bz9nT9wE3i/6m3wJIUBOmmxjGtL7zei10Ug0shUAy9
wi6gzOO2nLO8M5Ng5I2Jo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUel0wq4WPec6urBmogrwaM1xfzzAwHwYDVR0jBBgw
FoAUTvCb6QFlsO03eCI1y6/BHRKC+x0wCgYIKoZIzj0EAwIDSQAwRgIhANblRvok
QrGKa/Yf2LZ29J2DpnRtl9clsb9wnD/xXp+yAiEAwURTfSSMOPEKwRBRU2Ot/6R5
PE0YTICFWBpg2Lack54=
-----END CERTIFICATE-----
```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9c:ca:c7:e8:31:f4:89:b7:19:a2:a6:64:7b:bc:56:2e
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Mar  9 17:45:26 2023 GMT
            Not After : Mar  6 17:45:26 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:c0:90:be:e2:12:3b:62:d2:36:54:cd:d7:6f:c8:
                    dc:fb:b3:a6:f3:f6:74:fd:c0:4d:e2:ff:a9:b7:c0:
                    92:14:04:e9:a6:c6:31:ad:2f:bc:de:8b:5d:14:83:
                    4b:21:50:0c:bd:c2:2e:a0:cc:e3:b6:9c:b3:bc:33:
                    93:60:e4:8d:89
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                7A:5D:30:AB:85:8F:79:CE:AE:AC:19:A8:82:BC:1A:33:5C:5F:CF:30
            X509v3 Authority Key Identifier: 
                4E:F0:9B:E9:01:65:B0:ED:37:78:22:35:CB:AF:C1:1D:12:82:FB:1D
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:d6:e5:46:fa:24:42:b1:8a:6b:f6:1f:d8:b6:
        76:f4:9d:83:a6:74:6d:97:d7:25:b1:bf:70:9c:3f:f1:5e:9f:
        b2:02:21:00:c1:44:53:7d:24:8c:38:f1:0a:c1:10:51:53:63:
        ad:ff:a4:79:3c:4d:18:4c:80:85:58:1a:60:d8:b6:9c:93:9e

```
