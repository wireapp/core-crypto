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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/48f93c051d7168e2/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN/JMypt19IDyHWwePXO2qDSJQhVho6Y1bB
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK/eP1ZVUleDboZb4Qhn5YEzRC8CYoSAafA
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/9WPGu5WDMCUFoFGg1sln4iVpXcCbnuCX
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32818/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
x-request-id: c7123cbd-5024-46ee-9758-b1b5daba03a3
```
```json
{
  "newNonce": "https://stepca:32818/acme/wire/new-nonce",
  "newAccount": "https://stepca:32818/acme/wire/new-account",
  "newOrder": "https://stepca:32818/acme/wire/new-order",
  "revokeCert": "https://stepca:32818/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32818/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32818/acme/wire/directory>;rel="index"
replay-nonce: djhwTWdadWJWOUdqREJiQlZwT3VPczBFdFdWMU01Z0w
x-request-id: 4ec1182d-7ac6-4e43-81db-a3f3a733ea58
```
```text
djhwTWdadWJWOUdqREJiQlZwT3VPczBFdFdWMU01Z0w
```
#### 5. create a new account
```http request
POST https://stepca:32818/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkRKd2ZBdGczUFFBbnpYdXFodk9HOWtfSjRyb3Nncld2dHJ5cWJKekRqOXMifSwibm9uY2UiOiJkamh3VFdkYWRXSldPVWRxUkVKaVFsWndUM1ZQY3pCRmRGZFdNVTAxWjB3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "7d0XFTuvmnd1y6E09ob-IR1zzIZBLWI77Rn80_gtOZ_8BnGXBJq9oP2t8GQz0CdTqrR_EqHdsTTiroj2oN5dAQ"
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
      "x": "DJwfAtg3PQAnzXuqhvOG9k_J4rosgrWvtryqbJzDj9s"
    },
    "nonce": "djhwTWdadWJWOUdqREJiQlZwT3VPczBFdFdWMU01Z0w",
    "typ": "JWT",
    "url": "https://stepca:32818/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32818/acme/wire/directory>;rel="index"
location: https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli
replay-nonce: R1NrbmFHRlIzNXhWbXpFdXMwZHdmUnF2NFBJcDI4OUU
x-request-id: b34f4b41-bca6-40c2-a38c-beee014b2f88
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32818/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE4L2FjbWUvd2lyZS9hY2NvdW50L2JOVWdrVkR6am41dWpFdTVuVm9CTWxEWTNCN204bGxpIiwidHlwIjoiSldUIiwibm9uY2UiOiJSMU5yYm1GSFJsSXpOWGhXYlhwRmRYTXdaSGRtVW5GMk5GQkpjREk0T1VVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9uLWdkam83eFJ2bVZ2NmNDcXNGdGR3ITQ4ZjkzYzA1MWQ3MTY4ZTJAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0xMC0xN1QxMjozMDo1NC45NjQ1NDY0NzVaIiwibm90QWZ0ZXIiOiIyMDM0LTEwLTE1VDEyOjMwOjU0Ljk2NDU0NjQ3NVoifQ",
  "signature": "Ga5KMsv52uxumPqUQWdXLnJBeBWd2UOUg74q4vVGJ5ovFJSLEIm3XlsBaBbyP5IuYlgFsgAJKAvzjIJWwqd0BA"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://n-gdjo7xRvmVv6cCqsFtdw!48f93c051d7168e2@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2034-10-15T12:30:54.964546475Z",
    "notBefore": "2024-10-17T12:30:54.964546475Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli",
    "nonce": "R1NrbmFHRlIzNXhWbXpFdXMwZHdmUnF2NFBJcDI4OUU",
    "typ": "JWT",
    "url": "https://stepca:32818/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32818/acme/wire/directory>;rel="index"
location: https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T
replay-nonce: emVuNTg3S1RxWUg2Y0pUWk56enJtOXVVc2J6VVdwYVc
x-request-id: ee2bc093-a9b2-4254-a88f-4fb3badbcf5c
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://n-gdjo7xRvmVv6cCqsFtdw!48f93c051d7168e2@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32818/acme/wire/authz/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN",
    "https://stepca:32818/acme/wire/authz/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK"
  ],
  "expires": "2024-10-18T12:30:54Z",
  "notBefore": "2024-10-17T12:30:54.964546475Z",
  "notAfter": "2034-10-15T12:30:54.964546475Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32818/acme/wire/authz/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE4L2FjbWUvd2lyZS9hY2NvdW50L2JOVWdrVkR6am41dWpFdTVuVm9CTWxEWTNCN204bGxpIiwidHlwIjoiSldUIiwibm9uY2UiOiJlbVZ1TlRnM1MxUnhXVWcyWTBwVVdrNTZlbkp0T1hWVmMySjZWVmR3WVZjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL2F1dGh6L2h2b1NEWm1MN2Qxd0lIZWZxdGF5QWQ2WWhQWUozSnpOIn0",
  "payload": "",
  "signature": "TgCdAqKz1RdnWOezM-ov9_4y84i15dPB_njNxthBmkGr83zNDmi7kku-itwUP1PkPBZyHLdwYy08MP-7j14QBQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli",
    "nonce": "emVuNTg3S1RxWUg2Y0pUWk56enJtOXVVc2J6VVdwYVc",
    "typ": "JWT",
    "url": "https://stepca:32818/acme/wire/authz/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32818/acme/wire/directory>;rel="index"
location: https://stepca:32818/acme/wire/authz/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN
replay-nonce: UTRlNG9kNlJWMnRWU1o3Q3hEZFZlY0hLVDZPT1pZMHg
x-request-id: 6738c2e0-9530-40d2-856a-559739a6d271
```
```json
{
  "status": "pending",
  "expires": "2024-10-18T12:30:54Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32818/acme/wire/challenge/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN/JMypt19IDyHWwePXO2qDSJQhVho6Y1bB",
      "status": "pending",
      "token": "rm7VPT7dtCDXZ0f6n4QNsRMKJb570ngs",
      "target": "http://wire.com:24477/clients/48f93c051d7168e2/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://n-gdjo7xRvmVv6cCqsFtdw!48f93c051d7168e2@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:32818/acme/wire/authz/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE4L2FjbWUvd2lyZS9hY2NvdW50L2JOVWdrVkR6am41dWpFdTVuVm9CTWxEWTNCN204bGxpIiwidHlwIjoiSldUIiwibm9uY2UiOiJVVFJsTkc5a05sSldNblJXVTFvM1EzaEVaRlpsWTBoTFZEWlBUMXBaTUhnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL2F1dGh6L3pyYjJjQ0haQzBUNmF5dFZJOHpiNURDZzB5VjhUalhLIn0",
  "payload": "",
  "signature": "ENSNI2jiyOgbQlXGCtcnWUXd0EvR2I-DJDjw_b7TEhjuAJX6fBP6EBYQlkGJOWrETsSxr9sQA897D2JjEHZxCA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli",
    "nonce": "UTRlNG9kNlJWMnRWU1o3Q3hEZFZlY0hLVDZPT1pZMHg",
    "typ": "JWT",
    "url": "https://stepca:32818/acme/wire/authz/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK"
  }
}
```
#### 11. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32818/acme/wire/directory>;rel="index"
location: https://stepca:32818/acme/wire/authz/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK
replay-nonce: bzJpMTc3WnREbjJnT1NqakpsWTMzT2lyM0VZTEZsWGM
x-request-id: 6c4e741b-3fee-4d0e-863c-acec29c3c624
```
```json
{
  "status": "pending",
  "expires": "2024-10-18T12:30:54Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32818/acme/wire/challenge/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK/eP1ZVUleDboZb4Qhn5YEzRC8CYoSAafA",
      "status": "pending",
      "token": "YmOV7D5oTMLeKIevL0hqsOmE5zEAkF8l",
      "target": "http://keycloak:22847/realms/master"
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
GET http://wire.com:24477/clients/token/nonce
```
#### 13. get wire-server nonce
```http request
200

```
```text
YVpGcHU0MTc4a0k3d2pqT2Q1R2VhdWFzMnZqS3d1N2Q
```
#### 14. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiREp3ZkF0ZzNQUUFuelh1cWh2T0c5a19KNHJvc2dyV3Z0cnlxYkp6RGo5cyJ9fQ.eyJpYXQiOjE3MjkxNjQ2NTQsImV4cCI6MTcyOTE3MTg1NCwibmJmIjoxNzI5MTY0NjU0LCJzdWIiOiJ3aXJlYXBwOi8vbi1nZGpvN3hSdm1WdjZjQ3FzRnRkdyE0OGY5M2MwNTFkNzE2OGUyQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL2NoYWxsZW5nZS9odm9TRFptTDdkMXdJSGVmcXRheUFkNlloUFlKM0p6Ti9KTXlwdDE5SUR5SFd3ZVBYTzJxRFNKUWhWaG82WTFiQiIsImp0aSI6IjlkMDZkYTkxLThmZTUtNDIwOC04YTZmLTFmNjcyNjU1ODQ5NyIsIm5vbmNlIjoiWVZwR2NIVTBNVGM0YTBrM2QycHFUMlExUjJWaGRXRnpNblpxUzNkMU4yUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ0NzcvY2xpZW50cy80OGY5M2MwNTFkNzE2OGUyL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJybTdWUFQ3ZHRDRFhaMGY2bjRRTnNSTUtKYjU3MG5ncyIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.G_rErRQupBCFxxaMwNzAAw918LX-pT--LRGHiiiLpYqaEPSxpxBd9a7owNU8qg0hEIXgg-KN6oytx2_x0gMWAQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiREp3ZkF0ZzNQUUFuelh1cWh2T0c5a19K
NHJvc2dyV3Z0cnlxYkp6RGo5cyJ9fQ.eyJpYXQiOjE3MjkxNjQ2NTQsImV4cCI6M
TcyOTE3MTg1NCwibmJmIjoxNzI5MTY0NjU0LCJzdWIiOiJ3aXJlYXBwOi8vbi1nZ
GpvN3hSdm1WdjZjQ3FzRnRkdyE0OGY5M2MwNTFkNzE2OGUyQHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL2NoYWxsZW5nZS9od
m9TRFptTDdkMXdJSGVmcXRheUFkNlloUFlKM0p6Ti9KTXlwdDE5SUR5SFd3ZVBYT
zJxRFNKUWhWaG82WTFiQiIsImp0aSI6IjlkMDZkYTkxLThmZTUtNDIwOC04YTZmL
TFmNjcyNjU1ODQ5NyIsIm5vbmNlIjoiWVZwR2NIVTBNVGM0YTBrM2QycHFUMlExU
jJWaGRXRnpNblpxUzNkMU4yUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MjQ0NzcvY2xpZW50cy80OGY5M2MwNTFkNzE2OGUyL2FjY2Vzcy10b
2tlbiIsImNoYWwiOiJybTdWUFQ3ZHRDRFhaMGY2bjRRTnNSTUtKYjU3MG5ncyIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.G_rErRQupBCFxxaMwNzAAw
918LX-pT--LRGHiiiLpYqaEPSxpxBd9a7owNU8qg0hEIXgg-KN6oytx2_x0gMWAQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "DJwfAtg3PQAnzXuqhvOG9k_J4rosgrWvtryqbJzDj9s"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:32818/acme/wire/challenge/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN/JMypt19IDyHWwePXO2qDSJQhVho6Y1bB",
  "chal": "rm7VPT7dtCDXZ0f6n4QNsRMKJb570ngs",
  "exp": 1729171854,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:24477/clients/48f93c051d7168e2/access-token",
  "iat": 1729164654,
  "jti": "9d06da91-8fe5-4208-8a6f-1f6726558497",
  "name": "Alice Smith",
  "nbf": 1729164654,
  "nonce": "YVpGcHU0MTc4a0k3d2pqT2Q1R2VhdWFzMnZqS3d1N2Q",
  "sub": "wireapp://n-gdjo7xRvmVv6cCqsFtdw!48f93c051d7168e2@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEADJwfAtg3PQAnzXuqhvOG9k/J4rosgrWvtryqbJzDj9s=
-----END PUBLIC KEY-----
```

</details>


#### 15. trade client DPoP token for an access token
```http request
POST http://wire.com:24477/clients/48f93c051d7168e2/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pUkVwM1prRjBaek5RVVVGdWVsaDFjV2gyVDBjNWExOUtOSEp2YzJkeVYzWjBjbmx4WWtwNlJHbzVjeUo5ZlEuZXlKcFlYUWlPakUzTWpreE5qUTJOVFFzSW1WNGNDSTZNVGN5T1RFM01UZzFOQ3dpYm1KbUlqb3hOekk1TVRZME5qVTBMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZiaTFuWkdwdk4zaFNkbTFXZGpaalEzRnpSblJrZHlFME9HWTVNMk13TlRGa056RTJPR1V5UUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNekk0TVRndllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTOW9kbTlUUkZwdFREZGtNWGRKU0dWbWNYUmhlVUZrTmxsb1VGbEtNMHA2VGk5S1RYbHdkREU1U1VSNVNGZDNaVkJZVHpKeFJGTktVV2hXYUc4MldURmlRaUlzSW1wMGFTSTZJamxrTURaa1lUa3hMVGhtWlRVdE5ESXdPQzA0WVRabUxURm1OamN5TmpVMU9EUTVOeUlzSW01dmJtTmxJam9pV1Zad1IyTklWVEJOVkdNMFlUQnJNMlF5Y0hGVU1sRXhVakpXYUdSWFJucE5ibHB4VXpOa01VNHlVU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRME56Y3ZZMnhwWlc1MGN5ODBPR1k1TTJNd05URmtOekUyT0dVeUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUp5YlRkV1VGUTNaSFJEUkZoYU1HWTJialJSVG5OU1RVdEtZalUzTUc1bmN5SXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpTENKdVlXMWxJam9pUVd4cFkyVWdVMjFwZEdnaWZRLkdfckVyUlF1cEJDRnh4YU13TnpBQXc5MThMWC1wVC0tTFJHSGlpaUxwWXFhRVBTeHB4QmQ5YTdvd05VOHFnMGhFSVhnZy1LTjZveXR4Ml94MGdNV0FR
```
#### 16. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkI4RzNjYlhVQm9pVEFhckZNQmdlOW1rUWJmMXhTQ2hNeFVZaXRuMzFLdjQifX0.eyJpYXQiOjE3MjkxNjQ2NTQsImV4cCI6MTcyOTE2ODYxNCwibmJmIjoxNzI5MTY0NjU0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ0NzcvY2xpZW50cy80OGY5M2MwNTFkNzE2OGUyL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9uLWdkam83eFJ2bVZ2NmNDcXNGdGR3ITQ4ZjkzYzA1MWQ3MTY4ZTJAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjgxOC9hY21lL3dpcmUvY2hhbGxlbmdlL2h2b1NEWm1MN2Qxd0lIZWZxdGF5QWQ2WWhQWUozSnpOL0pNeXB0MTlJRHlIV3dlUFhPMnFEU0pRaFZobzZZMWJCIiwianRpIjoiNGQ0MzViOWEtNzhlYi00NzA2LTlmYjgtMDQ1NTJlNTI3ZjBlIiwibm9uY2UiOiJZVnBHY0hVME1UYzRhMGszZDJwcVQyUTFSMlZoZFdGek1uWnFTM2QxTjJRIiwiY2hhbCI6InJtN1ZQVDdkdENEWFowZjZuNFFOc1JNS0piNTcwbmdzIiwiY25mIjp7ImtpZCI6IjhfeWFiRTlSeWMtS1V6R3JBM0VJa0Z1d1pfU3Zrd3pRUENqQ3JjcWRVb0EifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lSRXAzWmtGMFp6TlFVVUZ1ZWxoMWNXaDJUMGM1YTE5S05ISnZjMmR5VjNaMGNubHhZa3A2UkdvNWN5SjlmUS5leUpwWVhRaU9qRTNNamt4TmpRMk5UUXNJbVY0Y0NJNk1UY3lPVEUzTVRnMU5Dd2libUptSWpveE56STVNVFkwTmpVMExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmJpMW5aR3B2TjNoU2RtMVdkalpqUTNGelJuUmtkeUUwT0dZNU0yTXdOVEZrTnpFMk9HVXlRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRNVGd2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5b2RtOVRSRnB0VERka01YZEpTR1ZtY1hSaGVVRmtObGxvVUZsS00wcDZUaTlLVFhsd2RERTVTVVI1U0ZkM1pWQllUekp4UkZOS1VXaFdhRzgyV1RGaVFpSXNJbXAwYVNJNklqbGtNRFprWVRreExUaG1aVFV0TkRJd09DMDRZVFptTFRGbU5qY3lOalUxT0RRNU55SXNJbTV2Ym1ObElqb2lXVlp3UjJOSVZUQk5WR00wWVRCck0yUXljSEZVTWxFeFVqSldhR1JYUm5wTmJscHhVek5rTVU0eVVTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEwTnpjdlkyeHBaVzUwY3k4ME9HWTVNMk13TlRGa056RTJPR1V5TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnliVGRXVUZRM1pIUkRSRmhhTUdZMmJqUlJUbk5TVFV0S1lqVTNNRzVuY3lJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuR19yRXJSUXVwQkNGeHhhTXdOekFBdzkxOExYLXBULS1MUkdIaWlpTHBZcWFFUFN4cHhCZDlhN293TlU4cWcwaEVJWGdnLUtONm95dHgyX3gwZ01XQVEiLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vbi1nZGpvN3hSdm1WdjZjQ3FzRnRkdyE0OGY5M2MwNTFkNzE2OGUyQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Si9uQkR_yy1sXUkLLGxujLUbFAmbbkp5-u-l_WDTJ7qq1C2E7odsDCYib68JCkZSpedqMCwlqKasTyq_xGN2BA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkI4RzNjYlhVQm9pVEFhckZNQmdlOW1rUWJmMXhTQ2hNeFVZaXRuMzFLdjQifX0.eyJpYXQiOjE3MjkxNjQ2NTQsImV4cCI6MTcyOTE2ODYxNCwibmJmIjoxNzI5MTY0NjU0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ0NzcvY2xpZW50cy80OGY5M2MwNTFkNzE2OGUyL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9uLWdkam83eFJ2bVZ2NmNDcXNGdGR3ITQ4ZjkzYzA1MWQ3MTY4ZTJAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjgxOC9hY21lL3dpcmUvY2hhbGxlbmdlL2h2b1NEWm1MN2Qxd0lIZWZxdGF5QWQ2WWhQWUozSnpOL0pNeXB0MTlJRHlIV3dlUFhPMnFEU0pRaFZobzZZMWJCIiwianRpIjoiNGQ0MzViOWEtNzhlYi00NzA2LTlmYjgtMDQ1NTJlNTI3ZjBlIiwibm9uY2UiOiJZVnBHY0hVME1UYzRhMGszZDJwcVQyUTFSMlZoZFdGek1uWnFTM2QxTjJRIiwiY2hhbCI6InJtN1ZQVDdkdENEWFowZjZuNFFOc1JNS0piNTcwbmdzIiwiY25mIjp7ImtpZCI6IjhfeWFiRTlSeWMtS1V6R3JBM0VJa0Z1d1pfU3Zrd3pRUENqQ3JjcWRVb0EifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lSRXAzWmtGMFp6TlFVVUZ1ZWxoMWNXaDJUMGM1YTE5S05ISnZjMmR5VjNaMGNubHhZa3A2UkdvNWN5SjlmUS5leUpwWVhRaU9qRTNNamt4TmpRMk5UUXNJbVY0Y0NJNk1UY3lPVEUzTVRnMU5Dd2libUptSWpveE56STVNVFkwTmpVMExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmJpMW5aR3B2TjNoU2RtMVdkalpqUTNGelJuUmtkeUUwT0dZNU0yTXdOVEZrTnpFMk9HVXlRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRNVGd2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5b2RtOVRSRnB0VERka01YZEpTR1ZtY1hSaGVVRmtObGxvVUZsS00wcDZUaTlLVFhsd2RERTVTVVI1U0ZkM1pWQllUekp4UkZOS1VXaFdhRzgyV1RGaVFpSXNJbXAwYVNJNklqbGtNRFprWVRreExUaG1aVFV0TkRJd09DMDRZVFptTFRGbU5qY3lOalUxT0RRNU55SXNJbTV2Ym1ObElqb2lXVlp3UjJOSVZUQk5WR00wWVRCck0yUXljSEZVTWxFeFVqSldhR1JYUm5wTmJscHhVek5rTVU0eVVTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEwTnpjdlkyeHBaVzUwY3k4ME9HWTVNMk13TlRGa056RTJPR1V5TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnliVGRXVUZRM1pIUkRSRmhhTUdZMmJqUlJUbk5TVFV0S1lqVTNNRzVuY3lJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuR19yRXJSUXVwQkNGeHhhTXdOekFBdzkxOExYLXBULS1MUkdIaWlpTHBZcWFFUFN4cHhCZDlhN293TlU4cWcwaEVJWGdnLUtONm95dHgyX3gwZ01XQVEiLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vbi1nZGpvN3hSdm1WdjZjQ3FzRnRkdyE0OGY5M2MwNTFkNzE2OGUyQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Si9uQkR_yy1sXUkLLGxujLUbFAmbbkp5-u-l_WDTJ7qq1C2E7odsDCYib68JCkZSpedqMCwlqKasTyq_xGN2BA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IkI4RzNjYlhVQm9pVEFhckZNQmdlOW1rUWJm
MXhTQ2hNeFVZaXRuMzFLdjQifX0.eyJpYXQiOjE3MjkxNjQ2NTQsImV4cCI6MTcy
OTE2ODYxNCwibmJmIjoxNzI5MTY0NjU0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQ0NzcvY2xpZW50cy80OGY5M2MwNTFkNzE2OGUyL2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9uLWdkam83eFJ2bVZ2NmNDcXNGdGR3ITQ4ZjkzYzA1MWQ3
MTY4ZTJAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjgxOC9hY21l
L3dpcmUvY2hhbGxlbmdlL2h2b1NEWm1MN2Qxd0lIZWZxdGF5QWQ2WWhQWUozSnpO
L0pNeXB0MTlJRHlIV3dlUFhPMnFEU0pRaFZobzZZMWJCIiwianRpIjoiNGQ0MzVi
OWEtNzhlYi00NzA2LTlmYjgtMDQ1NTJlNTI3ZjBlIiwibm9uY2UiOiJZVnBHY0hV
ME1UYzRhMGszZDJwcVQyUTFSMlZoZFdGek1uWnFTM2QxTjJRIiwiY2hhbCI6InJt
N1ZQVDdkdENEWFowZjZuNFFOc1JNS0piNTcwbmdzIiwiY25mIjp7ImtpZCI6Ijhf
eWFiRTlSeWMtS1V6R3JBM0VJa0Z1d1pfU3Zrd3pRUENqQ3JjcWRVb0EifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lSRXAzWmtGMFp6TlFVVUZ1ZWxoMWNXaDJUMGM1YTE5S05ISnZjMmR5VjNa
MGNubHhZa3A2UkdvNWN5SjlmUS5leUpwWVhRaU9qRTNNamt4TmpRMk5UUXNJbVY0
Y0NJNk1UY3lPVEUzTVRnMU5Dd2libUptSWpveE56STVNVFkwTmpVMExDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dmJpMW5aR3B2TjNoU2RtMVdkalpqUTNGelJuUmtkeUUw
T0dZNU0yTXdOVEZrTnpFMk9HVXlRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16STRNVGd2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM5b2RtOVRSRnB0VERka01YZEpTR1ZtY1hSaGVVRmtObGxvVUZsS00wcDZUaTlL
VFhsd2RERTVTVVI1U0ZkM1pWQllUekp4UkZOS1VXaFdhRzgyV1RGaVFpSXNJbXAw
YVNJNklqbGtNRFprWVRreExUaG1aVFV0TkRJd09DMDRZVFptTFRGbU5qY3lOalUx
T0RRNU55SXNJbTV2Ym1ObElqb2lXVlp3UjJOSVZUQk5WR00wWVRCck0yUXljSEZV
TWxFeFVqSldhR1JYUm5wTmJscHhVek5rTVU0eVVTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEwTnpjdlkyeHBaVzUw
Y3k4ME9HWTVNMk13TlRGa056RTJPR1V5TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSnliVGRXVUZRM1pIUkRSRmhhTUdZMmJqUlJUbk5TVFV0S1lqVTNNRzVu
Y3lJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hw
WTJVZ1UyMXBkR2dpZlEuR19yRXJSUXVwQkNGeHhhTXdOekFBdzkxOExYLXBULS1M
UkdIaWlpTHBZcWFFUFN4cHhCZDlhN293TlU4cWcwaEVJWGdnLUtONm95dHgyX3gw
Z01XQVEiLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vbi1nZGpvN3hSdm1WdjZjQ3Fz
RnRkdyE0OGY5M2MwNTFkNzE2OGUyQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUs
InNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Si9uQkR_yy1sXUkLLGxujLUbFAmbb
kp5-u-l_WDTJ7qq1C2E7odsDCYib68JCkZSpedqMCwlqKasTyq_xGN2BA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "B8G3cbXUBoiTAarFMBge9mkQbf1xSChMxUYitn31Kv4"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:32818/acme/wire/challenge/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN/JMypt19IDyHWwePXO2qDSJQhVho6Y1bB",
  "chal": "rm7VPT7dtCDXZ0f6n4QNsRMKJb570ngs",
  "client_id": "wireapp://n-gdjo7xRvmVv6cCqsFtdw!48f93c051d7168e2@wire.com",
  "cnf": {
    "kid": "8_yabE9Ryc-KUzGrA3EIkFuwZ_SvkwzQPCjCrcqdUoA"
  },
  "exp": 1729168614,
  "iat": 1729164654,
  "iss": "http://wire.com:24477/clients/48f93c051d7168e2/access-token",
  "jti": "4d435b9a-78eb-4706-9fb8-04552e527f0e",
  "nbf": 1729164654,
  "nonce": "YVpGcHU0MTc4a0k3d2pqT2Q1R2VhdWFzMnZqS3d1N2Q",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiREp3ZkF0ZzNQUUFuelh1cWh2T0c5a19KNHJvc2dyV3Z0cnlxYkp6RGo5cyJ9fQ.eyJpYXQiOjE3MjkxNjQ2NTQsImV4cCI6MTcyOTE3MTg1NCwibmJmIjoxNzI5MTY0NjU0LCJzdWIiOiJ3aXJlYXBwOi8vbi1nZGpvN3hSdm1WdjZjQ3FzRnRkdyE0OGY5M2MwNTFkNzE2OGUyQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL2NoYWxsZW5nZS9odm9TRFptTDdkMXdJSGVmcXRheUFkNlloUFlKM0p6Ti9KTXlwdDE5SUR5SFd3ZVBYTzJxRFNKUWhWaG82WTFiQiIsImp0aSI6IjlkMDZkYTkxLThmZTUtNDIwOC04YTZmLTFmNjcyNjU1ODQ5NyIsIm5vbmNlIjoiWVZwR2NIVTBNVGM0YTBrM2QycHFUMlExUjJWaGRXRnpNblpxUzNkMU4yUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ0NzcvY2xpZW50cy80OGY5M2MwNTFkNzE2OGUyL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJybTdWUFQ3ZHRDRFhaMGY2bjRRTnNSTUtKYjU3MG5ncyIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUiLCJuYW1lIjoiQWxpY2UgU21pdGgifQ.G_rErRQupBCFxxaMwNzAAw918LX-pT--LRGHiiiLpYqaEPSxpxBd9a7owNU8qg0hEIXgg-KN6oytx2_x0gMWAQ",
  "scope": "wire_client_id",
  "sub": "wireapp://n-gdjo7xRvmVv6cCqsFtdw!48f93c051d7168e2@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAB8G3cbXUBoiTAarFMBge9mkQbf1xSChMxUYitn31Kv4=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 17. validate Dpop challenge (clientId)
```http request
POST https://stepca:32818/acme/wire/challenge/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN/JMypt19IDyHWwePXO2qDSJQhVho6Y1bB
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE4L2FjbWUvd2lyZS9hY2NvdW50L2JOVWdrVkR6am41dWpFdTVuVm9CTWxEWTNCN204bGxpIiwidHlwIjoiSldUIiwibm9uY2UiOiJiekpwTVRjM1duUkViakpuVDFOcWFrcHNXVE16VDJseU0wVlpURVpzV0dNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL2NoYWxsZW5nZS9odm9TRFptTDdkMXdJSGVmcXRheUFkNlloUFlKM0p6Ti9KTXlwdDE5SUR5SFd3ZVBYTzJxRFNKUWhWaG82WTFiQiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrSTRSek5qWWxoVlFtOXBWRUZoY2taTlFtZGxPVzFyVVdKbU1YaFRRMmhOZUZWWmFYUnVNekZMZGpRaWZYMC5leUpwWVhRaU9qRTNNamt4TmpRMk5UUXNJbVY0Y0NJNk1UY3lPVEUyT0RZeE5Dd2libUptSWpveE56STVNVFkwTmpVMExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRME56Y3ZZMnhwWlc1MGN5ODBPR1k1TTJNd05URmtOekUyT0dVeUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTl1TFdka2FtODNlRkoyYlZaMk5tTkRjWE5HZEdSM0lUUTRaamt6WXpBMU1XUTNNVFk0WlRKQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TWpneE9DOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMMmgyYjFORVdtMU1OMlF4ZDBsSVpXWnhkR0Y1UVdRMldXaFFXVW96U25wT0wwcE5lWEIwTVRsSlJIbElWM2RsVUZoUE1uRkVVMHBSYUZab2J6WlpNV0pDSWl3aWFuUnBJam9pTkdRME16VmlPV0V0TnpobFlpMDBOekEyTFRsbVlqZ3RNRFExTlRKbE5USTNaakJsSWl3aWJtOXVZMlVpT2lKWlZuQkhZMGhWTUUxVVl6UmhNR3N6WkRKd2NWUXlVVEZTTWxab1pGZEdlazF1V25GVE0yUXhUakpSSWl3aVkyaGhiQ0k2SW5KdE4xWlFWRGRrZEVORVdGb3daalp1TkZGT2MxSk5TMHBpTlRjd2JtZHpJaXdpWTI1bUlqcDdJbXRwWkNJNklqaGZlV0ZpUlRsU2VXTXRTMVY2UjNKQk0wVkphMFoxZDFwZlUzWnJkM3BSVUVOcVEzSmpjV1JWYjBFaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsU1JYQXpXbXRHTUZwNlRsRlZWVVoxWld4b01XTlhhREpVTUdNMVlURTVTMDVJU25aak1tUjVWak5hTUdOdWJIaFphM0EyVWtkdk5XTjVTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5hbXQ0VG1wUk1rNVVVWE5KYlZZMFkwTkpOazFVWTNsUFZFVXpUVlJuTVU1RGQybGliVXB0U1dwdmVFNTZTVFZOVkZrd1RtcFZNRXhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRtSnBNVzVhUjNCMlRqTm9VMlJ0TVZka2FscHFVVE5HZWxKdVVtdGtlVVV3VDBkWk5VMHlUWGRPVkVaclRucEZNazlIVlhsUlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlNUUk5WR2QyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE01YjJSdE9WUlNSbkIwVkVSa2EwMVlaRXBUUjFadFkxaFNhR1ZWUm10T2JHeHZWVVpzUzAwd2NEWlVhVGxMVkZoc2QyUkVSVFZUVlZJMVUwWmtNMXBXUWxsVWVrcDRVa1pPUzFWWGFGZGhSemd5VjFSR2FWRnBTWE5KYlhBd1lWTkpOa2xxYkd0TlJGcHJXVlJyZUV4VWFHMWFWRlYwVGtSSmQwOURNRFJaVkZwdFRGUkdiVTVxWTNsT2FsVXhUMFJSTlU1NVNYTkpiVFYyWW0xT2JFbHFiMmxYVmxwM1VqSk9TVlpVUWs1V1IwMHdXVlJDY2sweVVYbGpTRVpWVFd4RmVGVnFTbGRoUjFKWVVtNXdUbUpzY0hoVmVrNXJUVlUwZVZWVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxFd1RucGpkbGt5ZUhCYVZ6VXdZM2s0TUU5SFdUVk5NazEzVGxSR2EwNTZSVEpQUjFWNVRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTbmxpVkdSWFZVWlJNMXBJVWtSU1JtaGhUVWRaTW1KcVVsSlViazVUVkZWMFMxbHFWVE5OUnpWdVkzbEpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsTVEwcDFXVmN4YkVscWIybFJWM2h3V1RKVloxVXlNWEJrUjJkcFpsRXVSMTl5UlhKU1VYVndRa05HZUhoaFRYZE9la0ZCZHpreE9FeFlMWEJVTFMxTVVrZElhV2xwVEhCWmNXRkZVRk40Y0hoQ1pEbGhOMjkzVGxVNGNXY3dhRVZKV0dkbkxVdE9ObTk1ZEhneVgzZ3daMDFYUVZFaUxDSmpiR2xsYm5SZmFXUWlPaUozYVhKbFlYQndPaTh2YmkxblpHcHZOM2hTZG0xV2RqWmpRM0Z6Um5Sa2R5RTBPR1k1TTJNd05URmtOekUyT0dVeVFIZHBjbVV1WTI5dElpd2lZWEJwWDNabGNuTnBiMjRpT2pVc0luTmpiM0JsSWpvaWQybHlaVjlqYkdsbGJuUmZhV1FpZlEuU2k5dVFrUl95eTFzWFVrTExHeHVqTFViRkFtYmJrcDUtdS1sX1dEVEo3cXExQzJFN29kc0RDWWliNjhKQ2taU3BlZHFNQ3dscUthc1R5cV94R04yQkEifQ",
  "signature": "7TLIFGs_-Z4UUkgzrhGkAa6l60sicg0HeEInY5Fb4HKaakQCroJEOVnFryIcYr9qVCB4N9DXDLBJ0i-C2ql4Bw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkI4RzNjYlhVQm9pVEFhckZNQmdlOW1rUWJmMXhTQ2hNeFVZaXRuMzFLdjQifX0.eyJpYXQiOjE3MjkxNjQ2NTQsImV4cCI6MTcyOTE2ODYxNCwibmJmIjoxNzI5MTY0NjU0LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ0NzcvY2xpZW50cy80OGY5M2MwNTFkNzE2OGUyL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9uLWdkam83eFJ2bVZ2NmNDcXNGdGR3ITQ4ZjkzYzA1MWQ3MTY4ZTJAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMjgxOC9hY21lL3dpcmUvY2hhbGxlbmdlL2h2b1NEWm1MN2Qxd0lIZWZxdGF5QWQ2WWhQWUozSnpOL0pNeXB0MTlJRHlIV3dlUFhPMnFEU0pRaFZobzZZMWJCIiwianRpIjoiNGQ0MzViOWEtNzhlYi00NzA2LTlmYjgtMDQ1NTJlNTI3ZjBlIiwibm9uY2UiOiJZVnBHY0hVME1UYzRhMGszZDJwcVQyUTFSMlZoZFdGek1uWnFTM2QxTjJRIiwiY2hhbCI6InJtN1ZQVDdkdENEWFowZjZuNFFOc1JNS0piNTcwbmdzIiwiY25mIjp7ImtpZCI6IjhfeWFiRTlSeWMtS1V6R3JBM0VJa0Z1d1pfU3Zrd3pRUENqQ3JjcWRVb0EifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lSRXAzWmtGMFp6TlFVVUZ1ZWxoMWNXaDJUMGM1YTE5S05ISnZjMmR5VjNaMGNubHhZa3A2UkdvNWN5SjlmUS5leUpwWVhRaU9qRTNNamt4TmpRMk5UUXNJbVY0Y0NJNk1UY3lPVEUzTVRnMU5Dd2libUptSWpveE56STVNVFkwTmpVMExDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dmJpMW5aR3B2TjNoU2RtMVdkalpqUTNGelJuUmtkeUUwT0dZNU0yTXdOVEZrTnpFMk9HVXlRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16STRNVGd2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM5b2RtOVRSRnB0VERka01YZEpTR1ZtY1hSaGVVRmtObGxvVUZsS00wcDZUaTlLVFhsd2RERTVTVVI1U0ZkM1pWQllUekp4UkZOS1VXaFdhRzgyV1RGaVFpSXNJbXAwYVNJNklqbGtNRFprWVRreExUaG1aVFV0TkRJd09DMDRZVFptTFRGbU5qY3lOalUxT0RRNU55SXNJbTV2Ym1ObElqb2lXVlp3UjJOSVZUQk5WR00wWVRCck0yUXljSEZVTWxFeFVqSldhR1JYUm5wTmJscHhVek5rTVU0eVVTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEwTnpjdlkyeHBaVzUwY3k4ME9HWTVNMk13TlRGa056RTJPR1V5TDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnliVGRXVUZRM1pIUkRSRmhhTUdZMmJqUlJUbk5TVFV0S1lqVTNNRzVuY3lJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlMQ0p1WVcxbElqb2lRV3hwWTJVZ1UyMXBkR2dpZlEuR19yRXJSUXVwQkNGeHhhTXdOekFBdzkxOExYLXBULS1MUkdIaWlpTHBZcWFFUFN4cHhCZDlhN293TlU4cWcwaEVJWGdnLUtONm95dHgyX3gwZ01XQVEiLCJjbGllbnRfaWQiOiJ3aXJlYXBwOi8vbi1nZGpvN3hSdm1WdjZjQ3FzRnRkdyE0OGY5M2MwNTFkNzE2OGUyQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Si9uQkR_yy1sXUkLLGxujLUbFAmbbkp5-u-l_WDTJ7qq1C2E7odsDCYib68JCkZSpedqMCwlqKasTyq_xGN2BA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli",
    "nonce": "bzJpMTc3WnREbjJnT1NqakpsWTMzT2lyM0VZTEZsWGM",
    "typ": "JWT",
    "url": "https://stepca:32818/acme/wire/challenge/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN/JMypt19IDyHWwePXO2qDSJQhVho6Y1bB"
  }
}
```
#### 18. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32818/acme/wire/directory>;rel="index"
link: <https://stepca:32818/acme/wire/authz/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN>;rel="up"
location: https://stepca:32818/acme/wire/challenge/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN/JMypt19IDyHWwePXO2qDSJQhVho6Y1bB
replay-nonce: S2lES1o1WVZDdWRLQzlEclZiWnFad1phb2pMUDU0TzU
x-request-id: abbbeb96-dc99-4464-8359-b1daf95c9242
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32818/acme/wire/challenge/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN/JMypt19IDyHWwePXO2qDSJQhVho6Y1bB",
  "status": "valid",
  "token": "rm7VPT7dtCDXZ0f6n4QNsRMKJb570ngs",
  "target": "http://wire.com:24477/clients/48f93c051d7168e2/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 19. OAUTH authorization request

```text
code_verifier=YgQ0cNseH4RXj26vJaWFoYKtAGFtbRboLofR4Atorbs&code_challenge=_p46qg1u3dg2srOcSzV4azUD-xBLhd8V3V7-uNuOLWM
```
#### 20. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:22847/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=7dV8sAnFJHcZXzfK57L5vQ&code_challenge=_p46qg1u3dg2srOcSzV4azUD-xBLhd8V3V7-uNuOLWM&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A24477%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A32818%2Facme%2Fwire%2Fchallenge%2Fzrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK%2FeP1ZVUleDboZb4Qhn5YEzRC8CYoSAafA%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22YmOV7D5oTMLeKIevL0hqsOmE5zEAkF8l.8_yabE9Ryc-KUzGrA3EIkFuwZ_SvkwzQPCjCrcqdUoA%22%7D%7D%7D&nonce=38dR_V5PxXQXVQK6C-Btdg
```

#### 21. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:22847/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=6d1b9780-511a-4b9f-bb5f-dbcdc3730220.23b088ad-26e6-42e4-8c79-1e9daea725e8.e8190646-9461-4f22-b1bb-af1e1de6045b&code_verifier=YgQ0cNseH4RXj26vJaWFoYKtAGFtbRboLofR4Atorbs&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A24477%2Fcallback
```
#### 22. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTSlB1T1J2Y0dVQnR5ZkFWdUFycFJZMWpuSjdPV05qcVg0RG10OWo0YVJJIn0.eyJleHAiOjE3MjkxNjgzMTUsImlhdCI6MTcyOTE2ODI1NSwiYXV0aF90aW1lIjoxNzI5MTY4MjU1LCJqdGkiOiI4NGVlMDlkZi00NzMzLTQ4ZTQtYWIxYy0xYzE4MGY4Y2JkN2IiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIyZmRmZGZlNy1lMjA2LTQxZDQtYTcxZS00YWE5NGJiZDhiZjAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiMjNiMDg4YWQtMjZlNi00MmU0LThjNzktMWU5ZGFlYTcyNWU4IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vd2lyZS5jb206MjQ0NzciXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWFzdGVyIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.auXXQGwOuq69RMfnWjQfaDS_Y_vDSq0XmtYd5yEacFIogkkIFN25Em_eU32TsDDF3OEMxIRkYubGZyxLHSvKprtiH3MV70PhKwTLrX2JeRI1gRIMTl01wiKZSDmt85-aBnjUl_gi4EISa7GORSWCPOYl9dBwc4WEaOqOHLvkDoB4kcN_ip_9-asayLsKibHv-UmtngeHLODo7C4hRGGALc_tb3p04GbLlhkbXl-yziGHmnXN7Goa9bFkhghBAedH6LDM4gYW4LIW54_KV1I-F34EwtycYLvvz-1SoBweFkK_3oijGS9HAWGGD3_hf-4Bj5fI0dN_92e3YkUHTcDKNQ",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTSlB1T1J2Y0dVQnR5ZkFWdUFycFJZMWpuSjdPV05qcVg0RG10OWo0YVJJIn0.eyJleHAiOjE3MjkxNjgzMTUsImlhdCI6MTcyOTE2ODI1NSwiYXV0aF90aW1lIjoxNzI5MTY4MjU1LCJqdGkiOiJhODA4N2YzNS01OThiLTRjMjYtOThiMy1hMzUwZGY5ZWNhZTYiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyZmRmZGZlNy1lMjA2LTQxZDQtYTcxZS00YWE5NGJiZDhiZjAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IjM4ZFJfVjVQeFhRWFZRSzZDLUJ0ZGciLCJzaWQiOiIyM2IwODhhZC0yNmU2LTQyZTQtOGM3OS0xZTlkYWVhNzI1ZTgiLCJhdF9oYXNoIjoiXzZoZlhBVzhobXc4eHg4emRvcU5YQSIsImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImdpdmVuX25hbWUiOiJBbGljZSIsImtleWF1dGgiOiJZbU9WN0Q1b1RNTGVLSWV2TDBocXNPbUU1ekVBa0Y4bC44X3lhYkU5UnljLUtVekdyQTNFSWtGdXdaX1N2a3d6UVBDakNyY3FkVW9BIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjgxOC9hY21lL3dpcmUvY2hhbGxlbmdlL3pyYjJjQ0haQzBUNmF5dFZJOHpiNURDZzB5VjhUalhLL2VQMVpWVWxlRGJvWmI0UWhuNVlFelJDOENZb1NBYWZBIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.cmIW_Hb-F8zHwThnDGAcmSj29chDDPK6zvGQQK_79hBSnrPDF3WvjCQmurxzdMJUtnE1l6TRFg2c0gy5js71rOiSAzUECFdA72P01nYigLPkH1N6FXBSwjdE7XXa15Wm8eTXH98InnGPXkT1xAijpteCb44sXmRnGGjT66kiNpdlKf-cM21CtvwczjxQ1gM1YK8Csj-Jp5QRzTV_XlTtXwXAkeSaFICe-1tB0p-Db5Cp7JLrHAaSZ53TAhw5bFBTVIR1ZaSzp-k0ItZTUcOeneGXSxwZU9jE59_EJ--0X1slAU0bIhb9305edz83_O8d7Ppnr-D9hpCmPctNYzIoXw",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4NWI2N2M2YS1mZmQ1LTQxYzYtYWZiYS05MTUyNDNjNWYzOTkifQ.eyJleHAiOjE3MjkxNzAwNTUsImlhdCI6MTcyOTE2ODI1NSwianRpIjoiYjYxYTYxM2ItOGIzNC00ODZlLTljY2UtMTkzNmRlZDBiMmU3IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjIyODQ3L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc3RlciIsInN1YiI6IjJmZGZkZmU3LWUyMDYtNDFkNC1hNzFlLTRhYTk0YmJkOGJmMCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiMjNiMDg4YWQtMjZlNi00MmU0LThjNzktMWU5ZGFlYTcyNWU4Iiwic2NvcGUiOiJvcGVuaWQgd2ViLW9yaWdpbnMgcm9sZXMgZW1haWwgYWNyIGJhc2ljIHByb2ZpbGUifQ.KgAkYwiHmuCysjyNkMDVJ_uRnv6J0upmL9eBVLw6YpOwunvvLhAAGW0JInxr-23xpphMMsf1ntQ96qjBRkIJhA",
  "scope": "openid email profile",
  "session_state": "23b088ad-26e6-42e4-8c79-1e9daea725e8",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTSlB1T1J2Y0dVQnR5ZkFWdUFycFJZMWpuSjdPV05qcVg0RG10OWo0YVJJIn0.eyJleHAiOjE3MjkxNjgzMTUsImlhdCI6MTcyOTE2ODI1NSwiYXV0aF90aW1lIjoxNzI5MTY4MjU1LCJqdGkiOiI4NGVlMDlkZi00NzMzLTQ4ZTQtYWIxYy0xYzE4MGY4Y2JkN2IiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiIyZmRmZGZlNy1lMjA2LTQxZDQtYTcxZS00YWE5NGJiZDhiZjAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiMjNiMDg4YWQtMjZlNi00MmU0LThjNzktMWU5ZGFlYTcyNWU4IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vd2lyZS5jb206MjQ0NzciXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWFzdGVyIiwib2ZmbGluZV9hY2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJlbWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.auXXQGwOuq69RMfnWjQfaDS_Y_vDSq0XmtYd5yEacFIogkkIFN25Em_eU32TsDDF3OEMxIRkYubGZyxLHSvKprtiH3MV70PhKwTLrX2JeRI1gRIMTl01wiKZSDmt85-aBnjUl_gi4EISa7GORSWCPOYl9dBwc4WEaOqOHLvkDoB4kcN_ip_9-asayLsKibHv-UmtngeHLODo7C4hRGGALc_tb3p04GbLlhkbXl-yziGHmnXN7Goa9bFkhghBAedH6LDM4gYW4LIW54_KV1I-F34EwtycYLvvz-1SoBweFkK_3oijGS9HAWGGD3_hf-4Bj5fI0dN_92e3YkUHTcDKNQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTSlB1T1J2Y0dV
QnR5ZkFWdUFycFJZMWpuSjdPV05qcVg0RG10OWo0YVJJIn0.eyJleHAiOjE3Mjkx
NjgzMTUsImlhdCI6MTcyOTE2ODI1NSwiYXV0aF90aW1lIjoxNzI5MTY4MjU1LCJq
dGkiOiI4NGVlMDlkZi00NzMzLTQ4ZTQtYWIxYy0xYzE4MGY4Y2JkN2IiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiIyZmRmZGZlNy1lMjA2LTQxZDQtYTcxZS00YWE5NGJiZDhi
ZjAiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiMjNiMDg4
YWQtMjZlNi00MmU0LThjNzktMWU5ZGFlYTcyNWU4IiwiYWNyIjoiMSIsImFsbG93
ZWQtb3JpZ2lucyI6WyJodHRwOi8vd2lyZS5jb206MjQ0NzciXSwicmVhbG1fYWNj
ZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtbWFzdGVyIiwib2ZmbGluZV9h
Y2Nlc3MiLCJ1bWFfYXV0aG9yaXphdGlvbiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7
ImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNj
b3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoib3BlbmlkIGVt
YWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNl
IFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNv
bSIsImdpdmVuX25hbWUiOiJBbGljZSIsImZhbWlseV9uYW1lIjoiU21pdGgiLCJl
bWFpbCI6ImFsaWNlc21pdGhAd2lyZS5jb20ifQ.auXXQGwOuq69RMfnWjQfaDS_Y
_vDSq0XmtYd5yEacFIogkkIFN25Em_eU32TsDDF3OEMxIRkYubGZyxLHSvKprtiH
3MV70PhKwTLrX2JeRI1gRIMTl01wiKZSDmt85-aBnjUl_gi4EISa7GORSWCPOYl9
dBwc4WEaOqOHLvkDoB4kcN_ip_9-asayLsKibHv-UmtngeHLODo7C4hRGGALc_tb
3p04GbLlhkbXl-yziGHmnXN7Goa9bFkhghBAedH6LDM4gYW4LIW54_KV1I-F34Ew
tycYLvvz-1SoBweFkK_3oijGS9HAWGGD3_hf-4Bj5fI0dN_92e3YkUHTcDKNQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "SJPuORvcGUBtyfAVuArpRY1jnJ7OWNjqX4Dmt9j4aRI",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:24477"
  ],
  "aud": "account",
  "auth_time": 1729168255,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1729168315,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1729168255,
  "iss": "http://keycloak:22847/realms/master",
  "jti": "84ee09df-4733-48e4-ab1c-1c180f8cbd7b",
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
  "sid": "23b088ad-26e6-42e4-8c79-1e9daea725e8",
  "sub": "2fdfdfe7-e206-41d4-a71e-4aa94bbd8bf0",
  "typ": "Bearer"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqEMRTQeMdKe0sBOjsnQk
F+F7lz6t8cHU7u2VZfeedB4vM9XutEY6Lr6aCzIDvtrMSdixLiWx9EkZOW+R6OYk
49X73DGx+xO396R0GL3f0Q6jQ8LrKbuPplcIfqwQ4QlH/fsxb1lViaSlJAxk1LZJ
HbrSYnq7ROCHzQMqvGlc76naD3s3LTp2jZ4JoOoCrGjaPm2zJGjZFttP5gPoOFUY
mIkW5SGT0FChzOlErXnEUZ1zSOMrR7Ui3mujjxrJD1zXHokdvmcptGRUtwKXJBoZ
dJM49LgYK4310gNELWMnS4smvheWWwhF/iwV/55Mv6SD3k431JK72mDb1U9ESHx1
oQIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4NWI2N2M2YS1mZmQ1LTQxYzYtYWZiYS05MTUyNDNjNWYzOTkifQ.eyJleHAiOjE3MjkxNzAwNTUsImlhdCI6MTcyOTE2ODI1NSwianRpIjoiYjYxYTYxM2ItOGIzNC00ODZlLTljY2UtMTkzNmRlZDBiMmU3IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjIyODQ3L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc3RlciIsInN1YiI6IjJmZGZkZmU3LWUyMDYtNDFkNC1hNzFlLTRhYTk0YmJkOGJmMCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiMjNiMDg4YWQtMjZlNi00MmU0LThjNzktMWU5ZGFlYTcyNWU4Iiwic2NvcGUiOiJvcGVuaWQgd2ViLW9yaWdpbnMgcm9sZXMgZW1haWwgYWNyIGJhc2ljIHByb2ZpbGUifQ.KgAkYwiHmuCysjyNkMDVJ_uRnv6J0upmL9eBVLw6YpOwunvvLhAAGW0JInxr-23xpphMMsf1ntQ96qjBRkIJhA)

Raw:
```text
eyJhbGciOiJIUzUxMiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI4NWI2N2M2YS1m
ZmQ1LTQxYzYtYWZiYS05MTUyNDNjNWYzOTkifQ.eyJleHAiOjE3MjkxNzAwNTUsI
mlhdCI6MTcyOTE2ODI1NSwianRpIjoiYjYxYTYxM2ItOGIzNC00ODZlLTljY2UtM
TkzNmRlZDBiMmU3IiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjIyODQ3L3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc
3RlciIsInN1YiI6IjJmZGZkZmU3LWUyMDYtNDFkNC1hNzFlLTRhYTk0YmJkOGJmM
CIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwic2lkIjoiMjNiMDg4Y
WQtMjZlNi00MmU0LThjNzktMWU5ZGFlYTcyNWU4Iiwic2NvcGUiOiJvcGVuaWQgd
2ViLW9yaWdpbnMgcm9sZXMgZW1haWwgYWNyIGJhc2ljIHByb2ZpbGUifQ.KgAkYw
iHmuCysjyNkMDVJ_uRnv6J0upmL9eBVLw6YpOwunvvLhAAGW0JInxr-23xpphMMs
f1ntQ96qjBRkIJhA
```

Decoded:

```json
{
  "alg": "HS512",
  "kid": "85b67c6a-ffd5-41c6-afba-915243c5f399",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:22847/realms/master",
  "azp": "wireapp",
  "exp": 1729170055,
  "iat": 1729168255,
  "iss": "http://keycloak:22847/realms/master",
  "jti": "b61a613b-8b34-486e-9cce-1936ded0b2e7",
  "scope": "openid web-origins roles email acr basic profile",
  "sid": "23b088ad-26e6-42e4-8c79-1e9daea725e8",
  "sub": "2fdfdfe7-e206-41d4-a71e-4aa94bbd8bf0",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqEMRTQeMdKe0sBOjsnQk
F+F7lz6t8cHU7u2VZfeedB4vM9XutEY6Lr6aCzIDvtrMSdixLiWx9EkZOW+R6OYk
49X73DGx+xO396R0GL3f0Q6jQ8LrKbuPplcIfqwQ4QlH/fsxb1lViaSlJAxk1LZJ
HbrSYnq7ROCHzQMqvGlc76naD3s3LTp2jZ4JoOoCrGjaPm2zJGjZFttP5gPoOFUY
mIkW5SGT0FChzOlErXnEUZ1zSOMrR7Ui3mujjxrJD1zXHokdvmcptGRUtwKXJBoZ
dJM49LgYK4310gNELWMnS4smvheWWwhF/iwV/55Mv6SD3k431JK72mDb1U9ESHx1
oQIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 23. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTSlB1T1J2Y0dVQnR5ZkFWdUFycFJZMWpuSjdPV05qcVg0RG10OWo0YVJJIn0.eyJleHAiOjE3MjkxNjgzMTUsImlhdCI6MTcyOTE2ODI1NSwiYXV0aF90aW1lIjoxNzI5MTY4MjU1LCJqdGkiOiJhODA4N2YzNS01OThiLTRjMjYtOThiMy1hMzUwZGY5ZWNhZTYiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyZmRmZGZlNy1lMjA2LTQxZDQtYTcxZS00YWE5NGJiZDhiZjAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IjM4ZFJfVjVQeFhRWFZRSzZDLUJ0ZGciLCJzaWQiOiIyM2IwODhhZC0yNmU2LTQyZTQtOGM3OS0xZTlkYWVhNzI1ZTgiLCJhdF9oYXNoIjoiXzZoZlhBVzhobXc4eHg4emRvcU5YQSIsImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImdpdmVuX25hbWUiOiJBbGljZSIsImtleWF1dGgiOiJZbU9WN0Q1b1RNTGVLSWV2TDBocXNPbUU1ekVBa0Y4bC44X3lhYkU5UnljLUtVekdyQTNFSWtGdXdaX1N2a3d6UVBDakNyY3FkVW9BIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjgxOC9hY21lL3dpcmUvY2hhbGxlbmdlL3pyYjJjQ0haQzBUNmF5dFZJOHpiNURDZzB5VjhUalhLL2VQMVpWVWxlRGJvWmI0UWhuNVlFelJDOENZb1NBYWZBIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.cmIW_Hb-F8zHwThnDGAcmSj29chDDPK6zvGQQK_79hBSnrPDF3WvjCQmurxzdMJUtnE1l6TRFg2c0gy5js71rOiSAzUECFdA72P01nYigLPkH1N6FXBSwjdE7XXa15Wm8eTXH98InnGPXkT1xAijpteCb44sXmRnGGjT66kiNpdlKf-cM21CtvwczjxQ1gM1YK8Csj-Jp5QRzTV_XlTtXwXAkeSaFICe-1tB0p-Db5Cp7JLrHAaSZ53TAhw5bFBTVIR1ZaSzp-k0ItZTUcOeneGXSxwZU9jE59_EJ--0X1slAU0bIhb9305edz83_O8d7Ppnr-D9hpCmPctNYzIoXw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTSlB1T1J2Y0dV
QnR5ZkFWdUFycFJZMWpuSjdPV05qcVg0RG10OWo0YVJJIn0.eyJleHAiOjE3Mjkx
NjgzMTUsImlhdCI6MTcyOTE2ODI1NSwiYXV0aF90aW1lIjoxNzI5MTY4MjU1LCJq
dGkiOiJhODA4N2YzNS01OThiLTRjMjYtOThiMy1hMzUwZGY5ZWNhZTYiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiIyZmRmZGZlNy1lMjA2LTQxZDQtYTcxZS00YWE5NGJiZDhi
ZjAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IjM4ZFJfVjVQ
eFhRWFZRSzZDLUJ0ZGciLCJzaWQiOiIyM2IwODhhZC0yNmU2LTQyZTQtOGM3OS0x
ZTlkYWVhNzI1ZTgiLCJhdF9oYXNoIjoiXzZoZlhBVzhobXc4eHg4emRvcU5YQSIs
ImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNt
aXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIs
ImdpdmVuX25hbWUiOiJBbGljZSIsImtleWF1dGgiOiJZbU9WN0Q1b1RNTGVLSWV2
TDBocXNPbUU1ekVBa0Y4bC44X3lhYkU5UnljLUtVekdyQTNFSWtGdXdaX1N2a3d6
UVBDakNyY3FkVW9BIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjgxOC9h
Y21lL3dpcmUvY2hhbGxlbmdlL3pyYjJjQ0haQzBUNmF5dFZJOHpiNURDZzB5VjhU
alhLL2VQMVpWVWxlRGJvWmI0UWhuNVlFelJDOENZb1NBYWZBIiwiZmFtaWx5X25h
bWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.cmIW_Hb
-F8zHwThnDGAcmSj29chDDPK6zvGQQK_79hBSnrPDF3WvjCQmurxzdMJUtnE1l6T
RFg2c0gy5js71rOiSAzUECFdA72P01nYigLPkH1N6FXBSwjdE7XXa15Wm8eTXH98
InnGPXkT1xAijpteCb44sXmRnGGjT66kiNpdlKf-cM21CtvwczjxQ1gM1YK8Csj-
Jp5QRzTV_XlTtXwXAkeSaFICe-1tB0p-Db5Cp7JLrHAaSZ53TAhw5bFBTVIR1ZaS
zp-k0ItZTUcOeneGXSxwZU9jE59_EJ--0X1slAU0bIhb9305edz83_O8d7Ppnr-D
9hpCmPctNYzIoXw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "SJPuORvcGUBtyfAVuArpRY1jnJ7OWNjqX4Dmt9j4aRI",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:32818/acme/wire/challenge/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK/eP1ZVUleDboZb4Qhn5YEzRC8CYoSAafA",
  "acr": "1",
  "at_hash": "_6hfXAW8hmw8xx8zdoqNXA",
  "aud": "wireapp",
  "auth_time": 1729168255,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1729168315,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1729168255,
  "iss": "http://keycloak:22847/realms/master",
  "jti": "a8087f35-598b-4c26-98b3-a350df9ecae6",
  "keyauth": "YmOV7D5oTMLeKIevL0hqsOmE5zEAkF8l.8_yabE9Ryc-KUzGrA3EIkFuwZ_SvkwzQPCjCrcqdUoA",
  "name": "Alice Smith",
  "nonce": "38dR_V5PxXQXVQK6C-Btdg",
  "preferred_username": "alice_wire@wire.com",
  "sid": "23b088ad-26e6-42e4-8c79-1e9daea725e8",
  "sub": "2fdfdfe7-e206-41d4-a71e-4aa94bbd8bf0",
  "typ": "ID"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqEMRTQeMdKe0sBOjsnQk
F+F7lz6t8cHU7u2VZfeedB4vM9XutEY6Lr6aCzIDvtrMSdixLiWx9EkZOW+R6OYk
49X73DGx+xO396R0GL3f0Q6jQ8LrKbuPplcIfqwQ4QlH/fsxb1lViaSlJAxk1LZJ
HbrSYnq7ROCHzQMqvGlc76naD3s3LTp2jZ4JoOoCrGjaPm2zJGjZFttP5gPoOFUY
mIkW5SGT0FChzOlErXnEUZ1zSOMrR7Ui3mujjxrJD1zXHokdvmcptGRUtwKXJBoZ
dJM49LgYK4310gNELWMnS4smvheWWwhF/iwV/55Mv6SD3k431JK72mDb1U9ESHx1
oQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32818/acme/wire/challenge/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK/eP1ZVUleDboZb4Qhn5YEzRC8CYoSAafA
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE4L2FjbWUvd2lyZS9hY2NvdW50L2JOVWdrVkR6am41dWpFdTVuVm9CTWxEWTNCN204bGxpIiwidHlwIjoiSldUIiwibm9uY2UiOiJTMmxFUzFvMVdWWkRkV1JMUXpsRWNsWmlXbkZhZDFwaGIycE1VRFUwVHpVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL2NoYWxsZW5nZS96cmIyY0NIWkMwVDZheXRWSTh6YjVEQ2cweVY4VGpYSy9lUDFaVlVsZURib1piNFFobjVZRXpSQzhDWW9TQWFmQSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSlRTbEIxVDFKMlkwZFZRblI1WmtGV2RVRnljRkpaTVdwdVNqZFBWMDVxY1ZnMFJHMTBPV28wWVZKSkluMC5leUpsZUhBaU9qRTNNamt4Tmpnek1UVXNJbWxoZENJNk1UY3lPVEUyT0RJMU5Td2lZWFYwYUY5MGFXMWxJam94TnpJNU1UWTRNalUxTENKcWRHa2lPaUpoT0RBNE4yWXpOUzAxT1RoaUxUUmpNall0T1RoaU15MWhNelV3WkdZNVpXTmhaVFlpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNakk0TkRjdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSXlabVJtWkdabE55MWxNakEyTFRReFpEUXRZVGN4WlMwMFlXRTVOR0ppWkRoaVpqQWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJak00WkZKZlZqVlFlRmhSV0ZaUlN6WkRMVUowWkdjaUxDSnphV1FpT2lJeU0ySXdPRGhoWkMweU5tVTJMVFF5WlRRdE9HTTNPUzB4WlRsa1lXVmhOekkxWlRnaUxDSmhkRjlvWVhOb0lqb2lYelpvWmxoQlZ6aG9iWGM0ZUhnNGVtUnZjVTVZUVNJc0ltRmpjaUk2SWpFaUxDSmxiV0ZwYkY5MlpYSnBabWxsWkNJNmRISjFaU3dpYm1GdFpTSTZJa0ZzYVdObElGTnRhWFJvSWl3aWNISmxabVZ5Y21Wa1gzVnpaWEp1WVcxbElqb2lZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW1kcGRtVnVYMjVoYldVaU9pSkJiR2xqWlNJc0ltdGxlV0YxZEdnaU9pSlpiVTlXTjBRMWIxUk5UR1ZMU1dWMlREQm9jWE5QYlVVMWVrVkJhMFk0YkM0NFgzbGhZa1U1VW5sakxVdFZla2R5UVRORlNXdEdkWGRhWDFOMmEzZDZVVkJEYWtOeVkzRmtWVzlCSWl3aVlXTnRaVjloZFdRaU9pSm9kSFJ3Y3pvdkwzTjBaWEJqWVRvek1qZ3hPQzloWTIxbEwzZHBjbVV2WTJoaGJHeGxibWRsTDNweVlqSmpRMGhhUXpCVU5tRjVkRlpKT0hwaU5VUkRaekI1VmpoVWFsaExMMlZRTVZwV1ZXeGxSR0p2V21JMFVXaHVOVmxGZWxKRE9FTlpiMU5CWVdaQklpd2labUZ0YVd4NVgyNWhiV1VpT2lKVGJXbDBhQ0lzSW1WdFlXbHNJam9pWVd4cFkyVnpiV2wwYUVCM2FYSmxMbU52YlNKOS5jbUlXX0hiLUY4ekh3VGhuREdBY21TajI5Y2hERFBLNnp2R1FRS183OWhCU25yUERGM1d2akNRbXVyeHpkTUpVdG5FMWw2VFJGZzJjMGd5NWpzNzFyT2lTQXpVRUNGZEE3MlAwMW5ZaWdMUGtIMU42RlhCU3dqZEU3WFhhMTVXbThlVFhIOThJbm5HUFhrVDF4QWlqcHRlQ2I0NHNYbVJuR0dqVDY2a2lOcGRsS2YtY00yMUN0dndjemp4UTFnTTFZSzhDc2otSnA1UVJ6VFZfWGxUdFh3WEFrZVNhRklDZS0xdEIwcC1EYjVDcDdKTHJIQWFTWjUzVEFodzViRkJUVklSMVphU3pwLWswSXRaVFVjT2VuZUdYU3h3WlU5akU1OV9FSi0tMFgxc2xBVTBiSWhiOTMwNWVkejgzX084ZDdQcG5yLUQ5aHBDbVBjdE5ZeklvWHcifQ",
  "signature": "rjG5IWyOzzAeTNvxEhPTMMNKz6wIHugaBufXCxSv0W7d534bPSeMGstc7Xy68dad4IvymcjPibnklqhJ9FXMBA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJTSlB1T1J2Y0dVQnR5ZkFWdUFycFJZMWpuSjdPV05qcVg0RG10OWo0YVJJIn0.eyJleHAiOjE3MjkxNjgzMTUsImlhdCI6MTcyOTE2ODI1NSwiYXV0aF90aW1lIjoxNzI5MTY4MjU1LCJqdGkiOiJhODA4N2YzNS01OThiLTRjMjYtOThiMy1hMzUwZGY5ZWNhZTYiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjI4NDcvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiIyZmRmZGZlNy1lMjA2LTQxZDQtYTcxZS00YWE5NGJiZDhiZjAiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6IjM4ZFJfVjVQeFhRWFZRSzZDLUJ0ZGciLCJzaWQiOiIyM2IwODhhZC0yNmU2LTQyZTQtOGM3OS0xZTlkYWVhNzI1ZTgiLCJhdF9oYXNoIjoiXzZoZlhBVzhobXc4eHg4emRvcU5YQSIsImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IkFsaWNlIFNtaXRoIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWxpY2Vfd2lyZUB3aXJlLmNvbSIsImdpdmVuX25hbWUiOiJBbGljZSIsImtleWF1dGgiOiJZbU9WN0Q1b1RNTGVLSWV2TDBocXNPbUU1ekVBa0Y4bC44X3lhYkU5UnljLUtVekdyQTNFSWtGdXdaX1N2a3d6UVBDakNyY3FkVW9BIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMjgxOC9hY21lL3dpcmUvY2hhbGxlbmdlL3pyYjJjQ0haQzBUNmF5dFZJOHpiNURDZzB5VjhUalhLL2VQMVpWVWxlRGJvWmI0UWhuNVlFelJDOENZb1NBYWZBIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.cmIW_Hb-F8zHwThnDGAcmSj29chDDPK6zvGQQK_79hBSnrPDF3WvjCQmurxzdMJUtnE1l6TRFg2c0gy5js71rOiSAzUECFdA72P01nYigLPkH1N6FXBSwjdE7XXa15Wm8eTXH98InnGPXkT1xAijpteCb44sXmRnGGjT66kiNpdlKf-cM21CtvwczjxQ1gM1YK8Csj-Jp5QRzTV_XlTtXwXAkeSaFICe-1tB0p-Db5Cp7JLrHAaSZ53TAhw5bFBTVIR1ZaSzp-k0ItZTUcOeneGXSxwZU9jE59_EJ--0X1slAU0bIhb9305edz83_O8d7Ppnr-D9hpCmPctNYzIoXw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli",
    "nonce": "S2lES1o1WVZDdWRLQzlEclZiWnFad1phb2pMUDU0TzU",
    "typ": "JWT",
    "url": "https://stepca:32818/acme/wire/challenge/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK/eP1ZVUleDboZb4Qhn5YEzRC8CYoSAafA"
  }
}
```
#### 24. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32818/acme/wire/directory>;rel="index"
link: <https://stepca:32818/acme/wire/authz/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK>;rel="up"
location: https://stepca:32818/acme/wire/challenge/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK/eP1ZVUleDboZb4Qhn5YEzRC8CYoSAafA
replay-nonce: UzdkZk1MV2FpSm16NXdjUDZ0OFJtN3Rta2pGbDZaTW8
x-request-id: ff972864-08ac-4904-85da-9ae34c300250
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32818/acme/wire/challenge/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK/eP1ZVUleDboZb4Qhn5YEzRC8CYoSAafA",
  "status": "valid",
  "token": "YmOV7D5oTMLeKIevL0hqsOmE5zEAkF8l",
  "target": "http://keycloak:22847/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 25. verify the status of the order
```http request
POST https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE4L2FjbWUvd2lyZS9hY2NvdW50L2JOVWdrVkR6am41dWpFdTVuVm9CTWxEWTNCN204bGxpIiwidHlwIjoiSldUIiwibm9uY2UiOiJVemRrWmsxTVYyRnBTbTE2TlhkalVEWjBPRkp0TjNSdGEycEdiRFphVFc4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL29yZGVyL2tkTk51T2U4VFhGM0dITnlsWlFGcURXaHVYdFd3cTNUIn0",
  "payload": "",
  "signature": "ODQ0Mgq4nbOFJERGJiI5QF6GcLtOxVCMm39ssWzXJhXb4rxaV0VLOR37srdZ1sIYsZRYBOFLiEVKmo417nzlAQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli",
    "nonce": "UzdkZk1MV2FpSm16NXdjUDZ0OFJtN3Rta2pGbDZaTW8",
    "typ": "JWT",
    "url": "https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T"
  }
}
```
#### 26. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32818/acme/wire/directory>;rel="index"
location: https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T
replay-nonce: RXlIbXJKYkZLOHcwVE5VS3VMdGp3VWtFcVQzMWlBN2w
x-request-id: 6f1957b8-3b10-4793-a27b-bc97962e7c5a
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://n-gdjo7xRvmVv6cCqsFtdw!48f93c051d7168e2@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32818/acme/wire/authz/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN",
    "https://stepca:32818/acme/wire/authz/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK"
  ],
  "expires": "2024-10-18T12:30:54Z",
  "notBefore": "2024-10-17T12:30:54.964546475Z",
  "notAfter": "2034-10-15T12:30:54.964546475Z"
}
```
#### 27. create a CSR and call finalize url
```http request
POST https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE4L2FjbWUvd2lyZS9hY2NvdW50L2JOVWdrVkR6am41dWpFdTVuVm9CTWxEWTNCN204bGxpIiwidHlwIjoiSldUIiwibm9uY2UiOiJSWGxJYlhKS1lrWkxPSGN3VkU1VlMzVk1kR3AzVld0RmNWUXpNV2xCTjJ3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL29yZGVyL2tkTk51T2U4VFhGM0dITnlsWlFGcURXaHVYdFd3cTNUL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTU9ISjdVWnhHVHk0V2hpc3lCUXZCeDF0UHVkMEpiOHBGWElrSTJac0hhRm9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2YmkxblpHcHZOM2hTZG0xV2RqWmpRM0Z6Um5Sa2R5RTBPR1k1TTJNd05URmtOekUyT0dVeVFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFDQjZLaGJPbEExWW1vVFVpZHZrck9Pcm9BYTFtWDdZSW5ZZWxUNzNXVjB4WGE0cFRYbGJSb0Vjb2NldDZXYTZzdW1vRUZyOTUteWxQNkx4RHRjbzhNQSJ9",
  "signature": "4aXUimoQtaxsIsLEyFoUxnx1FBikkeHj-W2sD_HDkukeSubydiBTA7nsa-vAjma9_bWqfhkztANc6fccTw32Bw"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMOHJ7UZxGTy4WhisyBQvBx1tPud0Jb8pFXIkI2ZsHaFoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vbi1nZGpvN3hSdm1WdjZjQ3FzRnRkdyE0OGY5M2MwNTFkNzE2OGUyQHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQCB6KhbOlA1YmoTUidvkrOOroAa1mX7YInYelT73WV0xXa4pTXlbRoEcocet6Wa6sumoEFr95-ylP6LxDtco8MA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli",
    "nonce": "RXlIbXJKYkZLOHcwVE5VS3VMdGp3VWtFcVQzMWlBN2w",
    "typ": "JWT",
    "url": "https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAMOHJ7UZxGTy4WhisyBQvBx1tPud0Jb8
pFXIkI2ZsHaFoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vbi1nZGpvN3hSdm1WdjZjQ3FzRnRkdyE0OGY5M2MwNTFkNzE2OGUyQHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQCB
6KhbOlA1YmoTUidvkrOOroAa1mX7YInYelT73WV0xXa4pTXlbRoEcocet6Wa6sum
oEFr95+ylP6LxDtco8MA
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
                    c3:87:27:b5:19:c4:64:f2:e1:68:62:b3:20:50:bc:
                    1c:75:b4:fb:9d:d0:96:fc:a4:55:c8:90:8d:99:b0:
                    76:85
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://n-gdjo7xRvmVv6cCqsFtdw!48f93c051d7168e2@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        81:e8:a8:5b:3a:50:35:62:6a:13:52:27:6f:92:b3:8e:ae:80:
        1a:d6:65:fb:60:89:d8:7a:54:fb:dd:65:74:c5:76:b8:a5:35:
        e5:6d:1a:04:72:87:1e:b7:a5:9a:ea:cb:a6:a0:41:6b:f7:9f:
        b2:94:fe:8b:c4:3b:5c:a3:c3:00

```

#### 28. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32818/acme/wire/directory>;rel="index"
location: https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T
replay-nonce: Y2dWYm9HY24yNm5lTlE5cms2ejRKT2xmbElMaEN1QTU
x-request-id: a9bb85ce-bec6-4609-8a76-79d64d91ed60
```
```json
{
  "certificate": "https://stepca:32818/acme/wire/certificate/9WPGu5WDMCUFoFGg1sln4iVpXcCbnuCX",
  "status": "valid",
  "finalize": "https://stepca:32818/acme/wire/order/kdNNuOe8TXF3GHNylZQFqDWhuXtWwq3T/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://n-gdjo7xRvmVv6cCqsFtdw!48f93c051d7168e2@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32818/acme/wire/authz/hvoSDZmL7d1wIHefqtayAd6YhPYJ3JzN",
    "https://stepca:32818/acme/wire/authz/zrb2cCHZC0T6aytVI8zb5DCg0yV8TjXK"
  ],
  "expires": "2024-10-18T12:30:54Z",
  "notBefore": "2024-10-17T12:30:54.964546475Z",
  "notAfter": "2034-10-15T12:30:54.964546475Z"
}
```
#### 29. fetch the certificate
```http request
POST https://stepca:32818/acme/wire/certificate/9WPGu5WDMCUFoFGg1sln4iVpXcCbnuCX
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODE4L2FjbWUvd2lyZS9hY2NvdW50L2JOVWdrVkR6am41dWpFdTVuVm9CTWxEWTNCN204bGxpIiwidHlwIjoiSldUIiwibm9uY2UiOiJZMmRXWW05SFkyNHlObTVsVGxFNWNtczJlalJLVDJ4bWJFbE1hRU4xUVRVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MTgvYWNtZS93aXJlL2NlcnRpZmljYXRlLzlXUEd1NVdETUNVRm9GR2cxc2xuNGlWcFhjQ2JudUNYIn0",
  "payload": "",
  "signature": "SgT17XEVj1BYCCLmGs9IaP7eWaIHS7uqE0nvkM_LR9ELNKj-i7UrWrX0fkoBUNphfEyL91HqRtOOrUJSKRh4Bw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32818/acme/wire/account/bNUgkVDzjn5ujEu5nVoBMlDY3B7m8lli",
    "nonce": "Y2dWYm9HY24yNm5lTlE5cms2ejRKT2xmbElMaEN1QTU",
    "typ": "JWT",
    "url": "https://stepca:32818/acme/wire/certificate/9WPGu5WDMCUFoFGg1sln4iVpXcCbnuCX"
  }
}
```
#### 30. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32818/acme/wire/directory>;rel="index"
replay-nonce: OVc1NlhjbERLQXkydktOYmZEVzVNRUo1NFZVOXFKeXY
x-request-id: 2289dc82-0f50-4dc9-91f4-15d8a1d1ec55
```
```json
"-----BEGIN CERTIFICATE-----\nMIICCzCCAbGgAwIBAgIRAIc8GfYTLNqUjc2fYPcG48owCgYIKoZIzj0EAwIwHzEd\nMBsGA1UEAxMUV2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcNMjQxMDE3MTIzMDU0WhcN\nMzQxMDE1MTIzMDU0WjApMREwDwYDVQQKEwh3aXJlLmNvbTEUMBIGA1UEAxMLQWxp\nY2UgU21pdGgwKjAFBgMrZXADIQDDhye1GcRk8uFoYrMgULwcdbT7ndCW/KRVyJCN\nmbB2haOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIw\nHQYDVR0OBBYEFPUAZQmr/0mLNRZmS8LL664QvUIoMB8GA1UdIwQYMBaAFLXTai3w\n7nCUYWVlmHDVIwca09DsMGkGA1UdEQRiMGCGIHdpcmVhcHA6Ly8lNDBhbGljZV93\naXJlQHdpcmUuY29thjx3aXJlYXBwOi8vbi1nZGpvN3hSdm1WdjZjQ3FzRnRkdyUy\nMTQ4ZjkzYzA1MWQ3MTY4ZTJAd2lyZS5jb20wHQYMKwYBBAGCpGTGKEABBA0wCwIB\nBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIG63QvlAlmqKCGF1EQHvMYFH5ovK\naGrWI8Ia6eDfHpcuAiEA4UpDlSf7qzgVHcUzYyia1HaviWo2+6IHbzpvO73Tysk=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBzzCCAXWgAwIBAgIQe2b4guOR5ztsvxDXN1dYozAKBggqhkjOPQQDAjAXMRUw\nEwYDVQQDEwxXaXJlIFJvb3QgQ0EwHhcNMjQxMDE3MTIzMDQ5WhcNMjQxMDE4MTIz\nMDQ5WjAfMR0wGwYDVQQDExRXaXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49\nAgEGCCqGSM49AwEHA0IABJ1+yDgwtUkrIowBzeomf/kGcMuAGrdX86tGN/d1F3D3\nnpdNKN5AyTLqm8mdnzo40ZuduJ3/cCA8tCgsKWTeIsKjgZowgZcwDgYDVR0PAQH/\nBAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLXTai3w7nCUYWVl\nmHDVIwca09DsMB8GA1UdIwQYMBaAFFlw5QtGGXerXuR9cOY8V/vPT/BWMDEGA1Ud\nHgEB/wQnMCWgIzALgglsb2NhbGhvc3QwCIIGc3RlcGNhMAqGCHdpcmUuY29tMAoG\nCCqGSM49BAMCA0gAMEUCIANL4DIe7a/sThnW10ez9Fhb/P87BiVzeqZlC7AjX1uG\nAiEAl6XQJt657nB1VAHZFd86ZDwOgkvUUI9Tu2wlOL/6fxM=\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICCzCCAbGgAwIBAgIRAIc8GfYTLNqUjc2fYPcG48owCgYIKoZIzj0EAwIwHzEd
MBsGA1UEAxMUV2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcNMjQxMDE3MTIzMDU0WhcN
MzQxMDE1MTIzMDU0WjApMREwDwYDVQQKEwh3aXJlLmNvbTEUMBIGA1UEAxMLQWxp
Y2UgU21pdGgwKjAFBgMrZXADIQDDhye1GcRk8uFoYrMgULwcdbT7ndCW/KRVyJCN
mbB2haOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwIw
HQYDVR0OBBYEFPUAZQmr/0mLNRZmS8LL664QvUIoMB8GA1UdIwQYMBaAFLXTai3w
7nCUYWVlmHDVIwca09DsMGkGA1UdEQRiMGCGIHdpcmVhcHA6Ly8lNDBhbGljZV93
aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vbi1nZGpvN3hSdm1WdjZjQ3FzRnRkdyUy
MTQ4ZjkzYzA1MWQ3MTY4ZTJAd2lyZS5jb20wHQYMKwYBBAGCpGTGKEABBA0wCwIB
BgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIG63QvlAlmqKCGF1EQHvMYFH5ovK
aGrWI8Ia6eDfHpcuAiEA4UpDlSf7qzgVHcUzYyia1HaviWo2+6IHbzpvO73Tysk=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            87:3c:19:f6:13:2c:da:94:8d:cd:9f:60:f7:06:e3:ca
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Wire Intermediate CA
        Validity
            Not Before: Oct 17 12:30:54 2024 GMT
            Not After : Oct 15 12:30:54 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    c3:87:27:b5:19:c4:64:f2:e1:68:62:b3:20:50:bc:
                    1c:75:b4:fb:9d:d0:96:fc:a4:55:c8:90:8d:99:b0:
                    76:85
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                F5:00:65:09:AB:FF:49:8B:35:16:66:4B:C2:CB:EB:AE:10:BD:42:28
            X509v3 Authority Key Identifier: 
                B5:D3:6A:2D:F0:EE:70:94:61:65:65:98:70:D5:23:07:1A:D3:D0:EC
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://n-gdjo7xRvmVv6cCqsFtdw%2148f93c051d7168e2@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:6e:b7:42:f9:40:96:6a:8a:08:61:75:11:01:ef:
        31:81:47:e6:8b:ca:68:6a:d6:23:c2:1a:e9:e0:df:1e:97:2e:
        02:21:00:e1:4a:43:95:27:fb:ab:38:15:1d:c5:33:63:28:9a:
        d4:76:af:89:6a:36:fb:a2:07:6f:3a:6f:3b:bd:d3:ca:c9

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBzzCCAXWgAwIBAgIQe2b4guOR5ztsvxDXN1dYozAKBggqhkjOPQQDAjAXMRUw
EwYDVQQDEwxXaXJlIFJvb3QgQ0EwHhcNMjQxMDE3MTIzMDQ5WhcNMjQxMDE4MTIz
MDQ5WjAfMR0wGwYDVQQDExRXaXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABJ1+yDgwtUkrIowBzeomf/kGcMuAGrdX86tGN/d1F3D3
npdNKN5AyTLqm8mdnzo40ZuduJ3/cCA8tCgsKWTeIsKjgZowgZcwDgYDVR0PAQH/
BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFLXTai3w7nCUYWVl
mHDVIwca09DsMB8GA1UdIwQYMBaAFFlw5QtGGXerXuR9cOY8V/vPT/BWMDEGA1Ud
HgEB/wQnMCWgIzALgglsb2NhbGhvc3QwCIIGc3RlcGNhMAqGCHdpcmUuY29tMAoG
CCqGSM49BAMCA0gAMEUCIANL4DIe7a/sThnW10ez9Fhb/P87BiVzeqZlC7AjX1uG
AiEAl6XQJt657nB1VAHZFd86ZDwOgkvUUI9Tu2wlOL/6fxM=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            7b:66:f8:82:e3:91:e7:3b:6c:bf:10:d7:37:57:58:a3
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Wire Root CA
        Validity
            Not Before: Oct 17 12:30:49 2024 GMT
            Not After : Oct 18 12:30:49 2024 GMT
        Subject: CN=Wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:9d:7e:c8:38:30:b5:49:2b:22:8c:01:cd:ea:26:
                    7f:f9:06:70:cb:80:1a:b7:57:f3:ab:46:37:f7:75:
                    17:70:f7:9e:97:4d:28:de:40:c9:32:ea:9b:c9:9d:
                    9f:3a:38:d1:9b:9d:b8:9d:ff:70:20:3c:b4:28:2c:
                    29:64:de:22:c2
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                B5:D3:6A:2D:F0:EE:70:94:61:65:65:98:70:D5:23:07:1A:D3:D0:EC
            X509v3 Authority Key Identifier: 
                59:70:E5:0B:46:19:77:AB:5E:E4:7D:70:E6:3C:57:FB:CF:4F:F0:56
            X509v3 Name Constraints: critical
                Permitted:
                  DNS:localhost
                  DNS:stepca
                  URI:wire.com
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:03:4b:e0:32:1e:ed:af:ec:4e:19:d6:d7:47:b3:
        f4:58:5b:fc:ff:3b:06:25:73:7a:a6:65:0b:b0:23:5f:5b:86:
        02:21:00:97:a5:d0:26:de:b9:ee:70:75:54:01:d9:15:df:3a:
        64:3c:0e:82:4b:d4:50:8f:53:bb:6c:25:38:bf:fa:7f:13

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBczCCARigAwIBAgIRAI0Fp0hvbTUwvkOEbHUgcbEwCgYIKoZIzj0EAwIwFzEV
MBMGA1UEAxMMV2lyZSBSb290IENBMB4XDTI0MTAxNzEyMzA0OVoXDTM0MTAxNTEy
MzA0OVowFzEVMBMGA1UEAxMMV2lyZSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEegkrBBZjjKi5fZfU1cC0js5wkGuiV/LkP44mU9gD+V3GHT9rI1Wf
GHIseXyg8Ieo8L492kNSmkv93ReTQx2o1qNFMEMwDgYDVR0PAQH/BAQDAgEGMBIG
A1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFFlw5QtGGXerXuR9cOY8V/vPT/BW
MAoGCCqGSM49BAMCA0kAMEYCIQCTSo9r7zwab9iTt6JB6vASCa6BCr2LwXiL86g9
5PbzTwIhAOMVRSAS2Omgbjeljtt2R7jpVE7FCR6+2GH0kxIcc1nO
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            8d:05:a7:48:6f:6d:35:30:be:43:84:6c:75:20:71:b1
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: CN=Wire Root CA
        Validity
            Not Before: Oct 17 12:30:49 2024 GMT
            Not After : Oct 15 12:30:49 2034 GMT
        Subject: CN=Wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:7a:09:2b:04:16:63:8c:a8:b9:7d:97:d4:d5:c0:
                    b4:8e:ce:70:90:6b:a2:57:f2:e4:3f:8e:26:53:d8:
                    03:f9:5d:c6:1d:3f:6b:23:55:9f:18:72:2c:79:7c:
                    a0:f0:87:a8:f0:be:3d:da:43:52:9a:4b:fd:dd:17:
                    93:43:1d:a8:d6
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                59:70:E5:0B:46:19:77:AB:5E:E4:7D:70:E6:3C:57:FB:CF:4F:F0:56
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:93:4a:8f:6b:ef:3c:1a:6f:d8:93:b7:a2:41:
        ea:f0:12:09:ae:81:0a:bd:8b:c1:78:8b:f3:a8:3d:e4:f6:f3:
        4f:02:21:00:e3:15:45:20:12:d8:e9:a0:6e:37:a5:8e:db:76:
        47:b8:e9:54:4e:c5:09:1e:be:d8:61:f4:93:12:1c:73:59:ce

```

openssl verify chain ❌ O=wire.com, CN=Alice Smith
error 47 at 0 depth lookup: permitted subtree violation
error /tmp/cert-ZkhvSklXbmhqaEVr.pem: verification failed
