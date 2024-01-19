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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/2531baed41682bfd/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/6SDQFoXfk1UT75qRfzurqxWCMEatapiL/5Qi9J8Jh6iP5zax2AuCyTTNMl623mcze
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz/y5rCMB1OJli5fp0ZWm8Ib2ZAvg1DtJmi
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/vyVCpvP32HaBPX6IqOrUcq7rFYVHhthx
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:33018/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:33018/acme/wire/new-nonce",
  "newAccount": "https://stepca:33018/acme/wire/new-account",
  "newOrder": "https://stepca:33018/acme/wire/new-order",
  "revokeCert": "https://stepca:33018/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:33018/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:33018/acme/wire/directory>;rel="index"
replay-nonce: V1hkeVJlZU45Z2lRdkJaYmhWREFtUUs4QzhyejJwd1g
```
```text
V1hkeVJlZU45Z2lRdkJaYmhWREFtUUs4QzhyejJwd1g
```
#### 5. create a new account
```http request
POST https://stepca:33018/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlhBdnBSZmMtM3FmLUx6dS10eFFiYUtqRmdPVXdPY1h0aVFiZzV0MWFwdE0ifSwibm9uY2UiOiJWMWhrZVZKbFpVNDVaMmxSZGtKYVltaFdSRUZ0VVVzNFF6aHllakp3ZDFnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "8529I0-u9mznTzJMi_Go2zgbPs-ztNHx2PCONlKOwbAjWwyeveZZn3G1QY0dkh8vUny4aBpq9P6vDrGuHeRXBA"
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
      "x": "XAvpRfc-3qf-Lzu-txQbaKjFgOUwOcXtiQbg5t1aptM"
    },
    "nonce": "V1hkeVJlZU45Z2lRdkJaYmhWREFtUUs4QzhyejJwd1g",
    "typ": "JWT",
    "url": "https://stepca:33018/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33018/acme/wire/directory>;rel="index"
location: https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg
replay-nonce: NDQwU1pwT2FPT2g1TURuRkVaR1RJSXAycHpWNVhEQ2o
```
```json
{
  "status": "valid",
  "orders": "https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:33018/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDE4L2FjbWUvd2lyZS9hY2NvdW50L0E2YWtSQ09XMTZxNlRiU3Ewb0pXR2pzZjFsdWVHbmdnIiwidHlwIjoiSldUIiwibm9uY2UiOiJORFF3VTFwd1QyRlBUMmcxVFVSdVJrVmFSMVJKU1hBeWNIcFdOVmhFUTJvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtZGV2aWNlIiwidmFsdWUiOiJ7XCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9RaUlPZi0tcFFXbWc5T0pNd3k4eFdRITI1MzFiYWVkNDE2ODJiZmRAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIixcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCJ9In0seyJ0eXBlIjoid2lyZWFwcC11c2VyIiwidmFsdWUiOiJ7XCJoYW5kbGVcIjpcIndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tXCIsXCJuYW1lXCI6XCJBbGljZSBTbWl0aFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyNC0wMS0xOVQxNToyOTo0OS40NDcxMDVaIiwibm90QWZ0ZXIiOiIyMDM0LTAxLTE2VDE1OjI5OjQ5LjQ0NzEwNVoifQ",
  "signature": "dfK6BaUsiRDbwB9IErzIfqlDmz8gaZbAo-xrtkiypmHiFY3-IcjQxJ_-NTdV5D4Hwa9c095sAQZ8CjCTGX9FCw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-device",
        "value": "{\"client-id\":\"wireapp://QiIOf--pQWmg9OJMwy8xWQ!2531baed41682bfd@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      },
      {
        "type": "wireapp-user",
        "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
      }
    ],
    "notAfter": "2034-01-16T15:29:49.447105Z",
    "notBefore": "2024-01-19T15:29:49.447105Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg",
    "nonce": "NDQwU1pwT2FPT2g1TURuRkVaR1RJSXAycHpWNVhEQ2o",
    "typ": "JWT",
    "url": "https://stepca:33018/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33018/acme/wire/directory>;rel="index"
location: https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB
replay-nonce: MWl3OTlOeGs4MzV1Nm5DUnhQd3hLRnZpaGg5alFMWHA
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://QiIOf--pQWmg9OJMwy8xWQ!2531baed41682bfd@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33018/acme/wire/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
    "https://stepca:33018/acme/wire/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
  ],
  "expires": "2024-01-20T15:29:49Z",
  "notBefore": "2024-01-19T15:29:49.447105Z",
  "notAfter": "2034-01-16T15:29:49.447105Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:33018/acme/wire/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDE4L2FjbWUvd2lyZS9hY2NvdW50L0E2YWtSQ09XMTZxNlRiU3Ewb0pXR2pzZjFsdWVHbmdnIiwidHlwIjoiSldUIiwibm9uY2UiOiJNV2wzT1RsT2VHczRNelYxTm01RFVuaFFkM2hMUm5acGFHZzVhbEZNV0hBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL2F1dGh6LzZTRFFGb1hmazFVVDc1cVJmenVycXhXQ01FYXRhcGlMIn0",
  "payload": "",
  "signature": "VjFf5tg0kcmu2iYmPH6HHmV6H4cZMufg7xiQ54-2Uk72lNlEKz0caRWKU-Rt5VfkOgtaNq2e9pdbOCWsDMmhBQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg",
    "nonce": "MWl3OTlOeGs4MzV1Nm5DUnhQd3hLRnZpaGg5alFMWHA",
    "typ": "JWT",
    "url": "https://stepca:33018/acme/wire/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33018/acme/wire/directory>;rel="index"
location: https://stepca:33018/acme/wire/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL
replay-nonce: eDZodUo3cUlLVlJDaFNCQVNtMWk2eGdvWWRlWHpaWkI
```
```json
{
  "status": "pending",
  "expires": "2024-01-20T15:29:49Z",
  "challenges": [
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:33018/acme/wire/challenge/6SDQFoXfk1UT75qRfzurqxWCMEatapiL/5Qi9J8Jh6iP5zax2AuCyTTNMl623mcze",
      "status": "pending",
      "token": "sGon6CGWYiDWKnBMlNHmoidxVf8e0okt",
      "target": "http://wire.com:21098/clients/2531baed41682bfd/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-device",
    "value": "{\"client-id\":\"wireapp://QiIOf--pQWmg9OJMwy8xWQ!2531baed41682bfd@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
  }
}
```
```http request
POST https://stepca:33018/acme/wire/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDE4L2FjbWUvd2lyZS9hY2NvdW50L0E2YWtSQ09XMTZxNlRiU3Ewb0pXR2pzZjFsdWVHbmdnIiwidHlwIjoiSldUIiwibm9uY2UiOiJlRFpvZFVvM2NVbExWbEpEYUZOQ1FWTnRNV2syZUdkdldXUmxXSHBhV2tJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL2F1dGh6L2Qyc0p5TTBNYVY2d1RYNENsUDhlVVE4VEY0WktrN2p6In0",
  "payload": "",
  "signature": "A8cCRWr0NrjmwlPOb3cLREq49NNVLNVws1xYN8qLkCtxgBIiIAYAvafRwcCyjHIj34BjDHKXgar4Nd4Fa8pPCw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg",
    "nonce": "eDZodUo3cUlLVlJDaFNCQVNtMWk2eGdvWWRlWHpaWkI",
    "typ": "JWT",
    "url": "https://stepca:33018/acme/wire/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
  }
}
```
#### 11. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33018/acme/wire/directory>;rel="index"
location: https://stepca:33018/acme/wire/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz
replay-nonce: cWpVck5lOVZ3elRHSXBGMG1CeUNWTHQxVk8ydVZabnQ
```
```json
{
  "status": "pending",
  "expires": "2024-01-20T15:29:49Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:33018/acme/wire/challenge/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz/y5rCMB1OJli5fp0ZWm8Ib2ZAvg1DtJmi",
      "status": "pending",
      "token": "PSzmZX28YUVY5iTIfDehT2oF8HERQWDt",
      "target": "http://keycloak:24584/realms/master"
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
GET http://wire.com:21098/clients/token/nonce
```
#### 13. get wire-server nonce
```http request
200

```
```text
Y3VJdWZzbGthUzNqWUtwZFlDMHczc2FwZDZVczlyTHA
```
#### 14. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiWEF2cFJmYy0zcWYtTHp1LXR4UWJhS2pGZ09Vd09jWHRpUWJnNXQxYXB0TSJ9fQ.eyJpYXQiOjE3MDU2NzQ1ODksImV4cCI6MTcwNTY4MTc4OSwibmJmIjoxNzA1Njc0NTg5LCJzdWIiOiJ3aXJlYXBwOi8vUWlJT2YtLXBRV21nOU9KTXd5OHhXUSEyNTMxYmFlZDQxNjgyYmZkQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL2NoYWxsZW5nZS82U0RRRm9YZmsxVVQ3NXFSZnp1cnF4V0NNRWF0YXBpTC81UWk5SjhKaDZpUDV6YXgyQXVDeVRUTk1sNjIzbWN6ZSIsImp0aSI6IjQ0N2FlMzg4LTdkNTMtNGE2Yi1hN2Q5LWE4MWIzMjU3NGQ2ZSIsIm5vbmNlIjoiWTNWSmRXWnpiR3RoVXpOcVdVdHdaRmxETUhjemMyRndaRFpWY3pseVRIQSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjEwOTgvY2xpZW50cy8yNTMxYmFlZDQxNjgyYmZkL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJzR29uNkNHV1lpRFdLbkJNbE5IbW9pZHhWZjhlMG9rdCIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.ImMQ8UVl6gVRzAAnQ9gdDTVtI7ven2htZNMU0tHbjt6tsatjSODE-z00WkWYLP-HygSj5fV9KnX6Ya3T5lCiCA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiWEF2cFJmYy0zcWYtTHp1LXR4UWJhS2pG
Z09Vd09jWHRpUWJnNXQxYXB0TSJ9fQ.eyJpYXQiOjE3MDU2NzQ1ODksImV4cCI6M
TcwNTY4MTc4OSwibmJmIjoxNzA1Njc0NTg5LCJzdWIiOiJ3aXJlYXBwOi8vUWlJT
2YtLXBRV21nOU9KTXd5OHhXUSEyNTMxYmFlZDQxNjgyYmZkQHdpcmUuY29tIiwiY
XVkIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL2NoYWxsZW5nZS82U
0RRRm9YZmsxVVQ3NXFSZnp1cnF4V0NNRWF0YXBpTC81UWk5SjhKaDZpUDV6YXgyQ
XVDeVRUTk1sNjIzbWN6ZSIsImp0aSI6IjQ0N2FlMzg4LTdkNTMtNGE2Yi1hN2Q5L
WE4MWIzMjU3NGQ2ZSIsIm5vbmNlIjoiWTNWSmRXWnpiR3RoVXpOcVdVdHdaRmxET
UhjemMyRndaRFpWY3pseVRIQSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd
2lyZS5jb206MjEwOTgvY2xpZW50cy8yNTMxYmFlZDQxNjgyYmZkL2FjY2Vzcy10b
2tlbiIsImNoYWwiOiJzR29uNkNHV1lpRFdLbkJNbE5IbW9pZHhWZjhlMG9rdCIsI
mhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhb
SI6IndpcmUifQ.ImMQ8UVl6gVRzAAnQ9gdDTVtI7ven2htZNMU0tHbjt6tsatjSO
DE-z00WkWYLP-HygSj5fV9KnX6Ya3T5lCiCA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "XAvpRfc-3qf-Lzu-txQbaKjFgOUwOcXtiQbg5t1aptM"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "aud": "https://stepca:33018/acme/wire/challenge/6SDQFoXfk1UT75qRfzurqxWCMEatapiL/5Qi9J8Jh6iP5zax2AuCyTTNMl623mcze",
  "chal": "sGon6CGWYiDWKnBMlNHmoidxVf8e0okt",
  "exp": 1705681789,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:21098/clients/2531baed41682bfd/access-token",
  "iat": 1705674589,
  "jti": "447ae388-7d53-4a6b-a7d9-a81b32574d6e",
  "nbf": 1705674589,
  "nonce": "Y3VJdWZzbGthUzNqWUtwZFlDMHczc2FwZDZVczlyTHA",
  "sub": "wireapp://QiIOf--pQWmg9OJMwy8xWQ!2531baed41682bfd@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICNthSDu/kt81qrzt2NHK86KtTNS89uxeJf1ioD9TXmq
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAXAvpRfc+3qf+Lzu+txQbaKjFgOUwOcXtiQbg5t1aptM=
-----END PUBLIC KEY-----
```

</details>


#### 15. trade client DPoP token for an access token
```http request
POST http://wire.com:21098/clients/2531baed41682bfd/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pV0VGMmNGSm1ZeTB6Y1dZdFRIcDFMWFI0VVdKaFMycEdaMDlWZDA5aldIUnBVV0puTlhReFlYQjBUU0o5ZlEuZXlKcFlYUWlPakUzTURVMk56UTFPRGtzSW1WNGNDSTZNVGN3TlRZNE1UYzRPU3dpYm1KbUlqb3hOekExTmpjME5UZzVMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZVV2xKVDJZdExYQlJWMjFuT1U5S1RYZDVPSGhYVVNFeU5UTXhZbUZsWkRReE5qZ3lZbVprUUhkcGNtVXVZMjl0SWl3aVlYVmtJam9pYUhSMGNITTZMeTl6ZEdWd1kyRTZNek13TVRndllXTnRaUzkzYVhKbEwyTm9ZV3hzWlc1blpTODJVMFJSUm05WVptc3hWVlEzTlhGU1pucDFjbkY0VjBOTlJXRjBZWEJwVEM4MVVXazVTamhLYURacFVEVjZZWGd5UVhWRGVWUlVUazFzTmpJemJXTjZaU0lzSW1wMGFTSTZJalEwTjJGbE16ZzRMVGRrTlRNdE5HRTJZaTFoTjJRNUxXRTRNV0l6TWpVM05HUTJaU0lzSW01dmJtTmxJam9pV1ROV1NtUlhXbnBpUjNSb1ZYcE9jVmRWZEhkYVJteEVUVWhqZW1NeVJuZGFSRnBXWTNwc2VWUklRU0lzSW1oMGJTSTZJbEJQVTFRaUxDSm9kSFVpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpFd09UZ3ZZMnhwWlc1MGN5OHlOVE14WW1GbFpEUXhOamd5WW1aa0wyRmpZMlZ6Y3kxMGIydGxiaUlzSW1Ob1lXd2lPaUp6UjI5dU5rTkhWMWxwUkZkTGJrSk5iRTVJYlc5cFpIaFdaamhsTUc5cmRDSXNJbWhoYm1Sc1pTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lkR1ZoYlNJNkluZHBjbVVpZlEuSW1NUThVVmw2Z1ZSekFBblE5Z2REVFZ0STd2ZW4yaHRaTk1VMHRIYmp0NnRzYXRqU09ERS16MDBXa1dZTFAtSHlnU2o1ZlY5S25YNllhM1Q1bENpQ0E
```
#### 16. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkhiWmNFRWR0bXI0aDNGTHlGTDZsbWZsZ1Z6RWhlcUlPNmFkOVQ0SWtZOHMifX0.eyJpYXQiOjE3MDU2NzQ1ODksImV4cCI6MTcwNTY3ODU0OSwibmJmIjoxNzA1Njc0NTg5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjEwOTgvY2xpZW50cy8yNTMxYmFlZDQxNjgyYmZkL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9RaUlPZi0tcFFXbWc5T0pNd3k4eFdRITI1MzFiYWVkNDE2ODJiZmRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMzAxOC9hY21lL3dpcmUvY2hhbGxlbmdlLzZTRFFGb1hmazFVVDc1cVJmenVycXhXQ01FYXRhcGlMLzVRaTlKOEpoNmlQNXpheDJBdUN5VFROTWw2MjNtY3plIiwianRpIjoiNmJkMDQyNTYtMWQwYy00YTdlLWI1Y2MtNjk5ZDNkNDJjMzBhIiwibm9uY2UiOiJZM1ZKZFdaemJHdGhVek5xV1V0d1pGbERNSGN6YzJGd1pEWlZjemx5VEhBIiwiY2hhbCI6InNHb242Q0dXWWlEV0tuQk1sTkhtb2lkeFZmOGUwb2t0IiwiY25mIjp7ImtpZCI6IlJ2Zzl0YVp2SDZXcV9pMDN4a0xXQXVwSkxnQkJhTnZxbHRRblVuelRVNzQifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lXRUYyY0ZKbVl5MHpjV1l0VEhwMUxYUjRVV0poUzJwR1owOVZkMDlqV0hScFVXSm5OWFF4WVhCMFRTSjlmUS5leUpwWVhRaU9qRTNNRFUyTnpRMU9Ea3NJbVY0Y0NJNk1UY3dOVFk0TVRjNE9Td2libUptSWpveE56QTFOamMwTlRnNUxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dlVXbEpUMll0TFhCUlYyMW5PVTlLVFhkNU9IaFhVU0V5TlRNeFltRmxaRFF4TmpneVltWmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16TXdNVGd2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM4MlUwUlJSbTlZWm1zeFZWUTNOWEZTWm5wMWNuRjRWME5OUldGMFlYQnBUQzgxVVdrNVNqaEthRFpwVURWNllYZ3lRWFZEZVZSVVRrMXNOakl6YldONlpTSXNJbXAwYVNJNklqUTBOMkZsTXpnNExUZGtOVE10TkdFMllpMWhOMlE1TFdFNE1XSXpNalUzTkdRMlpTSXNJbTV2Ym1ObElqb2lXVE5XU21SWFducGlSM1JvVlhwT2NWZFZkSGRhUm14RVRVaGplbU15Um5kYVJGcFdZM3BzZVZSSVFTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakV3T1RndlkyeHBaVzUwY3k4eU5UTXhZbUZsWkRReE5qZ3lZbVprTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnpSMjl1TmtOSFYxbHBSRmRMYmtKTmJFNUliVzlwWkhoV1pqaGxNRzlyZENJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5JbU1ROFVWbDZnVlJ6QUFuUTlnZERUVnRJN3ZlbjJodFpOTVUwdEhianQ2dHNhdGpTT0RFLXowMFdrV1lMUC1IeWdTajVmVjlLblg2WWEzVDVsQ2lDQSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9RaUlPZi0tcFFXbWc5T0pNd3k4eFdRITI1MzFiYWVkNDE2ODJiZmRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.VaEksjv6j9dINbampMNc-vc-HqA0BN_v8rwsZ22HzRBa8GOEAAFlAh214PaALSfpYuXjoW69fg-HzjmLduRICg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkhiWmNFRWR0bXI0aDNGTHlGTDZsbWZsZ1Z6RWhlcUlPNmFkOVQ0SWtZOHMifX0.eyJpYXQiOjE3MDU2NzQ1ODksImV4cCI6MTcwNTY3ODU0OSwibmJmIjoxNzA1Njc0NTg5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjEwOTgvY2xpZW50cy8yNTMxYmFlZDQxNjgyYmZkL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9RaUlPZi0tcFFXbWc5T0pNd3k4eFdRITI1MzFiYWVkNDE2ODJiZmRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMzAxOC9hY21lL3dpcmUvY2hhbGxlbmdlLzZTRFFGb1hmazFVVDc1cVJmenVycXhXQ01FYXRhcGlMLzVRaTlKOEpoNmlQNXpheDJBdUN5VFROTWw2MjNtY3plIiwianRpIjoiNmJkMDQyNTYtMWQwYy00YTdlLWI1Y2MtNjk5ZDNkNDJjMzBhIiwibm9uY2UiOiJZM1ZKZFdaemJHdGhVek5xV1V0d1pGbERNSGN6YzJGd1pEWlZjemx5VEhBIiwiY2hhbCI6InNHb242Q0dXWWlEV0tuQk1sTkhtb2lkeFZmOGUwb2t0IiwiY25mIjp7ImtpZCI6IlJ2Zzl0YVp2SDZXcV9pMDN4a0xXQXVwSkxnQkJhTnZxbHRRblVuelRVNzQifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lXRUYyY0ZKbVl5MHpjV1l0VEhwMUxYUjRVV0poUzJwR1owOVZkMDlqV0hScFVXSm5OWFF4WVhCMFRTSjlmUS5leUpwWVhRaU9qRTNNRFUyTnpRMU9Ea3NJbVY0Y0NJNk1UY3dOVFk0TVRjNE9Td2libUptSWpveE56QTFOamMwTlRnNUxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dlVXbEpUMll0TFhCUlYyMW5PVTlLVFhkNU9IaFhVU0V5TlRNeFltRmxaRFF4TmpneVltWmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16TXdNVGd2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM4MlUwUlJSbTlZWm1zeFZWUTNOWEZTWm5wMWNuRjRWME5OUldGMFlYQnBUQzgxVVdrNVNqaEthRFpwVURWNllYZ3lRWFZEZVZSVVRrMXNOakl6YldONlpTSXNJbXAwYVNJNklqUTBOMkZsTXpnNExUZGtOVE10TkdFMllpMWhOMlE1TFdFNE1XSXpNalUzTkdRMlpTSXNJbTV2Ym1ObElqb2lXVE5XU21SWFducGlSM1JvVlhwT2NWZFZkSGRhUm14RVRVaGplbU15Um5kYVJGcFdZM3BzZVZSSVFTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakV3T1RndlkyeHBaVzUwY3k4eU5UTXhZbUZsWkRReE5qZ3lZbVprTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnpSMjl1TmtOSFYxbHBSRmRMYmtKTmJFNUliVzlwWkhoV1pqaGxNRzlyZENJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5JbU1ROFVWbDZnVlJ6QUFuUTlnZERUVnRJN3ZlbjJodFpOTVUwdEhianQ2dHNhdGpTT0RFLXowMFdrV1lMUC1IeWdTajVmVjlLblg2WWEzVDVsQ2lDQSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9RaUlPZi0tcFFXbWc5T0pNd3k4eFdRITI1MzFiYWVkNDE2ODJiZmRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.VaEksjv6j9dINbampMNc-vc-HqA0BN_v8rwsZ22HzRBa8GOEAAFlAh214PaALSfpYuXjoW69fg-HzjmLduRICg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IkhiWmNFRWR0bXI0aDNGTHlGTDZsbWZsZ1Z6
RWhlcUlPNmFkOVQ0SWtZOHMifX0.eyJpYXQiOjE3MDU2NzQ1ODksImV4cCI6MTcw
NTY3ODU0OSwibmJmIjoxNzA1Njc0NTg5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjEwOTgvY2xpZW50cy8yNTMxYmFlZDQxNjgyYmZkL2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9RaUlPZi0tcFFXbWc5T0pNd3k4eFdRITI1MzFiYWVkNDE2
ODJiZmRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMzAxOC9hY21l
L3dpcmUvY2hhbGxlbmdlLzZTRFFGb1hmazFVVDc1cVJmenVycXhXQ01FYXRhcGlM
LzVRaTlKOEpoNmlQNXpheDJBdUN5VFROTWw2MjNtY3plIiwianRpIjoiNmJkMDQy
NTYtMWQwYy00YTdlLWI1Y2MtNjk5ZDNkNDJjMzBhIiwibm9uY2UiOiJZM1ZKZFda
emJHdGhVek5xV1V0d1pGbERNSGN6YzJGd1pEWlZjemx5VEhBIiwiY2hhbCI6InNH
b242Q0dXWWlEV0tuQk1sTkhtb2lkeFZmOGUwb2t0IiwiY25mIjp7ImtpZCI6IlJ2
Zzl0YVp2SDZXcV9pMDN4a0xXQXVwSkxnQkJhTnZxbHRRblVuelRVNzQifSwicHJv
b2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3
aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENK
NElqb2lXRUYyY0ZKbVl5MHpjV1l0VEhwMUxYUjRVV0poUzJwR1owOVZkMDlqV0hS
cFVXSm5OWFF4WVhCMFRTSjlmUS5leUpwWVhRaU9qRTNNRFUyTnpRMU9Ea3NJbVY0
Y0NJNk1UY3dOVFk0TVRjNE9Td2libUptSWpveE56QTFOamMwTlRnNUxDSnpkV0lp
T2lKM2FYSmxZWEJ3T2k4dlVXbEpUMll0TFhCUlYyMW5PVTlLVFhkNU9IaFhVU0V5
TlRNeFltRmxaRFF4TmpneVltWmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIw
Y0hNNkx5OXpkR1Z3WTJFNk16TXdNVGd2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVu
WlM4MlUwUlJSbTlZWm1zeFZWUTNOWEZTWm5wMWNuRjRWME5OUldGMFlYQnBUQzgx
VVdrNVNqaEthRFpwVURWNllYZ3lRWFZEZVZSVVRrMXNOakl6YldONlpTSXNJbXAw
YVNJNklqUTBOMkZsTXpnNExUZGtOVE10TkdFMllpMWhOMlE1TFdFNE1XSXpNalUz
TkdRMlpTSXNJbTV2Ym1ObElqb2lXVE5XU21SWFducGlSM1JvVlhwT2NWZFZkSGRh
Um14RVRVaGplbU15Um5kYVJGcFdZM3BzZVZSSVFTSXNJbWgwYlNJNklsQlBVMVFp
TENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakV3T1RndlkyeHBaVzUw
Y3k4eU5UTXhZbUZsWkRReE5qZ3lZbVprTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5v
WVd3aU9pSnpSMjl1TmtOSFYxbHBSRmRMYmtKTmJFNUliVzlwWkhoV1pqaGxNRzly
ZENJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEps
UUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5JbU1ROFVWbDZnVlJ6
QUFuUTlnZERUVnRJN3ZlbjJodFpOTVUwdEhianQ2dHNhdGpTT0RFLXowMFdrV1lM
UC1IeWdTajVmVjlLblg2WWEzVDVsQ2lDQSIsImNsaWVudF9pZCI6IndpcmVhcHA6
Ly9RaUlPZi0tcFFXbWc5T0pNd3k4eFdRITI1MzFiYWVkNDE2ODJiZmRAd2lyZS5j
b20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.VaE
ksjv6j9dINbampMNc-vc-HqA0BN_v8rwsZ22HzRBa8GOEAAFlAh214PaALSfpYuX
joW69fg-HzjmLduRICg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "HbZcEEdtmr4h3FLyFL6lmflgVzEheqIO6ad9T4IkY8s"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "https://stepca:33018/acme/wire/challenge/6SDQFoXfk1UT75qRfzurqxWCMEatapiL/5Qi9J8Jh6iP5zax2AuCyTTNMl623mcze",
  "chal": "sGon6CGWYiDWKnBMlNHmoidxVf8e0okt",
  "client_id": "wireapp://QiIOf--pQWmg9OJMwy8xWQ!2531baed41682bfd@wire.com",
  "cnf": {
    "kid": "Rvg9taZvH6Wq_i03xkLWAupJLgBBaNvqltQnUnzTU74"
  },
  "exp": 1705678549,
  "iat": 1705674589,
  "iss": "http://wire.com:21098/clients/2531baed41682bfd/access-token",
  "jti": "6bd04256-1d0c-4a7e-b5cc-699d3d42c30a",
  "nbf": 1705674589,
  "nonce": "Y3VJdWZzbGthUzNqWUtwZFlDMHczc2FwZDZVczlyTHA",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiWEF2cFJmYy0zcWYtTHp1LXR4UWJhS2pGZ09Vd09jWHRpUWJnNXQxYXB0TSJ9fQ.eyJpYXQiOjE3MDU2NzQ1ODksImV4cCI6MTcwNTY4MTc4OSwibmJmIjoxNzA1Njc0NTg5LCJzdWIiOiJ3aXJlYXBwOi8vUWlJT2YtLXBRV21nOU9KTXd5OHhXUSEyNTMxYmFlZDQxNjgyYmZkQHdpcmUuY29tIiwiYXVkIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL2NoYWxsZW5nZS82U0RRRm9YZmsxVVQ3NXFSZnp1cnF4V0NNRWF0YXBpTC81UWk5SjhKaDZpUDV6YXgyQXVDeVRUTk1sNjIzbWN6ZSIsImp0aSI6IjQ0N2FlMzg4LTdkNTMtNGE2Yi1hN2Q5LWE4MWIzMjU3NGQ2ZSIsIm5vbmNlIjoiWTNWSmRXWnpiR3RoVXpOcVdVdHdaRmxETUhjemMyRndaRFpWY3pseVRIQSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjEwOTgvY2xpZW50cy8yNTMxYmFlZDQxNjgyYmZkL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJzR29uNkNHV1lpRFdLbkJNbE5IbW9pZHhWZjhlMG9rdCIsImhhbmRsZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwidGVhbSI6IndpcmUifQ.ImMQ8UVl6gVRzAAnQ9gdDTVtI7ven2htZNMU0tHbjt6tsatjSODE-z00WkWYLP-HygSj5fV9KnX6Ya3T5lCiCA",
  "scope": "wire_client_id",
  "sub": "wireapp://QiIOf--pQWmg9OJMwy8xWQ!2531baed41682bfd@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINeQmha5FH+j6CTA3tHHb/L4JaofWtVW257Iul+aTvwN
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAHbZcEEdtmr4h3FLyFL6lmflgVzEheqIO6ad9T4IkY8s=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 17. validate Dpop challenge (clientId)
```http request
POST https://stepca:33018/acme/wire/challenge/6SDQFoXfk1UT75qRfzurqxWCMEatapiL/5Qi9J8Jh6iP5zax2AuCyTTNMl623mcze
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDE4L2FjbWUvd2lyZS9hY2NvdW50L0E2YWtSQ09XMTZxNlRiU3Ewb0pXR2pzZjFsdWVHbmdnIiwidHlwIjoiSldUIiwibm9uY2UiOiJjV3BWY2s1bE9WWjNlbFJIU1hCR01HMUNlVU5XVEhReFZrOHlkVlphYm5RIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL2NoYWxsZW5nZS82U0RRRm9YZmsxVVQ3NXFSZnp1cnF4V0NNRWF0YXBpTC81UWk5SjhKaDZpUDV6YXgyQXVDeVRUTk1sNjIzbWN6ZSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklraGlXbU5GUldSMGJYSTBhRE5HVEhsR1REWnNiV1pzWjFaNlJXaGxjVWxQTm1Ga09WUTBTV3RaT0hNaWZYMC5leUpwWVhRaU9qRTNNRFUyTnpRMU9Ea3NJbVY0Y0NJNk1UY3dOVFkzT0RVME9Td2libUptSWpveE56QTFOamMwTlRnNUxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpFd09UZ3ZZMnhwWlc1MGN5OHlOVE14WW1GbFpEUXhOamd5WW1aa0wyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTlSYVVsUFppMHRjRkZYYldjNVQwcE5kM2s0ZUZkUklUSTFNekZpWVdWa05ERTJPREppWm1SQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndjem92TDNOMFpYQmpZVG96TXpBeE9DOWhZMjFsTDNkcGNtVXZZMmhoYkd4bGJtZGxMelpUUkZGR2IxaG1hekZWVkRjMWNWSm1lblZ5Y1hoWFEwMUZZWFJoY0dsTUx6VlJhVGxLT0Vwb05tbFFOWHBoZURKQmRVTjVWRlJPVFd3Mk1qTnRZM3BsSWl3aWFuUnBJam9pTm1Ka01EUXlOVFl0TVdRd1l5MDBZVGRsTFdJMVkyTXROams1WkROa05ESmpNekJoSWl3aWJtOXVZMlVpT2lKWk0xWktaRmRhZW1KSGRHaFZlazV4VjFWMGQxcEdiRVJOU0dONll6SkdkMXBFV2xaamVteDVWRWhCSWl3aVkyaGhiQ0k2SW5OSGIyNDJRMGRYV1dsRVYwdHVRazFzVGtodGIybGtlRlptT0dVd2IydDBJaXdpWTI1bUlqcDdJbXRwWkNJNklsSjJaemwwWVZwMlNEWlhjVjlwTURONGEweFhRWFZ3U2t4blFrSmhUblp4YkhSUmJsVnVlbFJWTnpRaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsWFJVWXlZMFpLYlZsNU1IcGpWMWwwVkVod01VeFlValJWVjBwb1V6SndSMW93T1Zaa01EbHFWMGhTY0ZWWFNtNU9XRkY0V1ZoQ01GUlRTamxtVVM1bGVVcHdXVmhSYVU5cVJUTk5SRlV5VG5wUk1VOUVhM05KYlZZMFkwTkpOazFVWTNkT1ZGazBUVlJqTkU5VGQybGliVXB0U1dwdmVFNTZRVEZPYW1Nd1RsUm5OVXhEU25wa1YwbHBUMmxLTTJGWVNteFpXRUozVDJrNGRsVlhiRXBVTWxsMFRGaENVbFl5TVc1UFZUbExWRmhrTlU5SWFGaFZVMFY1VGxSTmVGbHRSbXhhUkZGNFRtcG5lVmx0V210UlNHUndZMjFWZFZreU9YUkphWGRwV1ZoV2EwbHFiMmxoU0ZJd1kwaE5Oa3g1T1hwa1IxWjNXVEpGTmsxNlRYZE5WR2QyV1ZkT2RGcFRPVE5oV0Vwc1RESk9iMWxYZUhOYVZ6VnVXbE00TWxVd1VsSlNiVGxaV20xemVGWldVVE5PV0VaVFdtNXdNV051UmpSV01FNU9VbGRHTUZsWVFuQlVRemd4VlZkck5WTnFhRXRoUkZwd1ZVUldObGxZWjNsUldGWkVaVlpTVlZSck1YTk9ha2w2WWxkT05scFRTWE5KYlhBd1lWTkpOa2xxVVRCT01rWnNUWHBuTkV4VVpHdE9WRTEwVGtkRk1sbHBNV2hPTWxFMVRGZEZORTFYU1hwTmFsVXpUa2RSTWxwVFNYTkpiVFYyWW0xT2JFbHFiMmxYVkU1WFUyMVNXRmR1Y0dsU00xSnZWbGh3VDJOV1pGWmtTR1JoVW0xNFJWUlZhR3BsYlUxNVVtNWtZVkpHY0ZkWk0zQnpaVlpTU1ZGVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWtWM1QxUm5kbGt5ZUhCYVZ6VXdZM2s0ZVU1VVRYaFpiVVpzV2tSUmVFNXFaM2xaYlZwclRESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTbnBTTWpsMVRtdE9TRll4YkhCU1JtUk1ZbXRLVG1KRk5VbGlWemx3V2tob1YxcHFhR3hOUnpseVpFTkpjMGx0YUdoaWJWSnpXbE5KTmtsdVpIQmpiVlpvWTBoQk5reDVPR3hPUkVKb1lrZHNhbHBXT1ROaFdFcHNVVWhrY0dOdFZYVlpNamwwU1dsM2FXUkhWbWhpVTBrMlNXNWtjR050VldsbVVTNUpiVTFST0ZWV2JEWm5WbEo2UVVGdVVUbG5aRVJVVm5SSk4zWmxiakpvZEZwT1RWVXdkRWhpYW5RMmRITmhkR3BUVDBSRkxYb3dNRmRyVjFsTVVDMUllV2RUYWpWbVZqbExibGcyV1dFelZEVnNRMmxEUVNJc0ltTnNhV1Z1ZEY5cFpDSTZJbmRwY21WaGNIQTZMeTlSYVVsUFppMHRjRkZYYldjNVQwcE5kM2s0ZUZkUklUSTFNekZpWVdWa05ERTJPREppWm1SQWQybHlaUzVqYjIwaUxDSmhjR2xmZG1WeWMybHZiaUk2TlN3aWMyTnZjR1VpT2lKM2FYSmxYMk5zYVdWdWRGOXBaQ0o5LlZhRWtzanY2ajlkSU5iYW1wTU5jLXZjLUhxQTBCTl92OHJ3c1oyMkh6UkJhOEdPRUFBRmxBaDIxNFBhQUxTZnBZdVhqb1c2OWZnLUh6am1MZHVSSUNnIn0",
  "signature": "BQqa0SZt7xW-1PdGaRyZu5WoKUr4Y_ua_eKAAz_zl_7s_wjfddKPOH8_DK_xDHcFj9HY8YHKpv-Oa_5iqAnpBw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkhiWmNFRWR0bXI0aDNGTHlGTDZsbWZsZ1Z6RWhlcUlPNmFkOVQ0SWtZOHMifX0.eyJpYXQiOjE3MDU2NzQ1ODksImV4cCI6MTcwNTY3ODU0OSwibmJmIjoxNzA1Njc0NTg5LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjEwOTgvY2xpZW50cy8yNTMxYmFlZDQxNjgyYmZkL2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9RaUlPZi0tcFFXbWc5T0pNd3k4eFdRITI1MzFiYWVkNDE2ODJiZmRAd2lyZS5jb20iLCJhdWQiOiJodHRwczovL3N0ZXBjYTozMzAxOC9hY21lL3dpcmUvY2hhbGxlbmdlLzZTRFFGb1hmazFVVDc1cVJmenVycXhXQ01FYXRhcGlMLzVRaTlKOEpoNmlQNXpheDJBdUN5VFROTWw2MjNtY3plIiwianRpIjoiNmJkMDQyNTYtMWQwYy00YTdlLWI1Y2MtNjk5ZDNkNDJjMzBhIiwibm9uY2UiOiJZM1ZKZFdaemJHdGhVek5xV1V0d1pGbERNSGN6YzJGd1pEWlZjemx5VEhBIiwiY2hhbCI6InNHb242Q0dXWWlEV0tuQk1sTkhtb2lkeFZmOGUwb2t0IiwiY25mIjp7ImtpZCI6IlJ2Zzl0YVp2SDZXcV9pMDN4a0xXQXVwSkxnQkJhTnZxbHRRblVuelRVNzQifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lXRUYyY0ZKbVl5MHpjV1l0VEhwMUxYUjRVV0poUzJwR1owOVZkMDlqV0hScFVXSm5OWFF4WVhCMFRTSjlmUS5leUpwWVhRaU9qRTNNRFUyTnpRMU9Ea3NJbVY0Y0NJNk1UY3dOVFk0TVRjNE9Td2libUptSWpveE56QTFOamMwTlRnNUxDSnpkV0lpT2lKM2FYSmxZWEJ3T2k4dlVXbEpUMll0TFhCUlYyMW5PVTlLVFhkNU9IaFhVU0V5TlRNeFltRmxaRFF4TmpneVltWmtRSGRwY21VdVkyOXRJaXdpWVhWa0lqb2lhSFIwY0hNNkx5OXpkR1Z3WTJFNk16TXdNVGd2WVdOdFpTOTNhWEpsTDJOb1lXeHNaVzVuWlM4MlUwUlJSbTlZWm1zeFZWUTNOWEZTWm5wMWNuRjRWME5OUldGMFlYQnBUQzgxVVdrNVNqaEthRFpwVURWNllYZ3lRWFZEZVZSVVRrMXNOakl6YldONlpTSXNJbXAwYVNJNklqUTBOMkZsTXpnNExUZGtOVE10TkdFMllpMWhOMlE1TFdFNE1XSXpNalUzTkdRMlpTSXNJbTV2Ym1ObElqb2lXVE5XU21SWFducGlSM1JvVlhwT2NWZFZkSGRhUm14RVRVaGplbU15Um5kYVJGcFdZM3BzZVZSSVFTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakV3T1RndlkyeHBaVzUwY3k4eU5UTXhZbUZsWkRReE5qZ3lZbVprTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSnpSMjl1TmtOSFYxbHBSRmRMYmtKTmJFNUliVzlwWkhoV1pqaGxNRzlyZENJc0ltaGhibVJzWlNJNkluZHBjbVZoY0hBNkx5OGxOREJoYkdsalpWOTNhWEpsUUhkcGNtVXVZMjl0SWl3aWRHVmhiU0k2SW5kcGNtVWlmUS5JbU1ROFVWbDZnVlJ6QUFuUTlnZERUVnRJN3ZlbjJodFpOTVUwdEhianQ2dHNhdGpTT0RFLXowMFdrV1lMUC1IeWdTajVmVjlLblg2WWEzVDVsQ2lDQSIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9RaUlPZi0tcFFXbWc5T0pNd3k4eFdRITI1MzFiYWVkNDE2ODJiZmRAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.VaEksjv6j9dINbampMNc-vc-HqA0BN_v8rwsZ22HzRBa8GOEAAFlAh214PaALSfpYuXjoW69fg-HzjmLduRICg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg",
    "nonce": "cWpVck5lOVZ3elRHSXBGMG1CeUNWTHQxVk8ydVZabnQ",
    "typ": "JWT",
    "url": "https://stepca:33018/acme/wire/challenge/6SDQFoXfk1UT75qRfzurqxWCMEatapiL/5Qi9J8Jh6iP5zax2AuCyTTNMl623mcze"
  }
}
```
#### 18. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33018/acme/wire/directory>;rel="index"
link: <https://stepca:33018/acme/wire/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL>;rel="up"
location: https://stepca:33018/acme/wire/challenge/6SDQFoXfk1UT75qRfzurqxWCMEatapiL/5Qi9J8Jh6iP5zax2AuCyTTNMl623mcze
replay-nonce: R01vS1prc0UwN20zaFBJc3NicFdaWnF5Y0lhZ3RTQXc
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:33018/acme/wire/challenge/6SDQFoXfk1UT75qRfzurqxWCMEatapiL/5Qi9J8Jh6iP5zax2AuCyTTNMl623mcze",
  "status": "valid",
  "token": "sGon6CGWYiDWKnBMlNHmoidxVf8e0okt",
  "target": "http://wire.com:21098/clients/2531baed41682bfd/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 19. OAUTH authorization request

```text
code_verifier=yS1Oe590BhMH8qTWX-NLvGu2cRcDSrfXQ7aN9UURNMQ&code_challenge=4iq4Rr5qFcv88Zd4bx0tl5tmK2Rq-YBI51jHyn6WIos
```
#### 20. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:24584/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=v2yVZNyRaZQokDIRKIkS2Q&code_challenge=4iq4Rr5qFcv88Zd4bx0tl5tmK2Rq-YBI51jHyn6WIos&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A21098%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22acme_aud%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22https%3A%2F%2Fstepca%3A33018%2Facme%2Fwire%2Fchallenge%2Fd2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz%2Fy5rCMB1OJli5fp0ZWm8Ib2ZAvg1DtJmi%22%7D%2C%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22PSzmZX28YUVY5iTIfDehT2oF8HERQWDt.Rvg9taZvH6Wq_i03xkLWAupJLgBBaNvqltQnUnzTU74%22%7D%7D%7D&nonce=sGcGkDWQT1DI2NyEGRq-NA
```

#### 21. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:24584/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=05e94885-441c-4df9-b47d-334b8c6a3501.63644a37-ecf1-4ebd-b626-13ca8d5da3cf.5e2f498e-d2c5-4403-8bc4-158eebb10c77&code_verifier=yS1Oe590BhMH8qTWX-NLvGu2cRcDSrfXQ7aN9UURNMQ&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A21098%2Fcallback
```
#### 22. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItSU0xR2FRYmtaZXlNOTRHYXZCMURpQUlnM3NfV0hOUWhDekxWeDVraE9nIn0.eyJleHAiOjE3MDU2NzgyNDksImlhdCI6MTcwNTY3ODE4OSwiYXV0aF90aW1lIjoxNzA1Njc4MTg5LCJqdGkiOiJjYjM3OWM3NC0wOWZiLTRmNmUtYWRiNi1hMzU1ZmEwY2UxMTIiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJjZTUzNjY0Yi05ZWI1LTQ3ZmQtYjM1OS1mODFkNGZmZDg2YmMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJzR2NHa0RXUVQxREkyTnlFR1JxLU5BIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNjQ0YTM3LWVjZjEtNGViZC1iNjI2LTEzY2E4ZDVkYTNjZiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjIxMDk4Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2MjYtMTNjYThkNWRhM2NmIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.mxtA84L-3uFYQKrQtwLA9N-lMiikQ_AouiHC2ju089w4Iz1vmaREurzamCkE3YBu9wZbuxDXa9gQN5-u9q7A_sxOnExt_Refbkuh8gjKJ2N8lEz3BzKPqikZk1oZtwhPFrSqE2Mzw50sfBBkcK2vUet9aGAiQyrlDi8d2kAseKVnm3wnIH9MUD7Yg2X-TR5xVN9HdcrCv0I4UaxiHTJr8n9f0KmLyHS5B-nzW9X00SKuIPhCmMK9Bcv0j-DleRowKu8zZWEwe-5wbBpO5m5BZ_avJ-V4XlFnGJODawgGqaYSDnL4Ge81owIfQrPFXfOp2PthgfxlnBKvVpA3ILMDZw",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItSU0xR2FRYmtaZXlNOTRHYXZCMURpQUlnM3NfV0hOUWhDekxWeDVraE9nIn0.eyJleHAiOjE3MDU2NzgyNDksImlhdCI6MTcwNTY3ODE4OSwiYXV0aF90aW1lIjoxNzA1Njc4MTg5LCJqdGkiOiJlNTJiMDc3Yy04Njc2LTQxOWQtYWYyNC1kNTYwMWRlODU2ZWMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJjZTUzNjY0Yi05ZWI1LTQ3ZmQtYjM1OS1mODFkNGZmZDg2YmMiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6InNHY0drRFdRVDFESTJOeUVHUnEtTkEiLCJzZXNzaW9uX3N0YXRlIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2MjYtMTNjYThkNWRhM2NmIiwiYXRfaGFzaCI6InV4QXB1WUVLQTBCMVpVX0FUOTJSLUEiLCJhY3IiOiIxIiwic2lkIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2MjYtMTNjYThkNWRhM2NmIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMzAxOC9hY21lL3dpcmUvY2hhbGxlbmdlL2Qyc0p5TTBNYVY2d1RYNENsUDhlVVE4VEY0WktrN2p6L3k1ckNNQjFPSmxpNWZwMFpXbThJYjJaQXZnMUR0Sm1pIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwia2V5YXV0aCI6IlBTem1aWDI4WVVWWTVpVElmRGVoVDJvRjhIRVJRV0R0LlJ2Zzl0YVp2SDZXcV9pMDN4a0xXQXVwSkxnQkJhTnZxbHRRblVuelRVNzQiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.id6SF_kqeODIHmKBrybunpdXpDshxjLK_Hl1HIyYBkJ9yRfsI6pH0h2B4pKrKdBuXvZ6HljuEe8C78OTZZ38wM6nWNdth-Ff7Bij_iIc__kVPrxfrWS7riNr1g33PWzqSK1kEU7TmTjpdHnC7K5eNQR3Rr91yd5NEBfcd0MutC7Y_2PFXwT2gLD3C2dNy0YykCwDiVEq90W9WTJ0WTLj1MOYNuz8TEC3zQtDRNP2xdHIKEe9LY1OUQGbjLP7ftzPAK44DtFjflhrZxg4kGtADdIc5fFnhmquoGZz-AFUyaZg46sTHfa9-0IC7ignJkGLarpfDhrC5dHREt5pxM0KbQ",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3NmJmNjkyNC02ZDljLTRhODctOTY1Zi0zNmI3NTY0OWMwOGQifQ.eyJleHAiOjE3MDU2Nzk5ODksImlhdCI6MTcwNTY3ODE4OSwianRpIjoiMWUyZDE3MjAtZGNkNS00YmU0LWI1NzAtYTNmNDQyYzgwMTViIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjI0NTg0L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc3RlciIsInN1YiI6ImNlNTM2NjRiLTllYjUtNDdmZC1iMzU5LWY4MWQ0ZmZkODZiYyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJzR2NHa0RXUVQxREkyTnlFR1JxLU5BIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNjQ0YTM3LWVjZjEtNGViZC1iNjI2LTEzY2E4ZDVkYTNjZiIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI2MzY0NGEzNy1lY2YxLTRlYmQtYjYyNi0xM2NhOGQ1ZGEzY2YifQ.wLCZke0jnORr0yDOrRwKet_a22lXzm4j8G-mmqLU7Rk",
  "scope": "openid profile email",
  "session_state": "63644a37-ecf1-4ebd-b626-13ca8d5da3cf",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItSU0xR2FRYmtaZXlNOTRHYXZCMURpQUlnM3NfV0hOUWhDekxWeDVraE9nIn0.eyJleHAiOjE3MDU2NzgyNDksImlhdCI6MTcwNTY3ODE4OSwiYXV0aF90aW1lIjoxNzA1Njc4MTg5LCJqdGkiOiJjYjM3OWM3NC0wOWZiLTRmNmUtYWRiNi1hMzU1ZmEwY2UxMTIiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJjZTUzNjY0Yi05ZWI1LTQ3ZmQtYjM1OS1mODFkNGZmZDg2YmMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJzR2NHa0RXUVQxREkyTnlFR1JxLU5BIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNjQ0YTM3LWVjZjEtNGViZC1iNjI2LTEzY2E4ZDVkYTNjZiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjIxMDk4Il0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic2lkIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2MjYtMTNjYThkNWRhM2NmIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.mxtA84L-3uFYQKrQtwLA9N-lMiikQ_AouiHC2ju089w4Iz1vmaREurzamCkE3YBu9wZbuxDXa9gQN5-u9q7A_sxOnExt_Refbkuh8gjKJ2N8lEz3BzKPqikZk1oZtwhPFrSqE2Mzw50sfBBkcK2vUet9aGAiQyrlDi8d2kAseKVnm3wnIH9MUD7Yg2X-TR5xVN9HdcrCv0I4UaxiHTJr8n9f0KmLyHS5B-nzW9X00SKuIPhCmMK9Bcv0j-DleRowKu8zZWEwe-5wbBpO5m5BZ_avJ-V4XlFnGJODawgGqaYSDnL4Ge81owIfQrPFXfOp2PthgfxlnBKvVpA3ILMDZw)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItSU0xR2FRYmta
ZXlNOTRHYXZCMURpQUlnM3NfV0hOUWhDekxWeDVraE9nIn0.eyJleHAiOjE3MDU2
NzgyNDksImlhdCI6MTcwNTY3ODE4OSwiYXV0aF90aW1lIjoxNzA1Njc4MTg5LCJq
dGkiOiJjYjM3OWM3NC0wOWZiLTRmNmUtYWRiNi1hMzU1ZmEwY2UxMTIiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiJjZTUzNjY0Yi05ZWI1LTQ3ZmQtYjM1OS1mODFkNGZmZDg2
YmMiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJzR2NH
a0RXUVQxREkyTnlFR1JxLU5BIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNjQ0YTM3LWVj
ZjEtNGViZC1iNjI2LTEzY2E4ZDVkYTNjZiIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjIxMDk4Il0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBwcm9maWxl
IGVtYWlsIiwic2lkIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2MjYtMTNjYThkNWRh
M2NmIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdp
cmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0
aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.mxtA84L-3uFYQKrQtwL
A9N-lMiikQ_AouiHC2ju089w4Iz1vmaREurzamCkE3YBu9wZbuxDXa9gQN5-u9q7
A_sxOnExt_Refbkuh8gjKJ2N8lEz3BzKPqikZk1oZtwhPFrSqE2Mzw50sfBBkcK2
vUet9aGAiQyrlDi8d2kAseKVnm3wnIH9MUD7Yg2X-TR5xVN9HdcrCv0I4UaxiHTJ
r8n9f0KmLyHS5B-nzW9X00SKuIPhCmMK9Bcv0j-DleRowKu8zZWEwe-5wbBpO5m5
BZ_avJ-V4XlFnGJODawgGqaYSDnL4Ge81owIfQrPFXfOp2PthgfxlnBKvVpA3ILM
DZw
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "-IM1GaQbkZeyM94GavB1DiAIg3s_WHNQhCzLVx5khOg",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:21098"
  ],
  "aud": "account",
  "auth_time": 1705678189,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1705678249,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1705678189,
  "iss": "http://keycloak:24584/realms/master",
  "jti": "cb379c74-09fb-4f6e-adb6-a355fa0ce112",
  "name": "Alice Smith",
  "nonce": "sGcGkDWQT1DI2NyEGRq-NA",
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
  "scope": "openid profile email",
  "session_state": "63644a37-ecf1-4ebd-b626-13ca8d5da3cf",
  "sid": "63644a37-ecf1-4ebd-b626-13ca8d5da3cf",
  "sub": "ce53664b-9eb5-47fd-b359-f81d4ffd86bc",
  "typ": "Bearer"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtemy+UDgnomX6OOF8Z4O
11Bkcq0Nxf/jNiYwZkyT5olIYQT7kSWtQwtemUjFJGy2/XM2/qHCYmFvadOzql/h
D9wpfYE17Kw7lf3lu30B6glIAoXqZzEsfCoLYxS0tHDd73SPnAPgQjk8oEhLpnSh
gJuXcC5y93Z8vcJIz3HqHAjmbMOgbEgC12v3jSiDjUKOFgRJZjNkdFM5AZEt3UCi
OvKJt29TMAx9NYPY02Af7gFKc5w6zymjsrE0VStFNV6AQ1S3bmIRYoBIuzPX+oYL
ySFK1TsU2Oj8yRNxKb0MXHNavdBE/is5m6I6vZp1ImI/Lrkn4g6zjjKPAtuSXDCH
fQIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3NmJmNjkyNC02ZDljLTRhODctOTY1Zi0zNmI3NTY0OWMwOGQifQ.eyJleHAiOjE3MDU2Nzk5ODksImlhdCI6MTcwNTY3ODE4OSwianRpIjoiMWUyZDE3MjAtZGNkNS00YmU0LWI1NzAtYTNmNDQyYzgwMTViIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjI0NTg0L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc3RlciIsInN1YiI6ImNlNTM2NjRiLTllYjUtNDdmZC1iMzU5LWY4MWQ0ZmZkODZiYyIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJzR2NHa0RXUVQxREkyTnlFR1JxLU5BIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNjQ0YTM3LWVjZjEtNGViZC1iNjI2LTEzY2E4ZDVkYTNjZiIsInNjb3BlIjoib3BlbmlkIHByb2ZpbGUgZW1haWwiLCJzaWQiOiI2MzY0NGEzNy1lY2YxLTRlYmQtYjYyNi0xM2NhOGQ1ZGEzY2YifQ.wLCZke0jnORr0yDOrRwKet_a22lXzm4j8G-mmqLU7Rk)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICI3NmJmNjkyNC02
ZDljLTRhODctOTY1Zi0zNmI3NTY0OWMwOGQifQ.eyJleHAiOjE3MDU2Nzk5ODksI
mlhdCI6MTcwNTY3ODE4OSwianRpIjoiMWUyZDE3MjAtZGNkNS00YmU0LWI1NzAtY
TNmNDQyYzgwMTViIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjI0NTg0L3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc
3RlciIsInN1YiI6ImNlNTM2NjRiLTllYjUtNDdmZC1iMzU5LWY4MWQ0ZmZkODZiY
yIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiJzR2NHa
0RXUVQxREkyTnlFR1JxLU5BIiwic2Vzc2lvbl9zdGF0ZSI6IjYzNjQ0YTM3LWVjZ
jEtNGViZC1iNjI2LTEzY2E4ZDVkYTNjZiIsInNjb3BlIjoib3BlbmlkIHByb2Zpb
GUgZW1haWwiLCJzaWQiOiI2MzY0NGEzNy1lY2YxLTRlYmQtYjYyNi0xM2NhOGQ1Z
GEzY2YifQ.wLCZke0jnORr0yDOrRwKet_a22lXzm4j8G-mmqLU7Rk
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "76bf6924-6d9c-4a87-965f-36b75649c08d",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:24584/realms/master",
  "azp": "wireapp",
  "exp": 1705679989,
  "iat": 1705678189,
  "iss": "http://keycloak:24584/realms/master",
  "jti": "1e2d1720-dcd5-4be4-b570-a3f442c8015b",
  "nonce": "sGcGkDWQT1DI2NyEGRq-NA",
  "scope": "openid profile email",
  "session_state": "63644a37-ecf1-4ebd-b626-13ca8d5da3cf",
  "sid": "63644a37-ecf1-4ebd-b626-13ca8d5da3cf",
  "sub": "ce53664b-9eb5-47fd-b359-f81d4ffd86bc",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtemy+UDgnomX6OOF8Z4O
11Bkcq0Nxf/jNiYwZkyT5olIYQT7kSWtQwtemUjFJGy2/XM2/qHCYmFvadOzql/h
D9wpfYE17Kw7lf3lu30B6glIAoXqZzEsfCoLYxS0tHDd73SPnAPgQjk8oEhLpnSh
gJuXcC5y93Z8vcJIz3HqHAjmbMOgbEgC12v3jSiDjUKOFgRJZjNkdFM5AZEt3UCi
OvKJt29TMAx9NYPY02Af7gFKc5w6zymjsrE0VStFNV6AQ1S3bmIRYoBIuzPX+oYL
ySFK1TsU2Oj8yRNxKb0MXHNavdBE/is5m6I6vZp1ImI/Lrkn4g6zjjKPAtuSXDCH
fQIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 23. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItSU0xR2FRYmtaZXlNOTRHYXZCMURpQUlnM3NfV0hOUWhDekxWeDVraE9nIn0.eyJleHAiOjE3MDU2NzgyNDksImlhdCI6MTcwNTY3ODE4OSwiYXV0aF90aW1lIjoxNzA1Njc4MTg5LCJqdGkiOiJlNTJiMDc3Yy04Njc2LTQxOWQtYWYyNC1kNTYwMWRlODU2ZWMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJjZTUzNjY0Yi05ZWI1LTQ3ZmQtYjM1OS1mODFkNGZmZDg2YmMiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6InNHY0drRFdRVDFESTJOeUVHUnEtTkEiLCJzZXNzaW9uX3N0YXRlIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2MjYtMTNjYThkNWRhM2NmIiwiYXRfaGFzaCI6InV4QXB1WUVLQTBCMVpVX0FUOTJSLUEiLCJhY3IiOiIxIiwic2lkIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2MjYtMTNjYThkNWRhM2NmIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMzAxOC9hY21lL3dpcmUvY2hhbGxlbmdlL2Qyc0p5TTBNYVY2d1RYNENsUDhlVVE4VEY0WktrN2p6L3k1ckNNQjFPSmxpNWZwMFpXbThJYjJaQXZnMUR0Sm1pIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwia2V5YXV0aCI6IlBTem1aWDI4WVVWWTVpVElmRGVoVDJvRjhIRVJRV0R0LlJ2Zzl0YVp2SDZXcV9pMDN4a0xXQXVwSkxnQkJhTnZxbHRRblVuelRVNzQiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.id6SF_kqeODIHmKBrybunpdXpDshxjLK_Hl1HIyYBkJ9yRfsI6pH0h2B4pKrKdBuXvZ6HljuEe8C78OTZZ38wM6nWNdth-Ff7Bij_iIc__kVPrxfrWS7riNr1g33PWzqSK1kEU7TmTjpdHnC7K5eNQR3Rr91yd5NEBfcd0MutC7Y_2PFXwT2gLD3C2dNy0YykCwDiVEq90W9WTJ0WTLj1MOYNuz8TEC3zQtDRNP2xdHIKEe9LY1OUQGbjLP7ftzPAK44DtFjflhrZxg4kGtADdIc5fFnhmquoGZz-AFUyaZg46sTHfa9-0IC7ignJkGLarpfDhrC5dHREt5pxM0KbQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItSU0xR2FRYmta
ZXlNOTRHYXZCMURpQUlnM3NfV0hOUWhDekxWeDVraE9nIn0.eyJleHAiOjE3MDU2
NzgyNDksImlhdCI6MTcwNTY3ODE4OSwiYXV0aF90aW1lIjoxNzA1Njc4MTg5LCJq
dGkiOiJlNTJiMDc3Yy04Njc2LTQxOWQtYWYyNC1kNTYwMWRlODU2ZWMiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiJjZTUzNjY0Yi05ZWI1LTQ3ZmQtYjM1OS1mODFkNGZmZDg2
YmMiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6InNHY0drRFdR
VDFESTJOeUVHUnEtTkEiLCJzZXNzaW9uX3N0YXRlIjoiNjM2NDRhMzctZWNmMS00
ZWJkLWI2MjYtMTNjYThkNWRhM2NmIiwiYXRfaGFzaCI6InV4QXB1WUVLQTBCMVpV
X0FUOTJSLUEiLCJhY3IiOiIxIiwic2lkIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2
MjYtMTNjYThkNWRhM2NmIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBh
bGljZV93aXJlQHdpcmUuY29tIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYToz
MzAxOC9hY21lL3dpcmUvY2hhbGxlbmdlL2Qyc0p5TTBNYVY2d1RYNENsUDhlVVE4
VEY0WktrN2p6L3k1ckNNQjFPSmxpNWZwMFpXbThJYjJaQXZnMUR0Sm1pIiwiZ2l2
ZW5fbmFtZSI6IkFsaWNlIiwia2V5YXV0aCI6IlBTem1aWDI4WVVWWTVpVElmRGVo
VDJvRjhIRVJRV0R0LlJ2Zzl0YVp2SDZXcV9pMDN4a0xXQXVwSkxnQkJhTnZxbHRR
blVuelRVNzQiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNt
aXRoQHdpcmUuY29tIn0.id6SF_kqeODIHmKBrybunpdXpDshxjLK_Hl1HIyYBkJ9
yRfsI6pH0h2B4pKrKdBuXvZ6HljuEe8C78OTZZ38wM6nWNdth-Ff7Bij_iIc__kV
PrxfrWS7riNr1g33PWzqSK1kEU7TmTjpdHnC7K5eNQR3Rr91yd5NEBfcd0MutC7Y
_2PFXwT2gLD3C2dNy0YykCwDiVEq90W9WTJ0WTLj1MOYNuz8TEC3zQtDRNP2xdHI
KEe9LY1OUQGbjLP7ftzPAK44DtFjflhrZxg4kGtADdIc5fFnhmquoGZz-AFUyaZg
46sTHfa9-0IC7ignJkGLarpfDhrC5dHREt5pxM0KbQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "-IM1GaQbkZeyM94GavB1DiAIg3s_WHNQhCzLVx5khOg",
  "typ": "JWT"
}
```

```json
{
  "acme_aud": "https://stepca:33018/acme/wire/challenge/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz/y5rCMB1OJli5fp0ZWm8Ib2ZAvg1DtJmi",
  "acr": "1",
  "at_hash": "uxApuYEKA0B1ZU_AT92R-A",
  "aud": "wireapp",
  "auth_time": 1705678189,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1705678249,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1705678189,
  "iss": "http://keycloak:24584/realms/master",
  "jti": "e52b077c-8676-419d-af24-d5601de856ec",
  "keyauth": "PSzmZX28YUVY5iTIfDehT2oF8HERQWDt.Rvg9taZvH6Wq_i03xkLWAupJLgBBaNvqltQnUnzTU74",
  "name": "Alice Smith",
  "nonce": "sGcGkDWQT1DI2NyEGRq-NA",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "session_state": "63644a37-ecf1-4ebd-b626-13ca8d5da3cf",
  "sid": "63644a37-ecf1-4ebd-b626-13ca8d5da3cf",
  "sub": "ce53664b-9eb5-47fd-b359-f81d4ffd86bc",
  "typ": "ID"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtemy+UDgnomX6OOF8Z4O
11Bkcq0Nxf/jNiYwZkyT5olIYQT7kSWtQwtemUjFJGy2/XM2/qHCYmFvadOzql/h
D9wpfYE17Kw7lf3lu30B6glIAoXqZzEsfCoLYxS0tHDd73SPnAPgQjk8oEhLpnSh
gJuXcC5y93Z8vcJIz3HqHAjmbMOgbEgC12v3jSiDjUKOFgRJZjNkdFM5AZEt3UCi
OvKJt29TMAx9NYPY02Af7gFKc5w6zymjsrE0VStFNV6AQ1S3bmIRYoBIuzPX+oYL
ySFK1TsU2Oj8yRNxKb0MXHNavdBE/is5m6I6vZp1ImI/Lrkn4g6zjjKPAtuSXDCH
fQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:33018/acme/wire/challenge/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz/y5rCMB1OJli5fp0ZWm8Ib2ZAvg1DtJmi
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDE4L2FjbWUvd2lyZS9hY2NvdW50L0E2YWtSQ09XMTZxNlRiU3Ewb0pXR2pzZjFsdWVHbmdnIiwidHlwIjoiSldUIiwibm9uY2UiOiJSMDF2UzFwcmMwVXdOMjB6YUZCSmMzTmljRmRhV25GNVkwbGhaM1JUUVhjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL2NoYWxsZW5nZS9kMnNKeU0wTWFWNndUWDRDbFA4ZVVROFRGNFpLazdqei95NXJDTUIxT0psaTVmcDBaV204SWIyWkF2ZzFEdEptaSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSXRTVTB4UjJGUlltdGFaWGxOT1RSSFlYWkNNVVJwUVVsbk0zTmZWMGhPVVdoRGVreFdlRFZyYUU5bkluMC5leUpsZUhBaU9qRTNNRFUyTnpneU5Ea3NJbWxoZENJNk1UY3dOVFkzT0RFNE9Td2lZWFYwYUY5MGFXMWxJam94TnpBMU5qYzRNVGc1TENKcWRHa2lPaUpsTlRKaU1EYzNZeTA0TmpjMkxUUXhPV1F0WVdZeU5DMWtOVFl3TVdSbE9EVTJaV01pTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNalExT0RRdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSmpaVFV6TmpZMFlpMDVaV0kxTFRRM1ptUXRZak0xT1MxbU9ERmtOR1ptWkRnMlltTWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJbk5IWTBkclJGZFJWREZFU1RKT2VVVkhVbkV0VGtFaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaU5qTTJORFJoTXpjdFpXTm1NUzAwWldKa0xXSTJNall0TVROallUaGtOV1JoTTJObUlpd2lZWFJmYUdGemFDSTZJblY0UVhCMVdVVkxRVEJDTVZwVlgwRlVPVEpTTFVFaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaU5qTTJORFJoTXpjdFpXTm1NUzAwWldKa0xXSTJNall0TVROallUaGtOV1JoTTJObUlpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lZV050WlY5aGRXUWlPaUpvZEhSd2N6b3ZMM04wWlhCallUb3pNekF4T0M5aFkyMWxMM2RwY21VdlkyaGhiR3hsYm1kbEwyUXljMHA1VFRCTllWWTJkMVJZTkVOc1VEaGxWVkU0VkVZMFdrdHJOMnA2TDNrMWNrTk5RakZQU214cE5XWndNRnBYYlRoSllqSmFRWFpuTVVSMFNtMXBJaXdpWjJsMlpXNWZibUZ0WlNJNklrRnNhV05sSWl3aWEyVjVZWFYwYUNJNklsQlRlbTFhV0RJNFdWVldXVFZwVkVsbVJHVm9WREp2UmpoSVJWSlJWMFIwTGxKMlp6bDBZVnAyU0RaWGNWOXBNRE40YTB4WFFYVndTa3huUWtKaFRuWnhiSFJSYmxWdWVsUlZOelFpTENKbVlXMXBiSGxmYm1GdFpTSTZJbE50YVhSb0lpd2laVzFoYVd3aU9pSmhiR2xqWlhOdGFYUm9RSGRwY21VdVkyOXRJbjAuaWQ2U0Zfa3FlT0RJSG1LQnJ5YnVucGRYcERzaHhqTEtfSGwxSEl5WUJrSjl5UmZzSTZwSDBoMkI0cEtyS2RCdVh2WjZIbGp1RWU4Qzc4T1RaWjM4d002bldOZHRoLUZmN0Jpal9pSWNfX2tWUHJ4ZnJXUzdyaU5yMWczM1BXenFTSzFrRVU3VG1UanBkSG5DN0s1ZU5RUjNScjkxeWQ1TkVCZmNkME11dEM3WV8yUEZYd1QyZ0xEM0MyZE55MFl5a0N3RGlWRXE5MFc5V1RKMFdUTGoxTU9ZTnV6OFRFQzN6UXREUk5QMnhkSElLRWU5TFkxT1VRR2JqTFA3ZnR6UEFLNDREdEZqZmxoclp4ZzRrR3RBRGRJYzVmRm5obXF1b0daei1BRlV5YVpnNDZzVEhmYTktMElDN2lnbkprR0xhcnBmRGhyQzVkSFJFdDVweE0wS2JRIn0",
  "signature": "eAdoIKcGQQLytP6B_C_wyPXbv_ybKdc0odq7K1TWKPrh-FxADjg3mirTqEErvZZZSaWrM9_wqJ7JiK7GUP8wAQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICItSU0xR2FRYmtaZXlNOTRHYXZCMURpQUlnM3NfV0hOUWhDekxWeDVraE9nIn0.eyJleHAiOjE3MDU2NzgyNDksImlhdCI6MTcwNTY3ODE4OSwiYXV0aF90aW1lIjoxNzA1Njc4MTg5LCJqdGkiOiJlNTJiMDc3Yy04Njc2LTQxOWQtYWYyNC1kNTYwMWRlODU2ZWMiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjQ1ODQvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJjZTUzNjY0Yi05ZWI1LTQ3ZmQtYjM1OS1mODFkNGZmZDg2YmMiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6InNHY0drRFdRVDFESTJOeUVHUnEtTkEiLCJzZXNzaW9uX3N0YXRlIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2MjYtMTNjYThkNWRhM2NmIiwiYXRfaGFzaCI6InV4QXB1WUVLQTBCMVpVX0FUOTJSLUEiLCJhY3IiOiIxIiwic2lkIjoiNjM2NDRhMzctZWNmMS00ZWJkLWI2MjYtMTNjYThkNWRhM2NmIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiYWNtZV9hdWQiOiJodHRwczovL3N0ZXBjYTozMzAxOC9hY21lL3dpcmUvY2hhbGxlbmdlL2Qyc0p5TTBNYVY2d1RYNENsUDhlVVE4VEY0WktrN2p6L3k1ckNNQjFPSmxpNWZwMFpXbThJYjJaQXZnMUR0Sm1pIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwia2V5YXV0aCI6IlBTem1aWDI4WVVWWTVpVElmRGVoVDJvRjhIRVJRV0R0LlJ2Zzl0YVp2SDZXcV9pMDN4a0xXQXVwSkxnQkJhTnZxbHRRblVuelRVNzQiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.id6SF_kqeODIHmKBrybunpdXpDshxjLK_Hl1HIyYBkJ9yRfsI6pH0h2B4pKrKdBuXvZ6HljuEe8C78OTZZ38wM6nWNdth-Ff7Bij_iIc__kVPrxfrWS7riNr1g33PWzqSK1kEU7TmTjpdHnC7K5eNQR3Rr91yd5NEBfcd0MutC7Y_2PFXwT2gLD3C2dNy0YykCwDiVEq90W9WTJ0WTLj1MOYNuz8TEC3zQtDRNP2xdHIKEe9LY1OUQGbjLP7ftzPAK44DtFjflhrZxg4kGtADdIc5fFnhmquoGZz-AFUyaZg46sTHfa9-0IC7ignJkGLarpfDhrC5dHREt5pxM0KbQ"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg",
    "nonce": "R01vS1prc0UwN20zaFBJc3NicFdaWnF5Y0lhZ3RTQXc",
    "typ": "JWT",
    "url": "https://stepca:33018/acme/wire/challenge/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz/y5rCMB1OJli5fp0ZWm8Ib2ZAvg1DtJmi"
  }
}
```
#### 24. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33018/acme/wire/directory>;rel="index"
link: <https://stepca:33018/acme/wire/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz>;rel="up"
location: https://stepca:33018/acme/wire/challenge/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz/y5rCMB1OJli5fp0ZWm8Ib2ZAvg1DtJmi
replay-nonce: UkF2QVJmbFhpNjdzNUFGVnFWZjN6ZG9vU2FzVGRQNjE
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:33018/acme/wire/challenge/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz/y5rCMB1OJli5fp0ZWm8Ib2ZAvg1DtJmi",
  "status": "valid",
  "token": "PSzmZX28YUVY5iTIfDehT2oF8HERQWDt",
  "target": "http://keycloak:24584/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 25. verify the status of the order
```http request
POST https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDE4L2FjbWUvd2lyZS9hY2NvdW50L0E2YWtSQ09XMTZxNlRiU3Ewb0pXR2pzZjFsdWVHbmdnIiwidHlwIjoiSldUIiwibm9uY2UiOiJVa0YyUVZKbWJGaHBOamR6TlVGR1ZuRldaak42Wkc5dlUyRnpWR1JRTmpFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL29yZGVyLzFmOFF5YUpSNE53bFFxbFZOWjFNOGV2Qm5aZGpBb0dCIn0",
  "payload": "",
  "signature": "v-jYjomhrPtDIzUTrOtnWTbaPpMV9GnEIi0lg537hMiITUTIkNtVZqPapozeAkdI1si8PJOo4nPytqd4dX23Ag"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg",
    "nonce": "UkF2QVJmbFhpNjdzNUFGVnFWZjN6ZG9vU2FzVGRQNjE",
    "typ": "JWT",
    "url": "https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB"
  }
}
```
#### 26. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33018/acme/wire/directory>;rel="index"
location: https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB
replay-nonce: T29Jd3JxdnBDdDlEbmVIc3Fpb1pZMndCWk4zSUVRaXY
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://QiIOf--pQWmg9OJMwy8xWQ!2531baed41682bfd@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33018/acme/wire/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
    "https://stepca:33018/acme/wire/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
  ],
  "expires": "2024-01-20T15:29:49Z",
  "notBefore": "2024-01-19T15:29:49.447105Z",
  "notAfter": "2034-01-16T15:29:49.447105Z"
}
```
#### 27. create a CSR and call finalize url
```http request
POST https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDE4L2FjbWUvd2lyZS9hY2NvdW50L0E2YWtSQ09XMTZxNlRiU3Ewb0pXR2pzZjFsdWVHbmdnIiwidHlwIjoiSldUIiwibm9uY2UiOiJUMjlKZDNKeGRuQkRkRGxFYm1WSWMzRnBiMXBaTW5kQ1drNHpTVVZSYVhZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL29yZGVyLzFmOFF5YUpSNE53bFFxbFZOWjFNOGV2Qm5aZGpBb0dCL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBTkRfWXhuVGpuV2FLSGQzcHpsdkxNSmJWbTNLelJuQ2pFOWdIelkyX2NLTW9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2VVdsSlQyWXRMWEJSVjIxbk9VOUtUWGQ1T0hoWFVTRXlOVE14WW1GbFpEUXhOamd5WW1aa1FIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFBY0FkRTlQb19YSUhWNHY4b29JY2pnbGNBVmZ2RE5INlV2eXR1cmc0MTNLRlVwYU5keWZxRTZ0X3EzX1d3VWhUZXk4YlVwcHRKSzRzS1FGSnlncVg4SCJ9",
  "signature": "_EbDwGRJBPcuox7zDcdPZkIbZZnxaouY3RHQzaeZ51xAbjBcMbNHDK4MITKccUafN_XfsxA-x4h-QETUm2LOAw"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAND_YxnTjnWaKHd3pzlvLMJbVm3KzRnCjE9gHzY2_cKMoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vUWlJT2YtLXBRV21nOU9KTXd5OHhXUSEyNTMxYmFlZDQxNjgyYmZkQHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQAcAdE9Po_XIHV4v8ooIcjglcAVfvDNH6Uvyturg413KFUpaNdyfqE6t_q3_WwUhTey8bUpptJK4sKQFJygqX8H"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg",
    "nonce": "T29Jd3JxdnBDdDlEbmVIc3Fpb1pZMndCWk4zSUVRaXY",
    "typ": "JWT",
    "url": "https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAND/YxnTjnWaKHd3pzlvLMJbVm3KzRnC
jE9gHzY2/cKMoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vUWlJT2YtLXBRV21nOU9KTXd5OHhXUSEyNTMxYmFlZDQxNjgyYmZkQHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQAc
AdE9Po/XIHV4v8ooIcjglcAVfvDNH6Uvyturg413KFUpaNdyfqE6t/q3/WwUhTey
8bUpptJK4sKQFJygqX8H
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
                    d0:ff:63:19:d3:8e:75:9a:28:77:77:a7:39:6f:2c:
                    c2:5b:56:6d:ca:cd:19:c2:8c:4f:60:1f:36:36:fd:
                    c2:8c
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://QiIOf--pQWmg9OJMwy8xWQ!2531baed41682bfd@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        1c:01:d1:3d:3e:8f:d7:20:75:78:bf:ca:28:21:c8:e0:95:c0:
        15:7e:f0:cd:1f:a5:2f:ca:db:ab:83:8d:77:28:55:29:68:d7:
        72:7e:a1:3a:b7:fa:b7:fd:6c:14:85:37:b2:f1:b5:29:a6:d2:
        4a:e2:c2:90:14:9c:a0:a9:7f:07

```

#### 28. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33018/acme/wire/directory>;rel="index"
location: https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB
replay-nonce: ZHk5RGh3WExNUUU4NlI1TnR3aVl6T3d3VUxia1hWeDg
```
```json
{
  "certificate": "https://stepca:33018/acme/wire/certificate/vyVCpvP32HaBPX6IqOrUcq7rFYVHhthx",
  "status": "valid",
  "finalize": "https://stepca:33018/acme/wire/order/1f8QyaJR4NwlQqlVNZ1M8evBnZdjAoGB/finalize",
  "identifiers": [
    {
      "type": "wireapp-device",
      "value": "{\"client-id\":\"wireapp://QiIOf--pQWmg9OJMwy8xWQ!2531baed41682bfd@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    },
    {
      "type": "wireapp-user",
      "value": "{\"handle\":\"wireapp://%40alice_wire@wire.com\",\"name\":\"Alice Smith\",\"domain\":\"wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33018/acme/wire/authz/6SDQFoXfk1UT75qRfzurqxWCMEatapiL",
    "https://stepca:33018/acme/wire/authz/d2sJyM0MaV6wTX4ClP8eUQ8TF4ZKk7jz"
  ],
  "expires": "2024-01-20T15:29:49Z",
  "notBefore": "2024-01-19T15:29:49.447105Z",
  "notAfter": "2034-01-16T15:29:49.447105Z"
}
```
#### 29. fetch the certificate
```http request
POST https://stepca:33018/acme/wire/certificate/vyVCpvP32HaBPX6IqOrUcq7rFYVHhthx
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMDE4L2FjbWUvd2lyZS9hY2NvdW50L0E2YWtSQ09XMTZxNlRiU3Ewb0pXR2pzZjFsdWVHbmdnIiwidHlwIjoiSldUIiwibm9uY2UiOiJaSGs1UkdoM1dFeE5VVVU0TmxJMVRuUjNhVmw2VDNkM1ZVeGlhMWhXZURnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMwMTgvYWNtZS93aXJlL2NlcnRpZmljYXRlL3Z5VkNwdlAzMkhhQlBYNklxT3JVY3E3ckZZVkhodGh4In0",
  "payload": "",
  "signature": "jgT8R0BA2tbiDI5700FwmKgCunL7jFPi-anLQVJeFjX4GwMO6mv4osqk_jv3YCjOkgD0ig5yAtTk4NKPdNhKDA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33018/acme/wire/account/A6akRCOW16q6TbSq0oJWGjsf1lueGngg",
    "nonce": "ZHk5RGh3WExNUUU4NlI1TnR3aVl6T3d3VUxia1hWeDg",
    "typ": "JWT",
    "url": "https://stepca:33018/acme/wire/certificate/vyVCpvP32HaBPX6IqOrUcq7rFYVHhthx"
  }
}
```
#### 30. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:33018/acme/wire/directory>;rel="index"
replay-nonce: NGxUeXVtam54aUZTQXZaS3hlbmhvQ2I4dmVLTXE3eHY
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAcCgAwIBAgIRAPRZ6CzItvqHUQSjksqGO5AwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMTE5MTUyOTQ5WhcNMzQwMTE2MTUyOTQ5WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDQ/2MZ0451mih3d6c5\nbyzCW1Ztys0ZwoxPYB82Nv3CjKOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFJRYvitW9A4bZGkuZg+Cb9pbhT3QMB8G\nA1UdIwQYMBaAFNlwQ3HjkfVm3x7JxMFcbcYIo1dEMGkGA1UdEQRiMGCGIHdpcmVh\ncHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vUWlJT2YtLXBR\nV21nOU9KTXd5OHhXUSUyMTI1MzFiYWVkNDE2ODJiZmRAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQCpQ9aJ\n7Wx/4cUiM6SgGBjd4nfV8EOrn+iwvVQ0E3d+9wIgdvxWTUO1+Jm/ftyniTDwksQr\nUcGIAI1VwXbN4OIq4Cs=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV+gAwIBAgIRAJU8li0pDGrQFZaVLzX9iOwwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExOTE1\nMjk0N1oXDTM0MDExNjE1Mjk0N1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATo\nBl5AgdzHN3hbH5GE8xGTIbkPcrf9s8BYT+3FZqFGAuy42+lemjE8VYqAot9YB9TF\nXiCBL2jE+Yo/HbcDu560o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQU2XBDceOR9WbfHsnEwVxtxgijV0QwHwYDVR0jBBgw\nFoAUu9oOE0btvBTQFKwXdidFqcNJ6uMwCgYIKoZIzj0EAwIDRwAwRAIgWy81Z+Uk\n15N4aaW/5oK9SO75wZzEsTW13VLSEnmR5sACICaYFQ3icM9lJ1fY+FN2tyrT32M3\n4NS+krymuaMtXu5P\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRAPRZ6CzItvqHUQSjksqGO5AwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMTE5MTUyOTQ5WhcNMzQwMTE2MTUyOTQ5WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQDQ/2MZ0451mih3d6c5
byzCW1Ztys0ZwoxPYB82Nv3CjKOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFJRYvitW9A4bZGkuZg+Cb9pbhT3QMB8G
A1UdIwQYMBaAFNlwQ3HjkfVm3x7JxMFcbcYIo1dEMGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vUWlJT2YtLXBR
V21nOU9KTXd5OHhXUSUyMTI1MzFiYWVkNDE2ODJiZmRAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQCpQ9aJ
7Wx/4cUiM6SgGBjd4nfV8EOrn+iwvVQ0E3d+9wIgdvxWTUO1+Jm/ftyniTDwksQr
UcGIAI1VwXbN4OIq4Cs=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f4:59:e8:2c:c8:b6:fa:87:51:04:a3:92:ca:86:3b:90
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan 19 15:29:49 2024 GMT
            Not After : Jan 16 15:29:49 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    d0:ff:63:19:d3:8e:75:9a:28:77:77:a7:39:6f:2c:
                    c2:5b:56:6d:ca:cd:19:c2:8c:4f:60:1f:36:36:fd:
                    c2:8c
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                94:58:BE:2B:56:F4:0E:1B:64:69:2E:66:0F:82:6F:DA:5B:85:3D:D0
            X509v3 Authority Key Identifier: 
                D9:70:43:71:E3:91:F5:66:DF:1E:C9:C4:C1:5C:6D:C6:08:A3:57:44
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://QiIOf--pQWmg9OJMwy8xWQ%212531baed41682bfd@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:a9:43:d6:89:ed:6c:7f:e1:c5:22:33:a4:a0:
        18:18:dd:e2:77:d5:f0:43:ab:9f:e8:b0:bd:54:34:13:77:7e:
        f7:02:20:76:fc:56:4d:43:b5:f8:99:bf:7e:dc:a7:89:30:f0:
        92:c4:2b:51:c1:88:00:8d:55:c1:76:cd:e0:e2:2a:e0:2b

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV+gAwIBAgIRAJU8li0pDGrQFZaVLzX9iOwwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExOTE1
Mjk0N1oXDTM0MDExNjE1Mjk0N1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATo
Bl5AgdzHN3hbH5GE8xGTIbkPcrf9s8BYT+3FZqFGAuy42+lemjE8VYqAot9YB9TF
XiCBL2jE+Yo/HbcDu560o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQU2XBDceOR9WbfHsnEwVxtxgijV0QwHwYDVR0jBBgw
FoAUu9oOE0btvBTQFKwXdidFqcNJ6uMwCgYIKoZIzj0EAwIDRwAwRAIgWy81Z+Uk
15N4aaW/5oK9SO75wZzEsTW13VLSEnmR5sACICaYFQ3icM9lJ1fY+FN2tyrT32M3
4NS+krymuaMtXu5P
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            95:3c:96:2d:29:0c:6a:d0:15:96:95:2f:35:fd:88:ec
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 19 15:29:47 2024 GMT
            Not After : Jan 16 15:29:47 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:e8:06:5e:40:81:dc:c7:37:78:5b:1f:91:84:f3:
                    11:93:21:b9:0f:72:b7:fd:b3:c0:58:4f:ed:c5:66:
                    a1:46:02:ec:b8:db:e9:5e:9a:31:3c:55:8a:80:a2:
                    df:58:07:d4:c5:5e:20:81:2f:68:c4:f9:8a:3f:1d:
                    b7:03:bb:9e:b4
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                D9:70:43:71:E3:91:F5:66:DF:1E:C9:C4:C1:5C:6D:C6:08:A3:57:44
            X509v3 Authority Key Identifier: 
                BB:DA:0E:13:46:ED:BC:14:D0:14:AC:17:76:27:45:A9:C3:49:EA:E3
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:5b:2f:35:67:e5:24:d7:93:78:69:a5:bf:e6:82:
        bd:48:ee:f9:c1:9c:c4:b1:35:b5:dd:52:d2:12:79:91:e6:c0:
        02:20:26:98:15:0d:e2:70:cf:65:27:57:d8:f8:53:76:b7:2a:
        d3:df:63:37:e0:d4:be:92:bc:a6:b9:a3:2d:5e:ee:4f

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATagAwIBAgIRAP9cz8ksB7awcyl2lHkInMIwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExOTE1
Mjk0NloXDTM0MDExNjE1Mjk0NlowJjENMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMM
d2lyZSBSb290IENBMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKdGXsKuso4cw
linMTYShj858pVYw+FzYlu1r3Zi6RHKdssNtKVdLeVrPEIDeoCIzfoxo8KPi+KHn
UQ8SYw1mHKNFMEMwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEw
HQYDVR0OBBYEFLvaDhNG7bwU0BSsF3YnRanDSerjMAoGCCqGSM49BAMCA0gAMEUC
IHPq0iLa9sB0yVB4p2S7f0DJs2U1FICKgSET1rUbvnnEAiEAudgaVuICXw9fp7A+
Yxz3bGtjavM1Ex+pgnWDlPtlJ+Y=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ff:5c:cf:c9:2c:07:b6:b0:73:29:76:94:79:08:9c:c2
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 19 15:29:46 2024 GMT
            Not After : Jan 16 15:29:46 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:29:d1:97:b0:ab:ac:a3:87:30:96:29:cc:4d:84:
                    a1:8f:ce:7c:a5:56:30:f8:5c:d8:96:ed:6b:dd:98:
                    ba:44:72:9d:b2:c3:6d:29:57:4b:79:5a:cf:10:80:
                    de:a0:22:33:7e:8c:68:f0:a3:e2:f8:a1:e7:51:0f:
                    12:63:0d:66:1c
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                BB:DA:0E:13:46:ED:BC:14:D0:14:AC:17:76:27:45:A9:C3:49:EA:E3
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:73:ea:d2:22:da:f6:c0:74:c9:50:78:a7:64:bb:
        7f:40:c9:b3:65:35:14:80:8a:81:21:13:d6:b5:1b:be:79:c4:
        02:21:00:b9:d8:1a:56:e2:02:5f:0f:5f:a7:b0:3e:63:1c:f7:
        6c:6b:63:6a:f3:35:13:1f:a9:82:75:83:94:fb:65:27:e6

```

openssl verify chain ✅