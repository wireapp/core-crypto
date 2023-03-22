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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/10249428487880759192/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/iguL8TKBUye1CH3B40EOtAy0dpnoIVzh
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
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/mXHpdW1uKx975A97Q8E7aq9Z7OfvPH6h
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/bdzCaag9kPTmDeEVD5QNPF3o6X2uaYw0
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:56203/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:56203/acme/wire/new-nonce",
  "newAccount": "https://stepca:56203/acme/wire/new-account",
  "newOrder": "https://stepca:56203/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:56203/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:56203/acme/wire/directory>;rel="index"
replay-nonce: djRyT0tYd1JLVzBxZ1BXNTRMdFNVM0FnVGhGS3QzNXg
```
```text
djRyT0tYd1JLVzBxZ1BXNTRMdFNVM0FnVGhGS3QzNXg
```
#### 5. create a new account
```http request
POST https://stepca:56203/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InV2ZmkwOTRKZzFpS042OW5JaWVyVkxuNFhLcWlseFgyZW9FQlIwQ3d0Y00ifSwibm9uY2UiOiJkalJ5VDB0WWQxSkxWekJ4WjFCWE5UUk1kRk5WTTBGblZHaEdTM1F6TlhnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYyMDMvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "XYfZHoLCKmuKnSLSidHywqZK-bjyUvxNRgkWiruOgZ_RYDhgqNRl3G-pqZ-JbviQb3Ict-nW1RqvXzb10AFVCA"
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
      "x": "uvfi094Jg1iKN69nIierVLn4XKqilxX2eoEBR0CwtcM"
    },
    "nonce": "djRyT0tYd1JLVzBxZ1BXNTRMdFNVM0FnVGhGS3QzNXg",
    "typ": "JWT",
    "url": "https://stepca:56203/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:56203/acme/wire/directory>;rel="index"
location: https://stepca:56203/acme/wire/account/yxQyZYLfjnHPYV3w8yPzD57fJZWKOwZo
replay-nonce: MW5OaWFQaXhxVzdiS0hZSDlsV0V4NGJXSDd6V3I1SnU
```
```json
{
  "status": "valid",
  "orders": "https://stepca:56203/acme/wire/account/yxQyZYLfjnHPYV3w8yPzD57fJZWKOwZo/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:56203/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MjAzL2FjbWUvd2lyZS9hY2NvdW50L3l4UXlaWUxmam5IUFlWM3c4eVB6RDU3ZkpaV0tPd1pvIiwidHlwIjoiSldUIiwibm9uY2UiOiJNVzVPYVdGUWFYaHhWemRpUzBoWlNEbHNWMFY0TkdKWFNEZDZWM0kxU25VIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYyMDMvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIlNtaXRoLCBBbGljZSBNIChRQSlcIixcImRvbWFpblwiOlwid2lyZS5jb21cIixcImNsaWVudC1pZFwiOlwiaW06d2lyZWFwcD1aRGc1WkRoa1ltRmlOemMzTkRnM09HRmlOemc0TldGaFlXSTJNalEwWVdJLzhlM2Q0OGU3ZWFlNmQ3OThAd2lyZS5jb21cIixcImhhbmRsZVwiOlwiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wMy0yN1QxMzoxNzo0My43NTM2ODVaIiwibm90QWZ0ZXIiOiIyMDIzLTAzLTI3VDE0OjE3OjQzLjc1MzY4NVoifQ",
  "signature": "E4FfcC92_iPGodDnN1Q8O42APJpNuBzTeXehmrNby8cmsb9Q9csCH_apfhFcE0w2LvKULuEtholak3fpYuM8CA"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDg5ZDhkYmFiNzc3NDg3OGFiNzg4NWFhYWI2MjQ0YWI/8e3d48e7eae6d798@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
      }
    ],
    "notAfter": "2023-03-27T14:17:43.753685Z",
    "notBefore": "2023-03-27T13:17:43.753685Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56203/acme/wire/account/yxQyZYLfjnHPYV3w8yPzD57fJZWKOwZo",
    "nonce": "MW5OaWFQaXhxVzdiS0hZSDlsV0V4NGJXSDd6V3I1SnU",
    "typ": "JWT",
    "url": "https://stepca:56203/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:56203/acme/wire/directory>;rel="index"
location: https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt
replay-nonce: V2RhVjBhNmptakNoWXBFZlFmY1lyMzZYM2x4UkExdmM
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDg5ZDhkYmFiNzc3NDg3OGFiNzg4NWFhYWI2MjQ0YWI/8e3d48e7eae6d798@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56203/acme/wire/authz/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL"
  ],
  "expires": "2023-03-28T13:17:43Z",
  "notBefore": "2023-03-27T13:17:43.753685Z",
  "notAfter": "2023-03-27T14:17:43.753685Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:56203/acme/wire/authz/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MjAzL2FjbWUvd2lyZS9hY2NvdW50L3l4UXlaWUxmam5IUFlWM3c4eVB6RDU3ZkpaV0tPd1pvIiwidHlwIjoiSldUIiwibm9uY2UiOiJWMlJoVmpCaE5tcHRha05vV1hCRlpsRm1ZMWx5TXpaWU0yeDRVa0V4ZG1NIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYyMDMvYWNtZS93aXJlL2F1dGh6L1plYVduNGFxblpHU3JVZFk0Zm1nVnZESlpJVjFzN3NMIn0",
  "payload": "",
  "signature": "EtGNrW5GUbuKMdAuvmf99BUlEobrNtPKQqLVZHUOxoX8Of_I-vFMxCye6LlBzuOX1j11CEZ4hCJNhvf0bF1gCA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56203/acme/wire/account/yxQyZYLfjnHPYV3w8yPzD57fJZWKOwZo",
    "nonce": "V2RhVjBhNmptakNoWXBFZlFmY1lyMzZYM2x4UkExdmM",
    "typ": "JWT",
    "url": "https://stepca:56203/acme/wire/authz/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL"
  }
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56203/acme/wire/directory>;rel="index"
location: https://stepca:56203/acme/wire/authz/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL
replay-nonce: d2lZWklwbWdqVzRPWUxwWXFsWUp0SG5odlkxVjZDaEg
```
```json
{
  "status": "pending",
  "expires": "2023-03-28T13:17:43Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/mXHpdW1uKx975A97Q8E7aq9Z7OfvPH6h",
      "status": "pending",
      "token": "JUD0p6WIONQK7fm96BuIKtUI8jlVFyjy"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/iguL8TKBUye1CH3B40EOtAy0dpnoIVzh",
      "status": "pending",
      "token": "JUD0p6WIONQK7fm96BuIKtUI8jlVFyjy"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDg5ZDhkYmFiNzc3NDg3OGFiNzg4NWFhYWI2MjQ0YWI/8e3d48e7eae6d798@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:20534/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
bHlXVVA3YzZESHkweTZmTXNkVDFVcUR5NmcwT25mWEg
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoidXZmaTA5NEpnMWlLTjY5bklpZXJWTG40WEtxaWx4WDJlb0VCUjBDd3RjTSJ9fQ.eyJpYXQiOjE2Nzk5MjMwNjMsImV4cCI6MTY3OTkyNjY2MywibmJmIjoxNjc5OTIzMDYzLCJzdWIiOiJpbTp3aXJlYXBwPVpEZzVaRGhrWW1GaU56YzNORGczT0dGaU56ZzROV0ZoWVdJMk1qUTBZV0kvOGUzZDQ4ZTdlYWU2ZDc5OEB3aXJlLmNvbSIsImp0aSI6Ijc5MDNmNTU5LTUzNjAtNDlkNy04MTk3LTYwYTQyNzYwOWQ1YyIsIm5vbmNlIjoiYkhsWFZWQTNZelpFU0hrd2VUWm1UWE5rVkRGVmNVUjVObWN3VDI1bVdFZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjA1MzQvIiwiY2hhbCI6IkpVRDBwNldJT05RSzdmbTk2QnVJS3RVSThqbFZGeWp5In0.u-berzb2XyNU4qSVr_TeaWnM33oQ0EoGFi2Nkc2nYq_iMsfTjAL1RZhiQXKLxUyLJdDoyot9Bvu9NYf9VuMlCg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoidXZmaTA5NEpnMWlLTjY5bklpZXJWTG40
WEtxaWx4WDJlb0VCUjBDd3RjTSJ9fQ.eyJpYXQiOjE2Nzk5MjMwNjMsImV4cCI6M
TY3OTkyNjY2MywibmJmIjoxNjc5OTIzMDYzLCJzdWIiOiJpbTp3aXJlYXBwPVpEZ
zVaRGhrWW1GaU56YzNORGczT0dGaU56ZzROV0ZoWVdJMk1qUTBZV0kvOGUzZDQ4Z
TdlYWU2ZDc5OEB3aXJlLmNvbSIsImp0aSI6Ijc5MDNmNTU5LTUzNjAtNDlkNy04M
Tk3LTYwYTQyNzYwOWQ1YyIsIm5vbmNlIjoiYkhsWFZWQTNZelpFU0hrd2VUWm1UW
E5rVkRGVmNVUjVObWN3VDI1bVdFZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MjA1MzQvIiwiY2hhbCI6IkpVRDBwNldJT05RSzdmbTk2QnVJS
3RVSThqbFZGeWp5In0.u-berzb2XyNU4qSVr_TeaWnM33oQ0EoGFi2Nkc2nYq_iM
sfTjAL1RZhiQXKLxUyLJdDoyot9Bvu9NYf9VuMlCg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "uvfi094Jg1iKN69nIierVLn4XKqilxX2eoEBR0CwtcM"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "JUD0p6WIONQK7fm96BuIKtUI8jlVFyjy",
  "exp": 1679926663,
  "htm": "POST",
  "htu": "http://wire.com:20534/",
  "iat": 1679923063,
  "jti": "7903f559-5360-49d7-8197-60a427609d5c",
  "nbf": 1679923063,
  "nonce": "bHlXVVA3YzZESHkweTZmTXNkVDFVcUR5NmcwT25mWEg",
  "sub": "im:wireapp=ZDg5ZDhkYmFiNzc3NDg3OGFiNzg4NWFhYWI2MjQ0YWI/8e3d48e7eae6d798@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIColxAEbBDEh+Pzk4je7J5WFP7kllu3sVDUkQSTD/Jgd
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuvfi094Jg1iKN69nIierVLn4XKqilxX2eoEBR0CwtcM=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:20534/clients/10249428487880759192/access-token
                          /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZFhabWFUQTVORXBuTVdsTFRqWTVia2xwWlhKV1RHNDBXRXR4YVd4NFdESmxiMFZDVWpCRGQzUmpUU0o5ZlEuZXlKcFlYUWlPakUyTnprNU1qTXdOak1zSW1WNGNDSTZNVFkzT1RreU5qWTJNeXdpYm1KbUlqb3hOamM1T1RJek1EWXpMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVnBFWnpWYVJHaHJXVzFHYVU1Nll6Tk9SR2N6VDBkR2FVNTZaelJPVjBab1dWZEpNazFxVVRCWlYwa3ZPR1V6WkRRNFpUZGxZV1UyWkRjNU9FQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqYzVNRE5tTlRVNUxUVXpOakF0TkRsa055MDRNVGszTFRZd1lUUXlOell3T1dRMVl5SXNJbTV2Ym1ObElqb2lZa2hzV0ZaV1FUTlplbHBGVTBocmQyVlVXbTFVV0U1clZrUkdWbU5WVWpWT2JXTjNWREkxYlZkRlp5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNakExTXpRdklpd2lZMmhoYkNJNklrcFZSREJ3TmxkSlQwNVJTemRtYlRrMlFuVkpTM1JWU1RocWJGWkdlV3A1SW4wLnUtYmVyemIyWHlOVTRxU1ZyX1RlYVduTTMzb1EwRW9HRmkyTmtjMm5ZcV9pTXNmVGpBTDFSWmhpUVhLTHhVeUxKZERveW90OUJ2dTlOWWY5VnVNbENn
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjRvbEY4STVJa3BhWm9BNk9leE9zZXcyQUx6OE1xajctWHh1azNMdFdxNjAifX0.eyJpYXQiOjE2Nzk5MjMwNjMsImV4cCI6MTY4NzY5OTA2MywibmJmIjoxNjc5OTIzMDYzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjA1MzQvIiwic3ViIjoiaW06d2lyZWFwcD1aRGc1WkRoa1ltRmlOemMzTkRnM09HRmlOemc0TldGaFlXSTJNalEwWVdJLzhlM2Q0OGU3ZWFlNmQ3OThAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjA1MzQvIiwianRpIjoiY2UzOGE5MjEtYjBlZi00NGMwLWEzZTQtOTZjMTE0YmRlOTljIiwibm9uY2UiOiJiSGxYVlZBM1l6WkVTSGt3ZVRabVRYTmtWREZWY1VSNU5tY3dUMjVtV0VnIiwiY2hhbCI6IkpVRDBwNldJT05RSzdmbTk2QnVJS3RVSThqbFZGeWp5IiwiY25mIjp7ImtpZCI6IjVwSXJwaWQ4NDBIaTRNQkcyZWwycTA3NnZ2ak1qV29MZXZleTFheFQyRDQifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lkWFptYVRBNU5FcG5NV2xMVGpZNWJrbHBaWEpXVEc0MFdFdHhhV3g0V0RKbGIwVkNVakJEZDNSalRTSjlmUS5leUpwWVhRaU9qRTJOems1TWpNd05qTXNJbVY0Y0NJNk1UWTNPVGt5TmpZMk15d2libUptSWpveE5qYzVPVEl6TURZekxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWcEVaelZhUkdocldXMUdhVTU2WXpOT1JHY3pUMGRHYVU1Nlp6Uk9WMFpvV1ZkSk1rMXFVVEJaVjBrdk9HVXpaRFE0WlRkbFlXVTJaRGM1T0VCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpjNU1ETm1OVFU1TFRVek5qQXRORGxrTnkwNE1UazNMVFl3WVRReU56WXdPV1ExWXlJc0ltNXZibU5sSWpvaVlraHNXRlpXUVROWmVscEZVMGhyZDJWVVdtMVVXRTVyVmtSR1ZtTlZValZPYldOM1ZESTFiVmRGWnlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQTFNelF2SWl3aVkyaGhiQ0k2SWtwVlJEQndObGRKVDA1UlN6ZG1iVGsyUW5WSlMzUlZTVGhxYkZaR2VXcDVJbjAudS1iZXJ6YjJYeU5VNHFTVnJfVGVhV25NMzNvUTBFb0dGaTJOa2MybllxX2lNc2ZUakFMMVJaaGlRWEtMeFV5TEpkRG95b3Q5QnZ1OU5ZZjlWdU1sQ2ciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVpEZzVaRGhrWW1GaU56YzNORGczT0dGaU56ZzROV0ZoWVdJMk1qUTBZV0kvOGUzZDQ4ZTdlYWU2ZDc5OEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.OPGsGXq_5CJ_uECFprIoP3cj7XPVMA3Mzl5TRNy4_EM8yTNzdERcDz2gKyCRPpSeXq5kjgzoL8d2SKU1oawkAg",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjRvbEY4STVJa3BhWm9BNk9leE9zZXcyQUx6OE1xajctWHh1azNMdFdxNjAifX0.eyJpYXQiOjE2Nzk5MjMwNjMsImV4cCI6MTY4NzY5OTA2MywibmJmIjoxNjc5OTIzMDYzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjA1MzQvIiwic3ViIjoiaW06d2lyZWFwcD1aRGc1WkRoa1ltRmlOemMzTkRnM09HRmlOemc0TldGaFlXSTJNalEwWVdJLzhlM2Q0OGU3ZWFlNmQ3OThAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjA1MzQvIiwianRpIjoiY2UzOGE5MjEtYjBlZi00NGMwLWEzZTQtOTZjMTE0YmRlOTljIiwibm9uY2UiOiJiSGxYVlZBM1l6WkVTSGt3ZVRabVRYTmtWREZWY1VSNU5tY3dUMjVtV0VnIiwiY2hhbCI6IkpVRDBwNldJT05RSzdmbTk2QnVJS3RVSThqbFZGeWp5IiwiY25mIjp7ImtpZCI6IjVwSXJwaWQ4NDBIaTRNQkcyZWwycTA3NnZ2ak1qV29MZXZleTFheFQyRDQifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lkWFptYVRBNU5FcG5NV2xMVGpZNWJrbHBaWEpXVEc0MFdFdHhhV3g0V0RKbGIwVkNVakJEZDNSalRTSjlmUS5leUpwWVhRaU9qRTJOems1TWpNd05qTXNJbVY0Y0NJNk1UWTNPVGt5TmpZMk15d2libUptSWpveE5qYzVPVEl6TURZekxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWcEVaelZhUkdocldXMUdhVTU2WXpOT1JHY3pUMGRHYVU1Nlp6Uk9WMFpvV1ZkSk1rMXFVVEJaVjBrdk9HVXpaRFE0WlRkbFlXVTJaRGM1T0VCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpjNU1ETm1OVFU1TFRVek5qQXRORGxrTnkwNE1UazNMVFl3WVRReU56WXdPV1ExWXlJc0ltNXZibU5sSWpvaVlraHNXRlpXUVROWmVscEZVMGhyZDJWVVdtMVVXRTVyVmtSR1ZtTlZValZPYldOM1ZESTFiVmRGWnlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQTFNelF2SWl3aVkyaGhiQ0k2SWtwVlJEQndObGRKVDA1UlN6ZG1iVGsyUW5WSlMzUlZTVGhxYkZaR2VXcDVJbjAudS1iZXJ6YjJYeU5VNHFTVnJfVGVhV25NMzNvUTBFb0dGaTJOa2MybllxX2lNc2ZUakFMMVJaaGlRWEtMeFV5TEpkRG95b3Q5QnZ1OU5ZZjlWdU1sQ2ciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVpEZzVaRGhrWW1GaU56YzNORGczT0dGaU56ZzROV0ZoWVdJMk1qUTBZV0kvOGUzZDQ4ZTdlYWU2ZDc5OEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.OPGsGXq_5CJ_uECFprIoP3cj7XPVMA3Mzl5TRNy4_EM8yTNzdERcDz2gKyCRPpSeXq5kjgzoL8d2SKU1oawkAg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IjRvbEY4STVJa3BhWm9BNk9leE9zZXcyQUx6
OE1xajctWHh1azNMdFdxNjAifX0.eyJpYXQiOjE2Nzk5MjMwNjMsImV4cCI6MTY4
NzY5OTA2MywibmJmIjoxNjc5OTIzMDYzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjA1MzQvIiwic3ViIjoiaW06d2lyZWFwcD1aRGc1WkRoa1ltRmlOemMzTkRnM09H
RmlOemc0TldGaFlXSTJNalEwWVdJLzhlM2Q0OGU3ZWFlNmQ3OThAd2lyZS5jb20i
LCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjA1MzQvIiwianRpIjoiY2UzOGE5MjEt
YjBlZi00NGMwLWEzZTQtOTZjMTE0YmRlOTljIiwibm9uY2UiOiJiSGxYVlZBM1l6
WkVTSGt3ZVRabVRYTmtWREZWY1VSNU5tY3dUMjVtV0VnIiwiY2hhbCI6IkpVRDBw
NldJT05RSzdmbTk2QnVJS3RVSThqbFZGeWp5IiwiY25mIjp7ImtpZCI6IjVwSXJw
aWQ4NDBIaTRNQkcyZWwycTA3NnZ2ak1qV29MZXZleTFheFQyRDQifSwicHJvb2Yi
OiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFu
ZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElq
b2lkWFptYVRBNU5FcG5NV2xMVGpZNWJrbHBaWEpXVEc0MFdFdHhhV3g0V0RKbGIw
VkNVakJEZDNSalRTSjlmUS5leUpwWVhRaU9qRTJOems1TWpNd05qTXNJbVY0Y0NJ
Nk1UWTNPVGt5TmpZMk15d2libUptSWpveE5qYzVPVEl6TURZekxDSnpkV0lpT2lK
cGJUcDNhWEpsWVhCd1BWcEVaelZhUkdocldXMUdhVTU2WXpOT1JHY3pUMGRHYVU1
Nlp6Uk9WMFpvV1ZkSk1rMXFVVEJaVjBrdk9HVXpaRFE0WlRkbFlXVTJaRGM1T0VC
M2FYSmxMbU52YlNJc0ltcDBhU0k2SWpjNU1ETm1OVFU1TFRVek5qQXRORGxrTnkw
NE1UazNMVFl3WVRReU56WXdPV1ExWXlJc0ltNXZibU5sSWpvaVlraHNXRlpXUVRO
WmVscEZVMGhyZDJWVVdtMVVXRTVyVmtSR1ZtTlZValZPYldOM1ZESTFiVmRGWnlJ
c0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIw
Nk1qQTFNelF2SWl3aVkyaGhiQ0k2SWtwVlJEQndObGRKVDA1UlN6ZG1iVGsyUW5W
SlMzUlZTVGhxYkZaR2VXcDVJbjAudS1iZXJ6YjJYeU5VNHFTVnJfVGVhV25NMzNv
UTBFb0dGaTJOa2MybllxX2lNc2ZUakFMMVJaaGlRWEtMeFV5TEpkRG95b3Q5QnZ1
OU5ZZjlWdU1sQ2ciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVpEZzVaRGhrWW1G
aU56YzNORGczT0dGaU56ZzROV0ZoWVdJMk1qUTBZV0kvOGUzZDQ4ZTdlYWU2ZDc5
OEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50
X2lkIn0.OPGsGXq_5CJ_uECFprIoP3cj7XPVMA3Mzl5TRNy4_EM8yTNzdERcDz2g
KyCRPpSeXq5kjgzoL8d2SKU1oawkAg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "4olF8I5IkpaZoA6OexOsew2ALz8Mqj7-Xxuk3LtWq60"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:20534/",
  "chal": "JUD0p6WIONQK7fm96BuIKtUI8jlVFyjy",
  "client_id": "im:wireapp=ZDg5ZDhkYmFiNzc3NDg3OGFiNzg4NWFhYWI2MjQ0YWI/8e3d48e7eae6d798@wire.com",
  "cnf": {
    "kid": "5pIrpid840Hi4MBG2el2q076vvjMjWoLevey1axT2D4"
  },
  "exp": 1687699063,
  "iat": 1679923063,
  "iss": "http://wire.com:20534/",
  "jti": "ce38a921-b0ef-44c0-a3e4-96c114bde99c",
  "nbf": 1679923063,
  "nonce": "bHlXVVA3YzZESHkweTZmTXNkVDFVcUR5NmcwT25mWEg",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoidXZmaTA5NEpnMWlLTjY5bklpZXJWTG40WEtxaWx4WDJlb0VCUjBDd3RjTSJ9fQ.eyJpYXQiOjE2Nzk5MjMwNjMsImV4cCI6MTY3OTkyNjY2MywibmJmIjoxNjc5OTIzMDYzLCJzdWIiOiJpbTp3aXJlYXBwPVpEZzVaRGhrWW1GaU56YzNORGczT0dGaU56ZzROV0ZoWVdJMk1qUTBZV0kvOGUzZDQ4ZTdlYWU2ZDc5OEB3aXJlLmNvbSIsImp0aSI6Ijc5MDNmNTU5LTUzNjAtNDlkNy04MTk3LTYwYTQyNzYwOWQ1YyIsIm5vbmNlIjoiYkhsWFZWQTNZelpFU0hrd2VUWm1UWE5rVkRGVmNVUjVObWN3VDI1bVdFZyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjA1MzQvIiwiY2hhbCI6IkpVRDBwNldJT05RSzdmbTk2QnVJS3RVSThqbFZGeWp5In0.u-berzb2XyNU4qSVr_TeaWnM33oQ0EoGFi2Nkc2nYq_iMsfTjAL1RZhiQXKLxUyLJdDoyot9Bvu9NYf9VuMlCg",
  "scope": "wire_client_id",
  "sub": "im:wireapp=ZDg5ZDhkYmFiNzc3NDg3OGFiNzg4NWFhYWI2MjQ0YWI/8e3d48e7eae6d798@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINHjliZInoSzHo/j0jySXtJbKyQw7lsQMSTKLoNaRCWx
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4olF8I5IkpaZoA6OexOsew2ALz8Mqj7+Xxuk3LtWq60=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/iguL8TKBUye1CH3B40EOtAy0dpnoIVzh
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MjAzL2FjbWUvd2lyZS9hY2NvdW50L3l4UXlaWUxmam5IUFlWM3c4eVB6RDU3ZkpaV0tPd1pvIiwidHlwIjoiSldUIiwibm9uY2UiOiJkMmxaV2tsd2JXZHFWelJQV1V4d1dYRnNXVXAwU0c1b2Rsa3hWalpEYUVnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYyMDMvYWNtZS93aXJlL2NoYWxsZW5nZS9aZWFXbjRhcW5aR1NyVWRZNGZtZ1Z2REpaSVYxczdzTC9pZ3VMOFRLQlV5ZTFDSDNCNDBFT3RBeTBkcG5vSVZ6aCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklqUnZiRVk0U1RWSmEzQmhXbTlCTms5bGVFOXpaWGN5UVV4Nk9FMXhhamN0V0hoMWF6Tk1kRmR4TmpBaWZYMC5leUpwWVhRaU9qRTJOems1TWpNd05qTXNJbVY0Y0NJNk1UWTROelk1T1RBMk15d2libUptSWpveE5qYzVPVEl6TURZekxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpBMU16UXZJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFhUkdjMVdrUm9hMWx0Um1sT2VtTXpUa1JuTTA5SFJtbE9lbWMwVGxkR2FGbFhTVEpOYWxFd1dWZEpMemhsTTJRME9HVTNaV0ZsTm1RM09UaEFkMmx5WlM1amIyMGlMQ0poZFdRaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQTFNelF2SWl3aWFuUnBJam9pWTJVek9HRTVNakV0WWpCbFppMDBOR013TFdFelpUUXRPVFpqTVRFMFltUmxPVGxqSWl3aWJtOXVZMlVpT2lKaVNHeFlWbFpCTTFsNldrVlRTR3QzWlZSYWJWUllUbXRXUkVaV1kxVlNOVTV0WTNkVU1qVnRWMFZuSWl3aVkyaGhiQ0k2SWtwVlJEQndObGRKVDA1UlN6ZG1iVGsyUW5WSlMzUlZTVGhxYkZaR2VXcDVJaXdpWTI1bUlqcDdJbXRwWkNJNklqVndTWEp3YVdRNE5EQklhVFJOUWtjeVpXd3ljVEEzTm5aMmFrMXFWMjlNWlhabGVURmhlRlF5UkRRaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsa1dGcHRZVlJCTlU1RmNHNU5WMnhNVkdwWk5XSnJiSEJhV0VwWFZFYzBNRmRGZEhoaFYzZzBWMFJLYkdJd1ZrTlZha0pFWkROU2FsUlRTamxtVVM1bGVVcHdXVmhSYVU5cVJUSk9lbXMxVFdwTmQwNXFUWE5KYlZZMFkwTkpOazFVV1ROUFZHdDVUbXBaTWsxNWQybGliVXB0U1dwdmVFNXFZelZQVkVsNlRVUlpla3hEU25wa1YwbHBUMmxLY0dKVWNETmhXRXBzV1ZoQ2QxQldjRVZhZWxaaFVrZG9jbGRYTVVkaFZUVTJXWHBPVDFKSFkzcFVNR1JIWVZVMU5scDZVazlXTUZwdlYxWmtTazFyTVhGVlZFSmFWakJyZGs5SFZYcGFSRkUwV2xSa2JGbFhWVEphUkdNMVQwVkNNMkZZU214TWJVNTJZbE5KYzBsdGNEQmhVMGsyU1dwak5VMUVUbTFPVkZVMVRGUlZlazVxUVhST1JHeHJUbmt3TkUxVWF6Tk1WRmwzV1ZSUmVVNTZXWGRQVjFFeFdYbEpjMGx0TlhaaWJVNXNTV3B2YVZscmFITlhSbHBYVVZST1dtVnNjRVpWTUdoeVpESldWVmR0TVZWWFJUVnlWbXRTUjFadFRsWlZhbFpQWWxkT00xWkVTVEZpVm1SR1dubEpjMGx0YURCaVUwazJTV3hDVUZVeFVXbE1RMHB2WkVoVmFVOXBTbTlrU0ZKM1QyazRkbVF5YkhsYVV6VnFZakl3TmsxcVFURk5lbEYyU1dsM2FWa3lhR2hpUTBrMlNXdHdWbEpFUW5kT2JHUktWREExVWxONlpHMWlWR3N5VVc1V1NsTXpVbFpUVkdoeFlrWmFSMlZYY0RWSmJqQXVkUzFpWlhKNllqSlllVTVWTkhGVFZuSmZWR1ZoVjI1Tk16TnZVVEJGYjBkR2FUSk9hMk15YmxseFgybE5jMlpVYWtGTU1WSmFhR2xSV0V0TWVGVjVURXBrUkc5NWIzUTVRbloxT1U1WlpqbFdkVTFzUTJjaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFZwRVp6VmFSR2hyV1cxR2FVNTZZek5PUkdjelQwZEdhVTU2WnpST1YwWm9XVmRKTWsxcVVUQlpWMGt2T0dVelpEUTRaVGRsWVdVMlpEYzVPRUIzYVhKbExtTnZiU0lzSW1Gd2FWOTJaWEp6YVc5dUlqb3pMQ0p6WTI5d1pTSTZJbmRwY21WZlkyeHBaVzUwWDJsa0luMC5PUEdzR1hxXzVDSl91RUNGcHJJb1AzY2o3WFBWTUEzTXpsNVRSTnk0X0VNOHlUTnpkRVJjRHoyZ0t5Q1JQcFNlWHE1a2pnem9MOGQyU0tVMW9hd2tBZyJ9",
  "signature": "A-pZ1l3sfNakdojMxvzhJk9Kx38Loc7aE9mvzsLTYtAPrbOQRYRugIaWZQEQ1mgZC0H75QRxvkQWMOQe1idzDw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjRvbEY4STVJa3BhWm9BNk9leE9zZXcyQUx6OE1xajctWHh1azNMdFdxNjAifX0.eyJpYXQiOjE2Nzk5MjMwNjMsImV4cCI6MTY4NzY5OTA2MywibmJmIjoxNjc5OTIzMDYzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjA1MzQvIiwic3ViIjoiaW06d2lyZWFwcD1aRGc1WkRoa1ltRmlOemMzTkRnM09HRmlOemc0TldGaFlXSTJNalEwWVdJLzhlM2Q0OGU3ZWFlNmQ3OThAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjA1MzQvIiwianRpIjoiY2UzOGE5MjEtYjBlZi00NGMwLWEzZTQtOTZjMTE0YmRlOTljIiwibm9uY2UiOiJiSGxYVlZBM1l6WkVTSGt3ZVRabVRYTmtWREZWY1VSNU5tY3dUMjVtV0VnIiwiY2hhbCI6IkpVRDBwNldJT05RSzdmbTk2QnVJS3RVSThqbFZGeWp5IiwiY25mIjp7ImtpZCI6IjVwSXJwaWQ4NDBIaTRNQkcyZWwycTA3NnZ2ak1qV29MZXZleTFheFQyRDQifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2lkWFptYVRBNU5FcG5NV2xMVGpZNWJrbHBaWEpXVEc0MFdFdHhhV3g0V0RKbGIwVkNVakJEZDNSalRTSjlmUS5leUpwWVhRaU9qRTJOems1TWpNd05qTXNJbVY0Y0NJNk1UWTNPVGt5TmpZMk15d2libUptSWpveE5qYzVPVEl6TURZekxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWcEVaelZhUkdocldXMUdhVTU2WXpOT1JHY3pUMGRHYVU1Nlp6Uk9WMFpvV1ZkSk1rMXFVVEJaVjBrdk9HVXpaRFE0WlRkbFlXVTJaRGM1T0VCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpjNU1ETm1OVFU1TFRVek5qQXRORGxrTnkwNE1UazNMVFl3WVRReU56WXdPV1ExWXlJc0ltNXZibU5sSWpvaVlraHNXRlpXUVROWmVscEZVMGhyZDJWVVdtMVVXRTVyVmtSR1ZtTlZValZPYldOM1ZESTFiVmRGWnlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qQTFNelF2SWl3aVkyaGhiQ0k2SWtwVlJEQndObGRKVDA1UlN6ZG1iVGsyUW5WSlMzUlZTVGhxYkZaR2VXcDVJbjAudS1iZXJ6YjJYeU5VNHFTVnJfVGVhV25NMzNvUTBFb0dGaTJOa2MybllxX2lNc2ZUakFMMVJaaGlRWEtMeFV5TEpkRG95b3Q5QnZ1OU5ZZjlWdU1sQ2ciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVpEZzVaRGhrWW1GaU56YzNORGczT0dGaU56ZzROV0ZoWVdJMk1qUTBZV0kvOGUzZDQ4ZTdlYWU2ZDc5OEB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.OPGsGXq_5CJ_uECFprIoP3cj7XPVMA3Mzl5TRNy4_EM8yTNzdERcDz2gKyCRPpSeXq5kjgzoL8d2SKU1oawkAg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56203/acme/wire/account/yxQyZYLfjnHPYV3w8yPzD57fJZWKOwZo",
    "nonce": "d2lZWklwbWdqVzRPWUxwWXFsWUp0SG5odlkxVjZDaEg",
    "typ": "JWT",
    "url": "https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/iguL8TKBUye1CH3B40EOtAy0dpnoIVzh"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56203/acme/wire/directory>;rel="index"
link: <https://stepca:56203/acme/wire/authz/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL>;rel="up"
location: https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/iguL8TKBUye1CH3B40EOtAy0dpnoIVzh
replay-nonce: bFBzYnJuSWhxRFdrTUhDS1QyUHdsR1VQT2R0cm9hN24
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/iguL8TKBUye1CH3B40EOtAy0dpnoIVzh",
  "status": "valid",
  "token": "JUD0p6WIONQK7fm96BuIKtUI8jlVFyjy"
}
```
### Authenticate end user using Open ID Connect implicit flow
#### 18. Client clicks login button
```http request
GET http://wire.com/login
accept: */*
host: wire.com:20534
```
#### 19. Resource server generates Verifier & Challenge Codes

```text
code_verifier=d1Xt6sBKwexmqH-4-3tFo3abzqKsIoQG4_7olnBYcyU&code_challenge=3MU7D0flpwgIeATFqTRtHaciqVPLXCAzIvI_3SkRqsE
```
#### 20. Resource server calls authorize url
```http request
GET http://dex:21318/dex/auth?response_type=code&client_id=wireapp&state=9WVGS7S5id-X69D80-iozQ&code_challenge=3MU7D0flpwgIeATFqTRtHaciqVPLXCAzIvI_3SkRqsE&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A20534%2Fcallback&scope=openid+profile&nonce=MPzHFWeCSRrjOVUptwzxvA
```
#### 21. Authorization server redirects to login prompt


```text
200 http://dex:21318/dex/auth/ldap/login?back=&state=sy5ochpqd42va63eukpdp5o43
{
    "content-length": "1525",
    "content-type": "text/html",
    "date": "Mon, 27 Mar 2023 13:17:43 GMT",
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
  <form method="post" action="/dex/auth/ldap/login?back=&amp;state=sy5ochpqd42va63eukpdp5o43">
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
POST http://dex:21318/dex/auth/ldap/login?back=&state=sy5ochpqd42va63eukpdp5o43
content-type: application/x-www-form-urlencoded
```
```text
login=alicesmith%40wire.com&password=foo
```
#### 23. (Optional) Authorization server presents consent form to client


```text
200 http://dex:21318/dex/approval?req=sy5ochpqd42va63eukpdp5o43&hmac=kCz_5m7Mzv15sii8lbzm0JRMD81TrHaJRdx1tlvqSTA
{
    "content-length": "1713",
    "date": "Mon, 27 Mar 2023 13:17:43 GMT",
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
        <input type="hidden" name="req" value="sy5ochpqd42va63eukpdp5o43"/>
        <input type="hidden" name="approval" value="approve">
        <button type="submit" class="dex-btn theme-btn--success">
            <span class="dex-btn-text">Grant Access</span>
        </button>
      </form>
    </div>
    <div class="theme-form-row">
      <form method="post">
        <input type="hidden" name="req" value="sy5ochpqd42va63eukpdp5o43"/>
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
POST http://dex:21318/dex/approval?req=sy5ochpqd42va63eukpdp5o43&hmac=kCz_5m7Mzv15sii8lbzm0JRMD81TrHaJRdx1tlvqSTA
content-type: application/x-www-form-urlencoded
```
```text
req=sy5ochpqd42va63eukpdp5o43&approval=approve
```
#### 25. Authorization server calls callback url with authorization code
```http request
GET http://wire.com/callback
accept: */*
referer: http://dex:21318/dex/approval?req=sy5ochpqd42va63eukpdp5o43&hmac=kCz_5m7Mzv15sii8lbzm0JRMD81TrHaJRdx1tlvqSTA
host: wire.com:20534
```
#### 26. Resource server call /oauth/token to get Id token
```http request
POST http://dex:21318/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpXamhLTjFKRE0wZFBXRXhaYlhwYU4yUjFTbE5VUW5aTQ==
```
```text
grant_type=authorization_code&code=n3ervxqzqp5z42bfuirg67smh&code_verifier=d1Xt6sBKwexmqH-4-3tFo3abzqKsIoQG4_7olnBYcyU&redirect_uri=http%3A%2F%2Fwire.com%3A20534%2Fcallback
```
#### 27. Authorization server validates Verifier & Challenge Codes

```text
code_verifier=d1Xt6sBKwexmqH-4-3tFo3abzqKsIoQG4_7olnBYcyU&code_challenge=3MU7D0flpwgIeATFqTRtHaciqVPLXCAzIvI_3SkRqsE
```
#### 28. Authorization server returns Access & Id token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE1ZGI0NDFhNjFmOTY2ZTIxM2FhZmNmODNlOGFjY2IwZGJlOTUyOWUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMzE4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFWnpWYVJHaHJXVzFHYVU1Nll6Tk9SR2N6VDBkR2FVNTZaelJPVjBab1dWZEpNazFxVVRCWlYwa3ZPR1V6WkRRNFpUZGxZV1UyWkRjNU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMDA5NDYzLCJpYXQiOjE2Nzk5MjMwNjMsIm5vbmNlIjoiTVB6SEZXZUNTUnJqT1ZVcHR3enh2QSIsImF0X2hhc2giOiJyWElUSXZwZXNlSk9INkQ0RnByelV3IiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Uuc21pdGgucWFAd2lyZS5jb20iLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIn0.flsnbWtxZye4_9vauujLN_71oEqUJklzjausY_FAVdYtsc3oypQimtiABADv9DKj8wVAAnKlPiv_ZmLjA26G00xqh0m99LY9P76eoVVymPzvx1pV4Tteg315s739CnDzNAZsWIdSAAdoRPmOYdcseSJDAvnUh0qHxiyqVSUsWtF-tl0UZrKZF5wjCkuyMTp56mSW0PRnUijggvVGIRHrzj42TQi9yDxQ1YuJWgjL8WGS4VtP6Tj-OTvHEKZG5WEXTHKxl59r-kRMSWRndXRlPrSW8vODIjxhvDVxGF3FcSv2oX0X5qfIQphaMduyRls3atxnH8e5G8WBKvJWLmgtzQ",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE1ZGI0NDFhNjFmOTY2ZTIxM2FhZmNmODNlOGFjY2IwZGJlOTUyOWUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMzE4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFWnpWYVJHaHJXVzFHYVU1Nll6Tk9SR2N6VDBkR2FVNTZaelJPVjBab1dWZEpNazFxVVRCWlYwa3ZPR1V6WkRRNFpUZGxZV1UyWkRjNU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMDA5NDYzLCJpYXQiOjE2Nzk5MjMwNjMsIm5vbmNlIjoiTVB6SEZXZUNTUnJqT1ZVcHR3enh2QSIsImF0X2hhc2giOiIwa3BGYk1jejRUb2JPanhJU25XYldnIiwiY19oYXNoIjoiQUs1NEpGMGVlWG9HLXNpUmhkNU1pdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.hPDpEgNq5Q_seXSdCyh8FkAgSPy31MV0fEjnM4SI1QqI30LIFvIn95F6xZJ-x9VLcVgZVwlyG-K1pqcjUNuJJ3gX_8Z9R78Cw_xiJkYCHFviOMdiiA-kuMH62mx9uGQrh4b3E4Kclj1u2OfzVM0FEPW4bB9vSu-1b9tCPq5HPGg5DV2VRNwzm4Ze3_wlGDXuihDgmUmr2GcPtvTPNknUVal2uJ-GtKvhvPwbMvkB3JUvVMcIHoxBkuIYedNLA7qWkHcrkVO0hS6YWQt-gaSv_S1f8rwPeYtHX2Uw8BNBMGXyuNBkXuriomYBKPAX_PkEVTrT4LITzvi-ZWXOACnZmQ",
  "token_type": "bearer"
}
```
#### 29. Resource server returns Id token to client

```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjE1ZGI0NDFhNjFmOTY2ZTIxM2FhZmNmODNlOGFjY2IwZGJlOTUyOWUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMzE4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFWnpWYVJHaHJXVzFHYVU1Nll6Tk9SR2N6VDBkR2FVNTZaelJPVjBab1dWZEpNazFxVVRCWlYwa3ZPR1V6WkRRNFpUZGxZV1UyWkRjNU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMDA5NDYzLCJpYXQiOjE2Nzk5MjMwNjMsIm5vbmNlIjoiTVB6SEZXZUNTUnJqT1ZVcHR3enh2QSIsImF0X2hhc2giOiIwa3BGYk1jejRUb2JPanhJU25XYldnIiwiY19oYXNoIjoiQUs1NEpGMGVlWG9HLXNpUmhkNU1pdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.hPDpEgNq5Q_seXSdCyh8FkAgSPy31MV0fEjnM4SI1QqI30LIFvIn95F6xZJ-x9VLcVgZVwlyG-K1pqcjUNuJJ3gX_8Z9R78Cw_xiJkYCHFviOMdiiA-kuMH62mx9uGQrh4b3E4Kclj1u2OfzVM0FEPW4bB9vSu-1b9tCPq5HPGg5DV2VRNwzm4Ze3_wlGDXuihDgmUmr2GcPtvTPNknUVal2uJ-GtKvhvPwbMvkB3JUvVMcIHoxBkuIYedNLA7qWkHcrkVO0hS6YWQt-gaSv_S1f8rwPeYtHX2Uw8BNBMGXyuNBkXuriomYBKPAX_PkEVTrT4LITzvi-ZWXOACnZmQ
```
#### 30. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjE1ZGI0NDFhNjFmOTY2ZTIxM2FhZmNmODNlOGFjY2IwZGJlOTUyOWUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMzE4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFWnpWYVJHaHJXVzFHYVU1Nll6Tk9SR2N6VDBkR2FVNTZaelJPVjBab1dWZEpNazFxVVRCWlYwa3ZPR1V6WkRRNFpUZGxZV1UyWkRjNU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMDA5NDYzLCJpYXQiOjE2Nzk5MjMwNjMsIm5vbmNlIjoiTVB6SEZXZUNTUnJqT1ZVcHR3enh2QSIsImF0X2hhc2giOiIwa3BGYk1jejRUb2JPanhJU25XYldnIiwiY19oYXNoIjoiQUs1NEpGMGVlWG9HLXNpUmhkNU1pdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.hPDpEgNq5Q_seXSdCyh8FkAgSPy31MV0fEjnM4SI1QqI30LIFvIn95F6xZJ-x9VLcVgZVwlyG-K1pqcjUNuJJ3gX_8Z9R78Cw_xiJkYCHFviOMdiiA-kuMH62mx9uGQrh4b3E4Kclj1u2OfzVM0FEPW4bB9vSu-1b9tCPq5HPGg5DV2VRNwzm4Ze3_wlGDXuihDgmUmr2GcPtvTPNknUVal2uJ-GtKvhvPwbMvkB3JUvVMcIHoxBkuIYedNLA7qWkHcrkVO0hS6YWQt-gaSv_S1f8rwPeYtHX2Uw8BNBMGXyuNBkXuriomYBKPAX_PkEVTrT4LITzvi-ZWXOACnZmQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjE1ZGI0NDFhNjFmOTY2ZTIxM2FhZmNmODNl
OGFjY2IwZGJlOTUyOWUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMzE4L2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFWnpWYVJHaHJXVzFHYVU1Nll6Tk9SR
2N6VDBkR2FVNTZaelJPVjBab1dWZEpNazFxVVRCWlYwa3ZPR1V6WkRRNFpUZGxZV
1UyWkRjNU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjgwMDA5NDYzLCJpYXQiOjE2Nzk5MjMwNjMsIm5vbmNlIjoiTVB6SEZXZ
UNTUnJqT1ZVcHR3enh2QSIsImF0X2hhc2giOiIwa3BGYk1jejRUb2JPanhJU25XY
ldnIiwiY19oYXNoIjoiQUs1NEpGMGVlWG9HLXNpUmhkNU1pdyIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZ
XJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.hPDpEgNq5Q_seXSdCyh8FkAg
SPy31MV0fEjnM4SI1QqI30LIFvIn95F6xZJ-x9VLcVgZVwlyG-K1pqcjUNuJJ3gX
_8Z9R78Cw_xiJkYCHFviOMdiiA-kuMH62mx9uGQrh4b3E4Kclj1u2OfzVM0FEPW4
bB9vSu-1b9tCPq5HPGg5DV2VRNwzm4Ze3_wlGDXuihDgmUmr2GcPtvTPNknUVal2
uJ-GtKvhvPwbMvkB3JUvVMcIHoxBkuIYedNLA7qWkHcrkVO0hS6YWQt-gaSv_S1f
8rwPeYtHX2Uw8BNBMGXyuNBkXuriomYBKPAX_PkEVTrT4LITzvi-ZWXOACnZmQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "15db441a61f966e213aafcf83e8accb0dbe9529e"
}
```

```json
{
  "at_hash": "0kpFbMcz4TobOjxISnWbWg",
  "aud": "wireapp",
  "c_hash": "AK54JF0eeXoG-siRhd5Miw",
  "exp": 1680009463,
  "iat": 1679923063,
  "iss": "http://dex:21318/dex",
  "name": "im:wireapp=alice.smith.qa@wire.com",
  "nonce": "MPzHFWeCSRrjOVUptwzxvA",
  "preferred_username": "Smith, Alice M (QA)",
  "sub": "ClBpbTp3aXJlYXBwPVpEZzVaRGhrWW1GaU56YzNORGczT0dGaU56ZzROV0ZoWVdJMk1qUTBZV0kvOGUzZDQ4ZTdlYWU2ZDc5OEB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4IZJrJFWCfbP/MwshJTw
sU/Xs0iTI2WUbxsk9q1wuYzBIyE1RF+xgf+QRGYw9+QBKUZGnb1B2QTs4Weztfqj
Zrm9pzpnf26vwMalQEqDjL5qJdiaWHTdaiFZRHB5/9/2IHULD7dNi+cMi7W83J8k
sGbM84WOdTPHXl6EbT/+dIci9BVomwFs5c37N24IvYnTxuQqPEYqgSXEEEr+kMvr
TN5Dm5EjDjnok6zynmJpNXOT2Eq7jp3xGxv2UYbL2hpnbPLBCNuqCjLWKMonNr06
SMGGSdNesNhVKTNct/oZIHtEyrf0fYyK8x+YNz8GaHEHVlotFTUuH++Yf/aEPszo
NwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/mXHpdW1uKx975A97Q8E7aq9Z7OfvPH6h
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MjAzL2FjbWUvd2lyZS9hY2NvdW50L3l4UXlaWUxmam5IUFlWM3c4eVB6RDU3ZkpaV0tPd1pvIiwidHlwIjoiSldUIiwibm9uY2UiOiJiRkJ6WW5KdVNXaHhSRmRyVFVoRFMxUXlVSGRzUjFWUVQyUjBjbTloTjI0IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYyMDMvYWNtZS93aXJlL2NoYWxsZW5nZS9aZWFXbjRhcW5aR1NyVWRZNGZtZ1Z2REpaSVYxczdzTC9tWEhwZFcxdUt4OTc1QTk3UThFN2FxOVo3T2Z2UEg2aCJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJakUxWkdJME5ERmhOakZtT1RZMlpUSXhNMkZoWm1ObU9ETmxPR0ZqWTJJd1pHSmxPVFV5T1dVaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSXhNekU0TDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZuQkZXbnBXWVZKSGFISlhWekZIWVZVMU5sbDZUazlTUjJONlZEQmtSMkZWTlRaYWVsSlBWakJhYjFkV1pFcE5hekZ4VlZSQ1dsWXdhM1pQUjFWNldrUlJORnBVWkd4WlYxVXlXa1JqTlU5RlFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qZ3dNREE1TkRZekxDSnBZWFFpT2pFMk56azVNak13TmpNc0ltNXZibU5sSWpvaVRWQjZTRVpYWlVOVFVuSnFUMVpWY0hSM2VuaDJRU0lzSW1GMFgyaGhjMmdpT2lJd2EzQkdZazFqZWpSVWIySlBhbmhKVTI1WFlsZG5JaXdpWTE5b1lYTm9Jam9pUVVzMU5FcEdNR1ZsV0c5SExYTnBVbWhrTlUxcGR5SXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObExuTnRhWFJvTG5GaFFIZHBjbVV1WTI5dElpd2ljSEpsWm1WeWNtVmtYM1Z6WlhKdVlXMWxJam9pVTIxcGRHZ3NJRUZzYVdObElFMGdLRkZCS1NKOS5oUERwRWdOcTVRX3NlWFNkQ3loOEZrQWdTUHkzMU1WMGZFam5NNFNJMVFxSTMwTElGdkluOTVGNnhaSi14OVZMY1ZnWlZ3bHlHLUsxcHFjalVOdUpKM2dYXzhaOVI3OEN3X3hpSmtZQ0hGdmlPTWRpaUEta3VNSDYybXg5dUdRcmg0YjNFNEtjbGoxdTJPZnpWTTBGRVBXNGJCOXZTdS0xYjl0Q1BxNUhQR2c1RFYyVlJOd3ptNFplM193bEdEWHVpaERnbVVtcjJHY1B0dlRQTmtuVVZhbDJ1Si1HdEt2aHZQd2JNdmtCM0pVdlZNY0lIb3hCa3VJWWVkTkxBN3FXa0hjcmtWTzBoUzZZV1F0LWdhU3ZfUzFmOHJ3UGVZdEhYMlV3OEJOQk1HWHl1TkJrWHVyaW9tWUJLUEFYX1BrRVZUclQ0TElUenZpLVpXWE9BQ25abVEiLCJrZXlhdXRoIjoiSlVEMHA2V0lPTlFLN2ZtOTZCdUlLdFVJOGpsVkZ5ankuc2hsWDEyd2l4ckNjb3JhMFZjUjA0V2Z5TDE5Mk82ZjRXNmlnYUFKRXVVcyJ9",
  "signature": "hL_g_iteL4KO5LsannweJJU58xj96ljykfSdnE44FponH_atIX7nQywQhwaXX-xCJ1zjz138X3KUF01vZND8AQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE1ZGI0NDFhNjFmOTY2ZTIxM2FhZmNmODNlOGFjY2IwZGJlOTUyOWUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxMzE4L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVnBFWnpWYVJHaHJXVzFHYVU1Nll6Tk9SR2N6VDBkR2FVNTZaelJPVjBab1dWZEpNazFxVVRCWlYwa3ZPR1V6WkRRNFpUZGxZV1UyWkRjNU9FQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgwMDA5NDYzLCJpYXQiOjE2Nzk5MjMwNjMsIm5vbmNlIjoiTVB6SEZXZUNTUnJqT1ZVcHR3enh2QSIsImF0X2hhc2giOiIwa3BGYk1jejRUb2JPanhJU25XYldnIiwiY19oYXNoIjoiQUs1NEpGMGVlWG9HLXNpUmhkNU1pdyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiU21pdGgsIEFsaWNlIE0gKFFBKSJ9.hPDpEgNq5Q_seXSdCyh8FkAgSPy31MV0fEjnM4SI1QqI30LIFvIn95F6xZJ-x9VLcVgZVwlyG-K1pqcjUNuJJ3gX_8Z9R78Cw_xiJkYCHFviOMdiiA-kuMH62mx9uGQrh4b3E4Kclj1u2OfzVM0FEPW4bB9vSu-1b9tCPq5HPGg5DV2VRNwzm4Ze3_wlGDXuihDgmUmr2GcPtvTPNknUVal2uJ-GtKvhvPwbMvkB3JUvVMcIHoxBkuIYedNLA7qWkHcrkVO0hS6YWQt-gaSv_S1f8rwPeYtHX2Uw8BNBMGXyuNBkXuriomYBKPAX_PkEVTrT4LITzvi-ZWXOACnZmQ",
    "keyauth": "JUD0p6WIONQK7fm96BuIKtUI8jlVFyjy.shlX12wixrCcora0VcR04WfyL192O6f4W6igaAJEuUs"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56203/acme/wire/account/yxQyZYLfjnHPYV3w8yPzD57fJZWKOwZo",
    "nonce": "bFBzYnJuSWhxRFdrTUhDS1QyUHdsR1VQT2R0cm9hN24",
    "typ": "JWT",
    "url": "https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/mXHpdW1uKx975A97Q8E7aq9Z7OfvPH6h"
  }
}
```
#### 31. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56203/acme/wire/directory>;rel="index"
link: <https://stepca:56203/acme/wire/authz/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL>;rel="up"
location: https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/mXHpdW1uKx975A97Q8E7aq9Z7OfvPH6h
replay-nonce: WW1OajlLWjVNRG5XY1ZUWDdlZGExTGl6YmVJZzZvc3U
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:56203/acme/wire/challenge/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL/mXHpdW1uKx975A97Q8E7aq9Z7OfvPH6h",
  "status": "valid",
  "token": "JUD0p6WIONQK7fm96BuIKtUI8jlVFyjy"
}
```
### Client presents a CSR and gets its certificate
#### 32. verify the status of the order
```http request
POST https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MjAzL2FjbWUvd2lyZS9hY2NvdW50L3l4UXlaWUxmam5IUFlWM3c4eVB6RDU3ZkpaV0tPd1pvIiwidHlwIjoiSldUIiwibm9uY2UiOiJXVzFPYWpsTFdqVk5SRzVYWTFaVVdEZGxaR0V4VEdsNlltVkpaelp2YzNVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYyMDMvYWNtZS93aXJlL29yZGVyLzZlcHZMR2RrelBKTlMwdUZ0T2hnbUptSEZDbjQzYWJ0In0",
  "payload": "",
  "signature": "3FLohsgv0jHtoPqLlz4ocrR6VXeClFWBTiAcejoMhc0SF8XMMvcxjtnAAgZjFwaK-0-oWlCTOYw7-oY7SN0vAg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56203/acme/wire/account/yxQyZYLfjnHPYV3w8yPzD57fJZWKOwZo",
    "nonce": "WW1OajlLWjVNRG5XY1ZUWDdlZGExTGl6YmVJZzZvc3U",
    "typ": "JWT",
    "url": "https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt"
  }
}
```
#### 33. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56203/acme/wire/directory>;rel="index"
location: https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt
replay-nonce: MXhNVUFBdE9uWnpnZnZYNzVYSldYUTNKQVg1MFRKU3U
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDg5ZDhkYmFiNzc3NDg3OGFiNzg4NWFhYWI2MjQ0YWI/8e3d48e7eae6d798@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56203/acme/wire/authz/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL"
  ],
  "expires": "2023-03-28T13:17:43Z",
  "notBefore": "2023-03-27T13:17:43.753685Z",
  "notAfter": "2023-03-27T14:17:43.753685Z"
}
```
#### 34. create a CSR and call finalize url
```http request
POST https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MjAzL2FjbWUvd2lyZS9hY2NvdW50L3l4UXlaWUxmam5IUFlWM3c4eVB6RDU3ZkpaV0tPd1pvIiwidHlwIjoiSldUIiwibm9uY2UiOiJNWGhOVlVGQmRFOXVXbnBuWm5aWU56VllTbGRZVVROS1FWZzFNRlJLVTNVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYyMDMvYWNtZS93aXJlL29yZGVyLzZlcHZMR2RrelBKTlMwdUZ0T2hnbUptSEZDbjQzYWJ0L2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCVURDQ0FRSUNBUUF3T1RFUk1BOEdBMVVFQ2d3SWQybHlaUzVqYjIweEpEQWlCZ3RnaGtnQmh2aENBd0dCY1F3VFUyMXBkR2dzSUVGc2FXTmxJRTBnS0ZGQktUQXFNQVVHQXl0bGNBTWhBTHIzNHRQZUNZTllpamV2WnlJbnExUzUtRnlxb3BjVjlucUJBVWRBc0xYRG9JR1ZNSUdTQmdrcWhraUc5dzBCQ1E0eGdZUXdnWUV3ZndZRFZSMFJCSGd3ZG9aUWFXMDZkMmx5WldGd2NEMTZaR2MxZW1Sb2EzbHRabWx1ZW1NemJtUm5NMjluWm1sdWVtYzBibmRtYUhsM2FUSnRhbkV3ZVhkcEx6aGxNMlEwT0dVM1pXRmxObVEzT1RoQWQybHlaUzVqYjIyR0ltbHRPbmRwY21WaGNIQTlZV3hwWTJVdWMyMXBkR2d1Y1dGQWQybHlaUzVqYjIwd0JRWURLMlZ3QTBFQTl3M2NHbklwc3NPbHJKOHQ5UlgxWS0ycWhkeWJlUXVwWS1fZG5QcHZSQ1ZKbFZjQ2pabmRYZFUtTkhfcHFydWNGVm1LbEp3TUVqdmlPaVJsZU5qZ0JnIn0",
  "signature": "l_jygbEfrv7r3PrTvXlFtHkU0AsOudxIpdKTSKs0zf9rIyVcyhhvPJ54oExs2JwA9dge7ERGvUrOepwbVxgOBA"
}
```
```json
{
  "payload": {
    "csr": "MIIBUDCCAQICAQAwOTERMA8GA1UECgwId2lyZS5jb20xJDAiBgtghkgBhvhCAwGBcQwTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhALr34tPeCYNYijevZyInq1S5-FyqopcV9nqBAUdAsLXDoIGVMIGSBgkqhkiG9w0BCQ4xgYQwgYEwfwYDVR0RBHgwdoZQaW06d2lyZWFwcD16ZGc1emRoa3ltZmluemMzbmRnM29nZmluemc0bndmaHl3aTJtanEweXdpLzhlM2Q0OGU3ZWFlNmQ3OThAd2lyZS5jb22GImltOndpcmVhcHA9YWxpY2Uuc21pdGgucWFAd2lyZS5jb20wBQYDK2VwA0EA9w3cGnIpssOlrJ8t9RX1Y-2qhdybeQupY-_dnPpvRCVJlVcCjZndXdU-NH_pqrucFVmKlJwMEjviOiRleNjgBg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56203/acme/wire/account/yxQyZYLfjnHPYV3w8yPzD57fJZWKOwZo",
    "nonce": "MXhNVUFBdE9uWnpnZnZYNzVYSldYUTNKQVg1MFRKU3U",
    "typ": "JWT",
    "url": "https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBUDCCAQICAQAwOTERMA8GA1UECgwId2lyZS5jb20xJDAiBgtghkgBhvhCAwGB
cQwTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhALr34tPeCYNYijevZyIn
q1S5+FyqopcV9nqBAUdAsLXDoIGVMIGSBgkqhkiG9w0BCQ4xgYQwgYEwfwYDVR0R
BHgwdoZQaW06d2lyZWFwcD16ZGc1emRoa3ltZmluemMzbmRnM29nZmluemc0bndm
aHl3aTJtanEweXdpLzhlM2Q0OGU3ZWFlNmQ3OThAd2lyZS5jb22GImltOndpcmVh
cHA9YWxpY2Uuc21pdGgucWFAd2lyZS5jb20wBQYDK2VwA0EA9w3cGnIpssOlrJ8t
9RX1Y+2qhdybeQupY+/dnPpvRCVJlVcCjZndXdU+NH/pqrucFVmKlJwMEjviOiRl
eNjgBg==
-----END CERTIFICATE REQUEST-----

```
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = wire.com, 2.16.840.1.113730.3.1.241 = "Smith, Alice M (QA)"
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    ba:f7:e2:d3:de:09:83:58:8a:37:af:67:22:27:ab:
                    54:b9:f8:5c:aa:a2:97:15:f6:7a:81:01:47:40:b0:
                    b5:c3
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=zdg5zdhkymfinzc3ndg3ogfinzg4nwfhywi2mjq0ywi/8e3d48e7eae6d798@wire.com, URI:im:wireapp=alice.smith.qa@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        f7:0d:dc:1a:72:29:b2:c3:a5:ac:9f:2d:f5:15:f5:63:ed:aa:
        85:dc:9b:79:0b:a9:63:ef:dd:9c:fa:6f:44:25:49:95:57:02:
        8d:99:dd:5d:d5:3e:34:7f:e9:aa:bb:9c:15:59:8a:94:9c:0c:
        12:3b:e2:3a:24:65:78:d8:e0:06

```

#### 35. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:56203/acme/wire/directory>;rel="index"
location: https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt
replay-nonce: TGNFTkp2M3JIdXB5SXpmcnozSmZTUnFOQW1vdkd0SkE
```
```json
{
  "certificate": "https://stepca:56203/acme/wire/certificate/bdzCaag9kPTmDeEVD5QNPF3o6X2uaYw0",
  "status": "valid",
  "finalize": "https://stepca:56203/acme/wire/order/6epvLGdkzPJNS0uFtOhgmJmHFCn43abt/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=ZDg5ZDhkYmFiNzc3NDg3OGFiNzg4NWFhYWI2MjQ0YWI/8e3d48e7eae6d798@wire.com\",\"handle\":\"im:wireapp=alice.smith.qa@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:56203/acme/wire/authz/ZeaWn4aqnZGSrUdY4fmgVvDJZIV1s7sL"
  ],
  "expires": "2023-03-28T13:17:43Z",
  "notBefore": "2023-03-27T13:17:43.753685Z",
  "notAfter": "2023-03-27T14:17:43.753685Z"
}
```
#### 36. fetch the certificate
```http request
POST https://stepca:56203/acme/wire/certificate/bdzCaag9kPTmDeEVD5QNPF3o6X2uaYw0
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU2MjAzL2FjbWUvd2lyZS9hY2NvdW50L3l4UXlaWUxmam5IUFlWM3c4eVB6RDU3ZkpaV0tPd1pvIiwidHlwIjoiSldUIiwibm9uY2UiOiJUR05GVGtwMk0zSklkWEI1U1hwbWNub3pTbVpUVW5GT1FXMXZka2QwU2tFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTYyMDMvYWNtZS93aXJlL2NlcnRpZmljYXRlL2JkekNhYWc5a1BUbURlRVZENVFOUEYzbzZYMnVhWXcwIn0",
  "payload": "",
  "signature": "kjwwN35E4r7UkrwcxZvkpW2OumGV8I8oXWk7YUvgUyext0mHI958-nrqJi4UxMojHZKsudy5AmYF6UWyuhs9AA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:56203/acme/wire/account/yxQyZYLfjnHPYV3w8yPzD57fJZWKOwZo",
    "nonce": "TGNFTkp2M3JIdXB5SXpmcnozSmZTUnFOQW1vdkd0SkE",
    "typ": "JWT",
    "url": "https://stepca:56203/acme/wire/certificate/bdzCaag9kPTmDeEVD5QNPF3o6X2uaYw0"
  }
}
```
#### 37. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:56203/acme/wire/directory>;rel="index"
replay-nonce: MDU2OXJxUE8wTklxN1pzVm5xUW1vQlNQbU1HUHM3Q2g
```
```json
"-----BEGIN CERTIFICATE-----\nMIICQzCCAeqgAwIBAgIRAOpABChUbf1FqdqX+8DeI1swCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwMzI3MTMxNzQzWhcNMjMwMzI3MTQxNzQzWjAxMREwDwYDVQQKEwh3aXJlLmNv\nbTEcMBoGA1UEAxMTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhALr34tPe\nCYNYijevZyInq1S5+FyqopcV9nqBAUdAsLXDo4IBEzCCAQ8wDgYDVR0PAQH/BAQD\nAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUxllU\nK1SfpIC0/6GcXuBKGCR6uCYwHwYDVR0jBBgwFoAUDQGlZChwPmUQ0n44pAobmReK\nd6AwfwYDVR0RBHgwdoYiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNv\nbYZQaW06d2lyZWFwcD16ZGc1emRoa3ltZmluemMzbmRnM29nZmluemc0bndmaHl3\naTJtanEweXdpLzhlM2Q0OGU3ZWFlNmQ3OThAd2lyZS5jb20wHQYMKwYBBAGCpGTG\nKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0cAMEQCIGY78koFQqrkU4mv\nDgFg4KG+/WbBELprC2aYkLHrAuFYAiACGbpEbmxfura90ZKUChvN8ewJjOLDUgHC\nIFJ8pG59Pw==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV+gAwIBAgIRAPVHe/8OX2RfxjVZWwmawkEwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMyNzEz\nMTc0MVoXDTMzMDMyNDEzMTc0MVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARp\n9LX0PiPPdms/r5gjzJZWXzhr0F5GsxQi7DZVacjxhec9g0cvrtfZABQYY2eVNoNa\ncT3WD+Q5Z4xmilVUJRm1o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUDQGlZChwPmUQ0n44pAobmReKd6AwHwYDVR0jBBgw\nFoAU7hLaiL39CMqRIC2hfq2Wtv5OX0YwCgYIKoZIzj0EAwIDRwAwRAIgRrvh+vNW\nGVPCocvwX13XujZXQxBVB93jN2MIEVeYUQUCIDzPefo3RdoKSPdZg9EI6NpwdFAq\nj7kMlBBb6b6sZABt\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICQzCCAeqgAwIBAgIRAOpABChUbf1FqdqX+8DeI1swCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwMzI3MTMxNzQzWhcNMjMwMzI3MTQxNzQzWjAxMREwDwYDVQQKEwh3aXJlLmNv
bTEcMBoGA1UEAxMTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhALr34tPe
CYNYijevZyInq1S5+FyqopcV9nqBAUdAsLXDo4IBEzCCAQ8wDgYDVR0PAQH/BAQD
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQUxllU
K1SfpIC0/6GcXuBKGCR6uCYwHwYDVR0jBBgwFoAUDQGlZChwPmUQ0n44pAobmReK
d6AwfwYDVR0RBHgwdoYiaW06d2lyZWFwcD1hbGljZS5zbWl0aC5xYUB3aXJlLmNv
bYZQaW06d2lyZWFwcD16ZGc1emRoa3ltZmluemMzbmRnM29nZmluemc0bndmaHl3
aTJtanEweXdpLzhlM2Q0OGU3ZWFlNmQ3OThAd2lyZS5jb20wHQYMKwYBBAGCpGTG
KEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0cAMEQCIGY78koFQqrkU4mv
DgFg4KG+/WbBELprC2aYkLHrAuFYAiACGbpEbmxfura90ZKUChvN8ewJjOLDUgHC
IFJ8pG59Pw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ea:40:04:28:54:6d:fd:45:a9:da:97:fb:c0:de:23:5b
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Mar 27 13:17:43 2023 GMT
            Not After : Mar 27 14:17:43 2023 GMT
        Subject: O = wire.com, CN = "Smith, Alice M (QA)"
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    ba:f7:e2:d3:de:09:83:58:8a:37:af:67:22:27:ab:
                    54:b9:f8:5c:aa:a2:97:15:f6:7a:81:01:47:40:b0:
                    b5:c3
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                C6:59:54:2B:54:9F:A4:80:B4:FF:A1:9C:5E:E0:4A:18:24:7A:B8:26
            X509v3 Authority Key Identifier: 
                0D:01:A5:64:28:70:3E:65:10:D2:7E:38:A4:0A:1B:99:17:8A:77:A0
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice.smith.qa@wire.com, URI:im:wireapp=zdg5zdhkymfinzc3ndg3ogfinzg4nwfhywi2mjq0ywi/8e3d48e7eae6d798@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:66:3b:f2:4a:05:42:aa:e4:53:89:af:0e:01:60:
        e0:a1:be:fd:66:c1:10:ba:6b:0b:66:98:90:b1:eb:02:e1:58:
        02:20:02:19:ba:44:6e:6c:5f:ba:b6:bd:d1:92:94:0a:1b:cd:
        f1:ec:09:8c:e2:c3:52:01:c2:20:52:7c:a4:6e:7d:3f

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV+gAwIBAgIRAPVHe/8OX2RfxjVZWwmawkEwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDMyNzEz
MTc0MVoXDTMzMDMyNDEzMTc0MVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARp
9LX0PiPPdms/r5gjzJZWXzhr0F5GsxQi7DZVacjxhec9g0cvrtfZABQYY2eVNoNa
cT3WD+Q5Z4xmilVUJRm1o2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUDQGlZChwPmUQ0n44pAobmReKd6AwHwYDVR0jBBgw
FoAU7hLaiL39CMqRIC2hfq2Wtv5OX0YwCgYIKoZIzj0EAwIDRwAwRAIgRrvh+vNW
GVPCocvwX13XujZXQxBVB93jN2MIEVeYUQUCIDzPefo3RdoKSPdZg9EI6NpwdFAq
j7kMlBBb6b6sZABt
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            f5:47:7b:ff:0e:5f:64:5f:c6:35:59:5b:09:9a:c2:41
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Mar 27 13:17:41 2023 GMT
            Not After : Mar 24 13:17:41 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:69:f4:b5:f4:3e:23:cf:76:6b:3f:af:98:23:cc:
                    96:56:5f:38:6b:d0:5e:46:b3:14:22:ec:36:55:69:
                    c8:f1:85:e7:3d:83:47:2f:ae:d7:d9:00:14:18:63:
                    67:95:36:83:5a:71:3d:d6:0f:e4:39:67:8c:66:8a:
                    55:54:25:19:b5
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                0D:01:A5:64:28:70:3E:65:10:D2:7E:38:A4:0A:1B:99:17:8A:77:A0
            X509v3 Authority Key Identifier: 
                EE:12:DA:88:BD:FD:08:CA:91:20:2D:A1:7E:AD:96:B6:FE:4E:5F:46
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:44:02:20:46:bb:e1:fa:f3:56:19:53:c2:a1:cb:f0:5f:5d:
        d7:ba:36:57:43:10:55:07:dd:e3:37:63:08:11:57:98:51:05:
        02:20:3c:cf:79:fa:37:45:da:0a:48:f7:59:83:d1:08:e8:da:
        70:74:50:2a:8f:b9:0c:94:10:5b:e9:be:ac:64:00:6d

```
