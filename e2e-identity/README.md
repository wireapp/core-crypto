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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/8e6424430d3b28be/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/s8y0OXyQLwMDTEHmU0KuZKYx41VCAvcT
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/b6gKurvFiAkViZX4bD9mn9PfGiFtIszq
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/leUvZchiW6iR45toJCeyFf7x1wnDBPIi
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32771/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32771/acme/wire/new-nonce",
  "newAccount": "https://stepca:32771/acme/wire/new-account",
  "newOrder": "https://stepca:32771/acme/wire/new-order",
  "revokeCert": "https://stepca:32771/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32771/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32771/acme/wire/directory>;rel="index"
replay-nonce: NUtYZjM1YjEybjhVam94MmZWOHdTUzhCZGNKRW11aG8
```
```text
NUtYZjM1YjEybjhVam94MmZWOHdTUzhCZGNKRW11aG8
```
#### 5. create a new account
```http request
POST https://stepca:32771/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IldDSU1UbEJNM3pLLVNvOS1DODgycWtUMWVFblFtV19RWkZxRU9RcUlpYlUifSwibm9uY2UiOiJOVXRZWmpNMVlqRXliamhWYW05NE1tWldPSGRUVXpoQ1pHTktSVzExYUc4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzEvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "sEre1e652aYZIgoWKVBaPpEx3plSJsFhzESOpLmjnzIUmGUYLurpztoUml08g4a4eMMShWSDvgIEG7uySDAYBQ"
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
      "x": "WCIMTlBM3zK-So9-C882qkT1eEnQmW_QZFqEOQqIibU"
    },
    "nonce": "NUtYZjM1YjEybjhVam94MmZWOHdTUzhCZGNKRW11aG8",
    "typ": "JWT",
    "url": "https://stepca:32771/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32771/acme/wire/directory>;rel="index"
location: https://stepca:32771/acme/wire/account/1KpNo1VC3eNOadojcAzjbQLStG1xq35Q
replay-nonce: Rzc3UGdpaWpNWFRja0ZXNDBzeWJWS3FTdVVZR21wc1Y
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32771/acme/wire/account/1KpNo1VC3eNOadojcAzjbQLStG1xq35Q/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32771/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzcxL2FjbWUvd2lyZS9hY2NvdW50LzFLcE5vMVZDM2VOT2Fkb2pjQXpqYlFMU3RHMXhxMzVRIiwidHlwIjoiSldUIiwibm9uY2UiOiJSemMzVUdkcGFXcE5XRlJqYTBaWE5EQnplV0pXUzNGVGRWVlpSMjF3YzFZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzEvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9TGNrc0piNzRUbTZOMTJjRGpGeTdsUS84ZTY0MjQ0MzBkM2IyOGJlQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9YWxpY2Vfd2lyZVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0xMC0wNFQxNDowMTo1OC4zNjE4MDlaIiwibm90QWZ0ZXIiOiIyMDMzLTEwLTAxVDE0OjAxOjU4LjM2MTgwOVoifQ",
  "signature": "9jYDWrMYE3cuz_KkAKbLXycXMMLbcTc1cvHAicRYil7dUBMM5OeZDW-vHioXFMB3sL1444Bxgzrl-nUafpIgBw"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2033-10-01T14:01:58.361809Z",
    "notBefore": "2023-10-04T14:01:58.361809Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32771/acme/wire/account/1KpNo1VC3eNOadojcAzjbQLStG1xq35Q",
    "nonce": "Rzc3UGdpaWpNWFRja0ZXNDBzeWJWS3FTdVVZR21wc1Y",
    "typ": "JWT",
    "url": "https://stepca:32771/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32771/acme/wire/directory>;rel="index"
location: https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W
replay-nonce: Q0tLU24yMWxDMGRBR1duQkdxMTlxYzhRTEdRSW5KaG8
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32771/acme/wire/authz/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK"
  ],
  "expires": "2023-10-05T14:01:58Z",
  "notBefore": "2023-10-04T14:01:58.361809Z",
  "notAfter": "2033-10-01T14:01:58.361809Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32771/acme/wire/authz/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzcxL2FjbWUvd2lyZS9hY2NvdW50LzFLcE5vMVZDM2VOT2Fkb2pjQXpqYlFMU3RHMXhxMzVRIiwidHlwIjoiSldUIiwibm9uY2UiOiJRMHRMVTI0eU1XeERNR1JCUjFkdVFrZHhNVGx4WXpoUlRFZFJTVzVLYUc4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzEvYWNtZS93aXJlL2F1dGh6L25hOXd2NDlhTWZnSmh2QnBNMnNzV01uaDVWdFJ3MEFLIn0",
  "payload": "",
  "signature": "GzGCb_41mLNcCT3KtTc7OQeizAYedSoEkYHkKaee4hMICuGJmD8zue-IwTVBzaG-t1OJiFfxvmy2lxE0ybKQCg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32771/acme/wire/account/1KpNo1VC3eNOadojcAzjbQLStG1xq35Q",
    "nonce": "Q0tLU24yMWxDMGRBR1duQkdxMTlxYzhRTEdRSW5KaG8",
    "typ": "JWT",
    "url": "https://stepca:32771/acme/wire/authz/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32771/acme/wire/directory>;rel="index"
location: https://stepca:32771/acme/wire/authz/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK
replay-nonce: ZzZ2aG5GUHZFdkVGSk1FWGFUQ24zOUJVNkk2WmpDVzM
```
```json
{
  "status": "pending",
  "expires": "2023-10-05T14:01:58Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/b6gKurvFiAkViZX4bD9mn9PfGiFtIszq",
      "status": "pending",
      "token": "6qgGq43yUhGfvM8vJWvQRr9AX735Q4QV",
      "target": "http://dex:15419/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/s8y0OXyQLwMDTEHmU0KuZKYx41VCAvcT",
      "status": "pending",
      "token": "6qgGq43yUhGfvM8vJWvQRr9AX735Q4QV",
      "target": "http://wire.com:23614/clients/8e6424430d3b28be/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:23614/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
Sng5T09QRWpSR1RYN2RIUDJ5TzQ3MXdSSHFGSHJReXU
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiV0NJTVRsQk0zekstU285LUM4ODJxa1QxZUVuUW1XX1FaRnFFT1FxSWliVSJ9fQ.eyJpYXQiOjE2OTY0MjQ1MTgsImV4cCI6MTY5NjQzMTcxOCwibmJmIjoxNjk2NDI0NTE4LCJzdWIiOiJpbTp3aXJlYXBwPUxja3NKYjc0VG02TjEyY0RqRnk3bFEvOGU2NDI0NDMwZDNiMjhiZUB3aXJlLmNvbSIsImp0aSI6ImU3MDU2ODg4LWZlMDctNGE0NS05NzllLTJiODJjNmJlNDI5OCIsIm5vbmNlIjoiU25nNVQwOVFSV3BTUjFSWU4yUklVREo1VHpRM01YZFNTSEZHU0hKUmVYVSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjM2MTQvY2xpZW50cy84ZTY0MjQ0MzBkM2IyOGJlL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI2cWdHcTQzeVVoR2Z2TTh2Sld2UVJyOUFYNzM1UTRRViJ9.ppWSIXjQadmBJUyeuDGtp9XBvmtXH4bXptwH4seAOasEzxIViIT3JMR4GVru1qSiCM_RTACdFLCViSHUG4WrBA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiV0NJTVRsQk0zekstU285LUM4ODJxa1Qx
ZUVuUW1XX1FaRnFFT1FxSWliVSJ9fQ.eyJpYXQiOjE2OTY0MjQ1MTgsImV4cCI6M
TY5NjQzMTcxOCwibmJmIjoxNjk2NDI0NTE4LCJzdWIiOiJpbTp3aXJlYXBwPUxja
3NKYjc0VG02TjEyY0RqRnk3bFEvOGU2NDI0NDMwZDNiMjhiZUB3aXJlLmNvbSIsI
mp0aSI6ImU3MDU2ODg4LWZlMDctNGE0NS05NzllLTJiODJjNmJlNDI5OCIsIm5vb
mNlIjoiU25nNVQwOVFSV3BTUjFSWU4yUklVREo1VHpRM01YZFNTSEZHU0hKUmVYV
SIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjM2MTQvY2xpZ
W50cy84ZTY0MjQ0MzBkM2IyOGJlL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI2cWdHc
TQzeVVoR2Z2TTh2Sld2UVJyOUFYNzM1UTRRViJ9.ppWSIXjQadmBJUyeuDGtp9XB
vmtXH4bXptwH4seAOasEzxIViIT3JMR4GVru1qSiCM_RTACdFLCViSHUG4WrBA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "WCIMTlBM3zK-So9-C882qkT1eEnQmW_QZFqEOQqIibU"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "6qgGq43yUhGfvM8vJWvQRr9AX735Q4QV",
  "exp": 1696431718,
  "htm": "POST",
  "htu": "http://wire.com:23614/clients/8e6424430d3b28be/access-token",
  "iat": 1696424518,
  "jti": "e7056888-fe07-4a45-979e-2b82c6be4298",
  "nbf": 1696424518,
  "nonce": "Sng5T09QRWpSR1RYN2RIUDJ5TzQ3MXdSSHFGSHJReXU",
  "sub": "im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOhojRA5NJf+HfldSVPQJgUXt3P8YGZAkFMa7lkAYq2t
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAWCIMTlBM3zK+So9+C882qkT1eEnQmW/QZFqEOQqIibU=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:23614/clients/8e6424430d3b28be/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVjBOSlRWUnNRazB6ZWtzdFUyODVMVU00T0RKeGExUXhaVVZ1VVcxWFgxRmFSbkZGVDFGeFNXbGlWU0o5ZlEuZXlKcFlYUWlPakUyT1RZME1qUTFNVGdzSW1WNGNDSTZNVFk1TmpRek1UY3hPQ3dpYm1KbUlqb3hOamsyTkRJME5URTRMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVXhqYTNOS1lqYzBWRzAyVGpFeVkwUnFSbmszYkZFdk9HVTJOREkwTkRNd1pETmlNamhpWlVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SW1VM01EVTJPRGc0TFdabE1EY3ROR0UwTlMwNU56bGxMVEppT0RKak5tSmxOREk1T0NJc0ltNXZibU5sSWpvaVUyNW5OVlF3T1ZGU1YzQlRVakZTV1U0eVVrbFZSRW8xVkhwUk0wMVlaRk5UU0VaSFUwaEtVbVZZVlNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qTTJNVFF2WTJ4cFpXNTBjeTg0WlRZME1qUTBNekJrTTJJeU9HSmxMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lJMmNXZEhjVFF6ZVZWb1IyWjJUVGgyU2xkMlVWSnlPVUZZTnpNMVVUUlJWaUo5LnBwV1NJWGpRYWRtQkpVeWV1REd0cDlYQnZtdFhINGJYcHR3SDRzZUFPYXNFenhJVmlJVDNKTVI0R1ZydTFxU2lDTV9SVEFDZEZMQ1ZpU0hVRzRXckJB
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InZhZnpLVlVBa2YzWG05RFR4RkVPX1RNRjJ2Ri1MckFsN1Itc2FyU1dzYTQifX0.eyJpYXQiOjE2OTY0MjgxMTgsImV4cCI6MTY5NjQyODQ3OCwibmJmIjoxNjk2NDI4MTEzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2MTQvY2xpZW50cy84ZTY0MjQ0MzBkM2IyOGJlL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9TGNrc0piNzRUbTZOMTJjRGpGeTdsUS84ZTY0MjQ0MzBkM2IyOGJlQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzNjE0L2NsaWVudHMvOGU2NDI0NDMwZDNiMjhiZS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJlYTJkZDliNS1jN2FmLTRiNjMtYWQ1Yi1kMjE3ODI3YmQ3MGIiLCJub25jZSI6IlNuZzVUMDlRUldwU1IxUllOMlJJVURKNVR6UTNNWGRTU0hGR1NISlJlWFUiLCJjaGFsIjoiNnFnR3E0M3lVaEdmdk04dkpXdlFScjlBWDczNVE0UVYiLCJjbmYiOnsia2lkIjoiNm9zY1ZZWGZWR1M1ZE83eDNkenYwaXQxNUxWcE1UaTZaQ1hLby1HWVdhVSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVYwTkpUVlJzUWswemVrc3RVMjg1TFVNNE9ESnhhMVF4WlVWdVVXMVhYMUZhUm5GRlQxRnhTV2xpVlNKOWZRLmV5SnBZWFFpT2pFMk9UWTBNalExTVRnc0ltVjRjQ0k2TVRZNU5qUXpNVGN4T0N3aWJtSm1Jam94TmprMk5ESTBOVEU0TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFV4amEzTktZamMwVkcwMlRqRXlZMFJxUm5rM2JGRXZPR1UyTkRJME5ETXdaRE5pTWpoaVpVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltVTNNRFUyT0RnNExXWmxNRGN0TkdFME5TMDVOemxsTFRKaU9ESmpObUpsTkRJNU9DSXNJbTV2Ym1ObElqb2lVMjVuTlZRd09WRlNWM0JUVWpGU1dVNHlVa2xWUkVvMVZIcFJNMDFZWkZOVFNFWkhVMGhLVW1WWVZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak0yTVRRdlkyeHBaVzUwY3k4NFpUWTBNalEwTXpCa00ySXlPR0psTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTJjV2RIY1RRemVWVm9SMloyVFRoMlNsZDJVVkp5T1VGWU56TTFVVFJSVmlKOS5wcFdTSVhqUWFkbUJKVXlldURHdHA5WEJ2bXRYSDRiWHB0d0g0c2VBT2FzRXp4SVZpSVQzSk1SNEdWcnUxcVNpQ01fUlRBQ2RGTENWaVNIVUc0V3JCQSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA9TGNrc0piNzRUbTZOMTJjRGpGeTdsUS84ZTY0MjQ0MzBkM2IyOGJlQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.woVD2uFjYWHe34qsWWgfeekYDVMUjLob6Bf-_9bu3DTilaIVDF-jtRNawZRvLbLRXYvD6xoxSHFu7Ce46mzcDA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InZhZnpLVlVBa2YzWG05RFR4RkVPX1RNRjJ2Ri1MckFsN1Itc2FyU1dzYTQifX0.eyJpYXQiOjE2OTY0MjgxMTgsImV4cCI6MTY5NjQyODQ3OCwibmJmIjoxNjk2NDI4MTEzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2MTQvY2xpZW50cy84ZTY0MjQ0MzBkM2IyOGJlL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9TGNrc0piNzRUbTZOMTJjRGpGeTdsUS84ZTY0MjQ0MzBkM2IyOGJlQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzNjE0L2NsaWVudHMvOGU2NDI0NDMwZDNiMjhiZS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJlYTJkZDliNS1jN2FmLTRiNjMtYWQ1Yi1kMjE3ODI3YmQ3MGIiLCJub25jZSI6IlNuZzVUMDlRUldwU1IxUllOMlJJVURKNVR6UTNNWGRTU0hGR1NISlJlWFUiLCJjaGFsIjoiNnFnR3E0M3lVaEdmdk04dkpXdlFScjlBWDczNVE0UVYiLCJjbmYiOnsia2lkIjoiNm9zY1ZZWGZWR1M1ZE83eDNkenYwaXQxNUxWcE1UaTZaQ1hLby1HWVdhVSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVYwTkpUVlJzUWswemVrc3RVMjg1TFVNNE9ESnhhMVF4WlVWdVVXMVhYMUZhUm5GRlQxRnhTV2xpVlNKOWZRLmV5SnBZWFFpT2pFMk9UWTBNalExTVRnc0ltVjRjQ0k2TVRZNU5qUXpNVGN4T0N3aWJtSm1Jam94TmprMk5ESTBOVEU0TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFV4amEzTktZamMwVkcwMlRqRXlZMFJxUm5rM2JGRXZPR1UyTkRJME5ETXdaRE5pTWpoaVpVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltVTNNRFUyT0RnNExXWmxNRGN0TkdFME5TMDVOemxsTFRKaU9ESmpObUpsTkRJNU9DSXNJbTV2Ym1ObElqb2lVMjVuTlZRd09WRlNWM0JUVWpGU1dVNHlVa2xWUkVvMVZIcFJNMDFZWkZOVFNFWkhVMGhLVW1WWVZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak0yTVRRdlkyeHBaVzUwY3k4NFpUWTBNalEwTXpCa00ySXlPR0psTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTJjV2RIY1RRemVWVm9SMloyVFRoMlNsZDJVVkp5T1VGWU56TTFVVFJSVmlKOS5wcFdTSVhqUWFkbUJKVXlldURHdHA5WEJ2bXRYSDRiWHB0d0g0c2VBT2FzRXp4SVZpSVQzSk1SNEdWcnUxcVNpQ01fUlRBQ2RGTENWaVNIVUc0V3JCQSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA9TGNrc0piNzRUbTZOMTJjRGpGeTdsUS84ZTY0MjQ0MzBkM2IyOGJlQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.woVD2uFjYWHe34qsWWgfeekYDVMUjLob6Bf-_9bu3DTilaIVDF-jtRNawZRvLbLRXYvD6xoxSHFu7Ce46mzcDA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InZhZnpLVlVBa2YzWG05RFR4RkVPX1RNRjJ2
Ri1MckFsN1Itc2FyU1dzYTQifX0.eyJpYXQiOjE2OTY0MjgxMTgsImV4cCI6MTY5
NjQyODQ3OCwibmJmIjoxNjk2NDI4MTEzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjM2MTQvY2xpZW50cy84ZTY0MjQ0MzBkM2IyOGJlL2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9TGNrc0piNzRUbTZOMTJjRGpGeTdsUS84ZTY0MjQ0MzBk
M2IyOGJlQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzNjE0L2Ns
aWVudHMvOGU2NDI0NDMwZDNiMjhiZS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJlYTJk
ZDliNS1jN2FmLTRiNjMtYWQ1Yi1kMjE3ODI3YmQ3MGIiLCJub25jZSI6IlNuZzVU
MDlRUldwU1IxUllOMlJJVURKNVR6UTNNWGRTU0hGR1NISlJlWFUiLCJjaGFsIjoi
NnFnR3E0M3lVaEdmdk04dkpXdlFScjlBWDczNVE0UVYiLCJjbmYiOnsia2lkIjoi
Nm9zY1ZZWGZWR1M1ZE83eDNkenYwaXQxNUxWcE1UaTZaQ1hLby1HWVdhVSJ9LCJw
cm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJ
aXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lM
Q0o0SWpvaVYwTkpUVlJzUWswemVrc3RVMjg1TFVNNE9ESnhhMVF4WlVWdVVXMVhY
MUZhUm5GRlQxRnhTV2xpVlNKOWZRLmV5SnBZWFFpT2pFMk9UWTBNalExTVRnc0lt
VjRjQ0k2TVRZNU5qUXpNVGN4T0N3aWJtSm1Jam94TmprMk5ESTBOVEU0TENKemRX
SWlPaUpwYlRwM2FYSmxZWEJ3UFV4amEzTktZamMwVkcwMlRqRXlZMFJxUm5rM2JG
RXZPR1UyTkRJME5ETXdaRE5pTWpoaVpVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklt
VTNNRFUyT0RnNExXWmxNRGN0TkdFME5TMDVOemxsTFRKaU9ESmpObUpsTkRJNU9D
SXNJbTV2Ym1ObElqb2lVMjVuTlZRd09WRlNWM0JUVWpGU1dVNHlVa2xWUkVvMVZI
cFJNMDFZWkZOVFNFWkhVMGhLVW1WWVZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RI
VWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak0yTVRRdlkyeHBaVzUwY3k4NFpU
WTBNalEwTXpCa00ySXlPR0psTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9p
STJjV2RIY1RRemVWVm9SMloyVFRoMlNsZDJVVkp5T1VGWU56TTFVVFJSVmlKOS5w
cFdTSVhqUWFkbUJKVXlldURHdHA5WEJ2bXRYSDRiWHB0d0g0c2VBT2FzRXp4SVZp
SVQzSk1SNEdWcnUxcVNpQ01fUlRBQ2RGTENWaVNIVUc0V3JCQSIsImNsaWVudF9p
ZCI6ImltOndpcmVhcHA9TGNrc0piNzRUbTZOMTJjRGpGeTdsUS84ZTY0MjQ0MzBk
M2IyOGJlQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9j
bGllbnRfaWQifQ.woVD2uFjYWHe34qsWWgfeekYDVMUjLob6Bf-_9bu3DTilaIVD
F-jtRNawZRvLbLRXYvD6xoxSHFu7Ce46mzcDA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "vafzKVUAkf3Xm9DTxFEO_TMF2vF-LrAl7R-sarSWsa4"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:23614/clients/8e6424430d3b28be/access-token",
  "chal": "6qgGq43yUhGfvM8vJWvQRr9AX735Q4QV",
  "client_id": "im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com",
  "cnf": {
    "kid": "6oscVYXfVGS5dO7x3dzv0it15LVpMTi6ZCXKo-GYWaU"
  },
  "exp": 1696428478,
  "iat": 1696428118,
  "iss": "http://wire.com:23614/clients/8e6424430d3b28be/access-token",
  "jti": "ea2dd9b5-c7af-4b63-ad5b-d217827bd70b",
  "nbf": 1696428113,
  "nonce": "Sng5T09QRWpSR1RYN2RIUDJ5TzQ3MXdSSHFGSHJReXU",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiV0NJTVRsQk0zekstU285LUM4ODJxa1QxZUVuUW1XX1FaRnFFT1FxSWliVSJ9fQ.eyJpYXQiOjE2OTY0MjQ1MTgsImV4cCI6MTY5NjQzMTcxOCwibmJmIjoxNjk2NDI0NTE4LCJzdWIiOiJpbTp3aXJlYXBwPUxja3NKYjc0VG02TjEyY0RqRnk3bFEvOGU2NDI0NDMwZDNiMjhiZUB3aXJlLmNvbSIsImp0aSI6ImU3MDU2ODg4LWZlMDctNGE0NS05NzllLTJiODJjNmJlNDI5OCIsIm5vbmNlIjoiU25nNVQwOVFSV3BTUjFSWU4yUklVREo1VHpRM01YZFNTSEZHU0hKUmVYVSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjM2MTQvY2xpZW50cy84ZTY0MjQ0MzBkM2IyOGJlL2FjY2Vzcy10b2tlbiIsImNoYWwiOiI2cWdHcTQzeVVoR2Z2TTh2Sld2UVJyOUFYNzM1UTRRViJ9.ppWSIXjQadmBJUyeuDGtp9XBvmtXH4bXptwH4seAOasEzxIViIT3JMR4GVru1qSiCM_RTACdFLCViSHUG4WrBA",
  "scope": "wire_client_id",
  "sub": "im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIFQQ7jyWXZj+y/AFz/Xh+gs0rXpf7xNVdRxYbbcM2cO8
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAvafzKVUAkf3Xm9DTxFEO/TMF2vF+LrAl7R+sarSWsa4=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/s8y0OXyQLwMDTEHmU0KuZKYx41VCAvcT
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzcxL2FjbWUvd2lyZS9hY2NvdW50LzFLcE5vMVZDM2VOT2Fkb2pjQXpqYlFMU3RHMXhxMzVRIiwidHlwIjoiSldUIiwibm9uY2UiOiJaeloyYUc1R1VIWkZka1ZHU2sxRldHRlVRMjR6T1VKVk5razJXbXBEVnpNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzEvYWNtZS93aXJlL2NoYWxsZW5nZS9uYTl3djQ5YU1mZ0podkJwTTJzc1dNbmg1VnRSdzBBSy9zOHkwT1h5UUx3TURURUhtVTBLdVpLWXg0MVZDQXZjVCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluWmhabnBMVmxWQmEyWXpXRzA1UkZSNFJrVlBYMVJOUmpKMlJpMU1ja0ZzTjFJdGMyRnlVMWR6WVRRaWZYMC5leUpwWVhRaU9qRTJPVFkwTWpneE1UZ3NJbVY0Y0NJNk1UWTVOalF5T0RRM09Dd2libUptSWpveE5qazJOREk0TVRFekxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNMk1UUXZZMnhwWlc1MGN5ODRaVFkwTWpRME16QmtNMkl5T0dKbEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5VEdOcmMwcGlOelJVYlRaT01USmpSR3BHZVRkc1VTODRaVFkwTWpRME16QmtNMkl5T0dKbFFIZHBjbVV1WTI5dElpd2lZWFZrSWpvaWFIUjBjRG92TDNkcGNtVXVZMjl0T2pJek5qRTBMMk5zYVdWdWRITXZPR1UyTkRJME5ETXdaRE5pTWpoaVpTOWhZMk5sYzNNdGRHOXJaVzRpTENKcWRHa2lPaUpsWVRKa1pEbGlOUzFqTjJGbUxUUmlOak10WVdRMVlpMWtNakUzT0RJM1ltUTNNR0lpTENKdWIyNWpaU0k2SWxOdVp6VlVNRGxSVWxkd1UxSXhVbGxPTWxKSlZVUktOVlI2VVROTldHUlRVMGhHUjFOSVNsSmxXRlVpTENKamFHRnNJam9pTm5GblIzRTBNM2xWYUVkbWRrMDRka3BYZGxGU2NqbEJXRGN6TlZFMFVWWWlMQ0pqYm1ZaU9uc2lhMmxrSWpvaU5tOXpZMVpaV0daV1IxTTFaRTgzZUROa2VuWXdhWFF4TlV4V2NFMVVhVFphUTFoTGJ5MUhXVmRoVlNKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVZZd1RrcFVWbEp6VVdzd2VtVnJjM1JWTWpnMVRGVk5ORTlFU25oaE1WRjRXbFZXZFZWWE1WaFlNVVpoVW01R1JsUXhSbmhUVjJ4cFZsTktPV1pSTG1WNVNuQlpXRkZwVDJwRk1rOVVXVEJOYWxFeFRWUm5jMGx0VmpSalEwazJUVlJaTlU1cVVYcE5WR040VDBOM2FXSnRTbTFKYW05NFRtcHJNazVFU1RCT1ZFVTBURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGVjRhbUV6VGt0WmFtTXdWa2N3TWxScVJYbFpNRkp4VW01ck0ySkdSWFpQUjFVeVRrUkpNRTVFVFhkYVJFNXBUV3BvYVZwVlFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2x0VlROTlJGVXlUMFJuTkV4WFdteE5SR04wVGtkRk1FNVRNRFZPZW14c1RGUkthVTlFU21wT2JVcHNUa1JKTlU5RFNYTkpiVFYyWW0xT2JFbHFiMmxWTWpWdVRsWlJkMDlXUmxOV00wSlVWV3BHVTFkVk5IbFZhMnhXVWtWdk1WWkljRkpOTURGWldrWk9WRk5GV2toVk1HaExWVzFXV1ZaVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWsweVRWUlJkbGt5ZUhCYVZ6VXdZM2s0TkZwVVdUQk5hbEV3VFhwQ2EwMHlTWGxQUjBwc1RESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTVEpqVjJSSVkxUlJlbVZXVm05U01sb3lWRlJvTWxOc1pESlZWa3A1VDFWR1dVNTZUVEZWVkZKU1ZtbEtPUzV3Y0ZkVFNWaHFVV0ZrYlVKS1ZYbGxkVVJIZEhBNVdFSjJiWFJZU0RSaVdIQjBkMGcwYzJWQlQyRnpSWHA0U1ZacFNWUXpTazFTTkVkV2NuVXhjVk5wUTAxZlVsUkJRMlJHVEVOV2FWTklWVWMwVjNKQ1FTSXNJbU5zYVdWdWRGOXBaQ0k2SW1sdE9uZHBjbVZoY0hBOVRHTnJjMHBpTnpSVWJUWk9NVEpqUkdwR2VUZHNVUzg0WlRZME1qUTBNekJrTTJJeU9HSmxRSGRwY21VdVkyOXRJaXdpWVhCcFgzWmxjbk5wYjI0aU9qVXNJbk5qYjNCbElqb2lkMmx5WlY5amJHbGxiblJmYVdRaWZRLndvVkQydUZqWVdIZTM0cXNXV2dmZWVrWURWTVVqTG9iNkJmLV85YnUzRFRpbGFJVkRGLWp0Uk5hd1pSdkxiTFJYWXZENnhveFNIRnU3Q2U0Nm16Y0RBIn0",
  "signature": "ZVuGLngiTuOpMXbxrlRhOOia5WkDpi1QZwsuQ1jgjjl2RvNKVxX1z2vGrg8LnfBWwWpTOs0AnEkaCFhaDBvjAg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InZhZnpLVlVBa2YzWG05RFR4RkVPX1RNRjJ2Ri1MckFsN1Itc2FyU1dzYTQifX0.eyJpYXQiOjE2OTY0MjgxMTgsImV4cCI6MTY5NjQyODQ3OCwibmJmIjoxNjk2NDI4MTEzLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2MTQvY2xpZW50cy84ZTY0MjQ0MzBkM2IyOGJlL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9TGNrc0piNzRUbTZOMTJjRGpGeTdsUS84ZTY0MjQ0MzBkM2IyOGJlQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjIzNjE0L2NsaWVudHMvOGU2NDI0NDMwZDNiMjhiZS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJlYTJkZDliNS1jN2FmLTRiNjMtYWQ1Yi1kMjE3ODI3YmQ3MGIiLCJub25jZSI6IlNuZzVUMDlRUldwU1IxUllOMlJJVURKNVR6UTNNWGRTU0hGR1NISlJlWFUiLCJjaGFsIjoiNnFnR3E0M3lVaEdmdk04dkpXdlFScjlBWDczNVE0UVYiLCJjbmYiOnsia2lkIjoiNm9zY1ZZWGZWR1M1ZE83eDNkenYwaXQxNUxWcE1UaTZaQ1hLby1HWVdhVSJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaVYwTkpUVlJzUWswemVrc3RVMjg1TFVNNE9ESnhhMVF4WlVWdVVXMVhYMUZhUm5GRlQxRnhTV2xpVlNKOWZRLmV5SnBZWFFpT2pFMk9UWTBNalExTVRnc0ltVjRjQ0k2TVRZNU5qUXpNVGN4T0N3aWJtSm1Jam94TmprMk5ESTBOVEU0TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFV4amEzTktZamMwVkcwMlRqRXlZMFJxUm5rM2JGRXZPR1UyTkRJME5ETXdaRE5pTWpoaVpVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltVTNNRFUyT0RnNExXWmxNRGN0TkdFME5TMDVOemxsTFRKaU9ESmpObUpsTkRJNU9DSXNJbTV2Ym1ObElqb2lVMjVuTlZRd09WRlNWM0JUVWpGU1dVNHlVa2xWUkVvMVZIcFJNMDFZWkZOVFNFWkhVMGhLVW1WWVZTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNak0yTVRRdlkyeHBaVzUwY3k4NFpUWTBNalEwTXpCa00ySXlPR0psTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSTJjV2RIY1RRemVWVm9SMloyVFRoMlNsZDJVVkp5T1VGWU56TTFVVFJSVmlKOS5wcFdTSVhqUWFkbUJKVXlldURHdHA5WEJ2bXRYSDRiWHB0d0g0c2VBT2FzRXp4SVZpSVQzSk1SNEdWcnUxcVNpQ01fUlRBQ2RGTENWaVNIVUc0V3JCQSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA9TGNrc0piNzRUbTZOMTJjRGpGeTdsUS84ZTY0MjQ0MzBkM2IyOGJlQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjUsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.woVD2uFjYWHe34qsWWgfeekYDVMUjLob6Bf-_9bu3DTilaIVDF-jtRNawZRvLbLRXYvD6xoxSHFu7Ce46mzcDA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32771/acme/wire/account/1KpNo1VC3eNOadojcAzjbQLStG1xq35Q",
    "nonce": "ZzZ2aG5GUHZFdkVGSk1FWGFUQ24zOUJVNkk2WmpDVzM",
    "typ": "JWT",
    "url": "https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/s8y0OXyQLwMDTEHmU0KuZKYx41VCAvcT"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32771/acme/wire/directory>;rel="index"
link: <https://stepca:32771/acme/wire/authz/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK>;rel="up"
location: https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/s8y0OXyQLwMDTEHmU0KuZKYx41VCAvcT
replay-nonce: SVRHVWdEbzZNc0NWcDFqbmRPUGxodjhWYWlLNjNib1I
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/s8y0OXyQLwMDTEHmU0KuZKYx41VCAvcT",
  "status": "valid",
  "token": "6qgGq43yUhGfvM8vJWvQRr9AX735Q4QV",
  "target": "http://wire.com:23614/clients/8e6424430d3b28be/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=Ff-l5lKhPtWTvAAgKde1HlUGy2_0lwdlSkFLYm5oqio&code_challenge=Ym7_OJF63McAxN6AbzCpYFdYtB1ELmrHKw8O_LJ4KrQ
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:15419/dex/auth?response_type=code&client_id=wireapp&state=4alcXSP6aMU69ausw0tZ7A&code_challenge=Ym7_OJF63McAxN6AbzCpYFdYtB1ELmrHKw8O_LJ4KrQ&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A23614%2Fcallback&scope=openid+profile&nonce=2S9xhxZR85FO6fPlU5A3Rg
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:15419/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpXblpMVWtWMWRHMXZTVmxhVGpoc2NYQTBkRFF6ZW10Sw==
```
```text
grant_type=authorization_code&code=v5audasvgrzbxtzkqfpczwjdm&code_verifier=Ff-l5lKhPtWTvAAgKde1HlUGy2_0lwdlSkFLYm5oqio&redirect_uri=http%3A%2F%2Fwire.com%3A23614%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjY0ZjViYTRjNjZiYTU2ZjdiNzJhZTYzZGYzYzQ1YmQ2MTBjZGZiYWMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NDE5L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXhqYTNOS1lqYzBWRzAyVGpFeVkwUnFSbmszYkZFdk9HVTJOREkwTkRNd1pETmlNamhpWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTY1MTQ1MTgsImlhdCI6MTY5NjQyODExOCwibm9uY2UiOiIyUzl4aHhaUjg1Rk82ZlBsVTVBM1JnIiwiYXRfaGFzaCI6ImlBV0szRERRV0dpQ3RWLWVaWFVkckEiLCJuYW1lIjoiaW06d2lyZWFwcD1hbGljZV93aXJlIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.mJSVLIz7z_elhxQsZfM0xRWzb6SB7fA1vHUAuM5mvob6UHrwoopSRmLZmVYF5slJIFQx0Vm93IW5d4qSb2prePotlLpw9a8hqyeoTKjLBul-fv9qiraKG96_o6rALanabBx-vZWERtgQBZP_KB5ddNyiZlnZAplWSuqEt0JEKMEBW6iu2u0YuU0rdhJWsFlcmXrW-qKv_r9YxT3LgsUFIm02UElJQSUHx8FSsv5iKKYKrWBM8TvjUcSG4HjJgrzkO2Rz7lNeTfveTzKyTcg-jMVkB_IF_ImjYNkW-46veqGua-zCeiYC3T57e8Xxzda6SHxl1GPsCwHJSCjee7EtDQ",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjY0ZjViYTRjNjZiYTU2ZjdiNzJhZTYzZGYzYzQ1YmQ2MTBjZGZiYWMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NDE5L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXhqYTNOS1lqYzBWRzAyVGpFeVkwUnFSbmszYkZFdk9HVTJOREkwTkRNd1pETmlNamhpWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTY1MTQ1MTgsImlhdCI6MTY5NjQyODExOCwibm9uY2UiOiIyUzl4aHhaUjg1Rk82ZlBsVTVBM1JnIiwiYXRfaGFzaCI6Ik44YXlSbDU0QS1WNmNndVNuY3ExZGciLCJjX2hhc2giOiJLQkxrTmRpeGJyeTlCMC0wV0RoWTNBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.OtCd3L6iv-iJ0M3cI_a8iN4qDa2c_SdqCofRWBwpokWXNj6V_t-1voGvCc808Atq9QnjiWHBhGgPzxymcYnjWk_wnjxz4L9NhxQxmwdm3eBjXDafIZ1OW4R2vH3zacrajRSL4psfZXMi3c6x0A0ag8OJ6253fyUpguX5jIeD45kkn-ciwGYPFz8WPnM83mva3ljLWgDlI91wMhWVC7BNC035VunyQpzr2gwIWMo2LUUdEx_Opl3_RtxZJVK76HvKgKVHk46ZAIU6AFsAIcxLgPZsOlAn7mlUxjTRyNaQnyuhr8EM2FU5fmTsV-Sm6gOVCzzW7FUD-V0WwCUXEkaFZA",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjY0ZjViYTRjNjZiYTU2ZjdiNzJhZTYzZGYzYzQ1YmQ2MTBjZGZiYWMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NDE5L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXhqYTNOS1lqYzBWRzAyVGpFeVkwUnFSbmszYkZFdk9HVTJOREkwTkRNd1pETmlNamhpWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTY1MTQ1MTgsImlhdCI6MTY5NjQyODExOCwibm9uY2UiOiIyUzl4aHhaUjg1Rk82ZlBsVTVBM1JnIiwiYXRfaGFzaCI6Ik44YXlSbDU0QS1WNmNndVNuY3ExZGciLCJjX2hhc2giOiJLQkxrTmRpeGJyeTlCMC0wV0RoWTNBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.OtCd3L6iv-iJ0M3cI_a8iN4qDa2c_SdqCofRWBwpokWXNj6V_t-1voGvCc808Atq9QnjiWHBhGgPzxymcYnjWk_wnjxz4L9NhxQxmwdm3eBjXDafIZ1OW4R2vH3zacrajRSL4psfZXMi3c6x0A0ag8OJ6253fyUpguX5jIeD45kkn-ciwGYPFz8WPnM83mva3ljLWgDlI91wMhWVC7BNC035VunyQpzr2gwIWMo2LUUdEx_Opl3_RtxZJVK76HvKgKVHk46ZAIU6AFsAIcxLgPZsOlAn7mlUxjTRyNaQnyuhr8EM2FU5fmTsV-Sm6gOVCzzW7FUD-V0WwCUXEkaFZA
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjY0ZjViYTRjNjZiYTU2ZjdiNzJhZTYzZGYzYzQ1YmQ2MTBjZGZiYWMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NDE5L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXhqYTNOS1lqYzBWRzAyVGpFeVkwUnFSbmszYkZFdk9HVTJOREkwTkRNd1pETmlNamhpWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTY1MTQ1MTgsImlhdCI6MTY5NjQyODExOCwibm9uY2UiOiIyUzl4aHhaUjg1Rk82ZlBsVTVBM1JnIiwiYXRfaGFzaCI6Ik44YXlSbDU0QS1WNmNndVNuY3ExZGciLCJjX2hhc2giOiJLQkxrTmRpeGJyeTlCMC0wV0RoWTNBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.OtCd3L6iv-iJ0M3cI_a8iN4qDa2c_SdqCofRWBwpokWXNj6V_t-1voGvCc808Atq9QnjiWHBhGgPzxymcYnjWk_wnjxz4L9NhxQxmwdm3eBjXDafIZ1OW4R2vH3zacrajRSL4psfZXMi3c6x0A0ag8OJ6253fyUpguX5jIeD45kkn-ciwGYPFz8WPnM83mva3ljLWgDlI91wMhWVC7BNC035VunyQpzr2gwIWMo2LUUdEx_Opl3_RtxZJVK76HvKgKVHk46ZAIU6AFsAIcxLgPZsOlAn7mlUxjTRyNaQnyuhr8EM2FU5fmTsV-Sm6gOVCzzW7FUD-V0WwCUXEkaFZA)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjY0ZjViYTRjNjZiYTU2ZjdiNzJhZTYzZGYz
YzQ1YmQ2MTBjZGZiYWMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NDE5L2RleCIsI
nN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXhqYTNOS1lqYzBWRzAyVGpFeVkwUnFSb
mszYkZFdk9HVTJOREkwTkRNd1pETmlNamhpWlVCM2FYSmxMbU52YlJJRWJHUmhjQ
SIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTY1MTQ1MTgsImlhdCI6MTY5NjQyO
DExOCwibm9uY2UiOiIyUzl4aHhaUjg1Rk82ZlBsVTVBM1JnIiwiYXRfaGFzaCI6I
k44YXlSbDU0QS1WNmNndVNuY3ExZGciLCJjX2hhc2giOiJLQkxrTmRpeGJyeTlCM
C0wV0RoWTNBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlc
nJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.OtCd3L6iv-iJ0M3cI_a8iN4qD
a2c_SdqCofRWBwpokWXNj6V_t-1voGvCc808Atq9QnjiWHBhGgPzxymcYnjWk_wn
jxz4L9NhxQxmwdm3eBjXDafIZ1OW4R2vH3zacrajRSL4psfZXMi3c6x0A0ag8OJ6
253fyUpguX5jIeD45kkn-ciwGYPFz8WPnM83mva3ljLWgDlI91wMhWVC7BNC035V
unyQpzr2gwIWMo2LUUdEx_Opl3_RtxZJVK76HvKgKVHk46ZAIU6AFsAIcxLgPZsO
lAn7mlUxjTRyNaQnyuhr8EM2FU5fmTsV-Sm6gOVCzzW7FUD-V0WwCUXEkaFZA
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "64f5ba4c66ba56f7b72ae63df3c45bd610cdfbac"
}
```

```json
{
  "at_hash": "N8ayRl54A-V6cguSncq1dg",
  "aud": "wireapp",
  "c_hash": "KBLkNdixbry9B0-0WDhY3A",
  "exp": 1696514518,
  "iat": 1696428118,
  "iss": "http://dex:15419/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "2S9xhxZR85FO6fPlU5A3Rg",
  "preferred_username": "Alice Smith",
  "sub": "CjtpbTp3aXJlYXBwPUxja3NKYjc0VG02TjEyY0RqRnk3bFEvOGU2NDI0NDMwZDNiMjhiZUB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA94ceBIZf2i7QQjJD0lFn
Uu2388P5HK6fbn4ahpdmXCiabT9uLdObLxHymTU3ULJC9yyYMwQHPmIKlO2nH2b4
uge0pxsPWhdVzwSnJuKyTmpChGmKkNcEQMqcVl82OwiMugsBzOe2KTPhf8O3ANWa
U02gyV388/Rgyl0lqU1Ba97IIsDYtoPnzXeyLr78ZdDoCgFnUYBaIb4K0eMNB8gZ
o2XxPGIYOKNcXwMQpBsjxsQU10OD0zP14lYafBJ1Anm10HiO/7qj97EjGBlStBIa
xqUiqaeIdIgZngxskorjftbS296IqIt4Cv5yH2ZbNe0PDB+EQT6/Yzb85hDnVotb
3wIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/b6gKurvFiAkViZX4bD9mn9PfGiFtIszq
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzcxL2FjbWUvd2lyZS9hY2NvdW50LzFLcE5vMVZDM2VOT2Fkb2pjQXpqYlFMU3RHMXhxMzVRIiwidHlwIjoiSldUIiwibm9uY2UiOiJTVlJIVldkRWJ6Wk5jME5XY0RGcWJtUlBVR3hvZGpoV1lXbExOak5pYjFJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzEvYWNtZS93aXJlL2NoYWxsZW5nZS9uYTl3djQ5YU1mZ0podkJwTTJzc1dNbmg1VnRSdzBBSy9iNmdLdXJ2RmlBa1ZpWlg0YkQ5bW45UGZHaUZ0SXN6cSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJalkwWmpWaVlUUmpOalppWVRVMlpqZGlOekpoWlRZelpHWXpZelExWW1RMk1UQmpaR1ppWVdNaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTFOREU1TDJSbGVDSXNJbk4xWWlJNklrTnFkSEJpVkhBellWaEtiRmxZUW5kUVZYaHFZVE5PUzFscVl6QldSekF5VkdwRmVWa3dVbkZTYm1zellrWkZkazlIVlRKT1JFa3dUa1JOZDFwRVRtbE5hbWhwV2xWQ00yRllTbXhNYlU1MllsSkpSV0pIVW1oalFTSXNJbUYxWkNJNkluZHBjbVZoY0hBaUxDSmxlSEFpT2pFMk9UWTFNVFExTVRnc0ltbGhkQ0k2TVRZNU5qUXlPREV4T0N3aWJtOXVZMlVpT2lJeVV6bDRhSGhhVWpnMVJrODJabEJzVlRWQk0xSm5JaXdpWVhSZmFHRnphQ0k2SWs0NFlYbFNiRFUwUVMxV05tTm5kVk51WTNFeFpHY2lMQ0pqWDJoaGMyZ2lPaUpMUWt4clRtUnBlR0p5ZVRsQ01DMHdWMFJvV1ROQklpd2libUZ0WlNJNkltbHRPbmRwY21WaGNIQTlZV3hwWTJWZmQybHlaU0lzSW5CeVpXWmxjbkpsWkY5MWMyVnlibUZ0WlNJNklrRnNhV05sSUZOdGFYUm9JbjAuT3RDZDNMNml2LWlKME0zY0lfYThpTjRxRGEyY19TZHFDb2ZSV0J3cG9rV1hOajZWX3QtMXZvR3ZDYzgwOEF0cTlRbmppV0hCaEdnUHp4eW1jWW5qV2tfd25qeHo0TDlOaHhReG13ZG0zZUJqWERhZklaMU9XNFIydkgzemFjcmFqUlNMNHBzZlpYTWkzYzZ4MEEwYWc4T0o2MjUzZnlVcGd1WDVqSWVENDVra24tY2l3R1lQRno4V1BuTTgzbXZhM2xqTFdnRGxJOTF3TWhXVkM3Qk5DMDM1VnVueVFwenIyZ3dJV01vMkxVVWRFeF9PcGwzX1J0eFpKVks3Nkh2S2dLVkhrNDZaQUlVNkFGc0FJY3hMZ1Bac09sQW43bWxVeGpUUnlOYVFueXVocjhFTTJGVTVmbVRzVi1TbTZnT1ZDenpXN0ZVRC1WMFd3Q1VYRWthRlpBIiwia2V5YXV0aCI6IjZxZ0dxNDN5VWhHZnZNOHZKV3ZRUnI5QVg3MzVRNFFWLjZvc2NWWVhmVkdTNWRPN3gzZHp2MGl0MTVMVnBNVGk2WkNYS28tR1lXYVUifQ",
  "signature": "Lm4B10w4qepfF6_bZZMZvWYkNccfvFu2rYFUxxKRkB8P5d-Hdo0Qe9rQX_S9oWJnr8yXCyy0ifIHlYRogJbgDA"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjY0ZjViYTRjNjZiYTU2ZjdiNzJhZTYzZGYzYzQ1YmQ2MTBjZGZiYWMifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE1NDE5L2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXhqYTNOS1lqYzBWRzAyVGpFeVkwUnFSbmszYkZFdk9HVTJOREkwTkRNd1pETmlNamhpWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE2OTY1MTQ1MTgsImlhdCI6MTY5NjQyODExOCwibm9uY2UiOiIyUzl4aHhaUjg1Rk82ZlBsVTVBM1JnIiwiYXRfaGFzaCI6Ik44YXlSbDU0QS1WNmNndVNuY3ExZGciLCJjX2hhc2giOiJLQkxrTmRpeGJyeTlCMC0wV0RoWTNBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.OtCd3L6iv-iJ0M3cI_a8iN4qDa2c_SdqCofRWBwpokWXNj6V_t-1voGvCc808Atq9QnjiWHBhGgPzxymcYnjWk_wnjxz4L9NhxQxmwdm3eBjXDafIZ1OW4R2vH3zacrajRSL4psfZXMi3c6x0A0ag8OJ6253fyUpguX5jIeD45kkn-ciwGYPFz8WPnM83mva3ljLWgDlI91wMhWVC7BNC035VunyQpzr2gwIWMo2LUUdEx_Opl3_RtxZJVK76HvKgKVHk46ZAIU6AFsAIcxLgPZsOlAn7mlUxjTRyNaQnyuhr8EM2FU5fmTsV-Sm6gOVCzzW7FUD-V0WwCUXEkaFZA",
    "keyauth": "6qgGq43yUhGfvM8vJWvQRr9AX735Q4QV.6oscVYXfVGS5dO7x3dzv0it15LVpMTi6ZCXKo-GYWaU"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32771/acme/wire/account/1KpNo1VC3eNOadojcAzjbQLStG1xq35Q",
    "nonce": "SVRHVWdEbzZNc0NWcDFqbmRPUGxodjhWYWlLNjNib1I",
    "typ": "JWT",
    "url": "https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/b6gKurvFiAkViZX4bD9mn9PfGiFtIszq"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32771/acme/wire/directory>;rel="index"
link: <https://stepca:32771/acme/wire/authz/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK>;rel="up"
location: https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/b6gKurvFiAkViZX4bD9mn9PfGiFtIszq
replay-nonce: TUFFbGJFdExrV3ZmMGNLalMwM3hrZVF3bTZvSWttdGo
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32771/acme/wire/challenge/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK/b6gKurvFiAkViZX4bD9mn9PfGiFtIszq",
  "status": "valid",
  "token": "6qgGq43yUhGfvM8vJWvQRr9AX735Q4QV",
  "target": "http://dex:15419/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzcxL2FjbWUvd2lyZS9hY2NvdW50LzFLcE5vMVZDM2VOT2Fkb2pjQXpqYlFMU3RHMXhxMzVRIiwidHlwIjoiSldUIiwibm9uY2UiOiJUVUZGYkdKRmRFeHJWM1ptTUdOTGFsTXdNM2hyWlZGM2JUWnZTV3R0ZEdvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzEvYWNtZS93aXJlL29yZGVyL01oS2VSNTVJNjV6dlRqSWhYOFcyTlVOQWt6cXFNTDhXIn0",
  "payload": "",
  "signature": "WoRJTgGbF0aH856dbMq532NNuY-s5KaT20MEg6Cen6bgEwOY-qEih-OqANr4TMCg52sNNMUHcXMzl-G_l0cBBQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32771/acme/wire/account/1KpNo1VC3eNOadojcAzjbQLStG1xq35Q",
    "nonce": "TUFFbGJFdExrV3ZmMGNLalMwM3hrZVF3bTZvSWttdGo",
    "typ": "JWT",
    "url": "https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32771/acme/wire/directory>;rel="index"
location: https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W
replay-nonce: RTV3R3hIMXlLMGJwV0tiNXZ1eTlMYmFWc2UwTmxNaUg
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32771/acme/wire/authz/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK"
  ],
  "expires": "2023-10-05T14:01:58Z",
  "notBefore": "2023-10-04T14:01:58.361809Z",
  "notAfter": "2033-10-01T14:01:58.361809Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzcxL2FjbWUvd2lyZS9hY2NvdW50LzFLcE5vMVZDM2VOT2Fkb2pjQXpqYlFMU3RHMXhxMzVRIiwidHlwIjoiSldUIiwibm9uY2UiOiJSVFYzUjNoSU1YbExNR0p3VjB0aU5YWjFlVGxNWW1GV2MyVXdUbXhOYVVnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzEvYWNtZS93aXJlL29yZGVyL01oS2VSNTVJNjV6dlRqSWhYOFcyTlVOQWt6cXFNTDhXL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCSVRDQjFBSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBRmdpREU1UVROOHl2a3FQZmd2UE5xcEU5WGhKMEpsdjBHUmFoRGtLaUltMW9IQXdiZ1lKS29aSWh2Y05BUWtPTVdFd1h6QmRCZ05WSFJFRVZqQlVoanRwYlRwM2FYSmxZWEJ3UFV4amEzTktZamMwVkcwMlRqRXlZMFJxUm5rM2JGRXZPR1UyTkRJME5ETXdaRE5pTWpoaVpVQjNhWEpsTG1OdmJZWVZhVzA2ZDJseVpXRndjRDFoYkdsalpWOTNhWEpsTUFVR0F5dGxjQU5CQU80VWpFUndJaHp2cnl2Um9kMGNTMS1NOHE5VDdUWHhOMjBkQW54VGpkcUotWUZDTmhRaUlONUdEV204NERuTmt2SlgtbjhUUUx3TXY3Y1l3akJFNGdFIn0",
  "signature": "L0dF9hJ5uKNEgmT5NCter2GpX0DYvzX3qc0bv9hc4IKnyZAyFN3qofSW35jgLLsZZneGTrLvY49ipaS07ItHDA"
}
```
```json
{
  "payload": {
    "csr": "MIIBITCB1AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAFgiDE5QTN8yvkqPfgvPNqpE9XhJ0Jlv0GRahDkKiIm1oHAwbgYJKoZIhvcNAQkOMWEwXzBdBgNVHREEVjBUhjtpbTp3aXJlYXBwPUxja3NKYjc0VG02TjEyY0RqRnk3bFEvOGU2NDI0NDMwZDNiMjhiZUB3aXJlLmNvbYYVaW06d2lyZWFwcD1hbGljZV93aXJlMAUGAytlcANBAO4UjERwIhzvryvRod0cS1-M8q9T7TXxN20dAnxTjdqJ-YFCNhQiIN5GDWm84DnNkvJX-n8TQLwMv7cYwjBE4gE"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32771/acme/wire/account/1KpNo1VC3eNOadojcAzjbQLStG1xq35Q",
    "nonce": "RTV3R3hIMXlLMGJwV0tiNXZ1eTlMYmFWc2UwTmxNaUg",
    "typ": "JWT",
    "url": "https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBITCB1AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAFgiDE5QTN8yvkqPfgvPNqpE9XhJ0Jlv
0GRahDkKiIm1oHAwbgYJKoZIhvcNAQkOMWEwXzBdBgNVHREEVjBUhjtpbTp3aXJl
YXBwPUxja3NKYjc0VG02TjEyY0RqRnk3bFEvOGU2NDI0NDMwZDNiMjhiZUB3aXJl
LmNvbYYVaW06d2lyZWFwcD1hbGljZV93aXJlMAUGAytlcANBAO4UjERwIhzvryvR
od0cS1+M8q9T7TXxN20dAnxTjdqJ+YFCNhQiIN5GDWm84DnNkvJX+n8TQLwMv7cY
wjBE4gE=
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
                    58:22:0c:4e:50:4c:df:32:be:4a:8f:7e:0b:cf:36:
                    aa:44:f5:78:49:d0:99:6f:d0:64:5a:84:39:0a:88:
                    89:b5
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        ee:14:8c:44:70:22:1c:ef:af:2b:d1:a1:dd:1c:4b:5f:8c:f2:
        af:53:ed:35:f1:37:6d:1d:02:7c:53:8d:da:89:f9:81:42:36:
        14:22:20:de:46:0d:69:bc:e0:39:cd:92:f2:57:fa:7f:13:40:
        bc:0c:bf:b7:18:c2:30:44:e2:01

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32771/acme/wire/directory>;rel="index"
location: https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W
replay-nonce: R01qSWgxV25FSDBWYW56TjE5WG5IM3FEaXB4T3F1b1Y
```
```json
{
  "certificate": "https://stepca:32771/acme/wire/certificate/leUvZchiW6iR45toJCeyFf7x1wnDBPIi",
  "status": "valid",
  "finalize": "https://stepca:32771/acme/wire/order/MhKeR55I65zvTjIhX8W2NUNAkzqqML8W/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32771/acme/wire/authz/na9wv49aMfgJhvBpM2ssWMnh5VtRw0AK"
  ],
  "expires": "2023-10-05T14:01:58Z",
  "notBefore": "2023-10-04T14:01:58.361809Z",
  "notAfter": "2033-10-01T14:01:58.361809Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32771/acme/wire/certificate/leUvZchiW6iR45toJCeyFf7x1wnDBPIi
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyNzcxL2FjbWUvd2lyZS9hY2NvdW50LzFLcE5vMVZDM2VOT2Fkb2pjQXpqYlFMU3RHMXhxMzVRIiwidHlwIjoiSldUIiwibm9uY2UiOiJSMDFxU1dneFYyNUZTREJXWVc1NlRqRTVXRzVJTTNGRWFYQjRUM0YxYjFZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI3NzEvYWNtZS93aXJlL2NlcnRpZmljYXRlL2xlVXZaY2hpVzZpUjQ1dG9KQ2V5RmY3eDF3bkRCUElpIn0",
  "payload": "",
  "signature": "swN6WWrKPuSQy-jeG5avoLHOeFN11cs8hTmw-TL-FMCUpHDTSLWIxhm7oChXe4tXBvgwjYOgxD0QkWlG_B9wAg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32771/acme/wire/account/1KpNo1VC3eNOadojcAzjbQLStG1xq35Q",
    "nonce": "R01qSWgxV25FSDBWYW56TjE5WG5IM3FEaXB4T3F1b1Y",
    "typ": "JWT",
    "url": "https://stepca:32771/acme/wire/certificate/leUvZchiW6iR45toJCeyFf7x1wnDBPIi"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32771/acme/wire/directory>;rel="index"
replay-nonce: YW9tb2RwSkJab3RYc3NOUXlzTk5GT0M5VlU0SHVocnU
```
```json
"-----BEGIN CERTIFICATE-----\nMIICDjCCAbSgAwIBAgIRAK1DlQbUQ0L9JHNF1bZj6KUwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMxMDA0MTQwMTU4WhcNMzMxMDAxMTQwMTU4WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQBYIgxOUEzfMr5Kj34L\nzzaqRPV4SdCZb9BkWoQ5CoiJtaOB5jCB4zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFFA2kJnLNbplaxYHdk4Dpd5PwkphMB8G\nA1UdIwQYMBaAFNnroB8NtWRP7G5gd0gut6ywYi8nMF0GA1UdEQRWMFSGFWltOndp\ncmVhcHA9YWxpY2Vfd2lyZYY7aW06d2lyZWFwcD1MY2tzSmI3NFRtNk4xMmNEakZ5\nN2xRLzhlNjQyNDQzMGQzYjI4YmVAd2lyZS5jb20wHQYMKwYBBAGCpGTGKEABBA0w\nCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQCjkvVPGaEULIgX5sStJeHn\n6P38nlWQqx/hUJnZu4pqwAIgXerNZnyJ+3GXiJfF7qqOFgT81SkndcKDoL50SQ7I\nBQY=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV6gAwIBAgIQJfiFPUj797UCuqEPQpqugzAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMDA0MTQw\nMTU2WhcNMzMxMDAxMTQwMTU2WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD8T\nTtbuu6f7zGfNBD/7MeMLIJBI+nXGaGcM7Tf6pvuvX/qzT/aqpBDze8bpRRA98XSJ\nqgOq+gQxoBzfqXBGBwmjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBTZ66AfDbVkT+xuYHdILressGIvJzAfBgNVHSMEGDAW\ngBSZ+ZGXjmZ5vT0hu/WqkgVTgDPs3jAKBggqhkjOPQQDAgNIADBFAiEA29/azNss\n1iOHSIpuBa4wanQRD8A+bjFwPBRqSNv29N0CIHHXBCXjWxBMtltly89W6MQizq1g\nG6AtiIMrHdSUUvi1\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICDjCCAbSgAwIBAgIRAK1DlQbUQ0L9JHNF1bZj6KUwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMxMDA0MTQwMTU4WhcNMzMxMDAxMTQwMTU4WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQBYIgxOUEzfMr5Kj34L
zzaqRPV4SdCZb9BkWoQ5CoiJtaOB5jCB4zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFFA2kJnLNbplaxYHdk4Dpd5PwkphMB8G
A1UdIwQYMBaAFNnroB8NtWRP7G5gd0gut6ywYi8nMF0GA1UdEQRWMFSGFWltOndp
cmVhcHA9YWxpY2Vfd2lyZYY7aW06d2lyZWFwcD1MY2tzSmI3NFRtNk4xMmNEakZ5
N2xRLzhlNjQyNDQzMGQzYjI4YmVAd2lyZS5jb20wHQYMKwYBBAGCpGTGKEABBA0w
CwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQCjkvVPGaEULIgX5sStJeHn
6P38nlWQqx/hUJnZu4pqwAIgXerNZnyJ+3GXiJfF7qqOFgT81SkndcKDoL50SQ7I
BQY=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ad:43:95:06:d4:43:42:fd:24:73:45:d5:b6:63:e8:a5
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Oct  4 14:01:58 2023 GMT
            Not After : Oct  1 14:01:58 2033 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    58:22:0c:4e:50:4c:df:32:be:4a:8f:7e:0b:cf:36:
                    aa:44:f5:78:49:d0:99:6f:d0:64:5a:84:39:0a:88:
                    89:b5
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                50:36:90:99:CB:35:BA:65:6B:16:07:76:4E:03:A5:DE:4F:C2:4A:61
            X509v3 Authority Key Identifier: 
                D9:EB:A0:1F:0D:B5:64:4F:EC:6E:60:77:48:2E:B7:AC:B0:62:2F:27
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=alice_wire, URI:im:wireapp=LcksJb74Tm6N12cDjFy7lQ/8e6424430d3b28be@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:a3:92:f5:4f:19:a1:14:2c:88:17:e6:c4:ad:
        25:e1:e7:e8:fd:fc:9e:55:90:ab:1f:e1:50:99:d9:bb:8a:6a:
        c0:02:20:5d:ea:cd:66:7c:89:fb:71:97:88:97:c5:ee:aa:8e:
        16:04:fc:d5:29:27:75:c2:83:a0:be:74:49:0e:c8:05:06

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQJfiFPUj797UCuqEPQpqugzAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMDA0MTQw
MTU2WhcNMzMxMDAxMTQwMTU2WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD8T
Ttbuu6f7zGfNBD/7MeMLIJBI+nXGaGcM7Tf6pvuvX/qzT/aqpBDze8bpRRA98XSJ
qgOq+gQxoBzfqXBGBwmjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBTZ66AfDbVkT+xuYHdILressGIvJzAfBgNVHSMEGDAW
gBSZ+ZGXjmZ5vT0hu/WqkgVTgDPs3jAKBggqhkjOPQQDAgNIADBFAiEA29/azNss
1iOHSIpuBa4wanQRD8A+bjFwPBRqSNv29N0CIHHXBCXjWxBMtltly89W6MQizq1g
G6AtiIMrHdSUUvi1
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            25:f8:85:3d:48:fb:f7:b5:02:ba:a1:0f:42:9a:ae:83
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Oct  4 14:01:56 2023 GMT
            Not After : Oct  1 14:01:56 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:3f:13:4e:d6:ee:bb:a7:fb:cc:67:cd:04:3f:fb:
                    31:e3:0b:20:90:48:fa:75:c6:68:67:0c:ed:37:fa:
                    a6:fb:af:5f:fa:b3:4f:f6:aa:a4:10:f3:7b:c6:e9:
                    45:10:3d:f1:74:89:aa:03:aa:fa:04:31:a0:1c:df:
                    a9:70:46:07:09
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                D9:EB:A0:1F:0D:B5:64:4F:EC:6E:60:77:48:2E:B7:AC:B0:62:2F:27
            X509v3 Authority Key Identifier: 
                99:F9:91:97:8E:66:79:BD:3D:21:BB:F5:AA:92:05:53:80:33:EC:DE
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:db:df:da:cc:db:2c:d6:23:87:48:8a:6e:05:
        ae:30:6a:74:11:0f:c0:3e:6e:31:70:3c:14:6a:48:db:f6:f4:
        dd:02:20:71:d7:04:25:e3:5b:10:4c:b6:5b:65:cb:cf:56:e8:
        c4:22:ce:ad:60:1b:a0:2d:88:83:2b:1d:d4:94:52:f8:b5

```
