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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/84cdc209f1eaaa5e/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/XIjynMkkw0ZJmGBBosKBrpPwycf9tsis
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/o04FcAcMYTQoxiLb0TW7UgrNv3TXJe40
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/1EcR76auxrrnjhSK2nk2vuKdIoNRIDOA
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32803/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
vary: Origin
```
```json
{
  "newNonce": "https://stepca:32803/acme/wire/new-nonce",
  "newAccount": "https://stepca:32803/acme/wire/new-account",
  "newOrder": "https://stepca:32803/acme/wire/new-order",
  "revokeCert": "https://stepca:32803/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32803/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32803/acme/wire/directory>;rel="index"
replay-nonce: UmR5V1RnTEhDTnQ5bHpoUW4zWkc0ZjJ3UWZLN1BsdXg
vary: Origin
```
```text
UmR5V1RnTEhDTnQ5bHpoUW4zWkc0ZjJ3UWZLN1BsdXg
```
#### 5. create a new account
```http request
POST https://stepca:32803/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im5CYXFCRExPWkNMSjlabmxtRFVMLUhod25tckhMLUM4Q2ZyWXd0ckxDMzgifSwibm9uY2UiOiJVbVI1VjFSblRFaERUblE1Ykhwb1VXNHpXa2MwWmpKM1VXWkxOMUJzZFhnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MDMvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "8qK0furAwN7mLrIAm3C5neDLH9ksIpk3stNeSUBQv4N9NMQtG-24sjnUR9PmV6mBl3BxZxuLH0uoVGL3ZqhRDA"
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
      "x": "nBaqBDLOZCLJ9ZnlmDUL-HhwnmrHL-C8CfrYwtrLC38"
    },
    "nonce": "UmR5V1RnTEhDTnQ5bHpoUW4zWkc0ZjJ3UWZLN1BsdXg",
    "typ": "JWT",
    "url": "https://stepca:32803/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32803/acme/wire/directory>;rel="index"
location: https://stepca:32803/acme/wire/account/RZufznFJkQpnQFTLr5X5WvSnLlDrhPRx
replay-nonce: ZzhOMnJwQkEyN2Y2UUM3N2pRZVN6dnY2all4YzJ5Z1I
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32803/acme/wire/account/RZufznFJkQpnQFTLr5X5WvSnLlDrhPRx/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32803/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODAzL2FjbWUvd2lyZS9hY2NvdW50L1JadWZ6bkZKa1FwblFGVExyNVg1V3ZTbkxsRHJoUFJ4IiwidHlwIjoiSldUIiwibm9uY2UiOiJaemhPTW5Kd1FrRXlOMlkyVVVNM04ycFJaVk42ZG5ZMmFsbDRZeko1WjFJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MDMvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9S1BycVY2N1VSQ09IRktrNHlLSVhaUS84NGNkYzIwOWYxZWFhYTVlQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0xMS0yM1QxNDoxODoxMi44NjQyMjJaIiwibm90QWZ0ZXIiOiIyMDMzLTExLTIwVDE0OjE4OjEyLjg2NDIyMloifQ",
  "signature": "lnbacdM2uEV5VI5wiY9DnM_Tn-0FLPIkkOjXKy7oSGpuAF1PcIuaQw9RHxS2pAtGypr3QXT0j9CRQDHIjzBVAg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2033-11-20T14:18:12.864222Z",
    "notBefore": "2023-11-23T14:18:12.864222Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32803/acme/wire/account/RZufznFJkQpnQFTLr5X5WvSnLlDrhPRx",
    "nonce": "ZzhOMnJwQkEyN2Y2UUM3N2pRZVN6dnY2all4YzJ5Z1I",
    "typ": "JWT",
    "url": "https://stepca:32803/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32803/acme/wire/directory>;rel="index"
location: https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76
replay-nonce: TWdUSHpRa3pZY2x3ckgxS2hZajhPOFJWT29sSXJOYkQ
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32803/acme/wire/authz/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J"
  ],
  "expires": "2023-11-24T14:18:12Z",
  "notBefore": "2023-11-23T14:18:12.864222Z",
  "notAfter": "2033-11-20T14:18:12.864222Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32803/acme/wire/authz/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODAzL2FjbWUvd2lyZS9hY2NvdW50L1JadWZ6bkZKa1FwblFGVExyNVg1V3ZTbkxsRHJoUFJ4IiwidHlwIjoiSldUIiwibm9uY2UiOiJUV2RVU0hwUmEzcFpZMngzY2tneFMyaFphamhQT0ZKV1QyOXNTWEpPWWtRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MDMvYWNtZS93aXJlL2F1dGh6L2hIejdOOFFrNUh1QUVWdXg2VUpDeFlyNlBjclBpYzVKIn0",
  "payload": "",
  "signature": "-pOGPW3KzjP9FBU1_V5u5b7Q-18xSuJkWANqbwkWJCUvwMXFeQGBus-b20tdNT07xkfXi426jYU5f6ZGnQ_HAA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32803/acme/wire/account/RZufznFJkQpnQFTLr5X5WvSnLlDrhPRx",
    "nonce": "TWdUSHpRa3pZY2x3ckgxS2hZajhPOFJWT29sSXJOYkQ",
    "typ": "JWT",
    "url": "https://stepca:32803/acme/wire/authz/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32803/acme/wire/directory>;rel="index"
location: https://stepca:32803/acme/wire/authz/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J
replay-nonce: R0RBcjRxdjBTY1g4SlVuTlFIcThzYTA5MktyY3I4UVk
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2023-11-24T14:18:12Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/o04FcAcMYTQoxiLb0TW7UgrNv3TXJe40",
      "status": "pending",
      "token": "fMw6wdUZL0KgBzxFRsAXLLIQD2Ywv0MQ",
      "target": "http://dex:22930/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/XIjynMkkw0ZJmGBBosKBrpPwycf9tsis",
      "status": "pending",
      "token": "fMw6wdUZL0KgBzxFRsAXLLIQD2Ywv0MQ",
      "target": "http://wire.com:24401/clients/84cdc209f1eaaa5e/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:24401/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
M1FxTzJ0dWdFbTNxRHZRMlNwY3dhem1kRlhLMEkxeGc
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoibkJhcUJETE9aQ0xKOVpubG1EVUwtSGh3bm1ySEwtQzhDZnJZd3RyTEMzOCJ9fQ.eyJpYXQiOjE3MDA3NDU0OTIsImV4cCI6MTcwMDc1MjY5MiwibmJmIjoxNzAwNzQ1NDkyLCJzdWIiOiJpbTp3aXJlYXBwPUtQcnFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJlLmNvbSIsImp0aSI6IjlhOGY3MDM5LTFjMzktNDcyZS1hYmE4LTY3YjdlYjU0YjViNiIsIm5vbmNlIjoiTTFGeFR6SjBkV2RGYlROeFJIWlJNbE53WTNkaGVtMWtSbGhMTUVreGVHYyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ0MDEvY2xpZW50cy84NGNkYzIwOWYxZWFhYTVlL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJmTXc2d2RVWkwwS2dCenhGUnNBWExMSVFEMll3djBNUSIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.ins06-1UH7HFvszWMWWkduzL-gkz1HC5CgNhvHNiFS2tl6i4deytJ8EQVWiU4kG7fNf8krhj2_-oyqY4NT8iCw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoibkJhcUJETE9aQ0xKOVpubG1EVUwtSGh3
bm1ySEwtQzhDZnJZd3RyTEMzOCJ9fQ.eyJpYXQiOjE3MDA3NDU0OTIsImV4cCI6M
TcwMDc1MjY5MiwibmJmIjoxNzAwNzQ1NDkyLCJzdWIiOiJpbTp3aXJlYXBwPUtQc
nFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJlLmNvbSIsI
mp0aSI6IjlhOGY3MDM5LTFjMzktNDcyZS1hYmE4LTY3YjdlYjU0YjViNiIsIm5vb
mNlIjoiTTFGeFR6SjBkV2RGYlROeFJIWlJNbE53WTNkaGVtMWtSbGhMTUVreGVHY
yIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ0MDEvY2xpZ
W50cy84NGNkYzIwOWYxZWFhYTVlL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJmTXc2d
2RVWkwwS2dCenhGUnNBWExMSVFEMll3djBNUSIsImhhbmRsZSI6ImltOndpcmVhc
HA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.ins06-1UH
7HFvszWMWWkduzL-gkz1HC5CgNhvHNiFS2tl6i4deytJ8EQVWiU4kG7fNf8krhj2
_-oyqY4NT8iCw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "nBaqBDLOZCLJ9ZnlmDUL-HhwnmrHL-C8CfrYwtrLC38"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "fMw6wdUZL0KgBzxFRsAXLLIQD2Ywv0MQ",
  "exp": 1700752692,
  "handle": "im:wireapp=%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:24401/clients/84cdc209f1eaaa5e/access-token",
  "iat": 1700745492,
  "jti": "9a8f7039-1c39-472e-aba8-67b7eb54b5b6",
  "nbf": 1700745492,
  "nonce": "M1FxTzJ0dWdFbTNxRHZRMlNwY3dhem1kRlhLMEkxeGc",
  "sub": "im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEICHJWZbIckZvrdT8EsFtxCo6yQP822OLmsBv2vcTnGZq
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAnBaqBDLOZCLJ9ZnlmDUL+HhwnmrHL+C8CfrYwtrLC38=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:24401/clients/84cdc209f1eaaa5e/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pYmtKaGNVSkVURTlhUTB4S09WcHViRzFFVlV3dFNHaDNibTF5U0V3dFF6aERabkpaZDNSeVRFTXpPQ0o5ZlEuZXlKcFlYUWlPakUzTURBM05EVTBPVElzSW1WNGNDSTZNVGN3TURjMU1qWTVNaXdpYm1KbUlqb3hOekF3TnpRMU5Ea3lMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVXRRY25GV05qZFZVa05QU0VaTGF6UjVTMGxZV2xFdk9EUmpaR015TURsbU1XVmhZV0UxWlVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpsaE9HWTNNRE01TFRGak16a3RORGN5WlMxaFltRTRMVFkzWWpkbFlqVTBZalZpTmlJc0ltNXZibU5sSWpvaVRURkdlRlI2U2pCa1YyUkdZbFJPZUZKSVdsSk5iRTUzV1ROa2FHVnRNV3RTYkdoTVRVVnJlR1ZIWXlJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1qUTBNREV2WTJ4cFpXNTBjeTg0TkdOa1l6SXdPV1l4WldGaFlUVmxMMkZqWTJWemN5MTBiMnRsYmlJc0ltTm9ZV3dpT2lKbVRYYzJkMlJWV2t3d1MyZENlbmhHVW5OQldFeE1TVkZFTWxsM2RqQk5VU0lzSW1oaGJtUnNaU0k2SW1sdE9uZHBjbVZoY0hBOUpUUXdZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW5SbFlXMGlPaUozYVhKbEluMC5pbnMwNi0xVUg3SEZ2c3pXTVdXa2R1ekwtZ2t6MUhDNUNnTmh2SE5pRlMydGw2aTRkZXl0SjhFUVZXaVU0a0c3Zk5mOGtyaGoyXy1veXFZNE5UOGlDdw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im0xLW1nTVZub3JaVGs5ZHE4bkJiVUotbnkxWkxTRVowUkFPSVpjb2RGTVkifX0.eyJpYXQiOjE3MDA3NDU0OTIsImV4cCI6MTcwMDc0OTQ1MiwibmJmIjoxNzAwNzQ1NDkyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ0MDEvY2xpZW50cy84NGNkYzIwOWYxZWFhYTVlL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9S1BycVY2N1VSQ09IRktrNHlLSVhaUS84NGNkYzIwOWYxZWFhYTVlQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NDAxL2NsaWVudHMvODRjZGMyMDlmMWVhYWE1ZS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhY2QyOTUxMy05M2RmLTQ5OGItYjI2ZC0yMDkzMGMxNzk3MjgiLCJub25jZSI6Ik0xRnhUekowZFdkRmJUTnhSSFpSTWxOd1kzZGhlbTFrUmxoTE1Fa3hlR2MiLCJjaGFsIjoiZk13NndkVVpMMEtnQnp4RlJzQVhMTElRRDJZd3YwTVEiLCJjbmYiOnsia2lkIjoidUl1c2hWU1lQLTBBTHEwVE5VQnk5eVBVSFlJMnZrSUFlNDZVa1VON05EbyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWJrSmhjVUpFVEU5YVEweEtPVnB1YkcxRVZVd3RTR2gzYm0xeVNFd3RRemhEWm5KWmQzUnlURU16T0NKOWZRLmV5SnBZWFFpT2pFM01EQTNORFUwT1RJc0ltVjRjQ0k2TVRjd01EYzFNalk1TWl3aWJtSm1Jam94TnpBd056UTFORGt5TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFV0UWNuRldOamRWVWtOUFNFWkxhelI1UzBsWVdsRXZPRFJqWkdNeU1EbG1NV1ZoWVdFMVpVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqbGhPR1kzTURNNUxURmpNemt0TkRjeVpTMWhZbUU0TFRZM1lqZGxZalUwWWpWaU5pSXNJbTV2Ym1ObElqb2lUVEZHZUZSNlNqQmtWMlJHWWxST2VGSklXbEpOYkU1M1dUTmthR1Z0TVd0U2JHaE1UVVZyZUdWSFl5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEwTURFdlkyeHBaVzUwY3k4NE5HTmtZekl3T1dZeFpXRmhZVFZsTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSm1UWGMyZDJSVldrd3dTMmRDZW5oR1VuTkJXRXhNU1ZGRU1sbDNkakJOVVNJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuaW5zMDYtMVVIN0hGdnN6V01XV2tkdXpMLWdrejFIQzVDZ05odkhOaUZTMnRsNmk0ZGV5dEo4RVFWV2lVNGtHN2ZOZjhrcmhqMl8tb3lxWTROVDhpQ3ciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUtQcnFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.HwERphUljxk-Kc0RrqKr2zEIRoMdSFk7pFK4byGSQdxW4ZyItpUTkSyxuzvI0Z9EC2XGykYWkV3dxzAXrpJTDw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im0xLW1nTVZub3JaVGs5ZHE4bkJiVUotbnkxWkxTRVowUkFPSVpjb2RGTVkifX0.eyJpYXQiOjE3MDA3NDU0OTIsImV4cCI6MTcwMDc0OTQ1MiwibmJmIjoxNzAwNzQ1NDkyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ0MDEvY2xpZW50cy84NGNkYzIwOWYxZWFhYTVlL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9S1BycVY2N1VSQ09IRktrNHlLSVhaUS84NGNkYzIwOWYxZWFhYTVlQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NDAxL2NsaWVudHMvODRjZGMyMDlmMWVhYWE1ZS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhY2QyOTUxMy05M2RmLTQ5OGItYjI2ZC0yMDkzMGMxNzk3MjgiLCJub25jZSI6Ik0xRnhUekowZFdkRmJUTnhSSFpSTWxOd1kzZGhlbTFrUmxoTE1Fa3hlR2MiLCJjaGFsIjoiZk13NndkVVpMMEtnQnp4RlJzQVhMTElRRDJZd3YwTVEiLCJjbmYiOnsia2lkIjoidUl1c2hWU1lQLTBBTHEwVE5VQnk5eVBVSFlJMnZrSUFlNDZVa1VON05EbyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWJrSmhjVUpFVEU5YVEweEtPVnB1YkcxRVZVd3RTR2gzYm0xeVNFd3RRemhEWm5KWmQzUnlURU16T0NKOWZRLmV5SnBZWFFpT2pFM01EQTNORFUwT1RJc0ltVjRjQ0k2TVRjd01EYzFNalk1TWl3aWJtSm1Jam94TnpBd056UTFORGt5TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFV0UWNuRldOamRWVWtOUFNFWkxhelI1UzBsWVdsRXZPRFJqWkdNeU1EbG1NV1ZoWVdFMVpVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqbGhPR1kzTURNNUxURmpNemt0TkRjeVpTMWhZbUU0TFRZM1lqZGxZalUwWWpWaU5pSXNJbTV2Ym1ObElqb2lUVEZHZUZSNlNqQmtWMlJHWWxST2VGSklXbEpOYkU1M1dUTmthR1Z0TVd0U2JHaE1UVVZyZUdWSFl5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEwTURFdlkyeHBaVzUwY3k4NE5HTmtZekl3T1dZeFpXRmhZVFZsTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSm1UWGMyZDJSVldrd3dTMmRDZW5oR1VuTkJXRXhNU1ZGRU1sbDNkakJOVVNJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuaW5zMDYtMVVIN0hGdnN6V01XV2tkdXpMLWdrejFIQzVDZ05odkhOaUZTMnRsNmk0ZGV5dEo4RVFWV2lVNGtHN2ZOZjhrcmhqMl8tb3lxWTROVDhpQ3ciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUtQcnFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.HwERphUljxk-Kc0RrqKr2zEIRoMdSFk7pFK4byGSQdxW4ZyItpUTkSyxuzvI0Z9EC2XGykYWkV3dxzAXrpJTDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6Im0xLW1nTVZub3JaVGs5ZHE4bkJiVUotbnkx
WkxTRVowUkFPSVpjb2RGTVkifX0.eyJpYXQiOjE3MDA3NDU0OTIsImV4cCI6MTcw
MDc0OTQ1MiwibmJmIjoxNzAwNzQ1NDkyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjQ0MDEvY2xpZW50cy84NGNkYzIwOWYxZWFhYTVlL2FjY2Vzcy10b2tlbiIsInN1
YiI6ImltOndpcmVhcHA9S1BycVY2N1VSQ09IRktrNHlLSVhaUS84NGNkYzIwOWYx
ZWFhYTVlQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NDAxL2Ns
aWVudHMvODRjZGMyMDlmMWVhYWE1ZS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhY2Qy
OTUxMy05M2RmLTQ5OGItYjI2ZC0yMDkzMGMxNzk3MjgiLCJub25jZSI6Ik0xRnhU
ekowZFdkRmJUTnhSSFpSTWxOd1kzZGhlbTFrUmxoTE1Fa3hlR2MiLCJjaGFsIjoi
Zk13NndkVVpMMEtnQnp4RlJzQVhMTElRRDJZd3YwTVEiLCJjbmYiOnsia2lkIjoi
dUl1c2hWU1lQLTBBTHEwVE5VQnk5eVBVSFlJMnZrSUFlNDZVa1VON05EbyJ9LCJw
cm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJ
aXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lM
Q0o0SWpvaWJrSmhjVUpFVEU5YVEweEtPVnB1YkcxRVZVd3RTR2gzYm0xeVNFd3RR
emhEWm5KWmQzUnlURU16T0NKOWZRLmV5SnBZWFFpT2pFM01EQTNORFUwT1RJc0lt
VjRjQ0k2TVRjd01EYzFNalk1TWl3aWJtSm1Jam94TnpBd056UTFORGt5TENKemRX
SWlPaUpwYlRwM2FYSmxZWEJ3UFV0UWNuRldOamRWVWtOUFNFWkxhelI1UzBsWVds
RXZPRFJqWkdNeU1EbG1NV1ZoWVdFMVpVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklq
bGhPR1kzTURNNUxURmpNemt0TkRjeVpTMWhZbUU0TFRZM1lqZGxZalUwWWpWaU5p
SXNJbTV2Ym1ObElqb2lUVEZHZUZSNlNqQmtWMlJHWWxST2VGSklXbEpOYkU1M1dU
TmthR1Z0TVd0U2JHaE1UVVZyZUdWSFl5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RI
VWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEwTURFdlkyeHBaVzUwY3k4NE5H
TmtZekl3T1dZeFpXRmhZVFZsTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9p
Sm1UWGMyZDJSVldrd3dTMmRDZW5oR1VuTkJXRXhNU1ZGRU1sbDNkakJOVVNJc0lt
aGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FY
SmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuaW5zMDYtMVVIN0hGdnN6V01X
V2tkdXpMLWdrejFIQzVDZ05odkhOaUZTMnRsNmk0ZGV5dEo4RVFWV2lVNGtHN2ZO
ZjhrcmhqMl8tb3lxWTROVDhpQ3ciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUtQ
cnFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJlLmNvbSIs
ImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.HwERphUl
jxk-Kc0RrqKr2zEIRoMdSFk7pFK4byGSQdxW4ZyItpUTkSyxuzvI0Z9EC2XGykYW
kV3dxzAXrpJTDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "m1-mgMVnorZTk9dq8nBbUJ-ny1ZLSEZ0RAOIZcodFMY"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:24401/clients/84cdc209f1eaaa5e/access-token",
  "chal": "fMw6wdUZL0KgBzxFRsAXLLIQD2Ywv0MQ",
  "client_id": "im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com",
  "cnf": {
    "kid": "uIushVSYP-0ALq0TNUBy9yPUHYI2vkIAe46UkUN7NDo"
  },
  "exp": 1700749452,
  "iat": 1700745492,
  "iss": "http://wire.com:24401/clients/84cdc209f1eaaa5e/access-token",
  "jti": "acd29513-93df-498b-b26d-20930c179728",
  "nbf": 1700745492,
  "nonce": "M1FxTzJ0dWdFbTNxRHZRMlNwY3dhem1kRlhLMEkxeGc",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoibkJhcUJETE9aQ0xKOVpubG1EVUwtSGh3bm1ySEwtQzhDZnJZd3RyTEMzOCJ9fQ.eyJpYXQiOjE3MDA3NDU0OTIsImV4cCI6MTcwMDc1MjY5MiwibmJmIjoxNzAwNzQ1NDkyLCJzdWIiOiJpbTp3aXJlYXBwPUtQcnFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJlLmNvbSIsImp0aSI6IjlhOGY3MDM5LTFjMzktNDcyZS1hYmE4LTY3YjdlYjU0YjViNiIsIm5vbmNlIjoiTTFGeFR6SjBkV2RGYlROeFJIWlJNbE53WTNkaGVtMWtSbGhMTUVreGVHYyIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MjQ0MDEvY2xpZW50cy84NGNkYzIwOWYxZWFhYTVlL2FjY2Vzcy10b2tlbiIsImNoYWwiOiJmTXc2d2RVWkwwS2dCenhGUnNBWExMSVFEMll3djBNUSIsImhhbmRsZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInRlYW0iOiJ3aXJlIn0.ins06-1UH7HFvszWMWWkduzL-gkz1HC5CgNhvHNiFS2tl6i4deytJ8EQVWiU4kG7fNf8krhj2_-oyqY4NT8iCw",
  "scope": "wire_client_id",
  "sub": "im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPSspzoUcjzEDxCVKO0B/FjQAp0ezGLOu29dkscnB3sw
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAm1+mgMVnorZTk9dq8nBbUJ+ny1ZLSEZ0RAOIZcodFMY=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/XIjynMkkw0ZJmGBBosKBrpPwycf9tsis
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODAzL2FjbWUvd2lyZS9hY2NvdW50L1JadWZ6bkZKa1FwblFGVExyNVg1V3ZTbkxsRHJoUFJ4IiwidHlwIjoiSldUIiwibm9uY2UiOiJSMFJCY2pSeGRqQlRZMWc0U2xWdVRsRkljVGh6WVRBNU1rdHlZM0k0VVZrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MDMvYWNtZS93aXJlL2NoYWxsZW5nZS9oSHo3TjhRazVIdUFFVnV4NlVKQ3hZcjZQY3JQaWM1Si9YSWp5bk1ra3cwWkptR0JCb3NLQnJwUHd5Y2Y5dHNpcyJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltMHhMVzFuVFZadWIzSmFWR3M1WkhFNGJrSmlWVW90Ym5reFdreFRSVm93VWtGUFNWcGpiMlJHVFZraWZYMC5leUpwWVhRaU9qRTNNREEzTkRVME9USXNJbVY0Y0NJNk1UY3dNRGMwT1RRMU1pd2libUptSWpveE56QXdOelExTkRreUxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpRME1ERXZZMnhwWlc1MGN5ODROR05rWXpJd09XWXhaV0ZoWVRWbEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbWx0T25kcGNtVmhjSEE5UzFCeWNWWTJOMVZTUTA5SVJrdHJOSGxMU1ZoYVVTODROR05rWXpJd09XWXhaV0ZoWVRWbFFIZHBjbVV1WTI5dElpd2lZWFZrSWpvaWFIUjBjRG92TDNkcGNtVXVZMjl0T2pJME5EQXhMMk5zYVdWdWRITXZPRFJqWkdNeU1EbG1NV1ZoWVdFMVpTOWhZMk5sYzNNdGRHOXJaVzRpTENKcWRHa2lPaUpoWTJReU9UVXhNeTA1TTJSbUxUUTVPR0l0WWpJMlpDMHlNRGt6TUdNeE56azNNamdpTENKdWIyNWpaU0k2SWsweFJuaFVla293WkZka1JtSlVUbmhTU0ZwU1RXeE9kMWt6WkdobGJURnJVbXhvVEUxRmEzaGxSMk1pTENKamFHRnNJam9pWmsxM05uZGtWVnBNTUV0blFucDRSbEp6UVZoTVRFbFJSREpaZDNZd1RWRWlMQ0pqYm1ZaU9uc2lhMmxrSWpvaWRVbDFjMmhXVTFsUUxUQkJUSEV3VkU1VlFuazVlVkJWU0ZsSk1uWnJTVUZsTkRaVmExVk9OMDVFYnlKOUxDSndjbTl2WmlJNkltVjVTbWhpUjJOcFQybEtSbHBGVWxSUlUwbHpTVzVTTldORFNUWkpiVkozWWpOQmNtRnVaREJKYVhkcFlXNWtja2xxY0RkSmJYUXdaVk5KTmtsck9VeFZRMGx6U1cxT2VXUnBTVFpKYTFaclRXcFZNVTFVYTJsTVEwbzBTV3B2YVdKclNtaGpWVXBGVkVVNVlWRXdlRXRQVm5CMVlrY3hSVlpWZDNSVFIyZ3pZbTB4ZVZORmQzUlJlbWhFV201S1dtUXpVbmxVUlUxNlQwTktPV1pSTG1WNVNuQlpXRkZwVDJwRk0wMUVRVE5PUkZVd1QxUkpjMGx0VmpSalEwazJUVlJqZDAxRVl6Rk5hbGsxVFdsM2FXSnRTbTFKYW05NFRucEJkMDU2VVRGT1JHdDVURU5LZW1SWFNXbFBhVXB3WWxSd00yRllTbXhaV0VKM1VGVjBVV051UmxkT2FtUldWV3RPVUZORldreGhlbEkxVXpCc1dWZHNSWFpQUkZKcVdrZE5lVTFFYkcxTlYxWm9XVmRGTVZwVlFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2xxYkdoUFIxa3pUVVJOTlV4VVJtcE5lbXQwVGtSamVWcFRNV2haYlVVMFRGUlpNMWxxWkd4WmFsVXdXV3BXYVU1cFNYTkpiVFYyWW0xT2JFbHFiMmxVVkVaSFpVWlNObE5xUW10V01sSkhXV3hTVDJWR1NrbFhiRXBPWWtVMU0xZFVUbXRoUjFaMFRWZDBVMkpIYUUxVVZWWnlaVWRXU0ZsNVNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpOYWxFd1RVUkZkbGt5ZUhCYVZ6VXdZM2s0TkU1SFRtdFpla2wzVDFkWmVGcFhSbWhaVkZac1RESkdhbGt5Vm5wamVURXdZakowYkdKcFNYTkpiVTV2V1ZkM2FVOXBTbTFVV0dNeVpESlNWbGRyZDNkVE1tUkRaVzVvUjFWdVRrSlhSWGhOVTFaR1JVMXNiRE5rYWtKT1ZWTkpjMGx0YUdoaWJWSnpXbE5KTmtsdGJIUlBibVJ3WTIxV2FHTklRVGxLVkZGM1dWZDRjRmt5Vm1aa01teDVXbFZDTTJGWVNteE1iVTUyWWxOSmMwbHVVbXhaVnpCcFQybEtNMkZZU214SmJqQXVhVzV6TURZdE1WVklOMGhHZG5ONlYwMVhWMnRrZFhwTUxXZHJlakZJUXpWRFowNW9ka2hPYVVaVE1uUnNObWswWkdWNWRFbzRSVkZXVjJsVk5HdEhOMlpPWmpocmNtaHFNbDh0YjNseFdUUk9WRGhwUTNjaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFV0UWNuRldOamRWVWtOUFNFWkxhelI1UzBsWVdsRXZPRFJqWkdNeU1EbG1NV1ZoWVdFMVpVQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvMUxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLkh3RVJwaFVsanhrLUtjMFJycUtyMnpFSVJvTWRTRms3cEZLNGJ5R1NRZHhXNFp5SXRwVVRrU3l4dXp2STBaOUVDMlhHeWtZV2tWM2R4ekFYcnBKVER3In0",
  "signature": "nAL6OxS6hjsKm2JuREOQk1bEmvugRm2poHJIvV0NpbztYsmFP6N9d2UXFZIrCZ3ain_Dx-vhSYLDbAHKezpFDg"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Im0xLW1nTVZub3JaVGs5ZHE4bkJiVUotbnkxWkxTRVowUkFPSVpjb2RGTVkifX0.eyJpYXQiOjE3MDA3NDU0OTIsImV4cCI6MTcwMDc0OTQ1MiwibmJmIjoxNzAwNzQ1NDkyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjQ0MDEvY2xpZW50cy84NGNkYzIwOWYxZWFhYTVlL2FjY2Vzcy10b2tlbiIsInN1YiI6ImltOndpcmVhcHA9S1BycVY2N1VSQ09IRktrNHlLSVhaUS84NGNkYzIwOWYxZWFhYTVlQHdpcmUuY29tIiwiYXVkIjoiaHR0cDovL3dpcmUuY29tOjI0NDAxL2NsaWVudHMvODRjZGMyMDlmMWVhYWE1ZS9hY2Nlc3MtdG9rZW4iLCJqdGkiOiJhY2QyOTUxMy05M2RmLTQ5OGItYjI2ZC0yMDkzMGMxNzk3MjgiLCJub25jZSI6Ik0xRnhUekowZFdkRmJUTnhSSFpSTWxOd1kzZGhlbTFrUmxoTE1Fa3hlR2MiLCJjaGFsIjoiZk13NndkVVpMMEtnQnp4RlJzQVhMTElRRDJZd3YwTVEiLCJjbmYiOnsia2lkIjoidUl1c2hWU1lQLTBBTHEwVE5VQnk5eVBVSFlJMnZrSUFlNDZVa1VON05EbyJ9LCJwcm9vZiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJbVJ3YjNBcmFuZDBJaXdpYW5kcklqcDdJbXQwZVNJNklrOUxVQ0lzSW1OeWRpSTZJa1ZrTWpVMU1Ua2lMQ0o0SWpvaWJrSmhjVUpFVEU5YVEweEtPVnB1YkcxRVZVd3RTR2gzYm0xeVNFd3RRemhEWm5KWmQzUnlURU16T0NKOWZRLmV5SnBZWFFpT2pFM01EQTNORFUwT1RJc0ltVjRjQ0k2TVRjd01EYzFNalk1TWl3aWJtSm1Jam94TnpBd056UTFORGt5TENKemRXSWlPaUpwYlRwM2FYSmxZWEJ3UFV0UWNuRldOamRWVWtOUFNFWkxhelI1UzBsWVdsRXZPRFJqWkdNeU1EbG1NV1ZoWVdFMVpVQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqbGhPR1kzTURNNUxURmpNemt0TkRjeVpTMWhZbUU0TFRZM1lqZGxZalUwWWpWaU5pSXNJbTV2Ym1ObElqb2lUVEZHZUZSNlNqQmtWMlJHWWxST2VGSklXbEpOYkU1M1dUTmthR1Z0TVd0U2JHaE1UVVZyZUdWSFl5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNalEwTURFdlkyeHBaVzUwY3k4NE5HTmtZekl3T1dZeFpXRmhZVFZsTDJGalkyVnpjeTEwYjJ0bGJpSXNJbU5vWVd3aU9pSm1UWGMyZDJSVldrd3dTMmRDZW5oR1VuTkJXRXhNU1ZGRU1sbDNkakJOVVNJc0ltaGhibVJzWlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luUmxZVzBpT2lKM2FYSmxJbjAuaW5zMDYtMVVIN0hGdnN6V01XV2tkdXpMLWdrejFIQzVDZ05odkhOaUZTMnRsNmk0ZGV5dEo4RVFWV2lVNGtHN2ZOZjhrcmhqMl8tb3lxWTROVDhpQ3ciLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPUtQcnFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjo1LCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.HwERphUljxk-Kc0RrqKr2zEIRoMdSFk7pFK4byGSQdxW4ZyItpUTkSyxuzvI0Z9EC2XGykYWkV3dxzAXrpJTDw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32803/acme/wire/account/RZufznFJkQpnQFTLr5X5WvSnLlDrhPRx",
    "nonce": "R0RBcjRxdjBTY1g4SlVuTlFIcThzYTA5MktyY3I4UVk",
    "typ": "JWT",
    "url": "https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/XIjynMkkw0ZJmGBBosKBrpPwycf9tsis"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32803/acme/wire/directory>;rel="index"
link: <https://stepca:32803/acme/wire/authz/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J>;rel="up"
location: https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/XIjynMkkw0ZJmGBBosKBrpPwycf9tsis
replay-nonce: Rm5KNWdha0ZXenFEVnBGaVlNM09QNkJpRHJFUE9kem0
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/XIjynMkkw0ZJmGBBosKBrpPwycf9tsis",
  "status": "valid",
  "token": "fMw6wdUZL0KgBzxFRsAXLLIQD2Ywv0MQ",
  "target": "http://wire.com:24401/clients/84cdc209f1eaaa5e/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=e_rb0mEI6iISTPBR-HcZSFt1tV4x76RP26pgWUiixB8&code_challenge=ICROlyRk7qQ5U2n7Tx8T1F6aRlaT0Jn3859YaxnnaI0
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:22930/dex/auth?response_type=code&client_id=wireapp&state=rGhmGIqqC_Sl309xyghcEg&code_challenge=ICROlyRk7qQ5U2n7Tx8T1F6aRlaT0Jn3859YaxnnaI0&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A24401%2Fcallback&scope=openid+profile&nonce=92xCaNfN6vu5L8jajTFimQ
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:22930/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpORmM0Um1KT1V6Vm5XV052TnpkdlVEQTFaRlY2VGt0VQ==
```
```text
grant_type=authorization_code&code=nzcqtgk7tm45jybcg6ucuq65k&code_verifier=e_rb0mEI6iISTPBR-HcZSFt1tV4x76RP26pgWUiixB8&redirect_uri=http%3A%2F%2Fwire.com%3A24401%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImUyZDQ4NGQ0NzkyYmMxZDEwYTg1M2RhMjVlNTI0YzY3ZDAzYjlhYjgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyOTMwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXRRY25GV05qZFZVa05QU0VaTGF6UjVTMGxZV2xFdk9EUmpaR015TURsbU1XVmhZV0UxWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4MzU0OTIsImlhdCI6MTcwMDc0OTA5Miwibm9uY2UiOiI5MnhDYU5mTjZ2dTVMOGphalRGaW1RIiwiYXRfaGFzaCI6Im9sNnE5WUV3WnpaT0V2WXgtN0hiN1EiLCJuYW1lIjoiaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.nKv3XfGexOlSCihL9S90lhSRjVLLrYZPUuw9U9LwWDNTbd8KZbgYPTRTEg1wA--3aw4lwEQRgTMhv10VBTbEwvpR0oJ0H8MBnur2Qo_6YmVMGlNJKB9qly5CMNgIu2tIL6an9pzBZUVH6ZMtgSsI0lxc8ACsxF8jzDMLnjHFn8qgY9VxwETa1HhYXVOGVLLWuFvTeiuzuaOBqrylwT32faFKxKvrs8AXhE0GOp27eElQqbiOXLwR_6JMkxOO9H3BlStCc7GPjV3lI2ibVGxKppL0FFmrnqnJvJq0EQOu_ne-LFIvNZocaqXZ7nzP_HH1JVGYaxXa5lhEnzBffBm8AQ",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImUyZDQ4NGQ0NzkyYmMxZDEwYTg1M2RhMjVlNTI0YzY3ZDAzYjlhYjgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyOTMwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXRRY25GV05qZFZVa05QU0VaTGF6UjVTMGxZV2xFdk9EUmpaR015TURsbU1XVmhZV0UxWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4MzU0OTIsImlhdCI6MTcwMDc0OTA5Miwibm9uY2UiOiI5MnhDYU5mTjZ2dTVMOGphalRGaW1RIiwiYXRfaGFzaCI6IlQyd1NUWGhUa2NGWlJzNXNRS2tBRXciLCJjX2hhc2giOiJuSmx1UmVaS3ViemNRSTZTdEZhWW5nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.TQ29k-Aav5p32fZW7Q-3i4hdMWyUN1hmrMjpXNkCgMcP9AholeKc4rvJKZ3U7j1SsiM3Rit9MJZCS-wV-fkFyZJPo9FeEDU72LQwS30PleWPp0hUqS7cKVldQdW7ctly6LVTTpv3vnmPlpLoCHuqSIsCXN39iTLIjWePRfUwOvwqq-3cvA4XBmmlXPnGPngs8Cc55et7YHjf8AG98QXaihgQDgGrq6WqKA4gBedZCgtRmCbycBAMGWjM-z41DLWua9N18IkBXdkZzeACY569yLUljambdmBViKFH2gVQNm8GF8SnaSa74rnUGdXgjQjIPYdHm0JtkpxUgdrFIdy4qg",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImUyZDQ4NGQ0NzkyYmMxZDEwYTg1M2RhMjVlNTI0YzY3ZDAzYjlhYjgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyOTMwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXRRY25GV05qZFZVa05QU0VaTGF6UjVTMGxZV2xFdk9EUmpaR015TURsbU1XVmhZV0UxWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4MzU0OTIsImlhdCI6MTcwMDc0OTA5Miwibm9uY2UiOiI5MnhDYU5mTjZ2dTVMOGphalRGaW1RIiwiYXRfaGFzaCI6IlQyd1NUWGhUa2NGWlJzNXNRS2tBRXciLCJjX2hhc2giOiJuSmx1UmVaS3ViemNRSTZTdEZhWW5nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.TQ29k-Aav5p32fZW7Q-3i4hdMWyUN1hmrMjpXNkCgMcP9AholeKc4rvJKZ3U7j1SsiM3Rit9MJZCS-wV-fkFyZJPo9FeEDU72LQwS30PleWPp0hUqS7cKVldQdW7ctly6LVTTpv3vnmPlpLoCHuqSIsCXN39iTLIjWePRfUwOvwqq-3cvA4XBmmlXPnGPngs8Cc55et7YHjf8AG98QXaihgQDgGrq6WqKA4gBedZCgtRmCbycBAMGWjM-z41DLWua9N18IkBXdkZzeACY569yLUljambdmBViKFH2gVQNm8GF8SnaSa74rnUGdXgjQjIPYdHm0JtkpxUgdrFIdy4qg
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImUyZDQ4NGQ0NzkyYmMxZDEwYTg1M2RhMjVlNTI0YzY3ZDAzYjlhYjgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyOTMwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXRRY25GV05qZFZVa05QU0VaTGF6UjVTMGxZV2xFdk9EUmpaR015TURsbU1XVmhZV0UxWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4MzU0OTIsImlhdCI6MTcwMDc0OTA5Miwibm9uY2UiOiI5MnhDYU5mTjZ2dTVMOGphalRGaW1RIiwiYXRfaGFzaCI6IlQyd1NUWGhUa2NGWlJzNXNRS2tBRXciLCJjX2hhc2giOiJuSmx1UmVaS3ViemNRSTZTdEZhWW5nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.TQ29k-Aav5p32fZW7Q-3i4hdMWyUN1hmrMjpXNkCgMcP9AholeKc4rvJKZ3U7j1SsiM3Rit9MJZCS-wV-fkFyZJPo9FeEDU72LQwS30PleWPp0hUqS7cKVldQdW7ctly6LVTTpv3vnmPlpLoCHuqSIsCXN39iTLIjWePRfUwOvwqq-3cvA4XBmmlXPnGPngs8Cc55et7YHjf8AG98QXaihgQDgGrq6WqKA4gBedZCgtRmCbycBAMGWjM-z41DLWua9N18IkBXdkZzeACY569yLUljambdmBViKFH2gVQNm8GF8SnaSa74rnUGdXgjQjIPYdHm0JtkpxUgdrFIdy4qg)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImUyZDQ4NGQ0NzkyYmMxZDEwYTg1M2RhMjVl
NTI0YzY3ZDAzYjlhYjgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyOTMwL2RleCIsI
nN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXRRY25GV05qZFZVa05QU0VaTGF6UjVTM
GxZV2xFdk9EUmpaR015TURsbU1XVmhZV0UxWlVCM2FYSmxMbU52YlJJRWJHUmhjQ
SIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4MzU0OTIsImlhdCI6MTcwMDc0O
TA5Miwibm9uY2UiOiI5MnhDYU5mTjZ2dTVMOGphalRGaW1RIiwiYXRfaGFzaCI6I
lQyd1NUWGhUa2NGWlJzNXNRS2tBRXciLCJjX2hhc2giOiJuSmx1UmVaS3ViemNRS
TZTdEZhWW5nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlL
mNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.TQ29k-Aav
5p32fZW7Q-3i4hdMWyUN1hmrMjpXNkCgMcP9AholeKc4rvJKZ3U7j1SsiM3Rit9M
JZCS-wV-fkFyZJPo9FeEDU72LQwS30PleWPp0hUqS7cKVldQdW7ctly6LVTTpv3v
nmPlpLoCHuqSIsCXN39iTLIjWePRfUwOvwqq-3cvA4XBmmlXPnGPngs8Cc55et7Y
Hjf8AG98QXaihgQDgGrq6WqKA4gBedZCgtRmCbycBAMGWjM-z41DLWua9N18IkBX
dkZzeACY569yLUljambdmBViKFH2gVQNm8GF8SnaSa74rnUGdXgjQjIPYdHm0Jtk
pxUgdrFIdy4qg
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "e2d484d4792bc1d10a853da25e524c67d03b9ab8"
}
```

```json
{
  "at_hash": "T2wSTXhTkcFZRs5sQKkAEw",
  "aud": "wireapp",
  "c_hash": "nJluReZKubzcQI6StFaYng",
  "exp": 1700835492,
  "iat": 1700749092,
  "iss": "http://dex:22930/dex",
  "name": "im:wireapp=%40alice_wire@wire.com",
  "nonce": "92xCaNfN6vu5L8jajTFimQ",
  "preferred_username": "Alice Smith",
  "sub": "CjtpbTp3aXJlYXBwPUtQcnFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8w4pafgjKF9ZEAidFxti
wzKLnmfc+2UxZM5yrT2QcG2C3cJyrEtCs/NVXbYx/BuxqydoFbM9B1Y6OwD/NXzL
AAnSonPmQpzHQjyA9k4aXGb7CBfBVElDWzgiVwCB+Srd6i4AeSqzfXvfUWhkh+FL
h0jR0zmkYdaBx9nMw2Q9O1u3BqHr6BLevzeNIXbe9HMhAXrjFhZkH5asSYdbarA6
CP2Uj2ftVOHUv0qATuF9IdtJWBcLLwzmHxujmpMQwX32ZJ77zBSTaX4NAe9diq1A
EsTjKOG8udjQexdKfn+CscFAAKHWy3h8QGbk55Bj4cZs9hKr/hln+pMyng08RQh3
pQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/o04FcAcMYTQoxiLb0TW7UgrNv3TXJe40
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODAzL2FjbWUvd2lyZS9hY2NvdW50L1JadWZ6bkZKa1FwblFGVExyNVg1V3ZTbkxsRHJoUFJ4IiwidHlwIjoiSldUIiwibm9uY2UiOiJSbTVLTldkaGEwWlhlbkZFVm5CR2FWbE5NMDlRTmtKcFJISkZVRTlrZW0wIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MDMvYWNtZS93aXJlL2NoYWxsZW5nZS9oSHo3TjhRazVIdUFFVnV4NlVKQ3hZcjZQY3JQaWM1Si9vMDRGY0FjTVlUUW94aUxiMFRXN1Vnck52M1RYSmU0MCJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJbVV5WkRRNE5HUTBOemt5WW1NeFpERXdZVGcxTTJSaE1qVmxOVEkwWXpZM1pEQXpZamxoWWpnaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSXlPVE13TDJSbGVDSXNJbk4xWWlJNklrTnFkSEJpVkhBellWaEtiRmxZUW5kUVZYUlJZMjVHVjA1cVpGWlZhMDVRVTBWYVRHRjZValZUTUd4WlYyeEZkazlFVW1wYVIwMTVUVVJzYlUxWFZtaFpWMFV4V2xWQ00yRllTbXhNYlU1MllsSkpSV0pIVW1oalFTSXNJbUYxWkNJNkluZHBjbVZoY0hBaUxDSmxlSEFpT2pFM01EQTRNelUwT1RJc0ltbGhkQ0k2TVRjd01EYzBPVEE1TWl3aWJtOXVZMlVpT2lJNU1uaERZVTVtVGpaMmRUVk1PR3BoYWxSR2FXMVJJaXdpWVhSZmFHRnphQ0k2SWxReWQxTlVXR2hVYTJOR1dsSnpOWE5SUzJ0QlJYY2lMQ0pqWDJoaGMyZ2lPaUp1U214MVVtVmFTM1ZpZW1OUlNUWlRkRVpoV1c1bklpd2libUZ0WlNJNkltbHRPbmRwY21WaGNIQTlKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJa0ZzYVdObElGTnRhWFJvSW4wLlRRMjlrLUFhdjVwMzJmWlc3US0zaTRoZE1XeVVOMWhtck1qcFhOa0NnTWNQOUFob2xlS2M0cnZKS1ozVTdqMVNzaU0zUml0OU1KWkNTLXdWLWZrRnlaSlBvOUZlRURVNzJMUXdTMzBQbGVXUHAwaFVxUzdjS1ZsZFFkVzdjdGx5NkxWVFRwdjN2bm1QbHBMb0NIdXFTSXNDWE4zOWlUTElqV2VQUmZVd092d3FxLTNjdkE0WEJtbWxYUG5HUG5nczhDYzU1ZXQ3WUhqZjhBRzk4UVhhaWhnUURnR3JxNldxS0E0Z0JlZFpDZ3RSbUNieWNCQU1HV2pNLXo0MURMV3VhOU4xOElrQlhka1p6ZUFDWTU2OXlMVWxqYW1iZG1CVmlLRkgyZ1ZRTm04R0Y4U25hU2E3NHJuVUdkWGdqUWpJUFlkSG0wSnRrcHhVZ2RyRklkeTRxZyIsImtleWF1dGgiOiJmTXc2d2RVWkwwS2dCenhGUnNBWExMSVFEMll3djBNUS51SXVzaFZTWVAtMEFMcTBUTlVCeTl5UFVIWUkydmtJQWU0NlVrVU43TkRvIn0",
  "signature": "nRThkoomkvxH-veWKPIyl_g3gTzGRVL-jNC0yN7-gXBvBr-6_Lm384umCa3fjr6ObPWHYI4ist17bl1Vb_pWAQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImUyZDQ4NGQ0NzkyYmMxZDEwYTg1M2RhMjVlNTI0YzY3ZDAzYjlhYjgifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIyOTMwL2RleCIsInN1YiI6IkNqdHBiVHAzYVhKbFlYQndQVXRRY25GV05qZFZVa05QU0VaTGF6UjVTMGxZV2xFdk9EUmpaR015TURsbU1XVmhZV0UxWlVCM2FYSmxMbU52YlJJRWJHUmhjQSIsImF1ZCI6IndpcmVhcHAiLCJleHAiOjE3MDA4MzU0OTIsImlhdCI6MTcwMDc0OTA5Miwibm9uY2UiOiI5MnhDYU5mTjZ2dTVMOGphalRGaW1RIiwiYXRfaGFzaCI6IlQyd1NUWGhUa2NGWlJzNXNRS2tBRXciLCJjX2hhc2giOiJuSmx1UmVaS3ViemNRSTZTdEZhWW5nIiwibmFtZSI6ImltOndpcmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.TQ29k-Aav5p32fZW7Q-3i4hdMWyUN1hmrMjpXNkCgMcP9AholeKc4rvJKZ3U7j1SsiM3Rit9MJZCS-wV-fkFyZJPo9FeEDU72LQwS30PleWPp0hUqS7cKVldQdW7ctly6LVTTpv3vnmPlpLoCHuqSIsCXN39iTLIjWePRfUwOvwqq-3cvA4XBmmlXPnGPngs8Cc55et7YHjf8AG98QXaihgQDgGrq6WqKA4gBedZCgtRmCbycBAMGWjM-z41DLWua9N18IkBXdkZzeACY569yLUljambdmBViKFH2gVQNm8GF8SnaSa74rnUGdXgjQjIPYdHm0JtkpxUgdrFIdy4qg",
    "keyauth": "fMw6wdUZL0KgBzxFRsAXLLIQD2Ywv0MQ.uIushVSYP-0ALq0TNUBy9yPUHYI2vkIAe46UkUN7NDo"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32803/acme/wire/account/RZufznFJkQpnQFTLr5X5WvSnLlDrhPRx",
    "nonce": "Rm5KNWdha0ZXenFEVnBGaVlNM09QNkJpRHJFUE9kem0",
    "typ": "JWT",
    "url": "https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/o04FcAcMYTQoxiLb0TW7UgrNv3TXJe40"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32803/acme/wire/directory>;rel="index"
link: <https://stepca:32803/acme/wire/authz/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J>;rel="up"
location: https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/o04FcAcMYTQoxiLb0TW7UgrNv3TXJe40
replay-nonce: bnBFVldiNkRzbUVma2NxSEZ1NkhUUW9xOHRXeGs1MFA
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32803/acme/wire/challenge/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J/o04FcAcMYTQoxiLb0TW7UgrNv3TXJe40",
  "status": "valid",
  "token": "fMw6wdUZL0KgBzxFRsAXLLIQD2Ywv0MQ",
  "target": "http://dex:22930/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODAzL2FjbWUvd2lyZS9hY2NvdW50L1JadWZ6bkZKa1FwblFGVExyNVg1V3ZTbkxsRHJoUFJ4IiwidHlwIjoiSldUIiwibm9uY2UiOiJibkJGVmxkaU5rUnpiVVZtYTJOeFNFWjFOa2hVVVc5eE9IUlhlR3MxTUZBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MDMvYWNtZS93aXJlL29yZGVyL1JJa21lMlRNYXhlQlI5QWtqbFczUEZaN3g1a3AyUjc2In0",
  "payload": "",
  "signature": "sSK_sbIO9BAzefiiyvUpf0l3Y5rr3FELthgxF-1L0WhPow9HVBvwD2j2hQo846SZzZDja8XeP7_7Hg65npMnAQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32803/acme/wire/account/RZufznFJkQpnQFTLr5X5WvSnLlDrhPRx",
    "nonce": "bnBFVldiNkRzbUVma2NxSEZ1NkhUUW9xOHRXeGs1MFA",
    "typ": "JWT",
    "url": "https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32803/acme/wire/directory>;rel="index"
location: https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76
replay-nonce: dFBxRDZYTEp6TkNzYTBDUlpPcVE2NWJjUUpYcndqTGU
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32803/acme/wire/authz/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J"
  ],
  "expires": "2023-11-24T14:18:12Z",
  "notBefore": "2023-11-23T14:18:12.864222Z",
  "notAfter": "2033-11-20T14:18:12.864222Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODAzL2FjbWUvd2lyZS9hY2NvdW50L1JadWZ6bkZKa1FwblFGVExyNVg1V3ZTbkxsRHJoUFJ4IiwidHlwIjoiSldUIiwibm9uY2UiOiJkRkJ4UkRaWVRFcDZUa056WVRCRFVscFBjVkUyTldKalVVcFljbmRxVEdVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MDMvYWNtZS93aXJlL29yZGVyL1JJa21lMlRNYXhlQlI5QWtqbFczUEZaN3g1a3AyUjc2L2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCTFRDQjRBSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBSndXcWdReXptUWl5ZldaNVpnMUNfaDRjSjVxeHlfZ3ZBbjYyTUxheXd0X29Id3dlZ1lKS29aSWh2Y05BUWtPTVcwd2F6QnBCZ05WSFJFRVlqQmdoanRwYlRwM2FYSmxZWEJ3UFV0UWNuRldOamRWVWtOUFNFWkxhelI1UzBsWVdsRXZPRFJqWkdNeU1EbG1NV1ZoWVdFMVpVQjNhWEpsTG1OdmJZWWhhVzA2ZDJseVpXRndjRDBsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dE1BVUdBeXRsY0FOQkFQTjh6LVpHaXJWdWkyMGV5UXdFQlF2MGhWUkZwUF9WV0kzWjZ0UE9KbVJVeTBZcHEwWG9vdXdqUkN4Vmh0aE1CVHZXY0dkYVRPX0g4SDAyUzliNjh3OCJ9",
  "signature": "0fYcX8RkEC1SZ8v7KVODwj52iWOfm4E9jMyyOq2nShfBDRDrWQrqrFFWS8qwyy1jWNA4BgNW-35uj_ZF5PFEBQ"
}
```
```json
{
  "payload": {
    "csr": "MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAJwWqgQyzmQiyfWZ5Zg1C_h4cJ5qxy_gvAn62MLaywt_oHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJlYXBwPUtQcnFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJlLmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANBAPN8z-ZGirVui20eyQwEBQv0hVRFpP_VWI3Z6tPOJmRUy0Ypq0XoouwjRCxVhthMBTvWcGdaTO_H8H02S9b68w8"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32803/acme/wire/account/RZufznFJkQpnQFTLr5X5WvSnLlDrhPRx",
    "nonce": "dFBxRDZYTEp6TkNzYTBDUlpPcVE2NWJjUUpYcndqTGU",
    "typ": "JWT",
    "url": "https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBLTCB4AIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAJwWqgQyzmQiyfWZ5Zg1C/h4cJ5qxy/g
vAn62MLaywt/oHwwegYJKoZIhvcNAQkOMW0wazBpBgNVHREEYjBghjtpbTp3aXJl
YXBwPUtQcnFWNjdVUkNPSEZLazR5S0lYWlEvODRjZGMyMDlmMWVhYWE1ZUB3aXJl
LmNvbYYhaW06d2lyZWFwcD0lNDBhbGljZV93aXJlQHdpcmUuY29tMAUGAytlcANB
APN8z+ZGirVui20eyQwEBQv0hVRFpP/VWI3Z6tPOJmRUy0Ypq0XoouwjRCxVhthM
BTvWcGdaTO/H8H02S9b68w8=
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
                    9c:16:aa:04:32:ce:64:22:c9:f5:99:e5:98:35:0b:
                    f8:78:70:9e:6a:c7:2f:e0:bc:09:fa:d8:c2:da:cb:
                    0b:7f
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com, URI:im:wireapp=%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        f3:7c:cf:e6:46:8a:b5:6e:8b:6d:1e:c9:0c:04:05:0b:f4:85:
        54:45:a4:ff:d5:58:8d:d9:ea:d3:ce:26:64:54:cb:46:29:ab:
        45:e8:a2:ec:23:44:2c:55:86:d8:4c:05:3b:d6:70:67:5a:4c:
        ef:c7:f0:7d:36:4b:d6:fa:f3:0f

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32803/acme/wire/directory>;rel="index"
location: https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76
replay-nonce: TkVVcVJjOVRuV1pYN2xWc01EYnpPSHdOQnVVSDFxOXU
vary: Origin
```
```json
{
  "certificate": "https://stepca:32803/acme/wire/certificate/1EcR76auxrrnjhSK2nk2vuKdIoNRIDOA",
  "status": "valid",
  "finalize": "https://stepca:32803/acme/wire/order/RIkme2TMaxeBR9AkjlW3PFZ7x5kp2R76/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com\",\"handle\":\"im:wireapp=%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32803/acme/wire/authz/hHz7N8Qk5HuAEVux6UJCxYr6PcrPic5J"
  ],
  "expires": "2023-11-24T14:18:12Z",
  "notBefore": "2023-11-23T14:18:12.864222Z",
  "notAfter": "2033-11-20T14:18:12.864222Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32803/acme/wire/certificate/1EcR76auxrrnjhSK2nk2vuKdIoNRIDOA
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODAzL2FjbWUvd2lyZS9hY2NvdW50L1JadWZ6bkZKa1FwblFGVExyNVg1V3ZTbkxsRHJoUFJ4IiwidHlwIjoiSldUIiwibm9uY2UiOiJUa1ZWY1ZKak9WUnVWMXBZTjJ4V2MwMUVZbnBQU0hkT1FuVlZTREZ4T1hVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4MDMvYWNtZS93aXJlL2NlcnRpZmljYXRlLzFFY1I3NmF1eHJybmpoU0sybmsydnVLZElvTlJJRE9BIn0",
  "payload": "",
  "signature": "EEpUZpObb7ILtUUwMOA_PUf-dtRYF61EKfyKWJN3_WGrLdirn3x_3QuOBUd7Wk9o-lNSlh0WuBlF9AFYS7kvBA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32803/acme/wire/account/RZufznFJkQpnQFTLr5X5WvSnLlDrhPRx",
    "nonce": "TkVVcVJjOVRuV1pYN2xWc01EYnpPSHdOQnVVSDFxOXU",
    "typ": "JWT",
    "url": "https://stepca:32803/acme/wire/certificate/1EcR76auxrrnjhSK2nk2vuKdIoNRIDOA"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32803/acme/wire/directory>;rel="index"
replay-nonce: NU16emFOTzhJVU1SdU9vWmgyeGNCYkpvZjI0SEZFSTE
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAcCgAwIBAgIRAJTE3uKV2kEMik7+EnbozPkwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMxMTIzMTQxODEyWhcNMzMxMTIwMTQxODEyWjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCcFqoEMs5kIsn1meWY\nNQv4eHCeascv4LwJ+tjC2ssLf6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFNeykifyJ+dyBF5CHvSQwPhpt4aVMB8G\nA1UdIwQYMBaAFPFAYbJrccD1hfoEkq3d04cQ5o+RMGkGA1UdEQRiMGCGIWltOndp\ncmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY7aW06d2lyZWFwcD1LUHJxVjY3\nVVJDT0hGS2s0eUtJWFpRLzg0Y2RjMjA5ZjFlYWFhNWVAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQCdpZoV\n+ZR5GbM5jgOw4AE71gpGKA2qiDMx8uPAKv3w+gIgAwfzKb3LftetUjp1z8Fm95Fh\nCskfoWvrtQuE7NM21gk=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV6gAwIBAgIQTj/yhhbMqaBCmEIxhN0RJTAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMTIzMTQx\nODExWhcNMzMxMTIwMTQxODExWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKt4\nMe6iaaZRrSt3UtkUbfsok6nKGpHltOsJVn24kgsJzScDx0uIdaKfrsS7vR0YGdXG\nIPweKy3Sxhn2R8g1NhyjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBTxQGGya3HA9YX6BJKt3dOHEOaPkTAfBgNVHSMEGDAW\ngBSpjqjkaXPIVDuX2/EW5Xk4Puw5rTAKBggqhkjOPQQDAgNIADBFAiBfMr2azU5d\nh/A1bthyZxgBmVx2zNKIYA/BRQrpoOJhAgIhAPYzxRA0jgzzH0sMM7/yNUrlmYhV\nmJRGOzVdLftxHl7Y\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRAJTE3uKV2kEMik7+EnbozPkwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMxMTIzMTQxODEyWhcNMzMxMTIwMTQxODEyWjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCcFqoEMs5kIsn1meWY
NQv4eHCeascv4LwJ+tjC2ssLf6OB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFNeykifyJ+dyBF5CHvSQwPhpt4aVMB8G
A1UdIwQYMBaAFPFAYbJrccD1hfoEkq3d04cQ5o+RMGkGA1UdEQRiMGCGIWltOndp
cmVhcHA9JTQwYWxpY2Vfd2lyZUB3aXJlLmNvbYY7aW06d2lyZWFwcD1LUHJxVjY3
VVJDT0hGS2s0eUtJWFpRLzg0Y2RjMjA5ZjFlYWFhNWVAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIQCdpZoV
+ZR5GbM5jgOw4AE71gpGKA2qiDMx8uPAKv3w+gIgAwfzKb3LftetUjp1z8Fm95Fh
CskfoWvrtQuE7NM21gk=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            94:c4:de:e2:95:da:41:0c:8a:4e:fe:12:76:e8:cc:f9
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Nov 23 14:18:12 2023 GMT
            Not After : Nov 20 14:18:12 2033 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    9c:16:aa:04:32:ce:64:22:c9:f5:99:e5:98:35:0b:
                    f8:78:70:9e:6a:c7:2f:e0:bc:09:fa:d8:c2:da:cb:
                    0b:7f
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                D7:B2:92:27:F2:27:E7:72:04:5E:42:1E:F4:90:C0:F8:69:B7:86:95
            X509v3 Authority Key Identifier: 
                F1:40:61:B2:6B:71:C0:F5:85:FA:04:92:AD:DD:D3:87:10:E6:8F:91
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=%40alice_wire@wire.com, URI:im:wireapp=KPrqV67URCOHFKk4yKIXZQ/84cdc209f1eaaa5e@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:9d:a5:9a:15:f9:94:79:19:b3:39:8e:03:b0:
        e0:01:3b:d6:0a:46:28:0d:aa:88:33:31:f2:e3:c0:2a:fd:f0:
        fa:02:20:03:07:f3:29:bd:cb:7e:d7:ad:52:3a:75:cf:c1:66:
        f7:91:61:0a:c9:1f:a1:6b:eb:b5:0b:84:ec:d3:36:d6:09

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQTj/yhhbMqaBCmEIxhN0RJTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMxMTIzMTQx
ODExWhcNMzMxMTIwMTQxODExWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKt4
Me6iaaZRrSt3UtkUbfsok6nKGpHltOsJVn24kgsJzScDx0uIdaKfrsS7vR0YGdXG
IPweKy3Sxhn2R8g1NhyjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBTxQGGya3HA9YX6BJKt3dOHEOaPkTAfBgNVHSMEGDAW
gBSpjqjkaXPIVDuX2/EW5Xk4Puw5rTAKBggqhkjOPQQDAgNIADBFAiBfMr2azU5d
h/A1bthyZxgBmVx2zNKIYA/BRQrpoOJhAgIhAPYzxRA0jgzzH0sMM7/yNUrlmYhV
mJRGOzVdLftxHl7Y
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4e:3f:f2:86:16:cc:a9:a0:42:98:42:31:84:dd:11:25
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Nov 23 14:18:11 2023 GMT
            Not After : Nov 20 14:18:11 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:ab:78:31:ee:a2:69:a6:51:ad:2b:77:52:d9:14:
                    6d:fb:28:93:a9:ca:1a:91:e5:b4:eb:09:56:7d:b8:
                    92:0b:09:cd:27:03:c7:4b:88:75:a2:9f:ae:c4:bb:
                    bd:1d:18:19:d5:c6:20:fc:1e:2b:2d:d2:c6:19:f6:
                    47:c8:35:36:1c
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                F1:40:61:B2:6B:71:C0:F5:85:FA:04:92:AD:DD:D3:87:10:E6:8F:91
            X509v3 Authority Key Identifier: 
                A9:8E:A8:E4:69:73:C8:54:3B:97:DB:F1:16:E5:79:38:3E:EC:39:AD
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:5f:32:bd:9a:cd:4e:5d:87:f0:35:6e:d8:72:67:
        18:01:99:5c:76:cc:d2:88:60:0f:c1:45:0a:e9:a0:e2:61:02:
        02:21:00:f6:33:c5:10:34:8e:0c:f3:1f:4b:0c:33:bf:f2:35:
        4a:e5:99:88:55:98:94:46:3b:35:5d:2d:fb:71:1e:5e:d8

```
