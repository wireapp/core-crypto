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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/7f39900830740008/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/xnRWBh033703AyPfEirQDytZggaHT2wt
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /realms/master/protocol/openid-connect/auth
    IdP->>-wire-client: 200
    wire-client->>+IdP:  POST /realms/master/protocol/openid-connect/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/2G5CjoDyCVob9Nf6lhT1hwRSNcjflZML
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/eN4Q9SLomOjJnA5YMDXNOHz7uRpMpg2t
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32900/acme/wire/directory
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
  "newNonce": "https://stepca:32900/acme/wire/new-nonce",
  "newAccount": "https://stepca:32900/acme/wire/new-account",
  "newOrder": "https://stepca:32900/acme/wire/new-order",
  "revokeCert": "https://stepca:32900/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32900/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32900/acme/wire/directory>;rel="index"
replay-nonce: WkVUUkR0VXg1NnAwMUpUcmxwYWZKMDBXaGw5dmkycHY
vary: Origin
```
```text
WkVUUkR0VXg1NnAwMUpUcmxwYWZKMDBXaGw5dmkycHY
```
#### 5. create a new account
```http request
POST https://stepca:32900/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjR1OFRPUG9SWi1GdUVIZ0RYeDNhT21aWmFWaUdSX190QzlPQXlJTHI1cWMifSwibm9uY2UiOiJXa1ZVVWtSMFZYZzFObkF3TVVwVWNteHdZV1pLTURCWGFHdzVkbWt5Y0hZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDAvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "_-ZVl_bdbtmGfY1jyzfRklOBunzQANuYVBJUSm6BSsAiex033mK7wHM2z3g6EfqBeJnejkU977EKO9qNORtqAQ"
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
      "x": "4u8TOPoRZ-FuEHgDXx3aOmZZaViGR__tC9OAyILr5qc"
    },
    "nonce": "WkVUUkR0VXg1NnAwMUpUcmxwYWZKMDBXaGw5dmkycHY",
    "typ": "JWT",
    "url": "https://stepca:32900/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32900/acme/wire/directory>;rel="index"
location: https://stepca:32900/acme/wire/account/gNNR5cLt7T81dtC2zzehEvQKu4LAYByz
replay-nonce: aDJoV3JRWFVZQ0pzWDZiT1MyTEc5S2JyRmRxMXg0dzY
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32900/acme/wire/account/gNNR5cLt7T81dtC2zzehEvQKu4LAYByz/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32900/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTAwL2FjbWUvd2lyZS9hY2NvdW50L2dOTlI1Y0x0N1Q4MWR0QzJ6emVoRXZRS3U0TEFZQnl6IiwidHlwIjoiSldUIiwibm9uY2UiOiJhREpvVjNKUldGVlpRMHB6V0RaaVQxTXlURWM1UzJKeVJtUnhNWGcwZHpZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDAvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9xSGlETHNia1QyLXA5dVNKc21yWl9BITdmMzk5MDA4MzA3NDAwMDhAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIn0ifV0sIm5vdEJlZm9yZSI6IjIwMjQtMDEtMTZUMTU6MDk6MjAuNDA0Mzg5WiIsIm5vdEFmdGVyIjoiMjAzNC0wMS0xM1QxNTowOToyMC40MDQzODlaIn0",
  "signature": "Bil4llgYBB1UiTCymbt5vv6SEZ1VefF9UkBf7-0rZjoL1mdLibyCdCnseegQ1rpnAGOgztfQHXd3q8Xll2Q3BQ"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://qHiDLsbkT2-p9uSJsmrZ_A!7f39900830740008@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2034-01-13T15:09:20.404389Z",
    "notBefore": "2024-01-16T15:09:20.404389Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32900/acme/wire/account/gNNR5cLt7T81dtC2zzehEvQKu4LAYByz",
    "nonce": "aDJoV3JRWFVZQ0pzWDZiT1MyTEc5S2JyRmRxMXg0dzY",
    "typ": "JWT",
    "url": "https://stepca:32900/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32900/acme/wire/directory>;rel="index"
location: https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2
replay-nonce: b3JMcGFjVW10WktzSFRZWWUxZG1ja2w4WFZQTDdoNFY
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://qHiDLsbkT2-p9uSJsmrZ_A!7f39900830740008@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32900/acme/wire/authz/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza"
  ],
  "expires": "2024-01-17T15:09:20Z",
  "notBefore": "2024-01-16T15:09:20.404389Z",
  "notAfter": "2034-01-13T15:09:20.404389Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:32900/acme/wire/authz/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTAwL2FjbWUvd2lyZS9hY2NvdW50L2dOTlI1Y0x0N1Q4MWR0QzJ6emVoRXZRS3U0TEFZQnl6IiwidHlwIjoiSldUIiwibm9uY2UiOiJiM0pNY0dGalZXMTBXa3R6U0ZSWldXVXhaRzFqYTJ3NFdGWlFURGRvTkZZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDAvYWNtZS93aXJlL2F1dGh6L1BRTU1Rc0ZSR0o2M3J3NUJKWGNaUlc1Z2R4aUFuZnphIn0",
  "payload": "",
  "signature": "7fTpp1fhxmS8domTi7GaGl_gOGTI7pFpI_KQJHp2Srm4UiOqJwwoRvHqNmOn5M_EdhylnxjB9jLtZTUTHmhPBA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32900/acme/wire/account/gNNR5cLt7T81dtC2zzehEvQKu4LAYByz",
    "nonce": "b3JMcGFjVW10WktzSFRZWWUxZG1ja2w4WFZQTDdoNFY",
    "typ": "JWT",
    "url": "https://stepca:32900/acme/wire/authz/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32900/acme/wire/directory>;rel="index"
location: https://stepca:32900/acme/wire/authz/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza
replay-nonce: ZzhkVmRwODVRdmhFakZJRlBRdUFTNGhwOER6eXFCdE4
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2024-01-17T15:09:20Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/2G5CjoDyCVob9Nf6lhT1hwRSNcjflZML",
      "status": "pending",
      "token": "J65uIAsUjdJvNF0Frf7lyPlO7hlDGnWh",
      "target": "http://keycloak:23675/realms/master"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/xnRWBh033703AyPfEirQDytZggaHT2wt",
      "status": "pending",
      "token": "J65uIAsUjdJvNF0Frf7lyPlO7hlDGnWh",
      "target": "http://wire.com:19803/clients/7f39900830740008/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://qHiDLsbkT2-p9uSJsmrZ_A!7f39900830740008@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:19803/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
SnpzWUZaVXZxa0pGYkJRUzBKOGw5Q0xFMGRQbzFmVTQ
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiNHU4VE9Qb1JaLUZ1RUhnRFh4M2FPbVpaYVZpR1JfX3RDOU9BeUlMcjVxYyJ9fQ.eyJpYXQiOjE3MDU0MTQxNjAsImV4cCI6MTcwNTQyMTM2MCwibmJmIjoxNzA1NDE0MTYwLCJzdWIiOiJ3aXJlYXBwOi8vcUhpRExzYmtUMi1wOXVTSnNtclpfQSE3ZjM5OTAwODMwNzQwMDA4QHdpcmUuY29tIiwianRpIjoiZTg2MTRhOGItMDAxNi00ZjFkLTg1ZGYtZjJiN2U1OGZhNTk2Iiwibm9uY2UiOiJTbnB6V1VaYVZYWnhhMHBHWWtKUlV6QktPR3c1UTB4Rk1HUlFiekZtVlRRIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToxOTgwMy9jbGllbnRzLzdmMzk5MDA4MzA3NDAwMDgvYWNjZXNzLXRva2VuIiwiY2hhbCI6Iko2NXVJQXNVamRKdk5GMEZyZjdseVBsTzdobERHbldoIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.4EDHws9_reRkRTBZbjSai0RPwgTQ_dTo1_ZLceyXnFTXuCxn23X8nALehe2wprP7eFeXQIksFgMAI2Bql9irBg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiNHU4VE9Qb1JaLUZ1RUhnRFh4M2FPbVpa
YVZpR1JfX3RDOU9BeUlMcjVxYyJ9fQ.eyJpYXQiOjE3MDU0MTQxNjAsImV4cCI6M
TcwNTQyMTM2MCwibmJmIjoxNzA1NDE0MTYwLCJzdWIiOiJ3aXJlYXBwOi8vcUhpR
ExzYmtUMi1wOXVTSnNtclpfQSE3ZjM5OTAwODMwNzQwMDA4QHdpcmUuY29tIiwia
nRpIjoiZTg2MTRhOGItMDAxNi00ZjFkLTg1ZGYtZjJiN2U1OGZhNTk2Iiwibm9uY
2UiOiJTbnB6V1VaYVZYWnhhMHBHWWtKUlV6QktPR3c1UTB4Rk1HUlFiekZtVlRRI
iwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToxOTgwMy9jbGllb
nRzLzdmMzk5MDA4MzA3NDAwMDgvYWNjZXNzLXRva2VuIiwiY2hhbCI6Iko2NXVJQ
XNVamRKdk5GMEZyZjdseVBsTzdobERHbldoIiwiaGFuZGxlIjoid2lyZWFwcDovL
yU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.4EDHws9_reRk
RTBZbjSai0RPwgTQ_dTo1_ZLceyXnFTXuCxn23X8nALehe2wprP7eFeXQIksFgMA
I2Bql9irBg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "4u8TOPoRZ-FuEHgDXx3aOmZZaViGR__tC9OAyILr5qc"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "J65uIAsUjdJvNF0Frf7lyPlO7hlDGnWh",
  "exp": 1705421360,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:19803/clients/7f39900830740008/access-token",
  "iat": 1705414160,
  "jti": "e8614a8b-0016-4f1d-85df-f2b7e58fa596",
  "nbf": 1705414160,
  "nonce": "SnpzWUZaVXZxa0pGYkJRUzBKOGw5Q0xFMGRQbzFmVTQ",
  "sub": "wireapp://qHiDLsbkT2-p9uSJsmrZ_A!7f39900830740008@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIN8QTftdDNtQqC6IZAsvVpmfFIiHVe7mbBrKFlr11Xgi
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA4u8TOPoRZ+FuEHgDXx3aOmZZaViGR//tC9OAyILr5qc=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:19803/clients/7f39900830740008/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTkhVNFZFOVFiMUphTFVaMVJVaG5SRmg0TTJGUGJWcGFZVlpwUjFKZlgzUkRPVTlCZVVsTWNqVnhZeUo5ZlEuZXlKcFlYUWlPakUzTURVME1UUXhOakFzSW1WNGNDSTZNVGN3TlRReU1UTTJNQ3dpYm1KbUlqb3hOekExTkRFME1UWXdMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZjVWhwUkV4elltdFVNaTF3T1hWVFNuTnRjbHBmUVNFM1pqTTVPVEF3T0RNd056UXdNREE0UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWlRnMk1UUmhPR0l0TURBeE5pMDBaakZrTFRnMVpHWXRaakppTjJVMU9HWmhOVGsySWl3aWJtOXVZMlVpT2lKVGJuQjZWMVZhWVZaWVduaGhNSEJIV1d0S1VsVjZRa3RQUjNjMVVUQjRSazFIVWxGaWVrWnRWbFJSSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveE9UZ3dNeTlqYkdsbGJuUnpMemRtTXprNU1EQTRNekEzTkRBd01EZ3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtvMk5YVkpRWE5WYW1SS2RrNUdNRVp5Wmpkc2VWQnNUemRvYkVSSGJsZG9JaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS40RURId3M5X3JlUmtSVEJaYmpTYWkwUlB3Z1RRX2RUbzFfWkxjZXlYbkZUWHVDeG4yM1g4bkFMZWhlMndwclA3ZUZlWFFJa3NGZ01BSTJCcWw5aXJCZw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Imhnbzl1SGEwNTg4bWsxM3F0bzZBMzl6Yk0xOW92OVk4SjRPSnVTLVZWQncifX0.eyJpYXQiOjE3MDU0MTQxNjAsImV4cCI6MTcwNTQxODEyMCwibmJmIjoxNzA1NDE0MTYwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTk4MDMvY2xpZW50cy83ZjM5OTAwODMwNzQwMDA4L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9xSGlETHNia1QyLXA5dVNKc21yWl9BITdmMzk5MDA4MzA3NDAwMDhAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MTk4MDMvY2xpZW50cy83ZjM5OTAwODMwNzQwMDA4L2FjY2Vzcy10b2tlbiIsImp0aSI6IjA4NWZiNWJjLTQ5OWUtNDFlMi1iZTJjLWY2ZTQxOWUxODgzMSIsIm5vbmNlIjoiU25weldVWmFWWFp4YTBwR1lrSlJVekJLT0d3NVEweEZNR1JRYnpGbVZUUSIsImNoYWwiOiJKNjV1SUFzVWpkSnZORjBGcmY3bHlQbE83aGxER25XaCIsImNuZiI6eyJraWQiOiI2QXl3V21OVER5Q3hXRzdZSkF6M2tSeGVjZUEtdDJYbm1UMHR3QUpKYmowIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTkhVNFZFOVFiMUphTFVaMVJVaG5SRmg0TTJGUGJWcGFZVlpwUjFKZlgzUkRPVTlCZVVsTWNqVnhZeUo5ZlEuZXlKcFlYUWlPakUzTURVME1UUXhOakFzSW1WNGNDSTZNVGN3TlRReU1UTTJNQ3dpYm1KbUlqb3hOekExTkRFME1UWXdMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZjVWhwUkV4elltdFVNaTF3T1hWVFNuTnRjbHBmUVNFM1pqTTVPVEF3T0RNd056UXdNREE0UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWlRnMk1UUmhPR0l0TURBeE5pMDBaakZrTFRnMVpHWXRaakppTjJVMU9HWmhOVGsySWl3aWJtOXVZMlVpT2lKVGJuQjZWMVZhWVZaWVduaGhNSEJIV1d0S1VsVjZRa3RQUjNjMVVUQjRSazFIVWxGaWVrWnRWbFJSSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveE9UZ3dNeTlqYkdsbGJuUnpMemRtTXprNU1EQTRNekEzTkRBd01EZ3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtvMk5YVkpRWE5WYW1SS2RrNUdNRVp5Wmpkc2VWQnNUemRvYkVSSGJsZG9JaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS40RURId3M5X3JlUmtSVEJaYmpTYWkwUlB3Z1RRX2RUbzFfWkxjZXlYbkZUWHVDeG4yM1g4bkFMZWhlMndwclA3ZUZlWFFJa3NGZ01BSTJCcWw5aXJCZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9xSGlETHNia1QyLXA5dVNKc21yWl9BITdmMzk5MDA4MzA3NDAwMDhAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9._1iBdjC9MUNMi8nk1IvZTHpOgdcdejz-vg5RTFRW3Mg0BnvYicGSUlxMyFtEe_fQg5iIObSlwB0GrIqeCN3OAw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Imhnbzl1SGEwNTg4bWsxM3F0bzZBMzl6Yk0xOW92OVk4SjRPSnVTLVZWQncifX0.eyJpYXQiOjE3MDU0MTQxNjAsImV4cCI6MTcwNTQxODEyMCwibmJmIjoxNzA1NDE0MTYwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTk4MDMvY2xpZW50cy83ZjM5OTAwODMwNzQwMDA4L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9xSGlETHNia1QyLXA5dVNKc21yWl9BITdmMzk5MDA4MzA3NDAwMDhAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MTk4MDMvY2xpZW50cy83ZjM5OTAwODMwNzQwMDA4L2FjY2Vzcy10b2tlbiIsImp0aSI6IjA4NWZiNWJjLTQ5OWUtNDFlMi1iZTJjLWY2ZTQxOWUxODgzMSIsIm5vbmNlIjoiU25weldVWmFWWFp4YTBwR1lrSlJVekJLT0d3NVEweEZNR1JRYnpGbVZUUSIsImNoYWwiOiJKNjV1SUFzVWpkSnZORjBGcmY3bHlQbE83aGxER25XaCIsImNuZiI6eyJraWQiOiI2QXl3V21OVER5Q3hXRzdZSkF6M2tSeGVjZUEtdDJYbm1UMHR3QUpKYmowIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTkhVNFZFOVFiMUphTFVaMVJVaG5SRmg0TTJGUGJWcGFZVlpwUjFKZlgzUkRPVTlCZVVsTWNqVnhZeUo5ZlEuZXlKcFlYUWlPakUzTURVME1UUXhOakFzSW1WNGNDSTZNVGN3TlRReU1UTTJNQ3dpYm1KbUlqb3hOekExTkRFME1UWXdMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZjVWhwUkV4elltdFVNaTF3T1hWVFNuTnRjbHBmUVNFM1pqTTVPVEF3T0RNd056UXdNREE0UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWlRnMk1UUmhPR0l0TURBeE5pMDBaakZrTFRnMVpHWXRaakppTjJVMU9HWmhOVGsySWl3aWJtOXVZMlVpT2lKVGJuQjZWMVZhWVZaWVduaGhNSEJIV1d0S1VsVjZRa3RQUjNjMVVUQjRSazFIVWxGaWVrWnRWbFJSSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveE9UZ3dNeTlqYkdsbGJuUnpMemRtTXprNU1EQTRNekEzTkRBd01EZ3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtvMk5YVkpRWE5WYW1SS2RrNUdNRVp5Wmpkc2VWQnNUemRvYkVSSGJsZG9JaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS40RURId3M5X3JlUmtSVEJaYmpTYWkwUlB3Z1RRX2RUbzFfWkxjZXlYbkZUWHVDeG4yM1g4bkFMZWhlMndwclA3ZUZlWFFJa3NGZ01BSTJCcWw5aXJCZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9xSGlETHNia1QyLXA5dVNKc21yWl9BITdmMzk5MDA4MzA3NDAwMDhAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9._1iBdjC9MUNMi8nk1IvZTHpOgdcdejz-vg5RTFRW3Mg0BnvYicGSUlxMyFtEe_fQg5iIObSlwB0GrIqeCN3OAw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6Imhnbzl1SGEwNTg4bWsxM3F0bzZBMzl6Yk0x
OW92OVk4SjRPSnVTLVZWQncifX0.eyJpYXQiOjE3MDU0MTQxNjAsImV4cCI6MTcw
NTQxODEyMCwibmJmIjoxNzA1NDE0MTYwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MTk4MDMvY2xpZW50cy83ZjM5OTAwODMwNzQwMDA4L2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9xSGlETHNia1QyLXA5dVNKc21yWl9BITdmMzk5MDA4MzA3
NDAwMDhAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MTk4MDMvY2xp
ZW50cy83ZjM5OTAwODMwNzQwMDA4L2FjY2Vzcy10b2tlbiIsImp0aSI6IjA4NWZi
NWJjLTQ5OWUtNDFlMi1iZTJjLWY2ZTQxOWUxODgzMSIsIm5vbmNlIjoiU25weldV
WmFWWFp4YTBwR1lrSlJVekJLT0d3NVEweEZNR1JRYnpGbVZUUSIsImNoYWwiOiJK
NjV1SUFzVWpkSnZORjBGcmY3bHlQbE83aGxER25XaCIsImNuZiI6eyJraWQiOiI2
QXl3V21OVER5Q3hXRzdZSkF6M2tSeGVjZUEtdDJYbm1UMHR3QUpKYmowIn0sInBy
b29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElp
d2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxD
SjRJam9pTkhVNFZFOVFiMUphTFVaMVJVaG5SRmg0TTJGUGJWcGFZVlpwUjFKZlgz
UkRPVTlCZVVsTWNqVnhZeUo5ZlEuZXlKcFlYUWlPakUzTURVME1UUXhOakFzSW1W
NGNDSTZNVGN3TlRReU1UTTJNQ3dpYm1KbUlqb3hOekExTkRFME1UWXdMQ0p6ZFdJ
aU9pSjNhWEpsWVhCd09pOHZjVWhwUkV4elltdFVNaTF3T1hWVFNuTnRjbHBmUVNF
M1pqTTVPVEF3T0RNd056UXdNREE0UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWlRn
Mk1UUmhPR0l0TURBeE5pMDBaakZrTFRnMVpHWXRaakppTjJVMU9HWmhOVGsySWl3
aWJtOXVZMlVpT2lKVGJuQjZWMVZhWVZaWVduaGhNSEJIV1d0S1VsVjZRa3RQUjNj
MVVUQjRSazFIVWxGaWVrWnRWbFJSSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJ
NkltaDBkSEE2THk5M2FYSmxMbU52YlRveE9UZ3dNeTlqYkdsbGJuUnpMemRtTXpr
NU1EQTRNekEzTkRBd01EZ3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtv
Mk5YVkpRWE5WYW1SS2RrNUdNRVp5Wmpkc2VWQnNUemRvYkVSSGJsZG9JaXdpYUdG
dVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1
amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS40RURId3M5X3JlUmtSVEJaYmpTYWkw
UlB3Z1RRX2RUbzFfWkxjZXlYbkZUWHVDeG4yM1g4bkFMZWhlMndwclA3ZUZlWFFJ
a3NGZ01BSTJCcWw5aXJCZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9xSGlETHNi
a1QyLXA5dVNKc21yWl9BITdmMzk5MDA4MzA3NDAwMDhAd2lyZS5jb20iLCJhcGlf
dmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9._1iBdjC9MUNMi8n
k1IvZTHpOgdcdejz-vg5RTFRW3Mg0BnvYicGSUlxMyFtEe_fQg5iIObSlwB0GrIq
eCN3OAw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "hgo9uHa0588mk13qto6A39zbM19ov9Y8J4OJuS-VVBw"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:19803/clients/7f39900830740008/access-token",
  "chal": "J65uIAsUjdJvNF0Frf7lyPlO7hlDGnWh",
  "client_id": "wireapp://qHiDLsbkT2-p9uSJsmrZ_A!7f39900830740008@wire.com",
  "cnf": {
    "kid": "6AywWmNTDyCxWG7YJAz3kRxeceA-t2XnmT0twAJJbj0"
  },
  "exp": 1705418120,
  "iat": 1705414160,
  "iss": "http://wire.com:19803/clients/7f39900830740008/access-token",
  "jti": "085fb5bc-499e-41e2-be2c-f6e419e18831",
  "nbf": 1705414160,
  "nonce": "SnpzWUZaVXZxa0pGYkJRUzBKOGw5Q0xFMGRQbzFmVTQ",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiNHU4VE9Qb1JaLUZ1RUhnRFh4M2FPbVpaYVZpR1JfX3RDOU9BeUlMcjVxYyJ9fQ.eyJpYXQiOjE3MDU0MTQxNjAsImV4cCI6MTcwNTQyMTM2MCwibmJmIjoxNzA1NDE0MTYwLCJzdWIiOiJ3aXJlYXBwOi8vcUhpRExzYmtUMi1wOXVTSnNtclpfQSE3ZjM5OTAwODMwNzQwMDA4QHdpcmUuY29tIiwianRpIjoiZTg2MTRhOGItMDAxNi00ZjFkLTg1ZGYtZjJiN2U1OGZhNTk2Iiwibm9uY2UiOiJTbnB6V1VaYVZYWnhhMHBHWWtKUlV6QktPR3c1UTB4Rk1HUlFiekZtVlRRIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToxOTgwMy9jbGllbnRzLzdmMzk5MDA4MzA3NDAwMDgvYWNjZXNzLXRva2VuIiwiY2hhbCI6Iko2NXVJQXNVamRKdk5GMEZyZjdseVBsTzdobERHbldoIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.4EDHws9_reRkRTBZbjSai0RPwgTQ_dTo1_ZLceyXnFTXuCxn23X8nALehe2wprP7eFeXQIksFgMAI2Bql9irBg",
  "scope": "wire_client_id",
  "sub": "wireapp://qHiDLsbkT2-p9uSJsmrZ_A!7f39900830740008@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEILTyPwPDjW15I0cFy/drf4/ZnCZw336E0/38wRmUHz4H
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAhgo9uHa0588mk13qto6A39zbM19ov9Y8J4OJuS+VVBw=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/xnRWBh033703AyPfEirQDytZggaHT2wt
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTAwL2FjbWUvd2lyZS9hY2NvdW50L2dOTlI1Y0x0N1Q4MWR0QzJ6emVoRXZRS3U0TEFZQnl6IiwidHlwIjoiSldUIiwibm9uY2UiOiJaemhrVm1Sd09EVlJkbWhGYWtaSlJsQlJkVUZUTkdod09FUjZlWEZDZEU0IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDAvYWNtZS93aXJlL2NoYWxsZW5nZS9QUU1NUXNGUkdKNjNydzVCSlhjWlJXNWdkeGlBbmZ6YS94blJXQmgwMzM3MDNBeVBmRWlyUUR5dFpnZ2FIVDJ3dCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkltaG5iemwxU0dFd05UZzRiV3N4TTNGMGJ6WkJNemw2WWsweE9XOTJPVms0U2pSUFNuVlRMVlpXUW5jaWZYMC5leUpwWVhRaU9qRTNNRFUwTVRReE5qQXNJbVY0Y0NJNk1UY3dOVFF4T0RFeU1Dd2libUptSWpveE56QTFOREUwTVRZd0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRrNE1ETXZZMnhwWlc1MGN5ODNaak01T1RBd09ETXdOelF3TURBNEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTl4U0dsRVRITmlhMVF5TFhBNWRWTktjMjF5V2w5QklUZG1Nems1TURBNE16QTNOREF3TURoQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRrNE1ETXZZMnhwWlc1MGN5ODNaak01T1RBd09ETXdOelF3TURBNEwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1wMGFTSTZJakE0TldaaU5XSmpMVFE1T1dVdE5ERmxNaTFpWlRKakxXWTJaVFF4T1dVeE9EZ3pNU0lzSW01dmJtTmxJam9pVTI1d2VsZFZXbUZXV0ZwNFlUQndSMWxyU2xKVmVrSkxUMGQzTlZFd2VFWk5SMUpSWW5wR2JWWlVVU0lzSW1Ob1lXd2lPaUpLTmpWMVNVRnpWV3BrU25aT1JqQkdjbVkzYkhsUWJFODNhR3hFUjI1WGFDSXNJbU51WmlJNmV5SnJhV1FpT2lJMlFYbDNWMjFPVkVSNVEzaFhSemRaU2tGNk0ydFNlR1ZqWlVFdGRESllibTFVTUhSM1FVcEtZbW93SW4wc0luQnliMjltSWpvaVpYbEthR0pIWTJsUGFVcEdXa1ZTVkZGVFNYTkpibEkxWTBOSk5rbHRVbmRpTTBGeVlXNWtNRWxwZDJsaGJtUnlTV3B3TjBsdGREQmxVMGsyU1dzNVRGVkRTWE5KYlU1NVpHbEpOa2xyVm10TmFsVXhUVlJyYVV4RFNqUkphbTlwVGtoVk5GWkZPVkZpTVVwaFRGVmFNVkpWYUc1U1JtZzBUVEpHVUdKV2NHRlpWbHB3VWpGS1psZ3pVa1JQVlRsQ1pWVnNUV05xVm5oWmVVbzVabEV1WlhsS2NGbFlVV2xQYWtVelRVUlZNRTFVVVhoT2FrRnpTVzFXTkdORFNUWk5WR04zVGxSUmVVMVVUVEpOUTNkcFltMUtiVWxxYjNoT2VrRXhUa1JGTUUxVVdYZE1RMHA2WkZkSmFVOXBTak5oV0Vwc1dWaENkMDlwT0haalZXaHdVa1Y0ZWxsdGRGVk5hVEYzVDFoV1ZGTnVUblJqYkhCbVVWTkZNMXBxVFRWUFZFRjNUMFJOZDA1NlVYZE5SRUUwVVVoa2NHTnRWWFZaTWpsMFNXbDNhV0Z1VW5CSmFtOXBXbFJuTWsxVVVtaFBSMGwwVFVSQmVFNXBNREJhYWtaclRGUm5NVnBIV1hSYWFrcHBUakpWTVU5SFdtaE9WR3N5U1dsM2FXSnRPWFZaTWxWcFQybEtWR0p1UWpaV01WWmhXVlphV1ZkdWFHaE5TRUpJVjFkMFMxVnNWalpSYTNSUVVqTmpNVlZVUWpSU2F6RklWV3hHYVdWclduUldiRkpTU1dsM2FXRklVblJKYW05cFZVVTVWRlpEU1hOSmJXZ3daRk5KTmtsdGFEQmtTRUUyVEhrNU0yRllTbXhNYlU1MllsUnZlRTlVWjNkTmVUbHFZa2RzYkdKdVVucE1lbVJ0VFhwck5VMUVRVFJOZWtFelRrUkJkMDFFWjNaWlYwNXFXbGhPZWt4WVVuWmhNbFoxU1dsM2FWa3lhR2hpUTBrMlNXdHZNazVZVmtwUldFNVdZVzFTUzJSck5VZE5SVnA1V21wa2MyVldRbk5VZW1SdllrVlNTR0pzWkc5SmFYZHBZVWRHZFZwSGVHeEphbTlwWkRKc2VWcFhSbmRqUkc5MlRIbFZNRTFIUm5OaFYwNXNXRE5rY0dOdFZrRmtNbXg1V2xNMWFtSXlNR2xNUTBvd1dsZEdkRWxxYjJsa01teDVXbE5LT1M0MFJVUklkM001WDNKbFVtdFNWRUphWW1wVFlXa3dVbEIzWjFSUlgyUlViekZmV2t4alpYbFlia1pVV0hWRGVHNHlNMWc0YmtGTVpXaGxNbmR3Y2xBM1pVWmxXRkZKYTNOR1owMUJTVEpDY1d3NWFYSkNaeUlzSW1Oc2FXVnVkRjlwWkNJNkluZHBjbVZoY0hBNkx5OXhTR2xFVEhOaWExUXlMWEE1ZFZOS2MyMXlXbDlCSVRkbU16azVNREE0TXpBM05EQXdNRGhBZDJseVpTNWpiMjBpTENKaGNHbGZkbVZ5YzJsdmJpSTZOU3dpYzJOdmNHVWlPaUozYVhKbFgyTnNhV1Z1ZEY5cFpDSjkuXzFpQmRqQzlNVU5NaThuazFJdlpUSHBPZ2RjZGVqei12ZzVSVEZSVzNNZzBCbnZZaWNHU1VseE15RnRFZV9mUWc1aUlPYlNsd0IwR3JJcWVDTjNPQXcifQ",
  "signature": "uTjiZ_TMBZ-2LetgDg8brFLAMsYRaWTPAYptmixO57Ss0M3T1gE9m3K1j4TlNGN_Zatq_RXU_nUJPEUIdkP0BQ"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Imhnbzl1SGEwNTg4bWsxM3F0bzZBMzl6Yk0xOW92OVk4SjRPSnVTLVZWQncifX0.eyJpYXQiOjE3MDU0MTQxNjAsImV4cCI6MTcwNTQxODEyMCwibmJmIjoxNzA1NDE0MTYwLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTk4MDMvY2xpZW50cy83ZjM5OTAwODMwNzQwMDA4L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9xSGlETHNia1QyLXA5dVNKc21yWl9BITdmMzk5MDA4MzA3NDAwMDhAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MTk4MDMvY2xpZW50cy83ZjM5OTAwODMwNzQwMDA4L2FjY2Vzcy10b2tlbiIsImp0aSI6IjA4NWZiNWJjLTQ5OWUtNDFlMi1iZTJjLWY2ZTQxOWUxODgzMSIsIm5vbmNlIjoiU25weldVWmFWWFp4YTBwR1lrSlJVekJLT0d3NVEweEZNR1JRYnpGbVZUUSIsImNoYWwiOiJKNjV1SUFzVWpkSnZORjBGcmY3bHlQbE83aGxER25XaCIsImNuZiI6eyJraWQiOiI2QXl3V21OVER5Q3hXRzdZSkF6M2tSeGVjZUEtdDJYbm1UMHR3QUpKYmowIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTkhVNFZFOVFiMUphTFVaMVJVaG5SRmg0TTJGUGJWcGFZVlpwUjFKZlgzUkRPVTlCZVVsTWNqVnhZeUo5ZlEuZXlKcFlYUWlPakUzTURVME1UUXhOakFzSW1WNGNDSTZNVGN3TlRReU1UTTJNQ3dpYm1KbUlqb3hOekExTkRFME1UWXdMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZjVWhwUkV4elltdFVNaTF3T1hWVFNuTnRjbHBmUVNFM1pqTTVPVEF3T0RNd056UXdNREE0UUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pWlRnMk1UUmhPR0l0TURBeE5pMDBaakZrTFRnMVpHWXRaakppTjJVMU9HWmhOVGsySWl3aWJtOXVZMlVpT2lKVGJuQjZWMVZhWVZaWVduaGhNSEJIV1d0S1VsVjZRa3RQUjNjMVVUQjRSazFIVWxGaWVrWnRWbFJSSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveE9UZ3dNeTlqYkdsbGJuUnpMemRtTXprNU1EQTRNekEzTkRBd01EZ3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtvMk5YVkpRWE5WYW1SS2RrNUdNRVp5Wmpkc2VWQnNUemRvYkVSSGJsZG9JaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS40RURId3M5X3JlUmtSVEJaYmpTYWkwUlB3Z1RRX2RUbzFfWkxjZXlYbkZUWHVDeG4yM1g4bkFMZWhlMndwclA3ZUZlWFFJa3NGZ01BSTJCcWw5aXJCZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9xSGlETHNia1QyLXA5dVNKc21yWl9BITdmMzk5MDA4MzA3NDAwMDhAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9._1iBdjC9MUNMi8nk1IvZTHpOgdcdejz-vg5RTFRW3Mg0BnvYicGSUlxMyFtEe_fQg5iIObSlwB0GrIqeCN3OAw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32900/acme/wire/account/gNNR5cLt7T81dtC2zzehEvQKu4LAYByz",
    "nonce": "ZzhkVmRwODVRdmhFakZJRlBRdUFTNGhwOER6eXFCdE4",
    "typ": "JWT",
    "url": "https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/xnRWBh033703AyPfEirQDytZggaHT2wt"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32900/acme/wire/directory>;rel="index"
link: <https://stepca:32900/acme/wire/authz/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza>;rel="up"
location: https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/xnRWBh033703AyPfEirQDytZggaHT2wt
replay-nonce: WUhXZ1h3bFFMR0VnYUZMendNa2VST20zUUFvTjNLaWw
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/xnRWBh033703AyPfEirQDytZggaHT2wt",
  "status": "valid",
  "token": "J65uIAsUjdJvNF0Frf7lyPlO7hlDGnWh",
  "target": "http://wire.com:19803/clients/7f39900830740008/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=x3lfj-3RagsxL0n7kLzoCaJZDrLU-4rsXxGmsok_1g4&code_challenge=piqmPnP3ihrZBPs9tvlZ9q0tEBSq7Pw3ztPveHVwijU
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://keycloak:23675/realms/master/protocol/openid-connect/auth?response_type=code&client_id=wireapp&state=GBC-3xK2gUWZf3H9E4sOEg&code_challenge=piqmPnP3ihrZBPs9tvlZ9q0tEBSq7Pw3ztPveHVwijU&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A19803%2Fcallback&scope=openid+profile&claims=%7B%22id_token%22%3A%7B%22keyauth%22%3A%7B%22essential%22%3Atrue%2C%22value%22%3A%22J65uIAsUjdJvNF0Frf7lyPlO7hlDGnWh.6AywWmNTDyCxWG7YJAz3kRxeceA-t2XnmT0twAJJbj0%22%7D%7D%7D&nonce=9yPAxE6EiPliwDJd3LZSPA
```

#### 20. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://keycloak:23675/realms/master/protocol/openid-connect/token
accept: application/json
content-type: application/x-www-form-urlencoded
```
```text
grant_type=authorization_code&code=40376dbb-b0dc-46b3-8b2a-6d8917a2898e.6dfbe005-854c-49cf-a2ec-8c7de826e00b.19c989f2-8db4-4ba1-b453-36ee3fd7e240&code_verifier=x3lfj-3RagsxL0n7kLzoCaJZDrLU-4rsXxGmsok_1g4&client_id=wireapp&redirect_uri=http%3A%2F%2Fwire.com%3A19803%2Fcallback
```
#### 21. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJaeTBJVHF2YjJzVUVpdFlLUkk2NnNuQzh1bE9RV3M1ZUpqTjJPSHlIeldNIn0.eyJleHAiOjE3MDU0MTc4MjAsImlhdCI6MTcwNTQxNzc2MCwiYXV0aF90aW1lIjoxNzA1NDE3NzYwLCJqdGkiOiJiMWMyZmZhNi1mOGE2LTQ0ODAtODg3My1kM2Y4MjM4YTk5OWEiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJkNGRlYzQyNS0xNDM2LTQ1NzUtOGRiMS0yMDJjZjliZjAzMDQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI5eVBBeEU2RWlQbGl3REpkM0xaU1BBIiwic2Vzc2lvbl9zdGF0ZSI6IjZkZmJlMDA1LTg1NGMtNDljZi1hMmVjLThjN2RlODI2ZTAwYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE5ODAzIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEyZWMtOGM3ZGU4MjZlMDBiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.XNfAPWwEjvqtNwP4Q2m1Bkoy3BrHKTRrVUsPYJgCpI_SY-Sf43i1K4Hes5k-76gCWlRikzddl_hbKBsykemntw4wnMw5WYlBZ9n0FtdZdcy2c8Z3sijpBy3nnw2cpNyy5LYYyOpOCjABkd5zE1Y8BBDXgxJxubGTfsD45mP3fporS9aqWYHn9wL2w8-nyCxitiMt6GkvS7_-6Q0JGka6tOueEHLDOltBind0kfM409Vtwp_xvCrpvl6qQIXQpdq3zwiHtC4h3thpQniVWGLOBBtTqJDnfVp684xt6yhbrei9nLJetqmzoGTj2Zy3mMvttfdLo8_cSZaBhfNOhAv96Q",
  "expires_in": 60,
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJaeTBJVHF2YjJzVUVpdFlLUkk2NnNuQzh1bE9RV3M1ZUpqTjJPSHlIeldNIn0.eyJleHAiOjE3MDU0MTc4MjAsImlhdCI6MTcwNTQxNzc2MCwiYXV0aF90aW1lIjoxNzA1NDE3NzYwLCJqdGkiOiJlOWI3ZWY5ZC1mNTA5LTQwNGEtOGRmNS1lNzJkOWYyNGUwNTAiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJkNGRlYzQyNS0xNDM2LTQ1NzUtOGRiMS0yMDJjZjliZjAzMDQiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ijl5UEF4RTZFaVBsaXdESmQzTFpTUEEiLCJzZXNzaW9uX3N0YXRlIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEyZWMtOGM3ZGU4MjZlMDBiIiwiYXRfaGFzaCI6IlloYVhWZWhGQ0NLaFJ6T0t1akdTOFEiLCJhY3IiOiIxIiwic2lkIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEyZWMtOGM3ZGU4MjZlMDBiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6Iko2NXVJQXNVamRKdk5GMEZyZjdseVBsTzdobERHbldoLjZBeXdXbU5URHlDeFdHN1lKQXoza1J4ZWNlQS10MlhubVQwdHdBSkpiajAiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.jFlx8sGXFdLyQaxt03JaAqKr9E03bBtk8jhiyJKm9yQ14A9BOOASm7EcSkTtX3DEnUnz_BHzM_Qgq0PHBiSbPAxQrO7OHFu8UCeZqe_tTq-b5UpDPyEJvaxVMWOTzy5rB7sDTuLBgrBW41d2SmCqwNhhg0r0ib6p8qfSxhM1nNZpxilWI7b_LZybWmAhdWKq6yfJeG_yGj1UuXkh2M79vP4hueFJ8LznfCF5dUsDVsazLlGwSacMv1Ku5hgZJzDkI9BGK4zbF0gwiPVtd7KWGwhD_CUpJ7HvBvapYSwqibbFf-AcFOSjjdG6bH_aBARa0kAC3ZHtOXORjrddkCY41Q",
  "not-before-policy": 0,
  "refresh_expires_in": 1800,
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIwMDJkOWFkZi1kOGJiLTQ0MjctODViNy0xNGFmOWIzODg4ZTUifQ.eyJleHAiOjE3MDU0MTk1NjAsImlhdCI6MTcwNTQxNzc2MCwianRpIjoiOThmZWRiMDEtYzVlZC00YTE1LWE4MzUtZmNkYWJiODdhYmFlIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjIzNjc1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc3RlciIsInN1YiI6ImQ0ZGVjNDI1LTE0MzYtNDU3NS04ZGIxLTIwMmNmOWJmMDMwNCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI5eVBBeEU2RWlQbGl3REpkM0xaU1BBIiwic2Vzc2lvbl9zdGF0ZSI6IjZkZmJlMDA1LTg1NGMtNDljZi1hMmVjLThjN2RlODI2ZTAwYiIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiI2ZGZiZTAwNS04NTRjLTQ5Y2YtYTJlYy04YzdkZTgyNmUwMGIifQ.WPQw1uCgdZn9_7n2KVYMHaBNusPAr-5ze5339O7wrAs",
  "scope": "openid email profile",
  "session_state": "6dfbe005-854c-49cf-a2ec-8c7de826e00b",
  "token_type": "Bearer"
}
```

<details>
<summary><b>OAuth Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJaeTBJVHF2YjJzVUVpdFlLUkk2NnNuQzh1bE9RV3M1ZUpqTjJPSHlIeldNIn0.eyJleHAiOjE3MDU0MTc4MjAsImlhdCI6MTcwNTQxNzc2MCwiYXV0aF90aW1lIjoxNzA1NDE3NzYwLCJqdGkiOiJiMWMyZmZhNi1mOGE2LTQ0ODAtODg3My1kM2Y4MjM4YTk5OWEiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFjY291bnQiLCJzdWIiOiJkNGRlYzQyNS0xNDM2LTQ1NzUtOGRiMS0yMDJjZjliZjAzMDQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI5eVBBeEU2RWlQbGl3REpkM0xaU1BBIiwic2Vzc2lvbl9zdGF0ZSI6IjZkZmJlMDA1LTg1NGMtNDljZi1hMmVjLThjN2RlODI2ZTAwYiIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE5ODAzIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBwcm9maWxlIiwic2lkIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEyZWMtOGM3ZGU4MjZlMDBiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.XNfAPWwEjvqtNwP4Q2m1Bkoy3BrHKTRrVUsPYJgCpI_SY-Sf43i1K4Hes5k-76gCWlRikzddl_hbKBsykemntw4wnMw5WYlBZ9n0FtdZdcy2c8Z3sijpBy3nnw2cpNyy5LYYyOpOCjABkd5zE1Y8BBDXgxJxubGTfsD45mP3fporS9aqWYHn9wL2w8-nyCxitiMt6GkvS7_-6Q0JGka6tOueEHLDOltBind0kfM409Vtwp_xvCrpvl6qQIXQpdq3zwiHtC4h3thpQniVWGLOBBtTqJDnfVp684xt6yhbrei9nLJetqmzoGTj2Zy3mMvttfdLo8_cSZaBhfNOhAv96Q)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJaeTBJVHF2YjJz
VUVpdFlLUkk2NnNuQzh1bE9RV3M1ZUpqTjJPSHlIeldNIn0.eyJleHAiOjE3MDU0
MTc4MjAsImlhdCI6MTcwNTQxNzc2MCwiYXV0aF90aW1lIjoxNzA1NDE3NzYwLCJq
dGkiOiJiMWMyZmZhNi1mOGE2LTQ0ODAtODg3My1kM2Y4MjM4YTk5OWEiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc3RlciIsImF1ZCI6ImFj
Y291bnQiLCJzdWIiOiJkNGRlYzQyNS0xNDM2LTQ1NzUtOGRiMS0yMDJjZjliZjAz
MDQiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI5eVBB
eEU2RWlQbGl3REpkM0xaU1BBIiwic2Vzc2lvbl9zdGF0ZSI6IjZkZmJlMDA1LTg1
NGMtNDljZi1hMmVjLThjN2RlODI2ZTAwYiIsImFjciI6IjEiLCJhbGxvd2VkLW9y
aWdpbnMiOlsiaHR0cDovL3dpcmUuY29tOjE5ODAzIl0sInJlYWxtX2FjY2VzcyI6
eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW1hc3RlciIsIm9mZmxpbmVfYWNjZXNz
IiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2Nv
dW50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQt
bGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6Im9wZW5pZCBlbWFpbCBw
cm9maWxlIiwic2lkIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEyZWMtOGM3ZGU4MjZl
MDBiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIs
InByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdp
cmUuY29tIiwiZ2l2ZW5fbmFtZSI6IkFsaWNlIiwiZmFtaWx5X25hbWUiOiJTbWl0
aCIsImVtYWlsIjoiYWxpY2VzbWl0aEB3aXJlLmNvbSJ9.XNfAPWwEjvqtNwP4Q2m
1Bkoy3BrHKTRrVUsPYJgCpI_SY-Sf43i1K4Hes5k-76gCWlRikzddl_hbKBsykem
ntw4wnMw5WYlBZ9n0FtdZdcy2c8Z3sijpBy3nnw2cpNyy5LYYyOpOCjABkd5zE1Y
8BBDXgxJxubGTfsD45mP3fporS9aqWYHn9wL2w8-nyCxitiMt6GkvS7_-6Q0JGka
6tOueEHLDOltBind0kfM409Vtwp_xvCrpvl6qQIXQpdq3zwiHtC4h3thpQniVWGL
OBBtTqJDnfVp684xt6yhbrei9nLJetqmzoGTj2Zy3mMvttfdLo8_cSZaBhfNOhAv
96Q
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "Zy0ITqvb2sUEitYKRI66snC8ulOQWs5eJjN2OHyHzWM",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "allowed-origins": [
    "http://wire.com:19803"
  ],
  "aud": "account",
  "auth_time": 1705417760,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1705417820,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1705417760,
  "iss": "http://keycloak:23675/realms/master",
  "jti": "b1c2ffa6-f8a6-4480-8873-d3f8238a999a",
  "name": "Alice Smith",
  "nonce": "9yPAxE6EiPliwDJd3LZSPA",
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
  "session_state": "6dfbe005-854c-49cf-a2ec-8c7de826e00b",
  "sid": "6dfbe005-854c-49cf-a2ec-8c7de826e00b",
  "sub": "d4dec425-1436-4575-8db1-202cf9bf0304",
  "typ": "Bearer"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1S175FnO1SBTJ0kjjGKn
J6gzdOZw10u5VgugG7lwreyTbVAni8rDne2puFX+22kwTlu1GqhuMxMRTOo9iTI/
yplRIRQbR5jTmCpfT7x5f79cn6AQeX5uBEfvSFLHVude8NSJbGInWJpGzF2tJ8KZ
w3ZphwAUjhFEqLBAk1fkxW4t5oY3+o7wUnYDJJNAmNGZgJUqkXLWL/hkGdIDHyaq
DivmLawRJA6oJPKzH45KbZ4c3KGv0mC++dgTU4qWr7Qvf0r4Drsu7jCQno1KXhon
fWhuHt1RQKws8vtmbKVUOoXxoXyJpVp5koVTj/tCCafLfdhi4weODpk73Jkcd5Ci
3QIDAQAB
-----END PUBLIC KEY-----
```

</details>



<details>
<summary><b>OAuth Refresh token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIwMDJkOWFkZi1kOGJiLTQ0MjctODViNy0xNGFmOWIzODg4ZTUifQ.eyJleHAiOjE3MDU0MTk1NjAsImlhdCI6MTcwNTQxNzc2MCwianRpIjoiOThmZWRiMDEtYzVlZC00YTE1LWE4MzUtZmNkYWJiODdhYmFlIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjIzNjc1L3JlYWxtcy9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc3RlciIsInN1YiI6ImQ0ZGVjNDI1LTE0MzYtNDU3NS04ZGIxLTIwMmNmOWJmMDMwNCIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI5eVBBeEU2RWlQbGl3REpkM0xaU1BBIiwic2Vzc2lvbl9zdGF0ZSI6IjZkZmJlMDA1LTg1NGMtNDljZi1hMmVjLThjN2RlODI2ZTAwYiIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJzaWQiOiI2ZGZiZTAwNS04NTRjLTQ5Y2YtYTJlYy04YzdkZTgyNmUwMGIifQ.WPQw1uCgdZn9_7n2KVYMHaBNusPAr-5ze5339O7wrAs)

Raw:
```text
eyJhbGciOiJIUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICIwMDJkOWFkZi1k
OGJiLTQ0MjctODViNy0xNGFmOWIzODg4ZTUifQ.eyJleHAiOjE3MDU0MTk1NjAsI
mlhdCI6MTcwNTQxNzc2MCwianRpIjoiOThmZWRiMDEtYzVlZC00YTE1LWE4MzUtZ
mNkYWJiODdhYmFlIiwiaXNzIjoiaHR0cDovL2tleWNsb2FrOjIzNjc1L3JlYWxtc
y9tYXN0ZXIiLCJhdWQiOiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc
3RlciIsInN1YiI6ImQ0ZGVjNDI1LTE0MzYtNDU3NS04ZGIxLTIwMmNmOWJmMDMwN
CIsInR5cCI6IlJlZnJlc2giLCJhenAiOiJ3aXJlYXBwIiwibm9uY2UiOiI5eVBBe
EU2RWlQbGl3REpkM0xaU1BBIiwic2Vzc2lvbl9zdGF0ZSI6IjZkZmJlMDA1LTg1N
GMtNDljZi1hMmVjLThjN2RlODI2ZTAwYiIsInNjb3BlIjoib3BlbmlkIGVtYWlsI
HByb2ZpbGUiLCJzaWQiOiI2ZGZiZTAwNS04NTRjLTQ5Y2YtYTJlYy04YzdkZTgyN
mUwMGIifQ.WPQw1uCgdZn9_7n2KVYMHaBNusPAr-5ze5339O7wrAs
```

Decoded:

```json
{
  "alg": "HS256",
  "kid": "002d9adf-d8bb-4427-85b7-14af9b3888e5",
  "typ": "JWT"
}
```

```json
{
  "aud": "http://keycloak:23675/realms/master",
  "azp": "wireapp",
  "exp": 1705419560,
  "iat": 1705417760,
  "iss": "http://keycloak:23675/realms/master",
  "jti": "98fedb01-c5ed-4a15-a835-fcdabb87abae",
  "nonce": "9yPAxE6EiPliwDJd3LZSPA",
  "scope": "openid email profile",
  "session_state": "6dfbe005-854c-49cf-a2ec-8c7de826e00b",
  "sid": "6dfbe005-854c-49cf-a2ec-8c7de826e00b",
  "sub": "d4dec425-1436-4575-8db1-202cf9bf0304",
  "typ": "Refresh"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1S175FnO1SBTJ0kjjGKn
J6gzdOZw10u5VgugG7lwreyTbVAni8rDne2puFX+22kwTlu1GqhuMxMRTOo9iTI/
yplRIRQbR5jTmCpfT7x5f79cn6AQeX5uBEfvSFLHVude8NSJbGInWJpGzF2tJ8KZ
w3ZphwAUjhFEqLBAk1fkxW4t5oY3+o7wUnYDJJNAmNGZgJUqkXLWL/hkGdIDHyaq
DivmLawRJA6oJPKzH45KbZ4c3KGv0mC++dgTU4qWr7Qvf0r4Drsu7jCQno1KXhon
fWhuHt1RQKws8vtmbKVUOoXxoXyJpVp5koVTj/tCCafLfdhi4weODpk73Jkcd5Ci
3QIDAQAB
-----END PUBLIC KEY-----
```

</details>


#### 22. validate oidc challenge (userId + displayName)

<details>
<summary><b>OIDC Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJaeTBJVHF2YjJzVUVpdFlLUkk2NnNuQzh1bE9RV3M1ZUpqTjJPSHlIeldNIn0.eyJleHAiOjE3MDU0MTc4MjAsImlhdCI6MTcwNTQxNzc2MCwiYXV0aF90aW1lIjoxNzA1NDE3NzYwLCJqdGkiOiJlOWI3ZWY5ZC1mNTA5LTQwNGEtOGRmNS1lNzJkOWYyNGUwNTAiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJkNGRlYzQyNS0xNDM2LTQ1NzUtOGRiMS0yMDJjZjliZjAzMDQiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ijl5UEF4RTZFaVBsaXdESmQzTFpTUEEiLCJzZXNzaW9uX3N0YXRlIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEyZWMtOGM3ZGU4MjZlMDBiIiwiYXRfaGFzaCI6IlloYVhWZWhGQ0NLaFJ6T0t1akdTOFEiLCJhY3IiOiIxIiwic2lkIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEyZWMtOGM3ZGU4MjZlMDBiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6Iko2NXVJQXNVamRKdk5GMEZyZjdseVBsTzdobERHbldoLjZBeXdXbU5URHlDeFdHN1lKQXoza1J4ZWNlQS10MlhubVQwdHdBSkpiajAiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.jFlx8sGXFdLyQaxt03JaAqKr9E03bBtk8jhiyJKm9yQ14A9BOOASm7EcSkTtX3DEnUnz_BHzM_Qgq0PHBiSbPAxQrO7OHFu8UCeZqe_tTq-b5UpDPyEJvaxVMWOTzy5rB7sDTuLBgrBW41d2SmCqwNhhg0r0ib6p8qfSxhM1nNZpxilWI7b_LZybWmAhdWKq6yfJeG_yGj1UuXkh2M79vP4hueFJ8LznfCF5dUsDVsazLlGwSacMv1Ku5hgZJzDkI9BGK4zbF0gwiPVtd7KWGwhD_CUpJ7HvBvapYSwqibbFf-AcFOSjjdG6bH_aBARa0kAC3ZHtOXORjrddkCY41Q)

Raw:
```text
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJaeTBJVHF2YjJz
VUVpdFlLUkk2NnNuQzh1bE9RV3M1ZUpqTjJPSHlIeldNIn0.eyJleHAiOjE3MDU0
MTc4MjAsImlhdCI6MTcwNTQxNzc2MCwiYXV0aF90aW1lIjoxNzA1NDE3NzYwLCJq
dGkiOiJlOWI3ZWY5ZC1mNTA5LTQwNGEtOGRmNS1lNzJkOWYyNGUwNTAiLCJpc3Mi
OiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc3RlciIsImF1ZCI6Indp
cmVhcHAiLCJzdWIiOiJkNGRlYzQyNS0xNDM2LTQ1NzUtOGRiMS0yMDJjZjliZjAz
MDQiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ijl5UEF4RTZF
aVBsaXdESmQzTFpTUEEiLCJzZXNzaW9uX3N0YXRlIjoiNmRmYmUwMDUtODU0Yy00
OWNmLWEyZWMtOGM3ZGU4MjZlMDBiIiwiYXRfaGFzaCI6IlloYVhWZWhGQ0NLaFJ6
T0t1akdTOFEiLCJhY3IiOiIxIiwic2lkIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEy
ZWMtOGM3ZGU4MjZlMDBiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJB
bGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBh
bGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6Iko2NXVJQXNVamRKdk5GMEZy
ZjdseVBsTzdobERHbldoLjZBeXdXbU5URHlDeFdHN1lKQXoza1J4ZWNlQS10Mlhu
bVQwdHdBSkpiajAiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6
IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.jFlx8sGXFdLy
Qaxt03JaAqKr9E03bBtk8jhiyJKm9yQ14A9BOOASm7EcSkTtX3DEnUnz_BHzM_Qg
q0PHBiSbPAxQrO7OHFu8UCeZqe_tTq-b5UpDPyEJvaxVMWOTzy5rB7sDTuLBgrBW
41d2SmCqwNhhg0r0ib6p8qfSxhM1nNZpxilWI7b_LZybWmAhdWKq6yfJeG_yGj1U
uXkh2M79vP4hueFJ8LznfCF5dUsDVsazLlGwSacMv1Ku5hgZJzDkI9BGK4zbF0gw
iPVtd7KWGwhD_CUpJ7HvBvapYSwqibbFf-AcFOSjjdG6bH_aBARa0kAC3ZHtOXOR
jrddkCY41Q
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "Zy0ITqvb2sUEitYKRI66snC8ulOQWs5eJjN2OHyHzWM",
  "typ": "JWT"
}
```

```json
{
  "acr": "1",
  "at_hash": "YhaXVehFCCKhRzOKujGS8Q",
  "aud": "wireapp",
  "auth_time": 1705417760,
  "azp": "wireapp",
  "email": "alicesmith@wire.com",
  "email_verified": true,
  "exp": 1705417820,
  "family_name": "Smith",
  "given_name": "Alice",
  "iat": 1705417760,
  "iss": "http://keycloak:23675/realms/master",
  "jti": "e9b7ef9d-f509-404a-8df5-e72d9f24e050",
  "keyauth": "J65uIAsUjdJvNF0Frf7lyPlO7hlDGnWh.6AywWmNTDyCxWG7YJAz3kRxeceA-t2XnmT0twAJJbj0",
  "name": "Alice Smith",
  "nonce": "9yPAxE6EiPliwDJd3LZSPA",
  "preferred_username": "wireapp://%40alice_wire@wire.com",
  "session_state": "6dfbe005-854c-49cf-a2ec-8c7de826e00b",
  "sid": "6dfbe005-854c-49cf-a2ec-8c7de826e00b",
  "sub": "d4dec425-1436-4575-8db1-202cf9bf0304",
  "typ": "ID"
}
```


❌ Invalid Signature with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1S175FnO1SBTJ0kjjGKn
J6gzdOZw10u5VgugG7lwreyTbVAni8rDne2puFX+22kwTlu1GqhuMxMRTOo9iTI/
yplRIRQbR5jTmCpfT7x5f79cn6AQeX5uBEfvSFLHVude8NSJbGInWJpGzF2tJ8KZ
w3ZphwAUjhFEqLBAk1fkxW4t5oY3+o7wUnYDJJNAmNGZgJUqkXLWL/hkGdIDHyaq
DivmLawRJA6oJPKzH45KbZ4c3KGv0mC++dgTU4qWr7Qvf0r4Drsu7jCQno1KXhon
fWhuHt1RQKws8vtmbKVUOoXxoXyJpVp5koVTj/tCCafLfdhi4weODpk73Jkcd5Ci
3QIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/2G5CjoDyCVob9Nf6lhT1hwRSNcjflZML
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTAwL2FjbWUvd2lyZS9hY2NvdW50L2dOTlI1Y0x0N1Q4MWR0QzJ6emVoRXZRS3U0TEFZQnl6IiwidHlwIjoiSldUIiwibm9uY2UiOiJXVWhYWjFoM2JGRk1SMFZuWVVaTWVuZE5hMlZTVDIwelVVRnZUak5MYVd3IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDAvYWNtZS93aXJlL2NoYWxsZW5nZS9QUU1NUXNGUkdKNjNydzVCSlhjWlJXNWdkeGlBbmZ6YS8yRzVDam9EeUNWb2I5TmY2bGhUMWh3UlNOY2pmbFpNTCJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSmFlVEJKVkhGMllqSnpWVVZwZEZsTFVrazJObk51UXpoMWJFOVJWM00xWlVwcVRqSlBTSGxJZWxkTkluMC5leUpsZUhBaU9qRTNNRFUwTVRjNE1qQXNJbWxoZENJNk1UY3dOVFF4TnpjMk1Dd2lZWFYwYUY5MGFXMWxJam94TnpBMU5ERTNOell3TENKcWRHa2lPaUpsT1dJM1pXWTVaQzFtTlRBNUxUUXdOR0V0T0dSbU5TMWxOekprT1dZeU5HVXdOVEFpTENKcGMzTWlPaUpvZEhSd09pOHZhMlY1WTJ4dllXczZNak0yTnpVdmNtVmhiRzF6TDIxaGMzUmxjaUlzSW1GMVpDSTZJbmRwY21WaGNIQWlMQ0p6ZFdJaU9pSmtOR1JsWXpReU5TMHhORE0yTFRRMU56VXRPR1JpTVMweU1ESmpaamxpWmpBek1EUWlMQ0owZVhBaU9pSkpSQ0lzSW1GNmNDSTZJbmRwY21WaGNIQWlMQ0p1YjI1alpTSTZJamw1VUVGNFJUWkZhVkJzYVhkRVNtUXpURnBUVUVFaUxDSnpaWE56YVc5dVgzTjBZWFJsSWpvaU5tUm1ZbVV3TURVdE9EVTBZeTAwT1dObUxXRXlaV010T0dNM1pHVTRNalpsTURCaUlpd2lZWFJmYUdGemFDSTZJbGxvWVZoV1pXaEdRME5MYUZKNlQwdDFha2RUT0ZFaUxDSmhZM0lpT2lJeElpd2ljMmxrSWpvaU5tUm1ZbVV3TURVdE9EVTBZeTAwT1dObUxXRXlaV010T0dNM1pHVTRNalpsTURCaUlpd2laVzFoYVd4ZmRtVnlhV1pwWldRaU9uUnlkV1VzSW01aGJXVWlPaUpCYkdsalpTQlRiV2wwYUNJc0luQnlaV1psY25KbFpGOTFjMlZ5Ym1GdFpTSTZJbmRwY21WaGNIQTZMeThsTkRCaGJHbGpaVjkzYVhKbFFIZHBjbVV1WTI5dElpd2lhMlY1WVhWMGFDSTZJa28yTlhWSlFYTlZhbVJLZGs1R01FWnlaamRzZVZCc1R6ZG9iRVJIYmxkb0xqWkJlWGRYYlU1VVJIbERlRmRITjFsS1FYb3phMUo0WldObFFTMTBNbGh1YlZRd2RIZEJTa3BpYWpBaUxDSm5hWFpsYmw5dVlXMWxJam9pUVd4cFkyVWlMQ0ptWVcxcGJIbGZibUZ0WlNJNklsTnRhWFJvSWl3aVpXMWhhV3dpT2lKaGJHbGpaWE50YVhSb1FIZHBjbVV1WTI5dEluMC5qRmx4OHNHWEZkTHlRYXh0MDNKYUFxS3I5RTAzYkJ0azhqaGl5SkttOXlRMTRBOUJPT0FTbTdFY1NrVHRYM0RFblVuel9CSHpNX1FncTBQSEJpU2JQQXhRck83T0hGdThVQ2VacWVfdFRxLWI1VXBEUHlFSnZheFZNV09Uenk1ckI3c0RUdUxCZ3JCVzQxZDJTbUNxd05oaGcwcjBpYjZwOHFmU3hoTTFuTlpweGlsV0k3Yl9MWnliV21BaGRXS3E2eWZKZUdfeUdqMVV1WGtoMk03OXZQNGh1ZUZKOEx6bmZDRjVkVXNEVnNhekxsR3dTYWNNdjFLdTVoZ1pKekRrSTlCR0s0emJGMGd3aVBWdGQ3S1dHd2hEX0NVcEo3SHZCdmFwWVN3cWliYkZmLUFjRk9TampkRzZiSF9hQkFSYTBrQUMzWkh0T1hPUmpyZGRrQ1k0MVEifQ",
  "signature": "CsGN1jheeaON0YaFVbq-FuyKIUrxuPEgdDbgrAgJW5ikYHLZSI7cLQxdfLLOEZOGaDRALERrsguywxW9BL_DBQ"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJaeTBJVHF2YjJzVUVpdFlLUkk2NnNuQzh1bE9RV3M1ZUpqTjJPSHlIeldNIn0.eyJleHAiOjE3MDU0MTc4MjAsImlhdCI6MTcwNTQxNzc2MCwiYXV0aF90aW1lIjoxNzA1NDE3NzYwLCJqdGkiOiJlOWI3ZWY5ZC1mNTA5LTQwNGEtOGRmNS1lNzJkOWYyNGUwNTAiLCJpc3MiOiJodHRwOi8va2V5Y2xvYWs6MjM2NzUvcmVhbG1zL21hc3RlciIsImF1ZCI6IndpcmVhcHAiLCJzdWIiOiJkNGRlYzQyNS0xNDM2LTQ1NzUtOGRiMS0yMDJjZjliZjAzMDQiLCJ0eXAiOiJJRCIsImF6cCI6IndpcmVhcHAiLCJub25jZSI6Ijl5UEF4RTZFaVBsaXdESmQzTFpTUEEiLCJzZXNzaW9uX3N0YXRlIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEyZWMtOGM3ZGU4MjZlMDBiIiwiYXRfaGFzaCI6IlloYVhWZWhGQ0NLaFJ6T0t1akdTOFEiLCJhY3IiOiIxIiwic2lkIjoiNmRmYmUwMDUtODU0Yy00OWNmLWEyZWMtOGM3ZGU4MjZlMDBiIiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJBbGljZSBTbWl0aCIsInByZWZlcnJlZF91c2VybmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwia2V5YXV0aCI6Iko2NXVJQXNVamRKdk5GMEZyZjdseVBsTzdobERHbldoLjZBeXdXbU5URHlDeFdHN1lKQXoza1J4ZWNlQS10MlhubVQwdHdBSkpiajAiLCJnaXZlbl9uYW1lIjoiQWxpY2UiLCJmYW1pbHlfbmFtZSI6IlNtaXRoIiwiZW1haWwiOiJhbGljZXNtaXRoQHdpcmUuY29tIn0.jFlx8sGXFdLyQaxt03JaAqKr9E03bBtk8jhiyJKm9yQ14A9BOOASm7EcSkTtX3DEnUnz_BHzM_Qgq0PHBiSbPAxQrO7OHFu8UCeZqe_tTq-b5UpDPyEJvaxVMWOTzy5rB7sDTuLBgrBW41d2SmCqwNhhg0r0ib6p8qfSxhM1nNZpxilWI7b_LZybWmAhdWKq6yfJeG_yGj1UuXkh2M79vP4hueFJ8LznfCF5dUsDVsazLlGwSacMv1Ku5hgZJzDkI9BGK4zbF0gwiPVtd7KWGwhD_CUpJ7HvBvapYSwqibbFf-AcFOSjjdG6bH_aBARa0kAC3ZHtOXORjrddkCY41Q"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32900/acme/wire/account/gNNR5cLt7T81dtC2zzehEvQKu4LAYByz",
    "nonce": "WUhXZ1h3bFFMR0VnYUZMendNa2VST20zUUFvTjNLaWw",
    "typ": "JWT",
    "url": "https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/2G5CjoDyCVob9Nf6lhT1hwRSNcjflZML"
  }
}
```
#### 23. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32900/acme/wire/directory>;rel="index"
link: <https://stepca:32900/acme/wire/authz/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza>;rel="up"
location: https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/2G5CjoDyCVob9Nf6lhT1hwRSNcjflZML
replay-nonce: N1VvNGNpWjNiVnVzV0V2UjVKd2RRWWFIaG9nZTVOeVc
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32900/acme/wire/challenge/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza/2G5CjoDyCVob9Nf6lhT1hwRSNcjflZML",
  "status": "valid",
  "token": "J65uIAsUjdJvNF0Frf7lyPlO7hlDGnWh",
  "target": "http://keycloak:23675/realms/master"
}
```
### Client presents a CSR and gets its certificate
#### 24. verify the status of the order
```http request
POST https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTAwL2FjbWUvd2lyZS9hY2NvdW50L2dOTlI1Y0x0N1Q4MWR0QzJ6emVoRXZRS3U0TEFZQnl6IiwidHlwIjoiSldUIiwibm9uY2UiOiJOMVZ2TkdOcFdqTmlWblZ6VjBWMlVqVktkMlJSV1dGSWFHOW5aVFZPZVZjIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDAvYWNtZS93aXJlL29yZGVyL1RoRWNSWEluSUw4WjRXN2Y5UzNwUURaOVF4YVBJU2EyIn0",
  "payload": "",
  "signature": "MEFTWDB7Y427EhvzWeZD4KUwc-hKYSWW3q4NUmmojSdcX28oTlqTlBvhyarwb4JwZaJ_6ld4PKEOvq_b2J9-AA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32900/acme/wire/account/gNNR5cLt7T81dtC2zzehEvQKu4LAYByz",
    "nonce": "N1VvNGNpWjNiVnVzV0V2UjVKd2RRWWFIaG9nZTVOeVc",
    "typ": "JWT",
    "url": "https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2"
  }
}
```
#### 25. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32900/acme/wire/directory>;rel="index"
location: https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2
replay-nonce: MGhRWlJrektSbkFGN01Fc3VkQmE3Vk5vSEh5ejFRNnI
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://qHiDLsbkT2-p9uSJsmrZ_A!7f39900830740008@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32900/acme/wire/authz/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza"
  ],
  "expires": "2024-01-17T15:09:20Z",
  "notBefore": "2024-01-16T15:09:20.404389Z",
  "notAfter": "2034-01-13T15:09:20.404389Z"
}
```
#### 26. create a CSR and call finalize url
```http request
POST https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTAwL2FjbWUvd2lyZS9hY2NvdW50L2dOTlI1Y0x0N1Q4MWR0QzJ6emVoRXZRS3U0TEFZQnl6IiwidHlwIjoiSldUIiwibm9uY2UiOiJNR2hSV2xKcmVrdFNia0ZHTjAxRmMzVmtRbUUzVms1dlNFaDVlakZSTm5JIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDAvYWNtZS93aXJlL29yZGVyL1RoRWNSWEluSUw4WjRXN2Y5UzNwUURaOVF4YVBJU2EyL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBT01LMzE5Ylh0dnB2b1Buc3ZxOGx6eU9WRkVLdU9Mak1PVVFIMkJkdi1xbW9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2Y1VocFJFeHpZbXRVTWkxd09YVlRTbk50Y2xwZlFTRTNaak01T1RBd09ETXdOelF3TURBNFFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFEcEVKTF82Uk9xN2NrelFvcDF6QlBiNjBIcDFlUEo1WmxMQTZuQUt0OGstZldjcVgxVUdlNlpHU3pQbVl1ekYwbGQxd3JrMWEyR0Zwd18wRC1tMmx3QyJ9",
  "signature": "rCNvbyaakt-WFuHTXLRqmg75iZYPDKRPzfx2R0Kk6XUIvyQP8pYt8dYc1KMXUNSCEl5g14ZyZyipd3AoQDo9DQ"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOMK319bXtvpvoPnsvq8lzyOVFEKuOLjMOUQH2Bdv-qmoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vcUhpRExzYmtUMi1wOXVTSnNtclpfQSE3ZjM5OTAwODMwNzQwMDA4QHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQDpEJL_6ROq7ckzQop1zBPb60Hp1ePJ5ZlLA6nAKt8k-fWcqX1UGe6ZGSzPmYuzF0ld1wrk1a2GFpw_0D-m2lwC"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32900/acme/wire/account/gNNR5cLt7T81dtC2zzehEvQKu4LAYByz",
    "nonce": "MGhRWlJrektSbkFGN01Fc3VkQmE3Vk5vSEh5ejFRNnI",
    "typ": "JWT",
    "url": "https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOMK319bXtvpvoPnsvq8lzyOVFEKuOLj
MOUQH2Bdv+qmoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vcUhpRExzYmtUMi1wOXVTSnNtclpfQSE3ZjM5OTAwODMwNzQwMDA4QHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQDp
EJL/6ROq7ckzQop1zBPb60Hp1ePJ5ZlLA6nAKt8k+fWcqX1UGe6ZGSzPmYuzF0ld
1wrk1a2GFpw/0D+m2lwC
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
                    e3:0a:df:5f:5b:5e:db:e9:be:83:e7:b2:fa:bc:97:
                    3c:8e:54:51:0a:b8:e2:e3:30:e5:10:1f:60:5d:bf:
                    ea:a6
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://qHiDLsbkT2-p9uSJsmrZ_A!7f39900830740008@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        e9:10:92:ff:e9:13:aa:ed:c9:33:42:8a:75:cc:13:db:eb:41:
        e9:d5:e3:c9:e5:99:4b:03:a9:c0:2a:df:24:f9:f5:9c:a9:7d:
        54:19:ee:99:19:2c:cf:99:8b:b3:17:49:5d:d7:0a:e4:d5:ad:
        86:16:9c:3f:d0:3f:a6:da:5c:02

```

#### 27. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32900/acme/wire/directory>;rel="index"
location: https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2
replay-nonce: a1Y2M2xDaEx2QkJHcGkySkl1TGxoemhvSndtaThQYkE
vary: Origin
```
```json
{
  "certificate": "https://stepca:32900/acme/wire/certificate/eN4Q9SLomOjJnA5YMDXNOHz7uRpMpg2t",
  "status": "valid",
  "finalize": "https://stepca:32900/acme/wire/order/ThEcRXInIL8Z4W7f9S3pQDZ9QxaPISa2/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://qHiDLsbkT2-p9uSJsmrZ_A!7f39900830740008@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32900/acme/wire/authz/PQMMQsFRGJ63rw5BJXcZRW5gdxiAnfza"
  ],
  "expires": "2024-01-17T15:09:20Z",
  "notBefore": "2024-01-16T15:09:20.404389Z",
  "notAfter": "2034-01-13T15:09:20.404389Z"
}
```
#### 28. fetch the certificate
```http request
POST https://stepca:32900/acme/wire/certificate/eN4Q9SLomOjJnA5YMDXNOHz7uRpMpg2t
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyOTAwL2FjbWUvd2lyZS9hY2NvdW50L2dOTlI1Y0x0N1Q4MWR0QzJ6emVoRXZRS3U0TEFZQnl6IiwidHlwIjoiSldUIiwibm9uY2UiOiJhMVkyTTJ4RGFFeDJRa0pIY0dreVNrbDFUR3hvZW1odlNuZHRhVGhRWWtFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI5MDAvYWNtZS93aXJlL2NlcnRpZmljYXRlL2VONFE5U0xvbU9qSm5BNVlNRFhOT0h6N3VScE1wZzJ0In0",
  "payload": "",
  "signature": "tD-46v0qiPxA_yytr8kSYkHIkIbM25TVmDl_UUyASf3sXy65cWksSAX4F2eigjuFvojaNGCTnsfMYkVClyTLBg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32900/acme/wire/account/gNNR5cLt7T81dtC2zzehEvQKu4LAYByz",
    "nonce": "a1Y2M2xDaEx2QkJHcGkySkl1TGxoemhvSndtaThQYkE",
    "typ": "JWT",
    "url": "https://stepca:32900/acme/wire/certificate/eN4Q9SLomOjJnA5YMDXNOHz7uRpMpg2t"
  }
}
```
#### 29. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32900/acme/wire/directory>;rel="index"
replay-nonce: U2gwSDNXSkkwSGd0TUN3bG94QWllY1UxbTRXdnJ2VHI
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAb+gAwIBAgIQPLhnaE6aYNLfbidzAp50yjAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nNDAxMTYxNTA5MjBaFw0zNDAxMTMxNTA5MjBaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOMK319bXtvpvoPnsvq8\nlzyOVFEKuOLjMOUQH2Bdv+qmo4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUEBZTO9TS3Y7InptUwzDx3cFfyJEwHwYD\nVR0jBBgwFoAUL5YqVyZXiMW5t/DGkuZdANPJ4HowaQYDVR0RBGIwYIYgd2lyZWFw\ncDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9xSGlETHNia1Qy\nLXA5dVNKc21yWl9BJTIxN2YzOTkwMDgzMDc0MDAwOEB3aXJlLmNvbTAdBgwrBgEE\nAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSQAwRgIhANfc/l4I\n6v70iPKAfFs01Ldqf0h5iVGTU1/AlvzzJF45AiEAz7rtuMUud49592HTsEIAz5MZ\nogeEg/9of5E0/LJXRdY=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAJy6V6Ss8fpxNeZQor0s0BYwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExNjE1\nMDkxOFoXDTM0MDExMzE1MDkxOFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATJ\nIZgIKmrKQ9qqsvKsl+0frjdV+N+6LFx3FN0QVXDPFiQe4X2un88eeg79+fW3yXhi\nDHf196luRN3ydPvScAGgo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUL5YqVyZXiMW5t/DGkuZdANPJ4HowHwYDVR0jBBgw\nFoAUfo7V/ISNlOldc1fr/SNvGrJcbV0wCgYIKoZIzj0EAwIDSAAwRQIgVeS/71Yn\noM/M5UOBVjGOZjWI/gjFUY/YJOv8mNwi9E0CIQCWyfsrXjHY3cutjYWdRhYhcxnF\nQdjSQ8JcFoE8bVhyog==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGjCCAb+gAwIBAgIQPLhnaE6aYNLfbidzAp50yjAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
NDAxMTYxNTA5MjBaFw0zNDAxMTMxNTA5MjBaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAOMK319bXtvpvoPnsvq8
lzyOVFEKuOLjMOUQH2Bdv+qmo4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUEBZTO9TS3Y7InptUwzDx3cFfyJEwHwYD
VR0jBBgwFoAUL5YqVyZXiMW5t/DGkuZdANPJ4HowaQYDVR0RBGIwYIYgd2lyZWFw
cDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9xSGlETHNia1Qy
LXA5dVNKc21yWl9BJTIxN2YzOTkwMDgzMDc0MDAwOEB3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSQAwRgIhANfc/l4I
6v70iPKAfFs01Ldqf0h5iVGTU1/AlvzzJF45AiEAz7rtuMUud49592HTsEIAz5MZ
ogeEg/9of5E0/LJXRdY=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3c:b8:67:68:4e:9a:60:d2:df:6e:27:73:02:9e:74:ca
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan 16 15:09:20 2024 GMT
            Not After : Jan 13 15:09:20 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    e3:0a:df:5f:5b:5e:db:e9:be:83:e7:b2:fa:bc:97:
                    3c:8e:54:51:0a:b8:e2:e3:30:e5:10:1f:60:5d:bf:
                    ea:a6
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                10:16:53:3B:D4:D2:DD:8E:C8:9E:9B:54:C3:30:F1:DD:C1:5F:C8:91
            X509v3 Authority Key Identifier: 
                2F:96:2A:57:26:57:88:C5:B9:B7:F0:C6:92:E6:5D:00:D3:C9:E0:7A
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://qHiDLsbkT2-p9uSJsmrZ_A%217f39900830740008@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:d7:dc:fe:5e:08:ea:fe:f4:88:f2:80:7c:5b:
        34:d4:b7:6a:7f:48:79:89:51:93:53:5f:c0:96:fc:f3:24:5e:
        39:02:21:00:cf:ba:ed:b8:c5:2e:77:8f:79:f7:61:d3:b0:42:
        00:cf:93:19:a2:07:84:83:ff:68:7f:91:34:fc:b2:57:45:d6

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAJy6V6Ss8fpxNeZQor0s0BYwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExNjE1
MDkxOFoXDTM0MDExMzE1MDkxOFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATJ
IZgIKmrKQ9qqsvKsl+0frjdV+N+6LFx3FN0QVXDPFiQe4X2un88eeg79+fW3yXhi
DHf196luRN3ydPvScAGgo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUL5YqVyZXiMW5t/DGkuZdANPJ4HowHwYDVR0jBBgw
FoAUfo7V/ISNlOldc1fr/SNvGrJcbV0wCgYIKoZIzj0EAwIDSAAwRQIgVeS/71Yn
oM/M5UOBVjGOZjWI/gjFUY/YJOv8mNwi9E0CIQCWyfsrXjHY3cutjYWdRhYhcxnF
QdjSQ8JcFoE8bVhyog==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9c:ba:57:a4:ac:f1:fa:71:35:e6:50:a2:bd:2c:d0:16
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 16 15:09:18 2024 GMT
            Not After : Jan 13 15:09:18 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:c9:21:98:08:2a:6a:ca:43:da:aa:b2:f2:ac:97:
                    ed:1f:ae:37:55:f8:df:ba:2c:5c:77:14:dd:10:55:
                    70:cf:16:24:1e:e1:7d:ae:9f:cf:1e:7a:0e:fd:f9:
                    f5:b7:c9:78:62:0c:77:f5:f7:a9:6e:44:dd:f2:74:
                    fb:d2:70:01:a0
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                2F:96:2A:57:26:57:88:C5:B9:B7:F0:C6:92:E6:5D:00:D3:C9:E0:7A
            X509v3 Authority Key Identifier: 
                7E:8E:D5:FC:84:8D:94:E9:5D:73:57:EB:FD:23:6F:1A:B2:5C:6D:5D
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:55:e4:bf:ef:56:27:a0:cf:cc:e5:43:81:56:31:
        8e:66:35:88:fe:08:c5:51:8f:d8:24:eb:fc:98:dc:22:f4:4d:
        02:21:00:96:c9:fb:2b:5e:31:d8:dd:cb:ad:8d:85:9d:46:16:
        21:73:19:c5:41:d8:d2:43:c2:5c:16:81:3c:6d:58:72:a2

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATWgAwIBAgIQI+8WrQnQcG1/veRnq6RqsTAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTE2MTUw
OTE3WhcNMzQwMTEzMTUwOTE3WjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3
aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAShTvawJEV5XIUB
CawfGaXUI2dvg3iSNqiT5AeYyHsHwG8dXGaLJH8eBuOGTXo4Jpr9+0RacmyaDkIq
1g2gN1b/o0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd
BgNVHQ4EFgQUfo7V/ISNlOldc1fr/SNvGrJcbV0wCgYIKoZIzj0EAwIDSQAwRgIh
APrydq1uv6NJPApolkm7yljrE/1WDpCbXy9AtLO3Jss9AiEA9M0ku60C21voy1Cf
xjrvE+FOa3AdOtIQMtSWNPhSm4A=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            23:ef:16:ad:09:d0:70:6d:7f:bd:e4:67:ab:a4:6a:b1
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 16 15:09:17 2024 GMT
            Not After : Jan 13 15:09:17 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:a1:4e:f6:b0:24:45:79:5c:85:01:09:ac:1f:19:
                    a5:d4:23:67:6f:83:78:92:36:a8:93:e4:07:98:c8:
                    7b:07:c0:6f:1d:5c:66:8b:24:7f:1e:06:e3:86:4d:
                    7a:38:26:9a:fd:fb:44:5a:72:6c:9a:0e:42:2a:d6:
                    0d:a0:37:56:ff
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                7E:8E:D5:FC:84:8D:94:E9:5D:73:57:EB:FD:23:6F:1A:B2:5C:6D:5D
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:fa:f2:76:ad:6e:bf:a3:49:3c:0a:68:96:49:
        bb:ca:58:eb:13:fd:56:0e:90:9b:5f:2f:40:b4:b3:b7:26:cb:
        3d:02:21:00:f4:cd:24:bb:ad:02:db:5b:e8:cb:50:9f:c6:3a:
        ef:13:e1:4e:6b:70:1d:3a:d2:10:32:d4:96:34:f8:52:9b:80

```

openssl verify chain ✅