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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/to4PSORb9CekCkQWXsyywhMmvrK2XbMD
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/4ad35c9d4c7b8405/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/xwGRxYaNRsYRsZBZl281NFARmoqOYiuh
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/B07ljGq51MhDersPbE8lBWky1ubciJtA
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/x5tVFUvGfs3xWIQYQjzrbx50GhsDVZ2e
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:33270/acme/wire/directory
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
  "newNonce": "https://stepca:33270/acme/wire/new-nonce",
  "newAccount": "https://stepca:33270/acme/wire/new-account",
  "newOrder": "https://stepca:33270/acme/wire/new-order",
  "revokeCert": "https://stepca:33270/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:33270/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:33270/acme/wire/directory>;rel="index"
replay-nonce: em5yanN4NGlUNGQ2TnROR3BWZDlpSTdFMEZqNmtHZjk
vary: Origin
```
```text
em5yanN4NGlUNGQ2TnROR3BWZDlpSTdFMEZqNmtHZjk
```
#### 5. create a new account
```http request
POST https://stepca:33270/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Il9Sa1FkSGdPRUNKLThmRkF2S0NkMWhlVFpWU1NHcWg2QkFjZWMwVll1LVEifSwibm9uY2UiOiJlbTV5YW5ONE5HbFVOR1EyVG5ST1IzQldaRGxwU1RkRk1FWnFObXRIWmprIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyNzAvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "Sd7Em3qtyIUVYKliVTGAXqEwV0CydGKadtdxcmk91nGamaUpL0pRkNJ8jHw-HySQcvaUU9foBkO2XBZFz2ijCg"
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
      "x": "_RkQdHgOECJ-8fFAvKCd1heTZVSSGqh6BAcec0VYu-Q"
    },
    "nonce": "em5yanN4NGlUNGQ2TnROR3BWZDlpSTdFMEZqNmtHZjk",
    "url": "https://stepca:33270/acme/wire/new-account"
  },
  "payload": {
    "termsOfServiceAgreed": true,
    "contact": [
      "anonymous@anonymous.invalid"
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
link: <https://stepca:33270/acme/wire/directory>;rel="index"
location: https://stepca:33270/acme/wire/account/vJnPkkMXFmyB6igfsi53cH1bk7LEfNz0
replay-nonce: NlVuSFZRNjZ4TFE5Rk85Q1JDNmtWSVpPczRwaXFZU0M
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:33270/acme/wire/account/vJnPkkMXFmyB6igfsi53cH1bk7LEfNz0/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:33270/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjcwL2FjbWUvd2lyZS9hY2NvdW50L3ZKblBra01YRm15QjZpZ2ZzaTUzY0gxYms3TEVmTnowIiwidHlwIjoiSldUIiwibm9uY2UiOiJObFZ1U0ZaUk5qWjRURkU1Ums4NVExSkRObXRXU1ZwUGN6UndhWEZaVTBNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyNzAvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9wQklmY29NY1E2aVJHemRrTHJTV1dRITRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIn0ifV0sIm5vdEJlZm9yZSI6IjIwMjQtMDEtMDlUMTQ6MjQ6MzMuNzE5MDQ2WiIsIm5vdEFmdGVyIjoiMjAzNC0wMS0wNlQxNDoyNDozMy43MTkwNDZaIn0",
  "signature": "2pf0Ml5_SlUcZH1MzjrHr3Qdy6ba3hyNmJ1uY8Xxm9khPc092wCt_YK-2cwkMwLUD7CT454ki206M716YjPkDg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33270/acme/wire/account/vJnPkkMXFmyB6igfsi53cH1bk7LEfNz0",
    "typ": "JWT",
    "nonce": "NlVuSFZRNjZ4TFE5Rk85Q1JDNmtWSVpPczRwaXFZU0M",
    "url": "https://stepca:33270/acme/wire/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://pBIfcoMcQ6iRGzdkLrSWWQ!4ad35c9d4c7b8405@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
      }
    ],
    "notBefore": "2024-01-09T14:24:33.719046Z",
    "notAfter": "2034-01-06T14:24:33.719046Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33270/acme/wire/directory>;rel="index"
location: https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B
replay-nonce: cFFrNjBPQlR5U3B1dGdndlZYMjlVOU01eUdlTE00dGo
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://pBIfcoMcQ6iRGzdkLrSWWQ!4ad35c9d4c7b8405@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33270/acme/wire/authz/to4PSORb9CekCkQWXsyywhMmvrK2XbMD"
  ],
  "expires": "2024-01-10T14:24:33Z",
  "notBefore": "2024-01-09T14:24:33.719046Z",
  "notAfter": "2034-01-06T14:24:33.719046Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:33270/acme/wire/authz/to4PSORb9CekCkQWXsyywhMmvrK2XbMD
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjcwL2FjbWUvd2lyZS9hY2NvdW50L3ZKblBra01YRm15QjZpZ2ZzaTUzY0gxYms3TEVmTnowIiwidHlwIjoiSldUIiwibm9uY2UiOiJjRkZyTmpCUFFsUjVVM0IxZEdkbmRsWllNamxWT1UwMWVVZGxURTAwZEdvIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyNzAvYWNtZS93aXJlL2F1dGh6L3RvNFBTT1JiOUNla0NrUVdYc3l5d2hNbXZySzJYYk1EIn0",
  "payload": "",
  "signature": "O3a2YmI1IIonuY2tyrr5L9f-9Das6iuVcLwB-BzMEFbrsdAh6vYSISaQrgWVjpHIuCnv3cJ2AHDp6NkwDepiCg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33270/acme/wire/account/vJnPkkMXFmyB6igfsi53cH1bk7LEfNz0",
    "typ": "JWT",
    "nonce": "cFFrNjBPQlR5U3B1dGdndlZYMjlVOU01eUdlTE00dGo",
    "url": "https://stepca:33270/acme/wire/authz/to4PSORb9CekCkQWXsyywhMmvrK2XbMD"
  },
  "payload": {}
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33270/acme/wire/directory>;rel="index"
location: https://stepca:33270/acme/wire/authz/to4PSORb9CekCkQWXsyywhMmvrK2XbMD
replay-nonce: ZkxacHpNdlZvY0V2NnRRM1RTd2N6NE16WXU3bGZXOWI
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2024-01-10T14:24:33Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/B07ljGq51MhDersPbE8lBWky1ubciJtA",
      "status": "pending",
      "token": "HsgMcPSVyxk3uZ1F3z8vxTK2rR0lf0Yr",
      "target": "http://dex:17393/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/xwGRxYaNRsYRsZBZl281NFARmoqOYiuh",
      "status": "pending",
      "token": "HsgMcPSVyxk3uZ1F3z8vxTK2rR0lf0Yr",
      "target": "http://wire.com:23621/clients/4ad35c9d4c7b8405/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://pBIfcoMcQ6iRGzdkLrSWWQ!4ad35c9d4c7b8405@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:23621/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
TnlNS1BVRkdLbW5SQ1BCODRiYVR0NUZVZEljZ0h1cDY
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiX1JrUWRIZ09FQ0otOGZGQXZLQ2QxaGVUWlZTU0dxaDZCQWNlYzBWWXUtUSJ9fQ.eyJpYXQiOjE3MDQ4MDY2NzMsImV4cCI6MTcwNDgxMzg3MywibmJmIjoxNzA0ODA2NjczLCJzdWIiOiJ3aXJlYXBwOi8vcEJJZmNvTWNRNmlSR3pka0xyU1dXUSE0YWQzNWM5ZDRjN2I4NDA1QHdpcmUuY29tIiwianRpIjoiOTQzMzY1ZTUtMGNiMi00NTczLTgxZTItMDYzNzc0NGZmZDhiIiwibm9uY2UiOiJUbmxOUzFCVlJrZExiVzVTUTFCQ09EUmlZVlIwTlVaVlpFbGpaMGgxY0RZIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzYyMS9jbGllbnRzLzRhZDM1YzlkNGM3Yjg0MDUvYWNjZXNzLXRva2VuIiwiY2hhbCI6IkhzZ01jUFNWeXhrM3VaMUYzejh2eFRLMnJSMGxmMFlyIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.dxrYLy5PTEuCzOkE1DYaEfkVT6h5-U_gPKQV1B_i3Z59SB1LzP1QHw2cx0KWWsaKLoJUHx1-0tQlj4EEVG52Cg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiX1JrUWRIZ09FQ0otOGZGQXZLQ2QxaGVU
WlZTU0dxaDZCQWNlYzBWWXUtUSJ9fQ.eyJpYXQiOjE3MDQ4MDY2NzMsImV4cCI6M
TcwNDgxMzg3MywibmJmIjoxNzA0ODA2NjczLCJzdWIiOiJ3aXJlYXBwOi8vcEJJZ
mNvTWNRNmlSR3pka0xyU1dXUSE0YWQzNWM5ZDRjN2I4NDA1QHdpcmUuY29tIiwia
nRpIjoiOTQzMzY1ZTUtMGNiMi00NTczLTgxZTItMDYzNzc0NGZmZDhiIiwibm9uY
2UiOiJUbmxOUzFCVlJrZExiVzVTUTFCQ09EUmlZVlIwTlVaVlpFbGpaMGgxY0RZI
iwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzYyMS9jbGllb
nRzLzRhZDM1YzlkNGM3Yjg0MDUvYWNjZXNzLXRva2VuIiwiY2hhbCI6IkhzZ01jU
FNWeXhrM3VaMUYzejh2eFRLMnJSMGxmMFlyIiwiaGFuZGxlIjoid2lyZWFwcDovL
yU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.dxrYLy5PTEuC
zOkE1DYaEfkVT6h5-U_gPKQV1B_i3Z59SB1LzP1QHw2cx0KWWsaKLoJUHx1-0tQl
j4EEVG52Cg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "dpop+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "_RkQdHgOECJ-8fFAvKCd1heTZVSSGqh6BAcec0VYu-Q"
  }
}
```

```json
{
  "iat": 1704806673,
  "exp": 1704813873,
  "nbf": 1704806673,
  "sub": "wireapp://pBIfcoMcQ6iRGzdkLrSWWQ!4ad35c9d4c7b8405@wire.com",
  "jti": "943365e5-0cb2-4573-81e2-0637744ffd8b",
  "nonce": "TnlNS1BVRkdLbW5SQ1BCODRiYVR0NUZVZEljZ0h1cDY",
  "htm": "POST",
  "htu": "http://wire.com:23621/clients/4ad35c9d4c7b8405/access-token",
  "chal": "HsgMcPSVyxk3uZ1F3z8vxTK2rR0lf0Yr",
  "handle": "wireapp://%40alice_wire@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINMaOUN9oDDZq6rmkW6t3UiQrEwid1XP8HoLJAfdRQDv
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA/RkQdHgOECJ+8fFAvKCd1heTZVSSGqh6BAcec0VYu+Q=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:23621/clients/4ad35c9d4c7b8405/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pWDFKclVXUklaMDlGUTBvdE9HWkdRWFpMUTJReGFHVlVXbFpUVTBkeGFEWkNRV05sWXpCV1dYVXRVU0o5ZlEuZXlKcFlYUWlPakUzTURRNE1EWTJOek1zSW1WNGNDSTZNVGN3TkRneE16ZzNNeXdpYm1KbUlqb3hOekEwT0RBMk5qY3pMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pT1RRek16WTFaVFV0TUdOaU1pMDBOVGN6TFRneFpUSXRNRFl6TnpjME5HWm1aRGhpSWl3aWJtOXVZMlVpT2lKVWJteE9VekZDVmxKclpFeGlWelZUVVRGQ1EwOUVVbWxaVmxJd1RsVmFWbHBGYkdwYU1HZ3hZMFJaSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU16WXlNUzlqYkdsbGJuUnpMelJoWkRNMVl6bGtOR00zWWpnME1EVXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtoelowMWpVRk5XZVhock0zVmFNVVl6ZWpoMmVGUkxNbkpTTUd4bU1GbHlJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5keHJZTHk1UFRFdUN6T2tFMURZYUVma1ZUNmg1LVVfZ1BLUVYxQl9pM1o1OVNCMUx6UDFRSHcyY3gwS1dXc2FLTG9KVUh4MS0wdFFsajRFRVZHNTJDZw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjZMYWNCaWxQZEh5T3M2WE1od05JQ0IwMU9kOE0tcngxZHVFNWQ0Vmx4T2sifX0.eyJpYXQiOjE3MDQ4MDY2NzMsImV4cCI6MTcwNDgxMDYzMywibmJmIjoxNzA0ODA2NjczLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2MjEvY2xpZW50cy80YWQzNWM5ZDRjN2I4NDA1L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9wQklmY29NY1E2aVJHemRrTHJTV1dRITRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjM2MjEvY2xpZW50cy80YWQzNWM5ZDRjN2I4NDA1L2FjY2Vzcy10b2tlbiIsImp0aSI6ImY4NzRmYzJkLTdjZTItNDdlZi05M2JlLTY5NjUyOWQ2YWFmYiIsIm5vbmNlIjoiVG5sTlMxQlZSa2RMYlc1U1ExQkNPRFJpWVZSME5VWlZaRWxqWjBoMWNEWSIsImNoYWwiOiJIc2dNY1BTVnl4azN1WjFGM3o4dnhUSzJyUjBsZjBZciIsImNuZiI6eyJraWQiOiJsYjRfWEM1amo1bEMwazZ2LWJYem84ZzRwTFduNWNoRm1SYVAwMmF1eDRvIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pWDFKclVXUklaMDlGUTBvdE9HWkdRWFpMUTJReGFHVlVXbFpUVTBkeGFEWkNRV05sWXpCV1dYVXRVU0o5ZlEuZXlKcFlYUWlPakUzTURRNE1EWTJOek1zSW1WNGNDSTZNVGN3TkRneE16ZzNNeXdpYm1KbUlqb3hOekEwT0RBMk5qY3pMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pT1RRek16WTFaVFV0TUdOaU1pMDBOVGN6TFRneFpUSXRNRFl6TnpjME5HWm1aRGhpSWl3aWJtOXVZMlVpT2lKVWJteE9VekZDVmxKclpFeGlWelZUVVRGQ1EwOUVVbWxaVmxJd1RsVmFWbHBGYkdwYU1HZ3hZMFJaSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU16WXlNUzlqYkdsbGJuUnpMelJoWkRNMVl6bGtOR00zWWpnME1EVXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtoelowMWpVRk5XZVhock0zVmFNVVl6ZWpoMmVGUkxNbkpTTUd4bU1GbHlJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5keHJZTHk1UFRFdUN6T2tFMURZYUVma1ZUNmg1LVVfZ1BLUVYxQl9pM1o1OVNCMUx6UDFRSHcyY3gwS1dXc2FLTG9KVUh4MS0wdFFsajRFRVZHNTJDZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9wQklmY29NY1E2aVJHemRrTHJTV1dRITRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.QQHwDPswh8zpEqaFFg1VH-gUv-C8D8abFZ9oi2tRZBXoW9Ep5fnYIkV1TtAo_AuOp97PZbd3XVSA-QRTiyZmCA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjZMYWNCaWxQZEh5T3M2WE1od05JQ0IwMU9kOE0tcngxZHVFNWQ0Vmx4T2sifX0.eyJpYXQiOjE3MDQ4MDY2NzMsImV4cCI6MTcwNDgxMDYzMywibmJmIjoxNzA0ODA2NjczLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2MjEvY2xpZW50cy80YWQzNWM5ZDRjN2I4NDA1L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9wQklmY29NY1E2aVJHemRrTHJTV1dRITRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjM2MjEvY2xpZW50cy80YWQzNWM5ZDRjN2I4NDA1L2FjY2Vzcy10b2tlbiIsImp0aSI6ImY4NzRmYzJkLTdjZTItNDdlZi05M2JlLTY5NjUyOWQ2YWFmYiIsIm5vbmNlIjoiVG5sTlMxQlZSa2RMYlc1U1ExQkNPRFJpWVZSME5VWlZaRWxqWjBoMWNEWSIsImNoYWwiOiJIc2dNY1BTVnl4azN1WjFGM3o4dnhUSzJyUjBsZjBZciIsImNuZiI6eyJraWQiOiJsYjRfWEM1amo1bEMwazZ2LWJYem84ZzRwTFduNWNoRm1SYVAwMmF1eDRvIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pWDFKclVXUklaMDlGUTBvdE9HWkdRWFpMUTJReGFHVlVXbFpUVTBkeGFEWkNRV05sWXpCV1dYVXRVU0o5ZlEuZXlKcFlYUWlPakUzTURRNE1EWTJOek1zSW1WNGNDSTZNVGN3TkRneE16ZzNNeXdpYm1KbUlqb3hOekEwT0RBMk5qY3pMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pT1RRek16WTFaVFV0TUdOaU1pMDBOVGN6TFRneFpUSXRNRFl6TnpjME5HWm1aRGhpSWl3aWJtOXVZMlVpT2lKVWJteE9VekZDVmxKclpFeGlWelZUVVRGQ1EwOUVVbWxaVmxJd1RsVmFWbHBGYkdwYU1HZ3hZMFJaSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU16WXlNUzlqYkdsbGJuUnpMelJoWkRNMVl6bGtOR00zWWpnME1EVXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtoelowMWpVRk5XZVhock0zVmFNVVl6ZWpoMmVGUkxNbkpTTUd4bU1GbHlJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5keHJZTHk1UFRFdUN6T2tFMURZYUVma1ZUNmg1LVVfZ1BLUVYxQl9pM1o1OVNCMUx6UDFRSHcyY3gwS1dXc2FLTG9KVUh4MS0wdFFsajRFRVZHNTJDZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9wQklmY29NY1E2aVJHemRrTHJTV1dRITRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.QQHwDPswh8zpEqaFFg1VH-gUv-C8D8abFZ9oi2tRZBXoW9Ep5fnYIkV1TtAo_AuOp97PZbd3XVSA-QRTiyZmCA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IjZMYWNCaWxQZEh5T3M2WE1od05JQ0IwMU9k
OE0tcngxZHVFNWQ0Vmx4T2sifX0.eyJpYXQiOjE3MDQ4MDY2NzMsImV4cCI6MTcw
NDgxMDYzMywibmJmIjoxNzA0ODA2NjczLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjM2MjEvY2xpZW50cy80YWQzNWM5ZDRjN2I4NDA1L2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9wQklmY29NY1E2aVJHemRrTHJTV1dRITRhZDM1YzlkNGM3
Yjg0MDVAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjM2MjEvY2xp
ZW50cy80YWQzNWM5ZDRjN2I4NDA1L2FjY2Vzcy10b2tlbiIsImp0aSI6ImY4NzRm
YzJkLTdjZTItNDdlZi05M2JlLTY5NjUyOWQ2YWFmYiIsIm5vbmNlIjoiVG5sTlMx
QlZSa2RMYlc1U1ExQkNPRFJpWVZSME5VWlZaRWxqWjBoMWNEWSIsImNoYWwiOiJI
c2dNY1BTVnl4azN1WjFGM3o4dnhUSzJyUjBsZjBZciIsImNuZiI6eyJraWQiOiJs
YjRfWEM1amo1bEMwazZ2LWJYem84ZzRwTFduNWNoRm1SYVAwMmF1eDRvIn0sInBy
b29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElp
d2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxD
SjRJam9pWDFKclVXUklaMDlGUTBvdE9HWkdRWFpMUTJReGFHVlVXbFpUVTBkeGFE
WkNRV05sWXpCV1dYVXRVU0o5ZlEuZXlKcFlYUWlPakUzTURRNE1EWTJOek1zSW1W
NGNDSTZNVGN3TkRneE16ZzNNeXdpYm1KbUlqb3hOekEwT0RBMk5qY3pMQ0p6ZFdJ
aU9pSjNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNF
MFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pT1RR
ek16WTFaVFV0TUdOaU1pMDBOVGN6TFRneFpUSXRNRFl6TnpjME5HWm1aRGhpSWl3
aWJtOXVZMlVpT2lKVWJteE9VekZDVmxKclpFeGlWelZUVVRGQ1EwOUVVbWxaVmxJ
d1RsVmFWbHBGYkdwYU1HZ3hZMFJaSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJ
NkltaDBkSEE2THk5M2FYSmxMbU52YlRveU16WXlNUzlqYkdsbGJuUnpMelJoWkRN
MVl6bGtOR00zWWpnME1EVXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWto
elowMWpVRk5XZVhock0zVmFNVVl6ZWpoMmVGUkxNbkpTTUd4bU1GbHlJaXdpYUdG
dVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1
amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5keHJZTHk1UFRFdUN6T2tFMURZYUVm
a1ZUNmg1LVVfZ1BLUVYxQl9pM1o1OVNCMUx6UDFRSHcyY3gwS1dXc2FLTG9KVUh4
MS0wdFFsajRFRVZHNTJDZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9wQklmY29N
Y1E2aVJHemRrTHJTV1dRITRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb20iLCJhcGlf
dmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.QQHwDPswh8zpEqa
FFg1VH-gUv-C8D8abFZ9oi2tRZBXoW9Ep5fnYIkV1TtAo_AuOp97PZbd3XVSA-QR
TiyZmCA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "typ": "at+jwt",
  "jwk": {
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "6LacBilPdHyOs6XMhwNICB01Od8M-rx1duE5d4VlxOk"
  }
}
```

```json
{
  "iat": 1704806673,
  "exp": 1704810633,
  "nbf": 1704806673,
  "iss": "http://wire.com:23621/clients/4ad35c9d4c7b8405/access-token",
  "sub": "wireapp://pBIfcoMcQ6iRGzdkLrSWWQ!4ad35c9d4c7b8405@wire.com",
  "aud": "http://wire.com:23621/clients/4ad35c9d4c7b8405/access-token",
  "jti": "f874fc2d-7ce2-47ef-93be-696529d6aafb",
  "nonce": "TnlNS1BVRkdLbW5SQ1BCODRiYVR0NUZVZEljZ0h1cDY",
  "chal": "HsgMcPSVyxk3uZ1F3z8vxTK2rR0lf0Yr",
  "cnf": {
    "kid": "lb4_XC5jj5lC0k6v-bXzo8g4pLWn5chFmRaP02aux4o"
  },
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiX1JrUWRIZ09FQ0otOGZGQXZLQ2QxaGVUWlZTU0dxaDZCQWNlYzBWWXUtUSJ9fQ.eyJpYXQiOjE3MDQ4MDY2NzMsImV4cCI6MTcwNDgxMzg3MywibmJmIjoxNzA0ODA2NjczLCJzdWIiOiJ3aXJlYXBwOi8vcEJJZmNvTWNRNmlSR3pka0xyU1dXUSE0YWQzNWM5ZDRjN2I4NDA1QHdpcmUuY29tIiwianRpIjoiOTQzMzY1ZTUtMGNiMi00NTczLTgxZTItMDYzNzc0NGZmZDhiIiwibm9uY2UiOiJUbmxOUzFCVlJrZExiVzVTUTFCQ09EUmlZVlIwTlVaVlpFbGpaMGgxY0RZIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMzYyMS9jbGllbnRzLzRhZDM1YzlkNGM3Yjg0MDUvYWNjZXNzLXRva2VuIiwiY2hhbCI6IkhzZ01jUFNWeXhrM3VaMUYzejh2eFRLMnJSMGxmMFlyIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.dxrYLy5PTEuCzOkE1DYaEfkVT6h5-U_gPKQV1B_i3Z59SB1LzP1QHw2cx0KWWsaKLoJUHx1-0tQlj4EEVG52Cg",
  "client_id": "wireapp://pBIfcoMcQ6iRGzdkLrSWWQ!4ad35c9d4c7b8405@wire.com",
  "api_version": 5,
  "scope": "wire_client_id"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINy8V290WIpM3oR3l68qfLLPZTODx1SBjv5TSNW1gpJW
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6LacBilPdHyOs6XMhwNICB01Od8M+rx1duE5d4VlxOk=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/xwGRxYaNRsYRsZBZl281NFARmoqOYiuh
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjcwL2FjbWUvd2lyZS9hY2NvdW50L3ZKblBra01YRm15QjZpZ2ZzaTUzY0gxYms3TEVmTnowIiwidHlwIjoiSldUIiwibm9uY2UiOiJaa3hhY0hwTmRsWnZZMFYyTm5SUk0xUlRkMk42TkUxNldYVTNiR1pYT1dJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyNzAvYWNtZS93aXJlL2NoYWxsZW5nZS90bzRQU09SYjlDZWtDa1FXWHN5eXdoTW12cksyWGJNRC94d0dSeFlhTlJzWVJzWkJabDI4MU5GQVJtb3FPWWl1aCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklqWk1ZV05DYVd4UVpFaDVUM00yV0Uxb2QwNUpRMEl3TVU5a09FMHRjbmd4WkhWRk5XUTBWbXg0VDJzaWZYMC5leUpwWVhRaU9qRTNNRFE0TURZMk56TXNJbVY0Y0NJNk1UY3dORGd4TURZek15d2libUptSWpveE56QTBPREEyTmpjekxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNMk1qRXZZMnhwWlc1MGN5ODBZV1F6TldNNVpEUmpOMkk0TkRBMUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTl3UWtsbVkyOU5ZMUUyYVZKSGVtUnJUSEpUVjFkUklUUmhaRE0xWXpsa05HTTNZamcwTURWQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpNMk1qRXZZMnhwWlc1MGN5ODBZV1F6TldNNVpEUmpOMkk0TkRBMUwyRmpZMlZ6Y3kxMGIydGxiaUlzSW1wMGFTSTZJbVk0TnpSbVl6SmtMVGRqWlRJdE5EZGxaaTA1TTJKbExUWTVOalV5T1dRMllXRm1ZaUlzSW01dmJtTmxJam9pVkc1c1RsTXhRbFpTYTJSTVlsYzFVMUV4UWtOUFJGSnBXVlpTTUU1VldsWmFSV3hxV2pCb01XTkVXU0lzSW1Ob1lXd2lPaUpJYzJkTlkxQlRWbmw0YXpOMVdqRkdNM280ZG5oVVN6SnlVakJzWmpCWmNpSXNJbU51WmlJNmV5SnJhV1FpT2lKc1lqUmZXRU0xYW1vMWJFTXdheloyTFdKWWVtODRaelJ3VEZkdU5XTm9SbTFTWVZBd01tRjFlRFJ2SW4wc0luQnliMjltSWpvaVpYbEthR0pIWTJsUGFVcEdXa1ZTVkZGVFNYTkpibEkxWTBOSk5rbHRVbmRpTTBGeVlXNWtNRWxwZDJsaGJtUnlTV3B3TjBsdGREQmxVMGsyU1dzNVRGVkRTWE5KYlU1NVpHbEpOa2xyVm10TmFsVXhUVlJyYVV4RFNqUkphbTlwV0RGS2NsVlhVa2xhTURsR1VUQnZkRTlIV2tkUldGcE1VVEpSZUdGSFZsVlhiRnBVVlRCa2VHRkVXa05SVjA1c1dYcENWMWRZVlhSVlUwbzVabEV1WlhsS2NGbFlVV2xQYWtVelRVUlJORTFFV1RKT2VrMXpTVzFXTkdORFNUWk5WR04zVGtSbmVFMTZaek5OZVhkcFltMUtiVWxxYjNoT2VrRXdUMFJCTWs1cVkzcE1RMHA2WkZkSmFVOXBTak5oV0Vwc1dWaENkMDlwT0haalJVcEtXbTFPZGxSWFRsSk9iV3hUVWpOd2EyRXdlSGxWTVdSWVZWTkZNRmxYVVhwT1YwMDFXa1JTYWs0eVNUUk9SRUV4VVVoa2NHTnRWWFZaTWpsMFNXbDNhV0Z1VW5CSmFtOXBUMVJSZWsxNldURmFWRlYwVFVkT2FVMXBNREJPVkdONlRGUm5lRnBVU1hSTlJGbDZUbnBqTUU1SFdtMWFSR2hwU1dsM2FXSnRPWFZaTWxWcFQybEtWV0p0ZUU5VmVrWkRWbXhLY2xwRmVHbFdlbFpVVlZSR1ExRXdPVVZWYld4YVZteEpkMVJzVm1GV2JIQkdZa2R3WVUxSFozaFpNRkphU1dsM2FXRklVblJKYW05cFZVVTVWRlpEU1hOSmJXZ3daRk5KTmtsdGFEQmtTRUUyVEhrNU0yRllTbXhNYlU1MllsUnZlVTE2V1hsTlV6bHFZa2RzYkdKdVVucE1lbEpvV2tSTk1WbDZiR3RPUjAweldXcG5NRTFFVlhaWlYwNXFXbGhPZWt4WVVuWmhNbFoxU1dsM2FWa3lhR2hpUTBrMlNXdG9lbG93TVdwVlJrNVhaVmhvY2swelZtRk5WVmw2Wldwb01tVkdVa3hOYmtwVFRVZDRiVTFHYkhsSmFYZHBZVWRHZFZwSGVHeEphbTlwWkRKc2VWcFhSbmRqUkc5MlRIbFZNRTFIUm5OaFYwNXNXRE5rY0dOdFZrRmtNbXg1V2xNMWFtSXlNR2xNUTBvd1dsZEdkRWxxYjJsa01teDVXbE5LT1M1a2VISlpUSGsxVUZSRmRVTjZUMnRGTVVSWllVVm1hMVpVTm1nMUxWVmZaMUJMVVZZeFFsOXBNMW8xT1ZOQ01VeDZVREZSU0hjeVkzZ3dTMWRYYzJGTFRHOUtWVWg0TVMwd2RGRnNhalJGUlZaSE5USkRaeUlzSW1Oc2FXVnVkRjlwWkNJNkluZHBjbVZoY0hBNkx5OXdRa2xtWTI5TlkxRTJhVkpIZW1SclRISlRWMWRSSVRSaFpETTFZemxrTkdNM1lqZzBNRFZBZDJseVpTNWpiMjBpTENKaGNHbGZkbVZ5YzJsdmJpSTZOU3dpYzJOdmNHVWlPaUozYVhKbFgyTnNhV1Z1ZEY5cFpDSjkuUVFId0RQc3doOHpwRXFhRkZnMVZILWdVdi1DOEQ4YWJGWjlvaTJ0UlpCWG9XOUVwNWZuWUlrVjFUdEFvX0F1T3A5N1BaYmQzWFZTQS1RUlRpeVptQ0EifQ",
  "signature": "D7NiXQ6WwiUtti9_JjxeLflMCrsgH2UCUlPTHsE19Qd3jCh5rvse0t4T4psqA64qCpgbMe6FRgZf6tXFeauSAg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33270/acme/wire/account/vJnPkkMXFmyB6igfsi53cH1bk7LEfNz0",
    "typ": "JWT",
    "nonce": "ZkxacHpNdlZvY0V2NnRRM1RTd2N6NE16WXU3bGZXOWI",
    "url": "https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/xwGRxYaNRsYRsZBZl281NFARmoqOYiuh"
  },
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjZMYWNCaWxQZEh5T3M2WE1od05JQ0IwMU9kOE0tcngxZHVFNWQ0Vmx4T2sifX0.eyJpYXQiOjE3MDQ4MDY2NzMsImV4cCI6MTcwNDgxMDYzMywibmJmIjoxNzA0ODA2NjczLCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjM2MjEvY2xpZW50cy80YWQzNWM5ZDRjN2I4NDA1L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9wQklmY29NY1E2aVJHemRrTHJTV1dRITRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjM2MjEvY2xpZW50cy80YWQzNWM5ZDRjN2I4NDA1L2FjY2Vzcy10b2tlbiIsImp0aSI6ImY4NzRmYzJkLTdjZTItNDdlZi05M2JlLTY5NjUyOWQ2YWFmYiIsIm5vbmNlIjoiVG5sTlMxQlZSa2RMYlc1U1ExQkNPRFJpWVZSME5VWlZaRWxqWjBoMWNEWSIsImNoYWwiOiJIc2dNY1BTVnl4azN1WjFGM3o4dnhUSzJyUjBsZjBZciIsImNuZiI6eyJraWQiOiJsYjRfWEM1amo1bEMwazZ2LWJYem84ZzRwTFduNWNoRm1SYVAwMmF1eDRvIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pWDFKclVXUklaMDlGUTBvdE9HWkdRWFpMUTJReGFHVlVXbFpUVTBkeGFEWkNRV05sWXpCV1dYVXRVU0o5ZlEuZXlKcFlYUWlPakUzTURRNE1EWTJOek1zSW1WNGNDSTZNVGN3TkRneE16ZzNNeXdpYm1KbUlqb3hOekEwT0RBMk5qY3pMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pT1RRek16WTFaVFV0TUdOaU1pMDBOVGN6TFRneFpUSXRNRFl6TnpjME5HWm1aRGhpSWl3aWJtOXVZMlVpT2lKVWJteE9VekZDVmxKclpFeGlWelZUVVRGQ1EwOUVVbWxaVmxJd1RsVmFWbHBGYkdwYU1HZ3hZMFJaSWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU16WXlNUzlqYkdsbGJuUnpMelJoWkRNMVl6bGtOR00zWWpnME1EVXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtoelowMWpVRk5XZVhock0zVmFNVVl6ZWpoMmVGUkxNbkpTTUd4bU1GbHlJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5keHJZTHk1UFRFdUN6T2tFMURZYUVma1ZUNmg1LVVfZ1BLUVYxQl9pM1o1OVNCMUx6UDFRSHcyY3gwS1dXc2FLTG9KVUh4MS0wdFFsajRFRVZHNTJDZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9wQklmY29NY1E2aVJHemRrTHJTV1dRITRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.QQHwDPswh8zpEqaFFg1VH-gUv-C8D8abFZ9oi2tRZBXoW9Ep5fnYIkV1TtAo_AuOp97PZbd3XVSA-QRTiyZmCA"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33270/acme/wire/directory>;rel="index"
link: <https://stepca:33270/acme/wire/authz/to4PSORb9CekCkQWXsyywhMmvrK2XbMD>;rel="up"
location: https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/xwGRxYaNRsYRsZBZl281NFARmoqOYiuh
replay-nonce: UmZZRjQ2eU0yMGJXQnRITGs1ZW5JNUdZcFlUa0N4ZE8
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/xwGRxYaNRsYRsZBZl281NFARmoqOYiuh",
  "status": "valid",
  "token": "HsgMcPSVyxk3uZ1F3z8vxTK2rR0lf0Yr",
  "target": "http://wire.com:23621/clients/4ad35c9d4c7b8405/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=DUDW0T73cutjIPqOP4LQ4f5DhfDBSqdGGYe7ffMYJ2w&code_challenge=JcCA9MwO9JfGCcdaeum9dR9UuTGsUowlFHZLMvdoaxM
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:17393/dex/auth?response_type=code&client_id=wireapp&state=AfjyWo0E3QCmsGvQldSg0w&code_challenge=JcCA9MwO9JfGCcdaeum9dR9UuTGsUowlFHZLMvdoaxM&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A23621%2Fcallback&scope=openid+profile&nonce=ERROX1ws_HiWYZBsRi2idw
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:17393/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpTMlphWVhvM00wODNaMm95UkVkb1lrUlRTMU01UW5JMg==
```
```text
grant_type=authorization_code&code=n4ypdg44kxfe5aq6gukbuzfdm&code_verifier=DUDW0T73cutjIPqOP4LQ4f5DhfDBSqdGGYe7ffMYJ2w&redirect_uri=http%3A%2F%2Fwire.com%3A23621%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjllMzU4OWNhMDI5YjI0NjJkMDk2ZTI1YzBlNzQzZGMwOWE2Yzc5NzcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MzkzL2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0ODk2NjczLCJpYXQiOjE3MDQ4MTAyNzMsIm5vbmNlIjoiRVJST1gxd3NfSGlXWVpCc1JpMmlkdyIsImF0X2hhc2giOiJ5WkRDNVVwaE1WQmJZWHJld0lkd2xRIiwibmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.EcAxyERgHwXbqvgZt8zDSQqtHDb85neZ02Vttk3nkezo7KV0aqn32ZQDNC5WJ-R6A4R4_tMhFuLGvrVp7nOg0rOE2u68Q-TdgyO-F02l6fd1I6o2iBhZnyZTuLQwLJTp372B61y3FPJ9KlnqxiaUj9PNckd_eNGp2psamMPk_HmLan70HHobedPBTkhffwaKz8xSOx0po1TkotfW58X38ZMwEP-W7VXjlho-4cS7JCRgCZAxdlE4ii0ct9UtMP9e5qOcwGD2qYlvYJ_7X_j83ghPkO76haMPLKb8piRK1nwyQIw9F4L7EQ2XXGtc60azVX51elqB6R2MHxRApYtVow",
  "token_type": "bearer",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjllMzU4OWNhMDI5YjI0NjJkMDk2ZTI1YzBlNzQzZGMwOWE2Yzc5NzcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MzkzL2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0ODk2NjczLCJpYXQiOjE3MDQ4MTAyNzMsIm5vbmNlIjoiRVJST1gxd3NfSGlXWVpCc1JpMmlkdyIsImF0X2hhc2giOiJ5YjQ4T1FsRDAzNVFqNmxfbHJzR3pBIiwiY19oYXNoIjoiLVNtcjRZVEZIUmNzaERUQTNPYXdTZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ZKRh9lSlw9KpRuDt7pxHSXU4kXnV-xLlhKXobt_pCXWxtg4EUmW59_8WItmlvsIJJYgRHJDbAHsxHkmGPKzbC-0D6JlBrA5cLU3TDt0vbpqreuaGC4Fbiyxb4mcFHNf-DiSAFOfmg9XzkqR5EGH6EN510pS_kZlngtAZJC7OQTU-7uks3ldWc7d9Y26E44ZVXD98SbBNwlSHh_wPvzN9EAk0HNGzR53G6VGwSvVF8rFsOnOEpDTh-eFyOkFGHleSL4TDM3pf9dcYObsdrYytdIqaKRNKrJbiocAa0n2Pg3f_2VfBAdrMUhcVNKtSPzYUOqX_WpEG8134m-JcAO2wFQ"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjllMzU4OWNhMDI5YjI0NjJkMDk2ZTI1YzBlNzQzZGMwOWE2Yzc5NzcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MzkzL2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0ODk2NjczLCJpYXQiOjE3MDQ4MTAyNzMsIm5vbmNlIjoiRVJST1gxd3NfSGlXWVpCc1JpMmlkdyIsImF0X2hhc2giOiJ5YjQ4T1FsRDAzNVFqNmxfbHJzR3pBIiwiY19oYXNoIjoiLVNtcjRZVEZIUmNzaERUQTNPYXdTZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ZKRh9lSlw9KpRuDt7pxHSXU4kXnV-xLlhKXobt_pCXWxtg4EUmW59_8WItmlvsIJJYgRHJDbAHsxHkmGPKzbC-0D6JlBrA5cLU3TDt0vbpqreuaGC4Fbiyxb4mcFHNf-DiSAFOfmg9XzkqR5EGH6EN510pS_kZlngtAZJC7OQTU-7uks3ldWc7d9Y26E44ZVXD98SbBNwlSHh_wPvzN9EAk0HNGzR53G6VGwSvVF8rFsOnOEpDTh-eFyOkFGHleSL4TDM3pf9dcYObsdrYytdIqaKRNKrJbiocAa0n2Pg3f_2VfBAdrMUhcVNKtSPzYUOqX_WpEG8134m-JcAO2wFQ
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjllMzU4OWNhMDI5YjI0NjJkMDk2ZTI1YzBlNzQzZGMwOWE2Yzc5NzcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MzkzL2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0ODk2NjczLCJpYXQiOjE3MDQ4MTAyNzMsIm5vbmNlIjoiRVJST1gxd3NfSGlXWVpCc1JpMmlkdyIsImF0X2hhc2giOiJ5YjQ4T1FsRDAzNVFqNmxfbHJzR3pBIiwiY19oYXNoIjoiLVNtcjRZVEZIUmNzaERUQTNPYXdTZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ZKRh9lSlw9KpRuDt7pxHSXU4kXnV-xLlhKXobt_pCXWxtg4EUmW59_8WItmlvsIJJYgRHJDbAHsxHkmGPKzbC-0D6JlBrA5cLU3TDt0vbpqreuaGC4Fbiyxb4mcFHNf-DiSAFOfmg9XzkqR5EGH6EN510pS_kZlngtAZJC7OQTU-7uks3ldWc7d9Y26E44ZVXD98SbBNwlSHh_wPvzN9EAk0HNGzR53G6VGwSvVF8rFsOnOEpDTh-eFyOkFGHleSL4TDM3pf9dcYObsdrYytdIqaKRNKrJbiocAa0n2Pg3f_2VfBAdrMUhcVNKtSPzYUOqX_WpEG8134m-JcAO2wFQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjllMzU4OWNhMDI5YjI0NjJkMDk2ZTI1YzBl
NzQzZGMwOWE2Yzc5NzcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MzkzL2RleCIsI
nN1YiI6IkNqcDNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVM
WRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0RWdSc1pHRnciL
CJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0ODk2NjczLCJpYXQiOjE3MDQ4MTAyN
zMsIm5vbmNlIjoiRVJST1gxd3NfSGlXWVpCc1JpMmlkdyIsImF0X2hhc2giOiJ5Y
jQ4T1FsRDAzNVFqNmxfbHJzR3pBIiwiY19oYXNoIjoiLVNtcjRZVEZIUmNzaERUQ
TNPYXdTZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvb
SIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ZKRh9lSlw9KpR
uDt7pxHSXU4kXnV-xLlhKXobt_pCXWxtg4EUmW59_8WItmlvsIJJYgRHJDbAHsxH
kmGPKzbC-0D6JlBrA5cLU3TDt0vbpqreuaGC4Fbiyxb4mcFHNf-DiSAFOfmg9Xzk
qR5EGH6EN510pS_kZlngtAZJC7OQTU-7uks3ldWc7d9Y26E44ZVXD98SbBNwlSHh
_wPvzN9EAk0HNGzR53G6VGwSvVF8rFsOnOEpDTh-eFyOkFGHleSL4TDM3pf9dcYO
bsdrYytdIqaKRNKrJbiocAa0n2Pg3f_2VfBAdrMUhcVNKtSPzYUOqX_WpEG8134m
-JcAO2wFQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "9e3589ca029b2462d096e25c0e743dc09a6c7977"
}
```

```json
{
  "iss": "http://dex:17393/dex",
  "sub": "Cjp3aXJlYXBwOi8vcEJJZmNvTWNRNmlSR3pka0xyU1dXUSE0YWQzNWM5ZDRjN2I4NDA1QHdpcmUuY29tEgRsZGFw",
  "aud": "wireapp",
  "exp": 1704896673,
  "iat": 1704810273,
  "nonce": "ERROX1ws_HiWYZBsRi2idw",
  "at_hash": "yb48OQlD035Qj6l_lrsGzA",
  "c_hash": "-Smr4YTFHRcshDTA3OawSg",
  "name": "wireapp://%40alice_wire@wire.com",
  "preferred_username": "Alice Smith"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5UPizNvrx+cspsDEklZo
/PTj6lzc7Vc9YVOrxASRaotKrZf+Ael/vw3wYTp0PfuIyoPPF2TR2naLHmwCSnjJ
5n5IurAYZbU15+Krz1Y5xQm+W/NDVloRsIu88+HdXIIx1pVuMP0KRipr5mi0rs6s
bCMDpIKxrmr5Qcza1CSqPirtXDdkcZnw2xuNBRYT5mKFDFgG92AXSjtmz6bwyQtz
KEwz6Iy8mL7xNwCL3AKiov9qsD2IUA0QljXDB5RYNQsi0h6Iri+ZhSfMhYp7tJw4
GWS0NpLVs56P+KWYZvZbOWKz83tqy3I+7ReZfBwxor6yp4fpTIyqxmGeU3S52xCx
9wIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/B07ljGq51MhDersPbE8lBWky1ubciJtA
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjcwL2FjbWUvd2lyZS9hY2NvdW50L3ZKblBra01YRm15QjZpZ2ZzaTUzY0gxYms3TEVmTnowIiwidHlwIjoiSldUIiwibm9uY2UiOiJVbVpaUmpRMmVVMHlNR0pYUW5SSVRHczFaVzVKTlVkWmNGbFVhME40WkU4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyNzAvYWNtZS93aXJlL2NoYWxsZW5nZS90bzRQU09SYjlDZWtDa1FXWHN5eXdoTW12cksyWGJNRC9CMDdsakdxNTFNaERlcnNQYkU4bEJXa3kxdWJjaUp0QSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJamxsTXpVNE9XTmhNREk1WWpJME5qSmtNRGsyWlRJMVl6QmxOelF6WkdNd09XRTJZemM1TnpjaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTNNemt6TDJSbGVDSXNJbk4xWWlJNklrTnFjRE5oV0Vwc1dWaENkMDlwT0haalJVcEtXbTFPZGxSWFRsSk9iV3hUVWpOd2EyRXdlSGxWTVdSWVZWTkZNRmxYVVhwT1YwMDFXa1JTYWs0eVNUUk9SRUV4VVVoa2NHTnRWWFZaTWpsMFJXZFNjMXBIUm5jaUxDSmhkV1FpT2lKM2FYSmxZWEJ3SWl3aVpYaHdJam94TnpBME9EazJOamN6TENKcFlYUWlPakUzTURRNE1UQXlOek1zSW01dmJtTmxJam9pUlZKU1QxZ3hkM05mU0dsWFdWcENjMUpwTW1sa2R5SXNJbUYwWDJoaGMyZ2lPaUo1WWpRNFQxRnNSREF6TlZGcU5teGZiSEp6UjNwQklpd2lZMTlvWVhOb0lqb2lMVk50Y2pSWlZFWklVbU56YUVSVVFUTlBZWGRUWnlJc0ltNWhiV1VpT2lKM2FYSmxZWEJ3T2k4dkpUUXdZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW5CeVpXWmxjbkpsWkY5MWMyVnlibUZ0WlNJNklrRnNhV05sSUZOdGFYUm9JbjAuWktSaDlsU2x3OUtwUnVEdDdweEhTWFU0a1huVi14TGxoS1hvYnRfcENYV3h0ZzRFVW1XNTlfOFdJdG1sdnNJSkpZZ1JISkRiQUhzeEhrbUdQS3piQy0wRDZKbEJyQTVjTFUzVER0MHZicHFyZXVhR0M0RmJpeXhiNG1jRkhOZi1EaVNBRk9mbWc5WHprcVI1RUdINkVONTEwcFNfa1psbmd0QVpKQzdPUVRVLTd1a3MzbGRXYzdkOVkyNkU0NFpWWEQ5OFNiQk53bFNIaF93UHZ6TjlFQWswSE5HelI1M0c2Vkd3U3ZWRjhyRnNPbk9FcERUaC1lRnlPa0ZHSGxlU0w0VERNM3BmOWRjWU9ic2RyWXl0ZElxYUtSTktySmJpb2NBYTBuMlBnM2ZfMlZmQkFkck1VaGNWTkt0U1B6WVVPcVhfV3BFRzgxMzRtLUpjQU8yd0ZRIiwia2V5YXV0aCI6IkhzZ01jUFNWeXhrM3VaMUYzejh2eFRLMnJSMGxmMFlyLmxiNF9YQzVqajVsQzBrNnYtYlh6bzhnNHBMV241Y2hGbVJhUDAyYXV4NG8ifQ",
  "signature": "FF1Q7eW1iJPwrdyJe0QoP_P6lzhRw3DxwHsjJ7c3A6brIDbfxxK8Q_tuypBWCovggHj6ZXUCl_R7U2t_DViZAQ"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33270/acme/wire/account/vJnPkkMXFmyB6igfsi53cH1bk7LEfNz0",
    "typ": "JWT",
    "nonce": "UmZZRjQ2eU0yMGJXQnRITGs1ZW5JNUdZcFlUa0N4ZE8",
    "url": "https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/B07ljGq51MhDersPbE8lBWky1ubciJtA"
  },
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjllMzU4OWNhMDI5YjI0NjJkMDk2ZTI1YzBlNzQzZGMwOWE2Yzc5NzcifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE3MzkzL2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZjRUpKWm1OdlRXTlJObWxTUjNwa2EweHlVMWRYVVNFMFlXUXpOV001WkRSak4ySTROREExUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0ODk2NjczLCJpYXQiOjE3MDQ4MTAyNzMsIm5vbmNlIjoiRVJST1gxd3NfSGlXWVpCc1JpMmlkdyIsImF0X2hhc2giOiJ5YjQ4T1FsRDAzNVFqNmxfbHJzR3pBIiwiY19oYXNoIjoiLVNtcjRZVEZIUmNzaERUQTNPYXdTZyIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.ZKRh9lSlw9KpRuDt7pxHSXU4kXnV-xLlhKXobt_pCXWxtg4EUmW59_8WItmlvsIJJYgRHJDbAHsxHkmGPKzbC-0D6JlBrA5cLU3TDt0vbpqreuaGC4Fbiyxb4mcFHNf-DiSAFOfmg9XzkqR5EGH6EN510pS_kZlngtAZJC7OQTU-7uks3ldWc7d9Y26E44ZVXD98SbBNwlSHh_wPvzN9EAk0HNGzR53G6VGwSvVF8rFsOnOEpDTh-eFyOkFGHleSL4TDM3pf9dcYObsdrYytdIqaKRNKrJbiocAa0n2Pg3f_2VfBAdrMUhcVNKtSPzYUOqX_WpEG8134m-JcAO2wFQ",
    "keyauth": "HsgMcPSVyxk3uZ1F3z8vxTK2rR0lf0Yr.lb4_XC5jj5lC0k6v-bXzo8g4pLWn5chFmRaP02aux4o"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33270/acme/wire/directory>;rel="index"
link: <https://stepca:33270/acme/wire/authz/to4PSORb9CekCkQWXsyywhMmvrK2XbMD>;rel="up"
location: https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/B07ljGq51MhDersPbE8lBWky1ubciJtA
replay-nonce: Vm15bGtZVmFGNnNTRWdQZXVFaG9IMjJGcWl0TzB0emQ
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:33270/acme/wire/challenge/to4PSORb9CekCkQWXsyywhMmvrK2XbMD/B07ljGq51MhDersPbE8lBWky1ubciJtA",
  "status": "valid",
  "token": "HsgMcPSVyxk3uZ1F3z8vxTK2rR0lf0Yr",
  "target": "http://dex:17393/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjcwL2FjbWUvd2lyZS9hY2NvdW50L3ZKblBra01YRm15QjZpZ2ZzaTUzY0gxYms3TEVmTnowIiwidHlwIjoiSldUIiwibm9uY2UiOiJWbTE1Ykd0WlZtRkdObk5UUldkUVpYVkZhRzlJTWpKR2NXbDBUekIwZW1RIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyNzAvYWNtZS93aXJlL29yZGVyL1hqZ00zZTY3cGdZV21ZWllqV21Xc1JlY1o3ck1mZjJCIn0",
  "payload": "",
  "signature": "KBPvCNxnh5I7aghacfExK3Xoxg4YWazhJifcoC2LDX8RlAkpxD7SWomdka3x1lQz3bGvsoa2NlUi7e7macWnBA"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33270/acme/wire/account/vJnPkkMXFmyB6igfsi53cH1bk7LEfNz0",
    "typ": "JWT",
    "nonce": "Vm15bGtZVmFGNnNTRWdQZXVFaG9IMjJGcWl0TzB0emQ",
    "url": "https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B"
  },
  "payload": {}
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33270/acme/wire/directory>;rel="index"
location: https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B
replay-nonce: NGVZSzNqZlpPZ0dScGlVNnJVMHdoYjVKNndNR3FRMWU
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://pBIfcoMcQ6iRGzdkLrSWWQ!4ad35c9d4c7b8405@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33270/acme/wire/authz/to4PSORb9CekCkQWXsyywhMmvrK2XbMD"
  ],
  "expires": "2024-01-10T14:24:33Z",
  "notBefore": "2024-01-09T14:24:33.719046Z",
  "notAfter": "2034-01-06T14:24:33.719046Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjcwL2FjbWUvd2lyZS9hY2NvdW50L3ZKblBra01YRm15QjZpZ2ZzaTUzY0gxYms3TEVmTnowIiwidHlwIjoiSldUIiwibm9uY2UiOiJOR1ZaU3pOcVpscFBaMGRTY0dsVk5uSlZNSGRvWWpWS05uZE5SM0ZSTVdVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyNzAvYWNtZS93aXJlL29yZGVyL1hqZ00zZTY3cGdZV21ZWllqV21Xc1JlY1o3ck1mZjJCL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBSTdwSi1JV2Q1bVFhaEczdXdRM0wxU0tMYTI4ZWRCcGE3bS1qQ2FKNGNGZW9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2Y0VKSlptTnZUV05STm1sU1IzcGthMHh5VTFkWFVTRTBZV1F6TldNNVpEUmpOMkk0TkRBMVFIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFEQlYyLXRFTGdmRzlUUnpRMkN3MzlvTi1URThyalVWR3RRYzhZZTdOb0liZy1mNXlDZk1nMEFBbWNhYU5laTJmcW1Ua002WlJXRVpCdzRvZy1aT2hrRyJ9",
  "signature": "HbzeZ8m03Pr2tosNdfbm0V8LGySKDA5HhelXPsRxq803Kx8M7Jyu-MrQbM6Ckv6XJk8_--aIdOeT3AuGBv4ACg"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33270/acme/wire/account/vJnPkkMXFmyB6igfsi53cH1bk7LEfNz0",
    "typ": "JWT",
    "nonce": "NGVZSzNqZlpPZ0dScGlVNnJVMHdoYjVKNndNR3FRMWU",
    "url": "https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B/finalize"
  },
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAI7pJ-IWd5mQahG3uwQ3L1SKLa28edBpa7m-jCaJ4cFeoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vcEJJZmNvTWNRNmlSR3pka0xyU1dXUSE0YWQzNWM5ZDRjN2I4NDA1QHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQDBV2-tELgfG9TRzQ2Cw39oN-TE8rjUVGtQc8Ye7NoIbg-f5yCfMg0AAmcaaNei2fqmTkM6ZRWEZBw4og-ZOhkG"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAI7pJ+IWd5mQahG3uwQ3L1SKLa28edBp
a7m+jCaJ4cFeoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vcEJJZmNvTWNRNmlSR3pka0xyU1dXUSE0YWQzNWM5ZDRjN2I4NDA1QHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQDB
V2+tELgfG9TRzQ2Cw39oN+TE8rjUVGtQc8Ye7NoIbg+f5yCfMg0AAmcaaNei2fqm
TkM6ZRWEZBw4og+ZOhkG
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
                    8e:e9:27:e2:16:77:99:90:6a:11:b7:bb:04:37:2f:
                    54:8a:2d:ad:bc:79:d0:69:6b:b9:be:8c:26:89:e1:
                    c1:5e
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://pBIfcoMcQ6iRGzdkLrSWWQ!4ad35c9d4c7b8405@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        c1:57:6f:ad:10:b8:1f:1b:d4:d1:cd:0d:82:c3:7f:68:37:e4:
        c4:f2:b8:d4:54:6b:50:73:c6:1e:ec:da:08:6e:0f:9f:e7:20:
        9f:32:0d:00:02:67:1a:68:d7:a2:d9:fa:a6:4e:43:3a:65:15:
        84:64:1c:38:a2:0f:99:3a:19:06

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33270/acme/wire/directory>;rel="index"
location: https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B
replay-nonce: UVhvd09aZzY5NkpXQWpiNW1RVUVZcFFac0lKdzlDRDU
vary: Origin
```
```json
{
  "certificate": "https://stepca:33270/acme/wire/certificate/x5tVFUvGfs3xWIQYQjzrbx50GhsDVZ2e",
  "status": "valid",
  "finalize": "https://stepca:33270/acme/wire/order/XjgM3e67pgYWmYZYjWmWsRecZ7rMff2B/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://pBIfcoMcQ6iRGzdkLrSWWQ!4ad35c9d4c7b8405@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33270/acme/wire/authz/to4PSORb9CekCkQWXsyywhMmvrK2XbMD"
  ],
  "expires": "2024-01-10T14:24:33Z",
  "notBefore": "2024-01-09T14:24:33.719046Z",
  "notAfter": "2034-01-06T14:24:33.719046Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:33270/acme/wire/certificate/x5tVFUvGfs3xWIQYQjzrbx50GhsDVZ2e
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzMjcwL2FjbWUvd2lyZS9hY2NvdW50L3ZKblBra01YRm15QjZpZ2ZzaTUzY0gxYms3TEVmTnowIiwidHlwIjoiSldUIiwibm9uY2UiOiJVVmh2ZDA5YVp6WTVOa3BYUVdwaU5XMVJWVVZaY0ZGYWMwbEtkemxEUkRVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzMyNzAvYWNtZS93aXJlL2NlcnRpZmljYXRlL3g1dFZGVXZHZnMzeFdJUVlRanpyYng1MEdoc0RWWjJlIn0",
  "payload": "",
  "signature": "F9tQ4h4F5RSyb1OzxBFQkx_Y1pzD60W4qMQfGSBbVjQM7WWHOm_ZMwG7B_Rtaea6W_8IuSDzbe7LH_rSIptkCw"
}
```
```json
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33270/acme/wire/account/vJnPkkMXFmyB6igfsi53cH1bk7LEfNz0",
    "typ": "JWT",
    "nonce": "UVhvd09aZzY5NkpXQWpiNW1RVUVZcFFac0lKdzlDRDU",
    "url": "https://stepca:33270/acme/wire/certificate/x5tVFUvGfs3xWIQYQjzrbx50GhsDVZ2e"
  },
  "payload": {}
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:33270/acme/wire/directory>;rel="index"
replay-nonce: dGVSU2FCYm4xRkU4Y21ldW5RMlZQU0VkZkI3OGFvR0s
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGjCCAcCgAwIBAgIRAIFnz0NPv2vdC5rDFHdGSiEwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjQwMTA5MTQyNDMzWhcNMzQwMTA2MTQyNDMzWjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCO6SfiFneZkGoRt7sE\nNy9Uii2tvHnQaWu5vowmieHBXqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l\nBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFJgeGHsXA55oxvBqJ1KYz5DHaMxOMB8G\nA1UdIwQYMBaAFM+bf7+dEKXoSM7s6FaDcJZIuRV9MGkGA1UdEQRiMGCGIHdpcmVh\ncHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vcEJJZmNvTWNR\nNmlSR3pka0xyU1dXUSUyMTRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb20wHQYMKwYB\nBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIBbKN66G\n2WTLlGgKHVoziwfpkY2xpI9sJlu+kRRsNtKbAiEAh8TqIbDPQq5EYQJc/QmPG+wG\ncXYykMZuinJUYNx6NC0=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAP2vQOroYW1kzfFw2RiRamowCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDEwOTE0\nMjQzMVoXDTM0MDEwNjE0MjQzMVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATS\n/3VjlEdKFkxCfQJ5geYA82Agqu9y6OsOqB1VcwN+KERYQQpiSOQ0qN2Ua9QbuNQZ\n61SCKBTDQLyt3EfO3Iwco2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUz5t/v50QpehIzuzoVoNwlki5FX0wHwYDVR0jBBgw\nFoAUTImOSctAsljCeiG8BiHHUbuJ2okwCgYIKoZIzj0EAwIDSAAwRQIhAKOI3wrH\nNdToQeWiQ0D785YQqqjC8z9NfRMjVQr91mNTAiBue3tDQVgHiiNKObcYKOP6VmIc\nVmWQYYdBLV5ImEjMQw==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGjCCAcCgAwIBAgIRAIFnz0NPv2vdC5rDFHdGSiEwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjQwMTA5MTQyNDMzWhcNMzQwMTA2MTQyNDMzWjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCO6SfiFneZkGoRt7sE
Ny9Uii2tvHnQaWu5vowmieHBXqOB8jCB7zAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFJgeGHsXA55oxvBqJ1KYz5DHaMxOMB8G
A1UdIwQYMBaAFM+bf7+dEKXoSM7s6FaDcJZIuRV9MGkGA1UdEQRiMGCGIHdpcmVh
cHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29thjx3aXJlYXBwOi8vcEJJZmNvTWNR
NmlSR3pka0xyU1dXUSUyMTRhZDM1YzlkNGM3Yjg0MDVAd2lyZS5jb20wHQYMKwYB
BAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoGCCqGSM49BAMCA0gAMEUCIBbKN66G
2WTLlGgKHVoziwfpkY2xpI9sJlu+kRRsNtKbAiEAh8TqIbDPQq5EYQJc/QmPG+wG
cXYykMZuinJUYNx6NC0=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            81:67:cf:43:4f:bf:6b:dd:0b:9a:c3:14:77:46:4a:21
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan  9 14:24:33 2024 GMT
            Not After : Jan  6 14:24:33 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    8e:e9:27:e2:16:77:99:90:6a:11:b7:bb:04:37:2f:
                    54:8a:2d:ad:bc:79:d0:69:6b:b9:be:8c:26:89:e1:
                    c1:5e
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                98:1E:18:7B:17:03:9E:68:C6:F0:6A:27:52:98:CF:90:C7:68:CC:4E
            X509v3 Authority Key Identifier: 
                CF:9B:7F:BF:9D:10:A5:E8:48:CE:EC:E8:56:83:70:96:48:B9:15:7D
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://pBIfcoMcQ6iRGzdkLrSWWQ%214ad35c9d4c7b8405@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:16:ca:37:ae:86:d9:64:cb:94:68:0a:1d:5a:33:
        8b:07:e9:91:8d:b1:a4:8f:6c:26:5b:be:91:14:6c:36:d2:9b:
        02:21:00:87:c4:ea:21:b0:cf:42:ae:44:61:02:5c:fd:09:8f:
        1b:ec:06:71:76:32:90:c6:6e:8a:72:54:60:dc:7a:34:2d

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAP2vQOroYW1kzfFw2RiRamowCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDEwOTE0
MjQzMVoXDTM0MDEwNjE0MjQzMVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATS
/3VjlEdKFkxCfQJ5geYA82Agqu9y6OsOqB1VcwN+KERYQQpiSOQ0qN2Ua9QbuNQZ
61SCKBTDQLyt3EfO3Iwco2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUz5t/v50QpehIzuzoVoNwlki5FX0wHwYDVR0jBBgw
FoAUTImOSctAsljCeiG8BiHHUbuJ2okwCgYIKoZIzj0EAwIDSAAwRQIhAKOI3wrH
NdToQeWiQ0D785YQqqjC8z9NfRMjVQr91mNTAiBue3tDQVgHiiNKObcYKOP6VmIc
VmWQYYdBLV5ImEjMQw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            fd:af:40:ea:e8:61:6d:64:cd:f1:70:d9:18:91:6a:6a
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan  9 14:24:31 2024 GMT
            Not After : Jan  6 14:24:31 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:d2:ff:75:63:94:47:4a:16:4c:42:7d:02:79:81:
                    e6:00:f3:60:20:aa:ef:72:e8:eb:0e:a8:1d:55:73:
                    03:7e:28:44:58:41:0a:62:48:e4:34:a8:dd:94:6b:
                    d4:1b:b8:d4:19:eb:54:82:28:14:c3:40:bc:ad:dc:
                    47:ce:dc:8c:1c
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                CF:9B:7F:BF:9D:10:A5:E8:48:CE:EC:E8:56:83:70:96:48:B9:15:7D
            X509v3 Authority Key Identifier: 
                4C:89:8E:49:CB:40:B2:58:C2:7A:21:BC:06:21:C7:51:BB:89:DA:89
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:a3:88:df:0a:c7:35:d4:e8:41:e5:a2:43:40:
        fb:f3:96:10:aa:a8:c2:f3:3f:4d:7d:13:23:55:0a:fd:d6:63:
        53:02:20:6e:7b:7b:43:41:58:07:8a:23:4a:39:b7:18:28:e3:
        fa:56:62:1c:56:65:90:61:87:41:2d:5e:48:98:48:cc:43

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIQXikAcecVVYjevnZYjzldrDAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTA5MTQy
NDMwWhcNMzQwMTA2MTQyNDMwWjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3
aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASUvsJGvrFrWewU
VUayWo1Y5M1ml+d83vmsnlO4H5aoLjPqkXV5P+cSKExe6LOmfiHeUCNSlnCbSRFS
AR+BVBYBo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd
BgNVHQ4EFgQUTImOSctAsljCeiG8BiHHUbuJ2okwCgYIKoZIzj0EAwIDSAAwRQIh
APAL5RBiXWtS1NDB2s2ZkZJQ++TDtAenXUmwB9ppYAlEAiAlwXwbLC4UhxDcD9z5
6yYadA4l83MDPLC1s5baWBrb+w==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5e:29:00:71:e7:15:55:88:de:be:76:58:8f:39:5d:ac
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan  9 14:24:30 2024 GMT
            Not After : Jan  6 14:24:30 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:94:be:c2:46:be:b1:6b:59:ec:14:55:46:b2:5a:
                    8d:58:e4:cd:66:97:e7:7c:de:f9:ac:9e:53:b8:1f:
                    96:a8:2e:33:ea:91:75:79:3f:e7:12:28:4c:5e:e8:
                    b3:a6:7e:21:de:50:23:52:96:70:9b:49:11:52:01:
                    1f:81:54:16:01
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                4C:89:8E:49:CB:40:B2:58:C2:7A:21:BC:06:21:C7:51:BB:89:DA:89
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:f0:0b:e5:10:62:5d:6b:52:d4:d0:c1:da:cd:
        99:91:92:50:fb:e4:c3:b4:07:a7:5d:49:b0:07:da:69:60:09:
        44:02:20:25:c1:7c:1b:2c:2e:14:87:10:dc:0f:dc:f9:eb:26:
        1a:74:0e:25:f3:73:03:3c:b0:b5:b3:96:da:58:1a:db:fb

```

openssl verify chain ✅