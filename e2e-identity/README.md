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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/b764c3887b32a6a7/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/JfMdzzuJ0LsvgJPfgkAV28e6IlthTYLG
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+IdP:  GET /dex/auth
    IdP->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+IdP:  POST /dex/token
    IdP->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/n45gi6jubXNyRl1RXwDnioc2hQQrHGCq
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/OVghb5U24G2ETTXZZQJwomMGNICvsm8V
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:33421/acme/wire/directory
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
  "newNonce": "https://stepca:33421/acme/wire/new-nonce",
  "newAccount": "https://stepca:33421/acme/wire/new-account",
  "newOrder": "https://stepca:33421/acme/wire/new-order",
  "revokeCert": "https://stepca:33421/acme/wire/revoke-cert"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:33421/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:33421/acme/wire/directory>;rel="index"
replay-nonce: YWQwNnlyczNheTBTUUNvSkRMMU9senJVb2pxRW9zTnY
vary: Origin
```
```text
YWQwNnlyczNheTBTUUNvSkRMMU9senJVb2pxRW9zTnY
```
#### 5. create a new account
```http request
POST https://stepca:33421/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IlJZbGlRcnRSSTZwWUZINS1fMVk1NnNscjZQLW14WndJb3RFS09VUjg2TTAifSwibm9uY2UiOiJZV1F3Tm5seWN6TmhlVEJUVVVOdlNrUk1NVTlzZW5KVmIycHhSVzl6VG5ZIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM0MjEvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJhbm9ueW1vdXNAYW5vbnltb3VzLmludmFsaWQiXSwib25seVJldHVybkV4aXN0aW5nIjpmYWxzZX0",
  "signature": "TjmTGFGOZbBuwqKmEbVmJB6n_dhDbVPpO5mYNpvuc9ZHhIsE6QE95fvHwE-pdnPmZLl21rAYiJ-qnX3KHsdaAg"
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
      "x": "RYliQrtRI6pYFH5-_1Y56slr6P-mxZwIotEKOUR86M0"
    },
    "nonce": "YWQwNnlyczNheTBTUUNvSkRMMU9senJVb2pxRW9zTnY",
    "typ": "JWT",
    "url": "https://stepca:33421/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33421/acme/wire/directory>;rel="index"
location: https://stepca:33421/acme/wire/account/Tj1iLYT3OC8fRqyvtLG4vKC9XLEZTYsq
replay-nonce: YjFvd1didFV6YVBxWm9aZTdyVFFFNmkxUXdBNTVDaDM
vary: Origin
```
```json
{
  "status": "valid",
  "orders": "https://stepca:33421/acme/wire/account/Tj1iLYT3OC8fRqyvtLG4vKC9XLEZTYsq/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:33421/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNDIxL2FjbWUvd2lyZS9hY2NvdW50L1RqMWlMWVQzT0M4ZlJxeXZ0TEc0dktDOVhMRVpUWXNxIiwidHlwIjoiSldUIiwibm9uY2UiOiJZakZ2ZDFkaWRGVjZZVkJ4V205YVpUZHlWRkZGTm1reFVYZEJOVFZEYURNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM0MjEvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcIndpcmVhcHA6Ly9jNnQ0R0NoQlN1eXZ1YlcwUWV3TEZBIWI3NjRjMzg4N2IzMmE2YTdAd2lyZS5jb21cIixcImhhbmRsZVwiOlwid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb21cIn0ifV0sIm5vdEJlZm9yZSI6IjIwMjQtMDEtMTBUMTc6MTI6MDcuNTU0NDg2WiIsIm5vdEFmdGVyIjoiMjAzNC0wMS0wN1QxNzoxMjowNy41NTQ0ODZaIn0",
  "signature": "pF4Mvx6HSuhCOlSXSE5uO69cd16cXgxelc-mzCaloZuKyUx6DFJWcE-0e4ja6m4atG4U3pyTFUgGqQj2lDlqAQ"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://c6t4GChBSuyvubW0QewLFA!b764c3887b32a6a7@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
      }
    ],
    "notAfter": "2034-01-07T17:12:07.554486Z",
    "notBefore": "2024-01-10T17:12:07.554486Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33421/acme/wire/account/Tj1iLYT3OC8fRqyvtLG4vKC9XLEZTYsq",
    "nonce": "YjFvd1didFV6YVBxWm9aZTdyVFFFNmkxUXdBNTVDaDM",
    "typ": "JWT",
    "url": "https://stepca:33421/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:33421/acme/wire/directory>;rel="index"
location: https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE
replay-nonce: Y2VxRkREM09NYnRPWHFPTVlDajA3ZG93MTFtN1h4TGI
vary: Origin
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://c6t4GChBSuyvubW0QewLFA!b764c3887b32a6a7@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33421/acme/wire/authz/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ"
  ],
  "expires": "2024-01-11T17:12:07Z",
  "notBefore": "2024-01-10T17:12:07.554486Z",
  "notAfter": "2034-01-07T17:12:07.554486Z"
}
```
### Display-name and handle already authorized
#### 9. create authorization and fetch challenges
```http request
POST https://stepca:33421/acme/wire/authz/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNDIxL2FjbWUvd2lyZS9hY2NvdW50L1RqMWlMWVQzT0M4ZlJxeXZ0TEc0dktDOVhMRVpUWXNxIiwidHlwIjoiSldUIiwibm9uY2UiOiJZMlZ4UmtSRU0wOU5ZblJQV0hGUFRWbERhakEzWkc5M01URnROMWg0VEdJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM0MjEvYWNtZS93aXJlL2F1dGh6LzBhdWQ1WHZEOUVWMG9RaHJiWFBiNkhKVHVLM3lWMm5KIn0",
  "payload": "",
  "signature": "CzXFd1dbyPVQJIuX5Vt4tfG6QbpqSikgRBoAmQc99wfP-O2BHAPbgdWzaNFRO0yP220h8x58rUL1ymMOwjScBQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33421/acme/wire/account/Tj1iLYT3OC8fRqyvtLG4vKC9XLEZTYsq",
    "nonce": "Y2VxRkREM09NYnRPWHFPTVlDajA3ZG93MTFtN1h4TGI",
    "typ": "JWT",
    "url": "https://stepca:33421/acme/wire/authz/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ"
  }
}
```
#### 10. get back challenges
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33421/acme/wire/directory>;rel="index"
location: https://stepca:33421/acme/wire/authz/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ
replay-nonce: Y2F3WDJGTTFxVm5zVWZoNGJGM21FeFhOQnI0WjU0Zkg
vary: Origin
```
```json
{
  "status": "pending",
  "expires": "2024-01-11T17:12:07Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/n45gi6jubXNyRl1RXwDnioc2hQQrHGCq",
      "status": "pending",
      "token": "FJpufnhw2PexFJGxoTYskfiJQsb4lQU1",
      "target": "http://dex:21985/dex"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/JfMdzzuJ0LsvgJPfgkAV28e6IlthTYLG",
      "status": "pending",
      "token": "FJpufnhw2PexFJGxoTYskfiJQsb4lQU1",
      "target": "http://wire.com:20305/clients/b764c3887b32a6a7/access-token"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://c6t4GChBSuyvubW0QewLFA!b764c3887b32a6a7@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:20305/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
U3NoN1BGN3JWSkVCSndTMU5WVWIzQ1VFWDQza3EwdUk
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUllsaVFydFJJNnBZRkg1LV8xWTU2c2xyNlAtbXhad0lvdEVLT1VSODZNMCJ9fQ.eyJpYXQiOjE3MDQ5MDMxMjcsImV4cCI6MTcwNDkxMDMyNywibmJmIjoxNzA0OTAzMTI3LCJzdWIiOiJ3aXJlYXBwOi8vYzZ0NEdDaEJTdXl2dWJXMFFld0xGQSFiNzY0YzM4ODdiMzJhNmE3QHdpcmUuY29tIiwianRpIjoiMzBiOWJhNGMtMGI2Ni00ZTZjLWJlZDQtMjBlMDYyZTgwNTI5Iiwibm9uY2UiOiJVM05vTjFCR04zSldTa1ZDU25kVE1VNVdWV0l6UTFWRldEUXphM0V3ZFVrIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMDMwNS9jbGllbnRzL2I3NjRjMzg4N2IzMmE2YTcvYWNjZXNzLXRva2VuIiwiY2hhbCI6IkZKcHVmbmh3MlBleEZKR3hvVFlza2ZpSlFzYjRsUVUxIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.XBFRmheD3UPlhEwWWXkycte6Ifrd7deoYi0bxzQ7HO8DZK5J2aHWDerPVyIxgDzjdOxIUiWJpenHWbv8EmLxCg)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUllsaVFydFJJNnBZRkg1LV8xWTU2c2xy
NlAtbXhad0lvdEVLT1VSODZNMCJ9fQ.eyJpYXQiOjE3MDQ5MDMxMjcsImV4cCI6M
TcwNDkxMDMyNywibmJmIjoxNzA0OTAzMTI3LCJzdWIiOiJ3aXJlYXBwOi8vYzZ0N
EdDaEJTdXl2dWJXMFFld0xGQSFiNzY0YzM4ODdiMzJhNmE3QHdpcmUuY29tIiwia
nRpIjoiMzBiOWJhNGMtMGI2Ni00ZTZjLWJlZDQtMjBlMDYyZTgwNTI5Iiwibm9uY
2UiOiJVM05vTjFCR04zSldTa1ZDU25kVE1VNVdWV0l6UTFWRldEUXphM0V3ZFVrI
iwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMDMwNS9jbGllb
nRzL2I3NjRjMzg4N2IzMmE2YTcvYWNjZXNzLXRva2VuIiwiY2hhbCI6IkZKcHVmb
mh3MlBleEZKR3hvVFlza2ZpSlFzYjRsUVUxIiwiaGFuZGxlIjoid2lyZWFwcDovL
yU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.XBFRmheD3UPl
hEwWWXkycte6Ifrd7deoYi0bxzQ7HO8DZK5J2aHWDerPVyIxgDzjdOxIUiWJpenH
Wbv8EmLxCg
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "RYliQrtRI6pYFH5-_1Y56slr6P-mxZwIotEKOUR86M0"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "FJpufnhw2PexFJGxoTYskfiJQsb4lQU1",
  "exp": 1704910327,
  "handle": "wireapp://%40alice_wire@wire.com",
  "htm": "POST",
  "htu": "http://wire.com:20305/clients/b764c3887b32a6a7/access-token",
  "iat": 1704903127,
  "jti": "30b9ba4c-0b66-4e6c-bed4-20e062e80529",
  "nbf": 1704903127,
  "nonce": "U3NoN1BGN3JWSkVCSndTMU5WVWIzQ1VFWDQza3EwdUk",
  "sub": "wireapp://c6t4GChBSuyvubW0QewLFA!b764c3887b32a6a7@wire.com",
  "team": "wire"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIF5MTG3Nt/8DJLCPBCLSn4pvJRmb6WfgRaYXwVQXnv/
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARYliQrtRI6pYFH5+/1Y56slr6P+mxZwIotEKOUR86M0=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:20305/clients/b764c3887b32a6a7/access-token
                          /clients/{device-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVWxsc2FWRnlkRkpKTm5CWlJrZzFMVjh4V1RVMmMyeHlObEF0YlhoYWQwbHZkRVZMVDFWU09EWk5NQ0o5ZlEuZXlKcFlYUWlPakUzTURRNU1ETXhNamNzSW1WNGNDSTZNVGN3TkRreE1ETXlOeXdpYm1KbUlqb3hOekEwT1RBek1USTNMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pTXpCaU9XSmhOR010TUdJMk5pMDBaVFpqTFdKbFpEUXRNakJsTURZeVpUZ3dOVEk1SWl3aWJtOXVZMlVpT2lKVk0wNXZUakZDUjA0elNsZFRhMVpEVTI1a1ZFMVZOVmRXVjBsNlVURldSbGRFVVhwaE0wVjNaRlZySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1ETXdOUzlqYkdsbGJuUnpMMkkzTmpSak16ZzROMkl6TW1FMllUY3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtaS2NIVm1ibWgzTWxCbGVFWktSM2h2VkZsemEyWnBTbEZ6WWpSc1VWVXhJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5YQkZSbWhlRDNVUGxoRXdXV1hreWN0ZTZJZnJkN2Rlb1lpMGJ4elE3SE84RFpLNUoyYUhXRGVyUFZ5SXhnRHpqZE94SVVpV0pwZW5IV2J2OEVtTHhDZw
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InNxN3doTUFvWXJTa1g5Q3NUXy1Za0tKc29Tc29JTUJGRGZPQXp4b2tCU2sifX0.eyJpYXQiOjE3MDQ5MDMxMjcsImV4cCI6MTcwNDkwNzA4NywibmJmIjoxNzA0OTAzMTI3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjAzMDUvY2xpZW50cy9iNzY0YzM4ODdiMzJhNmE3L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9jNnQ0R0NoQlN1eXZ1YlcwUWV3TEZBIWI3NjRjMzg4N2IzMmE2YTdAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAzMDUvY2xpZW50cy9iNzY0YzM4ODdiMzJhNmE3L2FjY2Vzcy10b2tlbiIsImp0aSI6IjI1MDY4OTA1LThmMGEtNDUwYS1iMWY3LWZmZTBjNGQxMzNjYiIsIm5vbmNlIjoiVTNOb04xQkdOM0pXU2tWQ1NuZFRNVTVXVldJelExVkZXRFF6YTNFd2RVayIsImNoYWwiOiJGSnB1Zm5odzJQZXhGSkd4b1RZc2tmaUpRc2I0bFFVMSIsImNuZiI6eyJraWQiOiJIWktNbjlFc1Ezd1pac0pwc21qOW1uVGlVcV9TVWN5a1NhZHlhMXZkXzBJIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVWxsc2FWRnlkRkpKTm5CWlJrZzFMVjh4V1RVMmMyeHlObEF0YlhoYWQwbHZkRVZMVDFWU09EWk5NQ0o5ZlEuZXlKcFlYUWlPakUzTURRNU1ETXhNamNzSW1WNGNDSTZNVGN3TkRreE1ETXlOeXdpYm1KbUlqb3hOekEwT1RBek1USTNMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pTXpCaU9XSmhOR010TUdJMk5pMDBaVFpqTFdKbFpEUXRNakJsTURZeVpUZ3dOVEk1SWl3aWJtOXVZMlVpT2lKVk0wNXZUakZDUjA0elNsZFRhMVpEVTI1a1ZFMVZOVmRXVjBsNlVURldSbGRFVVhwaE0wVjNaRlZySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1ETXdOUzlqYkdsbGJuUnpMMkkzTmpSak16ZzROMkl6TW1FMllUY3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtaS2NIVm1ibWgzTWxCbGVFWktSM2h2VkZsemEyWnBTbEZ6WWpSc1VWVXhJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5YQkZSbWhlRDNVUGxoRXdXV1hreWN0ZTZJZnJkN2Rlb1lpMGJ4elE3SE84RFpLNUoyYUhXRGVyUFZ5SXhnRHpqZE94SVVpV0pwZW5IV2J2OEVtTHhDZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9jNnQ0R0NoQlN1eXZ1YlcwUWV3TEZBIWI3NjRjMzg4N2IzMmE2YTdAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.GpnSI-elJqybUGyeKZr_yV69Ehw7aMrH_rzIxBwvHt_JUbO4t0JiN4EtWXhVU0oyTxA8fMB97Gu8RLctW-iBCA",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InNxN3doTUFvWXJTa1g5Q3NUXy1Za0tKc29Tc29JTUJGRGZPQXp4b2tCU2sifX0.eyJpYXQiOjE3MDQ5MDMxMjcsImV4cCI6MTcwNDkwNzA4NywibmJmIjoxNzA0OTAzMTI3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjAzMDUvY2xpZW50cy9iNzY0YzM4ODdiMzJhNmE3L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9jNnQ0R0NoQlN1eXZ1YlcwUWV3TEZBIWI3NjRjMzg4N2IzMmE2YTdAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAzMDUvY2xpZW50cy9iNzY0YzM4ODdiMzJhNmE3L2FjY2Vzcy10b2tlbiIsImp0aSI6IjI1MDY4OTA1LThmMGEtNDUwYS1iMWY3LWZmZTBjNGQxMzNjYiIsIm5vbmNlIjoiVTNOb04xQkdOM0pXU2tWQ1NuZFRNVTVXVldJelExVkZXRFF6YTNFd2RVayIsImNoYWwiOiJGSnB1Zm5odzJQZXhGSkd4b1RZc2tmaUpRc2I0bFFVMSIsImNuZiI6eyJraWQiOiJIWktNbjlFc1Ezd1pac0pwc21qOW1uVGlVcV9TVWN5a1NhZHlhMXZkXzBJIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVWxsc2FWRnlkRkpKTm5CWlJrZzFMVjh4V1RVMmMyeHlObEF0YlhoYWQwbHZkRVZMVDFWU09EWk5NQ0o5ZlEuZXlKcFlYUWlPakUzTURRNU1ETXhNamNzSW1WNGNDSTZNVGN3TkRreE1ETXlOeXdpYm1KbUlqb3hOekEwT1RBek1USTNMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pTXpCaU9XSmhOR010TUdJMk5pMDBaVFpqTFdKbFpEUXRNakJsTURZeVpUZ3dOVEk1SWl3aWJtOXVZMlVpT2lKVk0wNXZUakZDUjA0elNsZFRhMVpEVTI1a1ZFMVZOVmRXVjBsNlVURldSbGRFVVhwaE0wVjNaRlZySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1ETXdOUzlqYkdsbGJuUnpMMkkzTmpSak16ZzROMkl6TW1FMllUY3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtaS2NIVm1ibWgzTWxCbGVFWktSM2h2VkZsemEyWnBTbEZ6WWpSc1VWVXhJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5YQkZSbWhlRDNVUGxoRXdXV1hreWN0ZTZJZnJkN2Rlb1lpMGJ4elE3SE84RFpLNUoyYUhXRGVyUFZ5SXhnRHpqZE94SVVpV0pwZW5IV2J2OEVtTHhDZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9jNnQ0R0NoQlN1eXZ1YlcwUWV3TEZBIWI3NjRjMzg4N2IzMmE2YTdAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.GpnSI-elJqybUGyeKZr_yV69Ehw7aMrH_rzIxBwvHt_JUbO4t0JiN4EtWXhVU0oyTxA8fMB97Gu8RLctW-iBCA)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6InNxN3doTUFvWXJTa1g5Q3NUXy1Za0tKc29T
c29JTUJGRGZPQXp4b2tCU2sifX0.eyJpYXQiOjE3MDQ5MDMxMjcsImV4cCI6MTcw
NDkwNzA4NywibmJmIjoxNzA0OTAzMTI3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MjAzMDUvY2xpZW50cy9iNzY0YzM4ODdiMzJhNmE3L2FjY2Vzcy10b2tlbiIsInN1
YiI6IndpcmVhcHA6Ly9jNnQ0R0NoQlN1eXZ1YlcwUWV3TEZBIWI3NjRjMzg4N2Iz
MmE2YTdAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAzMDUvY2xp
ZW50cy9iNzY0YzM4ODdiMzJhNmE3L2FjY2Vzcy10b2tlbiIsImp0aSI6IjI1MDY4
OTA1LThmMGEtNDUwYS1iMWY3LWZmZTBjNGQxMzNjYiIsIm5vbmNlIjoiVTNOb04x
QkdOM0pXU2tWQ1NuZFRNVTVXVldJelExVkZXRFF6YTNFd2RVayIsImNoYWwiOiJG
SnB1Zm5odzJQZXhGSkd4b1RZc2tmaUpRc2I0bFFVMSIsImNuZiI6eyJraWQiOiJI
WktNbjlFc1Ezd1pac0pwc21qOW1uVGlVcV9TVWN5a1NhZHlhMXZkXzBJIn0sInBy
b29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElp
d2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxD
SjRJam9pVWxsc2FWRnlkRkpKTm5CWlJrZzFMVjh4V1RVMmMyeHlObEF0YlhoYWQw
bHZkRVZMVDFWU09EWk5NQ0o5ZlEuZXlKcFlYUWlPakUzTURRNU1ETXhNamNzSW1W
NGNDSTZNVGN3TkRreE1ETXlOeXdpYm1KbUlqb3hOekEwT1RBek1USTNMQ0p6ZFdJ
aU9pSjNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNG
aU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pTXpC
aU9XSmhOR010TUdJMk5pMDBaVFpqTFdKbFpEUXRNakJsTURZeVpUZ3dOVEk1SWl3
aWJtOXVZMlVpT2lKVk0wNXZUakZDUjA0elNsZFRhMVpEVTI1a1ZFMVZOVmRXVjBs
NlVURldSbGRFVVhwaE0wVjNaRlZySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJ
NkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1ETXdOUzlqYkdsbGJuUnpMMkkzTmpS
ak16ZzROMkl6TW1FMllUY3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWta
S2NIVm1ibWgzTWxCbGVFWktSM2h2VkZsemEyWnBTbEZ6WWpSc1VWVXhJaXdpYUdG
dVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1
amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5YQkZSbWhlRDNVUGxoRXdXV1hreWN0
ZTZJZnJkN2Rlb1lpMGJ4elE3SE84RFpLNUoyYUhXRGVyUFZ5SXhnRHpqZE94SVVp
V0pwZW5IV2J2OEVtTHhDZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9jNnQ0R0No
QlN1eXZ1YlcwUWV3TEZBIWI3NjRjMzg4N2IzMmE2YTdAd2lyZS5jb20iLCJhcGlf
dmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.GpnSI-elJqybUGy
eKZr_yV69Ehw7aMrH_rzIxBwvHt_JUbO4t0JiN4EtWXhVU0oyTxA8fMB97Gu8RLc
tW-iBCA
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "sq7whMAoYrSkX9CsT_-YkKJsoSsoIMBFDfOAzxokBSk"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 5,
  "aud": "http://wire.com:20305/clients/b764c3887b32a6a7/access-token",
  "chal": "FJpufnhw2PexFJGxoTYskfiJQsb4lQU1",
  "client_id": "wireapp://c6t4GChBSuyvubW0QewLFA!b764c3887b32a6a7@wire.com",
  "cnf": {
    "kid": "HZKMn9EsQ3wZZsJpsmj9mnTiUq_SUcykSadya1vd_0I"
  },
  "exp": 1704907087,
  "iat": 1704903127,
  "iss": "http://wire.com:20305/clients/b764c3887b32a6a7/access-token",
  "jti": "25068905-8f0a-450a-b1f7-ffe0c4d133cb",
  "nbf": 1704903127,
  "nonce": "U3NoN1BGN3JWSkVCSndTMU5WVWIzQ1VFWDQza3EwdUk",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiUllsaVFydFJJNnBZRkg1LV8xWTU2c2xyNlAtbXhad0lvdEVLT1VSODZNMCJ9fQ.eyJpYXQiOjE3MDQ5MDMxMjcsImV4cCI6MTcwNDkxMDMyNywibmJmIjoxNzA0OTAzMTI3LCJzdWIiOiJ3aXJlYXBwOi8vYzZ0NEdDaEJTdXl2dWJXMFFld0xGQSFiNzY0YzM4ODdiMzJhNmE3QHdpcmUuY29tIiwianRpIjoiMzBiOWJhNGMtMGI2Ni00ZTZjLWJlZDQtMjBlMDYyZTgwNTI5Iiwibm9uY2UiOiJVM05vTjFCR04zSldTa1ZDU25kVE1VNVdWV0l6UTFWRldEUXphM0V3ZFVrIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly93aXJlLmNvbToyMDMwNS9jbGllbnRzL2I3NjRjMzg4N2IzMmE2YTcvYWNjZXNzLXRva2VuIiwiY2hhbCI6IkZKcHVmbmh3MlBleEZKR3hvVFlza2ZpSlFzYjRsUVUxIiwiaGFuZGxlIjoid2lyZWFwcDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb20iLCJ0ZWFtIjoid2lyZSJ9.XBFRmheD3UPlhEwWWXkycte6Ifrd7deoYi0bxzQ7HO8DZK5J2aHWDerPVyIxgDzjdOxIUiWJpenHWbv8EmLxCg",
  "scope": "wire_client_id",
  "sub": "wireapp://c6t4GChBSuyvubW0QewLFA!b764c3887b32a6a7@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIIhV/nglGU/DH3s40WTSB+o0lSNwua/RTtubh58A5P/U
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAsq7whMAoYrSkX9CsT/+YkKJsoSsoIMBFDfOAzxokBSk=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/JfMdzzuJ0LsvgJPfgkAV28e6IlthTYLG
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNDIxL2FjbWUvd2lyZS9hY2NvdW50L1RqMWlMWVQzT0M4ZlJxeXZ0TEc0dktDOVhMRVpUWXNxIiwidHlwIjoiSldUIiwibm9uY2UiOiJZMkYzV0RKR1RURnhWbTV6Vldab05HSkdNMjFGZUZoT1FuSTBXalUwWmtnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM0MjEvYWNtZS93aXJlL2NoYWxsZW5nZS8wYXVkNVh2RDlFVjBvUWhyYlhQYjZISlR1SzN5VjJuSi9KZk1kenp1SjBMc3ZnSlBmZ2tBVjI4ZTZJbHRoVFlMRyJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluTnhOM2RvVFVGdldYSlRhMWc1UTNOVVh5MVphMHRLYzI5VGMyOUpUVUpHUkdaUFFYcDRiMnRDVTJzaWZYMC5leUpwWVhRaU9qRTNNRFE1TURNeE1qY3NJbVY0Y0NJNk1UY3dORGt3TnpBNE55d2libUptSWpveE56QTBPVEF6TVRJM0xDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpBek1EVXZZMnhwWlc1MGN5OWlOelkwWXpNNE9EZGlNekpoTm1FM0wyRmpZMlZ6Y3kxMGIydGxiaUlzSW5OMVlpSTZJbmRwY21WaGNIQTZMeTlqTm5RMFIwTm9RbE4xZVhaMVlsY3dVV1YzVEVaQklXSTNOalJqTXpnNE4ySXpNbUUyWVRkQWQybHlaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TWpBek1EVXZZMnhwWlc1MGN5OWlOelkwWXpNNE9EZGlNekpoTm1FM0wyRmpZMlZ6Y3kxMGIydGxiaUlzSW1wMGFTSTZJakkxTURZNE9UQTFMVGhtTUdFdE5EVXdZUzFpTVdZM0xXWm1aVEJqTkdReE16TmpZaUlzSW01dmJtTmxJam9pVlROT2IwNHhRa2RPTTBwWFUydFdRMU51WkZSTlZUVlhWbGRKZWxFeFZrWlhSRkY2WVRORmQyUlZheUlzSW1Ob1lXd2lPaUpHU25CMVptNW9kekpRWlhoR1NrZDRiMVJaYzJ0bWFVcFJjMkkwYkZGVk1TSXNJbU51WmlJNmV5SnJhV1FpT2lKSVdrdE5iamxGYzFFemQxcGFjMHB3YzIxcU9XMXVWR2xWY1Y5VFZXTjVhMU5oWkhsaE1YWmtYekJKSW4wc0luQnliMjltSWpvaVpYbEthR0pIWTJsUGFVcEdXa1ZTVkZGVFNYTkpibEkxWTBOSk5rbHRVbmRpTTBGeVlXNWtNRWxwZDJsaGJtUnlTV3B3TjBsdGREQmxVMGsyU1dzNVRGVkRTWE5KYlU1NVpHbEpOa2xyVm10TmFsVXhUVlJyYVV4RFNqUkphbTlwVld4c2MyRldSbmxrUmtwS1RtNUNXbEpyWnpGTVZqaDRWMVJWTW1NeWVIbE9iRUYwWWxob1lXUXdiSFprUlZaTVZERldVMDlFV2s1TlEwbzVabEV1WlhsS2NGbFlVV2xQYWtVelRVUlJOVTFFVFhoTmFtTnpTVzFXTkdORFNUWk5WR04zVGtScmVFMUVUWGxPZVhkcFltMUtiVWxxYjNoT2VrRXdUMVJCZWsxVVNUTk1RMHA2WkZkSmFVOXBTak5oV0Vwc1dWaENkMDlwT0haWmVsb3dUa1ZrUkdGRlNsUmtXR3d5WkZkS1dFMUdSbXhrTUhoSFVWTkdhVTU2V1RCWmVrMDBUMFJrYVUxNlNtaE9iVVV6VVVoa2NHTnRWWFZaTWpsMFNXbDNhV0Z1VW5CSmFtOXBUWHBDYVU5WFNtaE9SMDEwVFVkSk1rNXBNREJhVkZwcVRGZEtiRnBFVVhSTmFrSnNUVVJaZVZwVVozZE9WRWsxU1dsM2FXSnRPWFZaTWxWcFQybEtWazB3TlhaVWFrWkRVakEwZWxOc1pGUmhNVnBFVlRJMWExWkZNVlpPVm1SWFZqQnNObFZVUmxkU2JHUkZWVmh3YUUwd1ZqTmFSbFp5U1dsM2FXRklVblJKYW05cFZVVTVWRlpEU1hOSmJXZ3daRk5KTmtsdGFEQmtTRUUyVEhrNU0yRllTbXhNYlU1MllsUnZlVTFFVFhkT1V6bHFZa2RzYkdKdVVucE1Na2t6VG1wU2FrMTZaelJPTWtsNlRXMUZNbGxVWTNaWlYwNXFXbGhPZWt4WVVuWmhNbFoxU1dsM2FWa3lhR2hpUTBrMlNXdGFTMk5JVm0xaWJXZ3pUV3hDYkdWRldrdFNNMmgyVmtac2VtRXlXbkJUYkVaNldXcFNjMVZXVlhoSmFYZHBZVWRHZFZwSGVHeEphbTlwWkRKc2VWcFhSbmRqUkc5MlRIbFZNRTFIUm5OaFYwNXNXRE5rY0dOdFZrRmtNbXg1V2xNMWFtSXlNR2xNUTBvd1dsZEdkRWxxYjJsa01teDVXbE5LT1M1WVFrWlNiV2hsUkROVlVHeG9SWGRYVjFocmVXTjBaVFpKWm5Ka04yUmxiMWxwTUdKNGVsRTNTRTg0UkZwTE5Vb3lZVWhYUkdWeVVGWjVTWGhuUkhwcVpFOTRTVlZwVjBwd1pXNUlWMkoyT0VWdFRIaERaeUlzSW1Oc2FXVnVkRjlwWkNJNkluZHBjbVZoY0hBNkx5OWpOblEwUjBOb1FsTjFlWFoxWWxjd1VXVjNURVpCSVdJM05qUmpNemc0TjJJek1tRTJZVGRBZDJseVpTNWpiMjBpTENKaGNHbGZkbVZ5YzJsdmJpSTZOU3dpYzJOdmNHVWlPaUozYVhKbFgyTnNhV1Z1ZEY5cFpDSjkuR3BuU0ktZWxKcXliVUd5ZUtacl95VjY5RWh3N2FNckhfcnpJeEJ3dkh0X0pVYk80dDBKaU40RXRXWGhWVTBveVR4QThmTUI5N0d1OFJMY3RXLWlCQ0EifQ",
  "signature": "fmcGSOVr3QXgIZajMZEVNc93D_LCjvqh-_EdRvRSRnihp19OmiQuQkV4vkhaeOdAIVUgG1JZiLvBh81Oa62CBw"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InNxN3doTUFvWXJTa1g5Q3NUXy1Za0tKc29Tc29JTUJGRGZPQXp4b2tCU2sifX0.eyJpYXQiOjE3MDQ5MDMxMjcsImV4cCI6MTcwNDkwNzA4NywibmJmIjoxNzA0OTAzMTI3LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MjAzMDUvY2xpZW50cy9iNzY0YzM4ODdiMzJhNmE3L2FjY2Vzcy10b2tlbiIsInN1YiI6IndpcmVhcHA6Ly9jNnQ0R0NoQlN1eXZ1YlcwUWV3TEZBIWI3NjRjMzg4N2IzMmE2YTdAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MjAzMDUvY2xpZW50cy9iNzY0YzM4ODdiMzJhNmE3L2FjY2Vzcy10b2tlbiIsImp0aSI6IjI1MDY4OTA1LThmMGEtNDUwYS1iMWY3LWZmZTBjNGQxMzNjYiIsIm5vbmNlIjoiVTNOb04xQkdOM0pXU2tWQ1NuZFRNVTVXVldJelExVkZXRFF6YTNFd2RVayIsImNoYWwiOiJGSnB1Zm5odzJQZXhGSkd4b1RZc2tmaUpRc2I0bFFVMSIsImNuZiI6eyJraWQiOiJIWktNbjlFc1Ezd1pac0pwc21qOW1uVGlVcV9TVWN5a1NhZHlhMXZkXzBJIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pVWxsc2FWRnlkRkpKTm5CWlJrZzFMVjh4V1RVMmMyeHlObEF0YlhoYWQwbHZkRVZMVDFWU09EWk5NQ0o5ZlEuZXlKcFlYUWlPakUzTURRNU1ETXhNamNzSW1WNGNDSTZNVGN3TkRreE1ETXlOeXdpYm1KbUlqb3hOekEwT1RBek1USTNMQ0p6ZFdJaU9pSjNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0SWl3aWFuUnBJam9pTXpCaU9XSmhOR010TUdJMk5pMDBaVFpqTFdKbFpEUXRNakJsTURZeVpUZ3dOVEk1SWl3aWJtOXVZMlVpT2lKVk0wNXZUakZDUjA0elNsZFRhMVpEVTI1a1ZFMVZOVmRXVjBsNlVURldSbGRFVVhwaE0wVjNaRlZySWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRveU1ETXdOUzlqYkdsbGJuUnpMMkkzTmpSak16ZzROMkl6TW1FMllUY3ZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SWtaS2NIVm1ibWgzTWxCbGVFWktSM2h2VkZsemEyWnBTbEZ6WWpSc1VWVXhJaXdpYUdGdVpHeGxJam9pZDJseVpXRndjRG92THlVME1HRnNhV05sWDNkcGNtVkFkMmx5WlM1amIyMGlMQ0owWldGdElqb2lkMmx5WlNKOS5YQkZSbWhlRDNVUGxoRXdXV1hreWN0ZTZJZnJkN2Rlb1lpMGJ4elE3SE84RFpLNUoyYUhXRGVyUFZ5SXhnRHpqZE94SVVpV0pwZW5IV2J2OEVtTHhDZyIsImNsaWVudF9pZCI6IndpcmVhcHA6Ly9jNnQ0R0NoQlN1eXZ1YlcwUWV3TEZBIWI3NjRjMzg4N2IzMmE2YTdAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6NSwic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.GpnSI-elJqybUGyeKZr_yV69Ehw7aMrH_rzIxBwvHt_JUbO4t0JiN4EtWXhVU0oyTxA8fMB97Gu8RLctW-iBCA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33421/acme/wire/account/Tj1iLYT3OC8fRqyvtLG4vKC9XLEZTYsq",
    "nonce": "Y2F3WDJGTTFxVm5zVWZoNGJGM21FeFhOQnI0WjU0Zkg",
    "typ": "JWT",
    "url": "https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/JfMdzzuJ0LsvgJPfgkAV28e6IlthTYLG"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33421/acme/wire/directory>;rel="index"
link: <https://stepca:33421/acme/wire/authz/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ>;rel="up"
location: https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/JfMdzzuJ0LsvgJPfgkAV28e6IlthTYLG
replay-nonce: VHl4U0ltTkJ2OWM5c2NqUXRWd1BqS20wV3c0M0NUWXg
vary: Origin
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/JfMdzzuJ0LsvgJPfgkAV28e6IlthTYLG",
  "status": "valid",
  "token": "FJpufnhw2PexFJGxoTYskfiJQsb4lQU1",
  "target": "http://wire.com:20305/clients/b764c3887b32a6a7/access-token"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=BoftWCcu6y49FjTLKMuMHDQAl17esH5xfA_pLqmRRQI&code_challenge=ryKhvhBnBtBdSoMMfAGjYfXHBO-9mYNiUCEQ2NJVwjQ
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:21985/dex/auth?response_type=code&client_id=wireapp&state=WJsgsTpCbYATAM3kutrAzQ&code_challenge=ryKhvhBnBtBdSoMMfAGjYfXHBO-9mYNiUCEQ2NJVwjQ&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A20305%2Fcallback&scope=openid+profile&nonce=AZ07uvMZQbYLyGUCt13pLg
```

#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:21985/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpaVnB0Y25sbGFVNHdTamRpYTB0ck5VUlZiell4TVcxRA==
```
```text
grant_type=authorization_code&code=icsxgtw5p2ynhscrfcoohr2cy&code_verifier=BoftWCcu6y49FjTLKMuMHDQAl17esH5xfA_pLqmRRQI&redirect_uri=http%3A%2F%2Fwire.com%3A20305%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImM0MTdkYWQ5OTY3YzNhMWNmMDFlYzA3MDlmMjVkNTViZGU1ODU0NmYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxOTg1L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0OTkzMTI3LCJpYXQiOjE3MDQ5MDY3MjcsIm5vbmNlIjoiQVowN3V2TVpRYllMeUdVQ3QxM3BMZyIsImF0X2hhc2giOiJvNlpTaUtUMG80Z1VfUXZaTFdwa2ZBIiwibmFtZSI6IndpcmVhcHA6Ly8lNDBhbGljZV93aXJlQHdpcmUuY29tIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiQWxpY2UgU21pdGgifQ.dIp6C8Ibl08Tg1MKeUp1ECoCuTkxiEqn5cgwzF2TrTrYCC9EhC8nzLjqW5D_kSj-bqlOtEDV8ZmwsVMGKq2aQTwy8PuLtclq5Kky7vb-j2HBVUvRAYchnI5M3WD6a3okRnNVObsCpuQenfaT_BoMNYOsvUt_KN5KCv1x3gmTtT7DYCWTiqKnwbF3aVCMDt__Jx3uOOxVweymVnRyL87T9561Vtbg-zGeBsnlF4zC0UWuv9Lig7lfRek99-_2cryDUq6AZSOt4l2UBieJ01anoVNPWblQCXdoByxioc-wkwAlwkeD85r3N_Jg6ODWyQAu0yENq7at3xOVOsbtb6ZSJg",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImM0MTdkYWQ5OTY3YzNhMWNmMDFlYzA3MDlmMjVkNTViZGU1ODU0NmYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxOTg1L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0OTkzMTI3LCJpYXQiOjE3MDQ5MDY3MjcsIm5vbmNlIjoiQVowN3V2TVpRYllMeUdVQ3QxM3BMZyIsImF0X2hhc2giOiJERlNscmsxS3Q4VFhZZXVpNmpVUV9BIiwiY19oYXNoIjoiMVpjUWRIbnNCLTgzRHlhZlZ6T01XUSIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.AnJ2ko_-bwjvEWvzL5KZYLEM5wC1iP8U0MRfXEfWMgJzcVeag8ccRpZv9pA6jisSKOFxxcNaXIKe3ZRxYnZie7LDVgl11mG_xLs-U0g5a3q3-ix-0eiQ2J5MG6UCYagAR2k8oL9w5U_o1M_qNPLAcjM4yMc5SLrl5yj7w2zIYsF75mIxREwgbfOW4M6MhFp14tMf7qbhuQK1RIHXvyDPChZpU69FQJ7U-OaOc-bm85xqalmIUrqIfCTObyT1CQ5sxq5umuqh1bxE1lpiHdw0xufgtd1d0beaPpZOhkkMtNA0z2YeaH1IaBHSBIS9fjGksibOp5aQMALvHS7RuFp5DQ",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImM0MTdkYWQ5OTY3YzNhMWNmMDFlYzA3MDlmMjVkNTViZGU1ODU0NmYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxOTg1L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0OTkzMTI3LCJpYXQiOjE3MDQ5MDY3MjcsIm5vbmNlIjoiQVowN3V2TVpRYllMeUdVQ3QxM3BMZyIsImF0X2hhc2giOiJERlNscmsxS3Q4VFhZZXVpNmpVUV9BIiwiY19oYXNoIjoiMVpjUWRIbnNCLTgzRHlhZlZ6T01XUSIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.AnJ2ko_-bwjvEWvzL5KZYLEM5wC1iP8U0MRfXEfWMgJzcVeag8ccRpZv9pA6jisSKOFxxcNaXIKe3ZRxYnZie7LDVgl11mG_xLs-U0g5a3q3-ix-0eiQ2J5MG6UCYagAR2k8oL9w5U_o1M_qNPLAcjM4yMc5SLrl5yj7w2zIYsF75mIxREwgbfOW4M6MhFp14tMf7qbhuQK1RIHXvyDPChZpU69FQJ7U-OaOc-bm85xqalmIUrqIfCTObyT1CQ5sxq5umuqh1bxE1lpiHdw0xufgtd1d0beaPpZOhkkMtNA0z2YeaH1IaBHSBIS9fjGksibOp5aQMALvHS7RuFp5DQ
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImM0MTdkYWQ5OTY3YzNhMWNmMDFlYzA3MDlmMjVkNTViZGU1ODU0NmYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxOTg1L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0OTkzMTI3LCJpYXQiOjE3MDQ5MDY3MjcsIm5vbmNlIjoiQVowN3V2TVpRYllMeUdVQ3QxM3BMZyIsImF0X2hhc2giOiJERlNscmsxS3Q4VFhZZXVpNmpVUV9BIiwiY19oYXNoIjoiMVpjUWRIbnNCLTgzRHlhZlZ6T01XUSIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.AnJ2ko_-bwjvEWvzL5KZYLEM5wC1iP8U0MRfXEfWMgJzcVeag8ccRpZv9pA6jisSKOFxxcNaXIKe3ZRxYnZie7LDVgl11mG_xLs-U0g5a3q3-ix-0eiQ2J5MG6UCYagAR2k8oL9w5U_o1M_qNPLAcjM4yMc5SLrl5yj7w2zIYsF75mIxREwgbfOW4M6MhFp14tMf7qbhuQK1RIHXvyDPChZpU69FQJ7U-OaOc-bm85xqalmIUrqIfCTObyT1CQ5sxq5umuqh1bxE1lpiHdw0xufgtd1d0beaPpZOhkkMtNA0z2YeaH1IaBHSBIS9fjGksibOp5aQMALvHS7RuFp5DQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImM0MTdkYWQ5OTY3YzNhMWNmMDFlYzA3MDlm
MjVkNTViZGU1ODU0NmYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxOTg1L2RleCIsI
nN1YiI6IkNqcDNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkM
HhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0RWdSc1pHRnciL
CJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0OTkzMTI3LCJpYXQiOjE3MDQ5MDY3M
jcsIm5vbmNlIjoiQVowN3V2TVpRYllMeUdVQ3QxM3BMZyIsImF0X2hhc2giOiJER
lNscmsxS3Q4VFhZZXVpNmpVUV9BIiwiY19oYXNoIjoiMVpjUWRIbnNCLTgzRHlhZ
lZ6T01XUSIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvb
SIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.AnJ2ko_-bwjvE
WvzL5KZYLEM5wC1iP8U0MRfXEfWMgJzcVeag8ccRpZv9pA6jisSKOFxxcNaXIKe3
ZRxYnZie7LDVgl11mG_xLs-U0g5a3q3-ix-0eiQ2J5MG6UCYagAR2k8oL9w5U_o1
M_qNPLAcjM4yMc5SLrl5yj7w2zIYsF75mIxREwgbfOW4M6MhFp14tMf7qbhuQK1R
IHXvyDPChZpU69FQJ7U-OaOc-bm85xqalmIUrqIfCTObyT1CQ5sxq5umuqh1bxE1
lpiHdw0xufgtd1d0beaPpZOhkkMtNA0z2YeaH1IaBHSBIS9fjGksibOp5aQMALvH
S7RuFp5DQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "c417dad9967c3a1cf01ec0709f25d55bde58546f"
}
```

```json
{
  "at_hash": "DFSlrk1Kt8TXYeui6jUQ_A",
  "aud": "wireapp",
  "c_hash": "1ZcQdHnsB-83DyafVzOMWQ",
  "exp": 1704993127,
  "iat": 1704906727,
  "iss": "http://dex:21985/dex",
  "name": "wireapp://%40alice_wire@wire.com",
  "nonce": "AZ07uvMZQbYLyGUCt13pLg",
  "preferred_username": "Alice Smith",
  "sub": "Cjp3aXJlYXBwOi8vYzZ0NEdDaEJTdXl2dWJXMFFld0xGQSFiNzY0YzM4ODdiMzJhNmE3QHdpcmUuY29tEgRsZGFw"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtljoikta3W30Vhh+/jLY
AtJ49B18S1vwjGgBKISYbewhpr9sNNzUoOEaKq6GYAwmxlc24OHTnEAAIUAhLSKF
iuc9ul8Jnxsdkm8x7YkN+z90zZtrKko5s2sfKEKjpCoP+kYYS+aT+laoe4WSqmsa
mqqYz8v2mg/BP1V5P/ABsQlf36vkbqRgDl8jgTh7QvtLX46CvqD85w/pJrtTn6uB
CMixLcahdaiyi0oIbFFpwk5cUhL1UDafF65/znFXQb4E/07CJ0jMJc4068fgf1T6
WoCOCSmiLdcp/OEKBLcU63ZJ6cYEZDF+WXQfzX4y2+oE/XmM6Sg6eajXXRgB9zv4
KQIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/n45gi6jubXNyRl1RXwDnioc2hQQrHGCq
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNDIxL2FjbWUvd2lyZS9hY2NvdW50L1RqMWlMWVQzT0M4ZlJxeXZ0TEc0dktDOVhMRVpUWXNxIiwidHlwIjoiSldUIiwibm9uY2UiOiJWSGw0VTBsdFRrSjJPV001YzJOcVVYUldkMUJxUzIwd1YzYzBNME5VV1hnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM0MjEvYWNtZS93aXJlL2NoYWxsZW5nZS8wYXVkNVh2RDlFVjBvUWhyYlhQYjZISlR1SzN5VjJuSi9uNDVnaTZqdWJYTnlSbDFSWHdEbmlvYzJoUVFySEdDcSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJbU0wTVRka1lXUTVPVFkzWXpOaE1XTm1NREZsWXpBM01EbG1NalZrTlRWaVpHVTFPRFUwTm1ZaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qSXhPVGcxTDJSbGVDSXNJbk4xWWlJNklrTnFjRE5oV0Vwc1dWaENkMDlwT0haWmVsb3dUa1ZrUkdGRlNsUmtXR3d5WkZkS1dFMUdSbXhrTUhoSFVWTkdhVTU2V1RCWmVrMDBUMFJrYVUxNlNtaE9iVVV6VVVoa2NHTnRWWFZaTWpsMFJXZFNjMXBIUm5jaUxDSmhkV1FpT2lKM2FYSmxZWEJ3SWl3aVpYaHdJam94TnpBME9Ua3pNVEkzTENKcFlYUWlPakUzTURRNU1EWTNNamNzSW01dmJtTmxJam9pUVZvd04zVjJUVnBSWWxsTWVVZFZRM1F4TTNCTVp5SXNJbUYwWDJoaGMyZ2lPaUpFUmxOc2Ntc3hTM1E0VkZoWlpYVnBObXBWVVY5Qklpd2lZMTlvWVhOb0lqb2lNVnBqVVdSSWJuTkNMVGd6UkhsaFpsWjZUMDFYVVNJc0ltNWhiV1VpT2lKM2FYSmxZWEJ3T2k4dkpUUXdZV3hwWTJWZmQybHlaVUIzYVhKbExtTnZiU0lzSW5CeVpXWmxjbkpsWkY5MWMyVnlibUZ0WlNJNklrRnNhV05sSUZOdGFYUm9JbjAuQW5KMmtvXy1id2p2RVd2ekw1S1pZTEVNNXdDMWlQOFUwTVJmWEVmV01nSnpjVmVhZzhjY1JwWnY5cEE2amlzU0tPRnh4Y05hWElLZTNaUnhZblppZTdMRFZnbDExbUdfeExzLVUwZzVhM3EzLWl4LTBlaVEySjVNRzZVQ1lhZ0FSMms4b0w5dzVVX28xTV9xTlBMQWNqTTR5TWM1U0xybDV5ajd3MnpJWXNGNzVtSXhSRXdnYmZPVzRNNk1oRnAxNHRNZjdxYmh1UUsxUklIWHZ5RFBDaFpwVTY5RlFKN1UtT2FPYy1ibTg1eHFhbG1JVXJxSWZDVE9ieVQxQ1E1c3hxNXVtdXFoMWJ4RTFscGlIZHcweHVmZ3RkMWQwYmVhUHBaT2hra010TkEwejJZZWFIMUlhQkhTQklTOWZqR2tzaWJPcDVhUU1BTHZIUzdSdUZwNURRIiwia2V5YXV0aCI6IkZKcHVmbmh3MlBleEZKR3hvVFlza2ZpSlFzYjRsUVUxLkhaS01uOUVzUTN3WlpzSnBzbWo5bW5UaVVxX1NVY3lrU2FkeWExdmRfMEkifQ",
  "signature": "3Kz08Y2XDfy5v08L6mBWiyM5tGMVujbS0FXlP18qo--RE3cYtDhR639kRbNUnoKPcRvVIcwxC_Gyo-Bcb_0KAw"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImM0MTdkYWQ5OTY3YzNhMWNmMDFlYzA3MDlmMjVkNTViZGU1ODU0NmYifQ.eyJpc3MiOiJodHRwOi8vZGV4OjIxOTg1L2RleCIsInN1YiI6IkNqcDNhWEpsWVhCd09pOHZZelowTkVkRGFFSlRkWGwyZFdKWE1GRmxkMHhHUVNGaU56WTBZek00T0RkaU16SmhObUUzUUhkcGNtVXVZMjl0RWdSc1pHRnciLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNzA0OTkzMTI3LCJpYXQiOjE3MDQ5MDY3MjcsIm5vbmNlIjoiQVowN3V2TVpRYllMeUdVQ3QxM3BMZyIsImF0X2hhc2giOiJERlNscmsxS3Q4VFhZZXVpNmpVUV9BIiwiY19oYXNoIjoiMVpjUWRIbnNCLTgzRHlhZlZ6T01XUSIsIm5hbWUiOiJ3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.AnJ2ko_-bwjvEWvzL5KZYLEM5wC1iP8U0MRfXEfWMgJzcVeag8ccRpZv9pA6jisSKOFxxcNaXIKe3ZRxYnZie7LDVgl11mG_xLs-U0g5a3q3-ix-0eiQ2J5MG6UCYagAR2k8oL9w5U_o1M_qNPLAcjM4yMc5SLrl5yj7w2zIYsF75mIxREwgbfOW4M6MhFp14tMf7qbhuQK1RIHXvyDPChZpU69FQJ7U-OaOc-bm85xqalmIUrqIfCTObyT1CQ5sxq5umuqh1bxE1lpiHdw0xufgtd1d0beaPpZOhkkMtNA0z2YeaH1IaBHSBIS9fjGksibOp5aQMALvHS7RuFp5DQ",
    "keyauth": "FJpufnhw2PexFJGxoTYskfiJQsb4lQU1.HZKMn9EsQ3wZZsJpsmj9mnTiUq_SUcykSadya1vd_0I"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33421/acme/wire/account/Tj1iLYT3OC8fRqyvtLG4vKC9XLEZTYsq",
    "nonce": "VHl4U0ltTkJ2OWM5c2NqUXRWd1BqS20wV3c0M0NUWXg",
    "typ": "JWT",
    "url": "https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/n45gi6jubXNyRl1RXwDnioc2hQQrHGCq"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33421/acme/wire/directory>;rel="index"
link: <https://stepca:33421/acme/wire/authz/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ>;rel="up"
location: https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/n45gi6jubXNyRl1RXwDnioc2hQQrHGCq
replay-nonce: ZkpLRlNUWnVYWFhxNGE1S0ZTM3Q5TU1XZ1hYVExoODA
vary: Origin
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:33421/acme/wire/challenge/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ/n45gi6jubXNyRl1RXwDnioc2hQQrHGCq",
  "status": "valid",
  "token": "FJpufnhw2PexFJGxoTYskfiJQsb4lQU1",
  "target": "http://dex:21985/dex"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNDIxL2FjbWUvd2lyZS9hY2NvdW50L1RqMWlMWVQzT0M4ZlJxeXZ0TEc0dktDOVhMRVpUWXNxIiwidHlwIjoiSldUIiwibm9uY2UiOiJaa3BMUmxOVVduVllXRmh4TkdFMVMwWlRNM1E1VFUxWFoxaFlWRXhvT0RBIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM0MjEvYWNtZS93aXJlL29yZGVyL3VWWnZqcGxhbUNTU2lwNGdqZ2VUNEFJNTlNanlKSlZFIn0",
  "payload": "",
  "signature": "9OwH7kkZ4I4zZedaQ2ra_fDuoeKR8b35ZmnjzjmsVhk5EPUuIvAxZk-27yPYRJV9lPebQ3cpXdDZCqP8o5oSDg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33421/acme/wire/account/Tj1iLYT3OC8fRqyvtLG4vKC9XLEZTYsq",
    "nonce": "ZkpLRlNUWnVYWFhxNGE1S0ZTM3Q5TU1XZ1hYVExoODA",
    "typ": "JWT",
    "url": "https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33421/acme/wire/directory>;rel="index"
location: https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE
replay-nonce: OURYZmJycldLeWZ6V0t1dk1zUWVSRzFvcWEzNFZmWE8
vary: Origin
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://c6t4GChBSuyvubW0QewLFA!b764c3887b32a6a7@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33421/acme/wire/authz/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ"
  ],
  "expires": "2024-01-11T17:12:07Z",
  "notBefore": "2024-01-10T17:12:07.554486Z",
  "notAfter": "2034-01-07T17:12:07.554486Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNDIxL2FjbWUvd2lyZS9hY2NvdW50L1RqMWlMWVQzT0M4ZlJxeXZ0TEc0dktDOVhMRVpUWXNxIiwidHlwIjoiSldUIiwibm9uY2UiOiJPVVJZWm1KeWNsZExlV1o2VjB0MWRrMXpVV1ZTUnpGdmNXRXpORlptV0U4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM0MjEvYWNtZS93aXJlL29yZGVyL3VWWnZqcGxhbUNTU2lwNGdqZ2VUNEFJNTlNanlKSlZFL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCS3pDQjNnSUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBR3RGNlhWa0NjRkhmRGhpUlM0ZE9keFhmNjl5VzJ0czNuU0J5eW9BR1dORG9Ib3dlQVlKS29aSWh2Y05BUWtPTVdzd2FUQm5CZ05WSFJFRVlEQmVoanAzYVhKbFlYQndPaTh2WXpaME5FZERhRUpUZFhsMmRXSlhNRkZsZDB4R1FTRmlOelkwWXpNNE9EZGlNekpoTm1FM1FIZHBjbVV1WTI5dGhpQjNhWEpsWVhCd09pOHZKVFF3WVd4cFkyVmZkMmx5WlVCM2FYSmxMbU52YlRBRkJnTXJaWEFEUVFDanBUdy1rcFdtRXRIX3dSUTdCSlI0Q2gtcjRCOXhJdGhwTk5sZWw3Vzd1TjRzeDd3djFONWpCaGJNc2pVdFRDQmdqMlpFOUg3eWYwQzluR195V1RnTyJ9",
  "signature": "9JBmL3JMHtIVmK4oPcCtzgYIfSkxLSvZaTqGF4d0l0JHJm-6qAYHG0YV0pxHqdFx0hbLMYXAUo1NmkjKYcB8Bg"
}
```
```json
{
  "payload": {
    "csr": "MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGtF6XVkCcFHfDhiRS4dOdxXf69yW2ts3nSByyoAGWNDoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBwOi8vYzZ0NEdDaEJTdXl2dWJXMFFld0xGQSFiNzY0YzM4ODdiMzJhNmE3QHdpcmUuY29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQCjpTw-kpWmEtH_wRQ7BJR4Ch-r4B9xIthpNNlel7W7uN4sx7wv1N5jBhbMsjUtTCBgj2ZE9H7yf0C9nG_yWTgO"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33421/acme/wire/account/Tj1iLYT3OC8fRqyvtLG4vKC9XLEZTYsq",
    "nonce": "OURYZmJycldLeWZ6V0t1dk1zUWVSRzFvcWEzNFZmWE8",
    "typ": "JWT",
    "url": "https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBKzCB3gIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGtF6XVkCcFHfDhiRS4dOdxXf69yW2ts
3nSByyoAGWNDoHoweAYJKoZIhvcNAQkOMWswaTBnBgNVHREEYDBehjp3aXJlYXBw
Oi8vYzZ0NEdDaEJTdXl2dWJXMFFld0xGQSFiNzY0YzM4ODdiMzJhNmE3QHdpcmUu
Y29thiB3aXJlYXBwOi8vJTQwYWxpY2Vfd2lyZUB3aXJlLmNvbTAFBgMrZXADQQCj
pTw+kpWmEtH/wRQ7BJR4Ch+r4B9xIthpNNlel7W7uN4sx7wv1N5jBhbMsjUtTCBg
j2ZE9H7yf0C9nG/yWTgO
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
                    6b:45:e9:75:64:09:c1:47:7c:38:62:45:2e:1d:39:
                    dc:57:7f:af:72:5b:6b:6c:de:74:81:cb:2a:00:19:
                    63:43
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:wireapp://c6t4GChBSuyvubW0QewLFA!b764c3887b32a6a7@wire.com, URI:wireapp://%40alice_wire@wire.com
    Signature Algorithm: ED25519
    Signature Value:
        a3:a5:3c:3e:92:95:a6:12:d1:ff:c1:14:3b:04:94:78:0a:1f:
        ab:e0:1f:71:22:d8:69:34:d9:5e:97:b5:bb:b8:de:2c:c7:bc:
        2f:d4:de:63:06:16:cc:b2:35:2d:4c:20:60:8f:66:44:f4:7e:
        f2:7f:40:bd:9c:6f:f2:59:38:0e

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:33421/acme/wire/directory>;rel="index"
location: https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE
replay-nonce: Y3FuMWpvcU8wTkpxMzFqRjU1SUU4bXdsakd6TXJBR3g
vary: Origin
```
```json
{
  "certificate": "https://stepca:33421/acme/wire/certificate/OVghb5U24G2ETTXZZQJwomMGNICvsm8V",
  "status": "valid",
  "finalize": "https://stepca:33421/acme/wire/order/uVZvjplamCSSip4gjgeT4AI59MjyJJVE/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"wireapp://c6t4GChBSuyvubW0QewLFA!b764c3887b32a6a7@wire.com\",\"handle\":\"wireapp://%40alice_wire@wire.com\"}"
    }
  ],
  "authorizations": [
    "https://stepca:33421/acme/wire/authz/0aud5XvD9EV0oQhrbXPb6HJTuK3yV2nJ"
  ],
  "expires": "2024-01-11T17:12:07Z",
  "notBefore": "2024-01-10T17:12:07.554486Z",
  "notAfter": "2034-01-07T17:12:07.554486Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:33421/acme/wire/certificate/OVghb5U24G2ETTXZZQJwomMGNICvsm8V
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMzNDIxL2FjbWUvd2lyZS9hY2NvdW50L1RqMWlMWVQzT0M4ZlJxeXZ0TEc0dktDOVhMRVpUWXNxIiwidHlwIjoiSldUIiwibm9uY2UiOiJZM0Z1TVdwdmNVOHdUa3B4TXpGcVJqVTFTVVU0Ylhkc2FrZDZUWEpCUjNnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzM0MjEvYWNtZS93aXJlL2NlcnRpZmljYXRlL09WZ2hiNVUyNEcyRVRUWFpaUUp3b21NR05JQ3ZzbThWIn0",
  "payload": "",
  "signature": "fZf3Kwu5tJAsYvg88cZh8Qh04bGvyrYYpfM00MsmumIFmHJMVRBKvbA8-Zxpjr7TVJ1qMV-IEO9Oqk5n9chrAg"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:33421/acme/wire/account/Tj1iLYT3OC8fRqyvtLG4vKC9XLEZTYsq",
    "nonce": "Y3FuMWpvcU8wTkpxMzFqRjU1SUU4bXdsakd6TXJBR3g",
    "typ": "JWT",
    "url": "https://stepca:33421/acme/wire/certificate/OVghb5U24G2ETTXZZQJwomMGNICvsm8V"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:33421/acme/wire/directory>;rel="index"
replay-nonce: cDBVeHFCQTlLNHlwQ1Y4Y1N4dElHcU9uTE82amJWUHk
vary: Origin
```
```json
"-----BEGIN CERTIFICATE-----\nMIICGTCCAb+gAwIBAgIQaXR23p7YX+4vNNBA+SBOZzAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nNDAxMTAxNzEyMDdaFw0zNDAxMDcxNzEyMDdaMCkxETAPBgNVBAoTCHdpcmUuY29t\nMRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGtF6XVkCcFHfDhiRS4d\nOdxXf69yW2ts3nSByyoAGWNDo4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE\nDDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUtoq6SZpEH4O9j1S4xc01FOsjWncwHwYD\nVR0jBBgwFoAUXn2vyN9xnyUpz53HjaaQO1Th9VAwaQYDVR0RBGIwYIYgd2lyZWFw\ncDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9jNnQ0R0NoQlN1\neXZ1YlcwUWV3TEZBJTIxYjc2NGMzODg3YjMyYTZhN0B3aXJlLmNvbTAdBgwrBgEE\nAYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIgTpSc3u4x\nlKmazwI1Nm2EVwWdwJo28/zedkvaonqvQF0CIQDVVJnoRlszBHBPH3VdbgJDasok\n44opkFlB0aRJEHgQkA==\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAJm4hczxyvxJ7UyApZJCXA0wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExMDE3\nMTIwNVoXDTM0MDEwNzE3MTIwNVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQt\nyKW+eyaO06Xp5Iz/OSTpfwC9OJytvnvN7C9WkirXG+KEqiMphkb5wKRyNjeN8ZjO\nn3gW/rIIYG8CJ4p4h+PDo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUXn2vyN9xnyUpz53HjaaQO1Th9VAwHwYDVR0jBBgw\nFoAUDUvyEjF80Hb7ajpSMvz51wDLvjkwCgYIKoZIzj0EAwIDSAAwRQIhAITgoLgv\ngs27IfvmsJ1xorfJROMv8qEdBh9Eg1hlS0RzAiBVP4NjA/iY6KYzPClJwWepPQb3\n9MawtEwN8jdtkS11rw==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1

```
-----BEGIN CERTIFICATE-----
MIICGTCCAb+gAwIBAgIQaXR23p7YX+4vNNBA+SBOZzAKBggqhkjOPQQDAjAuMQ0w
CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y
NDAxMTAxNzEyMDdaFw0zNDAxMDcxNzEyMDdaMCkxETAPBgNVBAoTCHdpcmUuY29t
MRQwEgYDVQQDEwtBbGljZSBTbWl0aDAqMAUGAytlcAMhAGtF6XVkCcFHfDhiRS4d
OdxXf69yW2ts3nSByyoAGWNDo4HyMIHvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUtoq6SZpEH4O9j1S4xc01FOsjWncwHwYD
VR0jBBgwFoAUXn2vyN9xnyUpz53HjaaQO1Th9VAwaQYDVR0RBGIwYIYgd2lyZWFw
cDovLyU0MGFsaWNlX3dpcmVAd2lyZS5jb22GPHdpcmVhcHA6Ly9jNnQ0R0NoQlN1
eXZ1YlcwUWV3TEZBJTIxYjc2NGMzODg3YjMyYTZhN0B3aXJlLmNvbTAdBgwrBgEE
AYKkZMYoQAEEDTALAgEGBAR3aXJlBAAwCgYIKoZIzj0EAwIDSAAwRQIgTpSc3u4x
lKmazwI1Nm2EVwWdwJo28/zedkvaonqvQF0CIQDVVJnoRlszBHBPH3VdbgJDasok
44opkFlB0aRJEHgQkA==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            69:74:76:de:9e:d8:5f:ee:2f:34:d0:40:f9:20:4e:67
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Intermediate CA
        Validity
            Not Before: Jan 10 17:12:07 2024 GMT
            Not After : Jan  7 17:12:07 2034 GMT
        Subject: O=wire.com, CN=Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    6b:45:e9:75:64:09:c1:47:7c:38:62:45:2e:1d:39:
                    dc:57:7f:af:72:5b:6b:6c:de:74:81:cb:2a:00:19:
                    63:43
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                B6:8A:BA:49:9A:44:1F:83:BD:8F:54:B8:C5:CD:35:14:EB:23:5A:77
            X509v3 Authority Key Identifier: 
                5E:7D:AF:C8:DF:71:9F:25:29:CF:9D:C7:8D:A6:90:3B:54:E1:F5:50
            X509v3 Subject Alternative Name: 
                URI:wireapp://%40alice_wire@wire.com, URI:wireapp://c6t4GChBSuyvubW0QewLFA%21b764c3887b32a6a7@wire.com
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:4e:94:9c:de:ee:31:94:a9:9a:cf:02:35:36:6d:
        84:57:05:9d:c0:9a:36:f3:fc:de:76:4b:da:a2:7a:af:40:5d:
        02:21:00:d5:54:99:e8:46:5b:33:04:70:4f:1f:75:5d:6e:02:
        43:6a:ca:24:e3:8a:29:90:59:41:d1:a4:49:10:78:10:90

```

###### Certificate #2

```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAJm4hczxyvxJ7UyApZJCXA0wCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTI0MDExMDE3
MTIwNVoXDTM0MDEwNzE3MTIwNVowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQt
yKW+eyaO06Xp5Iz/OSTpfwC9OJytvnvN7C9WkirXG+KEqiMphkb5wKRyNjeN8ZjO
n3gW/rIIYG8CJ4p4h+PDo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUXn2vyN9xnyUpz53HjaaQO1Th9VAwHwYDVR0jBBgw
FoAUDUvyEjF80Hb7ajpSMvz51wDLvjkwCgYIKoZIzj0EAwIDSAAwRQIhAITgoLgv
gs27IfvmsJ1xorfJROMv8qEdBh9Eg1hlS0RzAiBVP4NjA/iY6KYzPClJwWepPQb3
9MawtEwN8jdtkS11rw==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            99:b8:85:cc:f1:ca:fc:49:ed:4c:80:a5:92:42:5c:0d
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 10 17:12:05 2024 GMT
            Not After : Jan  7 17:12:05 2034 GMT
        Subject: O=wire, CN=wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:2d:c8:a5:be:7b:26:8e:d3:a5:e9:e4:8c:ff:39:
                    24:e9:7f:00:bd:38:9c:ad:be:7b:cd:ec:2f:56:92:
                    2a:d7:1b:e2:84:aa:23:29:86:46:f9:c0:a4:72:36:
                    37:8d:f1:98:ce:9f:78:16:fe:b2:08:60:6f:02:27:
                    8a:78:87:e3:c3
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                5E:7D:AF:C8:DF:71:9F:25:29:CF:9D:C7:8D:A6:90:3B:54:E1:F5:50
            X509v3 Authority Key Identifier: 
                0D:4B:F2:12:31:7C:D0:76:FB:6A:3A:52:32:FC:F9:D7:00:CB:BE:39
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:84:e0:a0:b8:2f:82:cd:bb:21:fb:e6:b0:9d:
        71:a2:b7:c9:44:e3:2f:f2:a1:1d:06:1f:44:83:58:65:4b:44:
        73:02:20:55:3f:83:63:03:f8:98:e8:a6:33:3c:29:49:c1:67:
        a9:3d:06:f7:f4:c6:b0:b4:4c:0d:f2:37:6d:91:2d:75:af

```

###### Certificate #3

```
-----BEGIN CERTIFICATE-----
MIIBkDCCATWgAwIBAgIQSj5EjJr5M0IcnUeVOblsADAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjQwMTEwMTcx
MjA0WhcNMzQwMTA3MTcxMjA0WjAmMQ0wCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3
aXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ5f/cJmOT7RJ3H
y90GyiAYet8QzDhDS37gfZm9ucTxqdWmK4I5f5wXpUUey3g23kUHgm162ortRQF2
UCnEfXeEo0UwQzAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAd
BgNVHQ4EFgQUDUvyEjF80Hb7ajpSMvz51wDLvjkwCgYIKoZIzj0EAwIDSQAwRgIh
AJwfzUG913iF6E/2Xl08OSOdBW4VgZEASZo/GsWYqsh7AiEA7fvE3yzQW/vYWh4T
gGya3L/VZKDypBy1Lk5Y2VuPVf4=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            4a:3e:44:8c:9a:f9:33:42:1c:9d:47:95:39:b9:6c:00
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O=wire, CN=wire Root CA
        Validity
            Not Before: Jan 10 17:12:04 2024 GMT
            Not After : Jan  7 17:12:04 2034 GMT
        Subject: O=wire, CN=wire Root CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:39:7f:f7:09:98:e4:fb:44:9d:c7:cb:dd:06:ca:
                    20:18:7a:df:10:cc:38:43:4b:7e:e0:7d:99:bd:b9:
                    c4:f1:a9:d5:a6:2b:82:39:7f:9c:17:a5:45:1e:cb:
                    78:36:de:45:07:82:6d:7a:da:8a:ed:45:01:76:50:
                    29:c4:7d:77:84
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Subject Key Identifier: 
                0D:4B:F2:12:31:7C:D0:76:FB:6A:3A:52:32:FC:F9:D7:00:CB:BE:39
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:46:02:21:00:9c:1f:cd:41:bd:d7:78:85:e8:4f:f6:5e:5d:
        3c:39:23:9d:05:6e:15:81:91:00:49:9a:3f:1a:c5:98:aa:c8:
        7b:02:21:00:ed:fb:c4:df:2c:d0:5b:fb:d8:5a:1e:13:80:6c:
        9a:dc:bf:d5:64:a0:f2:a4:1c:b5:2e:4e:58:d9:5b:8f:55:fe

```

openssl verify chain ✅