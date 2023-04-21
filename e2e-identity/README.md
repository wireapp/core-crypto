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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/AwegYhMFAzT09PbztvcVlG4owLEPkEtb
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/3773524069437416930/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/o2l6SiuLShSUJxcRKJEdBmUIj8SQSSb8
    acme-server->>-wire-client: 200
    wire-client->>wire-client: OAUTH authorization request
    wire-client->>+authorization-server:  GET /dex/auth
    wire-client->>wire-client: OAUTH authorization code
    wire-client->>+authorization-server:  POST /dex/token
    authorization-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/YaUtWZ2bKbrpplQLvuJTUsLFKKxX0xq1
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/NEgEpPxAHrXqKp3SyaQW30erIEDjg9bv
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:32885/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:32885/acme/wire/new-nonce",
  "newAccount": "https://stepca:32885/acme/wire/new-account",
  "newOrder": "https://stepca:32885/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:32885/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:32885/acme/wire/directory>;rel="index"
replay-nonce: THV2VXlKVGR2RFRqZ0NVQmhiUURwSzJVWDViUlQzVU8
```
```text
THV2VXlKVGR2RFRqZ0NVQmhiUURwSzJVWDViUlQzVU8
```
#### 5. create a new account
```http request
POST https://stepca:32885/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InBDUVlETnBwNU5wUDZ1WDlPQmtlQ2ZnWGhDR3BXaEEwZ0FFSnFiRVh6OU0ifSwibm9uY2UiOiJUSFYyVlhsS1ZHUjJSRlJxWjBOVlFtaGlVVVJ3U3pKVldEVmlVbFF6VlU4IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4ODUvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "CPbU9bY6YT6hjrCWBxGn7ys60LyJdnRyRcYZZppLPpvDS74tyqnhPsiYoBp7OLSUPdVLzkCkXhs69ngMHXsRBA"
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
      "x": "pCQYDNpp5NpP6uX9OBkeCfgXhCGpWhA0gAEJqbEXz9M"
    },
    "nonce": "THV2VXlKVGR2RFRqZ0NVQmhiUURwSzJVWDViUlQzVU8",
    "typ": "JWT",
    "url": "https://stepca:32885/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32885/acme/wire/directory>;rel="index"
location: https://stepca:32885/acme/wire/account/gkjIfTp9ZUm6qzDVdPCUhS2eoB4mXWjG
replay-nonce: RU9UQkV4eEpUdFZ2SUJXdmJYQk1KMFFNVlZvUnRpOHQ
```
```json
{
  "status": "valid",
  "orders": "https://stepca:32885/acme/wire/account/gkjIfTp9ZUm6qzDVdPCUhS2eoB4mXWjG/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:32885/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODg1L2FjbWUvd2lyZS9hY2NvdW50L2draklmVHA5WlVtNnF6RFZkUENVaFMyZW9CNG1YV2pHIiwidHlwIjoiSldUIiwibm9uY2UiOiJSVTlVUWtWNGVFcFVkRloyU1VKWGRtSllRazFLTUZGTlZsWnZVblJwT0hRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4ODUvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkFsaWNlIFNtaXRoXCIsXCJkb21haW5cIjpcIndpcmUuY29tXCIsXCJjbGllbnQtaWRcIjpcImltOndpcmVhcHA9WVRWaE9HWTFNemRrTkdNM05HVmhaamhsTWpsaE9UQTVNMk13T0RrMVlUWS8zNDVlNDAyNWVlMzQyNWUyQHdpcmUuY29tXCIsXCJoYW5kbGVcIjpcImltOndpcmVhcHA9YWxpY2Vfd2lyZVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wNC0yMVQwOToxNjozOC4yOTg2NjdaIiwibm90QWZ0ZXIiOiIyMDIzLTA0LTIxVDEwOjE2OjM4LjI5ODY2N1oifQ",
  "signature": "4yqtCeLTUriJxSWyIjYNQe9VdbkyAJYdTyLhgmmngqeJhLY0D6pjoCKCKp2foZE-82ZqsbNvK4EP_xCMHMbJAg"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
      }
    ],
    "notAfter": "2023-04-21T10:16:38.298667Z",
    "notBefore": "2023-04-21T09:16:38.298667Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32885/acme/wire/account/gkjIfTp9ZUm6qzDVdPCUhS2eoB4mXWjG",
    "nonce": "RU9UQkV4eEpUdFZ2SUJXdmJYQk1KMFFNVlZvUnRpOHQ",
    "typ": "JWT",
    "url": "https://stepca:32885/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:32885/acme/wire/directory>;rel="index"
location: https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg
replay-nonce: OXd1cGVtMzJ0cHlwUXgwNDd3VVZvMGpwS2h5cHY5R2E
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32885/acme/wire/authz/AwegYhMFAzT09PbztvcVlG4owLEPkEtb"
  ],
  "expires": "2023-04-22T09:16:38Z",
  "notBefore": "2023-04-21T09:16:38.298667Z",
  "notAfter": "2023-04-21T10:16:38.298667Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:32885/acme/wire/authz/AwegYhMFAzT09PbztvcVlG4owLEPkEtb
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODg1L2FjbWUvd2lyZS9hY2NvdW50L2draklmVHA5WlVtNnF6RFZkUENVaFMyZW9CNG1YV2pHIiwidHlwIjoiSldUIiwibm9uY2UiOiJPWGQxY0dWdE16SjBjSGx3VVhnd05EZDNWVlp2TUdwd1MyaDVjSFk1UjJFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4ODUvYWNtZS93aXJlL2F1dGh6L0F3ZWdZaE1GQXpUMDlQYnp0dmNWbEc0b3dMRVBrRXRiIn0",
  "payload": "",
  "signature": "evQSHAwCyctTJjuYkA73rWJVMLE63oXUIuaQWpN05_sv8lo1CpEG5ejbFZv1APOkjbLkW1H6O4vd6xYJTUWFCQ"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32885/acme/wire/account/gkjIfTp9ZUm6qzDVdPCUhS2eoB4mXWjG",
    "nonce": "OXd1cGVtMzJ0cHlwUXgwNDd3VVZvMGpwS2h5cHY5R2E",
    "typ": "JWT",
    "url": "https://stepca:32885/acme/wire/authz/AwegYhMFAzT09PbztvcVlG4owLEPkEtb"
  }
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32885/acme/wire/directory>;rel="index"
location: https://stepca:32885/acme/wire/authz/AwegYhMFAzT09PbztvcVlG4owLEPkEtb
replay-nonce: ZUxZUk4wdkFkTUN3a29wVVFvazI3bHhqSHdDYTNQM3U
```
```json
{
  "status": "pending",
  "expires": "2023-04-22T09:16:38Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/YaUtWZ2bKbrpplQLvuJTUsLFKKxX0xq1",
      "status": "pending",
      "token": "eXxUenCbjifle7yTobRmYlGcdnlzljm2"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/o2l6SiuLShSUJxcRKJEdBmUIj8SQSSb8",
      "status": "pending",
      "token": "eXxUenCbjifle7yTobRmYlGcdnlzljm2"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:18691/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
WVB6T2RHT3BvQW1CdXRpMXNYOTV0S2NxbW9TVTRjOHQ
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoicENRWUROcHA1TnBQNnVYOU9Ca2VDZmdYaENHcFdoQTBnQUVKcWJFWHo5TSJ9fQ.eyJpYXQiOjE2ODIwNjg1OTgsImV4cCI6MTY4MjA3MjE5OCwibmJmIjoxNjgyMDY4NTk4LCJzdWIiOiJpbTp3aXJlYXBwPVlUVmhPR1kxTXpka05HTTNOR1ZoWmpobE1qbGhPVEE1TTJNd09EazFZVFkvMzQ1ZTQwMjVlZTM0MjVlMkB3aXJlLmNvbSIsImp0aSI6IjNhMTg4Yzc2LTZmYTYtNGM2Ny1iMzk0LWRlMDgxZWFiNGFmMCIsIm5vbmNlIjoiV1ZCNlQyUkhUM0J2UVcxQ2RYUnBNWE5ZT1RWMFMyTnhiVzlUVlRSak9IUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTg2OTEvIiwiY2hhbCI6ImVYeFVlbkNiamlmbGU3eVRvYlJtWWxHY2RubHpsam0yIn0.PdAWTGtoWBEWW7g_Qlf39rAQRIesp1lglVSC4GuGhKg5W8GeaM-mzccYyVRx1G1jdwSV90AH9m5xeuvKi-RVCQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoicENRWUROcHA1TnBQNnVYOU9Ca2VDZmdY
aENHcFdoQTBnQUVKcWJFWHo5TSJ9fQ.eyJpYXQiOjE2ODIwNjg1OTgsImV4cCI6M
TY4MjA3MjE5OCwibmJmIjoxNjgyMDY4NTk4LCJzdWIiOiJpbTp3aXJlYXBwPVlUV
mhPR1kxTXpka05HTTNOR1ZoWmpobE1qbGhPVEE1TTJNd09EazFZVFkvMzQ1ZTQwM
jVlZTM0MjVlMkB3aXJlLmNvbSIsImp0aSI6IjNhMTg4Yzc2LTZmYTYtNGM2Ny1iM
zk0LWRlMDgxZWFiNGFmMCIsIm5vbmNlIjoiV1ZCNlQyUkhUM0J2UVcxQ2RYUnBNW
E5ZT1RWMFMyTnhiVzlUVlRSak9IUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206MTg2OTEvIiwiY2hhbCI6ImVYeFVlbkNiamlmbGU3eVRvYlJtW
WxHY2RubHpsam0yIn0.PdAWTGtoWBEWW7g_Qlf39rAQRIesp1lglVSC4GuGhKg5W
8GeaM-mzccYyVRx1G1jdwSV90AH9m5xeuvKi-RVCQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "pCQYDNpp5NpP6uX9OBkeCfgXhCGpWhA0gAEJqbEXz9M"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "eXxUenCbjifle7yTobRmYlGcdnlzljm2",
  "exp": 1682072198,
  "htm": "POST",
  "htu": "http://wire.com:18691/",
  "iat": 1682068598,
  "jti": "3a188c76-6fa6-4c67-b394-de081eab4af0",
  "nbf": 1682068598,
  "nonce": "WVB6T2RHT3BvQW1CdXRpMXNYOTV0S2NxbW9TVTRjOHQ",
  "sub": "im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIAEqjuwlod5vniAl1Jjm5N4bOlcLqamHE6Tx1XBIFmBC
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEApCQYDNpp5NpP6uX9OBkeCfgXhCGpWhA0gAEJqbEXz9M=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:18691/clients/3773524069437416930/access-token
                          /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pY0VOUldVUk9jSEExVG5CUU5uVllPVTlDYTJWRFptZFlhRU5IY0Zkb1FUQm5RVVZLY1dKRldIbzVUU0o5ZlEuZXlKcFlYUWlPakUyT0RJd05qZzFPVGdzSW1WNGNDSTZNVFk0TWpBM01qRTVPQ3dpYm1KbUlqb3hOamd5TURZNE5UazRMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVmxVVm1oUFIxa3hUWHBrYTA1SFRUTk9SMVpvV21wb2JFMXFiR2hQVkVFMVRUSk5kMDlFYXpGWlZGa3ZNelExWlRRd01qVmxaVE0wTWpWbE1rQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqTmhNVGc0WXpjMkxUWm1ZVFl0TkdNMk55MWlNemswTFdSbE1EZ3haV0ZpTkdGbU1DSXNJbTV2Ym1ObElqb2lWMVpDTmxReVVraFVNMEoyVVZjeFEyUllVbkJOV0U1WlQxUldNRk15VG5oaVZ6bFVWbFJTYWs5SVVTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZNVGcyT1RFdklpd2lZMmhoYkNJNkltVlllRlZsYmtOaWFtbG1iR1UzZVZSdllsSnRXV3hIWTJSdWJIcHNhbTB5SW4wLlBkQVdUR3RvV0JFV1c3Z19RbGYzOXJBUVJJZXNwMWxnbFZTQzRHdUdoS2c1VzhHZWFNLW16Y2NZeVZSeDFHMWpkd1NWOTBBSDltNXhldXZLaS1SVkNR
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkctWHEwZnJZTjcwWENqTGVxQURvNURqUGRMR1VRb0xLNy1Pdk1jazd2Yk0ifX0.eyJpYXQiOjE2ODIwNjg1OTgsImV4cCI6MTY4OTg0NDU5OCwibmJmIjoxNjgyMDY4NTk4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTg2OTEvIiwic3ViIjoiaW06d2lyZWFwcD1ZVFZoT0dZMU16ZGtOR00zTkdWaFpqaGxNamxoT1RBNU0yTXdPRGsxWVRZLzM0NWU0MDI1ZWUzNDI1ZTJAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MTg2OTEvIiwianRpIjoiM2UwZGUyYjYtNTFhMS00NGI2LWE0YTAtODVjNzFkNmQ2ODlmIiwibm9uY2UiOiJXVkI2VDJSSFQzQnZRVzFDZFhScE1YTllPVFYwUzJOeGJXOVRWVFJqT0hRIiwiY2hhbCI6ImVYeFVlbkNiamlmbGU3eVRvYlJtWWxHY2RubHpsam0yIiwiY25mIjp7ImtpZCI6IjJIMzhwemRZVU5oUmVVWHJ5cnh0R0k0b3oxem01Y1pKSjY5Qlp5bVQ5N2sifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2ljRU5SV1VST2NIQTFUbkJRTm5WWU9VOUNhMlZEWm1kWWFFTkhjRmRvUVRCblFVVktjV0pGV0hvNVRTSjlmUS5leUpwWVhRaU9qRTJPREl3TmpnMU9UZ3NJbVY0Y0NJNk1UWTRNakEzTWpFNU9Dd2libUptSWpveE5qZ3lNRFk0TlRrNExDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWbFVWbWhQUjFreFRYcGthMDVIVFROT1IxWm9XbXBvYkUxcWJHaFBWRUUxVFRKTmQwOUVhekZaVkZrdk16UTFaVFF3TWpWbFpUTTBNalZsTWtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpOaE1UZzRZemMyTFRabVlUWXROR00yTnkxaU16azBMV1JsTURneFpXRmlOR0ZtTUNJc0ltNXZibU5sSWpvaVYxWkNObFF5VWtoVU0wSjJVVmN4UTJSWVVuQk5XRTVaVDFSV01GTXlUbmhpVnpsVVZsUlNhazlJVVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1UZzJPVEV2SWl3aVkyaGhiQ0k2SW1WWWVGVmxia05pYW1sbWJHVTNlVlJ2WWxKdFdXeEhZMlJ1Ykhwc2FtMHlJbjAuUGRBV1RHdG9XQkVXVzdnX1FsZjM5ckFRUkllc3AxbGdsVlNDNEd1R2hLZzVXOEdlYU0tbXpjY1l5VlJ4MUcxamR3U1Y5MEFIOW01eGV1dktpLVJWQ1EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVlUVmhPR1kxTXpka05HTTNOR1ZoWmpobE1qbGhPVEE1TTJNd09EazFZVFkvMzQ1ZTQwMjVlZTM0MjVlMkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.--wxzLC8OoRM1KjUC-SIfN2lU3MgerFUinCNhTj1eAvhKe13WsM7opzWO6snNvzKjsbEzYwC29RGmVfH4MV1Aw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkctWHEwZnJZTjcwWENqTGVxQURvNURqUGRMR1VRb0xLNy1Pdk1jazd2Yk0ifX0.eyJpYXQiOjE2ODIwNjg1OTgsImV4cCI6MTY4OTg0NDU5OCwibmJmIjoxNjgyMDY4NTk4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTg2OTEvIiwic3ViIjoiaW06d2lyZWFwcD1ZVFZoT0dZMU16ZGtOR00zTkdWaFpqaGxNamxoT1RBNU0yTXdPRGsxWVRZLzM0NWU0MDI1ZWUzNDI1ZTJAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MTg2OTEvIiwianRpIjoiM2UwZGUyYjYtNTFhMS00NGI2LWE0YTAtODVjNzFkNmQ2ODlmIiwibm9uY2UiOiJXVkI2VDJSSFQzQnZRVzFDZFhScE1YTllPVFYwUzJOeGJXOVRWVFJqT0hRIiwiY2hhbCI6ImVYeFVlbkNiamlmbGU3eVRvYlJtWWxHY2RubHpsam0yIiwiY25mIjp7ImtpZCI6IjJIMzhwemRZVU5oUmVVWHJ5cnh0R0k0b3oxem01Y1pKSjY5Qlp5bVQ5N2sifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2ljRU5SV1VST2NIQTFUbkJRTm5WWU9VOUNhMlZEWm1kWWFFTkhjRmRvUVRCblFVVktjV0pGV0hvNVRTSjlmUS5leUpwWVhRaU9qRTJPREl3TmpnMU9UZ3NJbVY0Y0NJNk1UWTRNakEzTWpFNU9Dd2libUptSWpveE5qZ3lNRFk0TlRrNExDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWbFVWbWhQUjFreFRYcGthMDVIVFROT1IxWm9XbXBvYkUxcWJHaFBWRUUxVFRKTmQwOUVhekZaVkZrdk16UTFaVFF3TWpWbFpUTTBNalZsTWtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpOaE1UZzRZemMyTFRabVlUWXROR00yTnkxaU16azBMV1JsTURneFpXRmlOR0ZtTUNJc0ltNXZibU5sSWpvaVYxWkNObFF5VWtoVU0wSjJVVmN4UTJSWVVuQk5XRTVaVDFSV01GTXlUbmhpVnpsVVZsUlNhazlJVVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1UZzJPVEV2SWl3aVkyaGhiQ0k2SW1WWWVGVmxia05pYW1sbWJHVTNlVlJ2WWxKdFdXeEhZMlJ1Ykhwc2FtMHlJbjAuUGRBV1RHdG9XQkVXVzdnX1FsZjM5ckFRUkllc3AxbGdsVlNDNEd1R2hLZzVXOEdlYU0tbXpjY1l5VlJ4MUcxamR3U1Y5MEFIOW01eGV1dktpLVJWQ1EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVlUVmhPR1kxTXpka05HTTNOR1ZoWmpobE1qbGhPVEE1TTJNd09EazFZVFkvMzQ1ZTQwMjVlZTM0MjVlMkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.--wxzLC8OoRM1KjUC-SIfN2lU3MgerFUinCNhTj1eAvhKe13WsM7opzWO6snNvzKjsbEzYwC29RGmVfH4MV1Aw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6IkctWHEwZnJZTjcwWENqTGVxQURvNURqUGRM
R1VRb0xLNy1Pdk1jazd2Yk0ifX0.eyJpYXQiOjE2ODIwNjg1OTgsImV4cCI6MTY4
OTg0NDU5OCwibmJmIjoxNjgyMDY4NTk4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206
MTg2OTEvIiwic3ViIjoiaW06d2lyZWFwcD1ZVFZoT0dZMU16ZGtOR00zTkdWaFpq
aGxNamxoT1RBNU0yTXdPRGsxWVRZLzM0NWU0MDI1ZWUzNDI1ZTJAd2lyZS5jb20i
LCJhdWQiOiJodHRwOi8vd2lyZS5jb206MTg2OTEvIiwianRpIjoiM2UwZGUyYjYt
NTFhMS00NGI2LWE0YTAtODVjNzFkNmQ2ODlmIiwibm9uY2UiOiJXVkI2VDJSSFQz
QnZRVzFDZFhScE1YTllPVFYwUzJOeGJXOVRWVFJqT0hRIiwiY2hhbCI6ImVYeFVl
bkNiamlmbGU3eVRvYlJtWWxHY2RubHpsam0yIiwiY25mIjp7ImtpZCI6IjJIMzhw
emRZVU5oUmVVWHJ5cnh0R0k0b3oxem01Y1pKSjY5Qlp5bVQ5N2sifSwicHJvb2Yi
OiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFu
ZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElq
b2ljRU5SV1VST2NIQTFUbkJRTm5WWU9VOUNhMlZEWm1kWWFFTkhjRmRvUVRCblFV
VktjV0pGV0hvNVRTSjlmUS5leUpwWVhRaU9qRTJPREl3TmpnMU9UZ3NJbVY0Y0NJ
Nk1UWTRNakEzTWpFNU9Dd2libUptSWpveE5qZ3lNRFk0TlRrNExDSnpkV0lpT2lK
cGJUcDNhWEpsWVhCd1BWbFVWbWhQUjFreFRYcGthMDVIVFROT1IxWm9XbXBvYkUx
cWJHaFBWRUUxVFRKTmQwOUVhekZaVkZrdk16UTFaVFF3TWpWbFpUTTBNalZsTWtC
M2FYSmxMbU52YlNJc0ltcDBhU0k2SWpOaE1UZzRZemMyTFRabVlUWXROR00yTnkx
aU16azBMV1JsTURneFpXRmlOR0ZtTUNJc0ltNXZibU5sSWpvaVYxWkNObFF5VWto
VU0wSjJVVmN4UTJSWVVuQk5XRTVaVDFSV01GTXlUbmhpVnpsVVZsUlNhazlJVVNJ
c0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIw
Nk1UZzJPVEV2SWl3aVkyaGhiQ0k2SW1WWWVGVmxia05pYW1sbWJHVTNlVlJ2WWxK
dFdXeEhZMlJ1Ykhwc2FtMHlJbjAuUGRBV1RHdG9XQkVXVzdnX1FsZjM5ckFRUkll
c3AxbGdsVlNDNEd1R2hLZzVXOEdlYU0tbXpjY1l5VlJ4MUcxamR3U1Y5MEFIOW01
eGV1dktpLVJWQ1EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVlUVmhPR1kxTXpk
a05HTTNOR1ZoWmpobE1qbGhPVEE1TTJNd09EazFZVFkvMzQ1ZTQwMjVlZTM0MjVl
MkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50
X2lkIn0.--wxzLC8OoRM1KjUC-SIfN2lU3MgerFUinCNhTj1eAvhKe13WsM7opzW
O6snNvzKjsbEzYwC29RGmVfH4MV1Aw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "G-Xq0frYN70XCjLeqADo5DjPdLGUQoLK7-OvMck7vbM"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:18691/",
  "chal": "eXxUenCbjifle7yTobRmYlGcdnlzljm2",
  "client_id": "im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com",
  "cnf": {
    "kid": "2H38pzdYUNhReUXryrxtGI4oz1zm5cZJJ69BZymT97k"
  },
  "exp": 1689844598,
  "iat": 1682068598,
  "iss": "http://wire.com:18691/",
  "jti": "3e0de2b6-51a1-44b6-a4a0-85c71d6d689f",
  "nbf": 1682068598,
  "nonce": "WVB6T2RHT3BvQW1CdXRpMXNYOTV0S2NxbW9TVTRjOHQ",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoicENRWUROcHA1TnBQNnVYOU9Ca2VDZmdYaENHcFdoQTBnQUVKcWJFWHo5TSJ9fQ.eyJpYXQiOjE2ODIwNjg1OTgsImV4cCI6MTY4MjA3MjE5OCwibmJmIjoxNjgyMDY4NTk4LCJzdWIiOiJpbTp3aXJlYXBwPVlUVmhPR1kxTXpka05HTTNOR1ZoWmpobE1qbGhPVEE1TTJNd09EazFZVFkvMzQ1ZTQwMjVlZTM0MjVlMkB3aXJlLmNvbSIsImp0aSI6IjNhMTg4Yzc2LTZmYTYtNGM2Ny1iMzk0LWRlMDgxZWFiNGFmMCIsIm5vbmNlIjoiV1ZCNlQyUkhUM0J2UVcxQ2RYUnBNWE5ZT1RWMFMyTnhiVzlUVlRSak9IUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206MTg2OTEvIiwiY2hhbCI6ImVYeFVlbkNiamlmbGU3eVRvYlJtWWxHY2RubHpsam0yIn0.PdAWTGtoWBEWW7g_Qlf39rAQRIesp1lglVSC4GuGhKg5W8GeaM-mzccYyVRx1G1jdwSV90AH9m5xeuvKi-RVCQ",
  "scope": "wire_client_id",
  "sub": "im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIDUFcx0RvRuMqrVBOL5r0vhOe8P9OZ4nSadFrLbBKNQe
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAG+Xq0frYN70XCjLeqADo5DjPdLGUQoLK7+OvMck7vbM=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/o2l6SiuLShSUJxcRKJEdBmUIj8SQSSb8
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODg1L2FjbWUvd2lyZS9hY2NvdW50L2draklmVHA5WlVtNnF6RFZkUENVaFMyZW9CNG1YV2pHIiwidHlwIjoiSldUIiwibm9uY2UiOiJaVXhaVWs0d2RrRmtUVU4zYTI5d1ZWRnZhekkzYkhocVNIZERZVE5RTTNVIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4ODUvYWNtZS93aXJlL2NoYWxsZW5nZS9Bd2VnWWhNRkF6VDA5UGJ6dHZjVmxHNG93TEVQa0V0Yi9vMmw2U2l1TFNoU1VKeGNSS0pFZEJtVUlqOFNRU1NiOCJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklrY3RXSEV3Wm5KWlRqY3dXRU5xVEdWeFFVUnZOVVJxVUdSTVIxVlJiMHhMTnkxUGRrMWphemQyWWswaWZYMC5leUpwWVhRaU9qRTJPREl3TmpnMU9UZ3NJbVY0Y0NJNk1UWTRPVGcwTkRVNU9Dd2libUptSWpveE5qZ3lNRFk0TlRrNExDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2TVRnMk9URXZJaXdpYzNWaUlqb2lhVzA2ZDJseVpXRndjRDFaVkZab1QwZFpNVTE2Wkd0T1IwMHpUa2RXYUZwcWFHeE5hbXhvVDFSQk5VMHlUWGRQUkdzeFdWUlpMek0wTldVME1ESTFaV1V6TkRJMVpUSkFkMmx5WlM1amIyMGlMQ0poZFdRaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1UZzJPVEV2SWl3aWFuUnBJam9pTTJVd1pHVXlZall0TlRGaE1TMDBOR0kyTFdFMFlUQXRPRFZqTnpGa05tUTJPRGxtSWl3aWJtOXVZMlVpT2lKWFZrSTJWREpTU0ZRelFuWlJWekZEWkZoU2NFMVlUbGxQVkZZd1V6Sk9lR0pYT1ZSV1ZGSnFUMGhSSWl3aVkyaGhiQ0k2SW1WWWVGVmxia05pYW1sbWJHVTNlVlJ2WWxKdFdXeEhZMlJ1Ykhwc2FtMHlJaXdpWTI1bUlqcDdJbXRwWkNJNklqSklNemh3ZW1SWlZVNW9VbVZWV0hKNWNuaDBSMGswYjNveGVtMDFZMXBLU2pZNVFscDViVlE1TjJzaWZTd2ljSEp2YjJZaU9pSmxlVXBvWWtkamFVOXBTa1phUlZKVVVWTkpjMGx1VWpWalEwazJTVzFTZDJJelFYSmhibVF3U1dsM2FXRnVaSEpKYW5BM1NXMTBNR1ZUU1RaSmF6bE1WVU5KYzBsdFRubGthVWsyU1d0V2EwMXFWVEZOVkd0cFRFTktORWxxYjJsalJVNVNWMVZTVDJOSVFURlVia0pSVG01V1dVOVZPVU5oTWxaRVdtMWtXV0ZGVGtoalJtUnZVVlJDYmxGVlZrdGpWMHBHVjBodk5WUlRTamxtVVM1bGVVcHdXVmhSYVU5cVJUSlBSRWwzVG1wbk1VOVVaM05KYlZZMFkwTkpOazFVV1RSTmFrRXpUV3BGTlU5RGQybGliVXB0U1dwdmVFNXFaM2xOUkZrMFRsUnJORXhEU25wa1YwbHBUMmxLY0dKVWNETmhXRXBzV1ZoQ2QxQldiRlZXYldoUVVqRnJlRlJZY0d0aE1EVklWRlJPVDFJeFdtOVhiWEJ2WWtVeGNXSkhhRkJXUlVVeFZGUktUbVF3T1VWaGVrWmFWa1pyZGsxNlVURmFWRkYzVFdwV2JGcFVUVEJOYWxac1RXdENNMkZZU214TWJVNTJZbE5KYzBsdGNEQmhVMGsyU1dwT2FFMVVaelJaZW1NeVRGUmFiVmxVV1hST1IwMHlUbmt4YVUxNmF6Qk1WMUpzVFVSbmVGcFhSbWxPUjBadFRVTkpjMGx0TlhaaWJVNXNTV3B2YVZZeFdrTk9iRkY1Vld0b1ZVMHdTakpWVm1ONFVUSlNXVlZ1UWs1WFJUVmFWREZTVjAxR1RYbFVibWhwVm5wc1ZWWnNVbE5oYXpsSlZWTkpjMGx0YURCaVUwazJTV3hDVUZVeFVXbE1RMHB2WkVoVmFVOXBTbTlrU0ZKM1QyazRkbVF5YkhsYVV6VnFZakl3TmsxVVp6SlBWRVYyU1dsM2FWa3lhR2hpUTBrMlNXMVdXV1ZHVm14aWEwNXBZVzFzYldKSFZUTmxWbEoyV1d4S2RGZFhlRWhaTWxKMVlraHdjMkZ0TUhsSmJqQXVVR1JCVjFSSGRHOVhRa1ZYVnpkblgxRnNaak01Y2tGUlVrbGxjM0F4Ykdkc1ZsTkRORWQxUjJoTFp6VlhPRWRsWVUwdGJYcGpZMWw1VmxKNE1VY3hhbVIzVTFZNU1FRklPVzAxZUdWMWRrdHBMVkpXUTFFaUxDSmpiR2xsYm5SZmFXUWlPaUpwYlRwM2FYSmxZWEJ3UFZsVVZtaFBSMWt4VFhwa2EwNUhUVE5PUjFab1dtcG9iRTFxYkdoUFZFRTFUVEpOZDA5RWF6RlpWRmt2TXpRMVpUUXdNalZsWlRNME1qVmxNa0IzYVhKbExtTnZiU0lzSW1Gd2FWOTJaWEp6YVc5dUlqb3pMQ0p6WTI5d1pTSTZJbmRwY21WZlkyeHBaVzUwWDJsa0luMC4tLXd4ekxDOE9vUk0xS2pVQy1TSWZOMmxVM01nZXJGVWluQ05oVGoxZUF2aEtlMTNXc003b3B6V082c25OdnpLanNiRXpZd0MyOVJHbVZmSDRNVjFBdyJ9",
  "signature": "zBxCAvCQifRwk3JMEc7ahMm1wk9t874ZdbDZEtxGg-US1PgDNCgibDvq_947dh3UIXAY9LU4gssKA-ajnacTBA"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IkctWHEwZnJZTjcwWENqTGVxQURvNURqUGRMR1VRb0xLNy1Pdk1jazd2Yk0ifX0.eyJpYXQiOjE2ODIwNjg1OTgsImV4cCI6MTY4OTg0NDU5OCwibmJmIjoxNjgyMDY4NTk4LCJpc3MiOiJodHRwOi8vd2lyZS5jb206MTg2OTEvIiwic3ViIjoiaW06d2lyZWFwcD1ZVFZoT0dZMU16ZGtOR00zTkdWaFpqaGxNamxoT1RBNU0yTXdPRGsxWVRZLzM0NWU0MDI1ZWUzNDI1ZTJAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vd2lyZS5jb206MTg2OTEvIiwianRpIjoiM2UwZGUyYjYtNTFhMS00NGI2LWE0YTAtODVjNzFkNmQ2ODlmIiwibm9uY2UiOiJXVkI2VDJSSFQzQnZRVzFDZFhScE1YTllPVFYwUzJOeGJXOVRWVFJqT0hRIiwiY2hhbCI6ImVYeFVlbkNiamlmbGU3eVRvYlJtWWxHY2RubHpsam0yIiwiY25mIjp7ImtpZCI6IjJIMzhwemRZVU5oUmVVWHJ5cnh0R0k0b3oxem01Y1pKSjY5Qlp5bVQ5N2sifSwicHJvb2YiOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJazlMVUNJc0ltTnlkaUk2SWtWa01qVTFNVGtpTENKNElqb2ljRU5SV1VST2NIQTFUbkJRTm5WWU9VOUNhMlZEWm1kWWFFTkhjRmRvUVRCblFVVktjV0pGV0hvNVRTSjlmUS5leUpwWVhRaU9qRTJPREl3TmpnMU9UZ3NJbVY0Y0NJNk1UWTRNakEzTWpFNU9Dd2libUptSWpveE5qZ3lNRFk0TlRrNExDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd1BWbFVWbWhQUjFreFRYcGthMDVIVFROT1IxWm9XbXBvYkUxcWJHaFBWRUUxVFRKTmQwOUVhekZaVkZrdk16UTFaVFF3TWpWbFpUTTBNalZsTWtCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpOaE1UZzRZemMyTFRabVlUWXROR00yTnkxaU16azBMV1JsTURneFpXRmlOR0ZtTUNJc0ltNXZibU5sSWpvaVYxWkNObFF5VWtoVU0wSjJVVmN4UTJSWVVuQk5XRTVaVDFSV01GTXlUbmhpVnpsVVZsUlNhazlJVVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmQybHlaUzVqYjIwNk1UZzJPVEV2SWl3aVkyaGhiQ0k2SW1WWWVGVmxia05pYW1sbWJHVTNlVlJ2WWxKdFdXeEhZMlJ1Ykhwc2FtMHlJbjAuUGRBV1RHdG9XQkVXVzdnX1FsZjM5ckFRUkllc3AxbGdsVlNDNEd1R2hLZzVXOEdlYU0tbXpjY1l5VlJ4MUcxamR3U1Y5MEFIOW01eGV1dktpLVJWQ1EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPVlUVmhPR1kxTXpka05HTTNOR1ZoWmpobE1qbGhPVEE1TTJNd09EazFZVFkvMzQ1ZTQwMjVlZTM0MjVlMkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.--wxzLC8OoRM1KjUC-SIfN2lU3MgerFUinCNhTj1eAvhKe13WsM7opzWO6snNvzKjsbEzYwC29RGmVfH4MV1Aw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32885/acme/wire/account/gkjIfTp9ZUm6qzDVdPCUhS2eoB4mXWjG",
    "nonce": "ZUxZUk4wdkFkTUN3a29wVVFvazI3bHhqSHdDYTNQM3U",
    "typ": "JWT",
    "url": "https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/o2l6SiuLShSUJxcRKJEdBmUIj8SQSSb8"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32885/acme/wire/directory>;rel="index"
link: <https://stepca:32885/acme/wire/authz/AwegYhMFAzT09PbztvcVlG4owLEPkEtb>;rel="up"
location: https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/o2l6SiuLShSUJxcRKJEdBmUIj8SQSSb8
replay-nonce: VkJuMmk5Y2NJSWtTWEJuMzBnaVlOTDZLWHBkWXYzVnM
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/o2l6SiuLShSUJxcRKJEdBmUIj8SQSSb8",
  "status": "valid",
  "token": "eXxUenCbjifle7yTobRmYlGcdnlzljm2"
}
```
### Authenticate end user using OIDC Authorization Code with PKCE flow
#### 18. OAUTH authorization request

```text
code_verifier=0zF5_aKUpiNB0XytUnT8MCy5YdeddZG9dpOxskIBEEw&code_challenge=fe2MaonylX_vDWyEfSQWzCIhrZ2z99CfcL3qJ8wn7f0
```
#### 19. OAUTH authorization request (auth code endpoint)
```http request
GET http://dex:18119/dex/auth?response_type=code&client_id=wireapp&state=hBRbCY6c8eLM-7zvSUtYQg&code_challenge=fe2MaonylX_vDWyEfSQWzCIhrZ2z99CfcL3qJ8wn7f0&code_challenge_method=S256&redirect_uri=http%3A%2F%2Fwire.com%3A18691%2Fcallback&scope=openid+profile&nonce=x9qQfg_EdbfRS5Q4Bw4nPg
```
#### 20. OAUTH authorization code
#### 21. OAUTH authorization code

#### 22. OAUTH authorization code + verifier (token endpoint)
```http request
POST http://dex:18119/dex/token
accept: application/json
content-type: application/x-www-form-urlencoded
authorization: Basic d2lyZWFwcDpiRmQ2Wlc0MFRuUlhWVUUxUW0xdk5IVTVhazF3VkRRMw==
```
```text
grant_type=authorization_code&code=wmx5uu6vdumqghsr6trczecly&code_verifier=0zF5_aKUpiNB0XytUnT8MCy5YdeddZG9dpOxskIBEEw&redirect_uri=http%3A%2F%2Fwire.com%3A18691%2Fcallback
```
#### 23. OAUTH access token

```text
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBkMjMxNjNiNTg5OWI0MzlmNDE1YTQ0YTEzZTIxMzMwNjY0ZGI3MzUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTE5L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmxVVm1oUFIxa3hUWHBrYTA1SFRUTk9SMVpvV21wb2JFMXFiR2hQVkVFMVRUSk5kMDlFYXpGWlZGa3ZNelExWlRRd01qVmxaVE0wTWpWbE1rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgyMTU0OTk4LCJpYXQiOjE2ODIwNjg1OTgsIm5vbmNlIjoieDlxUWZnX0VkYmZSUzVRNEJ3NG5QZyIsImF0X2hhc2giOiJCWWVtTVRTYTJ5OEdkVWYyR3hXcUNBIiwibmFtZSI6ImltOndpcmVhcHA9YWxpY2Vfd2lyZSIsInByZWZlcnJlZF91c2VybmFtZSI6IkFsaWNlIFNtaXRoIn0.Hs4N-VuYUFUwibjgoEgZYwCJH0so_qF_4puC6QXtKkXolXAcDqRBllo_H1_AJQOgvDEvGr17-IN6chdh5yCOkDT6VlFDpdysLpR7CKpNZFQViDezX3Lnm3kzS4Yv9Zp78eQ0qOuBilNojiwmB9IoOvdu5yoaX9ckatYjdURMveYP_6KIageXo1AS2vcDc2FQAckl-Z50KFNVRYT207qtF2SUDRJURC1XoF0qFBa8l7YcQ_dnZ7J__gHK2eJo-zopBdAOK90MdhfDpDzRZG2Gp8rYX7T_qYv2YkbobslFwPtmUzx0MlMMvFCaiuv0JCH5Je4uRcQnz_USjTTY4IrxWw",
  "expires_in": 86399,
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBkMjMxNjNiNTg5OWI0MzlmNDE1YTQ0YTEzZTIxMzMwNjY0ZGI3MzUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTE5L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmxVVm1oUFIxa3hUWHBrYTA1SFRUTk9SMVpvV21wb2JFMXFiR2hQVkVFMVRUSk5kMDlFYXpGWlZGa3ZNelExWlRRd01qVmxaVE0wTWpWbE1rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgyMTU0OTk4LCJpYXQiOjE2ODIwNjg1OTgsIm5vbmNlIjoieDlxUWZnX0VkYmZSUzVRNEJ3NG5QZyIsImF0X2hhc2giOiIxVFh5ZWVJTm9ULThZZnF1a2tBUDJ3IiwiY19oYXNoIjoiZUhDMndnRVRCMklWckNvN3ktUXQ3dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.kpff72BE56IFcnpopHQ55BfN-gLBBGH7xTUt4_MFUP1zYQPOrmhSTaL7JdIPN3R9CuOXEIkoey4zGiqiIRTdKH0U1cL0yl8yz6fvsOuEkrilkbYYU83fxLFwRydidS2SGQo8B3DwIn-u4LAollPLobX1EXOKIZ-1fLm-9qjijTWQXlp_trpj9pKa0fi1YQxXmNMw2swmvnZuQZTmaQZ9FJ8ZlfEaw7u29n5mF27mnxGYX5WgRqJDyXA2jAwxxKgXhkZa71BNP_hkHgvLPs7j2fOC0kO_EQMqgmsBoDlQBikuU_7MqZ0ETeuHYlOEzWofPYT2hxcwKnNVchDm0IQztQ",
  "token_type": "bearer"
}
```
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjBkMjMxNjNiNTg5OWI0MzlmNDE1YTQ0YTEzZTIxMzMwNjY0ZGI3MzUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTE5L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmxVVm1oUFIxa3hUWHBrYTA1SFRUTk9SMVpvV21wb2JFMXFiR2hQVkVFMVRUSk5kMDlFYXpGWlZGa3ZNelExWlRRd01qVmxaVE0wTWpWbE1rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgyMTU0OTk4LCJpYXQiOjE2ODIwNjg1OTgsIm5vbmNlIjoieDlxUWZnX0VkYmZSUzVRNEJ3NG5QZyIsImF0X2hhc2giOiIxVFh5ZWVJTm9ULThZZnF1a2tBUDJ3IiwiY19oYXNoIjoiZUhDMndnRVRCMklWckNvN3ktUXQ3dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.kpff72BE56IFcnpopHQ55BfN-gLBBGH7xTUt4_MFUP1zYQPOrmhSTaL7JdIPN3R9CuOXEIkoey4zGiqiIRTdKH0U1cL0yl8yz6fvsOuEkrilkbYYU83fxLFwRydidS2SGQo8B3DwIn-u4LAollPLobX1EXOKIZ-1fLm-9qjijTWQXlp_trpj9pKa0fi1YQxXmNMw2swmvnZuQZTmaQZ9FJ8ZlfEaw7u29n5mF27mnxGYX5WgRqJDyXA2jAwxxKgXhkZa71BNP_hkHgvLPs7j2fOC0kO_EQMqgmsBoDlQBikuU_7MqZ0ETeuHYlOEzWofPYT2hxcwKnNVchDm0IQztQ
```
#### 24. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6IjBkMjMxNjNiNTg5OWI0MzlmNDE1YTQ0YTEzZTIxMzMwNjY0ZGI3MzUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTE5L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmxVVm1oUFIxa3hUWHBrYTA1SFRUTk9SMVpvV21wb2JFMXFiR2hQVkVFMVRUSk5kMDlFYXpGWlZGa3ZNelExWlRRd01qVmxaVE0wTWpWbE1rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgyMTU0OTk4LCJpYXQiOjE2ODIwNjg1OTgsIm5vbmNlIjoieDlxUWZnX0VkYmZSUzVRNEJ3NG5QZyIsImF0X2hhc2giOiIxVFh5ZWVJTm9ULThZZnF1a2tBUDJ3IiwiY19oYXNoIjoiZUhDMndnRVRCMklWckNvN3ktUXQ3dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.kpff72BE56IFcnpopHQ55BfN-gLBBGH7xTUt4_MFUP1zYQPOrmhSTaL7JdIPN3R9CuOXEIkoey4zGiqiIRTdKH0U1cL0yl8yz6fvsOuEkrilkbYYU83fxLFwRydidS2SGQo8B3DwIn-u4LAollPLobX1EXOKIZ-1fLm-9qjijTWQXlp_trpj9pKa0fi1YQxXmNMw2swmvnZuQZTmaQZ9FJ8ZlfEaw7u29n5mF27mnxGYX5WgRqJDyXA2jAwxxKgXhkZa71BNP_hkHgvLPs7j2fOC0kO_EQMqgmsBoDlQBikuU_7MqZ0ETeuHYlOEzWofPYT2hxcwKnNVchDm0IQztQ)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6IjBkMjMxNjNiNTg5OWI0MzlmNDE1YTQ0YTEz
ZTIxMzMwNjY0ZGI3MzUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTE5L2RleCIsI
nN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmxVVm1oUFIxa3hUWHBrYTA1SFRUTk9SM
VpvV21wb2JFMXFiR2hQVkVFMVRUSk5kMDlFYXpGWlZGa3ZNelExWlRRd01qVmxaV
E0wTWpWbE1rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZ
XhwIjoxNjgyMTU0OTk4LCJpYXQiOjE2ODIwNjg1OTgsIm5vbmNlIjoieDlxUWZnX
0VkYmZSUzVRNEJ3NG5QZyIsImF0X2hhc2giOiIxVFh5ZWVJTm9ULThZZnF1a2tBU
DJ3IiwiY19oYXNoIjoiZUhDMndnRVRCMklWckNvN3ktUXQ3dyIsIm5hbWUiOiJpb
Tp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZ
SBTbWl0aCJ9.kpff72BE56IFcnpopHQ55BfN-gLBBGH7xTUt4_MFUP1zYQPOrmhS
TaL7JdIPN3R9CuOXEIkoey4zGiqiIRTdKH0U1cL0yl8yz6fvsOuEkrilkbYYU83f
xLFwRydidS2SGQo8B3DwIn-u4LAollPLobX1EXOKIZ-1fLm-9qjijTWQXlp_trpj
9pKa0fi1YQxXmNMw2swmvnZuQZTmaQZ9FJ8ZlfEaw7u29n5mF27mnxGYX5WgRqJD
yXA2jAwxxKgXhkZa71BNP_hkHgvLPs7j2fOC0kO_EQMqgmsBoDlQBikuU_7MqZ0E
TeuHYlOEzWofPYT2hxcwKnNVchDm0IQztQ
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "0d23163b5899b439f415a44a13e21330664db735"
}
```

```json
{
  "at_hash": "1TXyeeINoT-8YfqukkAP2w",
  "aud": "wireapp",
  "c_hash": "eHC2wgETB2IVrCo7y-Qt7w",
  "exp": 1682154998,
  "iat": 1682068598,
  "iss": "http://dex:18119/dex",
  "name": "im:wireapp=alice_wire",
  "nonce": "x9qQfg_EdbfRS5Q4Bw4nPg",
  "preferred_username": "Alice Smith",
  "sub": "ClBpbTp3aXJlYXBwPVlUVmhPR1kxTXpka05HTTNOR1ZoWmpobE1qbGhPVEE1TTJNd09EazFZVFkvMzQ1ZTQwMjVlZTM0MjVlMkB3aXJlLmNvbRIEbGRhcA"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvHpGfhNu2b6CncJMplCi
qVW78CvvgSv3PkVXNb/BfQtSxgLU7HPt9NFxg0ZyrcLyuFtaFRh8FwdlMpGQ3HcP
aaCZKEcG1+UhgawUVCH2Swm8BFFx3A/f0mOlzksSNCjixLQAVQFWw5JHC/uPXBLN
n74TkrX2K2lVeA2+OCr0J6AtO1gIvoJ/Jsg4jsNrifqXCER7eOqqxqgIoUmdwyLk
FihFbVs8WE77W9RDj6i9IquPBQDrkDjQwgklV8+FencRBE8LIhAQSc7l7Ig7S7jc
5tvjrY6sAGKXmA+1b81QcqN9xtQbdOopffuto4Y6hPkrraNeAvROwC947YdzKCPy
+QIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/YaUtWZ2bKbrpplQLvuJTUsLFKKxX0xq1
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODg1L2FjbWUvd2lyZS9hY2NvdW50L2draklmVHA5WlVtNnF6RFZkUENVaFMyZW9CNG1YV2pHIiwidHlwIjoiSldUIiwibm9uY2UiOiJWa0p1TW1rNVkyTkpTV3RUV0VKdU16Qm5hVmxPVERaTFdIQmtXWFl6Vm5NIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4ODUvYWNtZS93aXJlL2NoYWxsZW5nZS9Bd2VnWWhNRkF6VDA5UGJ6dHZjVmxHNG93TEVQa0V0Yi9ZYVV0V1oyYkticnBwbFFMdnVKVFVzTEZLS3hYMHhxMSJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJakJrTWpNeE5qTmlOVGc1T1dJME16bG1OREUxWVRRMFlURXpaVEl4TXpNd05qWTBaR0kzTXpVaWZRLmV5SnBjM01pT2lKb2RIUndPaTh2WkdWNE9qRTRNVEU1TDJSbGVDSXNJbk4xWWlJNklrTnNRbkJpVkhBellWaEtiRmxZUW5kUVZteFZWbTFvVUZJeGEzaFVXSEJyWVRBMVNGUlVUazlTTVZwdlYyMXdiMkpGTVhGaVIyaFFWa1ZGTVZSVVNrNWtNRGxGWVhwR1dsWkdhM1pOZWxFeFdsUlJkMDFxVm14YVZFMHdUV3BXYkUxclFqTmhXRXBzVEcxT2RtSlNTVVZpUjFKb1kwRWlMQ0poZFdRaU9pSjNhWEpsWVhCd0lpd2laWGh3SWpveE5qZ3lNVFUwT1RrNExDSnBZWFFpT2pFMk9ESXdOamcxT1Rnc0ltNXZibU5sSWpvaWVEbHhVV1puWDBWa1ltWlNVelZSTkVKM05HNVFaeUlzSW1GMFgyaGhjMmdpT2lJeFZGaDVaV1ZKVG05VUxUaFpabkYxYTJ0QlVESjNJaXdpWTE5b1lYTm9Jam9pWlVoRE1uZG5SVlJDTWtsV2NrTnZOM2t0VVhRM2R5SXNJbTVoYldVaU9pSnBiVHAzYVhKbFlYQndQV0ZzYVdObFgzZHBjbVVpTENKd2NtVm1aWEp5WldSZmRYTmxjbTVoYldVaU9pSkJiR2xqWlNCVGJXbDBhQ0o5LmtwZmY3MkJFNTZJRmNucG9wSFE1NUJmTi1nTEJCR0g3eFRVdDRfTUZVUDF6WVFQT3JtaFNUYUw3SmRJUE4zUjlDdU9YRUlrb2V5NHpHaXFpSVJUZEtIMFUxY0wweWw4eXo2ZnZzT3VFa3JpbGtiWVlVODNmeExGd1J5ZGlkUzJTR1FvOEIzRHdJbi11NExBb2xsUExvYlgxRVhPS0laLTFmTG0tOXFqaWpUV1FYbHBfdHJwajlwS2EwZmkxWVF4WG1OTXcyc3dtdm5adVFaVG1hUVo5Rko4WmxmRWF3N3UyOW41bUYyN21ueEdZWDVXZ1JxSkR5WEEyakF3eHhLZ1hoa1phNzFCTlBfaGtIZ3ZMUHM3ajJmT0Mwa09fRVFNcWdtc0JvRGxRQmlrdVVfN01xWjBFVGV1SFlsT0V6V29mUFlUMmh4Y3dLbk5WY2hEbTBJUXp0USIsImtleWF1dGgiOiJlWHhVZW5DYmppZmxlN3lUb2JSbVlsR2Nkbmx6bGptMi55V2szZ1JBTXR1VE95NnZndUo5b2FYNENhNHFtRXNyTzkweVQ3NXV4ZVFnIn0",
  "signature": "STeJq2Ba4ZQSdQUjNayOO99n77rh0hByXwJ1RE74oRckKJQnRc9636n0E42ZDLEmUSOYSyOtB6OW9y4ch4XEDg"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjBkMjMxNjNiNTg5OWI0MzlmNDE1YTQ0YTEzZTIxMzMwNjY0ZGI3MzUifQ.eyJpc3MiOiJodHRwOi8vZGV4OjE4MTE5L2RleCIsInN1YiI6IkNsQnBiVHAzYVhKbFlYQndQVmxVVm1oUFIxa3hUWHBrYTA1SFRUTk9SMVpvV21wb2JFMXFiR2hQVkVFMVRUSk5kMDlFYXpGWlZGa3ZNelExWlRRd01qVmxaVE0wTWpWbE1rQjNhWEpsTG1OdmJSSUViR1JoY0EiLCJhdWQiOiJ3aXJlYXBwIiwiZXhwIjoxNjgyMTU0OTk4LCJpYXQiOjE2ODIwNjg1OTgsIm5vbmNlIjoieDlxUWZnX0VkYmZSUzVRNEJ3NG5QZyIsImF0X2hhc2giOiIxVFh5ZWVJTm9ULThZZnF1a2tBUDJ3IiwiY19oYXNoIjoiZUhDMndnRVRCMklWckNvN3ktUXQ3dyIsIm5hbWUiOiJpbTp3aXJlYXBwPWFsaWNlX3dpcmUiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJBbGljZSBTbWl0aCJ9.kpff72BE56IFcnpopHQ55BfN-gLBBGH7xTUt4_MFUP1zYQPOrmhSTaL7JdIPN3R9CuOXEIkoey4zGiqiIRTdKH0U1cL0yl8yz6fvsOuEkrilkbYYU83fxLFwRydidS2SGQo8B3DwIn-u4LAollPLobX1EXOKIZ-1fLm-9qjijTWQXlp_trpj9pKa0fi1YQxXmNMw2swmvnZuQZTmaQZ9FJ8ZlfEaw7u29n5mF27mnxGYX5WgRqJDyXA2jAwxxKgXhkZa71BNP_hkHgvLPs7j2fOC0kO_EQMqgmsBoDlQBikuU_7MqZ0ETeuHYlOEzWofPYT2hxcwKnNVchDm0IQztQ",
    "keyauth": "eXxUenCbjifle7yTobRmYlGcdnlzljm2.yWk3gRAMtuTOy6vguJ9oaX4Ca4qmEsrO90yT75uxeQg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32885/acme/wire/account/gkjIfTp9ZUm6qzDVdPCUhS2eoB4mXWjG",
    "nonce": "VkJuMmk5Y2NJSWtTWEJuMzBnaVlOTDZLWHBkWXYzVnM",
    "typ": "JWT",
    "url": "https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/YaUtWZ2bKbrpplQLvuJTUsLFKKxX0xq1"
  }
}
```
#### 25. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32885/acme/wire/directory>;rel="index"
link: <https://stepca:32885/acme/wire/authz/AwegYhMFAzT09PbztvcVlG4owLEPkEtb>;rel="up"
location: https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/YaUtWZ2bKbrpplQLvuJTUsLFKKxX0xq1
replay-nonce: VzYwTmc3M2JtWTdOT29OZnVJc0lINGYwU1MzNlRmekg
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:32885/acme/wire/challenge/AwegYhMFAzT09PbztvcVlG4owLEPkEtb/YaUtWZ2bKbrpplQLvuJTUsLFKKxX0xq1",
  "status": "valid",
  "token": "eXxUenCbjifle7yTobRmYlGcdnlzljm2"
}
```
### Client presents a CSR and gets its certificate
#### 26. verify the status of the order
```http request
POST https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODg1L2FjbWUvd2lyZS9hY2NvdW50L2draklmVHA5WlVtNnF6RFZkUENVaFMyZW9CNG1YV2pHIiwidHlwIjoiSldUIiwibm9uY2UiOiJWell3VG1jM00ySnRXVGRPVDI5T1puVkpjMGxJTkdZd1UxTXpObFJtZWtnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4ODUvYWNtZS93aXJlL29yZGVyLzhXSDJrSG1MZ0pWN3JQaDhSZ3JWS0VPOEduZGNaSkRnIn0",
  "payload": "",
  "signature": "tacRkVDfB9olS0SSnoheYfVMHq6iiAz6MVktbtPFDJO9EdBurVTV4OmdNgpNNNNukWqh9ubRPDLesIAXHnGFCA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32885/acme/wire/account/gkjIfTp9ZUm6qzDVdPCUhS2eoB4mXWjG",
    "nonce": "VzYwTmc3M2JtWTdOT29OZnVJc0lINGYwU1MzNlRmekg",
    "typ": "JWT",
    "url": "https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg"
  }
}
```
#### 27. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32885/acme/wire/directory>;rel="index"
location: https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg
replay-nonce: Mm8zN2Z1V05QMm03TVk0b1FaQ29FWjJBNGtkY3FoRW4
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32885/acme/wire/authz/AwegYhMFAzT09PbztvcVlG4owLEPkEtb"
  ],
  "expires": "2023-04-22T09:16:38Z",
  "notBefore": "2023-04-21T09:16:38.298667Z",
  "notAfter": "2023-04-21T10:16:38.298667Z"
}
```
#### 28. create a CSR and call finalize url
```http request
POST https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODg1L2FjbWUvd2lyZS9hY2NvdW50L2draklmVHA5WlVtNnF6RFZkUENVaFMyZW9CNG1YV2pHIiwidHlwIjoiSldUIiwibm9uY2UiOiJNbTh6TjJaMVYwNVFNbTAzVFZrMGIxRmFRMjlGV2pKQk5HdGtZM0ZvUlc0IiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4ODUvYWNtZS93aXJlL29yZGVyLzhXSDJrSG1MZ0pWN3JQaDhSZ3JWS0VPOEduZGNaSkRnL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCT0RDQjZ3SUJBREF4TVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFY01Cb0dDMkNHU0FHRy1FSURBWUZ4REF0QmJHbGpaU0JUYldsMGFEQXFNQVVHQXl0bGNBTWhBS1FrR0F6YWFlVGFULXJsX1RnWkhnbjRGNFFocVZvUU5JQUJDYW14RjhfVG9JR0dNSUdEQmdrcWhraUc5dzBCQ1E0eGRqQjBNSElHQTFVZEVRUnJNR21HVUdsdE9uZHBjbVZoY0hBOVdWUldhRTlIV1RGTmVtUnJUa2ROTTA1SFZtaGFhbWhzVFdwc2FFOVVRVFZOTWsxM1QwUnJNVmxVV1M4ek5EVmxOREF5TldWbE16UXlOV1V5UUhkcGNtVXVZMjl0aGhWcGJUcDNhWEpsWVhCd1BXRnNhV05sWDNkcGNtVXdCUVlESzJWd0EwRUFuVnlRMjBaYnNQcWRLbFA5am94Zkp3TGs2LUhIWTFrUHJ3UkFPanNSbTBmejNSUmxwc0NrZHRqUjZaLVdsTTRBUkFLMm41MkdFWEc4VjR3NGhjMFRDZyJ9",
  "signature": "GIfFBd5OF6bUpls1qSPK_Zx2qqC4rFGE7kTScNhhbioWDx-EVEVoX4m6E4NBSJJzJQHEexVL_vimJ0_NTT9PDQ"
}
```
```json
{
  "payload": {
    "csr": "MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG-EIDAYFxDAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAKQkGAzaaeTaT-rl_TgZHgn4F4QhqVoQNIABCamxF8_ToIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndpcmVhcHA9WVRWaE9HWTFNemRrTkdNM05HVmhaamhsTWpsaE9UQTVNMk13T0RrMVlUWS8zNDVlNDAyNWVlMzQyNWUyQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dpcmUwBQYDK2VwA0EAnVyQ20ZbsPqdKlP9joxfJwLk6-HHY1kPrwRAOjsRm0fz3RRlpsCkdtjR6Z-WlM4ARAK2n52GEXG8V4w4hc0TCg"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32885/acme/wire/account/gkjIfTp9ZUm6qzDVdPCUhS2eoB4mXWjG",
    "nonce": "Mm8zN2Z1V05QMm03TVk0b1FaQ29FWjJBNGtkY3FoRW4",
    "typ": "JWT",
    "url": "https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBODCB6wIBADAxMREwDwYDVQQKDAh3aXJlLmNvbTEcMBoGC2CGSAGG+EIDAYFx
DAtBbGljZSBTbWl0aDAqMAUGAytlcAMhAKQkGAzaaeTaT+rl/TgZHgn4F4QhqVoQ
NIABCamxF8/ToIGGMIGDBgkqhkiG9w0BCQ4xdjB0MHIGA1UdEQRrMGmGUGltOndp
cmVhcHA9WVRWaE9HWTFNemRrTkdNM05HVmhaamhsTWpsaE9UQTVNMk13T0RrMVlU
WS8zNDVlNDAyNWVlMzQyNWUyQHdpcmUuY29thhVpbTp3aXJlYXBwPWFsaWNlX3dp
cmUwBQYDK2VwA0EAnVyQ20ZbsPqdKlP9joxfJwLk6+HHY1kPrwRAOjsRm0fz3RRl
psCkdtjR6Z+WlM4ARAK2n52GEXG8V4w4hc0TCg==
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
                    a4:24:18:0c:da:69:e4:da:4f:ea:e5:fd:38:19:1e:
                    09:f8:17:84:21:a9:5a:10:34:80:01:09:a9:b1:17:
                    cf:d3
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com, URI:im:wireapp=alice_wire
    Signature Algorithm: ED25519
    Signature Value:
        9d:5c:90:db:46:5b:b0:fa:9d:2a:53:fd:8e:8c:5f:27:02:e4:
        eb:e1:c7:63:59:0f:af:04:40:3a:3b:11:9b:47:f3:dd:14:65:
        a6:c0:a4:76:d8:d1:e9:9f:96:94:ce:00:44:02:b6:9f:9d:86:
        11:71:bc:57:8c:38:85:cd:13:0a

```

#### 29. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:32885/acme/wire/directory>;rel="index"
location: https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg
replay-nonce: S0NMMEVFdGVENk1aRWg0WW9oOFlyb0lzajZoTEtMMVE
```
```json
{
  "certificate": "https://stepca:32885/acme/wire/certificate/NEgEpPxAHrXqKp3SyaQW30erIEDjg9bv",
  "status": "valid",
  "finalize": "https://stepca:32885/acme/wire/order/8WH2kHmLgJV7rPh8RgrVKEO8GndcZJDg/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:32885/acme/wire/authz/AwegYhMFAzT09PbztvcVlG4owLEPkEtb"
  ],
  "expires": "2023-04-22T09:16:38Z",
  "notBefore": "2023-04-21T09:16:38.298667Z",
  "notAfter": "2023-04-21T10:16:38.298667Z"
}
```
#### 30. fetch the certificate
```http request
POST https://stepca:32885/acme/wire/certificate/NEgEpPxAHrXqKp3SyaQW30erIEDjg9bv
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjMyODg1L2FjbWUvd2lyZS9hY2NvdW50L2draklmVHA5WlVtNnF6RFZkUENVaFMyZW9CNG1YV2pHIiwidHlwIjoiSldUIiwibm9uY2UiOiJTME5NTUVWRmRHVkVOazFhUldnMFdXOW9PRmx5YjBsemFqWm9URXRNTVZFIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6MzI4ODUvYWNtZS93aXJlL2NlcnRpZmljYXRlL05FZ0VwUHhBSHJYcUtwM1N5YVFXMzBlcklFRGpnOWJ2In0",
  "payload": "",
  "signature": "9LCxpT6fJ7W1pmHU8ZAlSJklt33NJtMY33V-xbSV4nOunPK7bHoZff8cT2frfZFaoumohQ73kcAtxplk6WLCBA"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:32885/acme/wire/account/gkjIfTp9ZUm6qzDVdPCUhS2eoB4mXWjG",
    "nonce": "S0NMMEVFdGVENk1aRWg0WW9oOFlyb0lzajZoTEtMMVE",
    "typ": "JWT",
    "url": "https://stepca:32885/acme/wire/certificate/NEgEpPxAHrXqKp3SyaQW30erIEDjg9bv"
  }
}
```
#### 31. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:32885/acme/wire/directory>;rel="index"
replay-nonce: UXFBU2xVbE9QZHdYSUNuYzhuMkJ1SjlMZGRHM0FycWM
```
```json
"-----BEGIN CERTIFICATE-----\nMIICLzCCAdWgAwIBAgIRAKs0CSbaRJkV46ySwvOdHEAwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwNDIxMDkxNjM4WhcNMjMwNDIxMTAxNjM4WjApMREwDwYDVQQKEwh3aXJlLmNv\nbTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCkJBgM2mnk2k/q5f04\nGR4J+BeEIalaEDSAAQmpsRfP06OCAQYwggECMA4GA1UdDwEB/wQEAwIHgDAdBgNV\nHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFMuIc3VaitIl8xWM\nu4SI5Fr7JjAGMB8GA1UdIwQYMBaAFKDsHzSXSDqrt6ypqml2e3hBWl0JMHIGA1Ud\nEQRrMGmGUGltOndpcmVhcHA9WVRWaE9HWTFNemRrTkdNM05HVmhaamhsTWpsaE9U\nQTVNMk13T0RrMVlUWS8zNDVlNDAyNWVlMzQyNWUyQHdpcmUuY29thhVpbTp3aXJl\nYXBwPWFsaWNlX3dpcmUwHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoG\nCCqGSM49BAMCA0gAMEUCIQCb3ip4QY8lfxxO4Z9Mqg20XOUaXlRVY0OdZ1DBdehd\nvQIgQavEXR2GJ0rqiKqTy7yVsfxtrGZRd/Y5diesaWh+yQA=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuTCCAV+gAwIBAgIRAKWvezzydLgr047ozMBvxEwwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDQyMTA5\nMTYzMloXDTMzMDQxODA5MTYzMlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASc\nGEtxNh0JtZfNui9ygVzJblEe8MOclKbiVNsXfnfdZMhA4RQJHNUGqfzputye/6g8\nAaMKS/hlbFb5L/jk2qdJo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUoOwfNJdIOqu3rKmqaXZ7eEFaXQkwHwYDVR0jBBgw\nFoAUxoDiIHqkPl5JpoJmZH4obS9QFvwwCgYIKoZIzj0EAwIDSAAwRQIhALZEBaLs\ngPPNcv/dF/p/Lpk68Hexsn/swwbmCJAJgBiLAiA1uqE91v088f9+4h6/RQDwmoxz\nLkuDtLxF1WNKYWzycg==\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICLzCCAdWgAwIBAgIRAKs0CSbaRJkV46ySwvOdHEAwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwNDIxMDkxNjM4WhcNMjMwNDIxMTAxNjM4WjApMREwDwYDVQQKEwh3aXJlLmNv
bTEUMBIGA1UEAxMLQWxpY2UgU21pdGgwKjAFBgMrZXADIQCkJBgM2mnk2k/q5f04
GR4J+BeEIalaEDSAAQmpsRfP06OCAQYwggECMA4GA1UdDwEB/wQEAwIHgDAdBgNV
HSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFMuIc3VaitIl8xWM
u4SI5Fr7JjAGMB8GA1UdIwQYMBaAFKDsHzSXSDqrt6ypqml2e3hBWl0JMHIGA1Ud
EQRrMGmGUGltOndpcmVhcHA9WVRWaE9HWTFNemRrTkdNM05HVmhaamhsTWpsaE9U
QTVNMk13T0RrMVlUWS8zNDVlNDAyNWVlMzQyNWUyQHdpcmUuY29thhVpbTp3aXJl
YXBwPWFsaWNlX3dpcmUwHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2lyZQQAMAoG
CCqGSM49BAMCA0gAMEUCIQCb3ip4QY8lfxxO4Z9Mqg20XOUaXlRVY0OdZ1DBdehd
vQIgQavEXR2GJ0rqiKqTy7yVsfxtrGZRd/Y5diesaWh+yQA=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            ab:34:09:26:da:44:99:15:e3:ac:92:c2:f3:9d:1c:40
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Apr 21 09:16:38 2023 GMT
            Not After : Apr 21 10:16:38 2023 GMT
        Subject: O = wire.com, CN = Alice Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    a4:24:18:0c:da:69:e4:da:4f:ea:e5:fd:38:19:1e:
                    09:f8:17:84:21:a9:5a:10:34:80:01:09:a9:b1:17:
                    cf:d3
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                CB:88:73:75:5A:8A:D2:25:F3:15:8C:BB:84:88:E4:5A:FB:26:30:06
            X509v3 Authority Key Identifier: 
                A0:EC:1F:34:97:48:3A:AB:B7:AC:A9:AA:69:76:7B:78:41:5A:5D:09
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=YTVhOGY1MzdkNGM3NGVhZjhlMjlhOTA5M2MwODk1YTY/345e4025ee3425e2@wire.com, URI:im:wireapp=alice_wire
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:9b:de:2a:78:41:8f:25:7f:1c:4e:e1:9f:4c:
        aa:0d:b4:5c:e5:1a:5e:54:55:63:43:9d:67:50:c1:75:e8:5d:
        bd:02:20:41:ab:c4:5d:1d:86:27:4a:ea:88:aa:93:cb:bc:95:
        b1:fc:6d:ac:66:51:77:f6:39:76:27:ac:69:68:7e:c9:00

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAKWvezzydLgr047ozMBvxEwwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDQyMTA5
MTYzMloXDTMzMDQxODA5MTYzMlowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASc
GEtxNh0JtZfNui9ygVzJblEe8MOclKbiVNsXfnfdZMhA4RQJHNUGqfzputye/6g8
AaMKS/hlbFb5L/jk2qdJo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUoOwfNJdIOqu3rKmqaXZ7eEFaXQkwHwYDVR0jBBgw
FoAUxoDiIHqkPl5JpoJmZH4obS9QFvwwCgYIKoZIzj0EAwIDSAAwRQIhALZEBaLs
gPPNcv/dF/p/Lpk68Hexsn/swwbmCJAJgBiLAiA1uqE91v088f9+4h6/RQDwmoxz
LkuDtLxF1WNKYWzycg==
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            a5:af:7b:3c:f2:74:b8:2b:d3:8e:e8:cc:c0:6f:c4:4c
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Apr 21 09:16:32 2023 GMT
            Not After : Apr 18 09:16:32 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:9c:18:4b:71:36:1d:09:b5:97:cd:ba:2f:72:81:
                    5c:c9:6e:51:1e:f0:c3:9c:94:a6:e2:54:db:17:7e:
                    77:dd:64:c8:40:e1:14:09:1c:d5:06:a9:fc:e9:ba:
                    dc:9e:ff:a8:3c:01:a3:0a:4b:f8:65:6c:56:f9:2f:
                    f8:e4:da:a7:49
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                A0:EC:1F:34:97:48:3A:AB:B7:AC:A9:AA:69:76:7B:78:41:5A:5D:09
            X509v3 Authority Key Identifier: 
                C6:80:E2:20:7A:A4:3E:5E:49:A6:82:66:64:7E:28:6D:2F:50:16:FC
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:b6:44:05:a2:ec:80:f3:cd:72:ff:dd:17:fa:
        7f:2e:99:3a:f0:77:b1:b2:7f:ec:c3:06:e6:08:90:09:80:18:
        8b:02:20:35:ba:a1:3d:d6:fd:3c:f1:ff:7e:e2:1e:bf:45:00:
        f0:9a:8c:73:2e:4b:83:b4:bc:45:d5:63:4a:61:6c:f2:72

```
