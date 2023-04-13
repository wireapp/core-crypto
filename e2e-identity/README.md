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
    wire-client->>+acme-server: 🔒 POST /acme/wire/authz/SY4eBkEomijgWyWxe879HNwu04zleuBc
    acme-server->>-wire-client: 200
    wire-client->>+wire-server:  GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>wire-client: create DPoP token
    wire-client->>+wire-server:  POST /clients/5420157829857934351/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/TH9RXqaNUencfENLKsRRwppXEtEyL4Tz
    acme-server->>-wire-client: 200
    wire-client->>+wire-client: OAUTH authorization request 
    wire-client->>+IdP: OAUTH authorization request (auth code endpoint)
    wire-client->>-IdP: OAUTH authorization code
    wire-client->>-wire-client: OAUTH authorization code
    wire-client->>+IdP: OAUTH authorization code + verifier (token endpoint)
    wire-client->>-IdP: OAUTH access token
    wire-client->>+acme-server: 🔒 POST /acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/0mQZ4ACj5rwcoYMYxCiiXBAfw08Y5pYN
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: 🔒 POST /acme/wire/certificate/2BobcOVGGODd9ymXpaS0m4LUWcNamkWg
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://stepca:55035/acme/wire/directory
                        /acme/{acme-provisioner}/directory
```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://stepca:55035/acme/wire/new-nonce",
  "newAccount": "https://stepca:55035/acme/wire/new-account",
  "newOrder": "https://stepca:55035/acme/wire/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://stepca:55035/acme/wire/new-nonce
                         /acme/{acme-provisioner}/new-nonce
```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://stepca:55035/acme/wire/directory>;rel="index"
replay-nonce: VjhQbUxNRkJWeGlMZEhKT0FTRFZYNVh4am9GOGhhcTQ
```
```text
VjhQbUxNRkJWeGlMZEhKT0FTRFZYNVh4am9GOGhhcTQ
```
#### 5. create a new account
```http request
POST https://stepca:55035/acme/wire/new-account
                         /acme/{acme-provisioner}/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6IjJGS0dGOEx5QWxkaTZDZVlRSXA4d3Q2RVJDSGhiaTdkOUVNQVFPWUJnbDAifSwibm9uY2UiOiJWamhRYlV4TlJrSldlR2xNWkVoS1QwRlRSRlpZTlZoNGFtOUdPR2hoY1RRIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwMzUvYWNtZS93aXJlL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "fm6Z82m0KubHWv9VwT3ms7ctMRc7oKRyZl3OEgcu8vFAf6Of9OGslw-Y_enFn1D-CtC-QEJadvCwvKvCwkvZAQ"
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
      "x": "2FKGF8LyAldi6CeYQIp8wt6ERCHhbi7d9EMAQOYBgl0"
    },
    "nonce": "VjhQbUxNRkJWeGlMZEhKT0FTRFZYNVh4am9GOGhhcTQ",
    "typ": "JWT",
    "url": "https://stepca:55035/acme/wire/new-account"
  }
}
```
#### 6. account created
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:55035/acme/wire/directory>;rel="index"
location: https://stepca:55035/acme/wire/account/JDSgjtKVb5VNpXyGTvVLHPcbvC5ZVHka
replay-nonce: cDBsdFI3VkplTVY2bVZnblRHdE85RWVGZ2hHNGxpaVk
```
```json
{
  "status": "valid",
  "orders": "https://stepca:55035/acme/wire/account/JDSgjtKVb5VNpXyGTvVLHPcbvC5ZVHka/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://stepca:55035/acme/wire/new-order
                         /acme/{acme-provisioner}/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDM1L2FjbWUvd2lyZS9hY2NvdW50L0pEU2dqdEtWYjVWTnBYeUdUdlZMSFBjYnZDNVpWSGthIiwidHlwIjoiSldUIiwibm9uY2UiOiJjREJzZEZJM1ZrcGxUVlkyYlZabmJsUkhkRTg1UldWR1oyaEhOR3hwYVZrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwMzUvYWNtZS93aXJlL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIkJlbHRyYW0gTWFsZGFudFwiLFwiZG9tYWluXCI6XCJ3aXJlLmNvbVwiLFwiY2xpZW50LWlkXCI6XCJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbVwiLFwiaGFuZGxlXCI6XCJpbTp3aXJlYXBwPWJlbHRyYW1fd2lyZVwifSJ9XSwibm90QmVmb3JlIjoiMjAyMy0wNC0xMVQxMzo0NTo1Mi45NDk1NzJaIiwibm90QWZ0ZXIiOiIyMDIzLTA0LTExVDE0OjQ1OjUyLjk0OTU3MloifQ",
  "signature": "PT2IbwDtBViaEmpcHyvLB4sUv3eW2OrJzPDMKilO40p6Vea45rPPwxUE00cFbbArSUMYi8K0iNyv-260azfEBA"
}
```
```json
{
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com\",\"handle\":\"im:wireapp=beltram_wire\"}"
      }
    ],
    "notAfter": "2023-04-11T14:45:52.949572Z",
    "notBefore": "2023-04-11T13:45:52.949572Z"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55035/acme/wire/account/JDSgjtKVb5VNpXyGTvVLHPcbvC5ZVHka",
    "nonce": "cDBsdFI3VkplTVY2bVZnblRHdE85RWVGZ2hHNGxpaVk",
    "typ": "JWT",
    "url": "https://stepca:55035/acme/wire/new-order"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://stepca:55035/acme/wire/directory>;rel="index"
location: https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH
replay-nonce: VGpRcFFxZ2ZyTjBpTm9VdFZqSDlSc05DZ3dubVJnOEs
```
```json
{
  "status": "pending",
  "finalize": "https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com\",\"handle\":\"im:wireapp=beltram_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55035/acme/wire/authz/SY4eBkEomijgWyWxe879HNwu04zleuBc"
  ],
  "expires": "2023-04-12T13:45:52Z",
  "notBefore": "2023-04-11T13:45:52.949572Z",
  "notAfter": "2023-04-11T14:45:52.949572Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://stepca:55035/acme/wire/authz/SY4eBkEomijgWyWxe879HNwu04zleuBc
                         /acme/{acme-provisioner}/authz/{authz-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDM1L2FjbWUvd2lyZS9hY2NvdW50L0pEU2dqdEtWYjVWTnBYeUdUdlZMSFBjYnZDNVpWSGthIiwidHlwIjoiSldUIiwibm9uY2UiOiJWR3BSY0ZGeFoyWnlUakJwVG05VmRGWnFTRGxTYzA1RFozZHViVkpuT0VzIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwMzUvYWNtZS93aXJlL2F1dGh6L1NZNGVCa0VvbWlqZ1d5V3hlODc5SE53dTA0emxldUJjIn0",
  "payload": "",
  "signature": "Fkg7V7lMG1awlQurAat3_FN8QDLHKb11w2XEXQSu9Y1A4CqAyJzNErAyZrYjNY0xvftP80YQEYTh-_6XbwmkBw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55035/acme/wire/account/JDSgjtKVb5VNpXyGTvVLHPcbvC5ZVHka",
    "nonce": "VGpRcFFxZ2ZyTjBpTm9VdFZqSDlSc05DZ3dubVJnOEs",
    "typ": "JWT",
    "url": "https://stepca:55035/acme/wire/authz/SY4eBkEomijgWyWxe879HNwu04zleuBc"
  }
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55035/acme/wire/directory>;rel="index"
location: https://stepca:55035/acme/wire/authz/SY4eBkEomijgWyWxe879HNwu04zleuBc
replay-nonce: UENIcGhPeEVjMkUySFdYOFRIcWM1c2JBNG9LOHRGNGM
```
```json
{
  "status": "pending",
  "expires": "2023-04-12T13:45:52Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/0mQZ4ACj5rwcoYMYxCiiXBAfw08Y5pYN",
      "status": "pending",
      "token": "7g1wx6TTjMwVVM6xRQbXYY9ilMCAjlxo"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/TH9RXqaNUencfENLKsRRwppXEtEyL4Tz",
      "status": "pending",
      "token": "7g1wx6TTjMwVVM6xRQbXYY9ilMCAjlxo"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com\",\"handle\":\"im:wireapp=beltram_wire\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://wire.com:9090/clients/token/nonce
```
#### 12. get wire-server nonce
```http request
200

```
```text
bDVsNXBlTXA4dkJBVENKbHRSUjdJakJ0bEZTcDVtcjM
```
#### 13. create client DPoP token


<details>
<summary><b>Dpop token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMkZLR0Y4THlBbGRpNkNlWVFJcDh3dDZFUkNIaGJpN2Q5RU1BUU9ZQmdsMCJ9fQ.eyJpYXQiOjE2ODEyMjA3NTIsImV4cCI6MTY4MTIyNDM1MiwibmJmIjoxNjgxMjIwNzUyLCJzdWIiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbSIsImp0aSI6ImZiYzE2ZjYwLWZiZTgtNDRjZS05Yzg1LWNlNDczNmFmYjJkYyIsIm5vbmNlIjoiYkRWc05YQmxUWEE0ZGtKQlZFTktiSFJTVWpkSmFrSjBiRVpUY0RWdGNqTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJjaGFsIjoiN2cxd3g2VFRqTXdWVk02eFJRYlhZWTlpbE1DQWpseG8ifQ.qIBlDY4dHHs6Kz9oAomiY99nmXwDMPAEmDYZ5KHFbAoEHKAq3O_7CfuMAmoZJjBq8fQehDikte7tXJHdvRgvCQ)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9L
UCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMkZLR0Y4THlBbGRpNkNlWVFJcDh3dDZF
UkNIaGJpN2Q5RU1BUU9ZQmdsMCJ9fQ.eyJpYXQiOjE2ODEyMjA3NTIsImV4cCI6M
TY4MTIyNDM1MiwibmJmIjoxNjgxMjIwNzUyLCJzdWIiOiJpbTp3aXJlYXBwPU5HT
TVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0Z
DQzYjNiZmMwZkB3aXJlLmNvbSIsImp0aSI6ImZiYzE2ZjYwLWZiZTgtNDRjZS05Y
zg1LWNlNDczNmFmYjJkYyIsIm5vbmNlIjoiYkRWc05YQmxUWEE0ZGtKQlZFTktiS
FJTVWpkSmFrSjBiRVpUY0RWdGNqTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwO
i8vd2lyZS5jb206OTA5MC8iLCJjaGFsIjoiN2cxd3g2VFRqTXdWVk02eFJRYlhZW
TlpbE1DQWpseG8ifQ.qIBlDY4dHHs6Kz9oAomiY99nmXwDMPAEmDYZ5KHFbAoEHK
Aq3O_7CfuMAmoZJjBq8fQehDikte7tXJHdvRgvCQ
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "2FKGF8LyAldi6CeYQIp8wt6ERCHhbi7d9EMAQOYBgl0"
  },
  "typ": "dpop+jwt"
}
```

```json
{
  "chal": "7g1wx6TTjMwVVM6xRQbXYY9ilMCAjlxo",
  "exp": 1681224352,
  "htm": "POST",
  "htu": "http://wire.com:9090/",
  "iat": 1681220752,
  "jti": "fbc16f60-fbe8-44ce-9c85-ce4736afb2dc",
  "nbf": 1681220752,
  "nonce": "bDVsNXBlTXA4dkJBVENKbHRSUjdJakJ0bEZTcDVtcjM",
  "sub": "im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJUvNAyPUEXq7H2niuapOlWeBBaD+rz1lFg1kIicEvkC
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA2FKGF8LyAldi6CeYQIp8wt6ERCHhbi7d9EMAQOYBgl0=
-----END PUBLIC KEY-----
```

</details>


#### 14. trade client DPoP token for an access token
```http request
POST http://wire.com:9090/clients/5420157829857934351/access-token
                         /clients/{wire-client-id}/access-token
dpop: ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTWtaTFIwWTRUSGxCYkdScE5rTmxXVkZKY0RoM2REWkZVa05JYUdKcE4yUTVSVTFCVVU5WlFtZHNNQ0o5ZlEuZXlKcFlYUWlPakUyT0RFeU1qQTNOVElzSW1WNGNDSTZNVFk0TVRJeU5ETTFNaXdpYm1KbUlqb3hOamd4TWpJd056VXlMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVIVFRWTmVrbDVXVmRaZUU5RVp6Tk9SR3MxVFZkR2JFNXFaekZPUkUwelRXcFZlVTlIU21sT2Vra3ZOR0l6T0RRMFpEUXpZak5pWm1Nd1prQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltWmlZekUyWmpZd0xXWmlaVGd0TkRSalpTMDVZemcxTFdObE5EY3pObUZtWWpKa1l5SXNJbTV2Ym1ObElqb2lZa1JXYzA1WVFteFVXRUUwWkd0S1FsWkZUa3RpU0ZKVFZXcGtTbUZyU2pCaVJWcFVZMFJXZEdOcVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZPVEE1TUM4aUxDSmphR0ZzSWpvaU4yY3hkM2cyVkZScVRYZFdWazAyZUZKUllsaFpXVGxwYkUxRFFXcHNlRzhpZlEucUlCbERZNGRISHM2S3o5b0FvbWlZOTlubVh3RE1QQUVtRFlaNUtIRmJBb0VIS0FxM09fN0NmdU1BbW9aSmpCcThmUWVoRGlrdGU3dFhKSGR2Umd2Q1E
```
#### 15. get a Dpop access token from wire-server
```http request
200

```
```json
{
  "expires_in": 2082008461,
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Inhickt6ZEpnY1FGMXVBeDhGTXVYVE9iRmZocTd3b3ZnU3o3RmdHdnFyWDgifX0.eyJpYXQiOjE2ODEyMjA3NTIsImV4cCI6MTY4ODk5Njc1MiwibmJmIjoxNjgxMjIwNzUyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJzdWIiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbTo5MDkwLyIsImp0aSI6Ijk0NzQ5MTU4LTRjMmEtNDMwMC04ODZkLTk4NTA5OWUzNmFkMyIsIm5vbmNlIjoiYkRWc05YQmxUWEE0ZGtKQlZFTktiSFJTVWpkSmFrSjBiRVpUY0RWdGNqTSIsImNoYWwiOiI3ZzF3eDZUVGpNd1ZWTTZ4UlFiWFlZOWlsTUNBamx4byIsImNuZiI6eyJraWQiOiJseG5ZU1hLbUFCUWJWOE1UM1V2d0NTZ1UyM0lTMGFXX2prN0dvLWNlc1JBIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTWtaTFIwWTRUSGxCYkdScE5rTmxXVkZKY0RoM2REWkZVa05JYUdKcE4yUTVSVTFCVVU5WlFtZHNNQ0o5ZlEuZXlKcFlYUWlPakUyT0RFeU1qQTNOVElzSW1WNGNDSTZNVFk0TVRJeU5ETTFNaXdpYm1KbUlqb3hOamd4TWpJd056VXlMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVIVFRWTmVrbDVXVmRaZUU5RVp6Tk9SR3MxVFZkR2JFNXFaekZPUkUwelRXcFZlVTlIU21sT2Vra3ZOR0l6T0RRMFpEUXpZak5pWm1Nd1prQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltWmlZekUyWmpZd0xXWmlaVGd0TkRSalpTMDVZemcxTFdObE5EY3pObUZtWWpKa1l5SXNJbTV2Ym1ObElqb2lZa1JXYzA1WVFteFVXRUUwWkd0S1FsWkZUa3RpU0ZKVFZXcGtTbUZyU2pCaVJWcFVZMFJXZEdOcVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZPVEE1TUM4aUxDSmphR0ZzSWpvaU4yY3hkM2cyVkZScVRYZFdWazAyZUZKUllsaFpXVGxwYkUxRFFXcHNlRzhpZlEucUlCbERZNGRISHM2S3o5b0FvbWlZOTlubVh3RE1QQUVtRFlaNUtIRmJBb0VIS0FxM09fN0NmdU1BbW9aSmpCcThmUWVoRGlrdGU3dFhKSGR2Umd2Q1EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0._dWxPw8yheRu-cirHVQvdycZiazA2RwNT1hgp_26LViVdEjp87Hkyv5-9AOB23k46h3LalGZatPYTmqXLn3CDw",
  "type": "DPoP"
}
```

<details>
<summary><b>Access token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Inhickt6ZEpnY1FGMXVBeDhGTXVYVE9iRmZocTd3b3ZnU3o3RmdHdnFyWDgifX0.eyJpYXQiOjE2ODEyMjA3NTIsImV4cCI6MTY4ODk5Njc1MiwibmJmIjoxNjgxMjIwNzUyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJzdWIiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbTo5MDkwLyIsImp0aSI6Ijk0NzQ5MTU4LTRjMmEtNDMwMC04ODZkLTk4NTA5OWUzNmFkMyIsIm5vbmNlIjoiYkRWc05YQmxUWEE0ZGtKQlZFTktiSFJTVWpkSmFrSjBiRVpUY0RWdGNqTSIsImNoYWwiOiI3ZzF3eDZUVGpNd1ZWTTZ4UlFiWFlZOWlsTUNBamx4byIsImNuZiI6eyJraWQiOiJseG5ZU1hLbUFCUWJWOE1UM1V2d0NTZ1UyM0lTMGFXX2prN0dvLWNlc1JBIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTWtaTFIwWTRUSGxCYkdScE5rTmxXVkZKY0RoM2REWkZVa05JYUdKcE4yUTVSVTFCVVU5WlFtZHNNQ0o5ZlEuZXlKcFlYUWlPakUyT0RFeU1qQTNOVElzSW1WNGNDSTZNVFk0TVRJeU5ETTFNaXdpYm1KbUlqb3hOamd4TWpJd056VXlMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVIVFRWTmVrbDVXVmRaZUU5RVp6Tk9SR3MxVFZkR2JFNXFaekZPUkUwelRXcFZlVTlIU21sT2Vra3ZOR0l6T0RRMFpEUXpZak5pWm1Nd1prQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltWmlZekUyWmpZd0xXWmlaVGd0TkRSalpTMDVZemcxTFdObE5EY3pObUZtWWpKa1l5SXNJbTV2Ym1ObElqb2lZa1JXYzA1WVFteFVXRUUwWkd0S1FsWkZUa3RpU0ZKVFZXcGtTbUZyU2pCaVJWcFVZMFJXZEdOcVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZPVEE1TUM4aUxDSmphR0ZzSWpvaU4yY3hkM2cyVkZScVRYZFdWazAyZUZKUllsaFpXVGxwYkUxRFFXcHNlRzhpZlEucUlCbERZNGRISHM2S3o5b0FvbWlZOTlubVh3RE1QQUVtRFlaNUtIRmJBb0VIS0FxM09fN0NmdU1BbW9aSmpCcThmUWVoRGlrdGU3dFhKSGR2Umd2Q1EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0._dWxPw8yheRu-cirHVQvdycZiazA2RwNT1hgp_26LViVdEjp87Hkyv5-9AOB23k46h3LalGZatPYTmqXLn3CDw)

Raw:
```text
eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1Ai
LCJjcnYiOiJFZDI1NTE5IiwieCI6Inhickt6ZEpnY1FGMXVBeDhGTXVYVE9iRmZo
cTd3b3ZnU3o3RmdHdnFyWDgifX0.eyJpYXQiOjE2ODEyMjA3NTIsImV4cCI6MTY4
ODk5Njc1MiwibmJmIjoxNjgxMjIwNzUyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206
OTA5MC8iLCJzdWIiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdG
bE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbSIs
ImF1ZCI6Imh0dHA6Ly93aXJlLmNvbTo5MDkwLyIsImp0aSI6Ijk0NzQ5MTU4LTRj
MmEtNDMwMC04ODZkLTk4NTA5OWUzNmFkMyIsIm5vbmNlIjoiYkRWc05YQmxUWEE0
ZGtKQlZFTktiSFJTVWpkSmFrSjBiRVpUY0RWdGNqTSIsImNoYWwiOiI3ZzF3eDZU
VGpNd1ZWTTZ4UlFiWFlZOWlsTUNBamx4byIsImNuZiI6eyJraWQiOiJseG5ZU1hL
bUFCUWJWOE1UM1V2d0NTZ1UyM0lTMGFXX2prN0dvLWNlc1JBIn0sInByb29mIjoi
ZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRy
SWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9p
TWtaTFIwWTRUSGxCYkdScE5rTmxXVkZKY0RoM2REWkZVa05JYUdKcE4yUTVSVTFC
VVU5WlFtZHNNQ0o5ZlEuZXlKcFlYUWlPakUyT0RFeU1qQTNOVElzSW1WNGNDSTZN
VFk0TVRJeU5ETTFNaXdpYm1KbUlqb3hOamd4TWpJd056VXlMQ0p6ZFdJaU9pSnBi
VHAzYVhKbFlYQndQVTVIVFRWTmVrbDVXVmRaZUU5RVp6Tk9SR3MxVFZkR2JFNXFa
ekZPUkUwelRXcFZlVTlIU21sT2Vra3ZOR0l6T0RRMFpEUXpZak5pWm1Nd1prQjNh
WEpsTG1OdmJTSXNJbXAwYVNJNkltWmlZekUyWmpZd0xXWmlaVGd0TkRSalpTMDVZ
emcxTFdObE5EY3pObUZtWWpKa1l5SXNJbTV2Ym1ObElqb2lZa1JXYzA1WVFteFVX
RUUwWkd0S1FsWkZUa3RpU0ZKVFZXcGtTbUZyU2pCaVJWcFVZMFJXZEdOcVRTSXNJ
bWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZP
VEE1TUM4aUxDSmphR0ZzSWpvaU4yY3hkM2cyVkZScVRYZFdWazAyZUZKUllsaFpX
VGxwYkUxRFFXcHNlRzhpZlEucUlCbERZNGRISHM2S3o5b0FvbWlZOTlubVh3RE1Q
QUVtRFlaNUtIRmJBb0VIS0FxM09fN0NmdU1BbW9aSmpCcThmUWVoRGlrdGU3dFhK
SGR2Umd2Q1EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9E
ZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3
aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lk
In0._dWxPw8yheRu-cirHVQvdycZiazA2RwNT1hgp_26LViVdEjp87Hkyv5-9AOB
23k46h3LalGZatPYTmqXLn3CDw
```

Decoded:

```json
{
  "alg": "EdDSA",
  "jwk": {
    "crv": "Ed25519",
    "kty": "OKP",
    "x": "xbrKzdJgcQF1uAx8FMuXTObFfhq7wovgSz7FgGvqrX8"
  },
  "typ": "at+jwt"
}
```

```json
{
  "api_version": 3,
  "aud": "http://wire.com:9090/",
  "chal": "7g1wx6TTjMwVVM6xRQbXYY9ilMCAjlxo",
  "client_id": "im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com",
  "cnf": {
    "kid": "lxnYSXKmABQbV8MT3UvwCSgU23IS0aW_jk7Go-cesRA"
  },
  "exp": 1688996752,
  "iat": 1681220752,
  "iss": "http://wire.com:9090/",
  "jti": "94749158-4c2a-4300-886d-985099e36ad3",
  "nbf": 1681220752,
  "nonce": "bDVsNXBlTXA4dkJBVENKbHRSUjdJakJ0bEZTcDVtcjM",
  "proof": "eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMkZLR0Y4THlBbGRpNkNlWVFJcDh3dDZFUkNIaGJpN2Q5RU1BUU9ZQmdsMCJ9fQ.eyJpYXQiOjE2ODEyMjA3NTIsImV4cCI6MTY4MTIyNDM1MiwibmJmIjoxNjgxMjIwNzUyLCJzdWIiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbSIsImp0aSI6ImZiYzE2ZjYwLWZiZTgtNDRjZS05Yzg1LWNlNDczNmFmYjJkYyIsIm5vbmNlIjoiYkRWc05YQmxUWEE0ZGtKQlZFTktiSFJTVWpkSmFrSjBiRVpUY0RWdGNqTSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJjaGFsIjoiN2cxd3g2VFRqTXdWVk02eFJRYlhZWTlpbE1DQWpseG8ifQ.qIBlDY4dHHs6Kz9oAomiY99nmXwDMPAEmDYZ5KHFbAoEHKAq3O_7CfuMAmoZJjBq8fQehDikte7tXJHdvRgvCQ",
  "scope": "wire_client_id",
  "sub": "im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEINb1yGGoY23z1C03ns19F1Wt+WcE23xyhHeW46tUSvrB
-----END PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAxbrKzdJgcQF1uAx8FMuXTObFfhq7wovgSz7FgGvqrX8=
-----END PUBLIC KEY-----
```

</details>


### Client provides access token
#### 16. validate Dpop challenge (clientId)
```http request
POST https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/TH9RXqaNUencfENLKsRRwppXEtEyL4Tz
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDM1L2FjbWUvd2lyZS9hY2NvdW50L0pEU2dqdEtWYjVWTnBYeUdUdlZMSFBjYnZDNVpWSGthIiwidHlwIjoiSldUIiwibm9uY2UiOiJVRU5JY0doUGVFVmpNa1V5U0ZkWU9GUkljV00xYzJKQk5HOUxPSFJHTkdNIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwMzUvYWNtZS93aXJlL2NoYWxsZW5nZS9TWTRlQmtFb21pamdXeVd4ZTg3OUhOd3UwNHpsZXVCYy9USDlSWHFhTlVlbmNmRU5MS3NSUndwcFhFdEV5TDRUeiJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluaGlja3Q2WkVwblkxRkdNWFZCZURoR1RYVllWRTlpUm1ab2NUZDNiM1puVTNvM1JtZEhkbkZ5V0RnaWZYMC5leUpwWVhRaU9qRTJPREV5TWpBM05USXNJbVY0Y0NJNk1UWTRPRGs1TmpjMU1pd2libUptSWpveE5qZ3hNakl3TnpVeUxDSnBjM01pT2lKb2RIUndPaTh2ZDJseVpTNWpiMjA2T1RBNU1DOGlMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVIVFRWTmVrbDVXVmRaZUU5RVp6Tk9SR3MxVFZkR2JFNXFaekZPUkUwelRXcFZlVTlIU21sT2Vra3ZOR0l6T0RRMFpEUXpZak5pWm1Nd1prQjNhWEpsTG1OdmJTSXNJbUYxWkNJNkltaDBkSEE2THk5M2FYSmxMbU52YlRvNU1Ea3dMeUlzSW1wMGFTSTZJamswTnpRNU1UVTRMVFJqTW1FdE5ETXdNQzA0T0Raa0xUazROVEE1T1dVek5tRmtNeUlzSW01dmJtTmxJam9pWWtSV2MwNVlRbXhVV0VFMFpHdEtRbFpGVGt0aVNGSlRWV3BrU21GclNqQmlSVnBVWTBSV2RHTnFUU0lzSW1Ob1lXd2lPaUkzWnpGM2VEWlVWR3BOZDFaV1RUWjRVbEZpV0ZsWk9XbHNUVU5CYW14NGJ5SXNJbU51WmlJNmV5SnJhV1FpT2lKc2VHNVpVMWhMYlVGQ1VXSldPRTFVTTFWMmQwTlRaMVV5TTBsVE1HRlhYMnByTjBkdkxXTmxjMUpCSW4wc0luQnliMjltSWpvaVpYbEthR0pIWTJsUGFVcEdXa1ZTVkZGVFNYTkpibEkxWTBOSk5rbHRVbmRpTTBGeVlXNWtNRWxwZDJsaGJtUnlTV3B3TjBsdGREQmxVMGsyU1dzNVRGVkRTWE5KYlU1NVpHbEpOa2xyVm10TmFsVXhUVlJyYVV4RFNqUkphbTlwVFd0YVRGSXdXVFJVU0d4Q1lrZFNjRTVyVG14WFZrWktZMFJvTTJSRVdrWlZhMDVKWVVkS2NFNHlVVFZTVlRGQ1ZWVTVXbEZ0WkhOTlEwbzVabEV1WlhsS2NGbFlVV2xQYWtVeVQwUkZlVTFxUVROT1ZFbHpTVzFXTkdORFNUWk5WRmswVFZSSmVVNUVUVEZOYVhkcFltMUtiVWxxYjNoT2FtZDRUV3BKZDA1NlZYbE1RMHA2WkZkSmFVOXBTbkJpVkhBellWaEtiRmxZUW5kUVZUVklWRlJXVG1WcmJEVlhWbVJhWlVVNVJWcDZUazlTUjNNeFZGWmtSMkpGTlhGYWVrWlBVa1V3ZWxSWGNGWmxWVGxJVTIxc1QyVnJhM1pPUjBsNlQwUlJNRnBFVVhwWmFrNXBXbTFOZDFwclFqTmhXRXBzVEcxT2RtSlRTWE5KYlhBd1lWTkpOa2x0V21sWmVrVXlXbXBaZDB4WFdtbGFWR2QwVGtSU2FscFRNRFZaZW1jeFRGZE9iRTVFWTNwT2JVWnRXV3BLYTFsNVNYTkpiVFYyWW0xT2JFbHFiMmxaYTFKWFl6QTFXVkZ0ZUZWWFJVVXdXa2QwUzFGc1drWlVhM1JwVTBaS1ZGWlhjR3RUYlVaeVUycENhVkpXY0ZWWk1GSlhaRWRPY1ZSVFNYTkpiV2d3WWxOSk5rbHNRbEJWTVZGcFRFTktiMlJJVldsUGFVcHZaRWhTZDA5cE9IWmtNbXg1V2xNMWFtSXlNRFpQVkVFMVRVTTRhVXhEU21waFIwWnpTV3B2YVU0eVkzaGtNMmN5VmtaU2NWUllaRmRXYXpBeVpVWktVbGxzYUZwWFZHeHdZa1V4UkZGWGNITmxSemhwWmxFdWNVbENiRVJaTkdSSVNITTJTM281YjBGdmJXbFpPVGx1YlZoM1JFMVFRVVZ0UkZsYU5VdElSbUpCYjBWSVMwRnhNMDlmTjBObWRVMUJiVzlhU21wQ2NUaG1VV1ZvUkdscmRHVTNkRmhLU0dSMlVtZDJRMUVpTENKamJHbGxiblJmYVdRaU9pSnBiVHAzYVhKbFlYQndQVTVIVFRWTmVrbDVXVmRaZUU5RVp6Tk9SR3MxVFZkR2JFNXFaekZPUkUwelRXcFZlVTlIU21sT2Vra3ZOR0l6T0RRMFpEUXpZak5pWm1Nd1prQjNhWEpsTG1OdmJTSXNJbUZ3YVY5MlpYSnphVzl1SWpvekxDSnpZMjl3WlNJNkluZHBjbVZmWTJ4cFpXNTBYMmxrSW4wLl9kV3hQdzh5aGVSdS1jaXJIVlF2ZHljWmlhekEyUndOVDFoZ3BfMjZMVmlWZEVqcDg3SGt5djUtOUFPQjIzazQ2aDNMYWxHWmF0UFlUbXFYTG4zQ0R3In0",
  "signature": "Fel_KjKmPBXuyOtGUR1L55GhonNV6pPl8srfpdRb3Y-1rPcakaJ27sw4Tq64ZphV5okQsyg1jkz47k1-kuV6BA"
}
```
```json
{
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6Inhickt6ZEpnY1FGMXVBeDhGTXVYVE9iRmZocTd3b3ZnU3o3RmdHdnFyWDgifX0.eyJpYXQiOjE2ODEyMjA3NTIsImV4cCI6MTY4ODk5Njc1MiwibmJmIjoxNjgxMjIwNzUyLCJpc3MiOiJodHRwOi8vd2lyZS5jb206OTA5MC8iLCJzdWIiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly93aXJlLmNvbTo5MDkwLyIsImp0aSI6Ijk0NzQ5MTU4LTRjMmEtNDMwMC04ODZkLTk4NTA5OWUzNmFkMyIsIm5vbmNlIjoiYkRWc05YQmxUWEE0ZGtKQlZFTktiSFJTVWpkSmFrSjBiRVpUY0RWdGNqTSIsImNoYWwiOiI3ZzF3eDZUVGpNd1ZWTTZ4UlFiWFlZOWlsTUNBamx4byIsImNuZiI6eyJraWQiOiJseG5ZU1hLbUFCUWJWOE1UM1V2d0NTZ1UyM0lTMGFXX2prN0dvLWNlc1JBIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pTWtaTFIwWTRUSGxCYkdScE5rTmxXVkZKY0RoM2REWkZVa05JYUdKcE4yUTVSVTFCVVU5WlFtZHNNQ0o5ZlEuZXlKcFlYUWlPakUyT0RFeU1qQTNOVElzSW1WNGNDSTZNVFk0TVRJeU5ETTFNaXdpYm1KbUlqb3hOamd4TWpJd056VXlMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndQVTVIVFRWTmVrbDVXVmRaZUU5RVp6Tk9SR3MxVFZkR2JFNXFaekZPUkUwelRXcFZlVTlIU21sT2Vra3ZOR0l6T0RRMFpEUXpZak5pWm1Nd1prQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltWmlZekUyWmpZd0xXWmlaVGd0TkRSalpTMDVZemcxTFdObE5EY3pObUZtWWpKa1l5SXNJbTV2Ym1ObElqb2lZa1JXYzA1WVFteFVXRUUwWkd0S1FsWkZUa3RpU0ZKVFZXcGtTbUZyU2pCaVJWcFVZMFJXZEdOcVRTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZkMmx5WlM1amIyMDZPVEE1TUM4aUxDSmphR0ZzSWpvaU4yY3hkM2cyVkZScVRYZFdWazAyZUZKUllsaFpXVGxwYkUxRFFXcHNlRzhpZlEucUlCbERZNGRISHM2S3o5b0FvbWlZOTlubVh3RE1QQUVtRFlaNUtIRmJBb0VIS0FxM09fN0NmdU1BbW9aSmpCcThmUWVoRGlrdGU3dFhKSGR2Umd2Q1EiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0._dWxPw8yheRu-cirHVQvdycZiazA2RwNT1hgp_26LViVdEjp87Hkyv5-9AOB23k46h3LalGZatPYTmqXLn3CDw"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55035/acme/wire/account/JDSgjtKVb5VNpXyGTvVLHPcbvC5ZVHka",
    "nonce": "UENIcGhPeEVjMkUySFdYOFRIcWM1c2JBNG9LOHRGNGM",
    "typ": "JWT",
    "url": "https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/TH9RXqaNUencfENLKsRRwppXEtEyL4Tz"
  }
}
```
#### 17. DPoP challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55035/acme/wire/directory>;rel="index"
link: <https://stepca:55035/acme/wire/authz/SY4eBkEomijgWyWxe879HNwu04zleuBc>;rel="up"
location: https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/TH9RXqaNUencfENLKsRRwppXEtEyL4Tz
replay-nonce: ZzVlSWl4T2djQlgwS2tnZDNJakM5QTJlRHMzUkhSWXg
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/TH9RXqaNUencfENLKsRRwppXEtEyL4Tz",
  "status": "valid",
  "token": "7g1wx6TTjMwVVM6xRQbXYY9ilMCAjlxo"
}
```
#### 18. validate oidc challenge (userId + displayName)

<details>
<summary><b>Id token</b></summary>

See it on [jwt.io](https://jwt.io/#id_token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImFjZGEzNjBmYjM2Y2QxNWZmODNhZjgzZTE3M2Y0N2ZmYzM2ZDExMWMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI5NjcyNjk4OTk2NDc4NTY2MzgiLCJoZCI6IndpcmUuY29tIiwiZW1haWwiOiJiZWx0cmFtLm1hbGRhbnRAd2lyZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6Il9iTjZqWXVab0tVaDZFUGZ4UENwalEiLCJub25jZSI6Ik15S0VCeHBabXZiczdBcC1DOUxwSGciLCJuYW1lIjoiQmVsdHJhbSBNYWxkYW50IiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eGJsZmNWc3REOGRMVElSdUViSXUwU1Q2eElFTHk2Qkp3ZTNfTTNlPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkJlbHRyYW0iLCJmYW1pbHlfbmFtZSI6Ik1hbGRhbnQiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY4MTIyMDc1NiwiZXhwIjoxNjgxMjI0MzU2fQ.bGR_A0nhMyq5ELuDqiRCdRVMsZQw-hiujs9YAEz2QTOuwF9VYEV0n23nzJebaID9sPkwpKLJ8gsOGrK35xQNQaD1fGR_KSJOcNcD05Ye_WxDdZmtPfS_770ok5a7vnWllBNtvCJlPTODXZmwpfFfx_abCvpee9P0WaLbYn2tbWwXjcrvpS-HheqYucjenyG9f5eAtQiBAIT4OfwpyHQRIBb-NSpPSUMgW64yGycdwKzWuqxgv3mwY9pHaYxYUTezYXPVXdzU0pOOwzEUSdjU-6jQshW1jD5z6p2Erxxc6J5iO16MLZ3wsqLaC2QcJc7OziKu4Bk_MNrInQQivMTlLg)

Raw:
```text
eyJhbGciOiJSUzI1NiIsImtpZCI6ImFjZGEzNjBmYjM2Y2QxNWZmODNhZjgzZTE3
M2Y0N2ZmYzM2ZDExMWMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY
291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzb
XIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb
20iLCJhdWQiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpb
WVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI5N
jcyNjk4OTk2NDc4NTY2MzgiLCJoZCI6IndpcmUuY29tIiwiZW1haWwiOiJiZWx0c
mFtLm1hbGRhbnRAd2lyZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfa
GFzaCI6Il9iTjZqWXVab0tVaDZFUGZ4UENwalEiLCJub25jZSI6Ik15S0VCeHBab
XZiczdBcC1DOUxwSGciLCJuYW1lIjoiQmVsdHJhbSBNYWxkYW50IiwicGljdHVyZ
SI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eGJsZ
mNWc3REOGRMVElSdUViSXUwU1Q2eElFTHk2Qkp3ZTNfTTNlPXM5Ni1jIiwiZ2l2Z
W5fbmFtZSI6IkJlbHRyYW0iLCJmYW1pbHlfbmFtZSI6Ik1hbGRhbnQiLCJsb2Nhb
GUiOiJlbiIsImlhdCI6MTY4MTIyMDc1NiwiZXhwIjoxNjgxMjI0MzU2fQ.bGR_A0
nhMyq5ELuDqiRCdRVMsZQw-hiujs9YAEz2QTOuwF9VYEV0n23nzJebaID9sPkwpK
LJ8gsOGrK35xQNQaD1fGR_KSJOcNcD05Ye_WxDdZmtPfS_770ok5a7vnWllBNtvC
JlPTODXZmwpfFfx_abCvpee9P0WaLbYn2tbWwXjcrvpS-HheqYucjenyG9f5eAtQ
iBAIT4OfwpyHQRIBb-NSpPSUMgW64yGycdwKzWuqxgv3mwY9pHaYxYUTezYXPVXd
zU0pOOwzEUSdjU-6jQshW1jD5z6p2Erxxc6J5iO16MLZ3wsqLaC2QcJc7OziKu4B
k_MNrInQQivMTlLg
```

Decoded:

```json
{
  "alg": "RS256",
  "kid": "acda360fb36cd15ff83af83e173f47ffc36d111c",
  "typ": "JWT"
}
```

```json
{
  "at_hash": "_bN6jYuZoKUh6EPfxPCpjQ",
  "aud": "338888153072-ktbh66pv3mr0ua0dn64sphgimeo0p7ss.apps.googleusercontent.com",
  "azp": "338888153072-ktbh66pv3mr0ua0dn64sphgimeo0p7ss.apps.googleusercontent.com",
  "email": "beltram.maldant@wire.com",
  "email_verified": true,
  "exp": 1681224356,
  "family_name": "Maldant",
  "given_name": "Beltram",
  "hd": "wire.com",
  "iat": 1681220756,
  "iss": "https://accounts.google.com",
  "locale": "en",
  "name": "Beltram Maldant",
  "nonce": "MyKEBxpZmvbs7Ap-C9LpHg",
  "picture": "https://lh3.googleusercontent.com/a/AGNmyxblfcVstD8dLTIRuEbIu0ST6xIELy6BJwe3_M3e=s96-c",
  "sub": "112967269899647856638"
}
```


✅ Signature Verified with key:
```text
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr54td3hTv87IwUNhdc+b
YLIny4tBVcasvdSd7lbJILg58C4DJ0RJPczXd/rlfzzYGvgpt3Okf/anJd5aah19
6P3bqwVDdelcDYAhuajBzn40QjOBPefvdD5zSo18i7OtG7nhAhRSEGe6Pjzpck3w
AogqYcDgkF1BzTsRB+DkxprsYhp5pmL5RnX+6EYP5t2m9jJ+/oP9v1yvZkT5UPb2
IwOk5GDllRPbvp+aJW/RM18ITU3qIbkwSTs1gJGFWO7jwnxT0QBaFD8a8aev1tmR
50ehK+Sz2ORtvuWBxbzTqXXL39qgNJaYwZyW+2040vvuZnaGribcxT83t3cJlQdM
xwIDAQAB
-----END PUBLIC KEY-----
```

</details>


Note: The ACME provisioner is configured with rules for transforming values received in the token into a Wire handle and display name.
```http request
POST https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/0mQZ4ACj5rwcoYMYxCiiXBAfw08Y5pYN
                         /acme/{acme-provisioner}/challenge/{authz-id}/{challenge-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDM1L2FjbWUvd2lyZS9hY2NvdW50L0pEU2dqdEtWYjVWTnBYeUdUdlZMSFBjYnZDNVpWSGthIiwidHlwIjoiSldUIiwibm9uY2UiOiJaelZsU1dsNFQyZGpRbGd3UzJ0blpETkpha001UVRKbFJITXpVa2hTV1hnIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwMzUvYWNtZS93aXJlL2NoYWxsZW5nZS9TWTRlQmtFb21pamdXeVd4ZTg3OUhOd3UwNHpsZXVCYy8wbVFaNEFDajVyd2NvWU1ZeENpaVhCQWZ3MDhZNXBZTiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJbUZqWkdFek5qQm1Zak0yWTJReE5XWm1PRE5oWmpnelpURTNNMlkwTjJabVl6TTJaREV4TVdNaUxDSjBlWEFpT2lKS1YxUWlmUS5leUpwYzNNaU9pSm9kSFJ3Y3pvdkwyRmpZMjkxYm5SekxtZHZiMmRzWlM1amIyMGlMQ0poZW5BaU9pSXpNemc0T0RneE5UTXdOekl0YTNSaWFEWTJjSFl6YlhJd2RXRXdaRzQyTkhOd2FHZHBiV1Z2TUhBM2MzTXVZWEJ3Y3k1bmIyOW5iR1YxYzJWeVkyOXVkR1Z1ZEM1amIyMGlMQ0poZFdRaU9pSXpNemc0T0RneE5UTXdOekl0YTNSaWFEWTJjSFl6YlhJd2RXRXdaRzQyTkhOd2FHZHBiV1Z2TUhBM2MzTXVZWEJ3Y3k1bmIyOW5iR1YxYzJWeVkyOXVkR1Z1ZEM1amIyMGlMQ0p6ZFdJaU9pSXhNVEk1TmpjeU5qazRPVGsyTkRjNE5UWTJNemdpTENKb1pDSTZJbmRwY21VdVkyOXRJaXdpWlcxaGFXd2lPaUppWld4MGNtRnRMbTFoYkdSaGJuUkFkMmx5WlM1amIyMGlMQ0psYldGcGJGOTJaWEpwWm1sbFpDSTZkSEoxWlN3aVlYUmZhR0Z6YUNJNklsOWlUalpxV1hWYWIwdFZhRFpGVUdaNFVFTndhbEVpTENKdWIyNWpaU0k2SWsxNVMwVkNlSEJhYlhaaWN6ZEJjQzFET1V4d1NHY2lMQ0p1WVcxbElqb2lRbVZzZEhKaGJTQk5ZV3hrWVc1MElpd2ljR2xqZEhWeVpTSTZJbWgwZEhCek9pOHZiR2d6TG1kdmIyZHNaWFZ6WlhKamIyNTBaVzUwTG1OdmJTOWhMMEZIVG0xNWVHSnNabU5XYzNSRU9HUk1WRWxTZFVWaVNYVXdVMVEyZUVsRlRIazJRa3AzWlROZlRUTmxQWE01Tmkxaklpd2laMmwyWlc1ZmJtRnRaU0k2SWtKbGJIUnlZVzBpTENKbVlXMXBiSGxmYm1GdFpTSTZJazFoYkdSaGJuUWlMQ0pzYjJOaGJHVWlPaUpsYmlJc0ltbGhkQ0k2TVRZNE1USXlNRGMxTml3aVpYaHdJam94TmpneE1qSTBNelUyZlEuYkdSX0EwbmhNeXE1RUx1RHFpUkNkUlZNc1pRdy1oaXVqczlZQUV6MlFUT3V3RjlWWUVWMG4yM256SmViYUlEOXNQa3dwS0xKOGdzT0dySzM1eFFOUWFEMWZHUl9LU0pPY05jRDA1WWVfV3hEZFptdFBmU183NzBvazVhN3ZuV2xsQk50dkNKbFBUT0RYWm13cGZGZnhfYWJDdnBlZTlQMFdhTGJZbjJ0Yld3WGpjcnZwUy1IaGVxWXVjamVueUc5ZjVlQXRRaUJBSVQ0T2Z3cHlIUVJJQmItTlNwUFNVTWdXNjR5R3ljZHdLeld1cXhndjNtd1k5cEhhWXhZVVRlellYUFZYZHpVMHBPT3d6RVVTZGpVLTZqUXNoVzFqRDV6NnAyRXJ4eGM2SjVpTzE2TUxaM3dzcUxhQzJRY0pjN096aUt1NEJrX01OckluUVFpdk1UbExnIiwia2V5YXV0aCI6IjdnMXd4NlRUak13VlZNNnhSUWJYWVk5aWxNQ0FqbHhvLloya1AyOTAxaXlhYVpTNkRtcV8yaWd0TDROei1feHR5djBDSXI1bGtmWUUifQ",
  "signature": "nEAAxNa0YPAfyvJliuPhiyo-RPAInhS7KjxI2e8So5Wi_v7izMpOTY20WN85ORYfn18lTTBhQdPOICxWDfObAg"
}
```
```json
{
  "payload": {
    "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImFjZGEzNjBmYjM2Y2QxNWZmODNhZjgzZTE3M2Y0N2ZmYzM2ZDExMWMiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIzMzg4ODgxNTMwNzIta3RiaDY2cHYzbXIwdWEwZG42NHNwaGdpbWVvMHA3c3MuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMTI5NjcyNjk4OTk2NDc4NTY2MzgiLCJoZCI6IndpcmUuY29tIiwiZW1haWwiOiJiZWx0cmFtLm1hbGRhbnRAd2lyZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXRfaGFzaCI6Il9iTjZqWXVab0tVaDZFUGZ4UENwalEiLCJub25jZSI6Ik15S0VCeHBabXZiczdBcC1DOUxwSGciLCJuYW1lIjoiQmVsdHJhbSBNYWxkYW50IiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hL0FHTm15eGJsZmNWc3REOGRMVElSdUViSXUwU1Q2eElFTHk2Qkp3ZTNfTTNlPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IkJlbHRyYW0iLCJmYW1pbHlfbmFtZSI6Ik1hbGRhbnQiLCJsb2NhbGUiOiJlbiIsImlhdCI6MTY4MTIyMDc1NiwiZXhwIjoxNjgxMjI0MzU2fQ.bGR_A0nhMyq5ELuDqiRCdRVMsZQw-hiujs9YAEz2QTOuwF9VYEV0n23nzJebaID9sPkwpKLJ8gsOGrK35xQNQaD1fGR_KSJOcNcD05Ye_WxDdZmtPfS_770ok5a7vnWllBNtvCJlPTODXZmwpfFfx_abCvpee9P0WaLbYn2tbWwXjcrvpS-HheqYucjenyG9f5eAtQiBAIT4OfwpyHQRIBb-NSpPSUMgW64yGycdwKzWuqxgv3mwY9pHaYxYUTezYXPVXdzU0pOOwzEUSdjU-6jQshW1jD5z6p2Erxxc6J5iO16MLZ3wsqLaC2QcJc7OziKu4Bk_MNrInQQivMTlLg",
    "keyauth": "7g1wx6TTjMwVVM6xRQbXYY9ilMCAjlxo.Z2kP2901iyaaZS6Dmq_2igtL4Nz-_xtyv0CIr5lkfYE"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55035/acme/wire/account/JDSgjtKVb5VNpXyGTvVLHPcbvC5ZVHka",
    "nonce": "ZzVlSWl4T2djQlgwS2tnZDNJakM5QTJlRHMzUkhSWXg",
    "typ": "JWT",
    "url": "https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/0mQZ4ACj5rwcoYMYxCiiXBAfw08Y5pYN"
  }
}
```
#### 19. OIDC challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55035/acme/wire/directory>;rel="index"
link: <https://stepca:55035/acme/wire/authz/SY4eBkEomijgWyWxe879HNwu04zleuBc>;rel="up"
location: https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/0mQZ4ACj5rwcoYMYxCiiXBAfw08Y5pYN
replay-nonce: RktGVXFMUnZ0Qm5HUnIxTjhRT0Q5QTVHajhtWW1FYlk
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://stepca:55035/acme/wire/challenge/SY4eBkEomijgWyWxe879HNwu04zleuBc/0mQZ4ACj5rwcoYMYxCiiXBAfw08Y5pYN",
  "status": "valid",
  "token": "7g1wx6TTjMwVVM6xRQbXYY9ilMCAjlxo"
}
```
### Client presents a CSR and gets its certificate
#### 20. verify the status of the order
```http request
POST https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH
                         /acme/{acme-provisioner}/order/{order-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDM1L2FjbWUvd2lyZS9hY2NvdW50L0pEU2dqdEtWYjVWTnBYeUdUdlZMSFBjYnZDNVpWSGthIiwidHlwIjoiSldUIiwibm9uY2UiOiJSa3RHVlhGTVVuWjBRbTVIVW5JeFRqaFJUMFE1UVRWSGFqaHRXVzFGWWxrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwMzUvYWNtZS93aXJlL29yZGVyL0ROb1dGSmtWNm9NOWlNMlZ2WWpURjBTR1c1S0lTb21IIn0",
  "payload": "",
  "signature": "A9T2QK566e6uoymVL1cBhS9UlM8rAAFW7K201h7LFoE23z4Kpb2RBA0UK37NmpJBCb2iFut2szbOmV6d5gylBw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55035/acme/wire/account/JDSgjtKVb5VNpXyGTvVLHPcbvC5ZVHka",
    "nonce": "RktGVXFMUnZ0Qm5HUnIxTjhRT0Q5QTVHajhtWW1FYlk",
    "typ": "JWT",
    "url": "https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH"
  }
}
```
#### 21. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55035/acme/wire/directory>;rel="index"
location: https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH
replay-nonce: NlFTRTRESEl4bzUwOFRHREFxRFJrbE9aZG1aOHlSOXI
```
```json
{
  "status": "ready",
  "finalize": "https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com\",\"handle\":\"im:wireapp=beltram_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55035/acme/wire/authz/SY4eBkEomijgWyWxe879HNwu04zleuBc"
  ],
  "expires": "2023-04-12T13:45:52Z",
  "notBefore": "2023-04-11T13:45:52.949572Z",
  "notAfter": "2023-04-11T14:45:52.949572Z"
}
```
#### 22. create a CSR and call finalize url
```http request
POST https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH/finalize
                         /acme/{acme-provisioner}/order/{order-id}/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDM1L2FjbWUvd2lyZS9hY2NvdW50L0pEU2dqdEtWYjVWTnBYeUdUdlZMSFBjYnZDNVpWSGthIiwidHlwIjoiSldUIiwibm9uY2UiOiJObEZUUlRSRVNFbDRielV3T0ZSSFJFRnhSRkpyYkU5YVpHMWFPSGxTT1hJIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwMzUvYWNtZS93aXJlL29yZGVyL0ROb1dGSmtWNm9NOWlNMlZ2WWpURjBTR1c1S0lTb21IL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCUGpDQjhRSUJBREExTVJFd0R3WURWUVFLREFoM2FYSmxMbU52YlRFZ01CNEdDMkNHU0FHRy1FSURBWUZ4REE5Q1pXeDBjbUZ0SUUxaGJHUmhiblF3S2pBRkJnTXJaWEFESVFEWVVvWVh3dklDVjJMb0o1aEFpbnpDM29SRUllRnVMdDMwUXdCQTVnR0NYYUNCaURDQmhRWUpLb1pJaHZjTkFRa09NWGd3ZGpCMEJnTlZIUkVFYlRCcmhsQnBiVHAzYVhKbFlYQndQVTVIVFRWTmVrbDVXVmRaZUU5RVp6Tk9SR3MxVFZkR2JFNXFaekZPUkUwelRXcFZlVTlIU21sT2Vra3ZOR0l6T0RRMFpEUXpZak5pWm1Nd1prQjNhWEpsTG1OdmJZWVhhVzA2ZDJseVpXRndjRDFpWld4MGNtRnRYM2RwY21Vd0JRWURLMlZ3QTBFQWE5WEozRkFHRWt2SU5xQldNZ2RNUXg2Q0NkSFRBdWJaUmZZX1VWbDNuX0pqM3hXU19qYXNlMzJwSnAtT3ZOM1JWOFI0enVYWnFUSHFSdGx2b01wQURBIn0",
  "signature": "x6U87jf4JjVwlvA7UjpB_i1IT60-behqqzQJ_7RE-xS-OQ_S_NuKrveGVBBnnO-8CCIz8tVgcjwfPvxZdT7SCw"
}
```
```json
{
  "payload": {
    "csr": "MIIBPjCB8QIBADA1MREwDwYDVQQKDAh3aXJlLmNvbTEgMB4GC2CGSAGG-EIDAYFxDA9CZWx0cmFtIE1hbGRhbnQwKjAFBgMrZXADIQDYUoYXwvICV2LoJ5hAinzC3oREIeFuLt30QwBA5gGCXaCBiDCBhQYJKoZIhvcNAQkOMXgwdjB0BgNVHREEbTBrhlBpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbYYXaW06d2lyZWFwcD1iZWx0cmFtX3dpcmUwBQYDK2VwA0EAa9XJ3FAGEkvINqBWMgdMQx6CCdHTAubZRfY_UVl3n_Jj3xWS_jase32pJp-OvN3RV8R4zuXZqTHqRtlvoMpADA"
  },
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55035/acme/wire/account/JDSgjtKVb5VNpXyGTvVLHPcbvC5ZVHka",
    "nonce": "NlFTRTRESEl4bzUwOFRHREFxRFJrbE9aZG1aOHlSOXI",
    "typ": "JWT",
    "url": "https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH/finalize"
  }
}
```
###### CSR: 
openssl -verify ✅
```
-----BEGIN CERTIFICATE REQUEST-----
MIIBPjCB8QIBADA1MREwDwYDVQQKDAh3aXJlLmNvbTEgMB4GC2CGSAGG+EIDAYFx
DA9CZWx0cmFtIE1hbGRhbnQwKjAFBgMrZXADIQDYUoYXwvICV2LoJ5hAinzC3oRE
IeFuLt30QwBA5gGCXaCBiDCBhQYJKoZIhvcNAQkOMXgwdjB0BgNVHREEbTBrhlBp
bTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5qZzFORE0zTWpVeU9H
SmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbYYXaW06d2lyZWFwcD1iZWx0
cmFtX3dpcmUwBQYDK2VwA0EAa9XJ3FAGEkvINqBWMgdMQx6CCdHTAubZRfY/UVl3
n/Jj3xWS/jase32pJp+OvN3RV8R4zuXZqTHqRtlvoMpADA==
-----END CERTIFICATE REQUEST-----

```
```
Certificate Request:
    Data:
        Version: 1 (0x0)
        Subject: O = wire.com, 2.16.840.1.113730.3.1.241 = Beltram Maldant
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    d8:52:86:17:c2:f2:02:57:62:e8:27:98:40:8a:7c:
                    c2:de:84:44:21:e1:6e:2e:dd:f4:43:00:40:e6:01:
                    82:5d
        Attributes:
            Requested Extensions:
                X509v3 Subject Alternative Name: 
                    URI:im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com, URI:im:wireapp=beltram_wire
    Signature Algorithm: ED25519
    Signature Value:
        6b:d5:c9:dc:50:06:12:4b:c8:36:a0:56:32:07:4c:43:1e:82:
        09:d1:d3:02:e6:d9:45:f6:3f:51:59:77:9f:f2:63:df:15:92:
        fe:36:ac:7b:7d:a9:26:9f:8e:bc:dd:d1:57:c4:78:ce:e5:d9:
        a9:31:ea:46:d9:6f:a0:ca:40:0c

```

#### 23. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://stepca:55035/acme/wire/directory>;rel="index"
location: https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH
replay-nonce: VmJXU3dlZTd1dEhxRmJ3YlA0alBISmw2NHdMdXB1TGk
```
```json
{
  "certificate": "https://stepca:55035/acme/wire/certificate/2BobcOVGGODd9ymXpaS0m4LUWcNamkWg",
  "status": "valid",
  "finalize": "https://stepca:55035/acme/wire/order/DNoWFJkV6oM9iM2VvYjTF0SGW5KISomH/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Beltram Maldant\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com\",\"handle\":\"im:wireapp=beltram_wire\"}"
    }
  ],
  "authorizations": [
    "https://stepca:55035/acme/wire/authz/SY4eBkEomijgWyWxe879HNwu04zleuBc"
  ],
  "expires": "2023-04-12T13:45:52Z",
  "notBefore": "2023-04-11T13:45:52.949572Z",
  "notAfter": "2023-04-11T14:45:52.949572Z"
}
```
#### 24. fetch the certificate
```http request
POST https://stepca:55035/acme/wire/certificate/2BobcOVGGODd9ymXpaS0m4LUWcNamkWg
                         /acme/{acme-provisioner}/certificate/{certificate-id}
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vc3RlcGNhOjU1MDM1L2FjbWUvd2lyZS9hY2NvdW50L0pEU2dqdEtWYjVWTnBYeUdUdlZMSFBjYnZDNVpWSGthIiwidHlwIjoiSldUIiwibm9uY2UiOiJWbUpYVTNkbFpUZDFkRWh4Um1KM1lsQTBhbEJJU213Mk5IZE1kWEIxVEdrIiwidXJsIjoiaHR0cHM6Ly9zdGVwY2E6NTUwMzUvYWNtZS93aXJlL2NlcnRpZmljYXRlLzJCb2JjT1ZHR09EZDl5bVhwYVMwbTRMVVdjTmFta1dnIn0",
  "payload": "",
  "signature": "poIXRdn6dxDZDxXHHRy481IrJJ5TwOlmGYre2mOqMJcRYbp0d9qgRqEuzhqjRgnXzkEpxWCC9siwuCwF0Wg-Cw"
}
```
```json
{
  "payload": {},
  "protected": {
    "alg": "EdDSA",
    "kid": "https://stepca:55035/acme/wire/account/JDSgjtKVb5VNpXyGTvVLHPcbvC5ZVHka",
    "nonce": "VmJXU3dlZTd1dEhxRmJ3YlA0alBISmw2NHdMdXB1TGk",
    "typ": "JWT",
    "url": "https://stepca:55035/acme/wire/certificate/2BobcOVGGODd9ymXpaS0m4LUWcNamkWg"
  }
}
```
#### 25. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://stepca:55035/acme/wire/directory>;rel="index"
replay-nonce: ZHZjOGtVenc4TUVsTmthVmRLcng0b1B3ZlB4dnRRUmY
```
```json
"-----BEGIN CERTIFICATE-----\nMIICNTCCAdugAwIBAgIRAMy4ZaNHTaapw9J45ii2R/kwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwNDExMTM0NTUyWhcNMjMwNDExMTQ0NTUyWjAtMREwDwYDVQQKEwh3aXJlLmNv\nbTEYMBYGA1UEAxMPQmVsdHJhbSBNYWxkYW50MCowBQYDK2VwAyEA2FKGF8LyAldi\n6CeYQIp8wt6ERCHhbi7d9EMAQOYBgl2jggEIMIIBBDAOBgNVHQ8BAf8EBAMCB4Aw\nHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBRFiKVc23Ni\nlnhbJqzJa5aTiFEmdzAfBgNVHSMEGDAWgBRUxzYQ9TQjxyZmWoHsVgdOZLsNATB0\nBgNVHREEbTBrhlBpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5q\nZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbYYXaW06\nd2lyZWFwcD1iZWx0cmFtX3dpcmUwHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2ly\nZQQAMAoGCCqGSM49BAMCA0gAMEUCIFu3baFdSEZQvT0EdsRfWEtvQuonjHrhDEHF\nDDWAJMKvAiEA6BBCOT77I6hmldLkoZGADbO3pCIxMxnxlM8FNRd21Ao=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIBuDCCAV6gAwIBAgIQIFm7Lwi3jSKc2CU6IDAk6TAKBggqhkjOPQQDAjAmMQ0w\nCwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNDExMTM0\nNTUwWhcNMzMwNDA4MTM0NTUwWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\naXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIF2\ng2Tf7txi3KjAR20Zzi5VzevdFAKZhWqzYoG9da8PL2zM0hfBhT30e8ZDjmjpTXIx\nrapj0iZ6yZUBSZgv7UyjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\nAQH/AgEAMB0GA1UdDgQWBBRUxzYQ9TQjxyZmWoHsVgdOZLsNATAfBgNVHSMEGDAW\ngBQXHRk8jpVDYyBnNslv0xRYFcD4JzAKBggqhkjOPQQDAgNIADBFAiBoHWKNXo7c\nSyCP6+vnmhUDKYllDYGQiKuwDT/y798uUgIhAL2E9zUTknLOj2c9a6Q4heFbWpT1\nFqweztaosbkLcwyT\n-----END CERTIFICATE-----\n"
```
###### Certificate #1
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIICNTCCAdugAwIBAgIRAMy4ZaNHTaapw9J45ii2R/kwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwNDExMTM0NTUyWhcNMjMwNDExMTQ0NTUyWjAtMREwDwYDVQQKEwh3aXJlLmNv
bTEYMBYGA1UEAxMPQmVsdHJhbSBNYWxkYW50MCowBQYDK2VwAyEA2FKGF8LyAldi
6CeYQIp8wt6ERCHhbi7d9EMAQOYBgl2jggEIMIIBBDAOBgNVHQ8BAf8EBAMCB4Aw
HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBRFiKVc23Ni
lnhbJqzJa5aTiFEmdzAfBgNVHSMEGDAWgBRUxzYQ9TQjxyZmWoHsVgdOZLsNATB0
BgNVHREEbTBrhlBpbTp3aXJlYXBwPU5HTTVNekl5WVdZeE9EZzNORGs1TVdGbE5q
ZzFORE0zTWpVeU9HSmlOekkvNGIzODQ0ZDQzYjNiZmMwZkB3aXJlLmNvbYYXaW06
d2lyZWFwcD1iZWx0cmFtX3dpcmUwHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQEd2ly
ZQQAMAoGCCqGSM49BAMCA0gAMEUCIFu3baFdSEZQvT0EdsRfWEtvQuonjHrhDEHF
DDWAJMKvAiEA6BBCOT77I6hmldLkoZGADbO3pCIxMxnxlM8FNRd21Ao=
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            cc:b8:65:a3:47:4d:a6:a9:c3:d2:78:e6:28:b6:47:f9
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Intermediate CA
        Validity
            Not Before: Apr 11 13:45:52 2023 GMT
            Not After : Apr 11 14:45:52 2023 GMT
        Subject: O = wire.com, CN = Beltram Maldant
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    d8:52:86:17:c2:f2:02:57:62:e8:27:98:40:8a:7c:
                    c2:de:84:44:21:e1:6e:2e:dd:f4:43:00:40:e6:01:
                    82:5d
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            X509v3 Subject Key Identifier: 
                45:88:A5:5C:DB:73:62:96:78:5B:26:AC:C9:6B:96:93:88:51:26:77
            X509v3 Authority Key Identifier: 
                54:C7:36:10:F5:34:23:C7:26:66:5A:81:EC:56:07:4E:64:BB:0D:01
            X509v3 Subject Alternative Name: 
                URI:im:wireapp=NGM5MzIyYWYxODg3NDk5MWFlNjg1NDM3MjUyOGJiNzI/4b3844d43b3bfc0f@wire.com, URI:im:wireapp=beltram_wire
            1.3.6.1.4.1.37476.9000.64.1: 
                0......wire..
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:5b:b7:6d:a1:5d:48:46:50:bd:3d:04:76:c4:5f:
        58:4b:6f:42:ea:27:8c:7a:e1:0c:41:c5:0c:35:80:24:c2:af:
        02:21:00:e8:10:42:39:3e:fb:23:a8:66:95:d2:e4:a1:91:80:
        0d:b3:b7:a4:22:31:33:19:f1:94:cf:05:35:17:76:d4:0a

```

###### Certificate #2
openssl -verify ✅
```
-----BEGIN CERTIFICATE-----
MIIBuDCCAV6gAwIBAgIQIFm7Lwi3jSKc2CU6IDAk6TAKBggqhkjOPQQDAjAmMQ0w
CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwNDExMTM0
NTUwWhcNMzMwNDA4MTM0NTUwWjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3
aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIF2
g2Tf7txi3KjAR20Zzi5VzevdFAKZhWqzYoG9da8PL2zM0hfBhT30e8ZDjmjpTXIx
rapj0iZ6yZUBSZgv7UyjZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
AQH/AgEAMB0GA1UdDgQWBBRUxzYQ9TQjxyZmWoHsVgdOZLsNATAfBgNVHSMEGDAW
gBQXHRk8jpVDYyBnNslv0xRYFcD4JzAKBggqhkjOPQQDAgNIADBFAiBoHWKNXo7c
SyCP6+vnmhUDKYllDYGQiKuwDT/y798uUgIhAL2E9zUTknLOj2c9a6Q4heFbWpT1
FqweztaosbkLcwyT
-----END CERTIFICATE-----

```
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            20:59:bb:2f:08:b7:8d:22:9c:d8:25:3a:20:30:24:e9
        Signature Algorithm: ecdsa-with-SHA256
        Issuer: O = wire, CN = wire Root CA
        Validity
            Not Before: Apr 11 13:45:50 2023 GMT
            Not After : Apr  8 13:45:50 2033 GMT
        Subject: O = wire, CN = wire Intermediate CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:81:76:83:64:df:ee:dc:62:dc:a8:c0:47:6d:19:
                    ce:2e:55:cd:eb:dd:14:02:99:85:6a:b3:62:81:bd:
                    75:af:0f:2f:6c:cc:d2:17:c1:85:3d:f4:7b:c6:43:
                    8e:68:e9:4d:72:31:ad:aa:63:d2:26:7a:c9:95:01:
                    49:98:2f:ed:4c
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Certificate Sign, CRL Sign
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Subject Key Identifier: 
                54:C7:36:10:F5:34:23:C7:26:66:5A:81:EC:56:07:4E:64:BB:0D:01
            X509v3 Authority Key Identifier: 
                17:1D:19:3C:8E:95:43:63:20:67:36:C9:6F:D3:14:58:15:C0:F8:27
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:20:68:1d:62:8d:5e:8e:dc:4b:20:8f:eb:eb:e7:9a:
        15:03:29:89:65:0d:81:90:88:ab:b0:0d:3f:f2:ef:df:2e:52:
        02:21:00:bd:84:f7:35:13:92:72:ce:8f:67:3d:6b:a4:38:85:
        e1:5b:5a:94:f5:16:ac:1e:ce:d6:a8:b1:b9:0b:73:0c:93

```
