# Wire end to end identity example
Ed25519 - SHA256
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/wire-acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/wire-acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/authz/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/authz/1mx9BBDXlDqo8YGdofNGVephPtiXoZll
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST /clients/9695841546515832898/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/challenge/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf/Djz71pioa2ai6TZoK8qQRjKBFL00ck9u
    acme-server->>+wire-server: GET /.well-known/acme-challenge/J2iDTJbNltlxtngrQbROygRvkR39O93e
    wire-server->>-acme-server: 200
    acme-server->>+wire-server: GET /.well-known/acme-challenge/UWRaVu8KOQk576WzPmhDCnV83tKU8RVY
    wire-server->>-acme-server: 200
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/certificate/sa9z5Ytd75qCoNbcmZdXGkJ96QzqHwAT
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55093/acme/wire-acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55093/acme/wire-acme/new-nonce",
  "newAccount": "https://localhost:55093/acme/wire-acme/new-account",
  "newOrder": "https://localhost:55093/acme/wire-acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55093/acme/wire-acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
replay-nonce: ZE9IZUtCcTVOaGc3Z09TeHJ2WWtIeEllbXZwTWNYS1I
```
```json
"ZE9IZUtCcTVOaGc3Z09TeHJ2WWtIeEllbXZwTWNYS1I"
```
#### 5. create a new account
```http request
POST https://localhost:55093/acme/wire-acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImlzdjVRZFdoSlYyYXhyVGFnRWdIMzRQM2M5NVJNQW5KMG5YdkZoZUVwVnMifSwibm9uY2UiOiJaRTlJWlV0Q2NUVk9hR2MzWjA5VGVISjJXV3RJZUVsbGJYWndUV05ZUzFJIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTUwOTMvYWNtZS93aXJlLWFjbWUvbmV3LWFjY291bnQifQ",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "R5b8zKjwciZid1kIEWX_2ggkZRj029JZZavPYMFFMDKVbzaiC-DvZOsprM89L-etUzFnypIDnVKyNdC_62jDCg"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "typ": "JWT",
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "isv5QdWhJV2axrTagEgH34P3c95RMAnJ0nXvFheEpVs"
    },
    "nonce": "ZE9IZUtCcTVOaGc3Z09TeHJ2WWtIeEllbXZwTWNYS1I",
    "url": "https://localhost:55093/acme/wire-acme/new-account"
  },
  "payload": {
    "termsOfServiceAgreed": true,
    "contact": [
      "unknown@example.com"
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
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/account/b5PzmLZBD4EyIs0Gvz2taERCNbHGhYJp
replay-nonce: MHB4Sm50RnlpaVozbTNPaFZ6c3dwcTFUVE1meTdEU0Y
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55093/acme/wire-acme/account/b5PzmLZBD4EyIs0Gvz2taERCNbHGhYJp/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55093/acme/wire-acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvYjVQem1MWkJENEV5SXMwR3Z6MnRhRVJDTmJIR2hZSnAiLCJ0eXAiOiJKV1QiLCJub25jZSI6Ik1IQjRTbTUwUm5scGFWb3piVE5QYUZaNmMzZHdjVEZVVkUxbWVUZEVVMFkiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9uZXctb3JkZXIifQ",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaWRwLmV4YW1wbGUuY29tIn0seyJ0eXBlIjoiZG5zIiwidmFsdWUiOiJ3aXJlLmV4YW1wbGUuY29tIn1dLCJub3RCZWZvcmUiOiIyMDIzLTAxLTIwVDA5OjAzOjM1Ljc2NjgzOFoiLCJub3RBZnRlciI6IjIwMjMtMDEtMjBUMTA6MDM6MzUuNzY2ODM4WiJ9",
  "signature": "2q1uKqv5GLMHehkTs8StYC63yjHe5hYX39TZs4tbEwCPWqg_f0rg4MvmEisLnctrbRZQUmRnwzdXtHIBx9jYDQ"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55093/acme/wire-acme/account/b5PzmLZBD4EyIs0Gvz2taERCNbHGhYJp",
    "typ": "JWT",
    "nonce": "MHB4Sm50RnlpaVozbTNPaFZ6c3dwcTFUVE1meTdEU0Y",
    "url": "https://localhost:55093/acme/wire-acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "dns",
        "value": "idp.example.com"
      },
      {
        "type": "dns",
        "value": "wire.example.com"
      }
    ],
    "notBefore": "2023-01-20T09:03:35.766838Z",
    "notAfter": "2023-01-20T10:03:35.766838Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N
replay-nonce: eDFCTURGQ09hY3NINjFXYmpxaEVPUnc1d0hSZGhQelI
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55093/acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55093/acme/wire-acme/authz/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf",
    "https://localhost:55093/acme/wire-acme/authz/1mx9BBDXlDqo8YGdofNGVephPtiXoZll"
  ],
  "expires": "2023-01-21T09:03:35Z",
  "notBefore": "2023-01-20T09:03:35.766838Z",
  "notAfter": "2023-01-20T10:03:35.766838Z"
}
```
### Display-name and handle already authorized
#### 9. fetch first challenge
```http request
POST https://localhost:55093/acme/wire-acme/authz/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvYjVQem1MWkJENEV5SXMwR3Z6MnRhRVJDTmJIR2hZSnAiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImVERkNUVVJHUTA5aFkzTklOakZYWW1weGFFVlBVbmMxZDBoU1pHaFFlbEkiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9hdXRoei9KVGxXc0VwR284Tnc3OG8xUG0xekNFNFNYb1IyQTRsZiJ9",
  "payload": "",
  "signature": "7UWfIoLVAmQQ3ZD7QUgoAP5hK-F7ZDAjFAZ0hflCcLUyFDmZWUaD4ynRdSV3Xq-XTinpY1y1psM0z6zXsHLABQ"
}
```
#### 10. get back first challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/authz/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf
replay-nonce: OWR0Z3JUb3djN1BMc2ZCMnh5RUFUTTJmaUhscGVvM3Y
```
```json
{
  "status": "pending",
  "expires": "2023-01-21T09:03:35Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf/sidG82hIE1C6UvwXFgE5twz8Z4hqnubL",
      "status": "pending",
      "token": "J2iDTJbNltlxtngrQbROygRvkR39O93e"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf/Djz71pioa2ai6TZoK8qQRjKBFL00ck9u",
      "status": "pending",
      "token": "J2iDTJbNltlxtngrQbROygRvkR39O93e"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf/aN41wnVsobsB2fs9eQ77KJd7VRewpk0X",
      "status": "pending",
      "token": "J2iDTJbNltlxtngrQbROygRvkR39O93e"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "idp.example.com"
  }
}
```
### ACME provides a Wire client ID challenge
#### 11. fetch second challenge
```http request
POST https://localhost:55093/acme/wire-acme/authz/1mx9BBDXlDqo8YGdofNGVephPtiXoZll
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvYjVQem1MWkJENEV5SXMwR3Z6MnRhRVJDTmJIR2hZSnAiLCJ0eXAiOiJKV1QiLCJub25jZSI6Ik9XUjBaM0pVYjNkak4xQk1jMlpDTW5oNVJVRlVUVEptYVVoc2NHVnZNM1kiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9hdXRoei8xbXg5QkJEWGxEcW84WUdkb2ZOR1ZlcGhQdGlYb1psbCJ9",
  "payload": "",
  "signature": "CXNeolJQP0x8qON8d2WoOFeNDRT4WzaL2E9X5EInXTuyDPyKjFsPDsr4vsWeWCywgIlvuMWFON54ARpM4k3ACg"
}
```
#### 12. get back second challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/authz/1mx9BBDXlDqo8YGdofNGVephPtiXoZll
replay-nonce: NW8yWmdhbVoyVFdWYW5ySjNoRUVCaVRRbXJZVERCMjU
```
```json
{
  "status": "pending",
  "expires": "2023-01-21T09:03:35Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/1mx9BBDXlDqo8YGdofNGVephPtiXoZll/qvbtfmbfjuKPJAMnYF2mxeZ5lv9r0Eb2",
      "status": "pending",
      "token": "UWRaVu8KOQk576WzPmhDCnV83tKU8RVY"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/1mx9BBDXlDqo8YGdofNGVephPtiXoZll/NY9jkK7JLKrkoUk2AhNeYfsKjeTT579S",
      "status": "pending",
      "token": "UWRaVu8KOQk576WzPmhDCnV83tKU8RVY"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/1mx9BBDXlDqo8YGdofNGVephPtiXoZll/lF14F2RQr15eAPOHRgWUXZExqWSVoQf5",
      "status": "pending",
      "token": "UWRaVu8KOQk576WzPmhDCnV83tKU8RVY"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "wire.example.com"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 13. fetch a nonce from wire-server
```http request
GET http://localhost:63479/clients/token/nonce

```
#### 14. get wire-server nonce
```http request
200

```
```json
"WDhFa1hiQzdxcXVHeHpnRUJmVzlDaFZ3RmF6OHpqSHQ"
```
#### 15. create the client Dpop token with both nonces
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiaXN2NVFkV2hKVjJheHJUYWdFZ0gzNFAzYzk1Uk1Bbkowblh2RmhlRXBWcyJ9fQ.eyJpYXQiOjE2NzQyMDU0MTUsImV4cCI6MTY3NDI5MTgxNSwibmJmIjoxNjc0MjA1NDE1LCJzdWIiOiJpbTp3aXJlYXBwOllqZzNZakpoWldJNVl6Wm1ORE0yTm1JeVpqZzVZMlEyTXpnek1XSmxZVFUvODY4ZThjODQwYThjZTA0MkB3aXJlLmNvbSIsImp0aSI6IjJmOTZkMjk2LTM3ZWMtNGJjYS04Yjg2LTY1NzkwYTVlMDBiNSIsIm5vbmNlIjoiV0RoRmExaGlRemR4Y1hWSGVIcG5SVUptVnpsRGFGWjNSbUY2T0hwcVNIUSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjYzNDc5L2NsaWVudHMvOTY5NTg0MTU0NjUxNTgzMjg5OC9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiSjJpRFRKYk5sdGx4dG5nclFiUk95Z1J2a1IzOU85M2UifQ.oq1GnZAdjNoznPhWbN2qAU7urXIlwhXG1p8WqWSZiiBuqnW2rQrzi5oU-bu43vrqiMdrTZMwevL-Mk-8oN6HCA)
```http request
POST http://localhost:63479/clients/9695841546515832898/access-token

```
#### 16. get a Dpop access token from wire-server
```http request
200

```
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6ImtZZS0zRGxZWDBNbHhmZjRPMW1Da25pd09MUG5TV1d5ZWozYVR4YWk3NVUifX0.eyJpYXQiOjE2NzQyMDU0MTUsImV4cCI6MTY4MTk4MTQxNSwibmJmIjoxNjc0MjA1NDE1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjYzNDc5L2NsaWVudHMvOTY5NTg0MTU0NjUxNTgzMjg5OC9hY2Nlc3MtdG9rZW4iLCJzdWIiOiJpbTp3aXJlYXBwOllqZzNZakpoWldJNVl6Wm1ORE0yTm1JeVpqZzVZMlEyTXpnek1XSmxZVFUvODY4ZThjODQwYThjZTA0MkB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NjM0NzkvY2xpZW50cy85Njk1ODQxNTQ2NTE1ODMyODk4L2FjY2Vzcy10b2tlbiIsImp0aSI6IjVjYjc5NTM0LWJmMGUtNDM3Mi05ZmMxLTY3MzZjYWQzMTllNyIsIm5vbmNlIjoiV0RoRmExaGlRemR4Y1hWSGVIcG5SVUptVnpsRGFGWjNSbUY2T0hwcVNIUSIsImNoYWwiOiJKMmlEVEpiTmx0bHh0bmdyUWJST3lnUnZrUjM5TzkzZSIsImNuZiI6eyJraWQiOiI5V1BER09zeTZiSGxWWG1lRTZSSmJ1Y1VjcVZ1MUsySU9rZDRwdmdLVmxrIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pYVhOMk5WRmtWMmhLVmpKaGVISlVZV2RGWjBnek5GQXpZemsxVWsxQmJrb3dibGgyUm1obFJYQldjeUo5ZlEuZXlKcFlYUWlPakUyTnpReU1EVTBNVFVzSW1WNGNDSTZNVFkzTkRJNU1UZ3hOU3dpYm1KbUlqb3hOamMwTWpBMU5ERTFMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndPbGxxWnpOWmFrcG9XbGRKTlZsNldtMU9SRTB5VG0xSmVWcHFaelZaTWxFeVRYcG5lazFYU214WlZGVXZPRFk0WlRoak9EUXdZVGhqWlRBME1rQjNhWEpsTG1OdmJTSXNJbXAwYVNJNklqSm1PVFprTWprMkxUTTNaV010TkdKallTMDRZamcyTFRZMU56a3dZVFZsTURCaU5TSXNJbTV2Ym1ObElqb2lWMFJvUm1FeGFHbFJlbVI0WTFoV1NHVkljRzVTVlVwdFZucHNSR0ZHV2pOU2JVWTJUMGh3Y1ZOSVVTSXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZiRzlqWVd4b2IzTjBPall6TkRjNUwyTnNhV1Z1ZEhNdk9UWTVOVGcwTVRVME5qVXhOVGd6TWpnNU9DOWhZMk5sYzNNdGRHOXJaVzRpTENKamFHRnNJam9pU2pKcFJGUktZazVzZEd4NGRHNW5jbEZpVWs5NVoxSjJhMUl6T1U4NU0yVWlmUS5vcTFHblpBZGpOb3puUGhXYk4ycUFVN3VyWElsd2hYRzFwOFdxV1NaaWlCdXFuVzJyUXJ6aTVvVS1idTQzdnJxaU1kclRaTXdldkwtTWstOG9ONkhDQSIsImNsaWVudF9pZCI6ImltOndpcmVhcHA6WWpnM1lqSmhaV0k1WXpabU5ETTJObUl5WmpnNVkyUTJNemd6TVdKbFlUVS84NjhlOGM4NDBhOGNlMDQyQHdpcmUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.5_3QCF-83P6boczo0768b5rIleiAqVkJ2wUKmD9NZvkf9k2s1PuXbQqciXmDnb4RAE51WuyyRZVtvCvj6paSBQ)
### Client provides access token
#### 17. send DPoP access token to acme server to have it validated
```http request
POST https://localhost:55093/acme/wire-acme/challenge/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf/Djz71pioa2ai6TZoK8qQRjKBFL00ck9u
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvYjVQem1MWkJENEV5SXMwR3Z6MnRhRVJDTmJIR2hZSnAiLCJ0eXAiOiJKV1QiLCJub25jZSI6Ik5XOHlXbWRoYlZveVZGZFdZVzV5U2pOb1JVVkNhVlJSYlhKWlZFUkNNalUiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9jaGFsbGVuZ2UvSlRsV3NFcEdvOE53NzhvMVBtMXpDRTRTWG9SMkE0bGYvRGp6NzFwaW9hMmFpNlRab0s4cVFSaktCRkwwMGNrOXUifQ",
  "payload": "",
  "signature": "LjHAidXYANCu3erG1OUn5g268dldrWSEuvvoQukRYMT-8VT4Vs8-PuEdloZX-FLFfHAEQpxz4unWSNv-fCeOAA"
}
```
#### 18. acme server verifies client-id with an http challenge
```http request
GET http://wire.com/.well-known/acme-challenge/J2iDTJbNltlxtngrQbROygRvkR39O93e

```

#### 19. acme server verifies handle + display-name with an OIDC challenge
```http request
GET http://wire.com/.well-known/acme-challenge/UWRaVu8KOQk576WzPmhDCnV83tKU8RVY

```

#### 20. both challenges are valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
link: <https://localhost:55093/acme/wire-acme/authz/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf>;rel="up"
location: https://localhost:55093/acme/wire-acme/challenge/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf/Djz71pioa2ai6TZoK8qQRjKBFL00ck9u
replay-nonce: ZXlncURoNVJYdnl0OVpqSEw3Yzl6WDVDbGpMV2I1WVE
```
```json
{
  "type": "http-01",
  "url": "https://localhost:55093/acme/wire-acme/challenge/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf/Djz71pioa2ai6TZoK8qQRjKBFL00ck9u",
  "status": "valid",
  "token": "J2iDTJbNltlxtngrQbROygRvkR39O93e"
}
```
### Client presents a CSR and gets its certificate
#### 21. verify the status of the order
```http request
POST https://localhost:55093/acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvYjVQem1MWkJENEV5SXMwR3Z6MnRhRVJDTmJIR2hZSnAiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImMySkZiblZMVFdwdVpuQnFkVVl3YlhVMFFtOXZkbUpCU1Rkd1QzRTBhV3ciLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9vcmRlci85MU9LVHd1Z3NQRnprTVRoOG1hdUZOcVJHbUlYckc0TiJ9",
  "payload": "",
  "signature": "hKwhGtUnzKg09gD8sy27az9IZosWWmG7CP0VWw9DAadyPF8Bi92ebB9tVquO6tUqW1u_NaXgNLNOLIQr6tWEBw"
}
```
#### 22. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N
replay-nonce: bFZNdmRoaEdHZlVnbjM0czVQRU1xVFJRTG50MktPYmI
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55093/acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55093/acme/wire-acme/authz/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf",
    "https://localhost:55093/acme/wire-acme/authz/1mx9BBDXlDqo8YGdofNGVephPtiXoZll"
  ],
  "expires": "2023-01-21T09:03:35Z",
  "notBefore": "2023-01-20T09:03:35.766838Z",
  "notAfter": "2023-01-20T10:03:35.766838Z"
}
```
#### 23. create a CSR and call finalize url
```http request
POST https://localhost:55093/acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvYjVQem1MWkJENEV5SXMwR3Z6MnRhRVJDTmJIR2hZSnAiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImJGWk5kbVJvYUVkSFpsVm5iak0wY3pWUVJVMXhWRkpSVEc1ME1rdFBZbUkiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9vcmRlci85MU9LVHd1Z3NQRnprTVRoOG1hdUZOcVJHbUlYckc0Ti9maW5hbGl6ZSJ9",
  "payload": "eyJjc3IiOiJNSUctTUhJQ0FRQXdBREFxTUFVR0F5dGxjQU1oQUlyTC1VSFZvU1ZkbXNhMDJvQklCOS1EOTNQZVVUQUp5ZEoxN3hZWGhLVmJvRDh3UFFZSktvWklodmNOQVFrT01UQXdMakFzQmdOVkhSRUVKVEFqZ2hCM2FYSmxMbVY0WVcxd2JHVXVZMjl0Z2c5cFpIQXVaWGhoYlhCc1pTNWpiMjB3QlFZREsyVndBMEVBR05kdHEyQWVCeFZDZUdxSmktdENiNTJpMkJpZnI0Qzg4aFp3dmVfTHd3YUFSX0FRcDF5R0M0MUdLQ3lnRjYzU18wTUlBYmlpSFBydk9XZVhTRlFqQkEifQ",
  "signature": "3dUJBV_tehNmQmTKi695K1-PP-28THnCvyybhOs70jEJQsvFv_6aZaSORzvp9wGYGS7yOJY47fRfaujYabPDCQ"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55093/acme/wire-acme/account/b5PzmLZBD4EyIs0Gvz2taERCNbHGhYJp",
    "typ": "JWT",
    "nonce": "bFZNdmRoaEdHZlVnbjM0czVQRU1xVFJRTG50MktPYmI",
    "url": "https://localhost:55093/acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N/finalize"
  },
  "payload": {
    "csr": "MIG-MHICAQAwADAqMAUGAytlcAMhAIrL-UHVoSVdmsa02oBIB9-D93PeUTAJydJ17xYXhKVboD8wPQYJKoZIhvcNAQkOMTAwLjAsBgNVHREEJTAjghB3aXJlLmV4YW1wbGUuY29tgg9pZHAuZXhhbXBsZS5jb20wBQYDK2VwA0EAGNdtq2AeBxVCeGqJi-tCb52i2Bifr4C88hZwve_LwwaAR_AQp1yGC41GKCygF63S_0MIAbiiHPrvOWeXSFQjBA"
  }
}
```
#### 24. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N
replay-nonce: Q2JGbm14TGJUc3V6WnlpMENBM2pkQldnVXlsWnluT1k
```
```json
{
  "certificate": "https://localhost:55093/acme/wire-acme/certificate/sa9z5Ytd75qCoNbcmZdXGkJ96QzqHwAT",
  "status": "valid",
  "finalize": "https://localhost:55093/acme/wire-acme/order/91OKTwugsPFzkMTh8mauFNqRGmIXrG4N/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55093/acme/wire-acme/authz/JTlWsEpGo8Nw78o1Pm1zCE4SXoR2A4lf",
    "https://localhost:55093/acme/wire-acme/authz/1mx9BBDXlDqo8YGdofNGVephPtiXoZll"
  ],
  "expires": "2023-01-21T09:03:35Z",
  "notBefore": "2023-01-20T09:03:35.766838Z",
  "notAfter": "2023-01-20T10:03:35.766838Z"
}
```
#### 25. fetch the certificate
```http request
POST https://localhost:55093/acme/wire-acme/certificate/sa9z5Ytd75qCoNbcmZdXGkJ96QzqHwAT
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvYjVQem1MWkJENEV5SXMwR3Z6MnRhRVJDTmJIR2hZSnAiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlEySkdibTE0VEdKVWMzVjZXbmxwTUVOQk0ycGtRbGRuVlhsc1dubHVUMWsiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9jZXJ0aWZpY2F0ZS9zYTl6NVl0ZDc1cUNvTmJjbVpkWEdrSjk2UXpxSHdBVCJ9",
  "payload": "",
  "signature": "jXOqn85uK2dIes5ItjfDuNQRM1ScuQ9bOTbGUS_8i4STdWTe09eNSWD6LKiGcuD910-BfmaES52agHNfHK4lAg"
}
```
#### 26. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
replay-nonce: bHVDZW1EWm9aTUM1dWNlZjNFRzRFbVIzOHhwcHZKWFM
```
```json
[
  "MIIBxDCCAWugAwIBAgIQORN5SqKNwNiHZ7qZVOiIjzAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzAxMjAwOTAzMzVaFw0yMzAxMjAxMDAzMzVaMAAwKjAFBgMrZXADIQCKy/lB1aEl\nXZrGtNqASAffg/dz3lEwCcnSde8WF4SlW6OBxzCBxDAOBgNVHQ8BAf8EBAMCB4Aw\nHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQUJYO6vZRA\njvN9FUfPQekFlun2vjAfBgNVHSMEGDAWgBQFh14W6LYUwLfF176vB9VSEcrEHzAv\nBgNVHREBAf8EJTAjgg9pZHAuZXhhbXBsZS5jb22CEHdpcmUuZXhhbXBsZS5jb20w\nIgYMKwYBBAGCpGTGKEABBBIwEAIBBgQJd2lyZS1hY21lBAAwCgYIKoZIzj0EAwID\nRwAwRAIgKkQdWzjtlF9IkvCQ6E6GUvSEITVe9iHNnrusuWGIUTACIAda7zMruoTy\naK+9GDQDr/R9UamX9RuLe2ZncejgrZ9G",
  "MIIBuTCCAV+gAwIBAgIRAJdDcbalHF3srFt9bTHdTk8wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDEyMDA5\nMDMzMFoXDTMzMDExNzA5MDMzMFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATB\nbXVWBG0zE9Sxj8h5dO0+LS0lNBd1XV0fRLgbumlhDOyhnWI7XJs3Y7qnMrYz1ZUq\nBDPigaS4PtMFQm//+3Elo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUBYdeFui2FMC3xde+rwfVUhHKxB8wHwYDVR0jBBgw\nFoAUsEWSF3ZiE5J4hw7b9xavI00SYIMwCgYIKoZIzj0EAwIDSAAwRQIgQTx6o6lp\nwSm96ghkajsBmSUKhYv4brOhtiXnZgVy8fYCIQChM/zlOIts3qShX0rF5Y5qduqy\n5XUUA7k1kHCTJBbY0Q=="
]
```
P256 - SHA256
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/wire-acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/wire-acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/authz/csKaemo9GC6crni1PpZwRRjmlVN0x8EU
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/authz/ztLGNcicpX9vHKL5BpoWfFUCkVyhuhAN
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST /clients/7540493027090625450/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/challenge/csKaemo9GC6crni1PpZwRRjmlVN0x8EU/wJbiP0x5okMfpFSzQPC6IjlkhWPENeKj
    acme-server->>+wire-server: GET /.well-known/acme-challenge/zDm6C9qKaysaUXPixSXTshGrNHO0EoeL
    wire-server->>-acme-server: 200
    acme-server->>+wire-server: GET /.well-known/acme-challenge/Vh82XSlbkzGiZ9jOaz2Wz6P84yho58OG
    wire-server->>-acme-server: 200
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/certificate/eiSeuSbD6jMlGEVEpGzbsAfM22k5uoPf
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55093/acme/wire-acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55093/acme/wire-acme/new-nonce",
  "newAccount": "https://localhost:55093/acme/wire-acme/new-account",
  "newOrder": "https://localhost:55093/acme/wire-acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55093/acme/wire-acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
replay-nonce: VnRpZ3R1THdtc09HM3dpdFBMZTBMaWZJeVNhNXpZTUk
```
```json
"VnRpZ3R1THdtc09HM3dpdFBMZTBMaWZJeVNhNXpZTUk"
```
#### 5. create a new account
```http request
POST https://localhost:55093/acme/wire-acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IkpJLXNBc3d6NXluelVjSG9MNDRXU2FqU3lVNnhzWWx3Mm81dG13VlY0NDAiLCJ5IjoiYVBwaUZoa0RxWm9HQTUtLWZhUi1LUmppZUpyMlhKU1JSTFhacHlVeWdZdyJ9LCJub25jZSI6IlZuUnBaM1IxVEhkdGMwOUhNM2RwZEZCTVpUQk1hV1pKZVZOaE5YcFpUVWsiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9uZXctYWNjb3VudCJ9",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "_2tcD7EA8ysv5W6JJrtOFGjeCaYZxXY9kFcFXaYCE9lLnwnCgEoth-k5i3GjrPHX80Gp2aIrkcz5WcKTz2Ying"
}
...decoded...
{
  "protected": {
    "alg": "ES256",
    "typ": "JWT",
    "jwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "JI-sAswz5ynzUcHoL44WSajSyU6xsYlw2o5tmwVV440",
      "y": "aPpiFhkDqZoGA5--faR-KRjieJr2XJSRRLXZpyUygYw"
    },
    "nonce": "VnRpZ3R1THdtc09HM3dpdFBMZTBMaWZJeVNhNXpZTUk",
    "url": "https://localhost:55093/acme/wire-acme/new-account"
  },
  "payload": {
    "termsOfServiceAgreed": true,
    "contact": [
      "unknown@example.com"
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
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/account/XaBoZD6WN9FNdfDJ2TvhmXq8QCJEi1Sv
replay-nonce: ZTRuandJNWlhWVBOMFU3d1RpZnRRM3VHRnB1Tjd3Uno
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55093/acme/wire-acme/account/XaBoZD6WN9FNdfDJ2TvhmXq8QCJEi1Sv/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55093/acme/wire-acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvWGFCb1pENldOOUZOZGZESjJUdmhtWHE4UUNKRWkxU3YiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlpUUnVhbmRKTldsaFdWQk9NRlUzZDFScFpuUlJNM1ZIUm5CMVRqZDNVbm8iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9uZXctb3JkZXIifQ",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaWRwLmV4YW1wbGUuY29tIn0seyJ0eXBlIjoiZG5zIiwidmFsdWUiOiJ3aXJlLmV4YW1wbGUuY29tIn1dLCJub3RCZWZvcmUiOiIyMDIzLTAxLTIwVDA5OjAzOjM5LjA2OTQwN1oiLCJub3RBZnRlciI6IjIwMjMtMDEtMjBUMTA6MDM6MzkuMDY5NDA3WiJ9",
  "signature": "3e8BGaiOkEvlRXuY8NYgweb1xpFUg4hl50-CAitRigFKcYluHcr2Gb33aCogIlNpH4LI3B47Z5_tBgi5k3CxWQ"
}
...decoded...
{
  "protected": {
    "alg": "ES256",
    "kid": "https://localhost:55093/acme/wire-acme/account/XaBoZD6WN9FNdfDJ2TvhmXq8QCJEi1Sv",
    "typ": "JWT",
    "nonce": "ZTRuandJNWlhWVBOMFU3d1RpZnRRM3VHRnB1Tjd3Uno",
    "url": "https://localhost:55093/acme/wire-acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "dns",
        "value": "idp.example.com"
      },
      {
        "type": "dns",
        "value": "wire.example.com"
      }
    ],
    "notBefore": "2023-01-20T09:03:39.069407Z",
    "notAfter": "2023-01-20T10:03:39.069407Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR
replay-nonce: ZDNBVUU2UG5JUUpENzlVNVRWNk5zNTRiUEtlbGhzenA
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55093/acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55093/acme/wire-acme/authz/csKaemo9GC6crni1PpZwRRjmlVN0x8EU",
    "https://localhost:55093/acme/wire-acme/authz/ztLGNcicpX9vHKL5BpoWfFUCkVyhuhAN"
  ],
  "expires": "2023-01-21T09:03:39Z",
  "notBefore": "2023-01-20T09:03:39.069407Z",
  "notAfter": "2023-01-20T10:03:39.069407Z"
}
```
### Display-name and handle already authorized
#### 9. fetch first challenge
```http request
POST https://localhost:55093/acme/wire-acme/authz/csKaemo9GC6crni1PpZwRRjmlVN0x8EU
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvWGFCb1pENldOOUZOZGZESjJUdmhtWHE4UUNKRWkxU3YiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlpETkJWVVUyVUc1SlVVcEVOemxWTlZSV05rNXpOVFJpVUV0bGJHaHplbkEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9hdXRoei9jc0thZW1vOUdDNmNybmkxUHBad1JSam1sVk4weDhFVSJ9",
  "payload": "",
  "signature": "E21bVhdFP3zD7UMVp25BZyEgfCJD9vliR6EUrd02ev0XpXtZETOY3wGj1R8ANNYrNo1USTGElQIHWLqxiF18PQ"
}
```
#### 10. get back first challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/authz/csKaemo9GC6crni1PpZwRRjmlVN0x8EU
replay-nonce: VXJXeXhwSDJaMXVoQ05KZ0M4TzR5V3B2SnlrRFJjdXE
```
```json
{
  "status": "pending",
  "expires": "2023-01-21T09:03:39Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/csKaemo9GC6crni1PpZwRRjmlVN0x8EU/D4I1KBzO52y77puxNDqjQX0Ooj0eKZfq",
      "status": "pending",
      "token": "zDm6C9qKaysaUXPixSXTshGrNHO0EoeL"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/csKaemo9GC6crni1PpZwRRjmlVN0x8EU/wJbiP0x5okMfpFSzQPC6IjlkhWPENeKj",
      "status": "pending",
      "token": "zDm6C9qKaysaUXPixSXTshGrNHO0EoeL"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/csKaemo9GC6crni1PpZwRRjmlVN0x8EU/7snzmqFHphKoLU1HOxUjwo7hHhHGu1EY",
      "status": "pending",
      "token": "zDm6C9qKaysaUXPixSXTshGrNHO0EoeL"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "idp.example.com"
  }
}
```
### ACME provides a Wire client ID challenge
#### 11. fetch second challenge
```http request
POST https://localhost:55093/acme/wire-acme/authz/ztLGNcicpX9vHKL5BpoWfFUCkVyhuhAN
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvWGFCb1pENldOOUZOZGZESjJUdmhtWHE4UUNKRWkxU3YiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlZYSlhlWGh3U0RKYU1YVm9RMDVLWjBNNFR6UjVWM0IyU25sclJGSmpkWEUiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9hdXRoei96dExHTmNpY3BYOXZIS0w1QnBvV2ZGVUNrVnlodWhBTiJ9",
  "payload": "",
  "signature": "YVNX3wu95wqRvedIK7MRFb-naNWAUuLCup1XkAMsG8c5ij5sb-xk209yH5abd8pkqxL6RE4dMGv4rN30iookHQ"
}
```
#### 12. get back second challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/authz/ztLGNcicpX9vHKL5BpoWfFUCkVyhuhAN
replay-nonce: eHpTZUJ3dE5QSU5FeWJwcWpUaG9IN2hGellJV3ZiTlo
```
```json
{
  "status": "pending",
  "expires": "2023-01-21T09:03:39Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/ztLGNcicpX9vHKL5BpoWfFUCkVyhuhAN/d5pcYSsugFpEKoqf5cpGsLlrn5h1ZPzH",
      "status": "pending",
      "token": "Vh82XSlbkzGiZ9jOaz2Wz6P84yho58OG"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/ztLGNcicpX9vHKL5BpoWfFUCkVyhuhAN/s3ZmNbCWfihTIY2ea00gGkRYyXVeEYRV",
      "status": "pending",
      "token": "Vh82XSlbkzGiZ9jOaz2Wz6P84yho58OG"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/ztLGNcicpX9vHKL5BpoWfFUCkVyhuhAN/wtyRTfeer1Zs9OAk1kNYIsQ696tsPKAg",
      "status": "pending",
      "token": "Vh82XSlbkzGiZ9jOaz2Wz6P84yho58OG"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "wire.example.com"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 13. fetch a nonce from wire-server
```http request
GET http://localhost:63479/clients/token/nonce

```
#### 14. get wire-server nonce
```http request
200

```
```json
"U0xORW5UZEpkUmNBQUdVNGJqNVNROW5IS2ZCS3BsU3A"
```
#### 15. create the client Dpop token with both nonces
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzI1NiIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoiSkktc0Fzd3o1eW56VWNIb0w0NFdTYWpTeVU2eHNZbHcybzV0bXdWVjQ0MCIsInkiOiJhUHBpRmhrRHFab0dBNS0tZmFSLUtSamllSnIyWEpTUlJMWFpweVV5Z1l3In19.eyJpYXQiOjE2NzQyMDU0MTksImV4cCI6MTY3NDI5MTgxOSwibmJmIjoxNjc0MjA1NDE5LCJzdWIiOiJpbTp3aXJlYXBwOk5tSXpPREk0TldFeVltSTVORGN6Wm1KbFlqZ3lZbU16T1RrMFpUSmlaVEkvNjhhNTM2NzRmNzBiZjNhYUB3aXJlLmNvbSIsImp0aSI6IjljNWJhODdlLTdkNDgtNGM1Yi1hN2EzLTUwOGI3NTk2M2M5MyIsIm5vbmNlIjoiVTB4T1JXNVVaRXBrVW1OQlFVZFZOR0pxTlZOUk9XNUlTMlpDUzNCc1UzQSIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjYzNDc5L2NsaWVudHMvNzU0MDQ5MzAyNzA5MDYyNTQ1MC9hY2Nlc3MtdG9rZW4iLCJjaGFsIjoiekRtNkM5cUtheXNhVVhQaXhTWFRzaEdyTkhPMEVvZUwifQ.BeVep3evHV-9H78fOl9-3FX7H9jEhWXqSjme6Q1BZkIDuSmOoM73FsG8_dIZ_39u43kpTAG9NLjaq99TCXNBGg)
```http request
POST http://localhost:63479/clients/7540493027090625450/access-token

```
#### 16. get a Dpop access token from wire-server
```http request
200

```
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InBKSFczQ00yRFh0T20ycEFuZ3hza1J3bjB2N0xudUVHbUxkbWk3UEtHUlUiLCJ5IjoiQWtHZHFROWxTV2pVeER2TzY4Z2FjSVZzdHlLd0pVUTlFWjRpbjZDdFU5WSJ9fQ.eyJpYXQiOjE2NzQyMDU0MTksImV4cCI6MTY4MTk4MTQxOSwibmJmIjoxNjc0MjA1NDE5LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjYzNDc5L2NsaWVudHMvNzU0MDQ5MzAyNzA5MDYyNTQ1MC9hY2Nlc3MtdG9rZW4iLCJzdWIiOiJpbTp3aXJlYXBwOk5tSXpPREk0TldFeVltSTVORGN6Wm1KbFlqZ3lZbU16T1RrMFpUSmlaVEkvNjhhNTM2NzRmNzBiZjNhYUB3aXJlLmNvbSIsImF1ZCI6Imh0dHA6Ly9sb2NhbGhvc3Q6NjM0NzkvY2xpZW50cy83NTQwNDkzMDI3MDkwNjI1NDUwL2FjY2Vzcy10b2tlbiIsImp0aSI6Ijg4MDdiODdhLWIzNzYtNDczOS1hYWE5LTA2ZGRiYWQ0ODM3OSIsIm5vbmNlIjoiVTB4T1JXNVVaRXBrVW1OQlFVZFZOR0pxTlZOUk9XNUlTMlpDUzNCc1UzQSIsImNoYWwiOiJ6RG02QzlxS2F5c2FVWFBpeFNYVHNoR3JOSE8wRW9lTCIsImNuZiI6eyJraWQiOiJhSkh3aWJtRXB6TlJIbldFRWhWdEowUWRXYkFrLWNpMWNCOXhrUll4NDVzIn0sInByb29mIjoiZXlKaGJHY2lPaUpGVXpJMU5pSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWtWRElpd2lZM0oySWpvaVVDMHlOVFlpTENKNElqb2lTa2t0YzBGemQzbzFlVzU2VldOSWIwdzBORmRUWVdwVGVWVTJlSE5aYkhjeWJ6VjBiWGRXVmpRME1DSXNJbmtpT2lKaFVIQnBSbWhyUkhGYWIwZEJOUzB0Wm1GU0xVdFNhbWxsU25JeVdFcFRVbEpNV0Zwd2VWVjVaMWwzSW4xOS5leUpwWVhRaU9qRTJOelF5TURVME1Ua3NJbVY0Y0NJNk1UWTNOREk1TVRneE9Td2libUptSWpveE5qYzBNakExTkRFNUxDSnpkV0lpT2lKcGJUcDNhWEpsWVhCd09rNXRTWHBQUkVrMFRsZEZlVmx0U1RWT1JHTjZXbTFLYkZscVozbFpiVTE2VDFSck1GcFVTbWxhVkVrdk5qaGhOVE0yTnpSbU56Qmlaak5oWVVCM2FYSmxMbU52YlNJc0ltcDBhU0k2SWpsak5XSmhPRGRsTFRka05EZ3ROR00xWWkxaE4yRXpMVFV3T0dJM05UazJNMk01TXlJc0ltNXZibU5sSWpvaVZUQjRUMUpYTlZWYVJYQnJWVzFPUWxGVlpGWk9SMHB4VGxaT1VrOVhOVWxUTWxwRFV6TkNjMVV6UVNJc0ltaDBiU0k2SWxCUFUxUWlMQ0pvZEhVaU9pSm9kSFJ3T2k4dmJHOWpZV3hvYjNOME9qWXpORGM1TDJOc2FXVnVkSE12TnpVME1EUTVNekF5TnpBNU1EWXlOVFExTUM5aFkyTmxjM010ZEc5clpXNGlMQ0pqYUdGc0lqb2lla1J0TmtNNWNVdGhlWE5oVlZoUWFYaFRXRlJ6YUVkeVRraFBNRVZ2WlV3aWZRLkJlVmVwM2V2SFYtOUg3OGZPbDktM0ZYN0g5akVoV1hxU2ptZTZRMUJaa0lEdVNtT29NNzNGc0c4X2RJWl8zOXU0M2twVEFHOU5MamFxOTlUQ1hOQkdnIiwiY2xpZW50X2lkIjoiaW06d2lyZWFwcDpObUl6T0RJNE5XRXlZbUk1TkRjelptSmxZamd5WW1Nek9UazBaVEppWlRJLzY4YTUzNjc0ZjcwYmYzYWFAd2lyZS5jb20iLCJhcGlfdmVyc2lvbiI6Mywic2NvcGUiOiJ3aXJlX2NsaWVudF9pZCJ9.OflhZCbQisWCkI_CuIp_8BCmRJDbYw3gcmlzdegOru-A7gfuIoU6wq9tSUNTLqKVI1VnPXVAhQM50HP686-86w)
### Client provides access token
#### 17. send DPoP access token to acme server to have it validated
```http request
POST https://localhost:55093/acme/wire-acme/challenge/csKaemo9GC6crni1PpZwRRjmlVN0x8EU/wJbiP0x5okMfpFSzQPC6IjlkhWPENeKj
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvWGFCb1pENldOOUZOZGZESjJUdmhtWHE4UUNKRWkxU3YiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImVIcFRaVUozZEU1UVNVNUZlV0p3Y1dwVWFHOUlOMmhHZWxsSlYzWmlUbG8iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9jaGFsbGVuZ2UvY3NLYWVtbzlHQzZjcm5pMVBwWndSUmptbFZOMHg4RVUvd0piaVAweDVva01mcEZTelFQQzZJamxraFdQRU5lS2oifQ",
  "payload": "",
  "signature": "yac2bR3GzupYB_oZlufS2tob9KSur3XJAGAoL9x5fDYjtxIyBkXlig_nL9EKCJMzBx7dPbnjutKnA5ZpEZvm6Q"
}
```
#### 18. acme server verifies client-id with an http challenge
```http request
GET http://wire.com/.well-known/acme-challenge/zDm6C9qKaysaUXPixSXTshGrNHO0EoeL

```

#### 19. acme server verifies handle + display-name with an OIDC challenge
```http request
GET http://wire.com/.well-known/acme-challenge/Vh82XSlbkzGiZ9jOaz2Wz6P84yho58OG

```

#### 20. both challenges are valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
link: <https://localhost:55093/acme/wire-acme/authz/csKaemo9GC6crni1PpZwRRjmlVN0x8EU>;rel="up"
location: https://localhost:55093/acme/wire-acme/challenge/csKaemo9GC6crni1PpZwRRjmlVN0x8EU/wJbiP0x5okMfpFSzQPC6IjlkhWPENeKj
replay-nonce: bEJLekd4ZVdNbXh0c1VWT01CZFlBRnd3RnN6Qjl3T3U
```
```json
{
  "type": "http-01",
  "url": "https://localhost:55093/acme/wire-acme/challenge/csKaemo9GC6crni1PpZwRRjmlVN0x8EU/wJbiP0x5okMfpFSzQPC6IjlkhWPENeKj",
  "status": "valid",
  "token": "zDm6C9qKaysaUXPixSXTshGrNHO0EoeL"
}
```
### Client presents a CSR and gets its certificate
#### 21. verify the status of the order
```http request
POST https://localhost:55093/acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvWGFCb1pENldOOUZOZGZESjJUdmhtWHE4UUNKRWkxU3YiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlUxbHNkR2R3TTFRMGJHdFRiWGhJVmpJeWFtTnJRa2haWVZwNWEzTlhabVUiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9vcmRlci9DQTh2Nm4zSzVhOThEYlNJZ3prdXhiTkJpaVdaWDloUiJ9",
  "payload": "",
  "signature": "9-VpjcWNQK6BVKzR914wKLSY9EWsCqlpwAJ98wDmdXi4oguWn1Z5j4MEquyYYYywnIlwXihPW304v8wWVgtLtA"
}
```
#### 22. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR
replay-nonce: aWpQRjBwMHlraGtUcW4wTXZaM3NEZ3l2QTRBM3lpbGk
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55093/acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55093/acme/wire-acme/authz/csKaemo9GC6crni1PpZwRRjmlVN0x8EU",
    "https://localhost:55093/acme/wire-acme/authz/ztLGNcicpX9vHKL5BpoWfFUCkVyhuhAN"
  ],
  "expires": "2023-01-21T09:03:39Z",
  "notBefore": "2023-01-20T09:03:39.069407Z",
  "notAfter": "2023-01-20T10:03:39.069407Z"
}
```
#### 23. create a CSR and call finalize url
```http request
POST https://localhost:55093/acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvWGFCb1pENldOOUZOZGZESjJUdmhtWHE4UUNKRWkxU3YiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImFXcFFSakJ3TUhscmFHdFVjVzR3VFhaYU0zTkVaM2wyUVRSQk0zbHBiR2siLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9vcmRlci9DQTh2Nm4zSzVhOThEYlNJZ3prdXhiTkJpaVdaWDloUi9maW5hbGl6ZSJ9",
  "payload": "eyJjc3IiOiJNSUg3TUlHaEFnRUFNQUF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPUFFNQkJ3TkNBQVFrajZ3Q3pEUG5LZk5Sd2VndmpoWkpxTkxKVHJHeGlYRGFqbTJiQlZYampXajZZaFlaQTZtYUJnT2Z2bjJrZmlrWTRuaWE5bHlVa1VTMTJhY2xNb0dNb0Q4d1BRWUpLb1pJaHZjTkFRa09NVEF3TGpBc0JnTlZIUkVFSlRBamdoQjNhWEpsTG1WNFlXMXdiR1V1WTI5dGdnOXBaSEF1WlhoaGJYQnNaUzVqYjIwd0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFKWGVoS1ZlY0RYaFhtVmVWNGwtbTZ3bFVzalM2dEVEeWxjZnNIY29HUk5EQWlFQWlCdFRKenFjWjZLTzgydGttRWpvZV9QM0NmVTNFU3h6MjhTWFlHQWFCRFEifQ",
  "signature": "RPsC3rrFVAeopUauSytoGqrgxu8WbhSmbocGS9mqeekL_bGXSFqFx96K-lvWr2XTg6vRnaucgDhHRb1eBe2_pg"
}
...decoded...
{
  "protected": {
    "alg": "ES256",
    "kid": "https://localhost:55093/acme/wire-acme/account/XaBoZD6WN9FNdfDJ2TvhmXq8QCJEi1Sv",
    "typ": "JWT",
    "nonce": "aWpQRjBwMHlraGtUcW4wTXZaM3NEZ3l2QTRBM3lpbGk",
    "url": "https://localhost:55093/acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR/finalize"
  },
  "payload": {
    "csr": "MIH7MIGhAgEAMAAwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQkj6wCzDPnKfNRwegvjhZJqNLJTrGxiXDajm2bBVXjjWj6YhYZA6maBgOfvn2kfikY4nia9lyUkUS12aclMoGMoD8wPQYJKoZIhvcNAQkOMTAwLjAsBgNVHREEJTAjghB3aXJlLmV4YW1wbGUuY29tgg9pZHAuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSQAwRgIhAJXehKVecDXhXmVeV4l-m6wlUsjS6tEDylcfsHcoGRNDAiEAiBtTJzqcZ6KO82tkmEjoe_P3CfU3ESxz28SXYGAaBDQ"
  }
}
```
#### 24. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR
replay-nonce: RWNKWkhaOWxlTTV0WndFVnFPVTNEcE9YdzRaVGgyVWo
```
```json
{
  "certificate": "https://localhost:55093/acme/wire-acme/certificate/eiSeuSbD6jMlGEVEpGzbsAfM22k5uoPf",
  "status": "valid",
  "finalize": "https://localhost:55093/acme/wire-acme/order/CA8v6n3K5a98DbSIgzkuxbNBiiWZX9hR/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55093/acme/wire-acme/authz/csKaemo9GC6crni1PpZwRRjmlVN0x8EU",
    "https://localhost:55093/acme/wire-acme/authz/ztLGNcicpX9vHKL5BpoWfFUCkVyhuhAN"
  ],
  "expires": "2023-01-21T09:03:39Z",
  "notBefore": "2023-01-20T09:03:39.069407Z",
  "notAfter": "2023-01-20T10:03:39.069407Z"
}
```
#### 25. fetch the certificate
```http request
POST https://localhost:55093/acme/wire-acme/certificate/eiSeuSbD6jMlGEVEpGzbsAfM22k5uoPf
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvWGFCb1pENldOOUZOZGZESjJUdmhtWHE4UUNKRWkxU3YiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlJXTktXa2hhT1d4bFRUVjBXbmRGVm5GUFZUTkVjRTlZZHpSYVZHZ3lWV28iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9jZXJ0aWZpY2F0ZS9laVNldVNiRDZqTWxHRVZFcEd6YnNBZk0yMms1dW9QZiJ9",
  "payload": "",
  "signature": "Tj5MhoBu8eH_SpfVsSwjuGaODGX86IyZ4Z2loCs5H6_r2Phk-KMQ9mpGPQVndJ-B-9PKFIE31rlFb89gmWOjFA"
}
```
#### 26. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
replay-nonce: bnBWdGxBdUw4UUU0VUU0OE9WZmlTOENncXl2S0RXdUI
```
```json
[
  "MIIB9jCCAZugAwIBAgIRAI3D8s3YDyPV2TVE1VJP+A4wCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwMTIwMDkwMzM5WhcNMjMwMTIwMTAwMzM5WjAAMFkwEwYHKoZIzj0CAQYIKoZI\nzj0DAQcDQgAEJI+sAswz5ynzUcHoL44WSajSyU6xsYlw2o5tmwVV441o+mIWGQOp\nmgYDn759pH4pGOJ4mvZclJFEtdmnJTKBjKOBxzCBxDAOBgNVHQ8BAf8EBAMCB4Aw\nHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBQy+PersUmI\nNo+BsHze1f8Z2zXGOjAfBgNVHSMEGDAWgBQFh14W6LYUwLfF176vB9VSEcrEHzAv\nBgNVHREBAf8EJTAjgg9pZHAuZXhhbXBsZS5jb22CEHdpcmUuZXhhbXBsZS5jb20w\nIgYMKwYBBAGCpGTGKEABBBIwEAIBBgQJd2lyZS1hY21lBAAwCgYIKoZIzj0EAwID\nSQAwRgIhAMx/rkuUjzCZ3rPTdAc9UTysO9ZLkiHZtjg/q0c4sqwbAiEA6RldAvAL\n3pevjA5y8/Bb9WNoaAMRSu9d6jGhvcVZQr0=",
  "MIIBuTCCAV+gAwIBAgIRAJdDcbalHF3srFt9bTHdTk8wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDEyMDA5\nMDMzMFoXDTMzMDExNzA5MDMzMFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATB\nbXVWBG0zE9Sxj8h5dO0+LS0lNBd1XV0fRLgbumlhDOyhnWI7XJs3Y7qnMrYz1ZUq\nBDPigaS4PtMFQm//+3Elo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUBYdeFui2FMC3xde+rwfVUhHKxB8wHwYDVR0jBBgw\nFoAUsEWSF3ZiE5J4hw7b9xavI00SYIMwCgYIKoZIzj0EAwIDSAAwRQIgQTx6o6lp\nwSm96ghkajsBmSUKhYv4brOhtiXnZgVy8fYCIQChM/zlOIts3qShX0rF5Y5qduqy\n5XUUA7k1kHCTJBbY0Q=="
]
```
P384 - SHA384
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/wire-acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/wire-acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/wire-acme/authz/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/authz/RGtKG0QtpxehybPXeDx7MpAHzjvl6JMu
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET /clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST /clients/17605723069926893826/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/challenge/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n/FGvxJ9F3uJPLPZz2HqLTqPOLtJTlyDcs
    acme-server->>+wire-server: GET /.well-known/acme-challenge/wDfFhWzJFBxL12zOtdK7vGdweJy8kstx
    wire-server->>-acme-server: 200
    acme-server->>+wire-server: GET /.well-known/acme-challenge/0ZxU3Yy7tJD3zjpvZb9gdBq8nzFIx9cc
    wire-server->>-acme-server: 200
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/wire-acme/certificate/p0uJ5KxM0xGboVpvo4sEsXwoomzQIgMc
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55093/acme/wire-acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55093/acme/wire-acme/new-nonce",
  "newAccount": "https://localhost:55093/acme/wire-acme/new-account",
  "newOrder": "https://localhost:55093/acme/wire-acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55093/acme/wire-acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
replay-nonce: UWpMcEx2MzNKbHZZMWNSRzQyNjJCeFJDNFBrMkVVNnA
```
```json
"UWpMcEx2MzNKbHZZMWNSRzQyNjJCeFJDNFBrMkVVNnA"
```
#### 5. create a new account
```http request
POST https://localhost:55093/acme/wire-acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6Imxod2RFMjBQMUhiVm04cVpoSG5wbDZfVnkzRy1iTG5fNkI5VTc0Nnh0NzB6M0dHMDk2S3F6Y3Nzb2U3U3BIREYiLCJ5IjoiNi1uQXNiNGg5aUU4WGowNUxWRlZUNzJFNVdZYTZMN1hnaE93SkMwdWtiUG5qYnVoSVhIb1dsLVl0VndDSHotbCJ9LCJub25jZSI6IlVXcE1jRXgyTXpOS2JIWlpNV05TUnpReU5qSkNlRkpETkZCck1rVlZObkEiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9uZXctYWNjb3VudCJ9",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "KnaWgT6USf6_aC_vvyGMjXq3O3oJt4xU-Sg5QMfapA4VusM9IbmQ68IQPsThgTwGl9Ayv7rvT2MUctopGQExM09b1DHzZIG6U0RAwlXMAB4K7j4-hSIqog-ucAPBUr5M"
}
...decoded...
{
  "protected": {
    "alg": "ES384",
    "typ": "JWT",
    "jwk": {
      "kty": "EC",
      "crv": "P-384",
      "x": "lhwdE20P1HbVm8qZhHnpl6_Vy3G-bLn_6B9U746xt70z3GG096Kqzcssoe7SpHDF",
      "y": "6-nAsb4h9iE8Xj05LVFVT72E5WYa6L7XghOwJC0ukbPnjbuhIXHoWl-YtVwCHz-l"
    },
    "nonce": "UWpMcEx2MzNKbHZZMWNSRzQyNjJCeFJDNFBrMkVVNnA",
    "url": "https://localhost:55093/acme/wire-acme/new-account"
  },
  "payload": {
    "termsOfServiceAgreed": true,
    "contact": [
      "unknown@example.com"
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
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/account/LpFFSPjN7NlzdBBfS6DePS8XzukFUwyd
replay-nonce: d3E5NUtWVkRZZWpDTFFSR0drZVE3QUpuNkVGZ01wMnM
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55093/acme/wire-acme/account/LpFFSPjN7NlzdBBfS6DePS8XzukFUwyd/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55093/acme/wire-acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvTHBGRlNQak43Tmx6ZEJCZlM2RGVQUzhYenVrRlV3eWQiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImQzRTVOVXRXVmtSWlpXcERURkZTUjBkclpWRTNRVXB1TmtWR1owMXdNbk0iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9uZXctb3JkZXIifQ",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6ImRucyIsInZhbHVlIjoiaWRwLmV4YW1wbGUuY29tIn0seyJ0eXBlIjoiZG5zIiwidmFsdWUiOiJ3aXJlLmV4YW1wbGUuY29tIn1dLCJub3RCZWZvcmUiOiIyMDIzLTAxLTIwVDA5OjAzOjQyLjQ1NjEzNloiLCJub3RBZnRlciI6IjIwMjMtMDEtMjBUMTA6MDM6NDIuNDU2MTM2WiJ9",
  "signature": "VIqFstN2jA7kawo0zaHYYgr914Lb1vYkmtSvzF5ojqc4Y7q9LIKeoAByKFXPCDIA9Gv-z3I4ozcybRcMNDEQqKwGe8_ToRkBqlhoaCvYyXLIHmHLwG1eTmgGkMDD8aKa"
}
...decoded...
{
  "protected": {
    "alg": "ES384",
    "kid": "https://localhost:55093/acme/wire-acme/account/LpFFSPjN7NlzdBBfS6DePS8XzukFUwyd",
    "typ": "JWT",
    "nonce": "d3E5NUtWVkRZZWpDTFFSR0drZVE3QUpuNkVGZ01wMnM",
    "url": "https://localhost:55093/acme/wire-acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "dns",
        "value": "idp.example.com"
      },
      {
        "type": "dns",
        "value": "wire.example.com"
      }
    ],
    "notBefore": "2023-01-20T09:03:42.456136Z",
    "notAfter": "2023-01-20T10:03:42.456136Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ
replay-nonce: SE9PV1A3Szg2WnNZalZUcTB0UUlHSjhJRGo3eFdubXo
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55093/acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55093/acme/wire-acme/authz/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n",
    "https://localhost:55093/acme/wire-acme/authz/RGtKG0QtpxehybPXeDx7MpAHzjvl6JMu"
  ],
  "expires": "2023-01-21T09:03:42Z",
  "notBefore": "2023-01-20T09:03:42.456136Z",
  "notAfter": "2023-01-20T10:03:42.456136Z"
}
```
### Display-name and handle already authorized
#### 9. fetch first challenge
```http request
POST https://localhost:55093/acme/wire-acme/authz/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvTHBGRlNQak43Tmx6ZEJCZlM2RGVQUzhYenVrRlV3eWQiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlNFOVBWMUEzU3pnMlduTlphbFpVY1RCMFVVbEhTamhKUkdvM2VGZHViWG8iLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9hdXRoei9uUWJwYmRUdm1uZlJTZFN1dHpvY3E1cDU5dEoxUGEybiJ9",
  "payload": "",
  "signature": "QytmuhRMwz8UwrF4HzE24v3voVCj73iWJmXC4t_x4_1ftsQQuZuw3Yg4vrgsUZ4JaBQ1-W34EEb7wi8aPkyrLLvVZf_1hozSKOz6IsPcwKyxFz2z9Y5hTF3jQ5UpASUb"
}
```
#### 10. get back first challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/authz/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n
replay-nonce: bEVGdlRMRlNXR2tDMVNOQmdOQlAwTlduUzJrbXRnMk8
```
```json
{
  "status": "pending",
  "expires": "2023-01-21T09:03:42Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n/MmwhPsP6Ii0O2Mjd3AGE9EEFKZpe7xLb",
      "status": "pending",
      "token": "wDfFhWzJFBxL12zOtdK7vGdweJy8kstx"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n/FGvxJ9F3uJPLPZz2HqLTqPOLtJTlyDcs",
      "status": "pending",
      "token": "wDfFhWzJFBxL12zOtdK7vGdweJy8kstx"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n/wAY2bd9Jq1QmSGCmUFgLkeoqnvHDmRWS",
      "status": "pending",
      "token": "wDfFhWzJFBxL12zOtdK7vGdweJy8kstx"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "idp.example.com"
  }
}
```
### ACME provides a Wire client ID challenge
#### 11. fetch second challenge
```http request
POST https://localhost:55093/acme/wire-acme/authz/RGtKG0QtpxehybPXeDx7MpAHzjvl6JMu
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvTHBGRlNQak43Tmx6ZEJCZlM2RGVQUzhYenVrRlV3eWQiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImJFVkdkbFJNUmxOWFIydERNVk5PUW1kT1FsQXdUbGR1VXpKcmJYUm5NazgiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9hdXRoei9SR3RLRzBRdHB4ZWh5YlBYZUR4N01wQUh6anZsNkpNdSJ9",
  "payload": "",
  "signature": "H1dWgJtThqHKuQ4WTcAaHOJBwKa-rCezE82G-cTOq3yE2YHocyu5FdUy4DpL1kv-ZgDGvxf0LEJdtQWywKTeVX83yXJRvZoyWPkDO3UAc_l8KBUeQ_dY_z3GXfyUrJ2h"
}
```
#### 12. get back second challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/authz/RGtKG0QtpxehybPXeDx7MpAHzjvl6JMu
replay-nonce: bDIxMW9OamdIeGd1cnNKVW5ob1FRTXB5VlBMZG1LZnc
```
```json
{
  "status": "pending",
  "expires": "2023-01-21T09:03:42Z",
  "challenges": [
    {
      "type": "dns-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/RGtKG0QtpxehybPXeDx7MpAHzjvl6JMu/NJiEyNQxTWXruvY9VYDFqysSbHyV0NTX",
      "status": "pending",
      "token": "0ZxU3Yy7tJD3zjpvZb9gdBq8nzFIx9cc"
    },
    {
      "type": "http-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/RGtKG0QtpxehybPXeDx7MpAHzjvl6JMu/xMcLxhuDXvTJ6pnnOXlB1oPwOXEPcsCy",
      "status": "pending",
      "token": "0ZxU3Yy7tJD3zjpvZb9gdBq8nzFIx9cc"
    },
    {
      "type": "tls-alpn-01",
      "url": "https://localhost:55093/acme/wire-acme/challenge/RGtKG0QtpxehybPXeDx7MpAHzjvl6JMu/ZrjLs2xBC2G8ebJWehVGupj80ISQn3wA",
      "status": "pending",
      "token": "0ZxU3Yy7tJD3zjpvZb9gdBq8nzFIx9cc"
    }
  ],
  "identifier": {
    "type": "dns",
    "value": "wire.example.com"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 13. fetch a nonce from wire-server
```http request
GET http://localhost:63479/clients/token/nonce

```
#### 14. get wire-server nonce
```http request
200

```
```json
"WlZkSVhwcU1jQ0hZY2FGd2xsbUhoZDBFbEh0dzd0d1k"
```
#### 15. create the client Dpop token with both nonces
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzM4NCIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0zODQiLCJ4IjoibGh3ZEUyMFAxSGJWbThxWmhIbnBsNl9WeTNHLWJMbl82QjlVNzQ2eHQ3MHozR0cwOTZLcXpjc3NvZTdTcEhERiIsInkiOiI2LW5Bc2I0aDlpRThYajA1TFZGVlQ3MkU1V1lhNkw3WGdoT3dKQzB1a2JQbmpidWhJWEhvV2wtWXRWd0NIei1sIn19.eyJpYXQiOjE2NzQyMDU0MjIsImV4cCI6MTY3NDI5MTgyMiwibmJmIjoxNjc0MjA1NDIyLCJzdWIiOiJpbTp3aXJlYXBwOk5tVXpNemhsWWpBell6SXdORFV3WkdKa1kyUTNZakkzTURJMk16WTJZVEkvZjQ1NDE3ZGE1Y2U0NjkwMkB3aXJlLmNvbSIsImp0aSI6ImEwZDg5NDY5LWJhOTgtNDg2NS1iYWQ3LTc4MTY1ZWYwYTY1NCIsIm5vbmNlIjoiV2xaa1NWaHdjVTFqUTBoWlkyRkdkMnhzYlVob1pEQkZiRWgwZHpkMGQxayIsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwOi8vbG9jYWxob3N0OjYzNDc5L2NsaWVudHMvMTc2MDU3MjMwNjk5MjY4OTM4MjYvYWNjZXNzLXRva2VuIiwiY2hhbCI6IndEZkZoV3pKRkJ4TDEyek90ZEs3dkdkd2VKeThrc3R4In0.8Rr2St4HAQTb7BAu-eT3SGy_QeXaad3FkGkQwIUqWsYZrLtjOOnBmx1DGESgnCd1mmvH7LnkB8UPRrIiZJdn8hpp9bI1zNRZcgxBuzCpa3SlM1Ae8X9PZsabhlghbKtc)
```http request
POST http://localhost:63479/clients/17605723069926893826/access-token

```
#### 16. get a Dpop access token from wire-server
```http request
200

```
Token [here](https://jwt.io/#id_token=eyJhbGciOiJFUzM4NCIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMzg0IiwieCI6IlFvWHlCNWQxQk1POHRIVEFwODkycDRIb2J1dTFfTXdsNW9JWWdGNG1wQWgzUnRWNFhlTGNldDkwUWFaTzFkbGoiLCJ5IjoiMnVVNWV6MUk1UThKTXVSZVhiQnJ1N0U0TlIzLVlxSUJ0Qy11TEtnbjBHUlMwZXJQZFR1V1FyeXFPLXJxM1NtbSJ9fQ.eyJpYXQiOjE2NzQyMDU0MjIsImV4cCI6MTY4MTk4MTQyMiwibmJmIjoxNjc0MjA1NDIyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjYzNDc5L2NsaWVudHMvMTc2MDU3MjMwNjk5MjY4OTM4MjYvYWNjZXNzLXRva2VuIiwic3ViIjoiaW06d2lyZWFwcDpObVV6TXpobFlqQXpZekl3TkRVd1pHSmtZMlEzWWpJM01ESTJNelkyWVRJL2Y0NTQxN2RhNWNlNDY5MDJAd2lyZS5jb20iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjYzNDc5L2NsaWVudHMvMTc2MDU3MjMwNjk5MjY4OTM4MjYvYWNjZXNzLXRva2VuIiwianRpIjoiN2EyZThhZjItNTk1ZS00YmQ0LWIzNDAtZTg4OGE0MDdiNTY0Iiwibm9uY2UiOiJXbFprU1Zod2NVMWpRMGhaWTJGR2QyeHNiVWhvWkRCRmJFaDBkemQwZDFrIiwiY2hhbCI6IndEZkZoV3pKRkJ4TDEyek90ZEs3dkdkd2VKeThrc3R4IiwiY25mIjp7ImtpZCI6IlVyQTd2aGxvdkNzSlR1Zl96TXFsNDc1aTZxbUlKUUI1dWhmUHFOOTV5SlpLTGpVS1BxRU5hc21ieXRYRG5YbUkifSwicHJvb2YiOiJleUpoYkdjaU9pSkZVek00TkNJc0luUjVjQ0k2SW1Sd2IzQXJhbmQwSWl3aWFuZHJJanA3SW10MGVTSTZJa1ZESWl3aVkzSjJJam9pVUMwek9EUWlMQ0o0SWpvaWJHaDNaRVV5TUZBeFNHSldiVGh4V21oSWJuQnNObDlXZVROSExXSk1ibDgyUWpsVk56UTJlSFEzTUhvelIwY3dPVFpMY1hwamMzTnZaVGRUY0VoRVJpSXNJbmtpT2lJMkxXNUJjMkkwYURscFJUaFlhakExVEZaR1ZsUTNNa1UxVjFsaE5rdzNXR2RvVDNkS1F6QjFhMkpRYm1waWRXaEpXRWh2VjJ3dFdYUldkME5JZWkxc0luMTkuZXlKcFlYUWlPakUyTnpReU1EVTBNaklzSW1WNGNDSTZNVFkzTkRJNU1UZ3lNaXdpYm1KbUlqb3hOamMwTWpBMU5ESXlMQ0p6ZFdJaU9pSnBiVHAzYVhKbFlYQndPazV0VlhwTmVtaHNXV3BCZWxsNlNYZE9SRlYzV2tkS2Exa3lVVE5aYWtrelRVUkpNazE2V1RKWlZFa3ZaalExTkRFM1pHRTFZMlUwTmprd01rQjNhWEpsTG1OdmJTSXNJbXAwYVNJNkltRXdaRGc1TkRZNUxXSmhPVGd0TkRnMk5TMWlZV1EzTFRjNE1UWTFaV1l3WVRZMU5DSXNJbTV2Ym1ObElqb2lWMnhhYTFOV2FIZGpWVEZxVVRCb1dsa3lSa2RrTW5oellsVm9iMXBFUWtaaVJXZ3daSHBrTUdReGF5SXNJbWgwYlNJNklsQlBVMVFpTENKb2RIVWlPaUpvZEhSd09pOHZiRzlqWVd4b2IzTjBPall6TkRjNUwyTnNhV1Z1ZEhNdk1UYzJNRFUzTWpNd05qazVNalk0T1RNNE1qWXZZV05qWlhOekxYUnZhMlZ1SWl3aVkyaGhiQ0k2SW5kRVprWm9WM3BLUmtKNFRERXllazkwWkVzM2RrZGtkMlZLZVRocmMzUjRJbjAuOFJyMlN0NEhBUVRiN0JBdS1lVDNTR3lfUWVYYWFkM0ZrR2tRd0lVcVdzWVpyTHRqT09uQm14MURHRVNnbkNkMW1tdkg3TG5rQjhVUFJySWlaSmRuOGhwcDliSTF6TlJaY2d4QnV6Q3BhM1NsTTFBZThYOVBac2FiaGxnaGJLdGMiLCJjbGllbnRfaWQiOiJpbTp3aXJlYXBwOk5tVXpNemhsWWpBell6SXdORFV3WkdKa1kyUTNZakkzTURJMk16WTJZVEkvZjQ1NDE3ZGE1Y2U0NjkwMkB3aXJlLmNvbSIsImFwaV92ZXJzaW9uIjozLCJzY29wZSI6IndpcmVfY2xpZW50X2lkIn0.FlEJ7I3uZ80XLnhXMJRyEZxnhreu0Rnrr8ITfZ85LUTEvmA7VWTVIk6owkLOAA6Vvj4XaUWE8Tt--WsS-A6pYaqzquqnIu5sfWldTppejLiR-HQZ8mAuDlFkGXFpqVnW)
### Client provides access token
#### 17. send DPoP access token to acme server to have it validated
```http request
POST https://localhost:55093/acme/wire-acme/challenge/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n/FGvxJ9F3uJPLPZz2HqLTqPOLtJTlyDcs
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvTHBGRlNQak43Tmx6ZEJCZlM2RGVQUzhYenVrRlV3eWQiLCJ0eXAiOiJKV1QiLCJub25jZSI6ImJESXhNVzlPYW1kSWVHZDFjbk5LVlc1b2IxRlJUWEI1VmxCTVpHMUxabmMiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9jaGFsbGVuZ2UvblFicGJkVHZtbmZSU2RTdXR6b2NxNXA1OXRKMVBhMm4vRkd2eEo5RjN1SlBMUFp6MkhxTFRxUE9MdEpUbHlEY3MifQ",
  "payload": "",
  "signature": "PhHLyHcotj2NmcccOlWYIYdpGYQ2RJoFzXebzcqp7jlxt2jR_5cq1baA_H8aZCEnS-PH_6p0ihH7tJbPJREHC7xUj_6trl9__0yRR3ReO_3s162jI5N38nagtrQ9yxdQ"
}
```
#### 18. acme server verifies client-id with an http challenge
```http request
GET http://wire.com/.well-known/acme-challenge/wDfFhWzJFBxL12zOtdK7vGdweJy8kstx

```

#### 19. acme server verifies handle + display-name with an OIDC challenge
```http request
GET http://wire.com/.well-known/acme-challenge/0ZxU3Yy7tJD3zjpvZb9gdBq8nzFIx9cc

```

#### 20. both challenges are valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
link: <https://localhost:55093/acme/wire-acme/authz/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n>;rel="up"
location: https://localhost:55093/acme/wire-acme/challenge/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n/FGvxJ9F3uJPLPZz2HqLTqPOLtJTlyDcs
replay-nonce: WTJuRUpTc3dWSEdENnRDWUo5WnNLQVdIczJmM1hJckY
```
```json
{
  "type": "http-01",
  "url": "https://localhost:55093/acme/wire-acme/challenge/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n/FGvxJ9F3uJPLPZz2HqLTqPOLtJTlyDcs",
  "status": "valid",
  "token": "wDfFhWzJFBxL12zOtdK7vGdweJy8kstx"
}
```
### Client presents a CSR and gets its certificate
#### 21. verify the status of the order
```http request
POST https://localhost:55093/acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvTHBGRlNQak43Tmx6ZEJCZlM2RGVQUzhYenVrRlV3eWQiLCJ0eXAiOiJKV1QiLCJub25jZSI6IldqaDVaa3hWV1hWbE4zaDJURXRZZERaa1JrTkxkbU4yT0c1MFpXRjRhM0UiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9vcmRlci9xVEJGbHo4VTVBbXdVMEJCWktUZFdlUHBHM0dORkN0SiJ9",
  "payload": "",
  "signature": "GLZT5gqBEMemMQxUBnQzAvIzN183kBOcnMZ-Ph9ae4tBFcbFAGmusLXytY5RLe2KOlOXgOhDjLZa0RnjT_BQAYyk8Vl9I8muK1OKoyb9rtCj4AjENVVW7xBrkr4gPdev"
}
```
#### 22. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ
replay-nonce: TUZYYjFLWUgxUjVhQlR4TXRUeXZJNFF5TER3dmVtWGs
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55093/acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55093/acme/wire-acme/authz/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n",
    "https://localhost:55093/acme/wire-acme/authz/RGtKG0QtpxehybPXeDx7MpAHzjvl6JMu"
  ],
  "expires": "2023-01-21T09:03:42Z",
  "notBefore": "2023-01-20T09:03:42.456136Z",
  "notAfter": "2023-01-20T10:03:42.456136Z"
}
```
#### 23. create a CSR and call finalize url
```http request
POST https://localhost:55093/acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvTHBGRlNQak43Tmx6ZEJCZlM2RGVQUzhYenVrRlV3eWQiLCJ0eXAiOiJKV1QiLCJub25jZSI6IlRVWllZakZMV1VneFVqVmhRbFI0VFhSVWVYWkpORkY1VEVSM2RtVnRXR3MiLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9vcmRlci9xVEJGbHo4VTVBbXdVMEJCWktUZFdlUHBHM0dORkN0Si9maW5hbGl6ZSJ9",
  "payload": "eyJjc3IiOiJNSUlCTnpDQnZnSUJBREFBTUhZd0VBWUhLb1pJemowQ0FRWUZLNEVFQUNJRFlnQUVsaHdkRTIwUDFIYlZtOHFaaEhucGw2X1Z5M0ctYkxuXzZCOVU3NDZ4dDcwejNHRzA5NktxemNzc29lN1NwSERGNi1uQXNiNGg5aUU4WGowNUxWRlZUNzJFNVdZYTZMN1hnaE93SkMwdWtiUG5qYnVoSVhIb1dsLVl0VndDSHotbG9EOHdQUVlKS29aSWh2Y05BUWtPTVRBd0xqQXNCZ05WSFJFRUpUQWpnaEIzYVhKbExtVjRZVzF3YkdVdVkyOXRnZzlwWkhBdVpYaGhiWEJzWlM1amIyMHdDZ1lJS29aSXpqMEVBd01EYUFBd1pRSXhBS2dkZ3dWcFp4VU82SW1Ib1Bhb0tENVpMbnZZallwWkxEQ1lqcTE2RUpnY3RRUmdhSFVlX0dlSEdJOTVFME1UdmdJd1FWbkZnQXFkMURnNjZIZ0pRbXVOZHhiMjd0SXYyRTg0cVNtVERyemhWcnBkVGVRaW9JZFo2MTBKNWdjREg5LUMifQ",
  "signature": "iRILUIEnJliLJBeM2prqBSEgaYYGKh_aOD5KHoSp-8YxMrvuToZxK1VdSAiqVE_htc9tFLBbhAxoQgjeojzIkPko1rX_vAKj23KixssZgiZEDnBd8BPOAMK2uTtJFsRd"
}
...decoded...
{
  "protected": {
    "alg": "ES384",
    "kid": "https://localhost:55093/acme/wire-acme/account/LpFFSPjN7NlzdBBfS6DePS8XzukFUwyd",
    "typ": "JWT",
    "nonce": "TUZYYjFLWUgxUjVhQlR4TXRUeXZJNFF5TER3dmVtWGs",
    "url": "https://localhost:55093/acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ/finalize"
  },
  "payload": {
    "csr": "MIIBNzCBvgIBADAAMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAElhwdE20P1HbVm8qZhHnpl6_Vy3G-bLn_6B9U746xt70z3GG096Kqzcssoe7SpHDF6-nAsb4h9iE8Xj05LVFVT72E5WYa6L7XghOwJC0ukbPnjbuhIXHoWl-YtVwCHz-loD8wPQYJKoZIhvcNAQkOMTAwLjAsBgNVHREEJTAjghB3aXJlLmV4YW1wbGUuY29tgg9pZHAuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwMDaAAwZQIxAKgdgwVpZxUO6ImHoPaoKD5ZLnvYjYpZLDCYjq16EJgctQRgaHUe_GeHGI95E0MTvgIwQVnFgAqd1Dg66HgJQmuNdxb27tIv2E84qSmTDrzhVrpdTeQioIdZ610J5gcDH9-C"
  }
}
```
#### 24. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
location: https://localhost:55093/acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ
replay-nonce: WldueTZqMDUyZ05SV0VjbzlvRG8xeEFobWhPaElpb2w
```
```json
{
  "certificate": "https://localhost:55093/acme/wire-acme/certificate/p0uJ5KxM0xGboVpvo4sEsXwoomzQIgMc",
  "status": "valid",
  "finalize": "https://localhost:55093/acme/wire-acme/order/qTBFlz8U5AmwU0BBZKTdWePpG3GNFCtJ/finalize",
  "identifiers": [
    {
      "type": "dns",
      "value": "idp.example.com"
    },
    {
      "type": "dns",
      "value": "wire.example.com"
    }
  ],
  "authorizations": [
    "https://localhost:55093/acme/wire-acme/authz/nQbpbdTvmnfRSdSutzocq5p59tJ1Pa2n",
    "https://localhost:55093/acme/wire-acme/authz/RGtKG0QtpxehybPXeDx7MpAHzjvl6JMu"
  ],
  "expires": "2023-01-21T09:03:42Z",
  "notBefore": "2023-01-20T09:03:42.456136Z",
  "notAfter": "2023-01-20T10:03:42.456136Z"
}
```
#### 25. fetch the certificate
```http request
POST https://localhost:55093/acme/wire-acme/certificate/p0uJ5KxM0xGboVpvo4sEsXwoomzQIgMc
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFUzM4NCIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MDkzL2FjbWUvd2lyZS1hY21lL2FjY291bnQvTHBGRlNQak43Tmx6ZEJCZlM2RGVQUzhYenVrRlV3eWQiLCJ0eXAiOiJKV1QiLCJub25jZSI6IldsZHVlVFpxTURVeVowNVNWMFZqYnpsdlJHOHhlRUZvYldoUGFFbHBiMnciLCJ1cmwiOiJodHRwczovL2xvY2FsaG9zdDo1NTA5My9hY21lL3dpcmUtYWNtZS9jZXJ0aWZpY2F0ZS9wMHVKNUt4TTB4R2JvVnB2bzRzRXNYd29vbXpRSWdNYyJ9",
  "payload": "",
  "signature": "8pPMMtLqMVyekOESS960HCOyQ_9lOAeKji3NuAEF9BuerSTas6ykb7TwInkLjgXxzJv4aU-OS08woF57iqdXxphaK_vbFviYQiW2R6QvTqducw0nac9oQF99xOO0nN6r"
}
```
#### 26. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55093/acme/wire-acme/directory>;rel="index"
replay-nonce: eHRRQmM5QjJKZ2Q0a3RJZjhXNU1tZHRtVjFLaHhHdzM
```
```json
[
  "MIICEDCCAbegAwIBAgIQWBxu2y+aNa+h7LAQOhlZBDAKBggqhkjOPQQDAjAuMQ0w\nCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\nMzAxMjAwOTAzNDJaFw0yMzAxMjAxMDAzNDJaMAAwdjAQBgcqhkjOPQIBBgUrgQQA\nIgNiAASWHB0TbQ/UdtWbypmEeemXr9XLcb5suf/oH1TvjrG3vTPcYbT3oqrNyyyh\n7tKkcMXr6cCxviH2ITxePTktUVVPvYTlZhrovteCE7AkLS6Rs+eNu6EhcehaX5i1\nXAIfP6WjgccwgcQwDgYDVR0PAQH/BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMB\nBggrBgEFBQcDAjAdBgNVHQ4EFgQUNubpZtAeceQeVojcrgduBoIIbqgwHwYDVR0j\nBBgwFoAUBYdeFui2FMC3xde+rwfVUhHKxB8wLwYDVR0RAQH/BCUwI4IPaWRwLmV4\nYW1wbGUuY29tghB3aXJlLmV4YW1wbGUuY29tMCIGDCsGAQQBgqRkxihAAQQSMBAC\nAQYECXdpcmUtYWNtZQQAMAoGCCqGSM49BAMCA0cAMEQCIDuN2WHd725wozaBq3os\n1P39wcPY4xWDELyyc4+zIi6xAiBIRCeZ6MjDlHg6hxmn1zSkw2ZZH52OYzk28lkC\n2Fbpmg==",
  "MIIBuTCCAV+gAwIBAgIRAJdDcbalHF3srFt9bTHdTk8wCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDEyMDA5\nMDMzMFoXDTMzMDExNzA5MDMzMFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATB\nbXVWBG0zE9Sxj8h5dO0+LS0lNBd1XV0fRLgbumlhDOyhnWI7XJs3Y7qnMrYz1ZUq\nBDPigaS4PtMFQm//+3Elo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUBYdeFui2FMC3xde+rwfVUhHKxB8wHwYDVR0jBBgw\nFoAUsEWSF3ZiE5J4hw7b9xavI00SYIMwCgYIKoZIzj0EAwIDSAAwRQIgQTx6o6lp\nwSm96ghkajsBmSUKhYv4brOhtiXnZgVy8fYCIQChM/zlOIts3qShX0rF5Y5qduqy\n5XUUA7k1kHCTJBbY0Q=="
]
```