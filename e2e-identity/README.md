# Wire end to end identity example
Ed25519 - SHA256
```mermaid
sequenceDiagram
    autonumber
    wire-client->>+acme-server: GET /acme/acme/directory
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: HEAD /acme/acme/new-nonce
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/acme/new-account
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/acme/new-order
    acme-server->>-wire-client: 201
    wire-client->>+acme-server: POST /acme/acme/authz/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs
    acme-server->>-wire-client: 200
    wire-client->>+wire-server: GET //clients/token/nonce
    wire-server->>-wire-client: 200
    wire-client->>+wire-server: POST //clients/7332893846330786102/access-token
    wire-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/n7mcr316DajruQd3pDqLEbHlIsAhjih1
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/kpQYi9U70QylwrSo6AqdhM9ASeHtzjMv
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a/finalize
    acme-server->>-wire-client: 200
    wire-client->>+acme-server: POST /acme/acme/certificate/D9YM1rT8KKqhKMH9C2WbJhHwStYPHPl9
    acme-server->>-wire-client: 200
```
### Initial setup with ACME server
#### 1. fetch acme directory for hyperlinks
```http request
GET https://localhost:55195/acme/acme/directory

```
#### 2. get the ACME directory with links for newNonce, newAccount & newOrder
```http request
200
content-type: application/json
```
```json
{
  "newNonce": "https://localhost:55195/acme/acme/new-nonce",
  "newAccount": "https://localhost:55195/acme/acme/new-account",
  "newOrder": "https://localhost:55195/acme/acme/new-order"
}
```
#### 3. fetch a new nonce for the very first request
```http request
HEAD https://localhost:55195/acme/acme/new-nonce

```
#### 4. get a nonce for creating an account
```http request
200
cache-control: no-store
link: <https://localhost:55195/acme/acme/directory>;rel="index"
replay-nonce: c3dQbXFPaWh4bDVxUkpYYWtRWUZtUEN6Qm5vQUlQZlA
```
```json
"c3dQbXFPaWh4bDVxUkpYYWtRWUZtUEN6Qm5vQUlQZlA"
```
#### 5. create a new account
```http request
POST https://localhost:55195/acme/acme/new-account
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InlBd09VX0taYmhLR0dUeGdHeGNpZFFHam9SVmRjbWFQY0Z0eE5xcF9sNkkifSwibm9uY2UiOiJjM2RRYlhGUGFXaDRiRFZ4VWtwWVlXdFJXVVp0VUVONlFtNXZRVWxRWmxBIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTUxOTUvYWNtZS9hY21lL25ldy1hY2NvdW50In0",
  "payload": "eyJ0ZXJtc09mU2VydmljZUFncmVlZCI6dHJ1ZSwiY29udGFjdCI6WyJ1bmtub3duQGV4YW1wbGUuY29tIl0sIm9ubHlSZXR1cm5FeGlzdGluZyI6ZmFsc2V9",
  "signature": "Bran58MScz36cRg_VEqc6KnennWd0hFpAOrRYPJD5Mz6B44UCW-QeyjoM-yM3r5F-04-0Kw9KQDdKWWsICsABw"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "typ": "JWT",
    "jwk": {
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "yAwOU_KZbhKGGTxgGxcidQGjoRVdcmaPcFtxNqp_l6I"
    },
    "nonce": "c3dQbXFPaWh4bDVxUkpYYWtRWUZtUEN6Qm5vQUlQZlA",
    "url": "https://localhost:55195/acme/acme/new-account"
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
link: <https://localhost:55195/acme/acme/directory>;rel="index"
location: https://localhost:55195/acme/acme/account/5Qla8j6kKyv73qVSVuynAt8CzlShabxR
replay-nonce: N2tVOVNBYkFDaERIbnBMM0JSZk9MdGlTVjJ3alp3bE8
```
```json
{
  "status": "valid",
  "orders": "https://localhost:55195/acme/acme/account/5Qla8j6kKyv73qVSVuynAt8CzlShabxR/orders"
}
```
### Request a certificate with relevant identifiers
#### 7. create a new order
```http request
POST https://localhost:55195/acme/acme/new-order
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MTk1L2FjbWUvYWNtZS9hY2NvdW50LzVRbGE4ajZrS3l2NzNxVlNWdXluQXQ4Q3psU2hhYnhSIiwidHlwIjoiSldUIiwibm9uY2UiOiJOMnRWT1ZOQllrRkRhRVJJYm5CTU0wSlNaazlNZEdsVFZqSjNhbHAzYkU4IiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTUxOTUvYWNtZS9hY21lL25ldy1vcmRlciJ9",
  "payload": "eyJpZGVudGlmaWVycyI6W3sidHlwZSI6IndpcmVhcHAtaWQiLCJ2YWx1ZSI6IntcIm5hbWVcIjpcIlNtaXRoLCBBbGljZSBNIChRQSlcIixcImRvbWFpblwiOlwiZXhhbXBsZS5jb21cIixcImNsaWVudC1pZFwiOlwiaW1wcDp3aXJlYXBwPU5ERXlaR1l3TmpjMk16RmtOREJpTlRsbFltVm1NalF5WlRJek5UYzROV1EvNjVjM2FjMWExNjMxYzEzNkBleGFtcGxlLmNvbVwiLFwiaGFuZGxlXCI6XCJpbXBwOndpcmVhcHA9YWxpY2Uuc21pdGgucWFAZXhhbXBsZS5jb21cIn0ifV0sIm5vdEJlZm9yZSI6IjIwMjMtMDItMDlUMTY6NTU6NTYuMDMyMzA2WiIsIm5vdEFmdGVyIjoiMjAyMy0wMi0wOVQxNzo1NTo1Ni4wMzIzMDZaIn0",
  "signature": "NwATIFjfqLnVs22Bqo-KR4C4xd0ZiceH6g6AggHOfhRT0Wy81tz7sa_eipejUTppSLdUsBNe0UdBusFNh9ScBg"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55195/acme/acme/account/5Qla8j6kKyv73qVSVuynAt8CzlShabxR",
    "typ": "JWT",
    "nonce": "N2tVOVNBYkFDaERIbnBMM0JSZk9MdGlTVjJ3alp3bE8",
    "url": "https://localhost:55195/acme/acme/new-order"
  },
  "payload": {
    "identifiers": [
      {
        "type": "wireapp-id",
        "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NDEyZGYwNjc2MzFkNDBiNTllYmVmMjQyZTIzNTc4NWQ/65c3ac1a1631c136@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
      }
    ],
    "notBefore": "2023-02-09T16:55:56.032306Z",
    "notAfter": "2023-02-09T17:55:56.032306Z"
  }
}
```
#### 8. get new order with authorization URLS and finalize URL
```http request
201
cache-control: no-store
content-type: application/json
link: <https://localhost:55195/acme/acme/directory>;rel="index"
location: https://localhost:55195/acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a
replay-nonce: MzR1czBxS2FyeXZhYlpTcXMwOTU5R3V0bXBFTmdhRzA
```
```json
{
  "status": "pending",
  "finalize": "https://localhost:55195/acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NDEyZGYwNjc2MzFkNDBiNTllYmVmMjQyZTIzNTc4NWQ/65c3ac1a1631c136@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
    }
  ],
  "authorizations": [
    "https://localhost:55195/acme/acme/authz/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs"
  ],
  "expires": "2023-02-10T16:55:56Z",
  "notBefore": "2023-02-09T16:55:56.032306Z",
  "notAfter": "2023-02-09T17:55:56.032306Z"
}
```
### Display-name and handle already authorized
#### 9. fetch challenge
```http request
POST https://localhost:55195/acme/acme/authz/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MTk1L2FjbWUvYWNtZS9hY2NvdW50LzVRbGE4ajZrS3l2NzNxVlNWdXluQXQ4Q3psU2hhYnhSIiwidHlwIjoiSldUIiwibm9uY2UiOiJNelIxY3pCeFMyRnllWFpoWWxwVGNYTXdPVFU1UjNWMGJYQkZUbWRoUnpBIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTUxOTUvYWNtZS9hY21lL2F1dGh6L2U1WEJBTHIwV3BUY2l3Nm03cjFpaEk3bFhSYXBVbXZzIn0",
  "payload": "",
  "signature": "mKZKM5YnNkPKxpxYbfqwet6wiM4g71mvL0ysbvZuta-6C6H-Z5mxtyey3z4td9GMnpJY3Wq4qwwV6oH6qUwJCw"
}
```
#### 10. get back challenge
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55195/acme/acme/directory>;rel="index"
location: https://localhost:55195/acme/acme/authz/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs
replay-nonce: YWJTVFZjNFY5QU1IUmtIQXM5czFwbVJTYzV6RFZVc1Y
```
```json
{
  "status": "pending",
  "expires": "2023-02-10T16:55:56Z",
  "challenges": [
    {
      "type": "wire-oidc-01",
      "url": "https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/kpQYi9U70QylwrSo6AqdhM9ASeHtzjMv",
      "status": "pending",
      "token": "SY74tJmAIIhdzRtJvpx389f6EKHbXuxQ"
    },
    {
      "type": "wire-dpop-01",
      "url": "https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/n7mcr316DajruQd3pDqLEbHlIsAhjih1",
      "status": "pending",
      "token": "SY74tJmAIIhdzRtJvpx389f6EKHbXuxQ"
    }
  ],
  "identifier": {
    "type": "wireapp-id",
    "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NDEyZGYwNjc2MzFkNDBiNTllYmVmMjQyZTIzNTc4NWQ/65c3ac1a1631c136@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
  }
}
```
### Client fetches JWT DPoP access token (with wire-server)
#### 11. fetch a nonce from wire-server
```http request
GET http://localhost:59307//clients/token/nonce

```
#### 12. get wire-server nonce
```http request
200

```
```json
"b3VIOXNOZTN1UEtoaWJOU3Z0dUVubE03YWVHQWNocE0"
```
#### 13. create the client Dpop token with both nonces
[Dpop token](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImRwb3Arand0IiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoieUF3T1VfS1piaEtHR1R4Z0d4Y2lkUUdqb1JWZGNtYVBjRnR4TnFwX2w2SSJ9fQ.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJzdWIiOiJpbXBwOndpcmVhcHA9TkRFeVpHWXdOamMyTXpGa05EQmlOVGxsWW1WbU1qUXlaVEl6TlRjNE5XUS82NWMzYWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tIiwianRpIjoiNTA3OGZkZTItNTBiOC00ZmVmLWIxNDAtMzBkYTkzYjBkYzk5Iiwibm9uY2UiOiJiM1ZJT1hOT1pUTjFVRXRvYVdKT1UzWjBkVVZ1YkUwM1lXVkhRV05vY0UwIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTkzMDcvIiwiY2hhbCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRIn0.BMLKV58n7sWHMy12U-LyLsFIJGtMSJquhRFobuze9F4JA7ScvQVHGTLQveV_Qp_Q4Ne8ryOFpJaQ75UnNDtuDQ)
```http request
POST http://localhost:59307//clients/7332893846330786102/access-token

```
#### 14. get a Dpop access token from wire-server
```http request
200

```
[Access token](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InlldjZPWlVudWlwbmZrMHRWZFlLRnM5MWpSdjVoVmF6a2llTEhBTmN1UEUifX0.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY4MzczNzc1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsImp0aSI6Ijk4NGM1OTA0LWZhM2UtNDVhZi1iZGM1LTlhODMzNjkxOGUyYiIsIm5vbmNlIjoiYjNWSU9YTk9aVE4xVUV0b2FXSk9VM1owZFVWdWJFMDNZV1ZIUVdOb2NFMCIsImNoYWwiOiJTWTc0dEptQUlJaGR6UnRKdnB4Mzg5ZjZFS0hiWHV4USIsImNuZiI6eyJraWQiOiJocG9RV2xNUmtjUURKN2xNcDhaSHp4WVBNVDBJM0Vhc2VqUHZhWmlGUGpjIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZVVGM1QxVmZTMXBpYUV0SFIxUjRaMGQ0WTJsa1VVZHFiMUpXWkdOdFlWQmpSblI0VG5Gd1gydzJTU0o5ZlEuZXlKcFlYUWlPakUyTnpVNU5qRTNOVFlzSW1WNGNDSTZNVFkzTmpBME9ERTFOaXdpYm1KbUlqb3hOamMxT1RZeE56VTJMQ0p6ZFdJaU9pSnBiWEJ3T25kcGNtVmhjSEE5VGtSRmVWcEhXWGRPYW1NeVRYcEdhMDVFUW1sT1ZHeHNXVzFXYlUxcVVYbGFWRWw2VGxSak5FNVhVUzgyTldNellXTXhZVEUyTXpGak1UTTJRR1Y0WVcxd2JHVXVZMjl0SWl3aWFuUnBJam9pTlRBM09HWmtaVEl0TlRCaU9DMDBabVZtTFdJeE5EQXRNekJrWVRrellqQmtZems1SWl3aWJtOXVZMlVpT2lKaU0xWkpUMWhPVDFwVVRqRlZSWFJ2WVZkS1QxVXpXakJrVlZaMVlrVXdNMWxYVmtoUlYwNXZZMFV3SWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk5Ua3pNRGN2SWl3aVkyaGhiQ0k2SWxOWk56UjBTbTFCU1Vsb1pIcFNkRXAyY0hnek9EbG1Oa1ZMU0dKWWRYaFJJbjAuQk1MS1Y1OG43c1dITXkxMlUtTHlMc0ZJSkd0TVNKcXVoUkZvYnV6ZTlGNEpBN1NjdlFWSEdUTFF2ZVZfUXBfUTROZThyeU9GcEphUTc1VW5ORHR1RFEiLCJjbGllbnRfaWQiOiJpbXBwOndpcmVhcHA9TkRFeVpHWXdOamMyTXpGa05EQmlOVGxsWW1WbU1qUXlaVEl6TlRjNE5XUS82NWMzYWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Tf10dkKrNikGNgGhIdkrMHb0v6Jpde09MaIyBeuY6KORcxuglMGY7_V9Kd0LcVVPMDy1q4xbd39ZqosGz1NUBQ)
### Client provides access token
#### 15. validate Dpop challenge (clientId)
```http request
POST https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/n7mcr316DajruQd3pDqLEbHlIsAhjih1
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MTk1L2FjbWUvYWNtZS9hY2NvdW50LzVRbGE4ajZrS3l2NzNxVlNWdXluQXQ4Q3psU2hhYnhSIiwidHlwIjoiSldUIiwibm9uY2UiOiJZV0pUVkZaak5GWTVRVTFJVW10SVFYTTVjekZ3YlZKVFl6VjZSRlpWYzFZIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTUxOTUvYWNtZS9hY21lL2NoYWxsZW5nZS9lNVhCQUxyMFdwVGNpdzZtN3IxaWhJN2xYUmFwVW12cy9uN21jcjMxNkRhanJ1UWQzcERxTEViSGxJc0FoamloMSJ9",
  "payload": "eyJhY2Nlc3NfdG9rZW4iOiJleUpoYkdjaU9pSkZaRVJUUVNJc0luUjVjQ0k2SW1GMEsycDNkQ0lzSW1wM2F5STZleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNklubGxkalpQV2xWdWRXbHdibVpyTUhSV1pGbExSbk01TVdwU2RqVm9WbUY2YTJsbFRFaEJUbU4xVUVVaWZYMC5leUpwWVhRaU9qRTJOelU1TmpFM05UWXNJbVY0Y0NJNk1UWTRNemN6TnpjMU5pd2libUptSWpveE5qYzFPVFl4TnpVMkxDSnBjM01pT2lKb2RIUndPaTh2Ykc5allXeG9iM04wT2pVNU16QTNMeUlzSW5OMVlpSTZJbWx0Y0hBNmQybHlaV0Z3Y0QxT1JFVjVXa2RaZDA1cVl6Sk5la1pyVGtSQ2FVNVViR3haYlZadFRXcFJlVnBVU1hwT1ZHTTBUbGRSTHpZMVl6TmhZekZoTVRZek1XTXhNelpBWlhoaGJYQnNaUzVqYjIwaUxDSmhkV1FpT2lKb2RIUndPaTh2Ykc5allXeG9iM04wT2pVNU16QTNMeUlzSW1wMGFTSTZJams0TkdNMU9UQTBMV1poTTJVdE5EVmhaaTFpWkdNMUxUbGhPRE16TmpreE9HVXlZaUlzSW01dmJtTmxJam9pWWpOV1NVOVlUazlhVkU0eFZVVjBiMkZYU2s5Vk0xb3daRlZXZFdKRk1ETlpWMVpJVVZkT2IyTkZNQ0lzSW1Ob1lXd2lPaUpUV1RjMGRFcHRRVWxKYUdSNlVuUktkbkI0TXpnNVpqWkZTMGhpV0hWNFVTSXNJbU51WmlJNmV5SnJhV1FpT2lKb2NHOVJWMnhOVW10alVVUktOMnhOY0RoYVNIcDRXVkJOVkRCSk0wVmhjMlZxVUhaaFdtbEdVR3BqSW4wc0luQnliMjltSWpvaVpYbEthR0pIWTJsUGFVcEdXa1ZTVkZGVFNYTkpibEkxWTBOSk5rbHRVbmRpTTBGeVlXNWtNRWxwZDJsaGJtUnlTV3B3TjBsdGREQmxVMGsyU1dzNVRGVkRTWE5KYlU1NVpHbEpOa2xyVm10TmFsVXhUVlJyYVV4RFNqUkphbTlwWlZWR00xUXhWbVpUTVhCcFlVVjBTRkl4VWpSYU1HUTBXVEpzYTFWVlpIRmlNVXBYV2tkT2RGbFdRbXBTYmxJMFZHNUdkMWd5ZHpKVFUwbzVabEV1WlhsS2NGbFlVV2xQYWtVeVRucFZOVTVxUlROT1ZGbHpTVzFXTkdORFNUWk5WRmt6VG1wQk1FOUVSVEZPYVhkcFltMUtiVWxxYjNoT2FtTXhUMVJaZUU1NlZUSk1RMHA2WkZkSmFVOXBTbkJpV0VKM1QyNWtjR050Vm1oalNFRTVWR3RTUm1WV2NFaFhXR1JQWVcxTmVWUlljRWRoTURWRlVXMXNUMVpIZUhOWFZ6RlhZbFV4Y1ZWWWJHRldSV3cyVkd4U2FrNUZOVmhWVXpneVRsZE5lbGxYVFhoWlZFVXlUWHBHYWsxVVRUSlJSMVkwV1ZjeGQySkhWWFZaTWpsMFNXbDNhV0Z1VW5CSmFtOXBUbFJCTTA5SFdtdGFWRWwwVGxSQ2FVOURNREJhYlZadFRGZEplRTVFUVhSTmVrSnJXVlJyZWxscVFtdFplbXMxU1dsM2FXSnRPWFZaTWxWcFQybEthVTB4V2twVU1XaFBWREZ3VlZScVJsWlNXRkoyV1Zaa1MxUXhWWHBYYWtKclZsWmFNVmxyVlhkTk1XeFlWbXRvVWxZd05YWlpNRlYzU1dsM2FXRklVblJKYW05cFZVVTVWRlpEU1hOSmJXZ3daRk5KTmtsdGFEQmtTRUUyVEhrNWMySXlUbWhpUjJoMll6TlJOazVVYTNwTlJHTjJTV2wzYVZreWFHaGlRMGsyU1d4T1drNTZVakJUYlRGQ1UxVnNiMXBJY0ZOa1JYQXlZMGhuZWs5RWJHMU9hMVpNVTBkS1dXUllhRkpKYmpBdVFrMU1TMVkxT0c0M2MxZElUWGt4TWxVdFRIbE1jMFpKU2tkMFRWTktjWFZvVWtadlluVjZaVGxHTkVwQk4xTmpkbEZXU0VkVVRGRjJaVlpmVVhCZlVUUk9aVGh5ZVU5R2NFcGhVVGMxVlc1T1JIUjFSRkVpTENKamJHbGxiblJmYVdRaU9pSnBiWEJ3T25kcGNtVmhjSEE5VGtSRmVWcEhXWGRPYW1NeVRYcEdhMDVFUW1sT1ZHeHNXVzFXYlUxcVVYbGFWRWw2VGxSak5FNVhVUzgyTldNellXTXhZVEUyTXpGak1UTTJRR1Y0WVcxd2JHVXVZMjl0SWl3aVlYQnBYM1psY25OcGIyNGlPak1zSW5OamIzQmxJam9pZDJseVpWOWpiR2xsYm5SZmFXUWlmUS5UZjEwZGtLck5pa0dOZ0doSWRrck1IYjB2NkpwZGUwOU1hSXlCZXVZNktPUmN4dWdsTUdZN19WOUtkMExjVlZQTUR5MXE0eGJkMzlacW9zR3oxTlVCUSJ9",
  "signature": "cp7aKVcDAczS5OxzT8T0KHNl741_fMK68TDqwM2UHLr-7kLrEpO-PYgFxOLBz1Nw0JIAizqn7DpSy73LVuIdAA"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55195/acme/acme/account/5Qla8j6kKyv73qVSVuynAt8CzlShabxR",
    "typ": "JWT",
    "nonce": "YWJTVFZjNFY5QU1IUmtIQXM5czFwbVJTYzV6RFZVc1Y",
    "url": "https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/n7mcr316DajruQd3pDqLEbHlIsAhjih1"
  },
  "payload": {
    "access_token": "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InlldjZPWlVudWlwbmZrMHRWZFlLRnM5MWpSdjVoVmF6a2llTEhBTmN1UEUifX0.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY4MzczNzc1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsImp0aSI6Ijk4NGM1OTA0LWZhM2UtNDVhZi1iZGM1LTlhODMzNjkxOGUyYiIsIm5vbmNlIjoiYjNWSU9YTk9aVE4xVUV0b2FXSk9VM1owZFVWdWJFMDNZV1ZIUVdOb2NFMCIsImNoYWwiOiJTWTc0dEptQUlJaGR6UnRKdnB4Mzg5ZjZFS0hiWHV4USIsImNuZiI6eyJraWQiOiJocG9RV2xNUmtjUURKN2xNcDhaSHp4WVBNVDBJM0Vhc2VqUHZhWmlGUGpjIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZVVGM1QxVmZTMXBpYUV0SFIxUjRaMGQ0WTJsa1VVZHFiMUpXWkdOdFlWQmpSblI0VG5Gd1gydzJTU0o5ZlEuZXlKcFlYUWlPakUyTnpVNU5qRTNOVFlzSW1WNGNDSTZNVFkzTmpBME9ERTFOaXdpYm1KbUlqb3hOamMxT1RZeE56VTJMQ0p6ZFdJaU9pSnBiWEJ3T25kcGNtVmhjSEE5VGtSRmVWcEhXWGRPYW1NeVRYcEdhMDVFUW1sT1ZHeHNXVzFXYlUxcVVYbGFWRWw2VGxSak5FNVhVUzgyTldNellXTXhZVEUyTXpGak1UTTJRR1Y0WVcxd2JHVXVZMjl0SWl3aWFuUnBJam9pTlRBM09HWmtaVEl0TlRCaU9DMDBabVZtTFdJeE5EQXRNekJrWVRrellqQmtZems1SWl3aWJtOXVZMlVpT2lKaU0xWkpUMWhPVDFwVVRqRlZSWFJ2WVZkS1QxVXpXakJrVlZaMVlrVXdNMWxYVmtoUlYwNXZZMFV3SWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk5Ua3pNRGN2SWl3aVkyaGhiQ0k2SWxOWk56UjBTbTFCU1Vsb1pIcFNkRXAyY0hnek9EbG1Oa1ZMU0dKWWRYaFJJbjAuQk1MS1Y1OG43c1dITXkxMlUtTHlMc0ZJSkd0TVNKcXVoUkZvYnV6ZTlGNEpBN1NjdlFWSEdUTFF2ZVZfUXBfUTROZThyeU9GcEphUTc1VW5ORHR1RFEiLCJjbGllbnRfaWQiOiJpbXBwOndpcmVhcHA9TkRFeVpHWXdOamMyTXpGa05EQmlOVGxsWW1WbU1qUXlaVEl6TlRjNE5XUS82NWMzYWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Tf10dkKrNikGNgGhIdkrMHb0v6Jpde09MaIyBeuY6KORcxuglMGY7_V9Kd0LcVVPMDy1q4xbd39ZqosGz1NUBQ"
  }
}
```
#### 16. client id challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55195/acme/acme/directory>;rel="index"
link: <https://localhost:55195/acme/acme/authz/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs>;rel="up"
location: https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/n7mcr316DajruQd3pDqLEbHlIsAhjih1
replay-nonce: em1LdldUZ2NQUmxXSEhrOEJTUTdSUzZGVDN5NTRPems
```
```json
{
  "type": "wire-dpop-01",
  "url": "https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/n7mcr316DajruQd3pDqLEbHlIsAhjih1",
  "status": "valid",
  "token": "SY74tJmAIIhdzRtJvpx389f6EKHbXuxQ"
}
```
#### 17. validate oidc challenge (userId + displayName)
[Id token](https://jwt.io/#id_token=eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ)
```http request
POST https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/kpQYi9U70QylwrSo6AqdhM9ASeHtzjMv
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MTk1L2FjbWUvYWNtZS9hY2NvdW50LzVRbGE4ajZrS3l2NzNxVlNWdXluQXQ4Q3psU2hhYnhSIiwidHlwIjoiSldUIiwibm9uY2UiOiJlbTFMZGxkVVoyTlFVbXhYU0Vock9FSlRVVGRTVXpaR1ZETjVOVFJQZW1zIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTUxOTUvYWNtZS9hY21lL2NoYWxsZW5nZS9lNVhCQUxyMFdwVGNpdzZtN3IxaWhJN2xYUmFwVW12cy9rcFFZaTlVNzBReWx3clNvNkFxZGhNOUFTZUh0empNdiJ9",
  "payload": "eyJpZF90b2tlbiI6ImV5SmhiR2NpT2lKRlpFUlRRU0lzSW5SNWNDSTZJa3BYVkNKOS5leUpwWVhRaU9qRTJOelU1TmpFM05UWXNJbVY0Y0NJNk1UWTNOakEwT0RFMU5pd2libUptSWpveE5qYzFPVFl4TnpVMkxDSnBjM01pT2lKb2RIUndPaTh2YVdSd0x5SXNJbk4xWWlJNkltbHRjSEE2ZDJseVpXRndjRDFPUkVWNVdrZFpkMDVxWXpKTmVrWnJUa1JDYVU1VWJHeFpiVlp0VFdwUmVWcFVTWHBPVkdNMFRsZFJMelkxWXpOaFl6RmhNVFl6TVdNeE16WkFaWGhoYlhCc1pTNWpiMjBpTENKaGRXUWlPaUpvZEhSd09pOHZhV1J3THlJc0ltNWhiV1VpT2lKVGJXbDBhQ3dnUVd4cFkyVWdUU0FvVVVFcElpd2lhR0Z1Wkd4bElqb2lhVzF3Y0RwM2FYSmxZWEJ3UFdGc2FXTmxMbk50YVhSb0xuRmhRR1Y0WVcxd2JHVXVZMjl0SWl3aWEyVjVZWFYwYUNJNklsTlpOelIwU20xQlNVbG9aSHBTZEVwMmNIZ3pPRGxtTmtWTFNHSllkWGhSTGkxNVYyOVpWRGxJUWxZd2IwWk1WRWxTUkd3M2NqaFBjbFpHTkZKQ1ZqaE9WbEZPYkV3M2NVeGpiV2NpZlEuMGlpcTNwNUJtbXA4ZWtvRnF2NGpRdV9Hcm5QYkVmeEozNlNDdXctVXZWNmhDaTZHbHhPd1U3Z3d3dGd1YWpoc2Qxc2VkbkdXWnBOOFFzc0tJNV9DRFEifQ",
  "signature": "k9HCAvfbXNG1PQkEjTfsfHvKPHVpN6a86fOk59LSt7i2pxBVCoKnVSR6eBcW-W2p8gdwcg2ylhW8aKKKHP1iBQ"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55195/acme/acme/account/5Qla8j6kKyv73qVSVuynAt8CzlShabxR",
    "typ": "JWT",
    "nonce": "em1LdldUZ2NQUmxXSEhrOEJTUTdSUzZGVDN5NTRPems",
    "url": "https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/kpQYi9U70QylwrSo6AqdhM9ASeHtzjMv"
  },
  "payload": {
    "id_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ"
  }
}
```
#### 18. handle challenge is valid
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55195/acme/acme/directory>;rel="index"
link: <https://localhost:55195/acme/acme/authz/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs>;rel="up"
location: https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/kpQYi9U70QylwrSo6AqdhM9ASeHtzjMv
replay-nonce: bkl4QTEwQWpjY0htY2hSc0V1ME9XclN2ZEVSenNrU2o
```
```json
{
  "type": "wire-oidc-01",
  "url": "https://localhost:55195/acme/acme/challenge/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs/kpQYi9U70QylwrSo6AqdhM9ASeHtzjMv",
  "status": "valid",
  "token": "SY74tJmAIIhdzRtJvpx389f6EKHbXuxQ"
}
```
### Client presents a CSR and gets its certificate
#### 19. verify the status of the order
```http request
POST https://localhost:55195/acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MTk1L2FjbWUvYWNtZS9hY2NvdW50LzVRbGE4ajZrS3l2NzNxVlNWdXluQXQ4Q3psU2hhYnhSIiwidHlwIjoiSldUIiwibm9uY2UiOiJia2w0UVRFd1FXcGpZMGh0WTJoU2MwVjFNRTlYY2xOMlpFVlNlbk5yVTJvIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTUxOTUvYWNtZS9hY21lL29yZGVyL2ludXFFM3hZVGwxTk9yd2dyV28xVHZORG5PTmxOOTRhIn0",
  "payload": "",
  "signature": "Rf_A1CJxnL-UOYPn75hFaolVS3M_K6uY5pVVFMgtFGngrSTRqwUIxqP17ohZV7Sg20er_8Cmf4_-YfniJk8CAw"
}
```
#### 20. loop (with exponential backoff) until order is ready
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55195/acme/acme/directory>;rel="index"
location: https://localhost:55195/acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a
replay-nonce: ZkxwZmhSdW1QWmhMVVd5clM0TGhQTVl1SmZ6UmYwN3o
```
```json
{
  "status": "ready",
  "finalize": "https://localhost:55195/acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NDEyZGYwNjc2MzFkNDBiNTllYmVmMjQyZTIzNTc4NWQ/65c3ac1a1631c136@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
    }
  ],
  "authorizations": [
    "https://localhost:55195/acme/acme/authz/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs"
  ],
  "expires": "2023-02-10T16:55:56Z",
  "notBefore": "2023-02-09T16:55:56.032306Z",
  "notAfter": "2023-02-09T17:55:56.032306Z"
}
```
#### 21. create a CSR and call finalize url
```http request
POST https://localhost:55195/acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a/finalize
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MTk1L2FjbWUvYWNtZS9hY2NvdW50LzVRbGE4ajZrS3l2NzNxVlNWdXluQXQ4Q3psU2hhYnhSIiwidHlwIjoiSldUIiwibm9uY2UiOiJaa3h3Wm1oU2RXMVFXbWhNVlZkNWNsTTBUR2hRVFZsMVNtWjZVbVl3TjNvIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTUxOTUvYWNtZS9hY21lL29yZGVyL2ludXFFM3hZVGwxTk9yd2dyV28xVHZORG5PTmxOOTRhL2ZpbmFsaXplIn0",
  "payload": "eyJjc3IiOiJNSUlCV0RDQ0FRb0NBUUF3TkRFY01Cb0dBMVVFQXd3VFUyMXBkR2dzSUVGc2FXTmxJRTBnS0ZGQktURVVNQklHQTFVRUNnd0xaWGhoYlhCc1pTNWpiMjB3S2pBRkJnTXJaWEFESVFESURBNVQ4cGx1RW9ZWlBHQWJGeUoxQWFPaEZWMXlabzl3VzNFMnFuLVhvcUNCb2pDQm53WUpLb1pJaHZjTkFRa09NWUdSTUlHT01JR0xCZ05WSFJFRWdZTXdnWUNHVldsdGNIQTZkMmx5WldGd2NEMXVaR1Y1ZW1kNWQyNXFZekp0ZW1acmJtUmlhVzUwYkd4NWJYWnRiV3B4ZVhwMGFYcHVkR00wYm5keEx6WTFZek5oWXpGaE1UWXpNV014TXpaQVpYaGhiWEJzWlM1amIyMkdKMmx0Y0hBNmQybHlaV0Z3Y0QxaGJHbGpaUzV6YldsMGFDNXhZVUJsZUdGdGNHeGxMbU52YlRBRkJnTXJaWEFEUVFCQ05pQk5DeHFyQmp3MXFTLUg4bWVrdUp1R1kzUlQ4a05jLVVTbk9DZEM0eG1vNGxIaXY0QzFjNGFvQUtCTUNuVXpwVVFBVEVoRTVLUEFLVlo4VVVvRSJ9",
  "signature": "TevcJuvviY1Id0hUQfKuS23YJig7kRNZahwaTD-h5unkPF62R4z3jSXxwMnlhTyijZTjFvKYtysc_gH95r3TCQ"
}
...decoded...
{
  "protected": {
    "alg": "EdDSA",
    "kid": "https://localhost:55195/acme/acme/account/5Qla8j6kKyv73qVSVuynAt8CzlShabxR",
    "typ": "JWT",
    "nonce": "ZkxwZmhSdW1QWmhMVVd5clM0TGhQTVl1SmZ6UmYwN3o",
    "url": "https://localhost:55195/acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a/finalize"
  },
  "payload": {
    "csr": "MIIBWDCCAQoCAQAwNDEcMBoGA1UEAwwTU21pdGgsIEFsaWNlIE0gKFFBKTEUMBIGA1UECgwLZXhhbXBsZS5jb20wKjAFBgMrZXADIQDIDA5T8pluEoYZPGAbFyJ1AaOhFV1yZo9wW3E2qn-XoqCBojCBnwYJKoZIhvcNAQkOMYGRMIGOMIGLBgNVHREEgYMwgYCGVWltcHA6d2lyZWFwcD1uZGV5emd5d25qYzJtemZrbmRiaW50bGx5bXZtbWpxeXp0aXpudGM0bndxLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb22GJ2ltcHA6d2lyZWFwcD1hbGljZS5zbWl0aC5xYUBleGFtcGxlLmNvbTAFBgMrZXADQQBCNiBNCxqrBjw1qS-H8mekuJuGY3RT8kNc-USnOCdC4xmo4lHiv4C1c4aoAKBMCnUzpUQATEhE5KPAKVZ8UUoE"
  }
}
```
#### 22. get back a url for fetching the certificate
```http request
200
cache-control: no-store
content-type: application/json
link: <https://localhost:55195/acme/acme/directory>;rel="index"
location: https://localhost:55195/acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a
replay-nonce: c3VnczNDaEJ1dHI1eGNmNWc5MU5Zd21rZmdsR2plbzQ
```
```json
{
  "certificate": "https://localhost:55195/acme/acme/certificate/D9YM1rT8KKqhKMH9C2WbJhHwStYPHPl9",
  "status": "valid",
  "finalize": "https://localhost:55195/acme/acme/order/inuqE3xYTl1NOrwgrWo1TvNDnONlN94a/finalize",
  "identifiers": [
    {
      "type": "wireapp-id",
      "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NDEyZGYwNjc2MzFkNDBiNTllYmVmMjQyZTIzNTc4NWQ/65c3ac1a1631c136@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
    }
  ],
  "authorizations": [
    "https://localhost:55195/acme/acme/authz/e5XBALr0WpTciw6m7r1ihI7lXRapUmvs"
  ],
  "expires": "2023-02-10T16:55:56Z",
  "notBefore": "2023-02-09T16:55:56.032306Z",
  "notAfter": "2023-02-09T17:55:56.032306Z"
}
```
#### 23. fetch the certificate
```http request
POST https://localhost:55195/acme/acme/certificate/D9YM1rT8KKqhKMH9C2WbJhHwStYPHPl9
content-type: application/jose+json
```
```json
{
  "protected": "eyJhbGciOiJFZERTQSIsImtpZCI6Imh0dHBzOi8vbG9jYWxob3N0OjU1MTk1L2FjbWUvYWNtZS9hY2NvdW50LzVRbGE4ajZrS3l2NzNxVlNWdXluQXQ4Q3psU2hhYnhSIiwidHlwIjoiSldUIiwibm9uY2UiOiJjM1ZuY3pORGFFSjFkSEkxZUdObU5XYzVNVTVaZDIxclptZHNSMnBsYnpRIiwidXJsIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTUxOTUvYWNtZS9hY21lL2NlcnRpZmljYXRlL0Q5WU0xclQ4S0txaEtNSDlDMldiSmhId1N0WVBIUGw5In0",
  "payload": "",
  "signature": "Nw6QTLBbFomijmftM5_0lymbg9lhmFYqZiDOyWtjuB7QXFL403N8Op8QrJWGPWxMiVlym1D0TaC-Wc6hkosZDw"
}
```
#### 24. get the certificate chain
```http request
200
cache-control: no-store
content-type: application/pem-certificate-chain
link: <https://localhost:55195/acme/acme/directory>;rel="index"
replay-nonce: amI2NUk5VmtlMVhqSUxJWjRPYXpaZzVsTjlheHJHZ1o
```
```json
[
  "MIICaTCCAg+gAwIBAgIRALnjg5FSj7S7dFI7eRo2pSYwCgYIKoZIzj0EAwIwLjEN\nMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\nMjMwMjA5MTY1NTU2WhcNMjMwMjA5MTc1NTU2WjA0MRQwEgYDVQQKEwtleGFtcGxl\nLmNvbTEcMBoGA1UEAxMTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhAMgM\nDlPymW4Shhk8YBsXInUBo6EVXXJmj3BbcTaqf5eio4IBNTCCATEwDgYDVR0PAQH/\nBAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU\n+BzWWqumhuF/buv3LSAI/1nRdtUwHwYDVR0jBBgwFoAUxQDR9STgxvptfCqeRgDl\nekgCONYwgaAGA1UdEQSBmDCBlYITc21pdGgsIGFsaWNlIG0gKHFhKYYnaW1wcDp3\naXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29thlVpbXBwOndpcmVhcHA9\nbmRleXpneXduamMybXpma25kYmludGxseW12bW1qcXl6dGl6bnRjNG53cS82NWMz\nYWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tMB0GDCsGAQQBgqRkxihAAQQNMAsCAQYE\nBGFjbWUEADAKBggqhkjOPQQDAgNIADBFAiAs5CT4uzxKYrzd8ykdxLKxwY8l6FAW\nBQZYhH7uyUpUhwIhAPNag0AxSqgl0cgWWtPi74ozfSVYJTkvQ8HlzJTONLWG",
  "MIIBuTCCAV+gAwIBAgIRAKPdWNwxnFBBnOnvJPoTVaMwCgYIKoZIzj0EAwIwJjEN\nMAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDIwOTE2\nNTU1M1oXDTMzMDIwNjE2NTU1M1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\nd2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQe\nxO6YkGrcjmcTLLumAlSD9KfnUJ8AZ1APtPkYNciofXfCp8jBj/efK3wjExx6q67f\nJZVzMiDHsf/r0Odedu0po2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\nBgEB/wIBADAdBgNVHQ4EFgQUxQDR9STgxvptfCqeRgDlekgCONYwHwYDVR0jBBgw\nFoAUqv7HVtUZkSbetRdrzPl8eD2rCI8wCgYIKoZIzj0EAwIDSAAwRQIhALTbMMsD\nmKboHca7csH69bpj4Vy0P/Vr8iBO6FPYRj2MAiBywBlA1pqyJOHcolPF7FaowITY\n8ImY70xAtVTkRW81ag=="
]
```
###### Certificate #0
```
-----BEGIN CERTIFICATE-----
MIICaTCCAg+gAwIBAgIRALnjg5FSj7S7dFI7eRo2pSYwCgYIKoZIzj0EAwIwLjEN
MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN
MjMwMjA5MTY1NTU2WhcNMjMwMjA5MTc1NTU2WjA0MRQwEgYDVQQKEwtleGFtcGxl
LmNvbTEcMBoGA1UEAxMTU21pdGgsIEFsaWNlIE0gKFFBKTAqMAUGAytlcAMhAMgM
DlPymW4Shhk8YBsXInUBo6EVXXJmj3BbcTaqf5eio4IBNTCCATEwDgYDVR0PAQH/
BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAdBgNVHQ4EFgQU
+BzWWqumhuF/buv3LSAI/1nRdtUwHwYDVR0jBBgwFoAUxQDR9STgxvptfCqeRgDl
ekgCONYwgaAGA1UdEQSBmDCBlYITc21pdGgsIGFsaWNlIG0gKHFhKYYnaW1wcDp3
aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29thlVpbXBwOndpcmVhcHA9
bmRleXpneXduamMybXpma25kYmludGxseW12bW1qcXl6dGl6bnRjNG53cS82NWMz
YWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tMB0GDCsGAQQBgqRkxihAAQQNMAsCAQYE
BGFjbWUEADAKBggqhkjOPQQDAgNIADBFAiAs5CT4uzxKYrzd8ykdxLKxwY8l6FAW
BQZYhH7uyUpUhwIhAPNag0AxSqgl0cgWWtPi74ozfSVYJTkvQ8HlzJTONLWG
-----END CERTIFICATE-----
```
```

version: V3
serial: 00:b9:e3:83:91:52:8f:b4:bb:74:52:3b:79:1a:36:a5:26
subject: O=example.com, CN=Smith, Alice M (QA)
issuer: O=wire, CN=wire Intermediate CA
validity:
  not before: Feb  9 16:55:56 2023 +00:00
  not after: Feb  9 17:55:56 2023 +00:00
  is valid: false
extensions:
  KeyUsage:Digital Signature
  SubjectKeyIdentifier:f8:1c:d6:5a:ab:a6:86:e1:7f:6e:eb:f7:2d:20:08:ff:59:d1:76:d5
  SAN:DNSName: smith, alice m (qa)
  SAN:URI: impp:wireapp=alice.smith.qa@example.com
  SAN:URI: impp:wireapp=ndeyzgywnjc2mzfkndbintllymvmmjqyztizntc4nwq/65c3ac1a1631c136@example.com
                
```

###### Certificate #1
```
-----BEGIN CERTIFICATE-----
MIIBuTCCAV+gAwIBAgIRAKPdWNwxnFBBnOnvJPoTVaMwCgYIKoZIzj0EAwIwJjEN
MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDIwOTE2
NTU1M1oXDTMzMDIwNjE2NTU1M1owLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU
d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQe
xO6YkGrcjmcTLLumAlSD9KfnUJ8AZ1APtPkYNciofXfCp8jBj/efK3wjExx6q67f
JZVzMiDHsf/r0Odedu0po2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw
BgEB/wIBADAdBgNVHQ4EFgQUxQDR9STgxvptfCqeRgDlekgCONYwHwYDVR0jBBgw
FoAUqv7HVtUZkSbetRdrzPl8eD2rCI8wCgYIKoZIzj0EAwIDSAAwRQIhALTbMMsD
mKboHca7csH69bpj4Vy0P/Vr8iBO6FPYRj2MAiBywBlA1pqyJOHcolPF7FaowITY
8ImY70xAtVTkRW81ag==
-----END CERTIFICATE-----
```
```

version: V3
serial: 00:a3:dd:58:dc:31:9c:50:41:9c:e9:ef:24:fa:13:55:a3
subject: O=wire, CN=wire Intermediate CA
issuer: O=wire, CN=wire Root CA
validity:
  not before: Feb  9 16:55:53 2023 +00:00
  not after: Feb  6 16:55:53 2033 +00:00
  is valid: true
extensions:
  KeyUsage:Key Cert Sign, CRL Sign
  BasicConstraints:Ca:true
  PathLenConstraint:0
  SubjectKeyIdentifier:c5:00:d1:f5:24:e0:c6:fa:6d:7c:2a:9e:46:00:e5:7a:48:02:38:d6
                
```
