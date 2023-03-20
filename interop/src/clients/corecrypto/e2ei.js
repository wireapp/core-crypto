const [callback] = arguments;

const encoder = new TextEncoder();
const jsonToByteArray = json => encoder.encode(JSON.stringify(json, null, 0));

const clientId = "NDEyZGYwNjc2MzFkNDBiNTllYmVmMjQyZTIzNTc4NWQ:65c3ac1a1631c136@example.com";
const displayName = "Smith, Alice M (QA)";
const handle = "alice.smith.qa@example.com";
const expiry = 90;

const enrollment = await window.cc.newAcmeEnrollment(clientId, displayName, handle, expiry);

const directoryResp = {
    "newNonce": "https://example.com/acme/new-nonce",
    "newAccount": "https://example.com/acme/new-account",
    "newOrder": "https://example.com/acme/new-order"
};
enrollment.directoryResponse(jsonToByteArray(directoryResp));

const previousNonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
const accountReq = enrollment.newAccountRequest(previousNonce);

const accountResp = {
    "status": "valid",
    "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
};
enrollment.newAccountResponse(jsonToByteArray(accountResp));

const newOrderReq = enrollment.newOrderRequest(previousNonce);

const newOrderResp = {
    "status": "pending",
    "expires": "2037-01-05T14:09:07.99Z",
    "notBefore": "2016-01-01T00:00:00Z",
    "notAfter": "2037-01-08T00:00:00Z",
    "identifiers": [
        {
            "type": "wireapp-id",
            "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
        }
    ],
    "authorizations": [
        "https://example.com/acme/authz/PAniVnsZcis",
    ],
    "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
};
const newOrder = enrollment.newOrderResponse(jsonToByteArray(newOrderResp));

const authzUrl = "https://example.com/acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm";
const authzReq = enrollment.newAuthzRequest(authzUrl, previousNonce);

const authzResp = {
    "status": "pending",
    "expires": "2016-01-02T14:09:30Z",
    "identifier": {
        "type": "wireapp-id",
        "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
    },
    "challenges": [
        {
            "type": "wire-oidc-01",
            "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/RNb3z6tvknq7vz2U5DoHsSOGiWQyVtAz",
            "status": "pending",
            "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY"
        },
        {
            "type": "wire-dpop-01",
            "url": "https://localhost:55170/acme/acme/challenge/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw/0y6hLM0TTOVUkawDhQcw5RB7ONwuhooW",
            "status": "pending",
            "token": "Gvg5AyOaw0uIQOWKE8lCSIP9nIYwcQiY"
        }
    ]
};
const authz = enrollment.newAuthzResponse(jsonToByteArray(authzResp));

const accessTokenUrl = "https://example.org/clients/42/access-token";
const backendNonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
const clientDpopToken = enrollment.createDpopToken(accessTokenUrl, backendNonce);

const accessToken = "eyJhbGciOiJFZERTQSIsInR5cCI6ImF0K2p3dCIsImp3ayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InlldjZPWlVudWlwbmZrMHRWZFlLRnM5MWpSdjVoVmF6a2llTEhBTmN1UEUifX0.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY4MzczNzc1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vbG9jYWxob3N0OjU5MzA3LyIsImp0aSI6Ijk4NGM1OTA0LWZhM2UtNDVhZi1iZGM1LTlhODMzNjkxOGUyYiIsIm5vbmNlIjoiYjNWSU9YTk9aVE4xVUV0b2FXSk9VM1owZFVWdWJFMDNZV1ZIUVdOb2NFMCIsImNoYWwiOiJTWTc0dEptQUlJaGR6UnRKdnB4Mzg5ZjZFS0hiWHV4USIsImNuZiI6eyJraWQiOiJocG9RV2xNUmtjUURKN2xNcDhaSHp4WVBNVDBJM0Vhc2VqUHZhWmlGUGpjIn0sInByb29mIjoiZXlKaGJHY2lPaUpGWkVSVFFTSXNJblI1Y0NJNkltUndiM0FyYW5kMElpd2lhbmRySWpwN0ltdDBlU0k2SWs5TFVDSXNJbU55ZGlJNklrVmtNalUxTVRraUxDSjRJam9pZVVGM1QxVmZTMXBpYUV0SFIxUjRaMGQ0WTJsa1VVZHFiMUpXWkdOdFlWQmpSblI0VG5Gd1gydzJTU0o5ZlEuZXlKcFlYUWlPakUyTnpVNU5qRTNOVFlzSW1WNGNDSTZNVFkzTmpBME9ERTFOaXdpYm1KbUlqb3hOamMxT1RZeE56VTJMQ0p6ZFdJaU9pSnBiWEJ3T25kcGNtVmhjSEE5VGtSRmVWcEhXWGRPYW1NeVRYcEdhMDVFUW1sT1ZHeHNXVzFXYlUxcVVYbGFWRWw2VGxSak5FNVhVUzgyTldNellXTXhZVEUyTXpGak1UTTJRR1Y0WVcxd2JHVXVZMjl0SWl3aWFuUnBJam9pTlRBM09HWmtaVEl0TlRCaU9DMDBabVZtTFdJeE5EQXRNekJrWVRrellqQmtZems1SWl3aWJtOXVZMlVpT2lKaU0xWkpUMWhPVDFwVVRqRlZSWFJ2WVZkS1QxVXpXakJrVlZaMVlrVXdNMWxYVmtoUlYwNXZZMFV3SWl3aWFIUnRJam9pVUU5VFZDSXNJbWgwZFNJNkltaDBkSEE2THk5c2IyTmhiR2h2YzNRNk5Ua3pNRGN2SWl3aVkyaGhiQ0k2SWxOWk56UjBTbTFCU1Vsb1pIcFNkRXAyY0hnek9EbG1Oa1ZMU0dKWWRYaFJJbjAuQk1MS1Y1OG43c1dITXkxMlUtTHlMc0ZJSkd0TVNKcXVoUkZvYnV6ZTlGNEpBN1NjdlFWSEdUTFF2ZVZfUXBfUTROZThyeU9GcEphUTc1VW5ORHR1RFEiLCJjbGllbnRfaWQiOiJpbXBwOndpcmVhcHA9TkRFeVpHWXdOamMyTXpGa05EQmlOVGxsWW1WbU1qUXlaVEl6TlRjNE5XUS82NWMzYWMxYTE2MzFjMTM2QGV4YW1wbGUuY29tIiwiYXBpX3ZlcnNpb24iOjMsInNjb3BlIjoid2lyZV9jbGllbnRfaWQifQ.Tf10dkKrNikGNgGhIdkrMHb0v6Jpde09MaIyBeuY6KORcxuglMGY7_V9Kd0LcVVPMDy1q4xbd39ZqosGz1NUBQ";
const dpopChallengeReq = enrollment.newDpopChallengeRequest(accessToken, previousNonce);
const dpopChallengeResp = {
    "type": "wire-dpop-01",
    "url": "https://example.com/acme/chall/prV_B7yEyA4",
    "status": "valid",
    "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
};
enrollment.newChallengeResponse(jsonToByteArray(dpopChallengeResp));

const idToken = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2NzU5NjE3NTYsImV4cCI6MTY3NjA0ODE1NiwibmJmIjoxNjc1OTYxNzU2LCJpc3MiOiJodHRwOi8vaWRwLyIsInN1YiI6ImltcHA6d2lyZWFwcD1OREV5WkdZd05qYzJNekZrTkRCaU5UbGxZbVZtTWpReVpUSXpOVGM0TldRLzY1YzNhYzFhMTYzMWMxMzZAZXhhbXBsZS5jb20iLCJhdWQiOiJodHRwOi8vaWRwLyIsIm5hbWUiOiJTbWl0aCwgQWxpY2UgTSAoUUEpIiwiaGFuZGxlIjoiaW1wcDp3aXJlYXBwPWFsaWNlLnNtaXRoLnFhQGV4YW1wbGUuY29tIiwia2V5YXV0aCI6IlNZNzR0Sm1BSUloZHpSdEp2cHgzODlmNkVLSGJYdXhRLi15V29ZVDlIQlYwb0ZMVElSRGw3cjhPclZGNFJCVjhOVlFObEw3cUxjbWcifQ.0iiq3p5Bmmp8ekoFqv4jQu_GrnPbEfxJ36SCuw-UvV6hCi6GlxOwU7gwwtguajhsd1sednGWZpN8QssKI5_CDQ";
const oidcChallengeReq = enrollment.newOidcChallengeRequest(idToken, previousNonce);
const oidcChallengeResp = {
    "type": "wire-oidc-01",
    "url": "https://localhost:55794/acme/acme/challenge/tR33VAzGrR93UnBV5mTV9nVdTZrG2Ln0/QXgyA324mTntfVAIJKw2cF23i4UFJltk",
    "status": "valid",
    "token": "2FpTOmNQvNfWDktNWt1oIJnjLE3MkyFb"
};
enrollment.newChallengeResponse(jsonToByteArray(oidcChallengeResp));

const orderUrl = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";
const checkOrderReq = enrollment.checkOrderRequest(orderUrl, previousNonce);

const checkOrderResp = {
    "status": "ready",
    "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
    "identifiers": [
        {
            "type": "wireapp-id",
            "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
        }
    ],
    "authorizations": [
        "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
    ],
    "expires": "2032-02-10T14:59:20Z",
    "notBefore": "2013-02-09T14:59:20.442908Z",
    "notAfter": "2032-02-09T15:59:20.442908Z"
};
enrollment.checkOrderResponse(jsonToByteArray(checkOrderResp));

const finalizeReq = enrollment.finalizeRequest(previousNonce);
const finalizeResp = {
    "certificate": "https://localhost:55170/acme/acme/certificate/rLhCIYygqzWhUmP1i5tmtZxFUvJPFxSL",
    "status": "valid",
    "finalize": "https://localhost:55170/acme/acme/order/FaKNEM5iL79ROLGJdO1DXVzIq5rxPEob/finalize",
    "identifiers": [
        {
            "type": "wireapp-id",
            "value": "{\"name\":\"Smith, Alice M (QA)\",\"domain\":\"example.com\",\"client-id\":\"impp:wireapp=NjJiYTRjMTIyODJjNDY5YmE5NGZmMjhhNjFkODA0Njk/d2ba2c1a57588ee4@example.com\",\"handle\":\"impp:wireapp=alice.smith.qa@example.com\"}"
        }
    ],
    "authorizations": [
        "https://localhost:55170/acme/acme/authz/ZelRfonEK02jDGlPCJYHrY8tJKNsH0mw"
    ],
    "expires": "2032-02-10T14:59:20Z",
    "notBefore": "2013-02-09T14:59:20.442908Z",
    "notAfter": "2032-02-09T15:59:20.442908Z"
};
enrollment.finalizeResponse(jsonToByteArray(finalizeResp));

const certificateReq = enrollment.certificateRequest(previousNonce);

const certificateResp = "-----BEGIN CERTIFICATE-----\n" +
    "MIIB7DCCAZKgAwIBAgIRAIErw6bhWUQXxeS0xsdMvyEwCgYIKoZIzj0EAwIwLjEN\n" +
    "MAsGA1UEChMEd2lyZTEdMBsGA1UEAxMUd2lyZSBJbnRlcm1lZGlhdGUgQ0EwHhcN\n" +
    "MjMwMTA1MjAwMDQxWhcNMjMwMTA2MjAwMTQxWjAAMFkwEwYHKoZIzj0CAQYIKoZI\n" +
    "zj0DAQcDQgAEq9rybsGxEBLpn6Tx5LHladF6jw3Vuc5Yr27NKRLwFWbCUXUmwApv\n" +
    "arn35O3u+w1CnwTyCA2tt605GhvbL039AKOBvjCBuzAOBgNVHQ8BAf8EBAMCB4Aw\n" +
    "HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBTlxc6/odBa\n" +
    "eTAlHYZcoCeFyn0BCjAfBgNVHSMEGDAWgBRsNCwlQHq5dXTxxfhhKHYOFQtlXzAm\n" +
    "BgNVHREBAf8EHDAagg5sb2dpbi53aXJlLmNvbYIId2lyZS5jb20wIgYMKwYBBAGC\n" +
    "pGTGKEABBBIwEAIBBgQJd2lyZS1hY21lBAAwCgYIKoZIzj0EAwIDSAAwRQIgAwhX\n" +
    "Jvnc7hOUOT41I35ZZi5rgJKF4FtMyImvCFY1UQ0CIQC2k+k7uqwgMRp10z3xzWHE\n" +
    "3sMuOBJG/UAR+VtFvCmGSA==\n" +
    "-----END CERTIFICATE-----\n" +
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIBuTCCAV+gAwIBAgIRAOzPGCzghRSFfL08VAXS/DQwCgYIKoZIzj0EAwIwJjEN\n" +
    "MAsGA1UEChMEd2lyZTEVMBMGA1UEAxMMd2lyZSBSb290IENBMB4XDTIzMDEwNTIw\n" +
    "MDEzOFoXDTMzMDEwMjIwMDEzOFowLjENMAsGA1UEChMEd2lyZTEdMBsGA1UEAxMU\n" +
    "d2lyZSBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARc\n" +
    "LwmNj175LF1Wd+CC7lVGVUzr/ys+mR7XbN0csRx3okfJKZFxx0PGs6JO+pTUG0C3\n" +
    "27GSfNQU+2tz5fnrmahxo2YwZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgw\n" +
    "BgEB/wIBADAdBgNVHQ4EFgQUbDQsJUB6uXV08cX4YSh2DhULZV8wHwYDVR0jBBgw\n" +
    "FoAUuL+rLbn8HEXbB6Pw5wzGhGjlE24wCgYIKoZIzj0EAwIDSAAwRQIgEltwd9QL\n" +
    "LdKVfvqnrQ/H3a4uIPgJz0+YQI1Y0eYuMB4CIQCYMrIYAqC7nqjqVXrROShrISO+\n" +
    "S26guHAMqXDlqqueOQ==\n" +
    "-----END CERTIFICATE-----";

await window.cc.e2eiMlsInit(enrollment, certificateResp);

callback();
