const [callback] = arguments;

const encoder = new TextEncoder();
const jsonToByteArray = json => encoder.encode(JSON.stringify(json, null, 0));

const clientId = "NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg:6c1866f567616f31@wire.com";
const displayName = "Alice Smith";
const handle = "alice_wire";
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
            "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
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
        "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
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
            "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
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
            "value": "{\"name\":\"Alice Smith\",\"domain\":\"wire.com\",\"client-id\":\"im:wireapp=NjhlMzIxOWFjODRiNDAwYjk0ZGFhZDA2NzExNTEyNTg/6c1866f567616f31@wire.com\",\"handle\":\"im:wireapp=alice_wire\"}"
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
    "MIICaDCCAg6gAwIBAgIQH3CanUzXJpP+pbXNUVpp7TAKBggqhkjOPQQDAjAuMQ0w\n" +
    "CwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3aXJlIEludGVybWVkaWF0ZSBDQTAeFw0y\n" +
    "MzAyMDkxNDU5MjBaFw0yMzAyMDkxNTU5MjBaMDQxFDASBgNVBAoTC2V4YW1wbGUu\n" +
    "Y29tMRwwGgYDVQQDExNTbWl0aCwgQWxpY2UgTSAoUUEpMCowBQYDK2VwAyEAVCw/\n" +
    "lxGMV2Zx723yhVv94Fb+LCARV0h1F1/zmvRZGy6jggE1MIIBMTAOBgNVHQ8BAf8E\n" +
    "BAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMB0GA1UdDgQWBBSr\n" +
    "zp+ejXBydYcjmBr4cTp931ceUTAfBgNVHSMEGDAWgBS04sLODR52O3cPNlNdK3f6\n" +
    "tinkIzCBoAYDVR0RBIGYMIGVghNzbWl0aCwgYWxpY2UgbSAocWEphidpbXBwOndp\n" +
    "cmVhcHA9YWxpY2Uuc21pdGgucWFAZXhhbXBsZS5jb22GVWltcHA6d2lyZWFwcD1u\n" +
    "amppeXRyam10aXlvZGpqbmR5NXltZTVuZ3ptbWpoaG5qZmtvZGEwbmprL2QyYmEy\n" +
    "YzFhNTc1ODhlZTRAZXhhbXBsZS5jb20wHQYMKwYBBAGCpGTGKEABBA0wCwIBBgQE\n" +
    "YWNtZQQAMAoGCCqGSM49BAMCA0gAMEUCIG6cfFB2En9YKVPuQhEZcoELtZbkFsTJ\n" +
    "PeWa6zTkrI47AiEApQP8piMQWhofGLL6oTWoks3+6JfPRWZP9Z7JkhdiBmY=\n" +
    "-----END CERTIFICATE-----\n" +
    "-----BEGIN CERTIFICATE-----\n" +
    "MIIBuDCCAV6gAwIBAgIQP5i/9/vpRPXels/aSa5lZTAKBggqhkjOPQQDAjAmMQ0w\n" +
    "CwYDVQQKEwR3aXJlMRUwEwYDVQQDEwx3aXJlIFJvb3QgQ0EwHhcNMjMwMjA5MTQ1\n" +
    "OTE4WhcNMzMwMjA2MTQ1OTE4WjAuMQ0wCwYDVQQKEwR3aXJlMR0wGwYDVQQDExR3\n" +
    "aXJlIEludGVybWVkaWF0ZSBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFNd\n" +
    "5wbJjtVSmXxftBSmHgTJS3F1LGMlb789KtcSTjjJVO//VNdg3XDYvhHyitHx/Bz+\n" +
    "5yxkrPaRzeGeJkZfkuejZjBkMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG\n" +
    "AQH/AgEAMB0GA1UdDgQWBBS04sLODR52O3cPNlNdK3f6tinkIzAfBgNVHSMEGDAW\n" +
    "gBTqNi9/bemraZjLYA8TGat3ianEizAKBggqhkjOPQQDAgNIADBFAiEAuo8JLvys\n" +
    "IvUCvPUJi1++80IgPeRxxRvn5zlHDh3qKZECIHONc1xx1ixlIyp9mOtdeTvG5Dql\n" +
    "RheWYpDHRiLax1Id\n" +
    "-----END CERTIFICATE-----";

await window.cc.e2eiMlsInit(enrollment, certificateResp);

callback();
