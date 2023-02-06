const [callback] = arguments;

const jsonToByteArray = function (json) {
    let str = JSON.stringify(json, null, 0);
    let ret = new Uint8Array(str.length);
    for (let i = 0; i < str.length; i++) {
        ret[i] = str.charCodeAt(i);
    }
    return ret
};

let enrollment = await window.cc.newAcmeEnrollment();

let directoryResp = {
    "newNonce": "https://example.com/acme/new-nonce",
    "newAccount": "https://example.com/acme/new-account",
    "newOrder": "https://example.com/acme/new-order"
};
let directory = enrollment.directoryResponse(jsonToByteArray(directoryResp));

let previousNonce = "YUVndEZQVTV6ZUNlUkJxRG10c0syQmNWeW1kanlPbjM";
let accountReq = enrollment.newAccountRequest(directory, previousNonce);

let accountResp = {
    "status": "valid",
    "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
};
let account = enrollment.newAccountResponse(jsonToByteArray(accountResp));

let newOrderReq = enrollment.newOrderRequest("idp.example.com", "wire.example.com", 90, directory, account, previousNonce);

let newOrderResp = {
    "status": "pending",
    "expires": "2037-01-05T14:09:07.99Z",
    "notBefore": "2016-01-01T00:00:00Z",
    "notAfter": "2037-01-08T00:00:00Z",
    "identifiers": [
        {"type": "dns", "value": "www.example.org"},
        {"type": "dns", "value": "example.org"}
    ],
    "authorizations": [
        "https://example.com/acme/authz/PAniVnsZcis",
        "https://example.com/acme/authz/r4HqLzrSrpI"
    ],
    "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
};
let newOrder = enrollment.newOrderResponse(jsonToByteArray(newOrderResp));

let authz1Url = "https://example.com/acme/wire-acme/authz/1Mw1NcVgu1cusB9RTdtFVdEo6UQDueZm";
let authz1Req = enrollment.newAuthzRequest(authz1Url, account, previousNonce);

let authz1Resp = {
    "status": "pending",
    "expires": "2016-01-02T14:09:30Z",
    "identifier": {
        "type": "dns",
        "value": "wire.example.org"
    },
    "challenges": [
        {
            "type": "wire-http-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "token": "DGyRejmCefe7v4NfDGDKfA"
        }
    ]
};
let authz1 = enrollment.newAuthzResponse(jsonToByteArray(authz1Resp));

let authz2Url = "https://example.com/acme/wire-acme/authz/l6n7mSqcV8NImz4KCy5GfYbJ7q3HHSjh";
let authz2Req = enrollment.newAuthzRequest(authz2Url, account, previousNonce);

let authz2Resp = {
    "status": "pending",
    "expires": "2016-01-02T14:09:30Z",
    "identifier": {
        "type": "dns",
        "value": "idp.example.org"
    },
    "challenges": [
        {
            "type": "wire-oidc-01",
            "url": "https://example.com/acme/chall/prV_B7yEyA4",
            "token": "DGyRejmCefe7v4NfDGDKfA"
        }
    ]
};
let authz2 = enrollment.newAuthzResponse(jsonToByteArray(authz2Resp));

let clientIdChall = authz1.wireHttpChallenge;
let handleChall = authz2.wireOidcChallenge;

let userId = "c6755c56-8304-49e8-bb24-81b6034e30a2";
let clientId = BigInt(42);
let accessTokenUrl = "https://example.org/clients/42/access-token";
let domain = "example.org";
let backendNonce = "U09ZR0tnWE5QS1ozS2d3bkF2eWJyR3ZVUHppSTJsMnU";
let clientDpopToken = enrollment.createDpopToken(accessTokenUrl, userId, clientId, domain, clientIdChall, backendNonce, 90);

let challengeReq = enrollment.newChallengeRequest(handleChall, account, previousNonce);

let challengeResp = {
    "type": "wire-oidc-01",
    "url": "https://example.com/acme/chall/prV_B7yEyA4",
    "status": "valid",
    "token": "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
};
let challenge = enrollment.newChallengeResponse(jsonToByteArray(challengeResp));

let orderUrl = "https://example.com/acme/wire-acme/order/C7uOXEgg5KPMPtbdE3aVMzv7cJjwUVth";
let checkOrderReq = enrollment.checkOrderRequest(orderUrl, account, previousNonce);

let checkOrderResp = {
    "status": "ready",
    "expires": "2037-01-05T14:09:07.99Z",
    "notBefore": "2016-01-01T00:00:00Z",
    "notAfter": "2037-01-08T00:00:00Z",
    "identifiers": [
        {"type": "dns", "value": "wire.example.org"},
        {"type": "dns", "value": "idp.example.org"}
    ],
    "authorizations": [
        "https://example.com/acme/authz/PAniVnsZcis",
        "https://example.com/acme/authz/r4HqLzrSrpI"
    ],
    "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
};
let order = enrollment.checkOrderResponse(jsonToByteArray(checkOrderResp));

let domains = ["wire.example.org"];
let finalizeReq = enrollment.finalizeRequest(domains, order, account, previousNonce);

let finalizeResp = {
    "status": "valid",
    "expires": "2016-01-20T14:09:07.99Z",
    "notBefore": "2016-01-01T00:00:00Z",
    "notAfter": "2016-01-08T00:00:00Z",
    "identifiers": [
        {"type": "dns", "value": "www.example.org"},
        {"type": "dns", "value": "example.org"}
    ],
    "authorizations": [
        "https://example.com/acme/authz/PAniVnsZcis",
        "https://example.com/acme/authz/r4HqLzrSrpI"
    ],
    "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",
    "certificate": "https://example.com/acme/cert/mAt3xBGaobw"
};
let finalize = enrollment.finalizeResponse(jsonToByteArray(finalizeResp));

let certificateReq = enrollment.certificateRequest(finalize, account, previousNonce);

let certificateResp = "-----BEGIN CERTIFICATE-----\n" +
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
let certificateChain = enrollment.certificateResponse(certificateResp);

callback();
