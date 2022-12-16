/*fn sample() -> crate::error::E2eIdentityResult<()> {
    let enrollment: crate::RustyE2eIdentity = CoreCrypto::new_acme_enrollment();

    let directory_resp = http.get("https://acme.server/acme/{acme-provisionner}/directory");
    let directory = enrollment.acme_directory_response(directory_resp)?;

    let previous_nonce: &str = http.head(directory.new_nonce);

    let account_req = enrollment.acme_new_account_request(&directory, previous_nonce)?;
    let account_resp = http.post(directory.new_account, account_req);
    let previous_nonce = account_resp.header("replay-nonce");
    let account = enrollment.acme_new_account_response(account_resp)?;

    let handle = "login.wire.com".to_string();
    let client_id = "wire.com".to_string();
    let expiry = core::time::Duration::from_secs(3600 * 24 * 90); // 90 days
    let order_req =
        enrollment.acme_new_order_request(handle, client_id, expiry, &directory, &account, previous_nonce)?;
    let order_resp = http.post(directory.new_order, order_req);
    let previous_nonce = order_resp.header("replay-nonce");
    let order_url = order_resp.header("location");
    let new_order = enrollment.acme_new_order_response(order_resp)?;

    let authz1_url = new_order.authorizations.get(0).unwrap();
    let authz1_req = enrollment.acme_new_authz_request(authz1_url, &account, previous_nonce)?;
    let authz1_resp = http.post(authz1_url, authz1_req);
    let previous_nonce = authz1_resp.header("replay-nonce");
    let authz1 = enrollment.acme_new_authz_response(authz1_resp)?;

    let authz2_url = new_order.authorizations.get(1).unwrap();
    let authz2_req = enrollment.acme_new_authz_request(authz2_url, &account, previous_nonce)?;
    let authz2_resp = http.post(authz2_url, authz2_req);
    let previous_nonce = authz2_resp.header("replay-nonce");
    let authz2 = enrollment.acme_new_authz_response(authz2_resp)?;

    // authz order is randomized. So you have manually map them later here like this
    let (client_id_challenge, handle_challenge) = match (authz1.identifier, authz2.identifier) {
        (client_id, handle) if (client_id.as_str(), handle.as_str()) == ("wire.com", "login.wire.com") => {
            (authz1.wire_http_challenge.unwrap(), authz2.wire_oidc_challenge.unwrap())
        }
        (handle, client_id) if (client_id.as_str(), handle.as_str()) == ("wire.com", "login.wire.com") => {
            (authz1.wire_oidc_challenge.unwrap(), authz2.wire_http_challenge.unwrap())
        }
        _ => panic!("oups"),
    };

    let backend_nonce: String = http.head("https://wire-server/nonce");

    // this endpoint https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token
    let access_token_url = "https://wire-server/clients/{client_id}/access-token";
    // qualified clientId in the form '{user-id}/{client-id}@{domain}'
    let client_id = b"SvPfLlwBQi-6oddVRrkqpw/04c7@wire.com".to_vec();
    let expiry = core::time::Duration::from_secs(3600 * 24 * 90); // 90 days
    let client_dpop_token =
        enrollment.new_dpop_token(access_token_url, client_id, &client_id_challenge, backend_nonce, expiry)?;
    let dpop_access_token: String = http.post(access_token_url, client_dpop_token);

    let challenge_req = enrollment.acme_new_challenge_request(&handle_challenge, &account, previous_nonce)?;
    let challenge_resp = http.post(client_id_challenge.url, challenge_req);
    let previous_nonce = challenge_resp.header("replay-nonce");
    enrollment.acme_new_challenge_response(challenge_resp)?;

    let check_order_req = enrollment.acme_check_order_request(&order_url, &account, previous_nonce)?;
    let check_order_resp = http.post(&order_url, check_order_req);
    let previous_nonce = check_order_resp.header("replay-nonce");
    let order = enrollment.acme_check_order_response(check_order_resp)?;

    let domains = vec!["wire.com".to_string(), "login.wire.com".to_string()];
    let finalize_req = enrollment.acme_finalize_request(domains, &order, &account, previous_nonce)?;
    let finalize_resp = http.post(&order_url, finalize_req);
    let previous_nonce = finalize_resp.header("replay-nonce");
    let finalize = enrollment.acme_finalize_response(finalize_resp)?;

    let certificate_req = enrollment.acme_certificate_request(&finalize, &account, previous_nonce)?;
    let certificate_resp = http.post(&finalize.certificate_url, certificate_req);
    let _certificate_chain = enrollment.x509_certificate_response(certificate_resp)?;

    Ok(())
}*/
