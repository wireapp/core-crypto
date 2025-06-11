import { safeBigintToNumber } from "./Conversions.js";
import * as CoreCryptoFfiTypes from "./core-crypto-ffi.d.js";

import {
    NewAcmeAuthz,
    NewAcmeOrder,
    CrlRegistration as CrlRegistrationFfi,
} from "./core-crypto-ffi.js";

import { CoreCryptoError } from "./CoreCryptoError.js";

/**
 *  Supporting struct for CRL registration result
 */
export interface CRLRegistration {
    /**
     * Whether this CRL modifies the old CRL (i.e. has a different revocated cert list)
     *
     * @readonly
     */
    dirty: boolean;
    /**
     * Optional expiration timestamp
     *
     * @readonly
     */
    expiration?: number;
}

export function crlRegistrationFromFfi(r: CrlRegistrationFfi): CRLRegistration {
    return {
        dirty: r.dirty,
        expiration: r.expiration ? safeBigintToNumber(r.expiration) : undefined,
    };
}

export function normalizeEnum<T>(enumType: T, value: number): T[keyof T] {
    const enumAsString = enumType[value as unknown as keyof T];
    const enumAsDiscriminant = enumType[enumAsString as unknown as keyof T];
    return enumAsDiscriminant;
}

export interface AcmeDirectory {
    /**
     * URL for fetching a new nonce. Use this only for creating a new account.
     */
    newNonce: string;
    /**
     * URL for creating a new account.
     */
    newAccount: string;
    /**
     * URL for creating a new order.
     */
    newOrder: string;
    /**
     * Revocation URL
     */
    revokeCert: string;
}

/**
 * Returned by APIs whose code paths potentially discover new certificate revocation list distribution URLs.
 */
export type NewCrlDistributionPoints = string[] | undefined;

export type JsonRawData = Uint8Array;

export class E2eiEnrollment {
    /** @hidden */
    #enrollment: CoreCryptoFfiTypes.FfiWireE2EIdentity;

    /** @hidden */
    constructor(e2ei: CoreCryptoFfiTypes.FfiWireE2EIdentity) {
        this.#enrollment = e2ei;
    }

    free() {
        this.#enrollment.free();
    }

    /**
     * Should only be used internally
     */
    inner(): unknown {
        return this.#enrollment as CoreCryptoFfiTypes.FfiWireE2EIdentity;
    }

    /**
     * Parses the response from `GET /acme/{provisioner-name}/directory`.
     * Use this {@link AcmeDirectory} in the next step to fetch the first nonce from the acme server. Use
     * {@link AcmeDirectory.newNonce}.
     *
     * @param directory HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.1.1
     */
    async directoryResponse(directory: JsonRawData): Promise<AcmeDirectory> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.directory_response(directory)
        );
    }

    /**
     * For creating a new acme account. This returns a signed JWS-alike request body to send to
     * `POST /acme/{provisioner-name}/new-account`.
     *
     * @param previousNonce you got from calling `HEAD {@link AcmeDirectory.newNonce}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
     */
    async newAccountRequest(previousNonce: string): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_account_request(previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/new-account`.
     * @param account HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3
     */
    async newAccountResponse(account: JsonRawData): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_account_response(account)
        );
    }

    /**
     * Creates a new acme order for the handle (userId + display name) and the clientId.
     *
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/new-account`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async newOrderRequest(previousNonce: string): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_order_request(previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/new-order`.
     *
     * @param order HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async newOrderResponse(order: JsonRawData): Promise<NewAcmeOrder> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_order_response(order)
        );
    }

    /**
     * Creates a new authorization request.
     *
     * @param url one of the URL in new order's authorizations from {@link newOrderResponse})
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/new-order` (or from the
     * previous to this method if you are creating the second authorization)
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
     */
    async newAuthzRequest(
        url: string,
        previousNonce: string
    ): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_authz_request(url, previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/authz/{authz-id}`
     *
     * @param authz HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5
     */
    async newAuthzResponse(authz: JsonRawData): Promise<NewAcmeAuthz> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_authz_response(authz)
        );
    }

    /**
     * Generates a new client Dpop JWT token. It demonstrates proof of possession of the nonces
     * (from wire-server & acme server) and will be verified by the acme server when verifying the
     * challenge (in order to deliver a certificate).
     *
     * Then send it to `POST /clients/{id}/access-token`
     * {@link https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token} on wire-server.
     *
     * @param expirySecs of the client Dpop JWT. This should be equal to the grace period set in Team Management
     * @param backendNonce you get by calling `GET /clients/token/nonce` on wire-server as defined here {@link https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/get_clients__client__nonce}
     */
    async createDpopToken(
        expirySecs: number,
        backendNonce: string
    ): Promise<Uint8Array> {
        const token = await CoreCryptoError.asyncMapErr(
            this.#enrollment.create_dpop_token(expirySecs, backendNonce)
        );
        return new TextEncoder().encode(token);
    }

    /**
     * Creates a new challenge request for Wire Dpop challenge.
     *
     * @param accessToken returned by wire-server from https://staging-nginz-https.zinfra.io/api/swagger-ui/#/default/post_clients__cid__access_token
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    async newDpopChallengeRequest(
        accessToken: string,
        previousNonce: string
    ): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_dpop_challenge_request(
                accessToken,
                previousNonce
            )
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for the DPoP challenge.
     *
     * @param challenge HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    async newDpopChallengeResponse(challenge: JsonRawData): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_dpop_challenge_response(challenge)
        );
    }

    /**
     * Creates a new challenge request for Wire Oidc challenge.
     *
     * @param idToken you get back from Identity Provider
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/authz/{authz-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    async newOidcChallengeRequest(
        idToken: string,
        previousNonce: string
    ): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_oidc_challenge_request(idToken, previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/challenge/{challenge-id}` for the OIDC challenge.
     *
     * @param challenge HTTP response body
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.5.1
     */
    async newOidcChallengeResponse(challenge: JsonRawData): Promise<void> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.new_oidc_challenge_response(challenge)
        );
    }

    /**
     * Verifies that the previous challenge has been completed.
     *
     * @param orderUrl `location` header from http response you got from {@link newOrderResponse}
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/challenge/{challenge-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async checkOrderRequest(
        orderUrl: string,
        previousNonce: string
    ): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.check_order_request(orderUrl, previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/order/{order-id}`.
     *
     * @param order HTTP response body
     * @return finalize url to use with {@link finalizeRequest}
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async checkOrderResponse(order: JsonRawData): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.check_order_response(order)
        );
    }

    /**
     * Final step before fetching the certificate.
     *
     * @param previousNonce - `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async finalizeRequest(previousNonce: string): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.finalize_request(previousNonce)
        );
    }

    /**
     * Parses the response from `POST /acme/{provisioner-name}/order/{order-id}/finalize`.
     *
     * @param finalize HTTP response body
     * @return the certificate url to use with {@link certificateRequest}
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4
     */
    async finalizeResponse(finalize: JsonRawData): Promise<string> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.finalize_response(finalize)
        );
    }

    /**
     * Creates a request for finally fetching the x509 certificate.
     *
     * @param previousNonce `replay-nonce` response header from `POST /acme/{provisioner-name}/order/{order-id}/finalize`
     * @see https://www.rfc-editor.org/rfc/rfc8555.html#section-7.4.2
     */
    async certificateRequest(previousNonce: string): Promise<JsonRawData> {
        return await CoreCryptoError.asyncMapErr(
            this.#enrollment.certificate_request(previousNonce)
        );
    }
}

/**
 * Indicates the state of a Conversation regarding end-to-end identity.
 * Note: this does not check pending state (pending commit, pending proposals) so it does not
 * consider members about to be added/removed
 */
export enum E2eiConversationState {
    /**
     * All clients have a valid E2EI certificate
     */
    Verified = 0x0001,
    /**
     * Some clients are either still Basic or their certificate is expired
     */
    NotVerified = 0x0002,
    /**
     * All clients are still Basic. If all client have expired certificates, NotVerified is returned.
     */
    NotEnabled = 0x0003,
}
