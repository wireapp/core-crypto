// This module exists so we can use Typescript to review how our Proteus functions should look in `mod.rs`.
//
// While this is a Typescript file, use care to write the function bodies in pure Javascript.
// They will be copied directly into the JS environment without any transpilation!
// Even so, just having the definitions written in this file instead of as string literals
// means that TSC can help us out in case we're using the interface wrong.
//
// Note in particular that functions _must not_ use a normal parameters list. Instead they must
// internally destructure the `arguments` list. This is to conform with the webdriver `.execute` API.

import { CoreCrypto } from "./corecrypto.js";

declare global {
    interface Window {
        cc: CoreCrypto;
    }
}

export async function proteusInit() {
    await window.cc.transaction((ctx) =>
        ctx.proteusInit()
    );
}

export async function getPrekey() {
    const [prekeyId] = arguments;
    return await window.cc.transaction((ctx) =>
        ctx.proteusNewPrekey(prekeyId)
    );
}

export async function sessionFromPrekey() {
    const [sessionId, prekey] = arguments;
    const prekeyBuffer = Uint8Array.from(Object.values(prekey));
    await window.cc.transaction((ctx) =>
        ctx.proteusSessionFromPrekey(sessionId, prekeyBuffer)
    );
}

export async function sessionFromMessage() {
    const [sessionId, message] = arguments;
    const messageBuffer = Uint8Array.from(Object.values(message));
    return await window.cc.transaction((ctx) =>
        ctx.proteusSessionFromMessage(sessionId, messageBuffer)
    );
}

export async function encrypt() {
    const [sessionId, plaintext] = arguments;
    const plaintextBuffer = Uint8Array.from(Object.values(plaintext));
    return await window.cc.transaction((ctx) =>
        ctx.proteusEncrypt(sessionId, plaintextBuffer)
    );
}

export async function decrypt() {
    const [sessionId, ciphertext] = arguments;
    const ciphertextBuffer = Uint8Array.from(Object.values(ciphertext));
    return await window.cc.transaction((ctx) =>
        ctx.proteusDecrypt(sessionId, ciphertextBuffer)
    );
}

export async function fingerprint() {
    return window.cc.proteusFingerprint();
}
