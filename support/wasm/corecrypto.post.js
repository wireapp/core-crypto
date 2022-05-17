/// <reference types="emscripten" />
/** Above will import declarations from @types/emscripten, including Module etc. */
/** It is not .ts file but declaring reference will pass TypeScript Check. */

Module["onRuntimeInitialized"] = function () {
    Module["cc_version"] = cwarp("cc_version", "string");
    Module["cc_last_error_len"] = cwrap("cc_last_error_len", "number");
    Module["cc_last_error"] = cwrap("cc_last_error", "number", ["array"]);
    Module["cc_init_with_path_and_key"] = cwrap("cc_init_with_path_and_key", "number", ["string", "string", "string"]);
    Module["cc_create_conversation"] = cwrap("cc_create_conversation", "number", ["number", "array", "number", "array", "array"]);
    Module["cc_decrypt_message"] = cwrap("cc_decrypt_message", "number", ["number", "array", "array", "array"]);
    Module["cc_encrypt_message"] = cwrap("cc_encrypt_message", "number", ["number", "array", "array", "array"]);
    Module["cc_process_welcome_message"] = cwrap("cc_process_welcome_message", "number", ["number", "array", "array"]);
    Module["cc_client_public_key"] = cwrap("cc_client_public_key", "number", ["number", "array"]);
    Module["cc_client_keypackages"] = cwrap("cc_client_keypackages", "number", ["number", "number", "array"]);
    Module["cc_add_clients_to_conversation"] = cwrap("cc_add_clients_to_conversation", "number", ["number", "array", "array", "array"]);
    Module["cc_remove_clients_from_conversation"] = cwrap("cc_remove_clients_from_conversation", "number", ["number", "array", "array", "array"]);
    Module["cc_conversation_exists"] = cwrap("cc_conversation_exists", "number", ["number", "array"]);
    Module["cc_leave_conversation"] = cwrap("cc_leave_conversation", "number", ["number", "array", "array", "array", "array"]);
};
