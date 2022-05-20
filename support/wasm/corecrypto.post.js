/// <reference types="emscripten" />
/*
The above snippet will import declarations from @types/emscripten, including Module etc.
It is not a .ts file but declaring a reference will allow to pass TS typecheck.
*/

// `cwrap` ALL the things!
Module["onRuntimeInitialized"] = function () {

    //////////////////////////////////// MISC APIS ////////////////////////////////////////////

    Module["cc_version"] = cwrap("cc_version", "number" /* *const c_uchar */);

    //////////////////////////////////// ERRORS APIS /////////////////////////////////////////

    Module["cc_last_error_len"] = cwrap("cc_last_error_len", "number" /* size_t */);

    Module["cc_last_error"] = cwrap("cc_last_error", "number", [
        "number", // *mut dest
    ]);

    //////////////////////////////////////// CTOR ////////////////////////////////////////////

    Module["cc_init_with_path_and_key"] = cwrap("cc_init_with_path_and_key", "number", [
        "string", // path
        "string", // key
        "string", // client_id
    ]);

    ///////////////////////////////////// CLIENT APIS ////////////////////////////////////////

    Module["cc_client_public_key"] = cwrap("cc_client_public_key", "number", [
        "number", // ptr
        "number", // *mut dest
    ]);

    Module["cc_client_keypackages"] = cwrap("cc_client_keypackages", "number", [
        "number", // ptr
        "number", // amount_requested
        "number", // *mut dest[]
        "number", // kp_buf_len
    ]);

    ////////////////////////////////// CONVERSATIONS API ///////////////////////////////////

    Module["cc_create_conversation"] = cwrap("cc_create_conversation", "number", [
        "number", // ptr
        "number", // *const id
        "number", // id_len
        "number", // *const params
        "number", // *mut welcome_msg_buffer
        "number", // *mut commit_msg_buffer
    ]);

    Module["cc_process_welcome_message"] = cwrap("cc_process_welcome_message", "number", [
        "number", // ptr
        "number", // *const welcome
        "number", // welcome_len
        "number", // *mut conversation_id_buf
    ]);

    Module["cc_add_clients_to_conversation"] = cwrap("cc_add_clients_to_conversation", "number", [
        "number", // ptr
        "number", // *const conversation_id
        "number", // conversation_id_len
        "number", // *const keypackages
        "number", // keypackages_count
        "number", // *mut welcome_buffer
        "number", // *mut commit_buffer
    ]);

    Module["cc_remove_clients_from_conversation"] = cwrap("cc_remove_clients_from_conversation", "number", [
        "number", // ptr
        "number", // *const conversation_id
        "number", // conversation_id_len
        "number", // *const client_ids[]
        "number", // client_ids_amount
        "number", // *const client_ids_lengths
        "number", // *mut dest_commit
    ]);

    Module["cc_conversation_exists"] = cwrap("cc_conversation_exists", "number", [
        "number", // ptr
        "number", // *const conversation_id
        "number", // conversation_id_len
    ]);

    Module["cc_leave_conversation"] = cwrap("cc_leave_conversation", "number", [
        "number", // ptr
        "number", // *const conversation_id
        "number", // conversation_id_len
        "number", // *const other_clients
        "number", // other_clients_count
        "number", // *mut self_removal_proposal
        "number", // *mut other_clients_removal_commit
    ]);

    /////////////////////////////////// MESSAGES API ///////////////////////////////////////

    Module["cc_decrypt_message"] = cwrap("cc_decrypt_message", "number", [
        "number", // ptr
        "number", // *const conversation_id
        "number", // conversation_id_len
        "number", // *const payload
        "number", // payload_len
        "number", // *mut dest_buffer
    ]);

    Module["cc_encrypt_message"] = cwrap("cc_encrypt_message", "number", [
        "number", // ptr
        "number", // *const conversation_id
        "number", // conversation_id_len
        "number", // *const payload
        "number", // payload_len
        "number", // *mut dest_buffer
    ]);

    /////////////////////////////////////////// PROPOSALS API ///////////////////////////////////////////

    Module["cc_new_add_proposal"] = cwrap("cc_new_add_proposal", "number", [
        "number", // ptr
        "number", // *const conversation_id
        "number", // conversation_id_len
        "number", // *const key_package
        "number", // key_package_len
        "number", // *mut dest
    ]);

    Module["cc_new_update_proposal"] = cwrap("cc_new_update_proposal", "number", [
        "number", // ptr
        "number", // *const conversation_id
        "number", // conversation_id_len
        "number", // *mut dest
    ]);

    Module["cc_new_remove_proposal"] = cwrap("cc_new_remove_proposal", "number", [
        "number", // ptr
        "number", // *const conversation_id
        "number", // conversation_id_len
        "number", // *const client_id
        "number", // client_id_len
        "number", // *mut dest
    ]);
};
