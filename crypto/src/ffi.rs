use std::sync::{ONCE_INIT, Once};

static LIB_HAS_INIT: Once = ONCE_INIT;
static CALLBACK_HANDLER_HAS_INIT: Once = ONCE_INIT;
static mut CALLBACK_HANDLER: extern "C" fn(*const message::Message) = std::ptr::null_mut();

#[repr(C)]
pub union ConversationConfigurationUnion {
    mls: MlsConversationConfiguration,
    proteus: ProteusConversationConfiguration,
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct ConversationConfiguration {
    t: Protocol,
    c: ConversationConfigurationUnion,
}


#[no_mangle]
pub extern "C" fn init() {
    LIB_HAS_INIT.call_once(|| {

    });
}

#[no_mangle]
pub extern "C" fn init_and_listen_with(callback: extern "C" fn(*const message::Message)) {
    CALLBACK_HANDLER_INIT.call_once(move || {
        init();
        unsafe { CALLBACK_HANDLER = callback; }
    });
}
