// Wire
// Copyright (C) 2022 Wire Swiss GmbH

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

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
