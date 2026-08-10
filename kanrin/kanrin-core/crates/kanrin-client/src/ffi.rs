use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;
use std::sync::Mutex;

use once_cell::sync::Lazy;

use crate::config::KanrinConfig;
use crate::events::KanrinEvent;
use crate::{ClientState, KanrinClient};

/// Global client instance for FFI.
static CLIENT: Lazy<Mutex<Option<KanrinClient>>> = Lazy::new(|| Mutex::new(None));

/// Result codes for FFI.
#[repr(i32)]
pub enum KanrinResult {
    Ok = 0,
    ErrorConfig = -1,
    ErrorAlreadyRunning = -2,
    ErrorNotRunning = -3,
    ErrorInternal = -4,
}

/// Initialize the client with a YAML config string.
/// Must be called before kanrin_start().
#[no_mangle]
pub extern "C" fn kanrin_init(config_yaml: *const c_char) -> i32 {
    if config_yaml.is_null() {
        return KanrinResult::ErrorConfig as i32;
    }

    let config_str = unsafe { CStr::from_ptr(config_yaml) };
    let config_str = match config_str.to_str() {
        Ok(s) => s,
        Err(_) => return KanrinResult::ErrorConfig as i32,
    };

    let config: KanrinConfig = match serde_yaml::from_str(config_str) {
        Ok(c) => c,
        Err(_) => return KanrinResult::ErrorConfig as i32,
    };

    let client = KanrinClient::new(config);

    let mut guard = CLIENT.lock().unwrap();
    *guard = Some(client);

    KanrinResult::Ok as i32
}

/// Start the VPN connection.
#[no_mangle]
pub extern "C" fn kanrin_start() -> i32 {
    let mut guard = CLIENT.lock().unwrap();
    match guard.as_mut() {
        Some(client) => match client.start() {
            Ok(()) => KanrinResult::Ok as i32,
            Err(_) => KanrinResult::ErrorInternal as i32,
        },
        None => KanrinResult::ErrorNotRunning as i32,
    }
}

/// Stop the VPN connection.
#[no_mangle]
pub extern "C" fn kanrin_stop() -> i32 {
    let mut guard = CLIENT.lock().unwrap();
    match guard.as_mut() {
        Some(client) => match client.stop() {
            Ok(()) => KanrinResult::Ok as i32,
            Err(_) => KanrinResult::ErrorInternal as i32,
        },
        None => KanrinResult::ErrorNotRunning as i32,
    }
}

/// Get current state as integer.
/// 0=Disconnected, 1=Connecting, 2=Connected, 3=Reconnecting, 4=Disconnecting, 5=Error
#[no_mangle]
pub extern "C" fn kanrin_state() -> i32 {
    let guard = CLIENT.lock().unwrap();
    match guard.as_ref() {
        Some(client) => match client.state() {
            ClientState::Disconnected => 0,
            ClientState::Connecting => 1,
            ClientState::Connected => 2,
            ClientState::Reconnecting => 3,
            ClientState::Disconnecting => 4,
            ClientState::Error => 5,
        },
        None => 0,
    }
}

/// Destroy the client instance and free resources.
#[no_mangle]
pub extern "C" fn kanrin_destroy() {
    let mut guard = CLIENT.lock().unwrap();
    if let Some(mut client) = guard.take() {
        let _ = client.stop();
    }
}

/// Free a string allocated by kanrin (returned from status functions).
#[no_mangle]
pub extern "C" fn kanrin_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { drop(CString::from_raw(s)) };
    }
}
