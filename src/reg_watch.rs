use std::{ptr};
use failure::{Error, format_err};
use winapi::{
    um::{
        winnt::*,
        winreg::*,
        synchapi::{CreateEventW, WaitForSingleObject},
        handleapi::CloseHandle,
        winbase::*,
        errhandlingapi::GetLastError,
    },
};
use winapi::shared::winerror::*;
use winreg::RegKey;
use widestring::WideCString;
use uuid::Uuid;

/// Reexport notify filters
pub mod filter {
    pub use winapi::um::winnt::{
        REG_NOTIFY_CHANGE_NAME,
        REG_NOTIFY_CHANGE_ATTRIBUTES,
        REG_NOTIFY_CHANGE_LAST_SET,
        REG_NOTIFY_CHANGE_SECURITY,
        REG_NOTIFY_THREAD_AGNOSTIC,
        REG_LEGAL_CHANGE_FILTER,
    };
}

/// Timeout value for `watch` function
pub enum Timeout {
    Milli(u32),
    Infinite,
}

struct WaitEvent {
    handle: HANDLE,
}

impl WaitEvent {
    pub fn create(name_ptr: LPCWSTR) -> Self {
        let handle = unsafe { CreateEventW(
            ptr::null_mut(),
            false as i32,
            true as i32,
            name_ptr
        ) };
        Self { handle }
    }

    pub fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for WaitEvent {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

/// Watching response returned by `watch`
#[derive(Debug)]
pub enum WatchResponse {
    Notify,
    Timeout,
}

/// Watch a specific registry key.
/// Block the thread until the changing notify occur or timeout expired.
pub fn watch(
    reg_key: &RegKey,
    notify_filter: u32,
    watch_subtree: bool,
    timeout: Timeout,
) -> Result<WatchResponse, Error> {

    // generate unique name for wait event
    let uid = Uuid::new_v4().to_hyphenated().to_string() + "-reg-watcher";
    let name = WideCString::from_str(uid)?;

    let time_num = match &timeout {
        &Timeout::Milli(v) => v,
        &Timeout::Infinite => INFINITE,
    };

    let wait_handle = WaitEvent::create(name.as_ptr());

    unsafe {
        let ret = RegNotifyChangeKeyValue(
            reg_key.raw_handle(),
            watch_subtree as i32,
            notify_filter,
            wait_handle.handle(),
            true as i32,
        );

        if ret != ERROR_SUCCESS as i32 {
            Err(format_err!("RegNotifyChangeKeyValue return code: {}", ret))?
        }

        match WaitForSingleObject(wait_handle.handle(), time_num) {
            WAIT_ABANDONED => Err(format_err!("WaitForSingleObject return WAIT_ABANDONED")),
            WAIT_OBJECT_0 => Ok(WatchResponse::Notify),
            WAIT_TIMEOUT => Ok(WatchResponse::Timeout),
            WAIT_FAILED => Err(format_err!(
                "WaitForSingleObject return code: {}",
                GetLastError()
            )),
            _ => unreachable!(),
        }
    }
}
