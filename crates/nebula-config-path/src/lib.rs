use std::{ffi::OsString, path::PathBuf};

fn is_absolute_path(path: OsString) -> Option<PathBuf> {
    let path = PathBuf::from(path);
    if path.is_absolute() {
        Some(path)
    } else {
        None
    }
}

#[cfg(unix)]
mod unix {
    use std::env;
    use std::path::PathBuf;

    pub fn home_dir() -> Option<PathBuf> {
        env::var_os("HOME").and_then(|h| if h.is_empty() { None } else { Some(h) }).map(PathBuf::from)
    }

    pub fn config_dir() -> Option<PathBuf> {
        env::var_os("XDG_CONFIG_HOME")
            .and_then(super::is_absolute_path)
            .or_else(|| home_dir().map(|h| h.join(".config")))
    }
}

#[cfg(unix)]
pub use unix::{config_dir, home_dir};

#[cfg(target_os = "windows")]
mod windows {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::ptr;
    use std::slice;

    use winapi::shared::winerror;
    use winapi::um::{combaseapi, knownfolders, shlobj, shtypes, winbase, winnt};

    pub fn known_folder(folder_id: shtypes::REFKNOWNFOLDERID) -> Option<PathBuf> {
        unsafe {
            let mut path_ptr: winnt::PWSTR = ptr::null_mut();
            let result = shlobj::SHGetKnownFolderPath(folder_id, 0, ptr::null_mut(), &mut path_ptr);
            if result == winerror::S_OK {
                let len = winbase::lstrlenW(path_ptr) as usize;
                let path = slice::from_raw_parts(path_ptr, len);
                let ostr: OsString = OsStringExt::from_wide(path);
                combaseapi::CoTaskMemFree(path_ptr as *mut winapi::ctypes::c_void);
                Some(PathBuf::from(ostr))
            } else {
                None
            }
        }
    }

    pub fn home_dir() -> Option<PathBuf> {
        known_folder(&knownfolders::FOLDERID_Profile)
    }

    pub fn config_dir() -> Option<PathBuf> {
        known_folder(&knownfolders::FOLDERID_RoamingAppData)
    }
}

#[cfg(target_os = "windows")]
pub use windows::{config_dir, home_dir};
