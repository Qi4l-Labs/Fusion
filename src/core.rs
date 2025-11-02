#[cfg(target_os = "linux")]
pub mod run_linux;
#[cfg(target_os = "windows")]
pub mod run_windows;
#[cfg(target_os = "macos")]
pub mod run_mac;


pub mod postdata;
pub mod systeminfo;
pub mod tasks;