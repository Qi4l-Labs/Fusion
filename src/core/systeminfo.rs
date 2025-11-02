#[cfg(target_os = "linux")]
pub mod systeminfo_linux;
#[cfg(target_os = "windows")]
pub mod systeminfo_windows;