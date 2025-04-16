#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "windows")]
pub mod win;
#[cfg(target_os = "macos")]
pub mod macos;
pub mod screenshot;