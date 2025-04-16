// References:
// - https://learn.microsoft.com/en-us/windows/win32/procthread/creating-processes
// - https://github.com/ibigbug/windows-rs-CreateProcessW/blob/master/src/main.rs

use encoding_rs::GBK;
use std::{
    ffi::{c_void, OsStr},
    os::windows::ffi::OsStrExt,
};
use windows::{
    core::{Error, PWSTR, HRESULT, HSTRING, PCWSTR},
    Win32::{
        Foundation::{
            BOOL, CloseHandle, HANDLE,
            WAIT_EVENT, WAIT_OBJECT_0,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::ReadFile,
        System::{
            Pipes::{CreatePipe, PeekNamedPipe},
            Threading::{
                CreateProcessW,
                GetExitCodeProcess,
                PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
                STARTF_USESHOWWINDOW, STARTF_USESTDHANDLES,
                STARTUPINFOW,
                WaitForSingleObject,
            },
            IO::OVERLAPPED,
        },
        UI::WindowsAndMessaging::SW_HIDE,
    }
};

pub async fn shell(command: String) -> Result<Vec<u8>, Error> {
    let mut output: Vec<u8> = Vec::with_capacity(1024);

    let mut hreadpipe = HANDLE::default();
    let mut hwritepipe = HANDLE::default();

    let mut secattr = SECURITY_ATTRIBUTES::default();
    secattr.bInheritHandle = BOOL(true as i32);
    secattr.lpSecurityDescriptor = std::ptr::null_mut() as *mut c_void;
    
    unsafe {
        CreatePipe(
            &mut hreadpipe,
            &mut hwritepipe,
            Some(&mut secattr),
            0
        )?;
    }

    // Parse command
    let args = match shellwords::split(command.as_str()) {
        Ok(args) => { args }
        Err(err) => {
            // println!("Can't parse command line: {err}");
            vec!["".to_string()]
        }
    };

    let command = match args[0].as_str() {
        "cmd" => "cmd.exe /c ".to_string() + args[1..].join(" ").as_str(),
        // "powershell" => "powershell.exe /c ".to_string() + args[1..].join(" ").as_str(),
        "powershell" => "powershell.exe -noP -sta -w 1 ".to_string() + args[1..].join(" ").as_str(),
        _ => {
            return Err(Error::from_win32());
        },
    };

    let mut command_utf16: Vec<u16> = command.encode_utf16().chain(std::iter::once(0)).collect();

    let inherit_handles = true;
    let creation_flags = PROCESS_CREATION_FLAGS(0);

    // Create a process
    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
    si.hStdOutput = hwritepipe;
    si.hStdError = hwritepipe;
    si.wShowWindow = SW_HIDE.0 as u16;

    let mut pi = PROCESS_INFORMATION::default();

    let current_dir = std::env::current_dir().unwrap();
    let wide_path: Vec<u16> = current_dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let current_dir_ptr = wide_path.as_ptr();

    unsafe {
        // Reference: https://docs.rs/CreateProcessW/latest/src/CreateProcessW/lib.rs.html#304
        if let Err(e) = CreateProcessW(
            PCWSTR::null(),
            PWSTR(command_utf16.as_mut_ptr()),
            None,
            None,
            inherit_handles,
            creation_flags,
            None,
            PCWSTR(current_dir_ptr),
            &mut si,
            &mut pi,
        ) {
            // println!("Could not create a process: {}", e.to_string());
            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
            return Err(e);
        };

        let mut bprocessend = false;
        while !bprocessend {
            bprocessend = WaitForSingleObject(pi.hProcess, 50) == WAIT_OBJECT_0;

            loop {
                let mut buf = [0u8; 1024];
                let mut dwread: u32 = 0;
                let mut dwavail: u32 = 0;

                let success = PeekNamedPipe(
                    hreadpipe,
                    None,
                    0,
                    None,
                    Some(&mut dwavail),
                    None,
                );
                if success.is_err() {
                    break;
                }

                if dwavail == 0 {
                    break;
                }

                let success = ReadFile(
                    hreadpipe,
                    Some(&mut buf),
                    Some(&mut dwread),
                    Some(&mut OVERLAPPED::default()),
                );
                if success.is_err() {
                    println!("Error reading file.");
                    break;
                }

                // 只将有效读取的字节加入 output
                output.extend_from_slice(&buf[..dwread as usize]);
            }
        }

        // 关闭句柄
        let _ = CloseHandle(hwritepipe);
        let _ = CloseHandle(hreadpipe);
        let _ = CloseHandle(pi.hProcess);
        let _ = CloseHandle(pi.hThread);
    }

    Ok(output.to_vec())
}