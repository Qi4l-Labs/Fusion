// References for Windows API:
//  - https://learn.microsoft.com/en-us/windows/win32/sysinfo/system-information-functions
//  - https://microsoft.github.io/windows-docs-rs/doc/windows/
use std::io::{Error, ErrorKind};
use windows::{
    core::PWSTR,
    Win32::{
        Foundation::{WIN32_ERROR, ERROR_BUFFER_OVERFLOW},
        Networking::WinSock::AF_UNSPEC,
        NetworkManagement::IpHelper::{
            GetAdaptersAddresses,
            GET_ADAPTERS_ADDRESSES_FLAGS,
            IP_ADAPTER_ADDRESSES_LH},
        System::SystemInformation::{
            ComputerNameDnsHostname,
            GetComputerNameExW,
            GetSystemInfo,
            SYSTEM_INFO,
        },
    },
};

pub fn get_adapters_addresses() -> Result<String, Error> {
    unsafe {
        let mut buf_size = 0;

        // Get buffer size
        let result = GetAdaptersAddresses(
            AF_UNSPEC.0.into(),
            GET_ADAPTERS_ADDRESSES_FLAGS(0),
            None,
            None,
            &mut buf_size,
        );

        match WIN32_ERROR(result) {
            ERROR_BUFFER_OVERFLOW => {}
            e => {
                return Ok("error".to_string());
            }
        }

        let block_size = std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
        let new_capacity = buf_size + block_size;
        let mut buf = Vec::<u8>::with_capacity(new_capacity as usize);

        let (prefix, body, _) = buf.align_to_mut::<IP_ADAPTER_ADDRESSES_LH>();

        let mut buf_size = new_capacity - prefix.len() as u32;

        let error = GetAdaptersAddresses(
            AF_UNSPEC.0.into(),
            GET_ADAPTERS_ADDRESSES_FLAGS(0),
            None,
            Some(body.as_mut_ptr()),
            &mut buf_size
        );

        match WIN32_ERROR(result) {
            ERROR_BUFFER_OVERFLOW => {}
            e => {
                return Ok("error".to_string());
            }
        }

        let p_adapter = body.as_mut_ptr();
        let adapter = &*p_adapter;
        println!("AdapteraName: {:?}", adapter.AdapterName.to_string().unwrap());
        println!("Description: {:?}", adapter.Description.to_string().unwrap());
        println!("FirstDnsServerAddress: {:?}", adapter.FirstDnsServerAddress);
        // println!("FirstGatewayAddress: {:?}", adapter.FirstGatewayAddress);
        // println!("FirstWinsServerAddress: {:?}", adapter.FirstWinsServerAddress);
        println!("FriendlyName: {:?}", adapter.FriendlyName.to_string().unwrap());
        // println!("Ipv4Metric: {:?}", adapter.Ipv4Metric.to_string());
        // println!("Ipv6Metric: {:?}", adapter.Ipv6Metric.to_string());
        // println!("PhysicalAddress: {:?}", String::from_utf8(adapter.PhysicalAddress.to_vec()).to_owned());

        Ok("ok".to_string())
    }
}

pub fn get_computer_name() -> Result<String, Error> {
    unsafe {
        let mut buf_size = 0;

        // Get buffer size
        let _ = GetComputerNameExW(
            ComputerNameDnsHostname,
            PWSTR::null(),
            &mut buf_size,
        );

        let mut buf = Vec::with_capacity((buf_size as usize) + 8);
        if let Err(e) = GetComputerNameExW(
            ComputerNameDnsHostname,
            PWSTR::from_raw(buf.as_mut_ptr()),
            &mut buf_size,
        ) {
            println!("Error: {e}");
            return Err(Error::new(ErrorKind::Other, format!("{e}")));
        }

        buf.set_len(buf_size as usize);
        match String::from_utf16(&buf) {
            Ok(name) => Ok(name),
            Err(e) => Err(Error::new(ErrorKind::Other, format!("{e}"))),
        }
    }
}

pub fn get_systeminfo() {
    unsafe {
        let mut buffer = SYSTEM_INFO::default();
        GetSystemInfo(&mut buffer);
        println!("Number of Processors: {:?}", buffer.dwNumberOfProcessors);
    }
}