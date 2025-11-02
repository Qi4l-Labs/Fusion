
use rand::thread_rng;
use uuid::Uuid;
use crate::utils::random::random_name;

#[cfg(target_os = "windows")]
use winreg::enums::HKEY_LOCAL_MACHINE;
#[cfg(target_os = "windows")]
use winreg::RegKey;

pub fn uuid_from_mac() -> String {
    let mut uuid: String = "".to_string();
    let mac_result = mac_address::get_mac_address();
    match mac_result {
        Ok(Some(mac)) => {
            let namespace = Uuid::NAMESPACE_DNS;
            uuid = String::from(Uuid::new_v5(&namespace, mac.to_string().as_bytes()));
        }
        Ok(None) => {
            // println!("未找到MAC地址");
        }
        Err(e) => {
            // println!("获取MAC地址失败: {}", e);
        }
    }
    uuid
}

#[cfg(target_os = "windows")]
pub fn get_uuid_windows() -> String {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey("SYSTEM\\HardwareConfig") {
        Ok(cur_ver) => {
            let last_config: String = cur_ver.get_value("LastConfig").unwrap();
            let uuid = last_config.trim_matches(|c| c == '{' || c == '}');
            return uuid.to_string()
        }
        Err(e) => {
            uuid_from_mac()
        }
    };
    uuid_from_mac()
}

#[cfg(not(target_os = "windows"))]
pub fn get_uuid_windows() -> String {
    // 在非Windows平台上，可以返回一个空字符串或使用其他方法生成UUID
    uuid_from_mac()
}

pub fn get_uuid_linux(prefix: String) -> String {
    // 在Linux平台上生成UUID
    let namespace = Uuid::NAMESPACE_DNS;
    let uuid = Uuid::new_v5(&namespace, prefix.as_bytes());
    uuid.to_string()
}

pub fn get_uuid() -> String {
    if cfg!(target_os = "windows") {
        get_uuid_windows()
    } else if cfg!(target_os = "linux") {
        get_uuid_linux(random_name("".to_string()))
    } else {
        uuid_from_mac()
    }
}
