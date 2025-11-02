#![allow(unused_imports)]
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Read environment variables for initiali settings
    // let lproto = env::var_os("fusion_LPROTO").unwrap();
    // let lhost = env::var_os("fusion_LHOST").unwrap();
    // let lport = env::var_os("fusion_LPORT").unwrap();
    // let sleep = env::var_os("fusion_SLEEP").unwrap();
    // let jitter = env::var_os("fusion_JITTER").unwrap();
    // let user_agent = env::var_os("fusion_USER_AGENT").unwrap();
    // let https_root_cert = env::var_os("fusion_HTTPS_ROOT_CERT").unwrap();
    // let https_client_cert = env::var_os("fusion_HTTPS_CLIENT_CERT").unwrap();
    // let https_client_key = env::var_os("fusion_HTTPS_CLIENT_KEY").unwrap();
    // let server_public_key = env::var_os("fusion_PUBLIC_KEY").unwrap();
    //
    // let out_dir = env::var_os("OUT_DIR").unwrap(); // This is not allowed the prefix `fusion_` by cargo.
    // let dest_path = Path::new(&out_dir).join("init.rs");
    //
    // fs::write(
    //     &dest_path,
    //     format!("pub fn init() -> (
    //         &'static str,
    //         &'static str,
    //         u16,
    //         u64,
    //         u64,
    //         &'static str,
    //         &'static str,
    //         &'static str,
    //         &'static str,
    //         &'static str,
    //     ) {}
    //         (\"{}\", \"{}\", {}, {}, {}, \"{}\", \"{}\", \"{}\", \"{}\", \"{}\")
    //     {}
    //     ",
    //     "{",
    //     lproto.into_string().unwrap(),
    //     lhost.into_string().unwrap(),
    //     lport.into_string().unwrap(),
    //     sleep.into_string().unwrap(),
    //     jitter.into_string().unwrap(),
    //     user_agent.into_string().unwrap(),
    //     https_root_cert.into_string().unwrap(),
    //     https_client_cert.into_string().unwrap(),
    //     https_client_key.into_string().unwrap(),
    //     server_public_key.into_string().unwrap(),
    //     "}"
    // )).unwrap();
    //
    // println!("cargo:rerun-if-changed=build.rs");
}