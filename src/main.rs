#![allow(dead_code, unused_imports, unused_variables, deprecated)]
use crate::utils::fs::read_json;
use clap::{Parser, Subcommand};
use env_logger::Env;
use log::warn;

pub mod banner;
pub mod client;
pub mod config;
pub mod utils;

use crate::{banner::banner, client::client::Client, config::Config, utils::fs::mkdir};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let mut config = Config::new();

    match home::home_dir() {
        Some(path) if !path.as_os_str().is_empty() => {
            config.app_dir = format!("{}/.fusion", path.display()).into();
        }
        _ => warn!("Unable to get your home dir. "),
    }

    mkdir("agents".to_owned()).unwrap();
    mkdir("implants".to_owned()).unwrap();
    mkdir("tmp".to_owned()).unwrap();

    mkdir("client".to_string()).unwrap();
    banner("client");

    let _ = Client::new(
        read_json("server-config", "fusion-host"),
        read_json("server-config", "fusion-port").parse().unwrap(),
    )
    .run()
    .await;
}
