#![allow(dead_code, unused_imports, unused_variables, deprecated)]
use crate::utils::fs::read_json;
use clap::{Parser, Subcommand};
use env_logger::Env;
use log::warn;

pub mod banner;
pub mod config;
pub mod server;
pub mod utils;

use crate::{banner::banner, config::Config, server::server::run, utils::fs::mkdir};
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
    mkdir("server".to_string()).unwrap();
    banner("server");

    let _ = run(
        config,
        read_json("server-config", "fusion-port").parse().unwrap(),
    )
    .await;
}
