use rusqlite::Result;

use crate::utils::fs::get_app_dir;
use super::{
    agents::init_agents,
    implants::init_implants,
    keypair::init_keypair,
    listeners::init_listeners,
};

pub const DB_PATH: &str = "server/fusion.db";

#[derive(Debug)]
pub struct DB {
    pub path: String,
}

impl DB {

    pub fn new() -> Self {
        Self {
            path: format!("{}/{}", get_app_dir(), DB_PATH.to_string()),
        }
    }

}


pub fn init_db(db_path: String) -> Result<()> {
    init_listeners(db_path.to_owned())?;
    init_agents(db_path.to_owned())?;
    init_keypair(db_path.to_owned())?;
    init_implants(db_path.to_owned())?;

    Ok(())
}