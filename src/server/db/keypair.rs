use log::warn;
use rusqlite::{Connection, Result};

pub fn init_keypair(db_path: String) -> Result<()> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            return Err(e);
        }
    };

    db.execute(
        "CREATE TABLE keypair (
            id      INTEGER PRIMARY KEY,
            secret  TEXT NOT NULL,
            public  TEXT NOT NULL
        )",
        ()
    )?;

    Ok(())
}

pub fn add_keypair(db_path: String, secret_key: String, public_key: String) -> Result<()> {
    let db = match Connection::open(db_path.to_owned()) {
        Ok(d) => d,
        Err(e) => {
            return Err(e);
        }
    };

    let exists = exists_keypair(db_path)?;
    if exists {
        warn!("");
        return Ok(());
    }

    db.execute(
        "INSERT INTO keypair (secret, public) VALUES (?1, ?2)",
        (secret_key, public_key)
    )?;

    Ok(())
}

pub fn exists_keypair(db_path: String) -> Result<bool> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            return Err(e);
        }
    };

    let mut stmt = db.prepare(
        "SELECT * FROM keypair",
    )?;
    let exists = stmt.exists([])?;
    Ok(exists)
}

pub fn delete_all_keypair(db_path: String) -> Result<()> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            return Err(e);
        }
    };

    db.execute("DELETE FROM keypair", ())?;

    Ok(())
}

pub fn get_keypair(db_path: String) -> Result<(String, String)> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            return Err(e);
        }
    };

    let mut stmt = db.prepare(
        "SELECT secret, public FROM keypair"
    )?;
    let (secret, public) = stmt.query_row([], |row| {
        Ok((row.get(0)?, row.get(1)?))
    })?;

    Ok((secret, public))
}

pub fn update_keypair(db_path: String, secret_key: String, public_key: String) -> Result<()> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            return Err(e);
        }
    };

    db.execute(
        "UPDATE keypair SET secret = ?1, public = ?2 WHERE id = 1",
        [secret_key, public_key]
    )?;

    Ok(())
}