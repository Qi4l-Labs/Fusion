use log::{info, warn};
use rusqlite::{Connection, Result};

use crate::server::agents::Agent;

pub fn init_agents(db_path: String) -> Result<()> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => { 
            return Err(e);
        }
    };

    db.execute(
        "CREATE TABLE agents (
            id              INTEGER PRIMARY KEY,
            uuid            TEXT NOT NULL UNIQUE,
            hostname        TEXT NOT NULL,
            os              TEXT NOT NULL,
            arch            TEXT NOT NULL,
            listener_url    TEXT NOT NULL,
            public_key      TEXT NOT NULL,
            registered      TEXT NOT NULL,
            last_commit     TEXT NOT NULL
        )",
        (),
    )?;

    Ok(())
}

pub fn add_agent(db_path: String, agent: Agent) -> Result<()> {
    let db = match Connection::open(db_path.to_owned()) {
        Ok(d) => d,
        Err(e) => { 
            return Err(e);
        }
    };

    // Check if already exists
    let exists = exists_agent(
        db_path.to_owned(),
        agent.uuid.to_string(),
    )?;

    if exists {
        // Update other values if repeated
        info!("Agent already exists, update Agent info");
        db.execute(
            "UPDATE agents SET public_key = ?1, registered = ?2, last_commit = ?3 WHERE uuid = ?4",
            (
                agent.public_key.to_owned(),
                agent.registered.to_string(),
                agent.last_commit.to_string(),
                agent.uuid.to_owned(),
            ),
        )?;

        return Ok(())
    }

    db.execute(
        "INSERT INTO agents (
            uuid, hostname, os, arch, listener_url, public_key, registered, last_commit
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8
        )",
        (
            agent.uuid.to_owned(),
            agent.hostname.to_owned(),
            agent.os.to_owned(),
            agent.arch.to_owned(),
            agent.listener_url.to_owned(),
            agent.public_key.to_owned(),
            agent.registered.to_string(),
            agent.last_commit.to_string(),
        ),
    )?;

    Ok(())
}

pub fn exists_agent(db_path: String, agent_uuid: String) -> Result<bool> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => { 
            return Err(e);
        }
    };

    let mut stmt = db.prepare(
        "SELECT * FROM agents WHERE id = ?1 OR uuid = ?2",
    )?;
    let exists = stmt.exists([agent_uuid.to_string(), agent_uuid.to_string()])?;

    Ok(exists)
}

pub fn delete_agent(db_path: String, agent_uuid: String) -> Result<()> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => { 
            return Err(e);
        }
    };

    db.execute(
        "DELETE FROM agents WHERE id = ?1 OR uuid = ?2",
        [agent_uuid.to_string(), agent_uuid.to_string()],
    )?;

    Ok(())
}

pub fn delete_all_agents(db_path: String) -> Result<()> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => { 
            return Err(e);
        }
    };

    db.execute("DELETE FROM agents", [])?;
    Ok(())
}

pub fn get_agent(
    db_path: String,
    uuid: String,
) -> Result<Agent> {
    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => { 
            return Err(e);
        }
    };

    let mut stmt = db.prepare(
        "SELECT id, uuid, hostname, os, arch, listener_url, public_key, registered, last_commit
            FROM agents WHERE id = ?1 OR uuid = ?2"
    )?;
    let agent = stmt.query_row([uuid.to_string(), uuid.to_string()], |row| {
        Ok(Agent::new(
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
        ))
    })?;

    Ok(agent)
}

pub fn update_agent_last_commit(
    db_path: String,
    uuid: String,
    last_commit: String,
) -> Result<()> {
    let db = match Connection::open(db_path.to_owned()) {
        Ok(d) => d,
        Err(e) => {
            return Err(e);
        }
    };

    db.execute(
        "UPDATE agents SET last_commit = ?1 WHERE uuid = ?2",
        (
            last_commit,
            uuid,
        ),
    )?;
    Ok(())
}


pub fn get_all_agents(db_path: String) -> Result<Vec<Agent>> {
    let mut agents: Vec<Agent> = Vec::new();

    let db = match Connection::open(db_path) {
        Ok(d) => d,
        Err(e) => { 
            return Err(e);
        }
    };

    let mut stmt = db.prepare(
        "SELECT id, uuid, hostname, os, arch, listener_url, public_key, registered, last_commit
            FROM agents"
    )?;
    let agent_iter = stmt.query_map([], |row| {
        Ok(Agent::new(
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
            row.get(5)?,
            row.get(6)?,
            row.get(7)?,
            row.get(8)?,
        ))
    })?;

    for agent in agent_iter {
        agents.push(agent.unwrap());
    }

    Ok(agents)
}

// pub fn update_agent(db_path: String, agent: Agent) -> Result<()> {
//     let db = match Connection::open(db_path) {
//         Ok(d) => d,
//         Err(e) => {
//             return Err(e);
//         }
//     };
//
//     db.execute(
//         "UPDATE agents SET name = ?1, public_key = ?2 WHERE name = ?3",
//         [
//             agent.uuid,
//             agent.public_key,
//             agent.hostname,
//         ]
//     )?;
//
//     Ok(())
// }