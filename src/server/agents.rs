use log::info;
use serde::{Deserialize, Serialize};
use chrono::{NaiveDate, Utc};

// #[derive(Deserialize)]
// pub struct AgentData {
//     pub name: String,
//     pub hostname: String,
//     pub os: String,
//     pub arch: String,
//     pub listener_url: String,

//     pub task_result: Option<Vec<u8>>,
// }

// #[derive(Deserialize, Serialize)]
// pub struct AgentDataEnc {
//     pub a: String, // name
//     pub b: String, // hostname
//     pub c: String, // os
//     pub d: String, // arch
//     pub e: String, // listener_url
    
//     pub f: String, // key
//     pub g: String, // nonce

//     pub h: String, // task_result
// }


// pub fn dec_agentdataenc(ade: AgentDataEnc) -> AgentData {
//     // Decode and decrypt
//     let key = ade.f.clone();
//     let nonce = ade.g.clone();

//     let name = decode_decrypt(ade.a.as_bytes(), key.as_bytes(), nonce.as_bytes());
//     let hostname = decode_decrypt(ade.b.as_bytes(), key.as_bytes(), nonce.as_bytes());
//     let os = decode_decrypt(ade.c.as_bytes(), key.as_bytes(), nonce.as_bytes());
//     let arch = decode_decrypt(ade.d.as_bytes(), key.as_bytes(), nonce.as_bytes());
//     let listener_url = decode_decrypt(ade.e.as_bytes(), key.as_bytes(), nonce.as_bytes());
//     let task_result_tmp = decode_decrypt(ade.h.as_bytes(), key.as_bytes(), nonce.as_bytes());

//     let task_result: Option<Vec<u8>> = match String::from_utf8(task_result_tmp.clone()) {
//         Ok(tr_string) => {
//             match tr_string.as_str() {
//                 "none" => None,
//                 _ => Some(tr_string.as_bytes().to_vec()),
//             }
//         }
//         Err(_) => Some(task_result_tmp),
//     };

//     AgentData {
//         name: String::from_utf8(name).unwrap(),
//         hostname: String::from_utf8(hostname).unwrap(),
//         os: String::from_utf8(os).unwrap(),
//         arch: String::from_utf8(arch).unwrap(),
//         listener_url: String::from_utf8(listener_url).unwrap(),
//         key: key.to_owned(),
//         nonce: nonce.to_owned(),
//         task_result,
//     }
// }

// #[derive(Clone, Debug, Serialize)]
// pub enum AgentTask {
//     Empty,

//     Screenshot,
//     Shell(String),
// }

#[derive(Clone, Debug)]
pub struct Agent {
    pub id: u32,
    pub uuid: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub listener_url: String,
    pub public_key: String, // HEX encoded

    pub registered: NaiveDate,
    pub last_commit: String,
}

// 植入物结构体
impl Agent {
    pub fn new(
        id: u32,
        uuid: String,
        hostname: String,
        os: String,
        arch: String,
        listener_url: String,
        public_key: String,
        registered: NaiveDate,
        last_commit: String,
    ) -> Self {
        Self {
            id,
            uuid,
            hostname,
            os,
            arch,
            listener_url,
            public_key,
            registered,
            last_commit,
        }
    }
}

// 列出某个植入物的信息
pub fn format_agent_details(agent: Agent) -> String {
    info!("Getting the agent details...");

    let mut output = String::new();
    // output = output + "+" + "-".repeat(64).as_str() + "\n";
    output = output + "\n";
    output = output + format!("{:<15} : {:<20}\n", "ID", agent.id).as_str();
    output = output + format!("{:<15} : {:<36}\n", "UUID", agent.uuid).as_str();
    output = output + format!("{:<15} : {:<20}\n", "HOSTNAME", agent.hostname).as_str();
    output = output + format!("{:<15} : {:<20}\n", "OS", format!("{}/{}", agent.os.to_owned(), agent.arch.to_owned())).as_str();
    output = output + format!("{:<15} : {:<20}\n", "LISTENER", agent.listener_url).as_str();
    output = output + format!("{:<15} : {:<20}\n", "PUBLIC KEY", agent.public_key).as_str();
    output = output + format!("{:<15} : {:<20}\n", "REGISTERED", agent.registered.to_string()).as_str();
    output = output + format!("{:<15} : {:<40}\n", "LAST COMMIT", agent.last_commit.to_string()).as_str();
    output
}

// 列出所有植入物的信息
pub fn format_all_agents(agents: &Vec<Agent>) -> String  {
    info!("Getting agents status...");
    if agents.len() == 0 {
        return String::new();
    }

    let mut output = String::new();
    output = output + "\n";
    output = output + format!(
        "{:>3} | {:<36} | {:<15} | {:<15} | {:<25} | {:<15} | {:<40}\n",
        "ID", "UUID", "HOSTNAME", "OS", "LISTENER", "REGISTERED", "LAST COMMIT"
    ).as_str();
    output = output + "-".repeat(139).as_str() + "\n";

    for agent in agents {
        output = output + format!(
            "{:>3} | {:<18} | {:<15} | {:<15} | {:<25} | {:<15} | {:<40}\n",
            agent.id.to_owned(),
            agent.uuid.to_owned(),
            agent.hostname.to_owned(),
            format!("{}/{}", agent.os.to_owned(), agent.arch.to_owned()),
            agent.listener_url.to_owned(),
            agent.registered.to_string(),
            agent.last_commit.to_string()
        ).as_str();
    }

    output
}