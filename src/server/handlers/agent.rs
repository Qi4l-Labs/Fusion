use axum::extract::ws::{Message, WebSocket};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

use crate::server::{
    agents::{format_agent_details, format_all_agents},
    db,
    server::Server,
};

pub async fn handle_agent(
    args: Vec<String>,
    socket_lock: &mut MutexGuard<'_, WebSocket>,
    server: Arc<Mutex<Server>>
) {
    let server_lock = server.lock().await;
    let mut agents = db::get_all_agents(server_lock.db.path.to_string()).unwrap();

    match args[1].as_str() {
        "use" => {
            let ag_name = args[2].to_string();

            let mut found = false;
            for agent in agents {
                if agent.id.to_string() == ag_name || agent.uuid == ag_name {
                    found = true;

                    let _ = socket_lock.send(
                        Message::Text(format!("[agent:use:ok] {} {}", agent.uuid, agent.os))).await;
                    let _ = socket_lock.send(
                        Message::Text("[done]".to_owned())
                    ).await;

                    break;
                }
            }

            if !found {
                let _ = socket_lock.send(
                    Message::Text("[agent:use:error] Agent not found.".to_owned())
                ).await;
                let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
            }
        }
        "delete" => {
            let ag_name = args[2].to_string();

            if ag_name.as_str() == "all" {
                match db::delete_all_agents(server_lock.db.path.to_string()) {
                    Ok(_) => {
                        let _ = socket_lock.send(
                            Message::Text("[agent:delete:ok] All agents deleted successfully.".to_owned())
                        ).await;
                    }
                    Err(e) => {
                        let _ = socket_lock.send(
                            Message::Text(
                                format!("[agent:delete:error] Error deleting all agents: {:?}", e)
                            )).await;
                    }
                }

                let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
            } else {
                let mut found = false;
                for agent in agents {
                    if agent.id.to_string() == ag_name || agent.uuid == ag_name {
                        found = true;
    
                        match db::delete_agent(
                            server_lock.db.path.to_string(),
                            ag_name.to_string()
                        ) {
                            Ok(_) => {
                                let _ = socket_lock.send(
                                    Message::Text("[agent:delete:ok] Agent deleted successfully.".to_owned())
                                ).await;
                            }
                            Err(e) => {
                                let _ = socket_lock.send(
                                    Message::Text(
                                        format!("[agent:delete:error] Error deleting the agent: {:?}", e))
                                ).await;
                            }
                        }
    
                        let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                        break;
                    }
                }
    
                if !found {
                    let _ = socket_lock.send(
                        Message::Text("[agent:delete:error] Agent not found.".to_owned())
                    ).await;
                    let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                }
            }

        }
        "info" => {
            let ag_name = args[2].to_string();
            let agent = match db::get_agent(
                server_lock.db.path.to_string(),
                ag_name.to_string()
            ) {
                Ok(ag) => ag,
                Err(_) => {
                    let _ = socket_lock.send(Message::Text("[agent:info:error] Agent not found.".to_owned())).await;
                    let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                    return;
                }
            };

            let output = format_agent_details(agent);
            let _ = socket_lock.send(Message::Text(output)).await;
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        "list" => {
            let output = format_all_agents(&mut agents);

            if output == "" {
                let _ = socket_lock.send(Message::Text("[agent:list:error] Agent not found.".to_owned())).await;
            } else {
                let _ = socket_lock.send(Message::Text(output)).await;
            }
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        _ => {
            let _ = socket_lock.send(Message::Text("Unknown arguments".to_owned())).await;
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
    }
}