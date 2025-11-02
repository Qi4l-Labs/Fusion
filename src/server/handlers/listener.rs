use axum::extract::ws::{Message, WebSocket};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use url::Url;

use crate::server::{
    db,
    jobs::{find_job, format_all_listeners, format_listener_details, JobMessage},
    server::Server,
};

pub async fn handle_listener(
    args: Vec<String>,
    socket_lock: &mut MutexGuard<'_, WebSocket>,
    server: Arc<Mutex<Server>>,
) {
    let mut server_lock = server.lock().await;

    match args[1].as_str() {
        "add" => {
            let name = &args[2];
            let hostnames: Vec<String> = args[3].split(",").map(|s| s.to_string()).collect();
            let url = Url::parse(&args[4]).unwrap();

            match server_lock.add_listener(
                name.to_string(),
                hostnames,
                url.scheme().to_string(),
                url.host().unwrap().to_string(),
                url.port().unwrap().to_owned(),
                false,
            ).await {
                Ok(_) => {
                    let _ = socket_lock.send(Message::Text(
                        "[listener:add:ok] Listener added successfully.".to_owned())).await;
                },
                Err(e) => {
                    let _ = socket_lock.send(Message::Text(
                        format!("[listener:add:error] {}", e.to_string()))).await;
                },
            }
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        "delete" => {
            let name = args[2].to_string();

            if name.as_str() == "all" {
                match server_lock.delete_all_listeners().await {
                    Ok(_) => {
                        let _ = socket_lock.send(
                            Message::Text(
                                "[listener:delete:ok] All listeners deleted successfully.".to_owned()
                            )).await;
                    }
                    Err(e) => {
                        let _ = socket_lock.send(
                            Message::Text(
                                format!("[listener:delete:error] {}", e.to_string())
                            )).await;
                    }
                }
            } else {
                match server_lock.delete_listener(name.to_string()).await {
                    Ok(_) => {
                        let _ = socket_lock.send(
                            Message::Text(
                                "[listener:delete:ok] Listener deleted successfully.".to_owned()
                            )).await;
                    },
                    Err(e) => {
                        let _ = socket_lock.send(
                            Message::Text(
                                format!("[listener:delete:error] {}", e.to_string())
                            )).await;
                    }
                }
            }
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        "start" => {
            let target = args[2].to_owned();

            let mut jobs = server_lock.jobs.lock().await;
            let job = match find_job(&mut jobs, target.to_owned()).await {
                Some(j) => j,
                None => {
                    let _ = socket_lock.send(Message::Text(
                        format!("[listener:start:error] Listener `{target}` not found."))).await;
                    let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                    return;
                }
            };

            if !job.running {
                let _ = server_lock.tx_job.lock().await.send(JobMessage::Start(job.id));
                job.running = true;
                let _ = socket_lock.send(
                    Message::Text(format!("[listener:start:ok] Listener `{target}` started."))).await;
            } else {
                let _ = socket_lock.send(
                    Message::Text(
                        format!("[listener:start:warn] Listener `{target}` is already running"))).await;
            }
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        "stop" => {
            let target = args[2].to_string();

            let mut jobs = server_lock.jobs.lock().await;
            let job = match find_job(&mut jobs, target.to_owned()).await {
                Some(j) => j,
                None => {
                    let _ = socket_lock.send(
                        Message::Text(format!("[listener:stop:error] Listener `{target}` not found."))).await;
                    let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                    return;
                }
            };

            if job.running {
                let _ = server_lock.tx_job.lock().await.send(JobMessage::Stop(job.id));
                job.running = false;
                let _ = socket_lock.send(
                    Message::Text(format!("[listener:stop:ok] Listener `{target}` stopped."))).await;
            } else {
                let _ = socket_lock.send(
                    Message::Text(format!("[listener:stop:warn] Listener `{target}` is not running."))).await;
            }
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        "info" => {
            let target = args[2].to_string();

            let mut jobs = server_lock.jobs.lock().await;
            let job = match find_job(&mut jobs, target.to_owned()).await {
                Some(j) => j,
                None => {
                    let _ = socket_lock.send(
                        Message::Text(format!("[listener:info:error] Listener `{target}` not found."))).await;
                    let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                    return;
                }
            };

            let output = format_listener_details(job);
            let _ = socket_lock.send(Message::Text(output)).await;
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
            
        }
        "list" => {
            let mut jobs = server_lock.jobs.lock().await;
            let output = format_all_listeners(&mut jobs);

            if output == "" {
                let _ = socket_lock.send(
                    Message::Text("[listener:list:error] Listener not found.".to_owned())).await;
            } else {
                let _ = socket_lock.send(Message::Text(output)).await;
            }
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        _ => {
            let _ = socket_lock.send(Message::Text("Unknown arguments".to_owned())).await;
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
            return;
        }
    }
}