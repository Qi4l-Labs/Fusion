use axum::extract::ws::{Message, WebSocket};
use log::info;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

use crate::server::{
    db,
    implants::{
        generate::generate,
        implant::{format_all_implants, format_implant_details, Implant},
    },
    server::Server
};

pub async fn handle_implant(
    message_text: String,
    args: Vec<String>,
    socket_lock: &mut MutexGuard<'_, WebSocket>,
    server: Arc<Mutex<Server>>,
) {
    let server_lock = server.lock().await;
    let mut implants = db::get_all_implants(server_lock.db.path.to_string()).unwrap();

    match args[1].as_str() {
        "gen" => {
            let i_name = args[2].to_owned();
            let i_url = args[3].to_owned();
            let i_os = args[4].to_owned();
            let i_arch = args[5].to_owned();
            let i_format = args[6].to_owned();
            let i_sleep: u64 = args[7].to_owned().parse().unwrap();
            let i_jitter: u64 = args[8].to_owned().parse().unwrap();

            let implant = Implant::new(
                0, // Temporary ID
                i_name.to_owned(),
                i_url.to_owned(),
                i_os.to_owned(),
                i_arch.to_owned(),
                i_format.to_owned(),
                i_sleep.to_owned(),
                i_jitter.to_owned(),
            );

            // Check duplicate
            let exists = db::exists_implant(
                server_lock.db.path.to_string(),
                implant.clone()
            ).unwrap();
            if exists {
                let _ = socket_lock.send(
                    Message::Text(
                        "[implant:gen:error] Similar implant already exists. Please use it with `implant download`.".to_owned()
                    )).await;
                let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                return;
            }

            // Generate an implant
            match generate(
                server_lock.db.path.to_string(),
                i_name.to_owned(),
                i_url.to_owned(),
                i_os.to_owned(),
                i_arch.to_owned(),
                i_format.to_owned(),
                i_sleep,
                i_jitter,
            ) {
                Ok((output, mut buffer)) => {
                    let _ = send_implant_binary(
                        &mut buffer,
                        socket_lock,
                        output.to_owned(),
                    ).await;

                    // Add to the list (check duplicate again before adding it)
                    let exists = db::exists_implant(server_lock.db.path.to_string(), implant.clone()).unwrap();
                    if exists {
                        let _ = socket_lock.send(
                            Message::Text(
                                "[implant:gen:error] Similar implant already exists. Please use it with `implant download`.".to_owned()
                            )).await;
                        let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                        return;
                    }
                    match db::add_implant(server_lock.db.path.to_string(), implant.clone()) {
                        Ok(_) => {}
                        Err(e) => {
                            let _ = socket_lock.send(
                                Message::Text(
                                    format!("[implant:gen:error] {}", e.to_string())
                                )).await;
                            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                            return;
                        }
                    }       
                },
                Err(e) => {
                    let _ = socket_lock.send(
                        Message::Text(format!("[implant:gen:error] Could not generate an imaplant: {e}"))
                    ).await;
                }
            }

            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;

        }
        "download" => {
            let i_name = args[2].to_owned();
            // Get the implant
            let mut target_implant: Option<Implant> = None;
            for implant in implants {
                if implant.id.to_string() == i_name || implant.name == i_name {
                    target_implant = Some(implant.to_owned());
                    break;
                }
            }

            if let Some(imp) = target_implant {
                match generate(
                    server_lock.db.path.to_string(),
                    imp.name,
                    imp.url,
                    imp.os,
                    imp.arch,
                    imp.format,
                    imp.sleep,
                    imp.jitter,
                ) {
                    Ok((output, mut buffer)) => {
                        let _ = send_implant_binary(
                            &mut buffer,
                            socket_lock,
                            output.to_owned(),
                        ).await;

                    },
                    Err(e) => {
                        let _ = socket_lock.send(
                            Message::Text(format!("[implant:gen:error] {e}"))
                        ).await;
                    }
                }
            } else {
                let _ = socket_lock.send(
                    Message::Text(
                        format!("[implant:gen:error] Implant not found."))).await;
            }

            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        "delete" => {
            info!("Deleting the implant.");
            let i_name = args[2].to_owned();

            if i_name == "all" {
                match db::delete_all_implants(server_lock.db.path.to_string()) {
                    Ok(_) => {
                        let _ = socket_lock.send(
                            Message::Text(
                                "[implant:delete:ok] All implants deleted successfully.".to_owned()
                            )).await;
                    }
                    Err(_) => {
                        let _ = socket_lock.send(
                            Message::Text(
                                "[implant:delete:error] All implants could not be deleted.".to_owned()
                            )).await;
                    }
                }
            } else {
                match db::delete_implant(server_lock.db.path.to_string(), i_name.to_string()) {
                    Ok(_) => {
                        let _ = socket_lock.send(
                            Message::Text(
                                "[implant:delete:ok] Implant deleted successfully.".to_owned()
                            )).await;
                    }
                    Err(_) => {
                        let _ = socket_lock.send(
                            Message::Text(
                                "[implant:delete:error] Implant could not be deleted.".to_owned()
                            )).await;
                    }
                }
            }
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        "info" => {
            let i_name = args[2].to_owned();
            let implant = match db::get_implant(server_lock.db.path.to_string(), i_name.to_string()) {
                Ok(imp) => imp,
                Err(e) => {
                    let _ = socket_lock.send(
                        Message::Text(
                            format!("[implant:info:error] {}", e.to_string()))).await;
                    let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                    return;
                }
            };

            let output = format_implant_details(implant);
            let _ = socket_lock.send(Message::Text(output)).await;
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        "list" => {
            let output = format_all_implants(&mut implants);

            if output == "" {
                let _ = socket_lock.send(
                    Message::Text("[implant:list:error] Implant not found.".to_owned())).await;
            } else {
                let _ = socket_lock.send(Message::Text(output)).await;
            }
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
        _ => {
            let _ = socket_lock.send(Message::Text(format!("Unknown command: {message_text}"))).await;
            let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
        }
    }
}

async fn send_implant_binary(
    buffer: &mut Vec<u8>,
    socket_lock: &mut MutexGuard<'_, WebSocket>,
    output: String,
) {
    let split_size: usize = 10000000;

    if buffer.len() < split_size {
        let _ = socket_lock.send(
            Message::Text(format!(
                "[implant:gen:ok:complete] {}",
                output,
            ))).await;
        let _ = socket_lock.send(Message::Binary(buffer.to_vec())).await;
        return;
    }

    // let mut buf_split: Vec<Vec<u8>> = Vec::new();

    // Split buffer    
    let buffer2 = buffer.split_off(split_size);
    
    let _ = socket_lock.send(
        Message::Text("[implant:gen:ok:sending]".to_owned())).await;
    let _ = socket_lock.send(Message::Binary(buffer.to_vec())).await;

    let _ = socket_lock.send(
        Message::Text(format!(
            "[implant:gen:ok:complete] {}",
            output,
        ))).await;
    let _ = socket_lock.send(Message::Binary(buffer2.to_vec())).await;
}