pub struct ListenerConfig {
    pub proto: String,
    pub host: String,
    pub port: u16,
    pub user_agent: String,
    pub https_root_cert: String,
    pub https_client_cert: String,
    pub https_client_key: String,
}

impl ListenerConfig {
    pub fn new(
        proto: String,
        host: String,
        port: u16,
        user_agent: String,
        https_root_cert: String,
        https_client_cert: String,
        https_client_key: String,
    ) -> Self {
        
        Self {
            proto,
            host,
            port,
            user_agent,
            https_root_cert,
            https_client_cert,
            https_client_key
        }
    }
}