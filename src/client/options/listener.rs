#[derive(Debug)]
pub struct ListenerOption {
    pub name: Option<String>,
    pub domains: Option<Vec<String>>,
    pub proto: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
}