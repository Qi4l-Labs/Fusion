#[derive(Debug)]
pub struct ImplantOption {
    pub name: Option<String>,
    pub url: Option<String>,
    pub os: Option<String>,
    pub arch: Option<String>,
    pub format: Option<String>,
    pub sleep: Option<u64>,
    pub jitter: Option<u64>,
}