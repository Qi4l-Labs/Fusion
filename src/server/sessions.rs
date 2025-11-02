#[derive(Debug)]
pub struct Session {
    pub id: u32,
    pub user: String,
    pub hostname: String,
    pub os: String,
    pub available: bool,
}