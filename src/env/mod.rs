use std::env;

use crate::model::Error;

pub struct Env {
    pub db_host: String,
    pub db_name: String,
    pub db_user: String,
    pub db_password: String,
    pub sud_reg_token: String
}

impl Env {
    pub fn new(db_host: String, db_name: String, db_user: String, db_password: String, sud_reg_token: String) -> Self {
        Self {
            db_host, db_name, db_user, db_password, sud_reg_token
        }
    }
}

pub async fn init_env() -> Result<Env, Error> {
    let db_host: String = env::var("DB_HOST").unwrap_or_else(|_| "http://127.0.0.1:5984/".to_string());
    let db_name: String = env::var("DB_NAME").unwrap_or_else(|_| "sudski_registar".to_string());
    let db_user: String = env::var("DB_USER").unwrap_or_else(|_| "root".to_string());
    let db_password: String = env::var("DB_PASSWORD").unwrap_or_else(|_| "pass".to_string());
    let sud_reg_token: String = env::var("SUD_REG_TOKEN").unwrap_or_else(|_| "fd2756eee54b4b25b59b586a9185ea3b".to_string());
    Ok(Env::new(db_host, db_name, db_user, db_password, sud_reg_token))
}