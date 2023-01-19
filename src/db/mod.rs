use std::sync::Arc;

use couch_rs::{error::CouchError, database::Database};

mod register_adapter;
pub use register_adapter::RegisterAdapter;
pub use register_adapter::DbInteractions;

use crate::env::Env;

//data for local db
/*const DB_HOST: &str = "http://localhost:5984";
const DB_NAME: &str = "sudski_registar";
const DB_USER: &str = "root";
const DB_PASSWORD: &str = "pass";*/

pub type Db = Database; 

//init local db
/*pub async fn init_db() -> Result<Db, CouchError> {
        new_db(DB_HOST, DB_NAME, DB_USER, DB_PASSWORD).await
} */

pub async fn init_db(env: Arc<Env>) -> Result<Db, CouchError> {
    new_db(&env.db_host, &env.db_name, &env.db_user, &env.db_password).await
}
async fn new_db(db_host: &str, db_name: &str, user: &str, password: &str) -> Result<Db, CouchError> {
    let client = couch_rs::Client::new(db_host, user, password)?;
    client.db(db_name).await
}
