use std::sync::Arc;

use db::RegisterAdapter;
use env::init_env;
use handler::Handler;
use log::{LevelFilter, error};
use log4rs::{Config, config::{Appender, Root}, append::console::ConsoleAppender};
use web::WebServer;

use crate::db::init_db;

mod db;
mod web;
mod model;
mod handler;
mod util;
mod env;

#[cfg(test)]
mod tests;

const DEFAULT_WEB_PORT: u16 = 8080;

#[tokio::main]
async fn main() {

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(ConsoleAppender::builder().build())))
        .build(Root::builder().appender("stdout").build(LevelFilter::Debug))
        .unwrap();
    let _handle = log4rs::init_config(config).unwrap();

    //use when deployed in environment
    //init env
    let env = init_env().await.expect("Init env failed");
    let env = Arc::new(env);

    //init db
    let db = init_db(env).await.expect("Init db failed");
    let db = Arc::new(db);

    //init register adapter
    let reg_adapter = Arc::new(RegisterAdapter::new(db));

    //init handler
    let handler = Arc::new(Handler::new(reg_adapter));

    //init web server
    let web_server = Arc::new(WebServer::new(handler));

    //start web server
    match web_server.start_server(DEFAULT_WEB_PORT).await {
        Ok(_) => println!("Server ended"),
        Err(ex) => error!("Web server failed to start: {:?}", ex)
    }
}
