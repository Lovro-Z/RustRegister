use warp::hyper::Error;

use crate::handler::Handler;
use std::sync::Arc;

mod register;

pub struct WebServer {
    pub handler: Arc<Handler>,
}

impl WebServer {
    pub fn new(handler: Arc<Handler>) -> Self {
        Self { handler }
    }

    pub async fn start_server(&self, web_port: u16) -> Result<(), Error> {
    
        println!("Server running at: localhost:{}", web_port);
        let root_filter = register::register_handler(self.handler.clone());
        //warp::serve(root_filter).run(([127,0,0,1], web_port)).await;
        let (_adr, fut) = warp::serve(root_filter)
            .bind_with_graceful_shutdown(([127,0,0,1], web_port), async move {
                tokio::signal::ctrl_c()
                    .await
                    .expect("failed to listen to shutdown signal");
            });
        fut.await;
        println!("Server shuting down");
        Ok(())
    }
}