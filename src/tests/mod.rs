use std::sync::Arc;

use super::{init_env, init_db};

#[tokio::test]
async fn env_init_env() -> Result<(), Box<dyn std::error::Error>> {
    init_env().await?;
    Ok(())
}

#[tokio::test]
async fn db_init_db() -> Result<(), Box<dyn std::error::Error>> {
    let env = init_env().await?;
    let env = Arc::new(env);

    let _db = init_db(env).await?;
    Ok(())
}