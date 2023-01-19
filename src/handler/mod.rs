use std::sync::Arc;

use async_trait::async_trait;
use couch_rs::{error::{CouchError, CouchResult}, types::document::DocumentCreatedResult, document::DocumentCollection};

use crate::{db::{RegisterAdapter, DbInteractions}, model::{Subject, Details}};

#[derive(Clone)]
pub struct Handler {
    pub register_adapter: Arc<RegisterAdapter>,
}

impl Handler {
    pub fn new(register_adapter: Arc<RegisterAdapter>) -> Self {
        Self{
            register_adapter
        }
    }
}

#[async_trait]
pub trait HandlerInt {
    async fn get_subject(&self, id: &str) -> Result<Subject, CouchError>;
    async fn create_subject(&self, details: Details) -> DocumentCreatedResult;
    async fn get_subject_list(&self, limit: Option<u64>) -> CouchResult<DocumentCollection<Subject>>;
    async fn get_details(&self, oib: i64) -> Result<DocumentCollection<Details>, CouchError>;
}

#[async_trait]
impl HandlerInt for Handler {
    async fn get_subject(&self, id: &str) -> Result<Subject, CouchError> {
        let subject: Subject = self.register_adapter.get_subject(id).await?;
        Ok(subject)
    }

    async fn create_subject(&self, details: Details) -> DocumentCreatedResult {
        let subject_id = self.register_adapter.create_subject(details).await?;
        Ok(subject_id)
    }

    async fn get_subject_list(&self, limit: Option<u64>) -> CouchResult<DocumentCollection<Subject>> {
        let subject_list = self.register_adapter.get_subject_list(limit).await?;
        Ok(subject_list)
    }

    async fn get_details(&self, oib: i64) -> Result<DocumentCollection<Details>, CouchError> {
        let details: DocumentCollection<Details> = self.register_adapter.get_details(oib).await?;
        Ok(details)
    }
}