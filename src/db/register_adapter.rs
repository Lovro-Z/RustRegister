use std::sync::Arc;

use async_trait::async_trait;
use couch_rs::{error::{CouchError, CouchResult}, types::{document::DocumentCreatedResult, find::FindQuery}, document::DocumentCollection};
use serde_json::json;

use crate::model::{Subject, Details};

use super::Db;

pub struct RegisterAdapter {
    db: Arc<Db>,
}

impl RegisterAdapter {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }
}

#[async_trait]
pub trait DbInteractions {
    async fn get_subject(&self, id: &str) -> Result<Subject, CouchError>;
    async fn create_subject(&self, details: Details) -> DocumentCreatedResult;
    async fn get_subject_list(&self, limit: Option<u64>) -> CouchResult<DocumentCollection<Subject>>;
    async fn get_details(&self, oib: i64) -> Result<DocumentCollection<Details>, CouchError>;
}

#[async_trait]
impl DbInteractions for RegisterAdapter {
    async fn get_subject(&self, id: &str) -> Result<Subject, CouchError> {
        self.db.get(id).await
    }

    async fn create_subject(&self, details: Details) -> DocumentCreatedResult {
        let mut subject_value = json!(details);
        self.db.create(&mut subject_value).await
    }

    async fn get_subject_list(&self, limit: Option<u64>) -> CouchResult<DocumentCollection<Subject>> {
        if let Some(limit) = limit {
            let query = FindQuery::find_all().limit(limit);
            self.db.find(&query).await
        } else {
            self.db.get_all().await
        }
    }

    async fn get_details(&self, oib: i64) -> Result<DocumentCollection<Details>, CouchError> {
        let find_query = FindQuery::new(json!({"oib": oib})).limit(1);
        self.db.find(&find_query).await
    }
}