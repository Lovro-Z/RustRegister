use couch_rs::{document::TypedCouchDocument, types::document::DocumentId};
use couch_rs::CouchDocument;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, CouchDocument, Debug, PartialEq, Eq, Clone)]
pub struct Subject {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub _id: DocumentId,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub _rev: String,
    pub oib: i64,
}