use couch_rs::{document::TypedCouchDocument, types::document::DocumentId};
use couch_rs::CouchDocument;
use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, CouchDocument, Debug)]
pub struct Details {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub _id: DocumentId,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub _rev: String,
    pub mbs: i64,
    pub oib: i64,
}
