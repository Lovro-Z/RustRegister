use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RegisterDetails {
    pub mbs: i64,
    pub oib: i64,
}