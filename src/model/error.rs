use std::fmt;

use thiserror::Error;

#[derive(Debug, Error)]
pub struct Error {
    pub message: String
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Custom error: {}", self.message)
    }
}