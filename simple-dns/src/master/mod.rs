//! DNS Master file parsing

mod parse_error;
mod parser;
mod tokenizer;

pub use parse_error::ParseError;
pub use parser::{parse, parse_file};
