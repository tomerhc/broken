use crate::file_mng;
use crate::counter_block;
// TODO: maybe rename struct to file / msg and implement functions as methods in an OOP style?
pub struct Blocks {
    pub nonce: Vec<u8>,
    pub f_rounds: i32,
    pub blocks: Vec<Vec<u8>>,
}

pub impl Blocks {
    pub fn from_file(path: &str, key: &str, block_size: usize, f_rounds: i32) -> Result<Self, Box<dyn std::error:Error> {
       let f: file_mng::read_clear_file(path)?;
       let pass = key.to_owned().into_bytes();
       counter_block::par_encrypt(f, pass, block_size, f_rounds)
    }
}
