use std::fs::{File, metadata};
use std::io::prelude::*;
use std::env::args;

mod hasher;
mod feistel;
mod counter_block;
mod file_mng;


fn main() -> std::io::Result<()>{
    let args: Vec<String> = args().collect();
    let path = args[1].to_owned();
    let pass = args[2].to_owned().into_bytes();
    let file_buff = file_mng::read_clear_file(&path)?;
    let cypher = counter_block::encrypt(file_buff, pass.clone(), 15, 5).unwrap();

    file_mng::write_blocks(cypher, r"c:\Users\hacoh\desktop\test_file.txt_enc")?;
    let b = file_mng::read_enc_file(&path)?;
    
    let dec = counter_block::decrypt(b, pass).unwrap();
    let dec_str = String::from_utf8(dec).unwrap();
    let dec_str = dec_str.trim_matches('\x00');
    println!("decrypted => {:?}", dec_str);
    Ok(())
}
