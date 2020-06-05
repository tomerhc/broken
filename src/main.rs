use std::fs::{File, metadata};
use std::io::prelude::*;
use std::env::args;

mod hasher;
mod feistel;
mod counter_block;


fn main() -> std::io::Result<()>{
    let args: Vec<String> = args().collect();
    let mut path = args[1].to_owned();
    let pass = args[2].to_owned().into_bytes();
    let mut file = File::open(&path)?;
    let meta = metadata(&path)?;
    let mut buff = vec![0u8;meta.len() as usize];
    file.read(&mut buff)?;

    let mut cypher = counter_block::encrypt(buff, pass, 15, 5).unwrap();
    let mut write_buff: Vec<u8> = Vec::new();
    write_buff.append(&mut cypher.nonce);
    for b in cypher.blocks.iter_mut(){
        write_buff.append(b);
    }
    path.push_str("_enc");
    let mut enc_file = File::create(path)?;
    enc_file.write_all(&mut write_buff)?;
    Ok(())
}



fn old_main(){
    let text = String::from("hello wolrd, ny name is tomer and i am here to write an encryption softwere and save the world from slow enryption.");
    let bytes = text.into_bytes();
    let key = String::from("Barvaz1");
    let key_bytes = key.into_bytes();
    
    let cypher = counter_block::encrypt(bytes, key_bytes.clone(), 15, 3).unwrap();
    println!("nonce => {:?}\n", cypher.nonce);
    for b in cypher.blocks.iter(){
        println!("{:?}", String::from_utf8(b.to_vec()))
    }
    let dec = counter_block::decrypt(cypher, key_bytes).unwrap();
    let dec_str = String::from_utf8(dec).unwrap();
    let dec_str = dec_str.trim_matches('\x00');
    println!("decrypted => {:?}", dec_str)
}