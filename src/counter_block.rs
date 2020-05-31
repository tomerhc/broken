extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt};
use std::mem;
use rand::Rng;
use crate::feistel;

pub struct Blocks {
    pub nonce: Vec<u8>,
    pub f_rounds: i32,
    pub blocks: Vec<Vec<u8>>
}

pub fn encrypt(mut msg: Vec<u8>, key: Vec<u8>, block_size: usize, f_rounds: i32) -> Result<Blocks, String>{
    //assertions
    // number of block nust be less then MAX::i64 because it can overflow the counter
    
    let nonce_len: usize = 128 - mem::size_of::<i64>(); // nonce needs to be 128 bytes long beacuse of the use of SHA256, including the length of the counter
    let nonce: Vec<u8> = nonce_gen(nonce_len);
    let mut counter: i64 = 0;
    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(msg.len()/block_size);

    for chunk in msg.chunks_mut(block_size){
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter)?;
        let cypher = feistel::encrypt(nonce_counter, key.clone(), f_rounds);
        let mut chunk = chunk.to_vec();
        match cypher {
            Ok(_) => (),
            Err(e) => return Err(format!("{:?}", e))
        }
        let mut cypher = cypher.unwrap();
        pad_cypher(&mut cypher, block_size);
        pad_chunk(&mut chunk, block_size);
        chunk.iter_mut().zip(cypher.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
        blocks.push(chunk.to_vec());
        counter += 1;
    }
    Ok(Blocks {
        nonce: nonce,
        f_rounds: f_rounds,
        blocks: blocks
    })
}

pub fn decrypt(b: Blocks, key: Vec<u8>) -> Result<Vec<u8>, String>{
    let nonce = b.nonce;
    let mut blocks = b.blocks;
    let mut counter: i64 = 0;
    let mut msg: Vec<u8> = Vec::with_capacity(blocks.len() * blocks[0].len());
    for mut block in blocks.iter_mut() {
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter)?;
        let cypher = feistel::encrypt(nonce_counter, key.clone(), b.f_rounds);
        match cypher {
            Ok(_) => (),
            Err(e) => return Err(format!("{:?}", e))
        }
        let mut cypher = cypher.unwrap();
        pad_cypher(&mut cypher, block.len());
        block.iter_mut().zip(cypher.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
        msg.append(&mut block);
        counter += 1;
    } 
    Ok(msg)
}


pub fn decrypt_block(b: Blocks, block_num: usize){

}

pub fn parallel_encryption(){

}

pub fn parallel_decryption(){

}


fn nonce_gen(nonce_len: usize) -> Vec<u8> {
    let v: Vec<u8> = (0..nonce_len).map(|_|{
        let r: u8 = rand::thread_rng().gen();
        r
    }).collect();
    v
}

fn get_nonce_counter(nonce: &[u8], counter: i64) -> Result<Vec<u8>, String> {
    let mut nonce_counter = nonce.to_vec();
    let mut buff = [0u8; mem::size_of::<i64>()];
    match buff.as_mut().write_i64::<LittleEndian>(counter){
        Ok(_) => (),
        Err(e) => return Err(format!("{}", e))
    }
    nonce_counter.append(&mut buff.to_vec());
    Ok(nonce_counter)
}

fn pad_cypher(cypher: &mut Vec<u8>, block_size: usize) {
    while cypher.len() < block_size{
        cypher.append(&mut cypher.clone());
    }
    cypher.truncate(block_size)    
}

fn pad_chunk(chunk: &mut Vec<u8>, block_size: usize) {
    for _ in 0..block_size-chunk.len() {
        chunk.push(b'\x00');
    }
}
