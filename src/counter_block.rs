extern crate byteorder;
use byteorder::{LittleEndian, WriteBytesExt};
use rayon::prelude::*;
use std::mem;
use rand::Rng;
use crate::feistel;
use crate::error::*;


// TODO: maybe rename struct to file / msg and implement functions as methods in an OOP style?
pub struct Blocks {
    pub nonce: Vec<u8>,
    pub f_rounds: i32,
    pub blocks: Vec<Vec<u8>>
}

pub fn par_encrypt(mut msg: Vec<u8>, key: Vec<u8>, block_size: usize, f_rounds: i32) -> Result<Blocks, EncryptErr>{
    // TODO: assertions
    // number of block nust be less then MAX::i64 because it can overflow the counter
    
    let nonce_len: usize = 128 - mem::size_of::<i64>(); // nonce needs to be 128 bytes long beacuse of the use of SHA256, including the length of the counter
    let nonce: Vec<u8> = nonce_gen(nonce_len);

    let mut all_batches: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (counter, chunk) in msg.chunks_mut(block_size).enumerate(){
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter as i64);
        let chunk_vec: Vec<u8> = chunk.to_vec();
        all_batches.push((nonce_counter, chunk_vec));
    }
    let blocks_res: Vec<Result<Vec<u8>, EncryptErr>> = all_batches.into_par_iter()
    .map(
        |(nonce_counter, block)|
        encrypt_par_block(nonce_counter, block, key.clone(), f_rounds, block_size)
    ).collect();

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    for item in blocks_res.into_iter(){
        match item{
            Ok(i) => blocks.push(i),
            Err(e) => return Err(e)
        }
    }

    Ok(Blocks {
        nonce,
        f_rounds,
        blocks
    })
}


// may cause trailing null problems!!!!
pub fn par_decrypt(b: Blocks, key: Vec<u8>) -> Result<Vec<u8>, DecryptErr>{
    // TODO: assertions
    
    let (nonce, blocks) = (b.nonce, b.blocks);
    let block_len = blocks[0].len();
    let f_rounds = b.f_rounds;
    let mut all_batches: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut msg: Vec<u8> = Vec::with_capacity(blocks.len() * blocks[0].len());
    for (counter, block) in blocks.into_iter().enumerate(){
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter as i64);
        all_batches.push((nonce_counter, block));
    }
    
    let decrypted_blocks: Vec<Result<Vec<u8>, EncryptErr>> = all_batches.into_par_iter()
    .map(
        |(nonce_counter, block)|
        encrypt_par_block(nonce_counter, block, key.clone(), f_rounds, block_len)
    ).collect();
    
    for item in decrypted_blocks.into_iter(){
        match item{
            Ok(mut i) => msg.append(&mut i),
            Err(e) => return Err(DecryptErr::from(e))
        }
    }
    Ok(msg)
}

// TODO: decrypt by block num
// pub fn decrypt_block(b: Blocks, block_num: usize){

// }






fn encrypt_par_block(nonce: Vec<u8>, mut chunk: Vec<u8>, key: Vec<u8>, f_rounds: i32, block_size: usize) -> Result<Vec<u8>, EncryptErr>{
    let mut cypher = feistel::encrypt(nonce, key, f_rounds)?;
    pad_cypher(&mut cypher, block_size);
    pad_chunk(&mut chunk, block_size);
    chunk.iter_mut().zip(cypher.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    Ok(chunk)
}

fn nonce_gen(nonce_len: usize) -> Vec<u8> {
    let v: Vec<u8> = (0..nonce_len).map(|_|{
        let r: u8 = rand::thread_rng().gen();
        r
    }).collect();
    v
}

fn get_nonce_counter(nonce: &[u8], counter: i64) -> Vec<u8> {
    let mut nonce_counter = nonce.to_vec();
    let mut buff = [0u8; mem::size_of::<i64>()];
    buff.as_mut().write_i64::<LittleEndian>(counter).unwrap();
    nonce_counter.append(&mut buff.to_vec());
    nonce_counter
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



pub fn encrypt(mut msg: Vec<u8>, key: Vec<u8>, block_size: usize, f_rounds: i32) -> Result<Blocks, EncryptErr>{
        // TODO: remove function
    //assertions
    // number of block nust be less then MAX::i64 because it can overflow the counter
    
    let nonce_len: usize = 128 - mem::size_of::<i64>(); // nonce needs to be 128 bytes long beacuse of the use of SHA256, including the length of the counter
    let nonce: Vec<u8> = nonce_gen(nonce_len);
    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(msg.len()/block_size);

    for (counter, chunk) in msg.chunks_mut(block_size).enumerate(){
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter as i64);
        let mut cypher = feistel::encrypt(nonce_counter, key.clone(), f_rounds)?;
        let mut chunk = chunk.to_vec();
        pad_cypher(&mut cypher, block_size);
        pad_chunk(&mut chunk, block_size);
        chunk.iter_mut().zip(cypher.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
        blocks.push(chunk.to_vec());
    }
    Ok(Blocks {
        nonce,
        f_rounds,
        blocks
    })
}


pub fn decrypt(b: Blocks, key: Vec<u8>) -> Result<Vec<u8>, DecryptErr>{
    // TODO: remove function

    let nonce = b.nonce;
    let mut blocks = b.blocks;
    let mut counter: i64 = 0;
    let mut msg: Vec<u8> = Vec::with_capacity(blocks.len() * blocks[0].len());
    for mut block in blocks.iter_mut() {
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter);
        let mut cypher = feistel::encrypt(nonce_counter, key.clone(), b.f_rounds)?;
        pad_cypher(&mut cypher, block.len());
        block.iter_mut().zip(cypher.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
        msg.append(&mut block);
        counter += 1;
    } 
    Ok(msg)
}
