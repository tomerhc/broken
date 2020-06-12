use std::fs::{File, metadata};
use std::io::prelude::*;
use std::mem;
use byteorder::{LittleEndian, WriteBytesExt};
use crate::error::*;
use crate::counter_block;


pub fn read_clear_file(path: &str) -> std::io::Result<Vec<u8>>{
    let mut f = File::open(path)?;
    let meta = metadata(path)?;
    let mut buff = vec![0u8;meta.len() as usize];
    f.read_exact(&mut buff)?;
    Ok(buff)
}

pub fn write_clear_file(path: &str, buff: Vec<u8>) -> Result<(), DecryptErr>{
    let mut f = File::create(path)?;
    f.write_all(&buff)?;
    Ok(())
}

pub fn read_enc_file(path: &str) -> Result<counter_block::Blocks, DecryptErr>{
    // TODO: assertions
    let mut f = File::open(path).unwrap();
    let mut block_size_buff = [0u8;mem::size_of::<i32>()];
    let mut nonce_size_buff = [0u8;mem::size_of::<i32>()];
    let mut rounds_num_buff = [0u8;mem::size_of::<i32>()];

    f.read_exact(&mut block_size_buff)?;
    f.read_exact(&mut nonce_size_buff)?;
    f.read_exact(&mut rounds_num_buff)?;

    let block_size: i32 = i32::from_le_bytes(block_size_buff);
    let nonce_size: i32 = i32::from_le_bytes(nonce_size_buff);
    let f_rounds: i32 = i32::from_le_bytes(rounds_num_buff);
    let rest_of_file = f.metadata().unwrap().len() as usize - (3 * mem::size_of::<i32>()) - nonce_size as usize;
    let mut nonce = vec![0u8; nonce_size as usize];
    f.read_exact(&mut nonce)?;

    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(rest_of_file / block_size as usize);
    for _ in 0..blocks.capacity(){
        let mut buff = vec![0u8; block_size as usize];
        f.read_exact(&mut buff)?;
        blocks.push(buff);
    }
    Ok(
        counter_block::Blocks {
            nonce,
            f_rounds,
            blocks
        }
    )
}


pub fn write_blocks(mut cypher: counter_block::Blocks, path: &str) -> Result<(), EncryptErr>{
    // TODO: assertions

    let block_size = cypher.blocks[0].len();
    let byte_size = cypher.blocks.len() * block_size;
    let nonce_size = cypher.nonce.len();
    
    let mut serial_rounds_num = [0u8;mem::size_of::<i32>()];
    let mut serial_block_size = [0u8;mem::size_of::<i32>()];
    let mut serial_nonce_size = [0u8;mem::size_of::<i32>()];
    
    serial_rounds_num.as_mut().write_i32::<LittleEndian>(cypher.f_rounds).expect("could not write num rounds");
    serial_block_size.as_mut().write_i32::<LittleEndian>(block_size as i32).expect("could not write block size");
    serial_nonce_size.as_mut().write_i32::<LittleEndian>(nonce_size as i32).expect("could not write nonce size");
    
    let mut write_buff: Vec<u8> = Vec::with_capacity(nonce_size + byte_size + serial_rounds_num.len());
    
    write_buff.append(&mut serial_block_size.to_vec());
    write_buff.append(&mut serial_nonce_size.to_vec());
    write_buff.append(&mut serial_rounds_num.to_vec());
    write_buff.append(&mut cypher.nonce);
    for b in cypher.blocks.iter_mut(){
        write_buff.append(b)
    }
    let mut enc_file = File::create(path)?;
    enc_file.write_all(&write_buff)?;
    Ok(())
}

// TODO: load head / tail of file
// TODO: batch / directory reads and writes



