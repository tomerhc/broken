use glob::{glob_with, MatchOptions};
use std::fs::{metadata, File};
use std::io::{Cursor, SeekFrom};

use crate::counter_block;
use crate::error::*;
use byteorder::{LittleEndian, WriteBytesExt};
use std::io::prelude::*;
use std::mem;

///Used for reading a file for encryption
/// # Errors
/// Returns error if file not found or ther is a problem in reading it.
pub fn read_clear_file(path: &str) -> Result<Vec<u8>, EncryptErr> {
    let mut f = File::open(path)?;
    let meta = metadata(path)?;
    let mut buff = vec![0u8; meta.len() as usize];
    f.read_exact(&mut buff)?;
    Ok(buff)
}

///Used for writing a file after it has been decrypted.
/// # Errors
/// returns an error if there is a problem creating the file or a problem writing to it.
pub fn write_clear_file(path: &str, buff: Vec<u8>) -> Result<(), DecryptErr> {
    let mut f = File::create(path)?;
    f.write_all(&buff)?;
    Ok(())
}

///Used for reading a file for encryption.
/// The function parses the file costume header created by the encryption and returns a <counter_block::Blocks> struct.
/// notice: encrypted files will probably have a different file extention then their unencrypted version!
/// # Errors
/// Returns error if file not found or there is a problem in reading it.
pub fn read_enc_file(path: &str) -> Result<counter_block::Blocks, DecryptErr> {
    // TODO: assertions
    let mut f = File::open(path)?;
    let mut block_size_buff = [0u8; mem::size_of::<i32>()];
    let mut nonce_size_buff = [0u8; mem::size_of::<i32>()];
    let mut rounds_num_buff = [0u8; mem::size_of::<i32>()];

    f.read_exact(&mut block_size_buff)?;
    f.read_exact(&mut nonce_size_buff)?;
    f.read_exact(&mut rounds_num_buff)?;

    let block_size: i32 = i32::from_le_bytes(block_size_buff);
    let nonce_size: i32 = i32::from_le_bytes(nonce_size_buff);
    let f_rounds: i32 = i32::from_le_bytes(rounds_num_buff);
    let file_size = f.metadata().unwrap().len() as usize;
    if nonce_size > file_size as i32 {
        return Err(DecryptErr::IoError(String::from(
            "file not encrypted or corrupted",
        )));
    }

    let rest_of_file = file_size - (3 * mem::size_of::<i32>()) - nonce_size as usize;
    let mut nonce = vec![0u8; nonce_size as usize];
    f.read_exact(&mut nonce)?;

    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(rest_of_file / block_size as usize);
    for _ in 0..blocks.capacity() {
        let mut buff = vec![0u8; block_size as usize];
        f.read_exact(&mut buff)?;
        blocks.push(buff);
    }
    Ok(counter_block::Blocks {
        nonce,
        f_rounds,
        blocks,
    })
}

///Used for writing a <counter_block::Blocks> struct to a file.
/// Converts the nonce, block size and other params to a header and appends the raw bytes to it.
/// # Errors
/// returns an error if there is a problem creating the file or a problem writing to it.
pub fn write_blocks(mut cypher: counter_block::Blocks, path: &str) -> Result<(), EncryptErr> {
    // TODO: assertions

    let block_size = cypher.blocks[0].len();
    let byte_size = cypher.blocks.len() * block_size;
    let nonce_size = cypher.nonce.len();

    let mut serial_rounds_num = [0u8; mem::size_of::<i32>()];
    let mut serial_block_size = [0u8; mem::size_of::<i32>()];
    let mut serial_nonce_size = [0u8; mem::size_of::<i32>()];

    serial_rounds_num
        .as_mut()
        .write_i32::<LittleEndian>(cypher.f_rounds)
        .expect("could not write num rounds");
    serial_block_size
        .as_mut()
        .write_i32::<LittleEndian>(block_size as i32)
        .expect("could not write block size");
    serial_nonce_size
        .as_mut()
        .write_i32::<LittleEndian>(nonce_size as i32)
        .expect("could not write nonce size");

    let mut write_buff: Vec<u8> =
        Vec::with_capacity(nonce_size + byte_size + serial_rounds_num.len());

    write_buff.append(&mut serial_block_size.to_vec());
    write_buff.append(&mut serial_nonce_size.to_vec());
    write_buff.append(&mut serial_rounds_num.to_vec());
    write_buff.append(&mut cypher.nonce);
    for b in cypher.blocks.iter_mut() {
        write_buff.append(b)
    }
    let mut enc_file = File::create(path)?;
    enc_file.write_all(&write_buff)?;
    Ok(())
}

// TODO: load head / tail of file
pub fn read_first_n(path: &str, n: i32) -> Result<counter_block::Blocks, DecryptErr> {
    let mut f = File::open(path)?;
    let mut block_size_buff = [0u8; mem::size_of::<i32>()];
    let mut nonce_size_buff = [0u8; mem::size_of::<i32>()];
    let mut rounds_num_buff = [0u8; mem::size_of::<i32>()];

    f.read_exact(&mut block_size_buff)?;
    f.read_exact(&mut nonce_size_buff)?;
    f.read_exact(&mut rounds_num_buff)?;

    let block_size: i32 = i32::from_le_bytes(block_size_buff);
    let nonce_size: i32 = i32::from_le_bytes(nonce_size_buff);
    let f_rounds: i32 = i32::from_le_bytes(rounds_num_buff);
    let start_of_blocks = (3 * mem::size_of::<i32>()) as u64 + nonce_size as u64;
    let len = n as usize * block_size as usize;

    let mut nonce = vec![0u8; nonce_size as usize];
    f.read_exact(&mut nonce)?;

    let blocks_vec: Vec<u8> = read_from_to(&mut f, start_of_blocks, len)?;
    let blocks: Vec<Vec<u8>> = blocks_vec
        .chunks_exact(block_size as usize)
        .map(|x| x.to_vec())
        .collect();
    Ok(counter_block::Blocks {
        nonce,
        f_rounds,
        blocks,
    })
}

pub fn read_from_to(f: &mut File, from: u64, len: usize) -> std::io::Result<Vec<u8>> {
    assert!(f.metadata().unwrap().len() > from + len as u64);

    let mut buff: Vec<u8> = vec![0u8; len];
    f.seek(SeekFrom::Start(from))?;
    f.read_exact(&mut buff)?;
    Ok(buff)
}

// TODO: batch / directory reads and writes

pub fn list_glob(
    path: &str,
    options: MatchOptions,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let paths = glob_with(path, options)?;
    let mut res: Vec<String> = Vec::new();
    for entry in paths {
        if let Ok(p) = entry {
            res.push(p.display().to_string());
        }
    }
    Ok(res)
}
