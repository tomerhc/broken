#![warn(missing_debug_implementations, missing_docs)]
use crate::error::*;
use crate::feistel;
use crate::file_mng;
use byteorder::{LittleEndian, WriteBytesExt};
use glob::MatchOptions;
use rand::Rng;
use rayon::prelude::*;
use std::mem;

/// The Blocks struct is the basic object containing all the information for encrypting or
/// decrypting a byte array. it is used for loading a byte array (from a file or a vector),
/// manipulating it, and writing the results.
#[derive(Debug)]
pub struct Blocks {
    /// nonce: the random seed that is incremented for every block encryption.
    pub nonce: Vec<u8>,
    /// f_rounds: the number of fiestel rounds to preform
    pub f_rounds: i32,
    /// blocks: the actual byte arrays.
    pub blocks: Vec<Vec<u8>>,
}

impl Blocks {
    /// Read a clear file and generate a Blocks struct containing the encrypted data.
    /// This method is inteded for use incase of a signle file encryption, and preforms the
    /// encryption in parallel.
    pub fn from_clear_file(
        path: &str,
        key: &str,
        block_size: usize,
        f_rounds: i32,
    ) -> Result<Self, EncryptErr> {
        let f = file_mng::read_clear_file(path)?;
        let pass = key.to_owned().into_bytes();
        par_encrypt(f, pass, block_size, f_rounds)
    }

    /// Read a glob of clear files and generate Blocks structs containing the encrypted data.
    /// this method is intended for use incase of multiple files encryption, and will encrypt the
    /// files in parallel, rather then encrypting the block of every individual file in parallel.
    pub fn from_clear_glob(
        path: &str,
        key: &str,
        block_size: usize,
        f_rounds: i32,
        options: MatchOptions,
    ) -> Vec<(String, Result<Blocks, EncryptErr>)> {
        let paths = file_mng::list_glob(path, options).unwrap();
        let res: Vec<(String, Result<Blocks, EncryptErr>)> = paths
            .into_par_iter()
            .map(|p| {
                let b = Blocks::from_clear_file(&p, key, block_size, f_rounds);
                (p, b)
            })
            .collect();
        res
    }

    /// Read the contants of an encrypted file and generate a Blocks struct for it, parsing all the
    /// serialized variables (nonce, block size etc.). The Blocks struct will contain the encrypted
    /// data, which can then be decrypted with the into_clear method.
    pub fn from_enc_file(path: &str) -> Result<Self, DecryptErr> {
        file_mng::read_enc_file(&path)
    }

    /// Same as from_enc_file, but only reads the first n blocks of the file.
    pub fn from_enc_head(path: &str, block_num: i32) -> Result<Self, DecryptErr> {
        file_mng::read_first_n(path, block_num)
    }

    /// Same as from_enc_file, but only reads the last n blocks of the file.
    pub fn from_enc_tail(path: &str, block_num: i32) -> Result<(Self, i64), DecryptErr> {
        file_mng::read_last_n(path, block_num)
    }

    /// Read the contants of all encrypted files in a glob and generate a Blocks struct for it, parsing all the
    /// serialized variables (nonce, block size etc.). The Blocks struct will contain the encrypted
    /// data, which can then be decrypted with the into_clear method.
    pub fn from_enc_glob(
        path: &str,
        options: MatchOptions,
    ) -> Vec<(String, Result<Self, DecryptErr>)> {
        let paths = file_mng::list_glob(path, options).unwrap();
        let res: Vec<(String, Result<Self, DecryptErr>)> = paths
            .into_par_iter()
            .map(|p| {
                let b = file_mng::read_enc_file(&p);
                (p, b)
            })
            .collect();
        res
    }

    /// Same as from_enc_glob, but only reads the first n blocks of every file.
    pub fn from_enc_glob_head(
        path: &str,
        options: MatchOptions,
        block_num: i32,
    ) -> Vec<(String, Result<Self, DecryptErr>)> {
        let paths = file_mng::list_glob(path, options).unwrap();
        let res: Vec<(String, Result<Self, DecryptErr>)> = paths
            .into_par_iter()
            .map(|p| {
                let b = file_mng::read_first_n(&p, block_num);
                (p, b)
            })
            .collect();
        res
    }

    /// Same as from_enc_glob, but only reads the last n blocks of every file.
    pub fn from_enc_glob_tail(
        path: &str,
        options: MatchOptions,
        block_num: i32,
    ) -> Vec<(String, Result<(Self, i64), DecryptErr>)> {
        let paths = file_mng::list_glob(path, options).unwrap();
        let res: Vec<(String, Result<(Self, i64), DecryptErr>)> = paths
            .into_par_iter()
            .map(|p| {
                let b = file_mng::read_last_n(&p, block_num);
                (p, b)
            })
            .collect();
        res
    }

    /// Given the correct key, consumes the struct and returns a decrypted byte vector containing the original data.
    pub fn into_clear(self, key: &str, start_block: i64) -> Result<Vec<u8>, DecryptErr> {
        let pass = key.to_owned().into_bytes();
        par_decrypt(self, pass, start_block)
    }

    /// Given the correct key, consume the struct and write the decrypted contants of the struct to
    /// a file.
    pub fn into_clear_file(
        self,
        key: &str,
        path: &str,
        start_block: i64,
    ) -> Result<(), DecryptErr> {
        let pass = key.to_owned().into_bytes();
        let dec = par_decrypt(self, pass, start_block)?;
        file_mng::write_clear_file(path, dec)
    }

    /// writes the encrypted contents and variable of the struct to a file.
    pub fn into_enc_file(self, path: &str) -> Result<(), EncryptErr> {
        file_mng::write_blocks(self, path)
    }
}

/// Preformes a parallel block encryption, using Counter Block mode of operation, and fiestel
/// cypher method.
pub fn par_encrypt(
    mut msg: Vec<u8>,
    key: Vec<u8>,
    block_size: usize,
    f_rounds: i32,
) -> Result<Blocks, EncryptErr> {
    // TODO: assertions
    // number of block nust be less then MAX::i64 because it can overflow the counter

    let nonce_len: usize = 128 - mem::size_of::<i64>(); // nonce needs to be 128 bytes long beacuse of the use of SHA256, including the length of the counter
    let nonce: Vec<u8> = nonce_gen(nonce_len);

    let mut all_batches: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    for (counter, chunk) in msg.chunks_mut(block_size).enumerate() {
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter as i64);
        let chunk_vec: Vec<u8> = chunk.to_vec();
        all_batches.push((nonce_counter, chunk_vec));
    }
    let blocks_res: Vec<Result<Vec<u8>, EncryptErr>> = all_batches
        .into_par_iter()
        .map(|(nonce_counter, block)| {
            encrypt_par_block(nonce_counter, block, key.clone(), f_rounds, block_size)
        })
        .collect();

    let mut blocks: Vec<Vec<u8>> = Vec::new();
    for item in blocks_res.into_iter() {
        match item {
            Ok(i) => blocks.push(i),
            Err(e) => return Err(e),
        }
    }

    Ok(Blocks {
        nonce,
        f_rounds,
        blocks,
    })
}

// may cause trailing null problems!!!!
/// Preformes a parallel block decryption using Counter Block mode of operation, and fiestel cypher
/// method.
pub fn par_decrypt(b: Blocks, key: Vec<u8>, start_block: i64) -> Result<Vec<u8>, DecryptErr> {
    let (nonce, blocks) = (b.nonce, b.blocks);
    let block_len = blocks[0].len();
    let f_rounds = b.f_rounds;
    let mut all_batches: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    let mut msg: Vec<u8> = Vec::with_capacity(blocks.len() * blocks[0].len());
    for (counter, block) in blocks.into_iter().enumerate() {
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter as i64 + start_block);
        all_batches.push((nonce_counter, block));
    }

    let decrypted_blocks: Vec<Result<Vec<u8>, EncryptErr>> = all_batches
        .into_par_iter()
        .map(|(nonce_counter, block)| {
            encrypt_par_block(nonce_counter, block, key.clone(), f_rounds, block_len)
        })
        .collect();

    for item in decrypted_blocks.into_iter() {
        match item {
            Ok(mut i) => msg.append(&mut i),
            Err(e) => return Err(DecryptErr::from(e)),
        }
    }
    Ok(msg)
}

/// The function used by par_encrypt to preform the actual encryption of every block of the
/// messege.
fn encrypt_par_block(
    nonce: Vec<u8>,
    mut chunk: Vec<u8>,
    key: Vec<u8>,
    f_rounds: i32,
    block_size: usize,
) -> Result<Vec<u8>, EncryptErr> {
    let mut cypher = feistel::encrypt(nonce, key, f_rounds)?;
    pad_cypher(&mut cypher, block_size);
    pad_chunk(&mut chunk, block_size);
    chunk
        .iter_mut()
        .zip(cypher.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
    Ok(chunk)
}

/// Generates a random nonce to be used in the ecnryption algorithm.
fn nonce_gen(nonce_len: usize) -> Vec<u8> {
    let v: Vec<u8> = (0..nonce_len)
        .map(|_| {
            let r: u8 = rand::thread_rng().gen();
            r
        })
        .collect();
    v
}

/// Appends an i64 counter to the nonce in orded to mutate it for every block.
fn get_nonce_counter(nonce: &[u8], counter: i64) -> Vec<u8> {
    let mut nonce_counter = nonce.to_vec();
    let mut buff = [0u8; mem::size_of::<i64>()];
    buff.as_mut().write_i64::<LittleEndian>(counter).unwrap();
    nonce_counter.append(&mut buff.to_vec());
    nonce_counter
}

/// pads the cypher generated from xor-ing the nonce with the key, in preperation for xor-ing it
/// with the messege block. The padding is done by duplicating the cypher and then truncating it to
/// size.
fn pad_cypher(cypher: &mut Vec<u8>, block_size: usize) {
    while cypher.len() < block_size {
        cypher.append(&mut cypher.clone());
    }
    cypher.truncate(block_size)
}

/// Pads the messege block in preperation for xor-ing it with the cypher. The padding is trailing
/// nulls
fn pad_chunk(chunk: &mut Vec<u8>, block_size: usize) {
    for _ in 0..block_size - chunk.len() {
        chunk.push(b'\x00');
    }
}

/// Non-parallel encryption of a byte array. returns a Blocks struct containing the encrypted data.
/// This function is intended for use incase of encrypting of multiple files, where the files are
/// encrypted in parallel, not the blocks of every individual file.
pub fn encrypt(
    mut msg: Vec<u8>,
    key: Vec<u8>,
    block_size: usize,
    f_rounds: i32,
) -> Result<Blocks, EncryptErr> {
    // TODO: remove function
    //assertions
    // number of block nust be less then MAX::i64 because it can overflow the counter

    let nonce_len: usize = 128 - mem::size_of::<i64>(); // nonce needs to be 128 bytes long beacuse of the use of SHA256, including the length of the counter
    let nonce: Vec<u8> = nonce_gen(nonce_len);
    let mut blocks: Vec<Vec<u8>> = Vec::with_capacity(msg.len() / block_size);

    for (counter, chunk) in msg.chunks_mut(block_size).enumerate() {
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter as i64);
        let mut cypher = feistel::encrypt(nonce_counter, key.clone(), f_rounds)?;
        let mut chunk = chunk.to_vec();
        pad_cypher(&mut cypher, block_size);
        pad_chunk(&mut chunk, block_size);
        chunk
            .iter_mut()
            .zip(cypher.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
        blocks.push(chunk.to_vec());
    }
    Ok(Blocks {
        nonce,
        f_rounds,
        blocks,
    })
}

/// Non-parallel decryption of a byte array. returns a Blocks struct containing the decrypted data.
/// This function is intended for use incase of decrypting of multiple files, where the files are
/// decrypted in parallel, not the blocks of every individual file.
pub fn decrypt(b: Blocks, key: Vec<u8>, start_block: i64) -> Result<Vec<u8>, DecryptErr> {
    let nonce = b.nonce;
    let mut blocks = b.blocks;
    let mut counter: i64 = start_block;
    let mut msg: Vec<u8> = Vec::with_capacity(blocks.len() * blocks[0].len());
    for mut block in blocks.iter_mut() {
        let nonce_counter: Vec<u8> = get_nonce_counter(&nonce, counter);
        let mut cypher = feistel::encrypt(nonce_counter, key.clone(), b.f_rounds)?;
        pad_cypher(&mut cypher, block.len());
        block
            .iter_mut()
            .zip(cypher.iter())
            .for_each(|(x1, x2)| *x1 ^= *x2);
        msg.append(&mut block);
        counter += 1;
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use crate::counter_block;
    #[test]
    fn par_enc_dec_bytes() {
        let msg = String::from("hello world, this is my string! it may contain אותיות בעברית")
            .into_bytes();
        let key = String::from("super_secret123!@#").into_bytes();
        let blocks = counter_block::par_encrypt(msg, key.clone(), 15, 5).unwrap();
        let dec = counter_block::par_decrypt(blocks, key, 0).unwrap();

        assert_eq!(
            String::from_utf8(dec).unwrap().trim_matches(char::from(0)),
            String::from("hello world, this is my string! it may contain אותיות בעברית")
        );
    }

    #[test]
    fn enc_block_num() {
        // TODO:
    }

    #[test]
    fn dec_wrong_key() {
        let msg = String::from("hello world, this is my string! it may contain אותיות בעברית")
            .into_bytes();
        let key = String::from("super_secret123!@#").into_bytes();
        let wrong_key = String::from("incorrect!").into_bytes();
        let blocks = counter_block::par_encrypt(msg, key.clone(), 15, 5).unwrap();
        let dec = counter_block::par_decrypt(blocks, wrong_key, 0).unwrap();

        assert_ne!(
            dec,
            String::from("hello world, this is my string! it may contain אותיות בעברית")
                .into_bytes()
        );
    }

    #[test]
    fn enc_twice() {
        let msg = String::from("hello world, this is my string! it may contain אותיות בעברית")
            .into_bytes();
        let key = String::from("super_secret123!@#").into_bytes();
        let blocks1 = counter_block::par_encrypt(msg.clone(), key.clone(), 15, 5).unwrap();
        let blocks2 = counter_block::par_encrypt(msg, key.clone(), 15, 5).unwrap();

        assert_ne!(blocks1.nonce, blocks2.nonce);
        assert_ne!(blocks1.blocks, blocks2.blocks);
    }
}
