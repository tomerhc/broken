//!
#![warn(missing_debug_implementations, missing_docs)]

use std::env::args;
mod hasher;
mod feistel;
mod counter_block;
mod file_mng;
mod parse_args;

// TODO: error handling
fn main() -> std::io::Result<()> {
    let parsed_args = parse_args::parse_args(args().collect()).unwrap();
    let mut enc_dec: bool = true;
    let mut path: String = String::new();
    let mut key: String = String::new();
    for (t, v) in parsed_args.into_iter(){
        match &t[..] {
            "encrypt" => {
                enc_dec = true;
                path = v
            },
            "decrypt" => {
                enc_dec = false;
                path = v
            },
            "key" => key = v,
            "parallel" => (),
            _ => panic!("arg parsing error")
        }
    }

    if enc_dec {
        let f = file_mng::read_clear_file(&path)?;
        let pass = key.into_bytes();
        let cypher = counter_block::par_encrypt(f, pass, 30, 5).unwrap();
        path.push_str("_enc");
        file_mng::write_blocks(cypher, &path)?;
    }else{
        let f = file_mng::read_enc_file(&path)?;
        let pass = key.into_bytes();
        let dec = counter_block::par_decrypt(f, pass).unwrap();
        let new_path = path.replace("_enc", "");
        file_mng::write_clear_file(&new_path, dec)?;
    }

    Ok(())
}

mod tests {
    #[test]
    fn _test(){}
    // hasher functions 
    // => hash_xor_key with different lengths
    // 
    // fiestel
    // => encryption with pre comuted values
    // => description with pre comuted values
    // => encryption and decryption
    // => encryption with short msg, long key
    // => decryption with wrong key
    //
    // counter blocks
    // => par_encryption with pre comuted values
    // => par_description with pre comuted values
    // => decryption by block num 
    // => encryptiong twice with same key and msg and check that 
    //    result is not the same
    //
    // parse args 
    // => missing file
    // => missing password
    // => both -e and -d
    // => two of the same flag
    //
    // file_mng
    // => non-existent file
    // => invalid file name
    // => empty file
    //
    // integration
    // => encrypting and decrypting an image file and check original == new. 
}