#[warn(missing_debug_implementations, missing_docs)]

use std::env::args;
use std::process::exit;
mod hasher;
mod feistel;
mod counter_block;
mod file_mng;
mod parse_args;
mod error;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parsed_args_res = parse_args::parse_args(args().collect());
    let parsed_args = match parsed_args_res {
        Ok(parsed_args) => parsed_args,
        Err(_) => exit(0)
    };
    
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
            _ => ()
        }
    }

    if enc_dec {
        let f = file_mng::read_clear_file(&path)?;
        let pass = key.into_bytes();
        let cypher = counter_block::par_encrypt(f, pass, 30, 5)?;
        path.push_str("_enc");
        file_mng::write_blocks(cypher, &path)?;
    }else{
        let f = file_mng::read_enc_file(&path)?;
        let pass = key.into_bytes();
        let dec = counter_block::par_decrypt(f, pass)?;
        let new_path = path.replace("_enc", "");
        file_mng::write_clear_file(&new_path, dec)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    // ---hasher functions--- 
    // => hash_xor_key with different lengths
    fn hash_diff_len(){
        let mut msg = String::from("hello world, this is a string").into_bytes();
        let mut key = String::from("short").into_bytes();
        assert_eq!(hasher::hash_xor_key(&mut msg, &mut key).unwrap(), String::from("2b273b58b5f5cb8c45b10c1e8d92262e0e49498d5baa339f737fb87b8efd2415").into_bytes());
    }

    // ---fiestel---
    // => encryption with pre-comuted values
    // => decryption with pre-comuted values
    // => encryption with short msg, long key

    #[test]
    fn enc_bytes(){
        let msg = String::from("hello world, this is my string! it may contain אותיות בעברית").into_bytes();
        let key = String::from("super_secret123!@#").into_bytes();
        let res = feistel::encrypt(msg, key, 5).unwrap();

        assert_eq!(res, vec![212, 199, 130, 246, 134, 201, 139, 252, 82, 15, 80, 5, 87, 95, 0, 93, 3, 86, 81, 83, 80, 3, 1, 6, 87, 84, 5, 80, 13, 4, 83, 0, 5, 95, 6, 92, 1, 80, 4, 83, 81, 2, 81, 92, 9, 86, 1, 5, 82, 85, 0, 86, 0, 91, 2, 87, 0, 87, 7, 3, 83, 5, 6, 4, 95, 3, 88, 81, 0, 64, 71, 10, 66, 13, 3, 70, 21, 21, 90, 8, 31, 70, 14, 26, 69, 14, 29, 70, 67, 28, 71, 90, 
            5, 88, 66, 79, 89, 76, 77, 90, 87, 66, 65, 14, 13, 2, 16, 81, 11, 91, 17, 187, 244, 224, 173, 183, 199, 224, 252, 187, 166, 232, 204, 71, 224, 245, 229, 145]);
    }   

    #[test]
    fn dec_bytes(){
        let bytes = vec![212, 199, 130, 246, 134, 201, 139, 252, 82, 15, 80, 5, 87, 95, 0, 93, 3, 86, 81, 83, 80, 3, 1, 6, 87, 84, 5, 80, 13, 4, 83, 0, 5, 95, 6, 92, 1, 80, 4, 83, 81, 2, 81, 92, 9, 86, 1, 5, 82, 85, 0, 86, 0, 91, 2, 87, 0, 87, 7, 3, 83, 5, 6, 4, 95, 3, 88, 81, 0, 64, 71, 10, 66, 13, 3, 70, 21, 21, 90, 8, 31, 70, 14, 26, 69, 14, 29, 70, 67, 28, 71, 90, 
        5, 88, 66, 79, 89, 76, 77, 90, 87, 66, 65, 14, 13, 2, 16, 81, 11, 91, 17, 187, 244, 224, 173, 183, 199, 224, 252, 187, 166, 232, 204, 71, 224, 245, 229, 145];
        let key = String::from("super_secret123!@#").into_bytes();
        let res = feistel::decrypt(bytes, key, 5).unwrap();
        assert_eq!(String::from_utf8(res).unwrap().replace("\u{0}", ""), String::from("hello world, this is my string! it may contain אותיות בעברית"));
    }

    #[test]
    fn enc_short_msg_long_key() {
        let msg = String::from("hey").into_bytes();
        let key = String::from("super_secret123!@#blabalbalbalbalablabal123123123").into_bytes();
        let res = feistel::encrypt(msg,key,5).unwrap();
        assert_eq!(res, vec![82, 3, 83, 1, 87, 83, 92, 87, 86, 6, 15, 1, 82, 84, 15, 89, 6, 6, 2, 0, 83, 13, 80, 13, 85, 87, 5, 1, 6, 3, 0, 10, 4, 1, 9, 12, 0, 84, 14, 81, 8, 81, 80, 80, 89, 6, 4, 0, 86, 11, 5, 4, 2, 7, 82, 6, 0, 7, 3, 81, 86, 83, 93, 85, 13, 90, 28, 99, 105, 53, 63, 49, 63, 49, 52, 54, 49, 48, 51, 50, 110, 99, 62, 102, 107, 101, 48, 55, 49, 53, 51, 97, 109, 62, 59, 99, 105, 51, 99, 52, 109, 54, 106, 109, 54, 108, 50, 53, 49, 52, 60, 55, 59, 61, 52, 62, 106, 54, 99, 110, 96, 48, 54, 108, 50, 101, 51, 102]); 
    }

    // ---counter blocks---
    // => par_encryption with pre comuted values -> cant happen because nonce is random
    // => par_description with pre comuted values -> cant happen because nonce is random
    // ===> instead test encryptin and then decryption of Blocks
    // => decryption by block num
    // => decryption with wrong key
    // => encryptiong twice with same key and msg and check that 
    //    result is not the same
    
    #[test]
    fn par_enc_dec_bytes() {
        let msg = String::from("hello world, this is my string! it may contain אותיות בעברית").into_bytes();
        let key = String::from("super_secret123!@#").into_bytes();
        let blocks = counter_block::par_encrypt(msg, key.clone(), 15, 5).unwrap();
        let dec = counter_block::par_decrypt(blocks, key).unwrap();
        
        assert_eq!(String::from_utf8(dec).unwrap().trim_matches(char::from(0)), String::from("hello world, this is my string! it may contain אותיות בעברית"));
    }

    #[test]
    fn enc_block_num() {
        // TODO:  
    }

    #[test]
    fn dec_wrong_key() {
        let msg = String::from("hello world, this is my string! it may contain אותיות בעברית").into_bytes();
        let key = String::from("super_secret123!@#").into_bytes();
        let wrong_key = String::from("incorrect!").into_bytes();
        let blocks = counter_block::par_encrypt(msg, key.clone(), 15, 5).unwrap();
        let dec = counter_block::par_decrypt(blocks, wrong_key).unwrap();
        
        assert_ne!(dec, String::from("hello world, this is my string! it may contain אותיות בעברית").into_bytes());
    }

    #[test]
    fn enc_twice() {
        let msg = String::from("hello world, this is my string! it may contain אותיות בעברית").into_bytes();
        let key = String::from("super_secret123!@#").into_bytes();
        let blocks1 = counter_block::par_encrypt(msg.clone(), key.clone(), 15, 5).unwrap();
        let blocks2 = counter_block::par_encrypt(msg, key.clone(), 15, 5).unwrap();

        assert_ne!(blocks1.nonce, blocks2.nonce);
        assert_ne!(blocks1.blocks, blocks2.blocks);
    }
    // ---parse args--- 
    // => missing file
    // => missing password
    // => both -e and -d
    // => two of the same flag
    #[test]
    fn missing_f_name() {
        let args: Vec<String> = vec![
            String::from("-e"),
            String::from("-k"),
            String::from("suprsecret")
        ];
        let parsed = parse_args::parse_args(args);
        assert_eq!(parsed, Err(()));
    }
    #[test]
    fn empty_f_name() {
        let args: Vec<String> = vec![
            String::from("-e"),
            String::from("bla/bla"),
            String::from("-k"),
            String::from("suprsecret")
        ];
        let parsed = parse_args::parse_args(args);
        assert_eq!(parsed, Err(()));
    }

    #[test]
    fn both_e_d() {
        let args: Vec<String> = vec![
            String::from("-e"),
            String::from("bla/bla"),
            String::from("-d"),
            String::from("suprsecret")
        ];
        let parsed = parse_args::parse_args(args);
        assert_eq!(parsed, Err(()));
    }

    #[test]
    fn two_flags() {
        let args: Vec<String> = vec![
            String::from("-e"),
            String::from("bla/bla"),
            String::from("-e"),
            String::from("suprsecret")
        ];
        let parsed = parse_args::parse_args(args);
        assert_eq!(parsed, Err(()));
    }
    
    // file_mng
    // => invalid file name
    // => empty file
    
    #[test]
    fn non_existant_clear_file() {
        let path = String::from("d:/non/existant/file.txt");
        let f = file_mng::read_clear_file(&path);
        match f {
            Ok(_) => assert!(1==0),
            Err(e) => assert_eq!(format!("{}", e), "The system cannot find the path specified. (os error 3)")
        }   
    }
    //
    // integration
    // => encrypting and decrypting an image file and check original == new. 
}