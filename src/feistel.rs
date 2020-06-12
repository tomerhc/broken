use crate::hasher::{hash_xor_key, pad, pad_key};
use crate::error::*;

/// Encrypt a vector of bytes using a fistel network.
/// decryption is also implemented, althogh unnecessary due to the counter-block mode of operation.
///  # Parameters
/// - msg: the byte vector that you want to encrypt
/// - key: a byte vector. I use the user supplied password for the key.  
/// - rounds: i32, the number of fiestel rounds to preform. recomended above 3. 
pub fn encrypt(mut msg: Vec<u8>, mut key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, EncryptErr>{
    // TODO: assertions
    pad(&mut msg, 128);
    pad_key(&mut key, 64);
    for _ in 0..rounds {
        fiestel_round(&mut msg, &key)?;
        inc_key(&mut key);
    }
    Ok(msg)
}


// pub fn decrypt(mut msg: Vec<u8>,  mut key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, DecryptErr>{
//     // TODO: assertions
//     pad_key(&mut key, 64);
//     swap(&mut msg);
//     let mut final_key = calc_final_key(&key, rounds-1);
//     for _ in 0..rounds {
//         fiestel_round(&mut msg, &final_key)?;
//         dec_key(&mut final_key);
//     }
//     swap(&mut msg);
//     Ok(msg)
// }

/// preform a single fiestel round:
/// 
/// [------left------|------right------]
///         |                 |
///         |      (key_n)    | 
///       xor <----f(right)----
///         \                 /
///          ---   swap    ---
///                  |
/// [------right-----|--left ^ f(right)--]
///  
pub fn fiestel_round(msg: &mut Vec<u8>, k: &[u8]) -> Result<(), EncryptErr> {
    assert!(msg.len() == 128, "msg should be 2X256bits / 128 bytes");
    assert!(k.len() == 64, "key should be 256bits / 64 bytes");
    
    let mut right = msg.split_off(msg.len()/2);
    let f_of_right = f_func(&mut right.clone(), k)?;
    msg.iter_mut().zip(f_of_right.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    right.append(msg);
    *msg = right;
    Ok(())
}

fn f_func(v: &mut Vec<u8>, k: &[u8]) -> Result<Vec<u8>, EncryptErr>{
    hash_xor_key(v, &mut k.to_owned())
}

fn inc_key(k: &mut Vec<u8>){
    k.iter_mut().for_each(|x| *x += 1);
}

// fn dec_key(k: &mut Vec<u8>){
//     k.iter_mut().for_each(|x| *x -= 1);

// }


// fn calc_final_key(k: &[u8], rounds: i32) -> Vec<u8>{
//     let mut final_key = k.to_owned();
//     for _ in 0..rounds{
//         inc_key(&mut final_key)
//     }
//     final_key
// }


// pub fn swap(msg: &mut Vec<u8>){
//     let mut s = msg.split_off(msg.len()/2);
//     s.append(msg);
//     *msg = s;
//}

