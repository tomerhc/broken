use crate::error::*;
use crate::hasher::{hash_xor_key, pad, pad_key};

/// Encrypt a vector of bytes using a fistel network.
/// decryption is also implemented, althogh unnecessary due to the counter-block mode of operation.
///  # Parameters
/// - msg: the byte vector that you want to encrypt
/// - key: a byte vector. I use the user supplied password for the key.  
/// - rounds: i32, the number of fiestel rounds to preform. recomended above 3.
pub fn encrypt(mut msg: Vec<u8>, mut key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, EncryptErr> {
    // TODO: assertions
    pad(&mut msg, 128);
    pad_key(&mut key, 64);
    for _ in 0..rounds {
        fiestel_round(&mut msg, &key)?;
        inc_key(&mut key);
    }
    Ok(msg)
}

/// Decrypt a vector of bytes using a fiestel network.
/// This function is not used by the crate, because of the counter block mode-of-operation.
pub fn decrypt(mut msg: Vec<u8>, mut key: Vec<u8>, rounds: i32) -> Result<Vec<u8>, DecryptErr> {
    // TODO: assertions
    pad_key(&mut key, 64);
    swap(&mut msg);
    let mut final_key = calc_final_key(&key, rounds - 1);
    for _ in 0..rounds {
        fiestel_round(&mut msg, &final_key)?;
        dec_key(&mut final_key);
    }
    swap(&mut msg);
    Ok(msg)
}

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

    let mut right = msg.split_off(msg.len() / 2);
    let f_of_right = f_func(&mut right.clone(), k)?;
    msg.iter_mut()
        .zip(f_of_right.iter())
        .for_each(|(x1, x2)| *x1 ^= *x2);
    right.append(msg);
    *msg = right;
    Ok(())
}

/// the irreversibel function used by the fiestel network. In this case I implemented a simple xor
/// with a key.
fn f_func(v: &mut Vec<u8>, k: &[u8]) -> Result<Vec<u8>, EncryptErr> {
    hash_xor_key(v, &mut k.to_owned())
}

fn inc_key(k: &mut Vec<u8>) {
    k.iter_mut().for_each(|x| *x += 1);
}

fn dec_key(k: &mut Vec<u8>) {
    k.iter_mut().for_each(|x| *x -= 1);
}

/// calculate the final key, to be used in decryption (where we start from the final key and
/// decrement it for each round)
fn calc_final_key(k: &[u8], rounds: i32) -> Vec<u8> {
    let mut final_key = k.to_owned();
    for _ in 0..rounds {
        inc_key(&mut final_key)
    }
    final_key
}

/// Swap the left and right parts of the msg.
pub fn swap(msg: &mut Vec<u8>) {
    let mut s = msg.split_off(msg.len() / 2);
    s.append(msg);
    *msg = s;
}

#[cfg(test)]
mod tests {
    use crate::feistel;

    // => encryption with pre-comuted values
    // => decryption with pre-comuted values
    // => encryption with short msg, long key
    #[test]
    fn enc_bytes() {
        let msg = String::from("hello world, this is my string! it may contain אותיות בעברית")
            .into_bytes();
        let key = String::from("super_secret123!@#").into_bytes();
        let res = feistel::encrypt(msg, key, 5).unwrap();

        assert_eq!(
            res,
            vec![
                212, 199, 130, 246, 134, 201, 139, 252, 82, 15, 80, 5, 87, 95, 0, 93, 3, 86, 81,
                83, 80, 3, 1, 6, 87, 84, 5, 80, 13, 4, 83, 0, 5, 95, 6, 92, 1, 80, 4, 83, 81, 2,
                81, 92, 9, 86, 1, 5, 82, 85, 0, 86, 0, 91, 2, 87, 0, 87, 7, 3, 83, 5, 6, 4, 95, 3,
                88, 81, 0, 64, 71, 10, 66, 13, 3, 70, 21, 21, 90, 8, 31, 70, 14, 26, 69, 14, 29,
                70, 67, 28, 71, 90, 5, 88, 66, 79, 89, 76, 77, 90, 87, 66, 65, 14, 13, 2, 16, 81,
                11, 91, 17, 187, 244, 224, 173, 183, 199, 224, 252, 187, 166, 232, 204, 71, 224,
                245, 229, 145
            ]
        );
    }

    #[test]
    fn dec_bytes() {
        let bytes = vec![
            212, 199, 130, 246, 134, 201, 139, 252, 82, 15, 80, 5, 87, 95, 0, 93, 3, 86, 81, 83,
            80, 3, 1, 6, 87, 84, 5, 80, 13, 4, 83, 0, 5, 95, 6, 92, 1, 80, 4, 83, 81, 2, 81, 92, 9,
            86, 1, 5, 82, 85, 0, 86, 0, 91, 2, 87, 0, 87, 7, 3, 83, 5, 6, 4, 95, 3, 88, 81, 0, 64,
            71, 10, 66, 13, 3, 70, 21, 21, 90, 8, 31, 70, 14, 26, 69, 14, 29, 70, 67, 28, 71, 90,
            5, 88, 66, 79, 89, 76, 77, 90, 87, 66, 65, 14, 13, 2, 16, 81, 11, 91, 17, 187, 244,
            224, 173, 183, 199, 224, 252, 187, 166, 232, 204, 71, 224, 245, 229, 145,
        ];
        let key = String::from("super_secret123!@#").into_bytes();
        let res = feistel::decrypt(bytes, key, 5).unwrap();
        assert_eq!(
            String::from_utf8(res).unwrap().replace("\u{0}", ""),
            String::from("hello world, this is my string! it may contain אותיות בעברית")
        );
    }

    #[test]
    fn enc_short_msg_long_key() {
        let msg = String::from("hey").into_bytes();
        let key = String::from("super_secret123!@#blabalbalbalbalablabal123123123").into_bytes();
        let res = feistel::encrypt(msg, key, 5).unwrap();
        assert_eq!(
            res,
            vec![
                82, 3, 83, 1, 87, 83, 92, 87, 86, 6, 15, 1, 82, 84, 15, 89, 6, 6, 2, 0, 83, 13, 80,
                13, 85, 87, 5, 1, 6, 3, 0, 10, 4, 1, 9, 12, 0, 84, 14, 81, 8, 81, 80, 80, 89, 6, 4,
                0, 86, 11, 5, 4, 2, 7, 82, 6, 0, 7, 3, 81, 86, 83, 93, 85, 13, 90, 28, 99, 105, 53,
                63, 49, 63, 49, 52, 54, 49, 48, 51, 50, 110, 99, 62, 102, 107, 101, 48, 55, 49, 53,
                51, 97, 109, 62, 59, 99, 105, 51, 99, 52, 109, 54, 106, 109, 54, 108, 50, 53, 49,
                52, 60, 55, 59, 61, 52, 62, 106, 54, 99, 110, 96, 48, 54, 108, 50, 101, 51, 102
            ]
        );
    }
}
