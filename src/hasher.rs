use crypto_hash::{Algorithm, hex_digest};

#[derive(Debug)]
pub enum EncryptErr{
    XorError,

}

pub fn hash_xor_key(msg: &mut Vec<u8>, key: &mut Vec<u8>) -> Result<Vec<u8>, EncryptErr> {
    assert!(msg.len() > 0, "msg vector is of length 0!");
    assert!(key.len() > 0, "key vector is of length 0!");
    while msg.len() > key.len(){
        let mut key_copy = key.clone();
        key.append(&mut key_copy);
    }
    if msg.len() < key.len() {
        pad(msg, key.len());
    }
    xor_key(msg, key)?;
    Ok(hex_digest(Algorithm::SHA256, msg).into_bytes())
}

pub fn pad(v: &mut Vec<u8>, l: usize) {
    for _ in 0..l-v.len() {
        v.push(b'\x00');
    }
}

pub fn pad_key(v: &mut Vec<u8>, l: usize) {
    while v.len() < l{
        v.append(&mut v.clone());
    }
    v.truncate(l)
}

fn xor_key(v: &mut Vec<u8>, k: &mut Vec<u8>) -> Result<(), EncryptErr> {
    if v.len() != k.len(){
        return Err(EncryptErr::XorError);
    }
    v.iter_mut().zip(k.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    Ok(())
}