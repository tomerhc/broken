use crate::error::EncryptErr;
use crypto_hash::{hex_digest, Algorithm};

/// pads the key and msg to the same length, xors them and then preformes a SHA256 hash on the result.
/// # Examples
/// ```rust
/// let msg = String::from("hello world!").into_bytes();
/// let key = String::from("super_secret").into_bytes();
/// let res = hash_xor_key(&mut msg, &key).unwrap();

/// ```
pub fn hash_xor_key(msg: &mut Vec<u8>, key: &mut Vec<u8>) -> Result<Vec<u8>, EncryptErr> {
    assert!(!msg.is_empty(), "msg vector is of empty!");
    assert!(!key.is_empty(), "key vector is of empty!");
    while msg.len() > key.len() {
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
    for _ in 0..l - v.len() {
        v.push(b'\x00');
    }
}

///pads key by multiplying the bytes until longer then l, and then truncateing to size l
pub fn pad_key(v: &mut Vec<u8>, l: usize) {
    while v.len() < l {
        v.append(&mut v.clone());
    }
    v.truncate(l)
}

fn xor_key(v: &mut Vec<u8>, k: &mut Vec<u8>) -> Result<(), EncryptErr> {
    if v.len() != k.len() {
        return Err(EncryptErr::HashErr);
    }
    v.iter_mut().zip(k.iter()).for_each(|(x1, x2)| *x1 ^= *x2);
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::hasher;
    #[test]
    fn hash_diff_len() {
        let mut msg = String::from("hello world, this is a string").into_bytes();
        let mut key = String::from("short").into_bytes();
        assert_eq!(
            hasher::hash_xor_key(&mut msg, &mut key).unwrap(),
            String::from("2b273b58b5f5cb8c45b10c1e8d92262e0e49498d5baa339f737fb87b8efd2415")
                .into_bytes()
        );
    }
}
