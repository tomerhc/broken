mod hasher;
use hasher::hash_xor_key;

fn main() {
    let text = String::from("hello world! blablablabla  sdchbdcjshbdc  992chbcbcbcbcbbchhdh ");
    let mut bytes = text.into_bytes();
    let key:[u8;30] = [4;30];
    let mut key_vec = key.to_vec();
    let result = hash_xor_key(&mut bytes, &mut key_vec).unwrap();
    println!("{:?}", result);
    let res_str = String::from_utf8(result);
    println!("{:?}", res_str);
}