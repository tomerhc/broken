mod hasher;
mod feistel;
use hasher::hash_xor_key;

fn main(){
    let text = String::from("hello world and bla bla bla ");
    let key = String::from("secret");
    let msg_bytes = text.into_bytes();
    let key_bytes = key.into_bytes();
    let cypher = feistel::encrypt(msg_bytes, key_bytes.clone(), 5).unwrap();
    println!("cypher text: {:?}\n\n", String::from_utf8(cypher.clone()).unwrap());

    let dec = feistel::decrypt(cypher, key_bytes, 5).unwrap();
    let dec_str = String::from_utf8(dec).unwrap();
    let dec_str = dec_str.trim_matches('\x00');
    println!("decrypted: {:?}", dec_str);

}

fn real_main() {
    let text = String::from("hello world! blablablabla  sdchbdcjshbdc  992chbcbcbcbcbbchhdh ");
    let mut bytes = text.into_bytes();
    let key:[u8;30] = [4;30];
    let mut key_vec = key.to_vec();
    let result = hash_xor_key(&mut bytes, &mut key_vec).unwrap();
    println!("{:?}", result);
    let res_str = String::from_utf8(result);
    println!("{:?}", res_str);
}