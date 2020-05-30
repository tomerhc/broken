mod hasher;
mod feistel;
mod counter_block;


fn main(){
    let text = String::from("hello wolrd, ny name is tomer and i am here to write an encryption softwere and save the world from slow enryption.");
    let  bytes = text.into_bytes();
    let key = String::from("Barvaz1");
    let key_bytes = key.into_bytes();
    
    let cypher = counter_block::encrypt(bytes, key_bytes.clone(), 15, 3).unwrap();
    println!("nonce => {:?}\n", cypher.nonce);
    for b in cypher.blocks.iter(){
        println!("{:?}", String::from_utf8(b.to_vec()))
    }
    let dec = counter_block::decrypt(cypher, key_bytes).unwrap();
    let dec_str = String::from_utf8(dec).unwrap();
    let dec_str = dec_str.trim_matches('\x00');
    println!("decrypted => {:?}", dec_str)

}