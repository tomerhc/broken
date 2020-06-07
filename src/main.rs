use std::env::args;
use std::time::Instant;
mod hasher;
mod feistel;
mod counter_block;
mod file_mng;
mod parse_args;

fn main(){
    let path = String::from(r"C:\Users\hacoh\Pictures\wallpaper.png");
    let key = String::from("blabla");
    let f = file_mng::read_clear_file(&path).unwrap();
    let f2 = f.clone();
    let pass = key.into_bytes();
    let pass2 = pass.clone();
    let now = Instant::now();
    let reg_res = counter_block::encrypt(f, pass, 1024, 15).unwrap();
    println!("regular time took => {:?}", now.elapsed().as_millis());
    let now = Instant::now();
    let par_res = counter_block::par_encrypt(f2, pass2, 1024, 15).unwrap();
    println!("parallel time took => {:?}", now.elapsed().as_millis());
}


fn real_main() -> std::io::Result<()> {
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
        let cypher = counter_block::encrypt(f, pass, 30, 5).unwrap();
        path.push_str("_enc");
        file_mng::write_blocks(cypher, &path)?;
    }else{
        let f = file_mng::read_enc_file(&path)?;
        let pass = key.into_bytes();
        let dec = counter_block::decrypt(f, pass).unwrap();
        let new_path = path.replace("_enc", "");
        file_mng::write_clear_file(&new_path, dec)?;
    }

    Ok(())
}
 