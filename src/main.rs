#[warn(missing_debug_implementations, missing_docs)]
use std::env::args;
use std::process::exit;
mod counter_block;
mod error;
mod feistel;
mod file_mng;
mod hasher;
mod parse_args;
mod rgrep;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let f = file_mng::read_clear_file("/home/tomerh/Desktop/test.txt")?;
    rgrep::regex_grep(&f, r"Lorem")?;
    Ok(())
}

fn _main() -> Result<(), Box<dyn std::error::Error>> {
    let parsed_args_res = parse_args::parse_args(args().collect());
    let parsed_args = match parsed_args_res {
        Ok(parsed_args) => parsed_args,
        Err(_) => exit(0),
    };

    let mut enc_dec: bool = true;
    let mut head_tail: Option<bool> = None;
    let mut path: String = String::new();
    let mut key: String = String::new();
    for (t, v) in parsed_args.into_iter() {
        match &t[..] {
            "encrypt" => {
                enc_dec = true;
                path = v
            }
            "decrypt" => {
                enc_dec = false;
                path = v
            }
            "key" => key = v,
            "head" => head_tail = Some(true),
            "tail" => head_tail = Some(false),
            _ => (),
        }
    }

    if enc_dec {
        let f = file_mng::read_clear_file(&path)?;
        let pass = key.into_bytes();
        let cypher = counter_block::par_encrypt(f, pass, 30, 5)?;
        path.push_str("_enc");
        file_mng::write_blocks(cypher, &path)?;
    } else {
        let f: counter_block::Blocks;
        match head_tail {
            Some(t) => {
                if t {
                    f = file_mng::read_first_n(&path, 30)?; // TODO: set number of blocks
                } else {
                    unimplemented!("tail feature is not implemented yet!");
                }
            }
            None => {
                f = file_mng::read_enc_file(&path)?;
            }
        }
        let pass = key.into_bytes();
        let dec = counter_block::par_decrypt(f, pass)?;
        let new_path = path.replace("_enc", "");
        file_mng::write_clear_file(&new_path, dec)?;
    }

    Ok(())
}
