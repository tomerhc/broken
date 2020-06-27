#[warn(missing_debug_implementations, missing_docs)]
use common::*;
use std::env::args;
use std::process::exit;
mod parse_args;
use parse_args::Args;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parsed_args_res = parse_args::parse_args(args().collect());
    let parsed_args = match parsed_args_res {
        Ok(parsed_args) => parsed_args,
        Err(_) => exit(0),
    };

    let mut enc_dec: bool = true;
    let mut head_tail: Option<bool> = None;
    let mut path: String = String::new();
    let mut key: String = String::new();
    //TODO: deal with new Args type

    for arg in parsed_args.into_iter() {
        match arg {
            Args::Key(v) => key = v,
            Args::Encrypt(v) => {
                path = v;
                enc_dec = true;
            }
            Args::Decrypt(v) => {
                path = v;
                enc_dec = false;
            }
            Args::Head => head_tail = Some(true),
            Args::Tail => head_tail = Some(false),
        }
    }

    if enc_dec {
        let blocks = counter_block::Blocks::from_clear_file(&path, &key, 30, 5)?;
        path.push_str("_enc");
        blocks.to_enc_file(&path)?;
    } else {
        match head_tail {
            Some(h) => {
                if h {
                    let blocks = counter_block::Blocks::from_enc_head(&path, 100)?;
                    let new_path = path.replace("_enc", "");
                    blocks.to_clear_file(&key, &new_path)?;
                } else {
                    unimplemented!("tail feature is not implemented yet!");
                }
            }
            None => {
                let blocks = counter_block::Blocks::from_enc_file(&path)?;
                let new_path = path.replace("_enc", "");
                blocks.to_clear_file(&key, &new_path)?;
            }
        }
    }

    //   if enc_dec {
    //       let f = file_mng::read_clear_file(&path)?;
    //       let pass = key.into_bytes();
    //       let cypher = counter_block::par_encrypt(f, pass, 30, 5)?;
    //       path.push_str("_enc");
    //       file_mng::write_blocks(cypher, &path)?;
    //   } else {
    //       let f: counter_block::Blocks;
    //       match head_tail {
    //           Some(t) => {
    //               if t {
    //                   f = file_mng::read_first_n(&path, 30)?; // TODO: set number of blocks
    //               } else {
    //                   unimplemented!("tail feature is not implemented yet!");
    //               }
    //           }
    //           None => {
    //               f = file_mng::read_enc_file(&path)?;
    //           }
    //       }
    //       let pass = key.into_bytes();
    //       let dec = counter_block::par_decrypt(f, pass)?;
    //       let new_path = path.replace("_enc", "");
    //       file_mng::write_clear_file(&new_path, dec)?;
    //   }

    Ok(())
}
