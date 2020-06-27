#[deny(missing_debug_implementations, missing_docs)]
use common::*;
use std::env::args;
use std::process::exit;
mod parse_args;
use glob::MatchOptions;
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
    let mut is_glob: bool = true;
    let mut options: MatchOptions = MatchOptions::new();

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
        if is_glob {
            encrypt_glob(&path, &key, options)?;
        } else {
            encrypt_single(&path, &key)?;
        }
    } else {
        if is_glob {
            match head_tail {
                Some(t) => {
                    if t {
                        decrypt_glob_head(&path, &key, options)?
                    } else {
                        unimplemented!("tail not implemented")
                    }
                }
                None => decrypt_glob(&path, &key, options)?,
            }
        } else {
            match head_tail {
                Some(t) => {
                    if t {
                        decrypt_single_head(&path, &key)?
                    } else {
                        unimplemented!("tail not implemented")
                    }
                }
                None => decrypt_single_head(&path, &key)?,
            }
        }
    }
    Ok(())
}

fn encrypt_single(path: &str, key: &str) -> Result<(), error::EncryptErr> {
    let blocks = counter_block::Blocks::from_clear_file(&path, &key, 30, 5)?;
    let new_path = format!("{}_enc", path);
    blocks.to_enc_file(&new_path)
}

fn encrypt_glob(path: &str, key: &str, options: MatchOptions) -> Result<(), error::EncryptErr> {
    let globs = counter_block::Blocks::from_clear_glob(path, key, 100, 5, options);
    for b in globs {
        match b {
            (p, Ok(blocks)) => {
                let new_path = format!("{}_enc", p);
                blocks.to_enc_file(&new_path)?;
            }
            (p, Err(e)) => {
                println!("Error in file: {}", p);
                return Err(e);
            }
        }
    }
    Ok(())
}

fn decrypt_single(path: &str, key: &str) -> Result<(), error::DecryptErr> {
    let blocks = counter_block::Blocks::from_enc_file(path)?;
    let new_path = path.replace("_enc", "");
    blocks.to_clear_file(&key, &new_path)?;
    Ok(())
}

fn decrypt_glob(path: &str, key: &str, options: MatchOptions) -> Result<(), error::DecryptErr> {
    let globs = counter_block::Blocks::from_enc_glob(path, options);
    for b in globs {
        match b {
            (p, Ok(blocks)) => {
                let new_path = p.replace("_enc", "");
                blocks.to_clear_file(&key, &new_path)?;
            }
            (p, Err(e)) => {
                println!("Error in file: {}", p);
                return Err(e);
            }
        }
    }
    Ok(())
}

fn decrypt_single_head(path: &str, key: &str) -> Result<(), error::DecryptErr> {
    let blocks = counter_block::Blocks::from_enc_head(path, 100)?;
    let new_path = path.replace("_enc", "");
    blocks.to_clear_file(&key, &new_path)?;
    Ok(())
}

fn decrypt_glob_head(
    path: &str,
    key: &str,
    options: MatchOptions,
) -> Result<(), error::DecryptErr> {
    let globs = counter_block::Blocks::from_enc_glob_head(path, options, 100);
    for b in globs {
        match b {
            (p, Ok(blocks)) => {
                let new_path = p.replace("_enc", "");
                blocks.to_clear_file(&key, &new_path)?;
            }
            (p, Err(e)) => {
                println!("Error in file: {}", p);
                return Err(e);
            }
        }
    }
    Ok(())
}
