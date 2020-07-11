#![warn(missing_debug_implementations, missing_docs)]
use common::*;
use grep::{printer, regex, searcher};
use printer::Standard;
use regex::RegexMatcher;
use searcher::Searcher;
use std::env::args;
use std::process::exit;
use termcolor::{ColorChoice, StandardStream};
mod parse_args;
use parse_args::Args;

//use glob::MatchOptions;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let parsed_args_res = parse_args::parse_args(args().collect());
    let parsed_args = match parsed_args_res {
        Ok(p) => p,
        Err(_) => exit(0),
    };

    let mut key = String::new();
    let mut file_path = String::new();
    let mut exp = String::new();
    let mut head: bool = false;
    let mut tail: bool = false;

    for arg in parsed_args.into_iter() {
        match arg {
            Args::Key(v) => key = v,
            Args::File(v) => file_path = v,
            Args::Exp(v) => exp = v,
            Args::Head => head = true,
            Args::Tail => tail = true,
        }
    }

    let f: counter_block::Blocks;
    let mut block_num: i64 = 0;
    if head {
        f = file_mng::read_first_n(&file_path, 30)?; //TODO: set number of bytes
    } else if tail {
        let res = file_mng::read_last_n(&file_path, 30)?; //TODO: set number of bytes
        f = res.0;
        block_num = res.1;
    } else {
        f = file_mng::read_enc_file(&file_path)?;
    }
    let pass = key.into_bytes();
    let dec_bytes = counter_block::par_decrypt(f, pass, block_num)?;
    regex_grep(&dec_bytes, &exp)?;
    Ok(())
}

/// Preform a regex grep over a byte array represanting a slice of clear text.  
pub fn regex_grep(bytes: &[u8], exp: &str) -> Result<(), Box<dyn std::error::Error>> {
    let wrt = StandardStream::stdout(ColorChoice::Always);
    let mut printer = Standard::new(wrt);
    let matcher = RegexMatcher::new(exp)?;
    Searcher::new().search_slice(&matcher, bytes, printer.sink(&matcher))?;
    Ok(())
}
