use common::error::ArgErr;

#[derive(Debug)]
pub enum Args {
    Key(String),
    File(String),
    Exp(String),
    Head,
    Tail,
}

/// Parsing the arguments for brgrep utility.
/// returns Vec<Args> of arguments to be handled by the main program
///
/// # Examples
/// ```rust
/// use grep::{parse_args, Args};
/// let args: Vec<String> = vec![String::from("-f"),
///                             String::from("/home/user/test.txt"),
///                             String::from("-k")
///                             String::from("secretkey")
///                             String::from("-head"),
///                             String::from("/w+ hello /d")];
/// let res = parse_args(args).unwrap();
/// assert_eq!(res, vec![Args::Key(String::from("secretkey")),
///                     Args::File(String::from("/home/user/test.txt")),
///                     Args::Head,
///                     Args::Exp(String::from("/w+ hello /d"))]);
/// ```
pub fn parse_args(mut argv: Vec<String>) -> Result<Vec<Args>, ArgErr> {
    //TODO: implement input validation from other parse_args

    argv.remove(0);
    let mut final_args: Vec<Args> = Vec::new();

    let exp = argv.pop();
    match exp {
        Some(v) => final_args.push(Args::Exp(v)),
        None => {
            print_usege();
            return Err(ArgErr::MissingArg);
        }
    }

    let argv_iter = argv.iter().enumerate();
    let mut is_param: bool = false;
    for (index, arg) in argv_iter {
        if is_param {
            is_param = false;
            continue;
        }
        match &arg[..] {
            "-k" => {
                final_args.push(Args::Key(String::from(&argv[index + 1])));
                is_param = true;
            }
            "-f" => {
                final_args.push(Args::File(String::from(&argv[index + 1])));
                is_param = true;
            }
            "-head" => {
                final_args.push(Args::Head);
            }
            "-tail" => {
                final_args.push(Args::Tail);
            }

            _ => {
                print_usege();
                return Err(ArgErr::UnknownArg(String::from(arg)));
            }
        }
    }

    //    let mut flags: Vec<(usize, &str)> = Vec::new();
    //    for (index, arg) in argv.iter().enumerate() {
    //        if let Some('-') = arg.chars().next() {
    //            flags.push((index, arg))
    //        }
    //    }
    //
    //    let mut used_flags: Vec<&str> = Vec::new();
    //    for (index, flag) in flags.into_iter() {
    //        if used_flags.iter().any(|a| a == &flag) {
    //            print_usege();
    //            return Err(());
    //        }
    //
    //        match flag {
    //            "-k" => {
    //                let val = argv.get(index + 1).ok_or(())?;
    //                final_args.push(Args::Key(String::from(val)));
    //                used_flags.push(flag)
    //            }
    //            "-f" => {
    //                let val = argv.get(index + 1).ok_or(())?;
    //                final_args.push(Args::File(String::from(val)));
    //                used_flags.push(flag)
    //            }
    //            "-head" => {
    //                final_args.push(Args::Head);
    //                used_flags.push(flag)
    //            }
    //            "-tail" => {
    //                final_args.push(Args::Tail);
    //                used_flags.push(flag)
    //            }
    //
    //            _ => {
    //                print_usege();
    //                return Err(());
    //            }
    //        }
    //    }
    //    let exp = argv.pop();
    //    match exp {
    //        Some(v) => final_args.push(Args::Exp(v)),
    //        None => {
    //            print_usege();
    //            return Err(());
    //        }
    //    }
    validate_input(&final_args)?;
    Ok(final_args)
}

fn validate_input(v: &[Args]) -> Result<(), ArgErr> {
    let mut file: u8 = 0;
    let mut exp: u8 = 0;
    let mut key: u8 = 0;
    let mut head: u8 = 0;
    let mut tail: u8 = 0;

    for arg in v.iter() {
        match arg {
            Args::Exp(_) => exp += 1,
            Args::File(_) => file += 1,
            Args::Key(_) => key += 1,
            Args::Head => head += 1,
            Args::Tail => tail += 1,
        }
    }
    if file != 1 {
        print_usege();
        return Err(ArgErr::MissingArg);
    } else if key != 1 {
        print_usege();
        return Err(ArgErr::MissingArg);
    } else if exp != 1 {
        print_usege();
        return Err(ArgErr::MissingArg);
    } else if (head + tail) > 1 {
        print_usege();
        return Err(ArgErr::ArgMismatch);
    }
    Ok(())
}

fn print_usege() {
    println!(
        "usege: 
        brgrep -f <path/to/file/or/dir> -k <key> [-head / -tail] <expretion>"
    );
}

#[cfg(test)]
mod tests {
    use crate::parse_args;
    use common::error::ArgErr;
    #[test]
    fn missing_f_name() -> Result<(), String> {
        let args: Vec<String> = vec![
            String::from("path/to/exctuable/"),
            String::from("-f"),
            String::from("-k"),
            String::from("suprsecret"),
            String::from(r"exp\w*"),
        ];
        let parsed = parse_args::parse_args(args);
        match parsed {
            Err(ArgErr::UnknownArg(_)) => Ok(()),
            _ => Err(format!(
                "should preduce ArgErr::UnknownArg, but preduced {:?}",
                parsed
            )),
        }
    }

    #[test]
    fn both_tail_and_head() -> Result<(), String> {
        let args: Vec<String> = vec![
            String::from("path/to/exctuable/"),
            String::from("-f"),
            String::from("bla/bla"),
            String::from("-k"),
            String::from("suprsecret"),
            String::from("-head"),
            String::from("-tail"),
            String::from(r"exp\w*"),
        ];
        let parsed = parse_args::parse_args(args);
        match parsed {
            Err(ArgErr::ArgMismatch) => Ok(()),
            _ => Err(format!(
                "should preduce ArgErr::ArgMismatch, but preduced {:?}",
                parsed
            )),
        }
    }

    #[test]
    fn two_flags() -> Result<(), String> {
        let args: Vec<String> = vec![
            String::from("path/to/exctuable/"),
            String::from("-f"),
            String::from("bla/bla"),
            String::from("-f"),
            String::from("bla/bla"),
            String::from("-k"),
            String::from("suprsecret"),
            String::from(r"exp\w*"),
        ];
        let parsed = parse_args::parse_args(args);
        match parsed {
            Err(ArgErr::MissingArg) => Ok(()),
            _ => Err(format!(
                "should preduce ArgErr::ArgMismatch, but preduced {:?}",
                parsed
            )),
        }
    }
}
