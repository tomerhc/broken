///parse the vector of arguments passed from main into a vector of tuples that look like:
/// (<type of argument>, <value>)
///
/// types are:
/// - "-e" for encryption
/// - "-d" for decryption
/// - "-k" for the key
///
/// # Errors
/// will print a usege message if:
/// - amount of arguments is wrong
/// - a double argument
/// - unrecognized argument
/// and then returns an Err(()), which will cause main to exit.
use common::error::ArgErr;

#[derive(Debug)]
pub enum Args {
    Key(String),
    Encrypt(String),
    Decrypt(String),
    Head,
    Tail,
}

pub fn parse_args(mut argv: Vec<String>) -> Result<Vec<Args>, ArgErr> {
    //TODO: implement Args enum, write exapmle code in doc and deal with incorect number of
    //arguments
    argv.remove(0);

    let mut flags: Vec<(usize, &str)> = Vec::new();
    for (index, arg) in argv.iter().enumerate() {
        if let Some('-') = arg.chars().next() {
            flags.push((index, arg))
        }
    }

    let mut final_args: Vec<Args> = Vec::new();
    //    let mut used_flags: Vec<&str> = Vec::new();
    for (index, flag) in flags.into_iter() {
        //       if used_flags.iter().any(|a| a == &flag) {
        //           print_usege();
        //           return Err(());
        //       }
        match flag {
            "-e" => {
                final_args.push(Args::Encrypt(String::from(&argv[index + 1])));
                //used_flags.push(flag)
            }
            "-d" => {
                final_args.push(Args::Decrypt(String::from(&argv[index + 1])));
                //used_flags.push(flag)
            }
            "-k" => {
                final_args.push(Args::Key(String::from(&argv[index + 1])));
                //used_flags.push(flag)
            }
            "-head" => {
                final_args.push(Args::Head);
                //used_flags.push(flag)
            }
            "-tail" => {
                final_args.push(Args::Tail);
                //used_flags.push(flag)
            }

            _ => {
                print_usege();
                return Err(ArgErr::UnknownArg);
            }
        }
    }

    validate_input(&final_args)?;
    Ok(final_args)

    //    if (!final_args.iter().any(|a| a(_) == Args::Key(_)))
    //        || (final_args.iter().any(|(a, _)| a == "encrypt")
    //            && final_args.iter().any(|(a, _)| a == "decrypt"))
    //    {
    //        print_usege();
    //        Err(())
    //    } else if final_args.iter().any(|(a, _)| a == "encrypt")
    //        || final_args.iter().any(|(a, _)| a == "decrypt")
    //    {
    //        Ok(final_args)
    //    } else {
    //        print_usege();
    //        Err(())
    //    }
}

fn validate_input(v: &Vec<Args>) -> Result<(), ArgErr> {
    let mut enc: u8 = 0;
    let mut dec: u8 = 0;
    let mut key: u8 = 0;
    let mut head: u8 = 0;
    let mut tail: u8 = 0;
    for arg in v.iter() {
        match arg {
            Args::Encrypt(_) => enc += 1,
            Args::Decrypt(_) => dec += 1,
            Args::Key(_) => key += 1,
            Args::Head => head += 1,
            Args::Tail => tail += 1,
        }
    }
    if (enc + dec) != 1 {
        print_usege();
        return Err(ArgErr::ArgMismatch);
    } else if key != 1 {
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
            broken <flag> <path> <-k> <key>
            flags:
            -e => encrypt
            -d => decrypt
            "
    );
}

#[cfg(test)]
mod tests {
    use crate::parse_args;
    use common::error::ArgErr;
    #[test]
    fn missing_f_name() -> Result<(), String> {
        let args: Vec<String> = vec![
            String::from("-e"),
            String::from("-k"),
            String::from("suprsecret"),
        ];
        let parsed = parse_args::parse_args(args);
        match parsed {
            Err(ArgErr::MissingArg) => Ok(()),
            _ => Err(format!(
                "should preduce ArgErr::MissingArg, but preduced {:?}",
                parsed
            )),
        }
    }
    #[test]
    fn empty_f_name() -> Result<(), String> {
        let args: Vec<String> = vec![
            String::from("-e"),
            String::from("bla/bla"),
            String::from("-k"),
            String::from("suprsecret"),
        ];
        let parsed = parse_args::parse_args(args);
        match parsed {
            Err(ArgErr::MissingArg) => Ok(()),
            _ => Err(format!(
                "should preduce ArgErr::MissingArg, but preduced {:?}",
                parsed
            )),
        }
    }

    #[test]
    fn both_e_d() -> Result<(), String> {
        let args: Vec<String> = vec![
            String::from("-e"),
            String::from("bla/bla"),
            String::from("-d"),
            String::from("suprsecret"),
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
            String::from("-e"),
            String::from("bla/bla"),
            String::from("-e"),
            String::from("suprsecret"),
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
}
