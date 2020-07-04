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
    let argv_iter = argv.iter().enumerate();
    let mut final_args: Vec<Args> = Vec::new();
    let mut is_param: bool = false;
    for (index, arg) in argv_iter {
        if is_param {
            is_param = false;
            continue;
        }
        match &arg[..] {
            "-e" => {
                final_args.push(Args::Encrypt(String::from(&argv[index + 1])));
                is_param = true;
            }
            "-d" => {
                final_args.push(Args::Decrypt(String::from(&argv[index + 1])));
                is_param = true;
            }
            "-k" => {
                final_args.push(Args::Key(String::from(&argv[index + 1])));
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

    validate_input(&final_args)?;
    Ok(final_args)
}

fn validate_input(v: &[Args]) -> Result<(), ArgErr> {
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
    println!("{:?}", v);
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
            String::from("path/to/exctuable/"),
            String::from("-e"),
            String::from("-k"),
            String::from("suprsecret"),
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
    fn both_e_d() -> Result<(), String> {
        let args: Vec<String> = vec![
            String::from("path/to/exctuable/"),
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
            String::from("path/to/exctuable/"),
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
