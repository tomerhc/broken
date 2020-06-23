#[derive(Debug)]
pub enum Args {
    Key(String),
    File(String),
    Exp(String),
    Head,
    Tail,
}

/// Paring the arguments for brgrep utility.
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
pub fn parse_args(mut argv: Vec<String>) -> Result<Vec<Args>, ()> {
    //TODO: deal with incorect number of arguments
    argv.remove(0);
    let mut final_args: Vec<Args> = Vec::new(); // take last argument as the expretion
    let mut flags: Vec<(usize, &str)> = Vec::new();
    for (index, arg) in argv.iter().enumerate() {
        if let Some('-') = arg.chars().next() {
            flags.push((index, arg))
        }
    }

    let mut used_flags: Vec<&str> = Vec::new();
    for (index, flag) in flags.into_iter() {
        if used_flags.iter().any(|a| a == &flag) {
            print_usege();
            return Err(());
        }

        match flag {
            "-k" => {
                let val = argv.get(index + 1).ok_or(())?;
                final_args.push(Args::Key(String::from(val)));
                used_flags.push(flag)
            }
            "-f" => {
                let val = argv.get(index + 1).ok_or(())?;
                final_args.push(Args::File(String::from(val)));
                used_flags.push(flag)
            }
            "-head" => {
                final_args.push(Args::Head);
                used_flags.push(flag)
            }
            "-tail" => {
                final_args.push(Args::Tail);
                used_flags.push(flag)
            }

            _ => {
                print_usege();
                return Err(());
            }
        }
    }
    let exp = argv.pop();
    match exp {
        Some(v) => final_args.push(Args::Exp(v)),
        None => {
            print_usege();
            return Err(());
        }
    }

    Ok(final_args)
}

fn print_usege() {
    println!(
        "usege: 
        brgrep -f <path/to/file/or/dir> -k <key> <expretion>"
    );
}
