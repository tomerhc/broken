use std::process::exit;

// TODO: remove -p
pub fn parse_args(mut argv: Vec<String>) -> Result<Vec<(String, String)>, ()>{
    argv.remove(0);
    if argv.is_empty() || argv.len() % 2 != 0 {
        print_usege();
    }

    let mut flags: Vec<(usize, &str)> = Vec::new();
    for (index, arg) in argv.iter().enumerate() {
        if let Some('-') = arg.chars().next() {
            flags.push((index, arg))
        }
    }

    let mut final_args: Vec<(String, String)> = Vec::new();
    let mut used_flags: Vec<&str> = Vec::new();
    for (index, flag) in flags.into_iter(){
        if used_flags.iter().any(|a| a == &flag){
            print_usege();
        }
        match flag {
            "-e" => {
                        final_args.push((String::from("encrypt"), String::from(&argv[index+1])));
                        used_flags.push(flag)
                    },
            "-d" => {
                        final_args.push((String::from("decrypt"),String::from(&argv[index+1])));
                        used_flags.push(flag)
                    },
            "-k" => {
                        final_args.push((String::from("key") ,String::from(&argv[index+1])));
                        used_flags.push(flag)
                    },
            "-p" => {
                        final_args.push((String::from("parallel") ,String::from(&argv[index+1])));
                        used_flags.push(flag)
                    },
            _ => print_usege(), 
        }
    }

    if (!final_args.iter().any(|(a, _)| a == "key")) || (final_args.iter().any(|(a, _)| a == "encrypt") && final_args.iter().any(|(a, _)| a == "decrypt")){
        print_usege();
        Err(())
    } else if final_args.iter().any(|(a, _)| a == "encrypt") || final_args.iter().any(|(a, _)| a == "decrypt"){
        Ok(final_args)
    } else {
        print_usege();
        Err(())
    }
}

fn print_usege(){
    println!("usege:
            broken <flag> <path> <-k> <key> [options]
            flags:
            -e => encrypt
            -d => decrypt\n
            options:
            -p [n cores] => parallel procesing on n cores");
    exit(0);
}