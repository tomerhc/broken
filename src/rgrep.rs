use grep;
use grep::{matcher, printer, regex, searcher};
use printer::Standard;
use regex::RegexMatcher;
use searcher::Searcher;
use termcolor;
use termcolor::{ColorChoice, StandardStream};

pub fn regex_grep(bytes: &Vec<u8>, exp: &str) -> Result<(), Box<dyn std::error::Error>> {
    let wrt = StandardStream::stdout(ColorChoice::Always);
    let mut printer = Standard::new(wrt);
    let matcher = RegexMatcher::new(exp)?;
    Searcher::new().search_slice(&matcher, bytes, printer.sink(&matcher))?;
    Ok(())
}
