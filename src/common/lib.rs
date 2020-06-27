pub mod counter_block;
pub mod error;
pub mod feistel;
pub mod file_mng;
pub mod hasher;

#[cfg(test)]
mod tests {
    use super::*;
    use glob::MatchOptions;
    #[test]
    fn glob() {
        let options = MatchOptions::new();
        let path = "/home/tomerh/Desktop/*";
        file_mng::list_glob(path, options);
    }
}
