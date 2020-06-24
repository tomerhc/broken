use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum ArgErr {
    MissingArg,
    ArgMismatch,
    UnknownArg,
}

impl Error for ArgErr {}

impl fmt::Display for ArgErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "argument error: \n{}", self)
    }
}

#[derive(Debug)]
pub enum EncryptErr {
    HashErr,
    ioError(String),
}

impl Error for EncryptErr {}

impl fmt::Display for EncryptErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "encryption error: \n{}", self)
    }
}

impl From<std::io::Error> for EncryptErr {
    fn from(e: std::io::Error) -> EncryptErr {
        EncryptErr::ioError(format!("{}", e))
    }
}

#[derive(Debug)]
pub enum DecryptErr {
    HashErr,
    ioError(String),
}

impl Error for DecryptErr {}

impl fmt::Display for DecryptErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "decryption error: \n{}", self)
    }
}

impl From<EncryptErr> for DecryptErr {
    fn from(e: EncryptErr) -> DecryptErr {
        match e {
            EncryptErr::HashErr => DecryptErr::HashErr,
            EncryptErr::ioError(s) => DecryptErr::ioError(s),
        }
    }
}

impl From<std::io::Error> for DecryptErr {
    fn from(e: std::io::Error) -> DecryptErr {
        DecryptErr::ioError(format!("{}", e))
    }
}
