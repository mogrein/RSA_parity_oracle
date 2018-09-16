extern crate openssl;

use openssl::rsa::{Rsa, Padding};
use openssl::pkey::Private;
use std::io::{Error, ErrorKind};

pub trait CryptoService {
    fn pubkey_pem(&self) -> String;
//    fn privkey(&self) -> Vec<u8>;
    fn encrypt(&self, text: &[u8]) -> Result<Vec<u8>, Error>;
    fn decrypt(&self, text: &[u8]) -> Result<Vec<u8>, Error>;
}

pub struct RSACryptoService {
    rsa: Rsa<Private>,
    pad: Padding,
}

impl RSACryptoService {
    pub fn new() -> Self {
        let rsa = Rsa::generate(2048).unwrap();
        //let pkey = PKey::from_rsa(rsa).unwrap();
        RSACryptoService {rsa: rsa, pad: Padding::NONE}
    }
}

impl CryptoService for RSACryptoService {
    fn pubkey_pem(&self) -> String {
        let pub_key = self.rsa.public_key_to_pem().unwrap();
        String::from_utf8(pub_key).unwrap()
    }

    fn encrypt(&self, text_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if (self.rsa.size() as usize) < text_bytes.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "Text length to big :("));
        }
        let pad_size = self.rsa.size() as usize - text_bytes.len();
        let mut data: Vec<u8> = vec![0; pad_size];
        data.extend_from_slice(text_bytes);

        let mut result: Vec<u8> = vec![0; self.rsa.size() as usize];
        try!(self.rsa.public_encrypt(data.as_slice(), result.as_mut_slice(), self.pad));
        Ok(result)
    }

    fn decrypt(&self, text_bytes: &[u8]) -> Result<Vec<u8>, Error> {
        if (self.rsa.size() as usize) < text_bytes.len() {
            return Err(Error::new(ErrorKind::InvalidInput, "Text length to big :("));
        }
        let pad_size = self.rsa.size() as usize - text_bytes.len();
        let mut data: Vec<u8> = vec![0; pad_size];
        data.extend_from_slice(text_bytes);

        let mut result: Vec<u8> = vec![0; self.rsa.size() as usize];
        try!(self.rsa.private_decrypt(data.as_slice(), result.as_mut_slice(), self.pad));
        Ok(result)
    }
}
