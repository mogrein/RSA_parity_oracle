extern crate openssl;

use openssl::rsa::RSA;
use openssl::pkey::PKey;


pub trait CryptoService {
    fn pubkey_pem(&self) -> Vec<u8>;
    fn privkey(&self) -> Vec<u8>;
    fn encrypt(&self);
    fn decrypt(&self);
}

struct PKeyServiceImpl{
    pkey: PKey,
}

impl PKeyService {
    fn new() -> PKeyServiceImpl {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();
        PKeyServiceImpl{pkey: pkey}
    }
}

impl PKeyService for PKeyServiceImpl {
    fn pubkey_pem(&self) -> Vec<u8> {
        let pub_key = self.pkey.public_key_to_pem().unwrap();
        str::from_utf8(pub_key.as_slice()).unwrap()
    }
}

fn get_keys() {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    pkey
}