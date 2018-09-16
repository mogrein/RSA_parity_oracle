extern crate actix;
extern crate actix_web;
extern crate openssl;
#[macro_use] extern crate lazy_static;
#[macro_use] extern crate serde_derive;

mod crypto;

use actix_web::{server, App, Json, HttpRequest, http, Error};
use actix_web::error::{ ErrorBadRequest, ErrorInternalServerError};
use crypto::{CryptoService, RSACryptoService};
use openssl::bn::BigNum;
use std::env;

lazy_static! {
    static ref CRYPTO_SERVICE: RSACryptoService = RSACryptoService::new();
}

#[derive(Serialize)]
struct SecretMsg{
    secret: String,
}

#[derive(Deserialize)]
struct OracleReq {
    check: String,
}

#[derive(Serialize)]
struct OracleRsp {
    parity: bool,
}

fn secret(_req: &HttpRequest) -> Result<Json<SecretMsg>, Error> {
    let plaintext = env::var("SECRET").unwrap_or(String::from("SECRETSECRETSECRET"));
    let cryptotext: Vec<u8> = CRYPTO_SERVICE.encrypt(plaintext.as_bytes())
                                            .map_err(ErrorInternalServerError)?;
    let secret_num = BigNum::from_slice(cryptotext.as_slice())
                                            .map_err(ErrorInternalServerError)?;

    let secret = String::from(&**secret_num.to_dec_str().unwrap());
    Ok(Json(SecretMsg{secret: secret}))
}

fn oracle(req: Json<OracleReq>) -> Result<Json<OracleRsp>, Error> {
    let check = BigNum::from_dec_str(&req.check).map_err(ErrorBadRequest)?;

    let cryptotext = check.to_vec();
    let plaintext: Vec<u8> = CRYPTO_SERVICE.decrypt(cryptotext.as_slice())
                                           .map_err(ErrorInternalServerError)?;
    let dec_num = BigNum::from_slice(plaintext.as_slice()).unwrap();
    let parity = dec_num.mod_word(2).unwrap() == 0;
    return Ok(Json(OracleRsp { parity: parity }));
}

fn pubkey(_req: &HttpRequest) -> String {
    let pubkey = CRYPTO_SERVICE.pubkey_pem();
    pubkey
}

fn main() {
    let sys = actix::System::new("RSA padding oracle");

    server::new( || {
        vec![
            App::new()
                .resource("/pubkey", |r| r.f(pubkey))
                .resource("/secret", |r| r.f(secret))
                .resource("/oracle", |r| r.method(http::Method::POST).with(oracle)),
            //App::new().resource("/", |r| r.f(|_r| HttpResponse::Ok())),
        ]
    })
    .bind("127.0.0.1:8080")
    .expect("Can not bind to port 8080")
    .start();

    println!("Started http server: 127.0.0.1:8080");
    let _ = sys.run();
}
