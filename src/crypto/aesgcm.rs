use aes_gcm_siv::{
    aead::{Aead, generic_array::GenericArray, KeyInit, OsRng, Result},
    Aes256GcmSiv, Nonce,
};
use data_encoding::HEXLOWER;
use std::io::{Error, ErrorKind};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use crate::utils::random::random_string;

pub const AES_GCM_KEY_LENGTH: usize = 32;
pub const AES_GCM_NONCE_LENGTH: usize = 12;

pub struct EncMessage {
    pub ciphertext: String,
    pub nonce: String,
}

pub type MySecret = EphemeralSecret;

pub fn string_to_u8_32(text: String) -> core::result::Result<[u8; 32], Error> {
    if text.len() != 32 {
        return Err(Error::new(ErrorKind::InvalidInput, "Input string length is not 32."));
    }

    let mut bytearray: [u8; 32] = [0; 32];
    bytearray[..text.len()].copy_from_slice(&text.as_bytes()[..32]);

    Ok(bytearray)
}

pub fn string_to_u8_12(text: String) -> core::result::Result<[u8; 12], Error> {
    if text.len() != 12 {
        return Err(Error::new(ErrorKind::InvalidInput, "Input string length is not 12."));
    }

    let mut bytearray: [u8; 12] = [0; 12];
    bytearray[..text.len()].copy_from_slice(&text.as_bytes()[..12]);

    Ok(bytearray)
}

pub fn vec_u8_to_u8_12(v: Vec<u8>) -> core::result::Result<[u8; 12], Error> {
    let bytearray: [u8; 12] = match v.try_into() {
        Ok(b) => b,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other, format!("Error: {:?}", e)));
        }
    };
    Ok(bytearray)
}

pub fn vec_u8_to_u8_32(v: Vec<u8>) -> core::result::Result<[u8; 32], Error> {
    let bytearray: [u8; 32] = match v.try_into() {
        Ok(b) => b,
        Err(e) => {
            return Err(Error::new(
                ErrorKind::Other, format!("Error: {:?}", e)));
        }
    };
    Ok(bytearray)
}

pub fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret_key = StaticSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&secret_key);
    (secret_key, public_key)
}

pub fn derive_shared_secret(my_secret: StaticSecret, opp_public: PublicKey) -> SharedSecret {
    my_secret.diffie_hellman(&opp_public)
}

pub fn encrypt(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let nonce = Nonce::from_slice(nonce);

    let cipher = Aes256GcmSiv::new(key);
    cipher.encrypt(nonce, plaintext.as_ref())
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let key = GenericArray::from_slice(key);
    let nonce = Nonce::from_slice(nonce);

    let cipher = Aes256GcmSiv::new(key);
    cipher.decrypt(nonce, ciphertext.as_ref())
}

pub fn encode(input: &[u8]) -> String {
    HEXLOWER.encode(input)
}

pub fn decode(input: &[u8]) -> Vec<u8> {
    HEXLOWER.decode(input.as_ref()).unwrap()
}

pub fn cipher(plaintext: &[u8], my_secret: StaticSecret, opp_public: PublicKey) -> EncMessage {
    let shared_secret = derive_shared_secret(my_secret, opp_public).as_bytes().to_vec();

    let nonce_string = random_string(AES_GCM_NONCE_LENGTH);
    let nonce = string_to_u8_12(nonce_string.to_string()).unwrap();

    let encrypted = encrypt(plaintext, &shared_secret, &nonce).unwrap();

    EncMessage {
        ciphertext: encode(&encrypted),
        nonce: nonce_string,
    }
}

pub fn decipher(encrypted_message: EncMessage, my_secret: StaticSecret, opp_public: PublicKey) -> Vec<u8> {
    let shared_secret = derive_shared_secret(my_secret, opp_public).as_bytes().to_vec();

    let nonce = encrypted_message.nonce;

    let decoded_ciphertext = decode(encrypted_message.ciphertext.as_bytes());

    decrypt(&decoded_ciphertext, &shared_secret, nonce.as_bytes()).unwrap()
}