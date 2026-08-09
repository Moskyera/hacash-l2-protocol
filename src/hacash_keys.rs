//! Minimal Hacash L1-compatible keys (standalone — no monorepo `sys` crate).
//!
//! Same algorithms as fullnode wallets:
//! - address = version(0) || RIPEMD160(SHA2-256(compressed_pubkey))
//! - readable = base58check
//! - sign/verify = secp256k1 ECDSA over 32-byte message
//! - digests: SHA3-256 (payment/bill hashes), SHA2-256 (address)

use base58check::{FromBase58Check, ToBase58Check};
use libsecp256k1::{Message, PublicKey, SecretKey, Signature};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use zeroize::Zeroizing;

const ADDRESS_SIZE: usize = 21;
const PRIVATE_SIZE: usize = 32;
const PUBLIC_SIZE: usize = 33;

pub type Ret<T> = Result<T, String>;

/// SHA3-256 (used for L2 payment/bill message hashes).
pub fn sha3(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn sha2(data: impl AsRef<[u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

fn ripemd160(data: impl AsRef<[u8]>) -> [u8; 20] {
    use Digest as _;
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

#[derive(Clone)]
pub struct Account {
    secret_key: SecretKey,
    public_key: PublicKey,
    #[allow(dead_code)]
    address: [u8; ADDRESS_SIZE],
    address_readable: String,
}

impl Drop for Account {
    fn drop(&mut self) {
        self.secret_key.clear();
    }
}

impl Account {
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn readable(&self) -> &str {
        &self.address_readable
    }

    pub fn create_by_password(pass: &str) -> Ret<Account> {
        let dt = Zeroizing::new(sha2(pass.as_bytes()));
        Account::create_by_secret_key_value(*dt)
    }

    pub fn create_by_secret_key_value(key32: [u8; PRIVATE_SIZE]) -> Ret<Account> {
        let key32 = Zeroizing::new(key32);
        if key32[0] == 255 && key32[1] == 255 && key32[2] == 255 && key32[3] == 255 {
            return Err("secret_key not supported; try a different one".into());
        }
        match SecretKey::parse(&key32) {
            Err(e) => Err(e.to_string()),
            Ok(mut sk) => {
                let account = Account::create_by_secret_key(&sk);
                sk.clear();
                Ok(account)
            }
        }
    }

    fn create_by_secret_key(seckey: &SecretKey) -> Account {
        let pubkey = PublicKey::from_secret_key(seckey);
        let address = Account::get_address_by_public_key(pubkey.serialize_compressed());
        let addrshow = Account::to_readable(&address);
        Account {
            secret_key: *seckey,
            public_key: pubkey,
            address,
            address_readable: addrshow,
        }
    }

    pub fn get_address_by_public_key(pubkey: [u8; PUBLIC_SIZE]) -> [u8; ADDRESS_SIZE] {
        let dt = sha2(pubkey);
        let dt = ripemd160(dt);
        let version = 0u8;
        let mut addr = [version; ADDRESS_SIZE];
        addr[1..].copy_from_slice(&dt[..]);
        addr
    }

    pub fn to_readable(addr: &[u8; ADDRESS_SIZE]) -> String {
        let version = addr[0];
        addr[1..].to_base58check(version)
    }

    pub fn do_sign(&self, msg: &[u8; 32]) -> [u8; 64] {
        let msg = Message::parse(msg);
        let (s, _r) = libsecp256k1::sign(&msg, &self.secret_key);
        s.serialize()
    }

    pub fn verify_signature(msg: &[u8; 32], publickey: &[u8; 33], signature: &[u8; 64]) -> bool {
        if let (Ok(pubkey), Ok(sigobj)) = (
            PublicKey::parse_compressed(publickey),
            Signature::parse_standard(signature),
        ) {
            return libsecp256k1::verify(&Message::parse(msg), &sigobj, &pubkey);
        }
        false
    }
}

/// Optional: parse readable address (base58check) for future validation.
#[allow(dead_code)]
pub fn parse_readable_address(addr: &str) -> Ret<[u8; ADDRESS_SIZE]> {
    let (version, body) = addr
        .from_base58check()
        .map_err(|_| "base58check failed".to_string())?;
    if body.len() != ADDRESS_SIZE - 1 {
        return Err("address length invalid".into());
    }
    let mut data = [0u8; ADDRESS_SIZE];
    data[0] = version;
    data[1..].copy_from_slice(&body);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let acc = Account::create_by_password("standalone-l2-key").unwrap();
        let msg = sha3(b"hello");
        let sig = acc.do_sign(&msg);
        let pk = acc.public_key().serialize_compressed();
        assert!(Account::verify_signature(&msg, &pk, &sig));
        assert!(!acc.readable().is_empty());
    }
}
