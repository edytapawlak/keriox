use crate::error::Error;
use ursa::{
    keys::{PrivateKey, PublicKey},
    signatures::{ed25519, SignatureScheme},
};

pub trait KeyManager {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error>;
    fn public_key(&self) -> PublicKey;
    fn next_pub_key(&self) -> PublicKey;
    fn rotate(&self) -> Result<Self, Error>
    where
        Self: Sized;
}

pub struct CryptoBox {
    signer: Signer,
    next_priv_key: PrivateKey,
    next_pub_key: PublicKey,
}

impl CryptoBox {
    pub fn new() -> Result<Self, Error> {
        let ed = ed25519::Ed25519Sha512::new();
        let signer = Signer::new()?;
        let (next_pub_key, next_priv_key) = ed.keypair(None).map_err(|e| Error::CryptoError(e))?;
        Ok(CryptoBox {
            signer,
            next_pub_key,
            next_priv_key,
        })
    }
}

impl KeyManager for CryptoBox {
    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        self.signer.sign(msg)
    }

    fn public_key(&self) -> PublicKey {
        self.signer.pub_key.clone()
    }

    fn rotate(&self) -> Result<Self, Error> {
        let ed = ed25519::Ed25519Sha512::new();
        let (next_pub_key, next_priv_key) = ed.keypair(None).map_err(|e| Error::CryptoError(e))?;
        let new_signer = Signer {
            priv_key: self.next_priv_key.clone(),
            pub_key: self.next_pub_key.clone(),
        };

        Ok(CryptoBox {
            signer: new_signer,
            next_priv_key,
            next_pub_key,
        })
    }

    fn next_pub_key(&self) -> PublicKey {
        self.next_pub_key.clone()
    }
}

struct Signer {
    priv_key: PrivateKey,
    pub pub_key: PublicKey,
}

impl Signer {
    pub fn new() -> Result<Self, Error> {
        let ed = ed25519::Ed25519Sha512::new();
        let (pub_key, priv_key) = ed.keypair(None).map_err(|e| Error::CryptoError(e))?;

        Ok(Signer { pub_key, priv_key })
    }

    fn sign(&self, msg: &Vec<u8>) -> Result<Vec<u8>, Error> {
        let signature = ed25519::Ed25519Sha512::new()
            .sign(&msg, &self.priv_key)
            .map_err(|e| Error::CryptoError(e))?;
        Ok(signature)
    }
}
