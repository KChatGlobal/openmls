use openmls_traits::{signatures::SignerError, types::CryptoError};
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

pub(crate) fn key_gen() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (public_key, secret_key) = mldsa87::keypair();

    Ok((
        secret_key.as_bytes().to_vec(),
        public_key.as_bytes().to_vec(),
    ))
}

pub(crate) fn sign_detached(private: &[u8], message: &[u8]) -> Result<Vec<u8>, SignerError> {
    let secret_key =
        mldsa87::SecretKey::from_bytes(private).map_err(|_| SignerError::SigningError)?;
    let signature = mldsa87::detached_sign(message, &secret_key);

    Ok(signature.as_bytes().to_vec())
}
