use openmls_traits::types::CryptoError;
use pqcrypto_mldsa::mldsa87;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

pub(crate) fn key_gen() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let (public_key, secret_key) = mldsa87::keypair();

    Ok((
        secret_key.as_bytes().to_vec(),
        public_key.as_bytes().to_vec(),
    ))
}

pub(crate) fn sign_detached(private: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let secret_key =
        mldsa87::SecretKey::from_bytes(private).map_err(|_| CryptoError::InvalidLength)?;
    let signature = mldsa87::detached_sign(message, &secret_key);

    Ok(signature.as_bytes().to_vec())
}

pub(crate) fn verify_detached(
    public: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let public_key =
        mldsa87::PublicKey::from_bytes(public).map_err(|_| CryptoError::InvalidLength)?;
    let signature = mldsa87::DetachedSignature::from_bytes(signature)
        .map_err(|_| CryptoError::InvalidLength)?;

    mldsa87::verify_detached_signature(&signature, message, &public_key)
        .map_err(|_| CryptoError::InvalidSignature)
}
