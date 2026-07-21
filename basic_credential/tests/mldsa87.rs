use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, types::SignatureScheme};

#[test]
fn signature_key_pair_generates_and_signs_mldsa87() {
    let key_pair = SignatureKeyPair::new(SignatureScheme::MLDSA87).unwrap();

    assert_eq!(key_pair.signature_scheme(), SignatureScheme::MLDSA87);
    assert!(!key_pair.public().is_empty());

    let signature = key_pair.sign(b"kchat-pq-mls-basic-credential").unwrap();

    assert!(!signature.is_empty());
}
