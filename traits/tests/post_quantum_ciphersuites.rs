use openmls_traits::types::{
    AeadType, Ciphersuite, HashType, HpkeAeadType, HpkeKdfType, HpkeKemType, SignatureScheme,
};

#[test]
fn mldsa87_signature_scheme_uses_tls_codepoint() {
    assert_eq!(
        SignatureScheme::try_from(0x0906).unwrap(),
        SignatureScheme::MLDSA87
    );
    assert_eq!(SignatureScheme::MLDSA87 as u16, 0x0906);
}

#[test]
fn mlkem1024_sha384_mldsa87_ciphersuite_round_trips_local_private_use_codepoint() {
    let suite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;

    assert_eq!(suite as u16, 0xF001);
    assert_eq!(Ciphersuite::try_from(0xF001).unwrap(), suite);
}

#[test]
fn mlkem1024_sha384_mldsa87_maps_to_draft_primitives() {
    let suite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;

    assert_eq!(suite.signature_algorithm(), SignatureScheme::MLDSA87);
    assert_eq!(suite.hash_algorithm(), HashType::Sha2_384);
    assert_eq!(suite.aead_algorithm(), AeadType::Aes256Gcm);
    assert_eq!(suite.hpke_kem_algorithm(), HpkeKemType::MlKem1024);
    assert_eq!(suite.hpke_kdf_algorithm(), HpkeKdfType::Shake256);
    assert_eq!(suite.hpke_aead_algorithm(), HpkeAeadType::AesGcm256);
    assert_eq!(suite.hash_length(), 48);
}
