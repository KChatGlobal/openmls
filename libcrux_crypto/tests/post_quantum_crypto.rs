use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{
        Ciphersuite, CryptoError, HpkeAeadType, HpkeConfig, HpkeKdfType, HpkeKemType,
        SignatureScheme,
    },
};

#[test]
fn provider_generates_signs_and_verifies_mldsa87() {
    let provider = CryptoProvider::new().unwrap();
    let message = b"kchat-pq-mls-libcrux-provider";

    let (private, public) = provider
        .signature_key_gen(SignatureScheme::MLDSA87)
        .unwrap();
    let signature = provider
        .sign(SignatureScheme::MLDSA87, message, &private)
        .unwrap();

    provider
        .verify_signature(SignatureScheme::MLDSA87, message, &public, &signature)
        .unwrap();

    assert!(provider
        .verify_signature(SignatureScheme::MLDSA87, b"tampered", &public, &signature)
        .is_err());
}

#[test]
fn provider_hpke_round_trips_mlkem1024_shake256_aes256gcm() {
    let provider = CryptoProvider::new().unwrap();
    let config = || {
        HpkeConfig(
            HpkeKemType::MlKem1024,
            HpkeKdfType::Shake256,
            HpkeAeadType::AesGcm256,
        )
    };
    let aad = b"kchat-pq-mls-hpke-aad";
    let info = b"kchat-pq-mls-hpke-info";
    let plaintext = b"kchat-pq-mls-hpke-plaintext";

    let key_pair = provider
        .derive_hpke_keypair(config(), b"kchat-pq-mls-hpke-ikm-32-bytes")
        .unwrap();
    let ciphertext = provider
        .hpke_seal(config(), &key_pair.public, info, aad, plaintext)
        .unwrap();
    let opened = provider
        .hpke_open(config(), &ciphertext, key_pair.private.as_ref(), info, aad)
        .unwrap();

    assert_eq!(opened, plaintext);
}

#[test]
fn provider_hpke_rejects_oversized_info_for_mlkem1024_shake256_without_panicking() {
    let provider = CryptoProvider::new().unwrap();
    let config = || {
        HpkeConfig(
            HpkeKemType::MlKem1024,
            HpkeKdfType::Shake256,
            HpkeAeadType::AesGcm256,
        )
    };
    let key_pair = provider
        .derive_hpke_keypair(config(), b"kchat-pq-mls-hpke-ikm-32-bytes")
        .unwrap();
    let oversized_info = vec![0u8; u16::MAX as usize + 1];

    let result = std::panic::catch_unwind(|| {
        provider.hpke_seal(
            config(),
            &key_pair.public,
            &oversized_info,
            b"",
            b"plaintext",
        )
    });

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Err(CryptoError::InvalidLength));
}

#[test]
fn provider_supports_and_advertises_full_pq_ciphersuite() {
    let provider = CryptoProvider::new().unwrap();
    let ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;

    provider.supports(ciphersuite).unwrap();
    assert!(provider.supported_ciphersuites().contains(&ciphersuite));
}
