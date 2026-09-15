use hpke_pq::{
    aead::AesGcm256, kdf::KdfShake256, kem::MlKem1024, Deserializable, HpkeError, Kem as HpkeKem,
    OpModeR, OpModeS, Serializable,
};
use openmls_traits::types::{
    CryptoError, ExporterSecret, HpkeAeadType, HpkeCiphertext, HpkeConfig, HpkeKdfType,
    HpkeKemType, HpkeKeyPair, KemOutput,
};

type Aead = AesGcm256;
type Kdf = KdfShake256;
type Kem = MlKem1024;

const HPKE_SHAKE_ONE_STAGE_KDF_INFO_OVERHEAD: usize = 5;

pub(crate) fn is_supported_config(config: &HpkeConfig) -> bool {
    config.0 == HpkeKemType::MlKem1024
        && config.1 == HpkeKdfType::Shake256
        && config.2 == HpkeAeadType::AesGcm256
}

fn map_error(error: HpkeError) -> CryptoError {
    match error {
        HpkeError::IncorrectInputLength(_, _) => CryptoError::InvalidLength,
        HpkeError::ValidationError => CryptoError::InvalidPublicKey,
        HpkeError::EncapError => CryptoError::SenderSetupError,
        HpkeError::DecapError => CryptoError::ReceiverSetupError,
        HpkeError::SealError => CryptoError::HpkeEncryptionError,
        HpkeError::OpenError => CryptoError::HpkeDecryptionError,
        HpkeError::KdfOutputTooLong => CryptoError::ExporterError,
        _ => CryptoError::CryptoLibraryError,
    }
}

fn validate_info_length(info: &[u8]) -> Result<(), CryptoError> {
    // hpke 0.14's SHAKE one-stage KDF builds a single context containing
    // mode || length-prefixed psk_id || length-prefixed info, then encodes that
    // full context length as u16. With base mode psk_id is empty, so `info`
    // must leave room for the 5 context overhead bytes.
    if info.len() > usize::from(u16::MAX) - HPKE_SHAKE_ONE_STAGE_KDF_INFO_OVERHEAD {
        return Err(CryptoError::InvalidLength);
    }

    Ok(())
}

pub(crate) fn seal(
    pk_r: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HpkeCiphertext, CryptoError> {
    validate_info_length(info)?;

    let pk_r = <Kem as HpkeKem>::PublicKey::from_bytes(pk_r).map_err(map_error)?;
    let (enc, ciphertext) =
        hpke_pq::single_shot_seal::<Aead, Kdf, Kem>(&OpModeS::Base, &pk_r, info, plaintext, aad)
            .map_err(map_error)?;

    Ok(HpkeCiphertext {
        kem_output: enc.to_bytes().to_vec().into(),
        ciphertext: ciphertext.into(),
    })
}

pub(crate) fn open(
    input: &HpkeCiphertext,
    sk_r: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    validate_info_length(info)?;

    let sk_r = <Kem as HpkeKem>::PrivateKey::from_bytes(sk_r).map_err(map_error)?;
    let enc =
        <Kem as HpkeKem>::EncappedKey::from_bytes(input.kem_output.as_ref()).map_err(map_error)?;

    hpke_pq::single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk_r,
        &enc,
        info,
        input.ciphertext.as_ref(),
        aad,
    )
    .map_err(map_error)
}

pub(crate) fn setup_sender_and_export(
    pk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
) -> Result<(KemOutput, ExporterSecret), CryptoError> {
    validate_info_length(info)?;

    let pk_r = <Kem as HpkeKem>::PublicKey::from_bytes(pk_r).map_err(map_error)?;
    let (enc, context) =
        hpke_pq::setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &pk_r, info).map_err(map_error)?;
    let mut exported = vec![0u8; exporter_length];
    context
        .export(exporter_context, &mut exported)
        .map_err(map_error)?;

    Ok((enc.to_bytes().to_vec(), exported.into()))
}

pub(crate) fn setup_receiver_and_export(
    enc: &[u8],
    sk_r: &[u8],
    info: &[u8],
    exporter_context: &[u8],
    exporter_length: usize,
) -> Result<ExporterSecret, CryptoError> {
    validate_info_length(info)?;

    let enc = <Kem as HpkeKem>::EncappedKey::from_bytes(enc).map_err(map_error)?;
    let sk_r = <Kem as HpkeKem>::PrivateKey::from_bytes(sk_r).map_err(map_error)?;
    let context = hpke_pq::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk_r, &enc, info)
        .map_err(map_error)?;

    let mut exported = vec![0u8; exporter_length];
    context
        .export(exporter_context, &mut exported)
        .map_err(map_error)?;

    Ok(exported.into())
}

pub(crate) fn derive_keypair(ikm: &[u8]) -> Result<HpkeKeyPair, CryptoError> {
    let (private, public) = Kem::derive_keypair(ikm);

    Ok(HpkeKeyPair {
        private: private.to_bytes().to_vec().into(),
        public: public.to_bytes().to_vec(),
    })
}
