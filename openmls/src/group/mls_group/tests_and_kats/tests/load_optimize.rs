#![cfg(all(feature = "sqlite-provider", not(target_arch = "wasm32")))]

use crate::{
    credentials::test_utils::new_credential,
    framing::MessageDecryptionError,
    group::{LoadOptimizeError, MlsGroupLoadError, ProcessMessageError, ValidationError},
    prelude::*,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, Connection, SqliteStorageProvider};
use openmls_traits::storage::StorageProvider as _;
use serde::Serialize;

#[derive(Default)]
struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

struct SqliteTestProvider {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, Connection>,
}

impl Default for SqliteTestProvider {
    fn default() -> Self {
        let connection = Connection::open_in_memory().unwrap();
        let mut storage = SqliteStorageProvider::new(connection);
        storage.run_migrations().unwrap();
        Self {
            crypto: RustCrypto::default(),
            storage,
        }
    }
}

impl OpenMlsProvider for SqliteTestProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, Connection>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

fn try_load_group_optimize(
    provider: &SqliteTestProvider,
    group_id: &GroupId,
    past_epochs: impl IntoIterator<Item = GroupEpoch>,
) -> Result<MlsGroup, LoadOptimizeError> {
    let storage = provider.storage();
    MlsGroup::load_optimize(storage, group_id, past_epochs)
        .map(|group| group.expect("group should exist in storage"))
}

fn extract_application_message(processed_message: ProcessedMessage) -> Vec<u8> {
    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
        other => panic!("expected application message, got {other:?}"),
    }
}

fn setup_two_member_group(
    ciphersuite: Ciphersuite,
    max_past_epochs: usize,
) -> (
    SqliteTestProvider,
    SignatureKeyPair,
    MlsGroup,
    SqliteTestProvider,
    SignatureKeyPair,
    MlsGroup,
    GroupId,
) {
    let alice_provider = SqliteTestProvider::default();
    let bob_provider = SqliteTestProvider::default();
    let group_id = GroupId::from_slice(b"load_optimize_group");

    let (alice_credential, alice_signer) =
        new_credential(&alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(&bob_provider, b"Bob", ciphersuite.signature_algorithm());

    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, &bob_provider, &bob_signer, bob_credential)
        .unwrap()
        .key_package()
        .to_owned();

    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .max_past_epochs(max_past_epochs)
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        &alice_provider,
        &alice_signer,
        &config,
        group_id.clone(),
        alice_credential,
    )
    .unwrap();

    let (_, welcome, _) = alice_group
        .add_members(&alice_provider, &alice_signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().unwrap();
    let bob_group = StagedWelcome::new_from_welcome(
        &bob_provider,
        &MlsGroupJoinConfig::builder()
            .max_past_epochs(max_past_epochs)
            .build(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(&bob_provider)
    .unwrap();

    (
        alice_provider,
        alice_signer,
        alice_group,
        bob_provider,
        bob_signer,
        bob_group,
        group_id,
    )
}

#[test]
fn test_load_optimize_roundtrip_current_epoch() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let (
        alice_provider,
        alice_signer,
        mut alice_group,
        bob_provider,
        _bob_signer,
        _bob_group,
        group_id,
    ) = setup_two_member_group(ciphersuite, 0);

    let mut optimized_group = try_load_group_optimize(&bob_provider, &group_id, std::iter::empty())
        .expect("load_optimize should succeed for current epoch only");

    let plaintext = b"hello from current epoch";
    let ciphertext = alice_group
        .create_message(&alice_provider, &alice_signer, plaintext)
        .unwrap();
    let processed = optimized_group
        .process_message(
            &bob_provider,
            ciphertext.clone().into_protocol_message().unwrap(),
        )
        .unwrap();

    assert_eq!(extract_application_message(processed), plaintext);
}

#[test]
fn test_load_optimize_roundtrip_past_epoch() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let (
        alice_provider,
        alice_signer,
        mut alice_group,
        bob_provider,
        _bob_signer,
        mut bob_group,
        group_id,
    ) = setup_two_member_group(ciphersuite, 1);

    let old_plaintext = b"message from old epoch";
    let old_ciphertext = alice_group
        .create_message(&alice_provider, &alice_signer, old_plaintext)
        .unwrap();
    let old_epoch = bob_group.epoch();

    let (charlie_credential, charlie_signer) = new_credential(
        &alice_provider,
        b"Charlie",
        ciphersuite.signature_algorithm(),
    );
    let charlie_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(
            ciphersuite,
            &alice_provider,
            &charlie_signer,
            charlie_credential,
        )
        .unwrap()
        .key_package()
        .to_owned();

    let (commit, _, _) = alice_group
        .add_members(&alice_provider, &alice_signer, &[charlie_key_package])
        .unwrap();
    alice_group.merge_pending_commit(&alice_provider).unwrap();
    let processed_commit = bob_group
        .process_message(&bob_provider, commit.into_protocol_message().unwrap())
        .unwrap();
    let staged_commit = match processed_commit.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => *staged_commit,
        other => panic!("expected staged commit, got {other:?}"),
    };
    bob_group
        .merge_staged_commit(&bob_provider, staged_commit)
        .unwrap();

    let past_epoch_message_secrets = bob_group
        .export_past_epoch_message_secrets(old_epoch)
        .unwrap()
        .expect("past epoch message_secrets should exist after commit");

    let mut optimized_group = try_load_group_optimize(&bob_provider, &group_id, [old_epoch])
        .expect("load_optimize should succeed with selected past epoch message_secrets");

    let processed = optimized_group
        .process_message(
            &bob_provider,
            old_ciphertext.clone().into_protocol_message().unwrap(),
        )
        .unwrap();
    assert_eq!(extract_application_message(processed), old_plaintext);

    let err = try_load_group_optimize(&bob_provider, &group_id, std::iter::empty())
        .unwrap()
        .process_message(
            &bob_provider,
            old_ciphertext.clone().into_protocol_message().unwrap(),
        )
        .expect_err("missing past message_secrets should fail");
    assert!(matches!(
        err,
        ProcessMessageError::ValidationError(ValidationError::NoPastEpochData)
            | ProcessMessageError::ValidationError(ValidationError::UnableToDecrypt(
                MessageDecryptionError::SecretTreeError(SecretTreeError::TooDistantInThePast)
            ))
    ));

    let duplicate_err = try_load_group_optimize(
        &bob_provider,
        &group_id,
        [
            past_epoch_message_secrets.epoch,
            past_epoch_message_secrets.epoch,
        ],
    )
    .expect_err("duplicate past message secrets must fail");
    assert_eq!(
        duplicate_err,
        LoadOptimizeError::DuplicatePastEpochMessageSecrets
    );

    try_load_group_optimize(
        &bob_provider,
        &group_id,
        [(bob_group.epoch().as_u64() + 1).into()],
    )
    .expect("future epoch requests should be ignored at load time");

    bob_provider
        .storage()
        .write_group_epoch_message_secrets(&group_id, bob_group.epoch().as_u64(), &[0xff])
        .unwrap();
    let invalid_current_err = try_load_group_optimize(&bob_provider, &group_id, [old_epoch])
        .expect_err("corrupt current message_secrets must fail");
    assert_eq!(
        invalid_current_err,
        LoadOptimizeError::InvalidCurrentMessageSecrets
    );

    assert!(matches!(
        MlsGroup::load(bob_provider.storage(), &group_id),
        Err(MlsGroupLoadError::EpochMessageSecrets(
            LoadOptimizeError::InvalidCurrentMessageSecrets
        ))
    ));

    bob_provider
        .storage()
        .write_group_epoch_message_secrets(
            &group_id,
            bob_group.epoch().as_u64(),
            &bob_group
                .export_current_epoch_message_secrets()
                .unwrap()
                .message_secrets,
        )
        .unwrap();
    bob_provider
        .storage()
        .write_group_epoch_message_secrets(
            &group_id,
            past_epoch_message_secrets.epoch.as_u64(),
            &[0xff],
        )
        .unwrap();
    let invalid_past_err =
        try_load_group_optimize(&bob_provider, &group_id, [past_epoch_message_secrets.epoch])
            .expect_err("corrupt past message_secrets must fail");
    assert_eq!(
        invalid_past_err,
        LoadOptimizeError::InvalidPastMessageSecrets
    );
}
