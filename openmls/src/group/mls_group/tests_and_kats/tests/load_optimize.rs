use crate::{
    credentials::test_utils::new_credential,
    framing::MessageDecryptionError,
    group::{
        LoadOptimizeError, OptimizeCurrentEpochPayload, OptimizePastEpochPayload,
        ProcessMessageError, ValidationError,
    },
    prelude::*,
    test_utils::OpenMlsRustCrypto,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::storage::StorageProvider as _;

fn try_load_group_optimize<Provider: crate::storage::OpenMlsProvider>(
    provider: &Provider,
    group_id: &GroupId,
    current_epoch_payload: OptimizeCurrentEpochPayload,
    past_epoch_payloads: Vec<OptimizePastEpochPayload>,
) -> Result<MlsGroup, LoadOptimizeError> {
    let storage = provider.storage();
    let public_group = PublicGroup::load(storage, group_id)
        .unwrap()
        .expect("group should exist in storage");
    let group_epoch_secrets = storage
        .group_epoch_secrets(group_id)
        .unwrap()
        .expect("group epoch secrets should exist in storage");
    let own_leaf_index = storage
        .own_leaf_index(group_id)
        .unwrap()
        .expect("own leaf index should exist in storage");
    let resumption_psk_store = storage
        .resumption_psk_store(group_id)
        .unwrap()
        .expect("resumption psk store should exist in storage");
    let mls_group_config = storage
        .mls_group_join_config(group_id)
        .unwrap()
        .expect("group config should exist in storage");
    let own_leaf_nodes = storage.own_leaf_nodes(group_id).unwrap();
    let group_state = storage
        .group_state(group_id)
        .unwrap()
        .expect("group state should exist in storage");

    #[cfg(feature = "extensions-draft-08")]
    let application_export_tree = storage.application_export_tree(group_id).unwrap();

    #[cfg(feature = "extensions-draft-08")]
    {
        MlsGroup::load_optimize(
            public_group,
            group_epoch_secrets,
            own_leaf_index,
            resumption_psk_store,
            mls_group_config,
            own_leaf_nodes,
            group_state,
            current_epoch_payload,
            past_epoch_payloads,
            application_export_tree,
        )
    }

    #[cfg(not(feature = "extensions-draft-08"))]
    {
        MlsGroup::load_optimize(
            public_group,
            group_epoch_secrets,
            own_leaf_index,
            resumption_psk_store,
            mls_group_config,
            own_leaf_nodes,
            group_state,
            current_epoch_payload,
            past_epoch_payloads,
        )
    }
}

fn extract_application_message(
    processed_message: ProcessedMessage,
) -> Vec<u8> {
    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(message) => message.into_bytes(),
        other => panic!("expected application message, got {other:?}"),
    }
}

fn setup_two_member_group(
    ciphersuite: Ciphersuite,
    max_past_epochs: usize,
) -> (
    OpenMlsRustCrypto,
    SignatureKeyPair,
    MlsGroup,
    OpenMlsRustCrypto,
    SignatureKeyPair,
    MlsGroup,
    GroupId,
) {
    let alice_provider = OpenMlsRustCrypto::default();
    let bob_provider = OpenMlsRustCrypto::default();
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
        bob_group,
        group_id,
    ) = setup_two_member_group(ciphersuite, 0);

    let current_epoch_payload = bob_group.export_current_epoch_payload().unwrap();
    let mut optimized_group =
        try_load_group_optimize(&bob_provider, &group_id, current_epoch_payload, Vec::new())
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

    let (charlie_credential, charlie_signer) =
        new_credential(&alice_provider, b"Charlie", ciphersuite.signature_algorithm());
    let charlie_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .build(ciphersuite, &alice_provider, &charlie_signer, charlie_credential)
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

    let current_epoch_payload = bob_group.export_current_epoch_payload().unwrap();
    let past_epoch_payload = bob_group
        .export_past_epoch_payload(old_epoch)
        .unwrap()
        .expect("past epoch payload should exist after commit");

    let mut optimized_group = try_load_group_optimize(
        &bob_provider,
        &group_id,
        current_epoch_payload,
        vec![past_epoch_payload.clone()],
    )
    .expect("load_optimize should succeed with selected past epoch payload");

    let processed = optimized_group
        .process_message(
            &bob_provider,
            old_ciphertext.clone().into_protocol_message().unwrap(),
        )
        .unwrap();
    assert_eq!(extract_application_message(processed), old_plaintext);

    let err = try_load_group_optimize(
        &bob_provider,
        &group_id,
        bob_group.export_current_epoch_payload().unwrap(),
        Vec::new(),
    )
    .unwrap()
    .process_message(
        &bob_provider,
        old_ciphertext.clone().into_protocol_message().unwrap(),
    )
    .expect_err("missing past payload should fail");
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
        bob_group.export_current_epoch_payload().unwrap(),
        vec![past_epoch_payload.clone(), past_epoch_payload.clone()],
    )
    .expect_err("duplicate past payloads must fail");
    assert_eq!(duplicate_err, LoadOptimizeError::DuplicatePastEpoch);

    let invalid_epoch_err = try_load_group_optimize(
        &bob_provider,
        &group_id,
        bob_group.export_current_epoch_payload().unwrap(),
        vec![OptimizePastEpochPayload {
            epoch: bob_group.epoch(),
            payload: past_epoch_payload.payload.clone(),
        }],
    )
    .expect_err("current epoch cannot be supplied as a past epoch payload");
    assert_eq!(invalid_epoch_err, LoadOptimizeError::PastEpochIsCurrentOrFuture);

    let invalid_current_err = try_load_group_optimize(
        &bob_provider,
        &group_id,
        OptimizeCurrentEpochPayload { payload: vec![0xff] },
        vec![past_epoch_payload.clone()],
    )
    .expect_err("corrupt current payload must fail");
    assert_eq!(invalid_current_err, LoadOptimizeError::InvalidCurrentPayload);

    let invalid_past_err = try_load_group_optimize(
        &bob_provider,
        &group_id,
        bob_group.export_current_epoch_payload().unwrap(),
        vec![OptimizePastEpochPayload {
            epoch: past_epoch_payload.epoch,
            payload: vec![0xff],
        }],
    )
    .expect_err("corrupt past payload must fail");
    assert_eq!(invalid_past_err, LoadOptimizeError::InvalidPastPayload);
}
