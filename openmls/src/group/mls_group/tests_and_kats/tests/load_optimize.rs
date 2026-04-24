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

fn try_load_group_optimize(
    provider: &OpenMlsRustCrypto,
    group_id: &GroupId,
    current_epoch_payload: OptimizeCurrentEpochPayload,
    past_epoch_payloads: Vec<OptimizePastEpochPayload>,
) -> Result<MlsGroup, LoadOptimizeError> {
    let storage = provider.storage();
    let current_epoch = MlsGroup::load(storage, group_id)
        .unwrap()
        .expect("group should exist in storage")
        .epoch()
        .as_u64();
    storage
        .write_group_current_epoch(group_id, current_epoch)
        .unwrap();
    storage
        .write_group_epoch_payload(group_id, current_epoch, &current_epoch_payload.payload)
        .unwrap();
    for past_epoch_payload in &past_epoch_payloads {
        storage
            .write_group_epoch_payload(
                group_id,
                past_epoch_payload.epoch.as_u64(),
                &past_epoch_payload.payload,
            )
            .unwrap();
    }

    MlsGroup::load_optimize(
        storage,
        group_id,
        past_epoch_payloads
            .iter()
            .map(|past_epoch_payload| past_epoch_payload.epoch),
    )
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

    try_load_group_optimize(
        &bob_provider,
        &group_id,
        bob_group.export_current_epoch_payload().unwrap(),
        vec![OptimizePastEpochPayload {
            epoch: (bob_group.epoch().as_u64() + 1).into(),
            payload: past_epoch_payload.payload.clone(),
        }],
    )
    .expect("future epoch requests should be ignored at load time");

    let invalid_current_err = try_load_group_optimize(
        &bob_provider,
        &group_id,
        OptimizeCurrentEpochPayload {
            payload: vec![0xff],
        },
        vec![past_epoch_payload.clone()],
    )
    .expect_err("corrupt current payload must fail");
    assert_eq!(
        invalid_current_err,
        LoadOptimizeError::InvalidCurrentPayload
    );

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
