use openmls::{credentials::test_utils::new_credential, prelude::*, test_utils::OpenMlsLibcrux};

#[test]
fn new_group_can_use_mlkem1024_sha384_mldsa87() {
    let ciphersuite = Ciphersuite::MLS_256_MLKEM1024_AES256GCM_SHA384_MLDSA87;
    let group_id = GroupId::from_slice(b"kchat-pq-mls-new-group");

    let alice_provider = &OpenMlsLibcrux::default();
    let bob_provider = &OpenMlsLibcrux::default();

    alice_provider.crypto().supports(ciphersuite).unwrap();
    bob_provider.crypto().supports(ciphersuite).unwrap();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());
    let (bob_credential, bob_signer) =
        new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());
    let capabilities = Capabilities::new(None, Some(&[ciphersuite]), None, None, None);

    let bob_key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .leaf_node_capabilities(capabilities.clone())
        .build(
            ciphersuite,
            bob_provider,
            &bob_signer,
            bob_credential.clone(),
        )
        .unwrap()
        .key_package()
        .to_owned();

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(capabilities)
        .use_ratchet_tree_extension(true)
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_signer,
        &mls_group_create_config,
        group_id,
        alice_credential.clone(),
    )
    .unwrap();

    let (_, welcome, _) = alice_group
        .add_members(alice_provider, &alice_signer, &[bob_key_package])
        .unwrap();
    alice_group.merge_pending_commit(alice_provider).unwrap();

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome.into_welcome().unwrap();
    let mut bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(bob_provider)
    .unwrap();

    assert_eq!(alice_group.ciphersuite(), ciphersuite);
    assert_eq!(bob_group.ciphersuite(), ciphersuite);
    assert_eq!(alice_group.members().count(), 2);
    assert_eq!(bob_group.members().count(), 2);

    let plaintext = b"kchat full post-quantum MLS new group";
    let queued_message = alice_group
        .create_message(alice_provider, &alice_signer, plaintext)
        .unwrap();
    let processed_message = bob_group
        .process_message(
            bob_provider,
            queued_message.into_protocol_message().unwrap(),
        )
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::ApplicationMessage(application_message) => {
            assert_eq!(application_message.into_bytes(), plaintext);
        }
        _ => unreachable!("expected application message"),
    }
}
