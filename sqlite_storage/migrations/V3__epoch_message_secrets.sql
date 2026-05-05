CREATE TABLE IF NOT EXISTS openmls_group_epoch_message_secrets_metadata (
    provider_version INTEGER NOT NULL,
    group_id BLOB PRIMARY KEY,
    migrated INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS openmls_group_epoch_message_secrets (
    provider_version INTEGER NOT NULL,
    group_id BLOB NOT NULL,
    epoch INTEGER NOT NULL,
    message_secrets BLOB NOT NULL,
    PRIMARY KEY (group_id, epoch)
);
