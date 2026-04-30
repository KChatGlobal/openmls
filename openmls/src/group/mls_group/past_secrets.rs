use std::collections::{BTreeSet, HashMap, VecDeque};

#[cfg(not(target_arch = "wasm32"))]
use std::time::SystemTime;
#[cfg(target_arch = "wasm32")]
use web_time::SystemTime;

use crate::schedule::message_secrets::MessageSecrets;

use super::*;
use serde::de::DeserializeOwned;

impl EpochTree {
    #[cfg(all(test, feature = "sqlite-provider", feature = "libcrux-provider"))]
    pub(crate) fn timestamp(&self) -> Option<SystemTime> {
        self.message_secrets.timestamp()
    }
}

// Internal helper struct
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct EpochTree {
    epoch: u64,
    message_secrets: MessageSecrets,
    leaves: Vec<Member>,
}

/// Can store message secrets for up to `max_epochs`. The trees are added with [`self::add()`] and can be queried
/// with [`Self::get_epoch()`].
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
#[cfg_attr(feature = "crypto-debug", derive(Debug))]
pub(crate) struct MessageSecretsStore {
    // Maximum size of the `past_epoch_trees` list.
    pub(crate) max_epochs: usize,
    // Past message secrets.
    // NOTE: these are in order of addition (latest at end).
    past_epoch_trees: VecDeque<EpochTree>,
    // The message secrets of the current epoch.
    message_secrets: MessageSecrets,
}

#[cfg(not(feature = "crypto-debug"))]
impl core::fmt::Debug for MessageSecretsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MessageSecretsStore")
            .field("max_epochs", &"***")
            .field("past_epoch_trees", &"***")
            .field("message_secrets", &"***")
            .finish()
    }
}

const VECDEQUE_MAX_CAPACITY: usize = isize::MAX as usize;

// XXX: the VecDeque capacity is not checked elsewhere in this module.
/// Helper function to map a policy to a maximum number of past epochs
fn max_epochs(policy: &PastEpochDeletionPolicy) -> usize {
    // get the `max_epochs`, or the maximum capacity of a `VecDeque`
    let max_epochs = policy.max_epochs().unwrap_or(VECDEQUE_MAX_CAPACITY);

    // cap at max capacity
    max_epochs.min(VECDEQUE_MAX_CAPACITY)
}

impl MessageSecretsStore {
    /// Create a new store that can hold up to `max_past_epochs` message secrets.
    /// If `max_past_epochs` is 0, only the current epoch is being stored.
    pub(crate) fn new_with_secret(
        policy: &PastEpochDeletionPolicy,
        message_secrets: MessageSecrets,
    ) -> Self {
        // max or the limit of the storage size
        let max_epochs = max_epochs(policy);

        Self {
            max_epochs,
            past_epoch_trees: VecDeque::new(),
            message_secrets: message_secrets.with_timestamp(SystemTime::now()),
        }
    }

    /// Resize the store.
    pub(crate) fn resize(&mut self, policy: &PastEpochDeletionPolicy) {
        // max or the limit of the storage size
        let max_past_epochs = max_epochs(policy);

        let old_size = self.max_epochs;
        self.max_epochs = max_past_epochs;
        if old_size > max_past_epochs {
            let num_epochs_out = old_size - max_past_epochs;
            self.past_epoch_trees
                .rotate_left(num_epochs_out.min(self.past_epoch_trees.len()));
            self.past_epoch_trees.truncate(max_past_epochs);
        }
    }

    /// Set the `message_secrets` to a provided `MessageSecrets`, and return
    /// the previous one.
    pub(crate) fn replace_current_message_secrets(
        &mut self,
        message_secrets: MessageSecrets,
    ) -> MessageSecrets {
        let mut message_secrets = message_secrets.with_timestamp(SystemTime::now());
        std::mem::swap(&mut self.message_secrets, &mut message_secrets);

        message_secrets
    }

    /// Add a secret tree for a given epoch `group_epoch`.
    /// Note that this does not take the epoch into account and pops out the
    /// oldest element.
    pub(crate) fn add_past_epoch_tree(
        &mut self,
        group_epoch: impl Into<GroupEpoch>,
        message_secrets: MessageSecrets,
        leaves: Vec<Member>,
    ) {
        // Don't store the tree if it's not intended
        if self.max_epochs == 0 {
            return;
        }
        if self.past_epoch_trees.len() >= self.max_epochs {
            self.past_epoch_trees.rotate_left(1);
            self.past_epoch_trees.truncate(self.max_epochs - 1);
        }

        self.past_epoch_trees.push_back(EpochTree {
            epoch: group_epoch.into().as_u64(),
            message_secrets,
            leaves,
        });
        debug_assert!(
            self.max_epochs >= self.past_epoch_trees.len(),
            "Only {} past secrets must be stored but we found {}",
            self.max_epochs,
            self.past_epoch_trees.len()
        );
    }

    /// Get a mutable reference to a secret tree for a given epoch `group_epoch`.
    /// If no message secrets are found for that epoch, `None` is returned.
    pub(crate) fn secrets_for_epoch_mut(
        &mut self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<&mut MessageSecrets> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter_mut() {
            if epoch_tree.epoch == epoch {
                return Some(&mut epoch_tree.message_secrets);
            }
        }
        None
    }

    /// Get a reference to a secret tree for a given epoch `group_epoch`.
    /// If no message secrets are found for that epoch, `None` is returned.
    pub(crate) fn secrets_for_epoch(
        &self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<&MessageSecrets> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return Some(&epoch_tree.message_secrets);
            }
        }
        None
    }

    /// Get a mutable reference to a secret tree for a given epoch `group_epoch`.
    /// Return a mutable reference to the [`MessageSecrets`] and a slice to the
    /// [`Member`]s of the epoch.
    pub(crate) fn secrets_and_leaves_for_epoch(
        &self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> Option<(&MessageSecrets, &[Member])> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return Some((&epoch_tree.message_secrets, &epoch_tree.leaves));
            }
        }
        None
    }

    /// Returns a `HashMap` that maps a `LeafNodeIndex` to the correct
    /// [`Member`] in the given `group_epoch`.
    pub(crate) fn leaves_for_epoch(
        &self,
        group_epoch: impl Into<GroupEpoch>,
    ) -> HashMap<LeafNodeIndex, &Member> {
        let epoch = group_epoch.into().as_u64();
        for epoch_tree in self.past_epoch_trees.iter() {
            if epoch_tree.epoch == epoch {
                return epoch_tree
                    .leaves
                    .iter()
                    .map(|m| (m.index, m))
                    .collect::<HashMap<LeafNodeIndex, &Member>>();
            }
        }
        HashMap::new()
    }

    /// Check if the provided epoch contains a leaf index.
    pub(crate) fn epoch_has_leaf(
        &self,
        group_epoch: GroupEpoch,
        leaf_index: LeafNodeIndex,
    ) -> bool {
        self.past_epoch_trees.iter().any(|t| {
            t.epoch == group_epoch.0
                && t.leaves
                    .iter()
                    .any(|Member { index, .. }| *index == leaf_index)
        })
    }

    /// Get a mutable reference to the message secrets of the current epoch.
    pub(crate) fn message_secrets_mut(&mut self) -> &mut MessageSecrets {
        &mut self.message_secrets
    }

    /// Get a reference to the message secrets of the current epoch.
    pub(crate) fn message_secrets(&self) -> &MessageSecrets {
        &self.message_secrets
    }

    fn delete_past_epoch_secrets_older_than_duration(&mut self, duration: std::time::Duration) {
        // first, compare to the timestamp of the current message secrets
        if let Some(added_at) = self.message_secrets.timestamp() {
            if let Ok(elapsed) = SystemTime::now().duration_since(added_at) {
                if elapsed > duration {
                    // delete all
                    self.past_epoch_trees.clear();
                    return;
                }
            }
        }

        // find the first past epoch tree with a timestamp past the duration
        let found = self
            .past_epoch_trees
            .iter()
            .enumerate()
            .rev()
            .find(|(_idx, tree)| {
                let Some(added_at) = tree.message_secrets.timestamp() else {
                    return false;
                };

                let Ok(elapsed) = SystemTime::now().duration_since(added_at) else {
                    return false;
                };

                elapsed > duration
            })
            .map(|(idx, _tree)| idx);

        if let Some(found_idx) = found {
            // delete all before and including the index
            self.past_epoch_trees.drain(0..found_idx + 1);
        } else {

            // keep all
        }
    }

    fn delete_past_epoch_secrets_before_timestamp(&mut self, cutoff: SystemTime) {
        // first, compare to timestamp of the current message secrets
        if let Some(added_at) = self.message_secrets.timestamp() {
            if added_at < cutoff {
                // delete all
                self.past_epoch_trees.clear();
                return;
            }
        }

        // find the first past epoch tree with an earlier non-None timestamp
        let found = self
            .past_epoch_trees
            .iter()
            .enumerate()
            .rev()
            .find(|(_idx, tree)| {
                let Some(added_at) = tree.message_secrets.timestamp() else {
                    return false;
                };

                added_at < cutoff
            })
            .map(|(idx, _tree)| idx);

        if let Some(found_idx) = found {
            // delete all before and including the index
            self.past_epoch_trees.drain(0..found_idx + 1);
        } else {
            // keep all
        }
    }

    pub(crate) fn delete_past_epoch_secrets(&mut self, policy: PastEpochDeletion) {
        // handle different types of past epoch deletion
        if let Some(config) = policy.config {
            match config {
                PastEpochDeletionTimeConfig::DeleteAllWithoutTimestamp => {
                    self.past_epoch_trees
                        .retain(|tree| tree.message_secrets.timestamp().is_some());
                }
                PastEpochDeletionTimeConfig::BeforeTimestamp(timestamp) => {
                    self.delete_past_epoch_secrets_before_timestamp(timestamp)
                }
                PastEpochDeletionTimeConfig::OlderThanDuration(duration) => {
                    self.delete_past_epoch_secrets_older_than_duration(duration)
                }
            };
            // ensure at most `max_past_epochs` entries are included
            if let Some(max_past_epochs) = policy.max_past_epochs {
                if let Some(i) = self.past_epoch_trees.len().checked_sub(max_past_epochs) {
                    self.past_epoch_trees.drain(0..i);
                }
            }
        } else {
            // delete all
            self.past_epoch_trees.clear();
        }
    }

    #[cfg(all(test, feature = "sqlite-provider", feature = "libcrux-provider"))]
    /// Helper function for testing, to iterate over all past epoch secrets
    pub(crate) fn iter_past_epoch_trees(&self) -> impl Iterator<Item = &EpochTree> {
        self.past_epoch_trees.iter()
    }

    #[cfg(test)]
    /// Helper function for testing, to get the number of past epoch trees
    pub(crate) fn num_past_epoch_trees(&self) -> usize {
        self.past_epoch_trees.len()
    }
    /// KCHAT: Rebuild a MessageSecretsStore from epoch-based storage rows.
    pub(crate) fn from_epoch_message_secrets(
        max_epochs: usize,
        current_group_epoch: GroupEpoch,
        current_epoch_message_secrets: OptimizeCurrentEpochMessageSecrets,
        mut past_epoch_message_secrets: Vec<OptimizePastEpochMessageSecrets>,
    ) -> Result<Self, LoadOptimizeError> {
        let message_secrets =
            deserialize_current_epoch_message_secrets(current_epoch_message_secrets)
                .map_err(|_| LoadOptimizeError::InvalidCurrentMessageSecrets)?;

        let mut seen_epochs = BTreeSet::new();
        for message_secrets in &past_epoch_message_secrets {
            if message_secrets.epoch >= current_group_epoch {
                return Err(LoadOptimizeError::PastEpochMessageSecretsIsCurrentOrFuture);
            }

            if !seen_epochs.insert(message_secrets.epoch.as_u64()) {
                return Err(LoadOptimizeError::DuplicatePastEpochMessageSecrets);
            }
        }

        past_epoch_message_secrets.sort_by_key(|message_secrets| message_secrets.epoch);
        if past_epoch_message_secrets.len() > max_epochs {
            let keep_from = past_epoch_message_secrets.len() - max_epochs;
            past_epoch_message_secrets = past_epoch_message_secrets.split_off(keep_from);
        }

        let mut past_epoch_trees = VecDeque::new();
        for message_secrets in past_epoch_message_secrets {
            let epoch_tree = deserialize_past_epoch_message_secrets(message_secrets)
                .map_err(|_| LoadOptimizeError::InvalidPastMessageSecrets)?;
            past_epoch_trees.push_back(epoch_tree);
        }

        Ok(Self {
            max_epochs,
            past_epoch_trees,
            message_secrets,
        })
    }

    /// KCHAT: Insert or update one past epoch MessageSecrets row loaded on demand.
    pub(crate) fn insert_past_epoch_message_secrets(
        &mut self,
        current_group_epoch: GroupEpoch,
        message_secrets: OptimizePastEpochMessageSecrets,
    ) -> Result<(), LoadOptimizeError> {
        if message_secrets.epoch >= current_group_epoch {
            return Err(LoadOptimizeError::PastEpochMessageSecretsIsCurrentOrFuture);
        }

        let epoch_tree = deserialize_past_epoch_message_secrets(message_secrets)
            .map_err(|_| LoadOptimizeError::InvalidPastMessageSecrets)?;
        if let Some(existing) = self
            .past_epoch_trees
            .iter_mut()
            .find(|existing| existing.epoch == epoch_tree.epoch)
        {
            *existing = epoch_tree;
            return Ok(());
        }

        self.past_epoch_trees.push_back(epoch_tree);
        Ok(())
    }

    /// KCHAT: Export the current epoch MessageSecrets row for external storage.
    pub(crate) fn export_current_epoch_message_secrets(
        &self,
    ) -> Result<OptimizeCurrentEpochMessageSecrets, ExportOptimizeError> {
        Ok(OptimizeCurrentEpochMessageSecrets {
            message_secrets: serialize_message_secrets_data(&self.message_secrets)?,
        })
    }

    /// KCHAT: Export one retained past epoch MessageSecrets row for external storage.
    pub(crate) fn export_past_epoch_message_secrets(
        &self,
        epoch: GroupEpoch,
    ) -> Result<Option<OptimizePastEpochMessageSecrets>, ExportOptimizeError> {
        let epoch = epoch.as_u64();
        self.past_epoch_trees
            .iter()
            .find(|epoch_tree| epoch_tree.epoch == epoch)
            .map(encode_past_epoch_message_secrets)
            .transpose()
    }
}

/// KCHAT: Serialize MessageSecrets data into an opaque storage row.
fn serialize_message_secrets_data<T: serde::Serialize>(
    value: &T,
) -> Result<Vec<u8>, ExportOptimizeError> {
    serde_json::to_vec(value)
        .map_err(|_| LibraryError::custom("Failed to serialize optimize message_secrets").into())
}

/// KCHAT: Deserialize an opaque MessageSecrets storage row.
fn deserialize_message_secrets_data<T: DeserializeOwned>(message_secrets: &[u8]) -> Result<T, ()> {
    serde_json::from_slice(message_secrets).map_err(|_| ())
}

/// KCHAT: Decode the current epoch MessageSecrets row.
fn deserialize_current_epoch_message_secrets(
    message_secrets: OptimizeCurrentEpochMessageSecrets,
) -> Result<MessageSecrets, ()> {
    deserialize_message_secrets_data(&message_secrets.message_secrets)
}

/// KCHAT: Encode one past epoch MessageSecrets row.
fn encode_past_epoch_message_secrets(
    epoch_tree: &EpochTree,
) -> Result<OptimizePastEpochMessageSecrets, ExportOptimizeError> {
    Ok(OptimizePastEpochMessageSecrets {
        epoch: epoch_tree.epoch.into(),
        message_secrets: serialize_message_secrets_data(epoch_tree)?,
    })
}

/// KCHAT: Decode one past epoch MessageSecrets row and validate its epoch.
fn deserialize_past_epoch_message_secrets(
    message_secrets: OptimizePastEpochMessageSecrets,
) -> Result<EpochTree, ()> {
    let epoch = message_secrets.epoch;
    let epoch_tree: EpochTree = deserialize_message_secrets_data(&message_secrets.message_secrets)?;
    if epoch_tree.epoch != epoch.as_u64() {
        return Err(());
    }
    Ok(epoch_tree)
}
