use alloc::vec::Vec;

use ayatori::{
    protocol_author_api::RuntimeError,
    signature::digest::{self, FixedOutput},
};
use serde_encoded_bytes::{Hex, SliceLike};

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
struct MerkleNode<D: FixedOutput>(#[serde(with = "SliceLike::<Hex>")] digest::Output<D>);

impl<D: FixedOutput + Default> MerkleNode<D> {
    fn from_value(value: &impl Hashable<D>) -> Self {
        let mut digest = D::default();
        digest.update(b"MerkleTree");
        digest.update(b"\x01");
        digest.update(&value.hash());
        Self(digest.finalize_fixed())
    }

    fn padding() -> Self {
        let mut digest = D::default();
        digest.update(b"MerkleTree");
        digest.update(b"\x00");
        Self(digest.finalize_fixed())
    }

    fn from_nodes(left: &Self, right: &Self) -> Self {
        let mut digest = D::default();
        digest.update(b"MerkleTree");
        digest.update(&left.0);
        digest.update(&right.0);
        Self(digest.finalize_fixed())
    }
}

#[derive_where::derive_where(Debug, Clone)]
pub(crate) struct MerkleTree<D: FixedOutput> {
    // Tree nodes are stored linearly: first 2^L leaf nodes,
    // then 2^(L-1) nodes produced by hashing leaves,
    // and so on, the root node being the last.
    nodes: Vec<MerkleNode<D>>,
}

pub(crate) trait Hashable<D: FixedOutput> {
    fn hash(&self) -> digest::Output<D>;
}

impl<D: FixedOutput + Default> MerkleTree<D> {
    // TODO: enforce via types that it's a "full set" of shards, not just some of them
    #[expect(
        // This can only fail if we have more items than the capacity of `usize`
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::as_conversions,
    )]
    pub fn new<'a, T: Hashable<D> + 'a>(items: impl Iterator<Item = (usize, &'a T)>) -> Result<Self, RuntimeError> {
        let padding = MerkleNode::padding();
        let mut nodes = Vec::<MerkleNode<D>>::new();
        for (idx, item) in items {
            if idx >= nodes.len() {
                nodes.resize_with(idx + 1, || padding.clone());
            }
            nodes[idx] = MerkleNode::from_value(item);
        }

        if nodes.is_empty() {
            return Err(RuntimeError::new("The set of items must be non-empty"));
        }

        let num_leaves = nodes.len().next_power_of_two();

        nodes.resize_with(num_leaves, || padding.clone());
        nodes.reserve_exact(num_leaves * 2 - 1);

        // The number of tree levels including the leaf level
        let levels = num_leaves.ilog2() as usize + 1;
        for level in 0..(levels - 1) {
            // The start of the current level in the array of nodes.
            let level_offset = (1 << (levels - level)) * ((1 << level) - 1);
            // The number of nodes in the next level (the one that we are currently filling).
            let nodes_in_next_level = 1 << (levels - level - 2);
            for idx in 0..nodes_in_next_level {
                nodes.push(MerkleNode::from_nodes(
                    &nodes[level_offset + 2 * idx],
                    &nodes[level_offset + 2 * idx + 1],
                ));
            }
        }

        Ok(Self { nodes })
    }

    #[expect(clippy::arithmetic_side_effects, clippy::indexing_slicing, clippy::as_conversions)]
    pub fn branch(&self, idx: usize) -> MerkleBranch<D> {
        let mut nodes = Vec::new();
        let levels = (self.nodes.len() + 1).ilog2() as usize;
        for level in 0..(levels - 1) {
            let level_offset = (1 << (levels - level)) * ((1 << level) - 1);
            let idx_in_level = (idx >> level) ^ 1;
            nodes.push(self.nodes[level_offset + idx_in_level].clone());
        }

        MerkleBranch {
            nodes,
            root: self.root(),
        }
    }

    pub fn root(&self) -> MerkleRoot<D> {
        MerkleRoot(
            self.nodes
                .last()
                .expect("the nodes list is non-empty as enforced in `new()`")
                .0
                .clone(),
        )
    }
}

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct MerkleRoot<D: FixedOutput>(#[serde(with = "SliceLike::<Hex>")] digest::Output<D>);

#[derive_where::derive_where(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MerkleBranch<D: FixedOutput> {
    nodes: Vec<MerkleNode<D>>,
    root: MerkleRoot<D>,
}

impl<D: FixedOutput + Default> MerkleBranch<D> {
    pub fn root(&self) -> &MerkleRoot<D> {
        &self.root
    }

    pub fn verify(&self, idx: usize, value: &impl Hashable<D>) -> bool {
        let mut current_node = MerkleNode::from_value(value);
        for (level, node) in self.nodes.iter().enumerate() {
            let node_idx = idx >> level;
            if node_idx & 1 == 0 {
                current_node = MerkleNode::from_nodes(&current_node, node);
            } else {
                current_node = MerkleNode::from_nodes(node, &current_node);
            }
        }
        MerkleRoot(current_node.0) == self.root
    }
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;

    use ayatori::{
        dev::TestHasher,
        signature::digest::{self, FixedOutput},
    };

    use super::{Hashable, MerkleTree};

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Shard(usize);

    impl<D: FixedOutput + Default> Hashable<D> for Shard {
        fn hash(&self) -> digest::Output<D> {
            let mut digest = D::default();
            digest.update(&self.0.to_be_bytes());
            digest.finalize_fixed()
        }
    }

    #[test]
    fn verification() {
        let shards_num = 12usize;
        let shards = (0..shards_num).map(Shard).collect::<Vec<_>>();
        let tree = MerkleTree::<TestHasher>::new(shards.iter().enumerate()).unwrap();

        for (idx, shard) in shards.iter().enumerate() {
            let branch = tree.branch(idx);
            assert_eq!(branch.root(), &tree.root());
            assert!(branch.verify(idx, shard));
        }

        let correct_idx = 8;
        let branch = tree.branch(correct_idx);
        for (idx, shard) in shards.iter().enumerate().filter(|(idx, _shard)| idx != &correct_idx) {
            assert!(!branch.verify(idx, shard));
        }
    }
}
