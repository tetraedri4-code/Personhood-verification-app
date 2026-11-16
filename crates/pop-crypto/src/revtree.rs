//! A real sorted revocation tree (design v2 §4.6, "one cumulative tree" variant measured by the benchmark).
//!
//! Revoked handles are sorted, framed by the sentinels 0 and u64::MAX, and every pair of neighbours
//! (a, b) becomes a leaf `Hp_leaf(a, b)`. A holder whose handle r is not revoked finds the leaf with
//! a < r < b and proves, inside the circuit, the path from that leaf to the public root.
//! Unused leaves hold `Hp_leaf(0, 0)`, which no handle can fall between.
//!
//! The benchmark (`tree::make_path`) used random siblings of the right depth; this module builds the
//! tree for real so that issuer, holders and verifiers agree on one root.
use crate::params::Fr;
use crate::poseidon::Poseidon;
use crate::tree::{dom_leaf, node_hash, TreePath, TreeShape};

/// Handles are random 64-bit values in [1, u64::MAX - 1].
pub const SENTINEL_LOW: u64 = 0;
pub const SENTINEL_HIGH: u64 = u64::MAX;

pub struct RevocationTree {
    pub shape: TreeShape,
    /// sorted handles including both sentinels
    sorted: Vec<u64>,
    /// levels[0] = leaves, levels[depth] = [root]
    levels: Vec<Vec<Fr>>,
}

impl RevocationTree {
    /// Build the tree over `revoked`. Fails if more handles are revoked than the tree can hold.
    pub fn build(revoked: &[u64], shape: TreeShape, pos3: &Poseidon, pos5: &Poseidon) -> Result<Self, String> {
        let mut sorted: Vec<u64> = revoked
            .iter()
            .copied()
            .filter(|h| *h != SENTINEL_LOW && *h != SENTINEL_HIGH)
            .collect();
        sorted.sort_unstable();
        sorted.dedup();
        sorted.insert(0, SENTINEL_LOW);
        sorted.push(SENTINEL_HIGH);
        let capacity = (shape.arity as u64).pow(shape.depth as u32);
        let n_leaves = (sorted.len() - 1) as u64;
        if n_leaves > capacity {
            return Err(format!("revocation tree full: {n_leaves} leaves > capacity {capacity}"));
        }
        let empty = pos3.hash_dom(dom_leaf(), &[Fr::from(0u64), Fr::from(0u64)]);
        let mut leaves: Vec<Fr> = sorted
            .windows(2)
            .map(|w| pos3.hash_dom(dom_leaf(), &[Fr::from(w[0]), Fr::from(w[1])]))
            .collect();
        leaves.resize(capacity as usize, empty);
        let mut levels = vec![leaves];
        for _ in 0..shape.depth {
            let prev = levels.last().unwrap();
            let next: Vec<Fr> = prev.chunks(shape.arity).map(|c| node_hash(pos3, pos5, c)).collect();
            levels.push(next);
        }
        Ok(RevocationTree { shape, sorted, levels })
    }

    pub fn root(&self) -> Fr {
        self.levels[self.shape.depth][0]
    }

    pub fn is_revoked(&self, r: u64) -> bool {
        self.sorted.binary_search(&r).is_ok()
    }

    /// Non-membership path for handle r, or None if r is revoked or a sentinel.
    pub fn path(&self, r: u64) -> Option<TreePath> {
        if r == SENTINEL_LOW || r == SENTINEL_HIGH || self.is_revoked(r) {
            return None;
        }
        // index of the leaf (a, b) with a < r < b
        let idx = self.sorted.partition_point(|h| *h < r) - 1;
        let (a, b) = (self.sorted[idx], self.sorted[idx + 1]);
        let mut sib = vec![];
        let mut pos = vec![];
        let mut i = idx;
        for lvl in 0..self.shape.depth {
            let p = i % self.shape.arity;
            let start = i - p;
            let s: Vec<Fr> = (0..self.shape.arity)
                .filter(|j| *j != p)
                .map(|j| self.levels[lvl][start + j])
                .collect();
            sib.push(s);
            pos.push(p);
            i /= self.shape.arity;
        }
        Some(TreePath { a, b, sib, pos, root: self.root() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::arrange;

    #[test]
    fn path_recomputes_root() {
        let pos3 = Poseidon::new(3);
        let pos5 = Poseidon::new(5);
        let shape = TreeShape { arity: 4, depth: 3 };
        let t = RevocationTree::build(&[10, 500, 77, 1 << 40], shape, &pos3, &pos5).unwrap();
        assert!(t.path(77).is_none());
        let p = t.path(100).unwrap();
        assert_eq!((p.a, p.b), (77, 500));
        let mut cur = pos3.hash_dom(dom_leaf(), &[Fr::from(p.a), Fr::from(p.b)]);
        for l in 0..shape.depth {
            cur = node_hash(&pos3, &pos5, &arrange(cur, &p.sib[l], p.pos[l]));
        }
        assert_eq!(cur, t.root());
    }

    #[test]
    fn full_tree_rejected() {
        let pos3 = Poseidon::new(3);
        let pos5 = Poseidon::new(5);
        let shape = TreeShape { arity: 4, depth: 1 };
        assert!(RevocationTree::build(&[1, 2, 3, 4], shape, &pos3, &pos5).is_err());
        assert!(RevocationTree::build(&[1, 2, 3], shape, &pos3, &pos5).is_ok());
    }
}
