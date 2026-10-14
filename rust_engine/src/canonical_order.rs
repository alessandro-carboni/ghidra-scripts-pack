//! Exact colored directed multigraph labeling. Resource exhaustion is an error,
//! never an address-based fallback or a partially canonical result.
use std::collections::{BTreeMap, BTreeSet};

type Arc = (usize, usize, String);

fn colors(keys: &[String]) -> Vec<usize> {
    let unique: BTreeSet<_> = keys.iter().cloned().collect();
    let ranks: BTreeMap<_, _> = unique
        .into_iter()
        .enumerate()
        .map(|(i, k)| (k, i))
        .collect();
    keys.iter().map(|k| ranks[k]).collect()
}

fn refine(mut labels: Vec<usize>, arcs: &[Arc]) -> Vec<usize> {
    loop {
        let keys: Vec<_> = (0..labels.len())
            .map(|i| {
                let mut neighbors = Vec::new();
                for (s, t, kind) in arcs {
                    if *s == i {
                        neighbors.push(("out", kind, labels[*t]));
                    }
                    if *t == i {
                        neighbors.push(("in", kind, labels[*s]));
                    }
                }
                neighbors.sort();
                serde_json::to_string(&(labels[i], neighbors)).unwrap()
            })
            .collect();
        let next = colors(&keys);
        let old_count = labels.iter().collect::<BTreeSet<_>>().len();
        let new_count = next.iter().collect::<BTreeSet<_>>().len();
        if new_count == old_count {
            return next;
        }
        labels = next;
    }
}

fn interchangeable(a: usize, b: usize, arcs: &[Arc]) -> bool {
    let swap = |v| {
        if v == a {
            b
        } else if v == b {
            a
        } else {
            v
        }
    };
    let mut original = arcs.to_vec();
    let mut swapped: Vec<_> = arcs
        .iter()
        .map(|(s, t, k)| (swap(*s), swap(*t), k.clone()))
        .collect();
    original.sort();
    swapped.sort();
    original == swapped
}

/// Node indices only index input storage. They do not occur in the comparison key.
pub fn canonical_order(keys: &[String], arcs: &[Arc]) -> Result<Vec<usize>, String> {
    struct Search<'a> {
        keys: &'a [String],
        arcs: &'a [Arc],
        remaining: usize,
        best: Option<(String, Vec<usize>)>,
    }
    impl Search<'_> {
        fn visit(&mut self, labels: Vec<usize>, depth: usize) -> Result<(), String> {
            if self.remaining == 0 || depth > 256 {
                return Err(
                    "canonical labeling resource limit exceeded; no output produced".into(),
                );
            }
            self.remaining -= 1;
            let labels = refine(labels, self.arcs);
            let mut cells: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
            for (i, label) in labels.iter().enumerate() {
                cells.entry(*label).or_default().push(i);
            }
            if let Some(cell) = cells
                .values()
                .filter(|c| c.len() > 1)
                .min_by_key(|c| c.len())
            {
                let mut representatives = Vec::new();
                for &i in cell {
                    if representatives
                        .iter()
                        .any(|&j| interchangeable(i, j, self.arcs))
                    {
                        continue;
                    }
                    representatives.push(i);
                    let split: Vec<_> = labels
                        .iter()
                        .enumerate()
                        .map(|(j, l)| format!("{l}:{}", usize::from(i == j)))
                        .collect();
                    self.visit(colors(&split), depth + 1)?;
                }
            } else {
                let order: Vec<_> = cells.values().map(|c| c[0]).collect();
                let mut inverse = vec![0; order.len()];
                for (new, old) in order.iter().enumerate() {
                    inverse[*old] = new;
                }
                let mut edges: Vec<_> = self
                    .arcs
                    .iter()
                    .map(|(s, t, k)| (inverse[*s], inverse[*t], k))
                    .collect();
                edges.sort();
                let key = serde_json::to_string(&(
                    order.iter().map(|i| &self.keys[*i]).collect::<Vec<_>>(),
                    edges,
                ))
                .unwrap();
                if self.best.as_ref().is_none_or(|(best, _)| key < *best) {
                    self.best = Some((key, order));
                }
            }
            Ok(())
        }
    }
    let mut search = Search {
        keys,
        arcs,
        remaining: 100_000,
        best: None,
    };
    search.visit(colors(keys), 0)?;
    Ok(search.best.unwrap().1)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encoded(keys: &[String], arcs: &[Arc]) -> String {
        let order = canonical_order(keys, arcs).unwrap();
        let mut inverse = vec![0; keys.len()];
        for (new, old) in order.iter().enumerate() {
            inverse[*old] = new;
        }
        let mut edges: Vec<_> = arcs
            .iter()
            .map(|(s, t, k)| (inverse[*s], inverse[*t], k))
            .collect();
        edges.sort();
        serde_json::to_string(&(order.iter().map(|i| &keys[*i]).collect::<Vec<_>>(), edges))
            .unwrap()
    }
    #[test]
    fn symmetric_and_asymmetric_topologies_are_permutation_invariant() {
        for edges in [
            vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)],
            vec![(0, 1), (0, 2), (1, 3), (2, 4), (3, 2)],
        ] {
            let keys = vec!["function".to_string(); 5];
            let arcs: Vec<_> = edges.iter().map(|(s, t)| (*s, *t, "call".into())).collect();
            let baseline = encoded(&keys, &arcs);
            for a in 0..5 {
                for b in 0..5 {
                    for c in 0..5 {
                        for d in 0..5 {
                            for e in 0..5 {
                                let permutation = [a, b, c, d, e];
                                if permutation.iter().collect::<BTreeSet<_>>().len() != 5 {
                                    continue;
                                }
                                let shuffled: Vec<_> = arcs
                                    .iter()
                                    .rev()
                                    .map(|(s, t, k)| (permutation[*s], permutation[*t], k.clone()))
                                    .collect();
                                assert_eq!(encoded(&keys, &shuffled), baseline);
                            }
                        }
                    }
                }
            }
        }
    }
}
