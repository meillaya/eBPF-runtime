// SPDX-License-Identifier: Apache-2.0 OR MIT
//! List/sequence integrity: unique names and no recursive list references.
//!
//! Lists are reusable, immutable string lists. A list item that names another
//! list is a *reference*; a cycle of references is *recursion*, which the
//! evaluator could never resolve. We reject cycles (including self-reference)
//! at validation time so a rule set can never activate a recursive list.

use std::collections::{HashMap, HashSet};

use crate::ast::RuleSet;
use crate::error::{Result, RuleError};

/// All list names across the rule set must be unique.
pub fn check_list_names_unique(ruleset: &RuleSet) -> Result<()> {
    let mut seen = HashSet::new();
    for rule in &ruleset.rules {
        for list in &rule.lists {
            if !seen.insert(list.name.as_str()) {
                return Err(RuleError::DuplicateListName(list.name.clone()));
            }
        }
    }
    Ok(())
}

/// All sequence names across the rule set must be unique.
pub fn check_sequence_names_unique(ruleset: &RuleSet) -> Result<()> {
    let mut seen = HashSet::new();
    for rule in &ruleset.rules {
        for seq in &rule.sequences {
            if !seen.insert(seq.name.as_str()) {
                return Err(RuleError::DuplicateSequenceName(seq.name.clone()));
            }
        }
    }
    Ok(())
}

/// Reject any cycle in the list-reference graph (a list item naming a list).
///
/// Iteration starts in document order so the reported cycle is deterministic.
pub fn check_list_recursion(ruleset: &RuleSet) -> Result<()> {
    let lists = collect_lists(ruleset);
    let name_to_path: HashMap<String, String> = lists
        .iter()
        .map(|(path, name, _)| (name.clone(), path.clone()))
        .collect();
    let name_set: HashSet<String> = lists.iter().map(|(_, name, _)| name.clone()).collect();
    let adj: HashMap<String, Vec<String>> = lists
        .iter()
        .map(|(_, name, items)| {
            let refs = items
                .iter()
                .filter(|item| name_set.contains(*item))
                .cloned()
                .collect();
            (name.clone(), refs)
        })
        .collect();
    let mut color: HashMap<String, u8> = name_set.iter().map(|name| (name.clone(), 0)).collect();
    for (_, start, _) in &lists {
        if color.get(start).copied() == Some(0) {
            let mut stack: Vec<String> = Vec::new();
            if let Some(cycle) = dfs_cycle(start, &adj, &mut color, &mut stack) {
                let path = name_to_path
                    .get(&cycle[0])
                    .cloned()
                    .unwrap_or_else(|| "?".into());
                return Err(RuleError::SchemaValidationError(format!(
                    "{path}: recursive list reference detected: {} -> {}",
                    cycle.join(" -> "),
                    cycle[0]
                )));
            }
        }
    }
    Ok(())
}

/// Gather every list as `(path, name, items)` in document order.
fn collect_lists(ruleset: &RuleSet) -> Vec<(String, String, Vec<String>)> {
    let mut lists = Vec::new();
    for (ri, rule) in ruleset.rules.iter().enumerate() {
        for (li, list) in rule.lists.iter().enumerate() {
            lists.push((
                format!("rules[{ri}].lists[{li}]"),
                list.name.clone(),
                list.items.clone(),
            ));
        }
    }
    lists
}

/// DFS cycle detection (white/gray/black). Returns the cycle path if found.
fn dfs_cycle(
    node: &str,
    adj: &HashMap<String, Vec<String>>,
    color: &mut HashMap<String, u8>,
    stack: &mut Vec<String>,
) -> Option<Vec<String>> {
    color.insert(node.to_string(), 1);
    stack.push(node.to_string());
    if let Some(neighbors) = adj.get(node) {
        for nb in neighbors {
            match color.get(nb).copied() {
                Some(1) => {
                    let pos = stack.iter().position(|n| n == nb).unwrap();
                    return Some(stack[pos..].to_vec());
                }
                Some(0) => {
                    if let Some(cycle) = dfs_cycle(nb, adj, color, stack) {
                        return Some(cycle);
                    }
                }
                _ => {}
            }
        }
    }
    stack.pop();
    color.insert(node.to_string(), 2);
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_ruleset;

    fn doc_with_list(items: &str) -> String {
        format!(
            "schema_version: 1\nengine_version: \"1.0.0\"\nrules:\n  - id: r\n    version: 1\n    severity: low\n    source: file\n    description: d\n    condition:\n      field: file.path\n      operator: eq\n      value: /x\n    action: alert\n    lists:\n      - name: a\n        items: [{items}]\n"
        )
    }

    #[test]
    fn self_referencing_list_is_rejected() {
        let doc = doc_with_list("\"a\"");
        assert!(matches!(
            parse_ruleset(&doc),
            Err(RuleError::SchemaValidationError(_))
        ));
    }

    #[test]
    fn plain_list_is_accepted() {
        let doc = doc_with_list("\"/etc\", \"/var\"");
        assert!(parse_ruleset(&doc).is_ok());
    }
}
