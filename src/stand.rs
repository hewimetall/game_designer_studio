/// Paths the existing editors already call via `apiUrl()` / `api()`.
pub fn prefetch_json_paths(slug: &str) -> Vec<String> {
    vec![
        format!("/stand/{slug}/api/levels"),
        format!("/stand/{slug}/api/sprites"),
        format!("/stand/{slug}/api/bestiary"),
        format!("/stand/{slug}/api/spawn-slots"),
        format!("/stand/{slug}/api/spawn-bindings"),
    ]
}

pub fn level_get_path(slug: &str, kind: &str) -> String {
    format!("/stand/{slug}/api/level?kind={kind}")
}

/// Expand `/api/levels` JSON into per-kind GETs (no atlas/file — those stay lazy).
pub fn level_paths_from_list(slug: &str, body: &[u8]) -> Vec<String> {
    let Ok(items) = serde_json::from_slice::<Vec<serde_json::Value>>(body) else {
        return Vec::new();
    };
    items
        .into_iter()
        .filter_map(|item| {
            let kind = item.get("kind")?.as_str()?;
            Some(level_get_path(slug, kind))
        })
        .collect()
}

/// After a successful POST, refresh the matching GET snapshot so the next
/// offline open shows what the stand already accepted.
pub fn write_updates_get(method: &str, path_and_query: &str) -> Option<String> {
    if method != "POST" && method != "PUT" {
        return None;
    }
    let (path, query) = split_pq(path_and_query);
    if path.ends_with("/api/level") {
        return Some(path_and_query.to_string());
    }
    for suffix in ["/api/sprites", "/api/bestiary", "/api/spawn-bindings"] {
        if path.ends_with(suffix) && query.is_empty() {
            return Some(path.to_string());
        }
    }
    if let Some(rest) = path.split_once("/api/sprites/save-file/") {
        return Some(format!(
            "{}/api/sprites/file/{}",
            stand_prefix(rest.0),
            rest.1
        ));
    }
    if let Some(rest) = path.split_once("/api/sprites/upload/") {
        return Some(format!(
            "{}/api/sprites/atlas/{}",
            stand_prefix(rest.0),
            rest.1
        ));
    }
    None
}

pub fn atlas_get_path(slug: &str, name: &str) -> String {
    format!("/stand/{slug}/api/sprites/atlas/{name}")
}

/// Unique `/api/sprites/atlas/{name}` GETs referenced by spawn-bindings JSON.
/// Bestiary portraits are `bindings[QueenTank].atlas` + slot `idle`.
pub fn atlas_paths_from_bindings(slug: &str, body: &[u8]) -> Vec<String> {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(bindings) = value.get("bindings").and_then(|item| item.as_object()) else {
        return Vec::new();
    };
    let mut paths: Vec<String> = bindings
        .values()
        .filter_map(|binding| binding.get("atlas").and_then(|atlas| atlas.as_str()))
        .filter(|name| !name.is_empty())
        .map(|name| atlas_get_path(slug, name))
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

/// Atlas GETs for names that are new or whose `path` changed vs the previous
/// `/api/sprites` snapshot. Frame-only edits keep the same PNG and stay lazy.
pub fn changed_atlas_get_paths(slug: &str, previous: Option<&[u8]>, next: &[u8]) -> Vec<String> {
    let Some(new_map) = atlas_path_map(next) else {
        return Vec::new();
    };
    let old_map = previous.and_then(atlas_path_map).unwrap_or_default();
    new_map
        .into_iter()
        .filter(|(name, path)| old_map.get(name) != Some(path))
        .map(|(name, _)| atlas_get_path(slug, &name))
        .collect()
}

/// Bestiary loads `/api/sprites/atlas/{name}`, not `/api/sprites/file/...`.
/// Map a save-file relative path onto atlas names from the sprites snapshot.
pub fn atlas_paths_for_saved_file(slug: &str, sprites_body: &[u8], saved_rel: &str) -> Vec<String> {
    let Some(map) = atlas_path_map(sprites_body) else {
        return Vec::new();
    };
    let saved = saved_rel.trim_matches('/');
    let mut paths: Vec<String> = map
        .into_iter()
        .filter(|(_, path)| atlas_path_matches_saved(path, saved))
        .map(|(name, _)| atlas_get_path(slug, &name))
        .collect();
    paths.sort();
    paths.dedup();
    paths
}

fn atlas_path_matches_saved(atlas_path: &str, saved_rel: &str) -> bool {
    let atlas_path = atlas_path.trim_matches('/');
    let saved_rel = saved_rel.trim_matches('/');
    if atlas_path.is_empty() || saved_rel.is_empty() {
        return false;
    }
    atlas_path == saved_rel
        || atlas_path.strip_prefix("sprites/") == Some(saved_rel)
        || atlas_path.ends_with(&format!("/{saved_rel}"))
}

pub fn slug_from_stand_path(path_and_query: &str) -> Option<&str> {
    let (path, _) = split_pq(path_and_query);
    let rest = path.strip_prefix("/stand/")?;
    let slug = rest.split('/').next()?;
    if slug.is_empty() {
        None
    } else {
        Some(slug)
    }
}

fn atlas_path_map(body: &[u8]) -> Option<std::collections::BTreeMap<String, String>> {
    let value = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let atlases = value.get("atlases")?.as_object()?;
    Some(
        atlases
            .iter()
            .map(|(name, def)| {
                let path = def
                    .get("path")
                    .and_then(|item| item.as_str())
                    .unwrap_or("")
                    .to_string();
                (name.clone(), path)
            })
            .collect(),
    )
}

fn stand_prefix(before_api: &str) -> &str {
    before_api.trim_end_matches('/')
}

fn split_pq(path_and_query: &str) -> (&str, &str) {
    match path_and_query.split_once('?') {
        Some((path, query)) => (path, query),
        None => (path_and_query, ""),
    }
}

pub fn health_path(slug: &str) -> String {
    format!("/stand/{slug}/api/health")
}

pub fn stand_root_path(slug: &str) -> String {
    // Singular `/stand/` is what the outpost actually serves. Live proof:
    // HEAD https://my.mcpwork.space/stand/cursorgo/ → 302 /stand/cursorgo/level/
    format!("/stand/{slug}/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefetch_is_json_only() {
        let paths = prefetch_json_paths("cursorgo");
        assert!(paths.iter().all(|p| p.contains("/api/")));
        assert!(paths
            .iter()
            .all(|p| !p.contains("atlas") && !p.contains("file/")));
        assert!(paths.contains(&"/stand/cursorgo/api/bestiary".into()));
        assert!(!paths
            .iter()
            .any(|p| p.contains("alife") || p.contains("game")));
    }

    #[test]
    fn successful_level_post_refreshes_same_get() {
        let pq = "/stand/s/api/level?kind=Hub";
        assert_eq!(write_updates_get("POST", pq).as_deref(), Some(pq));
        assert!(write_updates_get("GET", pq).is_none());
    }

    #[test]
    fn levels_list_expands_to_kind_gets() {
        let body = br#"[{"kind":"Hub"},{"kind":"Market"}]"#;
        let paths = level_paths_from_list("s", body);
        assert_eq!(
            paths,
            vec![
                "/stand/s/api/level?kind=Hub".to_string(),
                "/stand/s/api/level?kind=Market".to_string()
            ]
        );
    }

    #[test]
    fn save_file_post_maps_to_file_get() {
        assert_eq!(
            write_updates_get("POST", "/stand/s/api/sprites/save-file/units/queen.png").as_deref(),
            Some("/stand/s/api/sprites/file/units/queen.png")
        );
        assert_eq!(
            write_updates_get("POST", "/stand/s/api/sprites/upload/матка танк").as_deref(),
            Some("/stand/s/api/sprites/atlas/матка танк")
        );
    }

    #[test]
    fn bindings_expand_to_unique_atlas_gets() {
        let body = r#"{
            "bindings": {
                "QueenTank": {"atlas": "матка танк", "slot_anims": {"idle": "idle"}},
                "QueenFighter": {"atlas": "mutant_basic", "slot_anims": {"idle": "idle"}},
                "QueenRanged": {"atlas": "матка танк", "slot_anims": {"idle": "idle"}},
                "Campfire": {"atlas": "", "slot_anims": {}}
            }
        }"#;
        let paths = atlas_paths_from_bindings("cursorgo", body.as_bytes());
        assert_eq!(
            paths,
            vec![
                "/stand/cursorgo/api/sprites/atlas/mutant_basic".to_string(),
                "/stand/cursorgo/api/sprites/atlas/матка танк".to_string()
            ]
        );
    }

    #[test]
    fn sprites_post_warms_only_new_or_replaced_atlas_gets() {
        let previous = br#"{
            "atlases": {
                "mutant_basic": {"path": "sprites/mutants/mutant_basic.png"}
            }
        }"#;
        let next = r#"{
            "atlases": {
                "mutant_basic": {"path": "sprites/mutants/mutant_basic.png"},
                "матка танк": {"path": "sprites/units/_-abc.png"}
            }
        }"#;
        assert_eq!(
            changed_atlas_get_paths("s", Some(previous), next.as_bytes()),
            vec!["/stand/s/api/sprites/atlas/матка танк".to_string()]
        );
        assert!(changed_atlas_get_paths("s", Some(next.as_bytes()), next.as_bytes()).is_empty());
        assert_eq!(
            slug_from_stand_path("/stand/cursorgo/api/sprites"),
            Some("cursorgo")
        );
        assert_eq!(stand_root_path("cursorgo"), "/stand/cursorgo/");
        assert!(!stand_root_path("cursorgo").starts_with("/stands/"));
    }

    #[test]
    fn save_file_maps_to_bestiary_atlas_get() {
        let sprites = r#"{
            "atlases": {
                "матка танк": {"path": "sprites/units/queen.png"},
                "mutant_basic": {"path": "sprites/mutants/mutant_basic.png"}
            }
        }"#;
        assert_eq!(
            atlas_paths_for_saved_file("s", sprites.as_bytes(), "units/queen.png"),
            vec!["/stand/s/api/sprites/atlas/матка танк".to_string()]
        );
        assert!(
            atlas_paths_for_saved_file("s", sprites.as_bytes(), "units/missing.png").is_empty()
        );
    }
}
