/// Stand slug: same shape the gateway uses (`/stand/<slug>/…`).
pub fn parse_slug(raw: &str) -> Result<String, &'static str> {
    let slug = raw.trim();
    if slug.is_empty() || slug.len() > 64 {
        return Err("slug: пустой или длиннее 64");
    }
    let ok = slug
        .bytes()
        .enumerate()
        .all(|(i, b)| matches!(b, b'a'..=b'z' | b'0'..=b'9') || (b == b'-' && i > 0));
    if !ok {
        return Err("slug: только [a-z0-9], дефис не первым");
    }
    Ok(slug.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_stand_slugs() {
        assert_eq!(parse_slug("neweditor").unwrap(), "neweditor");
        assert_eq!(parse_slug(" stand-01 ").unwrap(), "stand-01");
    }

    #[test]
    fn rejects_junk() {
        assert!(parse_slug("").is_err());
        assert!(parse_slug("-x").is_err());
        assert!(parse_slug("NewEditor").is_err());
        assert!(parse_slug("../x").is_err());
    }
}
