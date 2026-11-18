//! Which cross-origin page may host the app. A framing page on another origin names itself with
//! `?parentOrigin=<origin>`, and the app's own HTML lists the origins it trusts in
//! `<meta name="craft-allowed-parents" content="<origin> <origin>…">`. Only a named origin found
//! in that list is used, and it becomes the `targetOrigin` of every post, so document bytes reach
//! no other page even when the query lies about who the parent is.

/// The `parentOrigin` named in a page URL's query (with or without its leading `?`), as
/// `scheme://host[:port]`: lowercase, without a path or a trailing `/`, and without the scheme's
/// default port (the form a browser gives in `MessageEvent.origin`). `None` when it is missing,
/// named more than once, or not an `http(s)` origin.
pub fn parent_origin(query: &str) -> Option<String> {
    let query = query.strip_prefix('?').unwrap_or(query);
    let mut values = query.split('&').filter_map(|pair| pair.strip_prefix("parentOrigin="));
    let raw = values.next()?;
    // Two values could be read differently by the page that built the URL; trust neither.
    if values.next().is_some() {
        return None;
    }
    normalize(&percent_decode(raw)?)
}

/// Whether `origin` is in `list`, origins separated by whitespace and compared exactly. `*`,
/// `null` and an empty origin never match, so a list cannot open the app to every page.
pub fn allowed(list: &str, origin: &str) -> bool {
    if origin.is_empty() || origin == "*" || origin == "null" {
        return false;
    }
    list.split_ascii_whitespace().any(|entry| entry == origin)
}

/// The parent origin the query names when it differs from `own_origin`: the parent is then on
/// another origin, and reading its `location` would throw, so only the allowlist can admit it.
/// `None` sends the caller down the same-origin path.
pub fn cross_origin(query: &str, own_origin: &str) -> Option<String> {
    parent_origin(query).filter(|origin| origin != own_origin)
}

fn normalize(value: &str) -> Option<String> {
    let (scheme, rest) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = split_port(authority)?;
    let host = host.to_ascii_lowercase();
    if !valid_host(&host) {
        return None;
    }
    Some(match port {
        Some(port) if port != default_port => format!("{scheme}://{host}:{port}"),
        _ => format!("{scheme}://{host}"),
    })
}

/// `host` and its port. A user-info part (`a@b`) is refused: it hides the real host from a reader.
fn split_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if authority.contains('@') {
        return None;
    }
    let colon = match authority.rfind(':') {
        // A colon inside `[…]` belongs to an IPv6 address, not a port.
        Some(i) if !authority[i..].contains(']') => i,
        _ => return Some((authority, None)),
    };
    let (host, port) = (&authority[..colon], &authority[colon + 1..]);
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    if port == 0 {
        return None;
    }
    Some((host, Some(port)))
}

/// Only the characters a browser leaves in an origin's host: ASCII names (IDNs arrive as
/// punycode) or a bracketed IPv6 address. Anything else could be read as another host.
fn valid_host(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return !inner.is_empty() && inner.bytes().all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
    }
    !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

fn percent_decode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = raw.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_parent_origin_is_decoded_from_the_query() {
        assert_eq!(parent_origin("host=parent&parentOrigin=http%3A%2F%2Flocalhost%3A5432").as_deref(), Some("http://localhost:5432"));
        assert_eq!(parent_origin("?parentOrigin=https://admin.kortly.no&host=parent").as_deref(), Some("https://admin.kortly.no"));
    }

    #[test]
    fn a_path_and_a_trailing_slash_are_dropped() {
        assert_eq!(parent_origin("parentOrigin=https://admin.kortly.no/x").as_deref(), Some("https://admin.kortly.no"));
        assert_eq!(parent_origin("parentOrigin=https%3A%2F%2Fadmin.kortly.no%2F").as_deref(), Some("https://admin.kortly.no"));
        assert_eq!(parent_origin("parentOrigin=https://admin.kortly.no?x=1").as_deref(), Some("https://admin.kortly.no"));
        assert_eq!(parent_origin("parentOrigin=https://admin.kortly.no#top").as_deref(), Some("https://admin.kortly.no"));
    }

    #[test]
    fn it_takes_the_form_a_browser_reports_as_the_event_origin() {
        assert_eq!(parent_origin("parentOrigin=HTTPS://Admin.Kortly.NO").as_deref(), Some("https://admin.kortly.no"));
        assert_eq!(parent_origin("parentOrigin=https://admin.kortly.no:443").as_deref(), Some("https://admin.kortly.no"));
        assert_eq!(parent_origin("parentOrigin=http://localhost:80").as_deref(), Some("http://localhost"));
        assert_eq!(parent_origin("parentOrigin=http://localhost:443").as_deref(), Some("http://localhost:443"));
        assert_eq!(parent_origin("parentOrigin=http://[::1]:5432").as_deref(), Some("http://[::1]:5432"));
        assert_eq!(parent_origin("parentOrigin=http://[::1]").as_deref(), Some("http://[::1]"));
    }

    #[test]
    fn anything_but_an_http_origin_is_refused() {
        for query in [
            "parentOrigin=javascript:alert(1)",
            "parentOrigin=javascript%3A%2F%2Falert(1)",
            "parentOrigin=null",
            "parentOrigin=*",
            "parentOrigin=",
            "host=parent",
            "",
            "parentOrigin=file:///etc/passwd",
            "parentOrigin=data:text/html,x",
            "parentOrigin=https://",
            "parentOrigin=https:///x",
            "parentOrigin=//admin.kortly.no",
            "parentOrigin=admin.kortly.no",
            "parentOrigin=https://user@evil.example",
            "parentOrigin=https://admin.kortly.no@evil.example",
            "parentOrigin=https://admin.kortly.no%5C@evil.example",
            "parentOrigin=https://evil.example%00.kortly.no",
            "parentOrigin=https://a b.example",
            "parentOrigin=https://admin.kortly.no:",
            "parentOrigin=https://admin.kortly.no:0",
            "parentOrigin=https://admin.kortly.no:65536",
            "parentOrigin=https://admin.kortly.no:+80",
            "parentOrigin=https://[]",
            "parentOrigin=https://bl%C3%A5b%C3%A6r.no",
            "parentOrigin=https%3A%2F%2Fa%2",
            "parentOrigin=https%3A%2F%2Fa%zz",
            "parentOrigin=%FF",
            "parentorigin=https://admin.kortly.no",
            "xparentOrigin=https://admin.kortly.no",
        ] {
            assert_eq!(parent_origin(query), None, "{query:?}");
        }
    }

    #[test]
    fn a_parent_origin_named_twice_is_refused() {
        assert_eq!(parent_origin("parentOrigin=https://admin.kortly.no&parentOrigin=https://evil.example"), None);
        assert_eq!(parent_origin("parentOrigin=https://admin.kortly.no&parentOrigin=https://admin.kortly.no"), None);
    }

    #[test]
    fn only_listed_origins_are_allowed_exactly() {
        let list = "http://localhost:5432 https://admin.kortly.no";
        assert!(allowed(list, "http://localhost:5432"));
        assert!(allowed(list, "https://admin.kortly.no"));
        assert!(!allowed(list, "http://localhost:5433"));
        assert!(!allowed(list, "http://localhost"));
        assert!(!allowed(list, "https://localhost:5432"), "the scheme counts");
        assert!(!allowed(list, "https://evil.admin.kortly.no"));
        assert!(!allowed(list, "https://admin.kortly.no.evil.example"));
        assert!(!allowed(list, "https://admin.kortly.no/"));
        assert!(allowed("  https://admin.kortly.no\n\thttp://localhost:5432 ", "http://localhost:5432"), "any whitespace separates");
    }

    #[test]
    fn an_empty_or_wildcard_list_allows_nothing() {
        for origin in ["http://localhost:5432", "*", "null", ""] {
            assert!(!allowed("", origin), "{origin:?}");
            assert!(!allowed("   ", origin), "{origin:?}");
            assert!(!allowed("*", origin), "{origin:?}");
            assert!(!allowed("null", origin), "{origin:?}");
            assert!(!allowed("* null", origin), "{origin:?}");
        }
    }

    #[test]
    fn only_a_named_other_origin_leaves_the_same_origin_path() {
        let own = "https://cad.example";
        assert_eq!(cross_origin("host=parent", own), None, "no parentOrigin: today's same-origin path");
        assert_eq!(cross_origin("host=parent&parentOrigin=https%3A%2F%2Fcad.example", own), None, "the same origin named");
        assert_eq!(cross_origin("host=parent&parentOrigin=nonsense", own), None, "an invalid name is ignored");
        assert_eq!(cross_origin("host=parent&parentOrigin=https%3A%2F%2Fadmin.kortly.no", own).as_deref(), Some("https://admin.kortly.no"));
        // A sandboxed frame's own origin is "null"; a named parent is still another origin.
        assert_eq!(cross_origin("parentOrigin=https://admin.kortly.no", "null").as_deref(), Some("https://admin.kortly.no"));
    }
}
