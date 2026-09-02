use super::{redact_url, REDACTED_URL_PLACEHOLDER};

#[test]
fn redact_url_keeps_only_scheme_host_and_port() {
    let redacted =
        redact_url("https://user:pw@rpc.example.com:8545/v0_9/abc123?apikey=SECRET#frag");
    assert_eq!(redacted, "https://rpc.example.com:8545");
    for leaked in ["SECRET", "abc123", "user", "pw", "frag", "v0_9"] {
        assert!(!redacted.contains(leaked), "leaked {leaked:?}");
    }
}

#[test]
fn redact_url_handles_bare_hosts_and_ipv6_literals() {
    assert_eq!(
        redact_url("https://rpc.example.com"),
        "https://rpc.example.com"
    );
    assert_eq!(
        redact_url("http://[::1]:5050/rpc/v0_7?x=1"),
        "http://[::1]:5050"
    );
    assert_eq!(
        redact_url("http://127.0.0.1:5050#frag"),
        "http://127.0.0.1:5050"
    );
}

#[test]
fn redact_url_never_echoes_unparseable_input() {
    for input in [
        "",
        "not a url",
        "https://",
        "://host",
        "https://@/path?apikey=SECRET",
    ] {
        assert_eq!(
            redact_url(input),
            REDACTED_URL_PLACEHOLDER,
            "input {input:?}"
        );
    }
}

/// Codex review: malformed inputs that still contain `://` must not echo
/// credential-shaped text as if it were a scheme or host.
#[test]
fn redact_url_rejects_credential_shaped_scheme_or_host() {
    for leaky in [
        "apikey=SECRET://host/path",
        "https://user:SECRET/path",
        "https://user:SECRET@/path",
        "https://ho st/path",
        "https://[::1/path",
        "https://[deadbeef]/rpc",
        "https://[SECRET]:443/rpc",
        "https://[::1]x/path",
        "https://host:notaport/path",
        "https://host:98765/rpc",
        "https://host:+443/rpc",
        "https://host:/rpc",
        "://host",
    ] {
        let out = redact_url(leaky);
        assert_eq!(out, REDACTED_URL_PLACEHOLDER, "{leaky}");
        assert!(!out.contains("SECRET"), "{leaky}");
    }
}

#[test]
fn redact_url_keeps_valid_authorities() {
    assert_eq!(
        redact_url("http://[::1]:8545/v0_9/KEY"),
        "http://[::1]:8545"
    );
    assert_eq!(redact_url("http://[::1]/v0_9/KEY"), "http://[::1]");
    assert_eq!(redact_url("https://host:65535/x"), "https://host:65535");
    assert_eq!(
        redact_url("https://[2001:db8::1]:443/v0_9/KEY"),
        "https://[2001:db8::1]:443"
    );
    assert_eq!(
        redact_url("https://rpc.example.com/v0_9/KEY?k=v"),
        "https://rpc.example.com"
    );
    assert_eq!(
        redact_url("https://10.0.0.1:5050/x"),
        "https://10.0.0.1:5050"
    );
    assert_eq!(redact_url("svc+tls://a-b.c/x"), "svc+tls://a-b.c");
}
