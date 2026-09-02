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
