use super::*;
use tokio::io::{duplex, BufReader};

#[tokio::test]
async fn read_line_limited_accepts_exact_limit_line() {
    let payload = "a".repeat(16);
    let input = format!("{payload}\n");
    let mut reader = BufReader::new(input.as_bytes());
    match read_line_limited(&mut reader, 16).await.unwrap() {
        Some(LimitedLine::Complete(line)) => assert_eq!(line, payload),
        other => panic!("unexpected result: {other:?}"),
    }
}

#[tokio::test]
async fn read_line_limited_rejects_oversized_split_chunks_and_resyncs() {
    let (client, server) = duplex(64);
    let mut writer = client;
    let mut reader = BufReader::new(server);

    // Write an oversized line in small chunks, then a valid follow-up request.
    let oversized = format!("{}\n", "x".repeat(40));
    let follow_up = "{\"ok\":true}\n";
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        for chunk in oversized.as_bytes().chunks(7) {
            writer.write_all(chunk).await.unwrap();
            writer.flush().await.unwrap();
            tokio::task::yield_now().await;
        }
        writer.write_all(follow_up.as_bytes()).await.unwrap();
        writer.flush().await.unwrap();
    });

    match read_line_limited(&mut reader, 16).await.unwrap() {
        Some(LimitedLine::TooLong) => {}
        other => panic!("expected TooLong, got {other:?}"),
    }
    match read_line_limited(&mut reader, 16).await.unwrap() {
        Some(LimitedLine::Complete(line)) => assert_eq!(line, "{\"ok\":true}"),
        other => panic!("expected resync Complete, got {other:?}"),
    }
}

#[tokio::test]
async fn read_line_limited_eof_during_discard_returns_too_long() {
    let input = "y".repeat(20); // no trailing newline
    let mut reader = BufReader::new(input.as_bytes());
    match read_line_limited(&mut reader, 8).await.unwrap() {
        Some(LimitedLine::TooLong) => {}
        other => panic!("expected TooLong on EOF during discard, got {other:?}"),
    }
}

#[tokio::test]
async fn read_line_limited_strips_crlf() {
    let mut reader = BufReader::new(&b"hello\r\n"[..]);
    match read_line_limited(&mut reader, 64).await.unwrap() {
        Some(LimitedLine::Complete(line)) => assert_eq!(line, "hello"),
        other => panic!("unexpected result: {other:?}"),
    }
}

#[tokio::test]
async fn read_line_limited_rejects_invalid_utf8() {
    let mut reader = BufReader::new(&[0xff, 0xfe, b'\n'][..]);
    match read_line_limited(&mut reader, 64).await.unwrap() {
        Some(LimitedLine::InvalidUtf8) => {}
        other => panic!("expected InvalidUtf8, got {other:?}"),
    }
}
