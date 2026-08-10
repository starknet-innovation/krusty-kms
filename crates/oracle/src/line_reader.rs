//! Bounded newline-delimited line reading for the stdio transport.

use tokio::io::AsyncBufReadExt;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub(crate) enum LimitedLine {
    Complete(String),
    TooLong,
    InvalidUtf8,
}

/// Read one newline-delimited line without exceeding `max_bytes` of payload.
///
/// On overflow, discards input through the next newline (or EOF) and returns
/// [`LimitedLine::TooLong`] without retaining the oversized body.
/// Non-UTF-8 payloads are rejected as [`LimitedLine::InvalidUtf8`] (no lossy
/// substitution that could mutate JSON/secret IDs).
pub(crate) async fn read_line_limited<R>(
    reader: &mut R,
    max_bytes: usize,
) -> std::io::Result<Option<LimitedLine>>
where
    R: AsyncBufReadExt + Unpin,
{
    let mut buf = Vec::new();
    let mut discarded = false;

    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if buf.is_empty() && !discarded {
                return Ok(None);
            }
            if discarded {
                return Ok(Some(LimitedLine::TooLong));
            }
            return Ok(Some(decode_line_utf8(buf)));
        }

        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if !discarded {
                let chunk = &available[..pos];
                if buf.len().saturating_add(chunk.len()) > max_bytes {
                    discarded = true;
                } else {
                    buf.extend_from_slice(chunk);
                }
            }
            reader.consume(pos + 1);
            if discarded {
                return Ok(Some(LimitedLine::TooLong));
            }
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(Some(decode_line_utf8(buf)));
        }

        // No newline in this buffer fill.
        if discarded {
            let n = available.len();
            reader.consume(n);
            continue;
        }

        if buf.len().saturating_add(available.len()) > max_bytes {
            discarded = true;
            let n = available.len();
            reader.consume(n);
            continue;
        }

        buf.extend_from_slice(available);
        let n = available.len();
        reader.consume(n);
    }
}

fn decode_line_utf8(buf: Vec<u8>) -> LimitedLine {
    match String::from_utf8(buf) {
        Ok(s) => LimitedLine::Complete(s),
        Err(_) => LimitedLine::InvalidUtf8,
    }
}
