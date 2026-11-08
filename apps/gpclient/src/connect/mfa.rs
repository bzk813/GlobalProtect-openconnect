//! Non-interactive answers to gateway MFA challenges (`--mfa-on-stdin`).
//!
//! For every challenge one JSON line is written to stdout:
//!
//! ```json
//! {"event":"mfa_challenge","message":"Enter the OTP code:","attempt":1}
//! ```
//!
//! and the answer is read as the next line of stdin. This keeps secrets (an
//! authenticator seed, a keyring) on the caller's side: gpclient usually runs
//! as root, the caller does not.

use std::io::{BufRead, Write};

use anyhow::{Context, bail};

/// Stop after this many challenges so a wrong answer cannot loop until the
/// account is locked.
pub(super) const MAX_MFA_ATTEMPTS: u32 = 5;

pub(super) fn challenge_event(message: &str, attempt: u32) -> String {
  serde_json::json!({ "event": "mfa_challenge", "message": message, "attempt": attempt }).to_string()
}

pub(super) fn answer_challenge<R: BufRead, W: Write>(
  input: &mut R,
  output: &mut W,
  message: &str,
  attempt: u32,
) -> anyhow::Result<String> {
  if attempt > MAX_MFA_ATTEMPTS {
    bail!("Gateway MFA challenge repeated {MAX_MFA_ATTEMPTS} times, giving up");
  }
  writeln!(output, "{}", challenge_event(message, attempt))?;
  output.flush()?;

  let mut line = String::new();
  let read = input.read_line(&mut line).context("Failed to read the MFA answer from standard input")?;
  if read == 0 {
    bail!("Standard input closed while waiting for the MFA answer");
  }
  Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn emits_one_json_event_and_reads_one_line() {
    let mut input = "123456\nnext\n".as_bytes();
    let mut output = Vec::new();
    let answer = answer_challenge(&mut input, &mut output, "Enter \"OTP\":", 1).unwrap();
    assert_eq!(answer, "123456");
    assert_eq!(input, b"next\n");

    let out = String::from_utf8(output).unwrap();
    assert_eq!(out.lines().count(), 1);
    let v: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(v["event"], "mfa_challenge");
    assert_eq!(v["message"], "Enter \"OTP\":");
    assert_eq!(v["attempt"], 1);
  }

  #[test]
  fn strips_crlf() {
    let mut input = "1\r\n".as_bytes();
    assert_eq!(answer_challenge(&mut input, &mut Vec::new(), "m", 1).unwrap(), "1");
  }

  #[test]
  fn fails_on_eof() {
    let err = answer_challenge(&mut "".as_bytes(), &mut Vec::new(), "m", 1).unwrap_err();
    assert!(err.to_string().contains("closed"), "{err}");
  }

  #[test]
  fn gives_up_after_max_attempts() {
    let mut output = Vec::new();
    let err = answer_challenge(&mut "x\n".as_bytes(), &mut output, "m", MAX_MFA_ATTEMPTS + 1).unwrap_err();
    assert!(err.to_string().contains("giving up"), "{err}");
    assert!(output.is_empty(), "no event once we gave up");
  }
}
