# fuzz/ — libFuzzer harnesses for the network-facing parsers

Two targets, both fed by arbitrary client bytes in production:

| Target | Surface |
| ------ | ------- |
| `pkt_line` | `artifacts::pkt_line::read` — the 4-hex-char length-prefixed framing every smart-HTTP body is composed of. |
| `git_proto` | The three v2 / push parsers in `artifacts::git_wire::proto`: `parse_ls_refs_only`, `parse_v2_fetch`, `parse_receive_pack_body`. |

## Running

```sh
# Install once (nightly is required by libfuzzer-sys).
cargo +nightly install cargo-fuzz

# Time-boxed run against one target.
cargo +nightly fuzz run pkt_line  --max-total-time=60
cargo +nightly fuzz run git_proto --max-total-time=60

# Or open-ended until a crash is found:
cargo +nightly fuzz run pkt_line
```

A crash drops to `fuzz/artifacts/<target>/crash-*` with the offending
input bytes. Re-run a known input via:

```sh
cargo +nightly fuzz run pkt_line fuzz/artifacts/pkt_line/crash-xxxxxx
```

## CI

`.github/workflows/fuzz.yml` runs both targets nightly (UTC) for
five minutes each, and is also `workflow_dispatch` so an operator can
trigger an ad-hoc run from the GitHub UI. Failures upload the crash
reports as build artifacts.
