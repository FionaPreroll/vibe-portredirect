# Fuzzing

The fuzz targets feed random input to the parsers of the protocol (see [docs/PROTOCOL.md](../docs/PROTOCOL.md)): everything a peer can send before or during authentication, the control messages and the header of each data stream.
They run with [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer.

| Target | Input | Checks beyond not crashing |
|---|---|---|
| `server_authentication` | The client's messages, as the server receives them | The server never accepts a client: the input can't hold a valid proof, as the server's challenge is random. |
| `client_authentication` | The server's messages, as the client receives them | The client never accepts a server: the input can't hold a valid proof without the PSK. |
| `hello` | HELLO, as the server receives it | A client that sends what the server understood sends the same. |
| `welcome` | WELCOME, as the client receives it | A server that sends what the client understood sends the same. |
| `control_messages` | Messages on the control stream | Both ways of reading messages agree. The server's control loop answers each PING up to the first message it doesn't expect, and stops there. |
| `connection_header` | The header of a data stream, as the client receives it | A server that sends the address the client understood sends the same. |
| `parameters` | The parameters of a message or a header | Decoding their encoding gives the same parameters. |

The first byte of the input sets how many bytes each read returns, so the parsers also get their input in parts; `parameters` decodes the whole input at once.

## Running

The fuzz targets need a nightly toolchain and cargo-fuzz:

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

Run each target for a minute, or for longer with `FUZZ_SECONDS`:

```sh
make fuzz
make fuzz FUZZ_SECONDS=600
```

Or run a single target until you stop it:

```sh
cd fuzz
cargo +nightly fuzz run hello -- -dict=portredirect.dict
```

[`portredirect.dict`](portredirect.dict) holds tokens of the protocol, e.g. the headers of the authentication messages, which help libFuzzer find valid input.
The inputs it found go to `corpus/<target>`, and are used again in the next run.

## When a Target Fails

libFuzzer saves the input that made the target fail in `artifacts/<target>/`, and prints the command that runs the target with it again:

```sh
cargo +nightly fuzz run hello artifacts/hello/crash-<hash>
```

`cargo +nightly fuzz tmin hello artifacts/hello/crash-<hash>` shortens the input. Once the bug is fixed, add the input to the smoke test of the target in `src/fuzz.rs`, so it stays fixed.

## How It Works

- The parsers are private to the crate. The functions the targets call are in [`src/fuzz.rs`](../src/fuzz.rs), which is compiled with `--cfg fuzzing`, which cargo fuzz sets, and for the tests.
- `cargo test` runs each of these functions on changed copies of valid input, as a smoke test that needs neither nightly nor cargo-fuzz.
- The fuzz crate has a workspace and a `Cargo.lock` of its own, so the main crate's `Cargo.lock` stays free of fuzzing dependencies.
- CI ([`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml)) runs each target for 30 seconds on pull requests and for 15 minutes once a week. It can also be started by hand, with the time per target. If a target fails, the input is uploaded as the artifact `fuzz-artifacts`.

## Adding a Target

1. Add a function to `src/fuzz.rs` that feeds its input to the parser and checks what it can, with a smoke test.
2. Add `fuzz_targets/<target>.rs`, which calls it, like the others.
3. Add a `[[bin]]` section for it to `Cargo.toml`.
