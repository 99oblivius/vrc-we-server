# Contributing

Pull requests are welcome. Open an issue first for anything larger than a fix, so the change can be agreed before you write it.

## Contribution license

The software in this repository is offered under the [PolyForm Shield License 1.0.0 and an Additional Permission](LICENSE). The relay's wire crate is also built into the closed-source vrc-WiredExpressions client, so contributions need broader terms than the license gives back.

By submitting a contribution (a pull request, patch, or any other material) to this repository, you:

1. confirm that you wrote it, or otherwise have the right to submit it under these terms;
2. grant oblivius a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, reproduce, modify, distribute, sublicense and relicense your contribution, under any terms, including in proprietary software;
3. grant oblivius a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license under any patent claims you can license that your contribution would infringe, for the same uses.

You keep the copyright in your contribution.

## Checks

Every pull request must pass:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

A change to a dependency must also keep [`THIRD-PARTY-NOTICES.txt`](THIRD-PARTY-NOTICES.txt) current:

```bash
cargo about generate --locked about.hbs -o THIRD-PARTY-NOTICES.txt
```

A change to `ClientFrame` or `ServerFrame` bumps `WIRE_VERSION` in `crates/relay-wire`.

## Commit messages

`Area: what changed (why)`, several items joined with ` + `.
