#!/usr/bin/env bash
# Resolve the MSRV graph before checking it with the original old compiler.
set -euo pipefail

export CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback
cargo +stable update
# Quinn's published lower bounds avoid transitive crates with incomplete MSRV metadata.
cargo +stable update -p quinn --precise 0.11.7
cargo +stable update -p quinn-proto --precise 0.11.10
