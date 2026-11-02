#!/usr/bin/env bash
while read -r pkg name; do
  cargo clippy -p "$pkg" --example "$name" -- -D warnings
done
