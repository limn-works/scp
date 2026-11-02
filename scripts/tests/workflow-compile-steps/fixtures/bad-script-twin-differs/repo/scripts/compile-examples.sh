#!/usr/bin/env bash
while read -r pkg name; do
  cargo check -p "$pkg" --example "$name"
done
