#!/bin/sh
# Official release bytes, with the same version/revision/checksum used by the Wasm gate.
set -eu
case "${1:-}" in
    amd64) target=x86_64-unknown-linux-gnu; digest=357bf712f6353c28cd33c794402a3c87231757a5b305e6ef1604365af4fdd556 ;;
    arm64) target=aarch64-unknown-linux-gnu; digest=a341adcc152e1865ea61d6c332e75b3d82b1f2f32108198fac97c50878b17034 ;;
    *) echo 'unsupported container architecture' >&2; exit 1 ;;
esac
version=27.0.0
revision=5a7c5fe76530bf4248477ac812fc757146b98cc4
workflow=.github/workflows/nightly-live.yml
test "$(sed -n 's/^  STELLAR_CLI_VERSION: //p' "$workflow")" = "$version"
test "$(sed -n 's/^  STELLAR_CLI_REVISION: //p' "$workflow")" = "$revision"
test "$(sed -n 's/^  STELLAR_CLI_SHA256: //p' "$workflow")" = 357bf712f6353c28cd33c794402a3c87231757a5b305e6ef1604365af4fdd556
test "$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" = 1.91.1
archive="/tmp/stellar-cli.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    "https://github.com/stellar/stellar-cli/releases/download/v${version}/stellar-cli-${version}-${target}.tar.gz" -o "$archive"
printf '%s  %s\n' "$digest" "$archive" | sha256sum --check --status
tar -xzf "$archive" -C /usr/local/bin stellar
rm "$archive"
stellar --version | grep -F "$version" >/dev/null
stellar --version | grep -F "$(printf '%s' "$revision" | cut -c1-7)" >/dev/null
