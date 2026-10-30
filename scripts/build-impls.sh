#!/usr/bin/env bash
# Build every implementation under test at a pinned commit into $AWG_BIN.
set -euo pipefail
AWG_BIN=${AWG_BIN:-/opt/awg/bin}
SRC=${SRC:-/tmp/awg-src}
mkdir -p "$AWG_BIN" "$SRC"

fetch() { # url sha dir
  if [ ! -d "$SRC/$3/.git" ]; then git init -q "$SRC/$3"; git -C "$SRC/$3" remote add origin "$1"; fi
  git -C "$SRC/$3" fetch -q --depth 1 origin "$2"
  git -C "$SRC/$3" checkout -q FETCH_HEAD
}

fetch https://github.com/amnezia-vpn/amneziawg-go b5928efb6ca19f0153958460c3d141f04abc5c2e amneziawg-go
fetch https://github.com/hoaxisr/amneziawg-go     ad2b1d906df4e4e0c405c5490addc7c984bc878d amnezia-box-go
fetch https://github.com/AYastrebov/awgtun        738ce7e26b520dd621571e913a53bdc9795fc2f5 awgtun
fetch https://github.com/okhsunrog/gotatun        cc2597ff84734f2f49378cd40403f50574261d75 gotatun

(cd "$SRC/amneziawg-go"   && go build -o "$AWG_BIN/awg-go-official" .)
(cd "$SRC/amnezia-box-go" && go build -o "$AWG_BIN/awg-go-hoaxisr" .)
(cd "$SRC/awgtun"         && cargo build --release -q -p awgtun-cli && cp target/release/awgtun-cli "$AWG_BIN/")
(cd "$SRC/gotatun"        && cargo build --release -q -p gotatun-cli && cp target/release/gotatun "$AWG_BIN/")
ls -la "$AWG_BIN"
