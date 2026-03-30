# mapeced 特権統合テスト用 Docker イメージ
#
# ビルド・実行は tools/docker-test/run-tests.sh を使用すること。
#
# 必要な権限:
#   --privileged または --cap-add NET_ADMIN --cap-add SYS_ADMIN

FROM ubuntu:24.04

# ── システムパッケージ ────────────────────────────────────────────────────────

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    # ネットワーク操作ツール
    iproute2 \
    nftables \
    # ビルド依存
    build-essential \
    pkg-config \
    libssl-dev \
    # Rust インストール用
    curl \
    ca-certificates \
    # デバッグ用
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# ── Rust インストール ─────────────────────────────────────────────────────────

ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --no-modify-path --profile minimal --default-toolchain stable \
    && rustup --version \
    && cargo --version \
    && rustc --version

# ── 作業ディレクトリ ──────────────────────────────────────────────────────────

WORKDIR /workspace

# ── デフォルトコマンド ────────────────────────────────────────────────────────
# run-tests.sh からオーバーライドされる

CMD ["bash"]
