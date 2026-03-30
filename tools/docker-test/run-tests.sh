#!/usr/bin/env bash
# tools/docker-test/run-tests.sh
#
# mapeced 特権統合テストを Docker コンテナ内で実行するスクリプト。
#
# 用途:
#   root に Rust がインストールされていない環境で、
#   CAP_NET_ADMIN を必要とする統合テストを実行する。
#
# 使い方:
#   ./tools/docker-test/run-tests.sh [オプション] [テスト名...]
#
# オプション:
#   -b, --build     イメージを強制再ビルドする
#   -h, --help      このヘルプを表示する
#
# テスト名（省略時はすべて実行）:
#   netlink    Phase 2: Netlink 統合テスト
#   nftables   Phase 3: nftables / tc 統合テスト
#   lifecycle  Phase 4: ライフサイクル統合テスト
#   all        上記すべて（デフォルト）
#   unit       ユニットテストと非特権統合テスト（cargo test）
#
# 例:
#   ./tools/docker-test/run-tests.sh
#   ./tools/docker-test/run-tests.sh --build netlink
#   ./tools/docker-test/run-tests.sh lifecycle

set -euo pipefail

# ── 定数 ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_NAME="mapeced-test"
CONTAINER_NAME="mapeced-test-run"

# Cargo キャッシュをホストと共有して再ビルドを避ける
CARGO_CACHE_VOLUME="mapeced-cargo-cache"

# ── 引数パース ────────────────────────────────────────────────────────────────

FORCE_BUILD=0
TESTS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--build)
            FORCE_BUILD=1
            shift
            ;;
        -h|--help)
            sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        netlink|nftables|lifecycle|all|unit)
            TESTS+=("$1")
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

# デフォルトはすべての統合テスト
if [[ ${#TESTS[@]} -eq 0 ]]; then
    TESTS=("all")
fi

# ── Docker イメージビルド ─────────────────────────────────────────────────────

need_build() {
    [[ "$FORCE_BUILD" -eq 1 ]] || ! docker image inspect "${IMAGE_NAME}" &>/dev/null
}

if need_build; then
    echo "==> Building Docker image: ${IMAGE_NAME}"
    docker build \
        --tag "${IMAGE_NAME}" \
        --file "${SCRIPT_DIR}/Dockerfile" \
        "${SCRIPT_DIR}"
else
    echo "==> Using existing Docker image: ${IMAGE_NAME} (use -b to rebuild)"
fi

# ── テストコマンド組み立て ────────────────────────────────────────────────────

build_test_cmd() {
    local tests=("$@")
    local cmds=()

    for t in "${tests[@]}"; do
        case "$t" in
            unit)
                cmds+=("cargo test")
                ;;
            netlink)
                cmds+=("cargo test --test netlink -- --test-threads=1")
                ;;
            nftables)
                cmds+=("cargo test --test nftables -- --test-threads=1")
                ;;
            lifecycle)
                cmds+=("cargo test --test lifecycle -- --test-threads=1")
                ;;
            all)
                cmds+=("cargo test")
                cmds+=("cargo test --test netlink  -- --test-threads=1")
                cmds+=("cargo test --test nftables -- --test-threads=1")
                cmds+=("cargo test --test lifecycle -- --test-threads=1")
                ;;
        esac
    done

    # 重複排除しつつ順序を保つ
    local seen=()
    local unique=()
    for cmd in "${cmds[@]}"; do
        local dup=0
        for s in "${seen[@]+"${seen[@]}"}"; do
            [[ "$s" == "$cmd" ]] && dup=1 && break
        done
        if [[ "$dup" -eq 0 ]]; then
            unique+=("$cmd")
            seen+=("$cmd")
        fi
    done

    # 各コマンドを && で連結
    local joined=""
    for cmd in "${unique[@]}"; do
        [[ -n "$joined" ]] && joined+=" && "
        joined+="$cmd"
    done
    echo "$joined"
}

TEST_CMD="$(build_test_cmd "${TESTS[@]}")"

# ── コンテナ実行 ──────────────────────────────────────────────────────────────

echo "==> Running tests in Docker container"
echo "    Tests : ${TESTS[*]}"
echo "    Cmd   : ${TEST_CMD}"
echo ""

# 古いコンテナを削除
docker rm -f "${CONTAINER_NAME}" &>/dev/null || true

# Cargo キャッシュボリュームを作成（初回のみ）
docker volume create "${CARGO_CACHE_VOLUME}" &>/dev/null

docker run \
    --rm \
    --name "${CONTAINER_NAME}" \
    --privileged \
    --volume "${REPO_ROOT}:/workspace:ro" \
    --volume "${CARGO_CACHE_VOLUME}:/usr/local/cargo/registry" \
    --tmpfs /workspace/target:exec,size=4g \
    --workdir /workspace \
    "${IMAGE_NAME}" \
    bash -c "${TEST_CMD}"

echo ""
echo "==> Tests completed successfully"
