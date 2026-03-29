# v6プラス 技術仕様

## 概要

v6プラスは、JPIX（株式会社日本インターネットエクスチェンジ）が提供する MAP-E（RFC 7597）ベースの IPv4 over IPv6 サービスである。
複数の ISP が v6プラスを採用しており、本ドキュメントでは初期実装ターゲットとしての仕様を整理する。

---

## MAP-E パラメータ（v6プラス固有値）

| パラメータ                       | 値        | 説明                                 |
| -------------------------------- | --------- | ------------------------------------ |
| PSID offset (a)                  | 4         | ポートセット先頭のオフセットビット数 |
| PSID length (k)                  | 8         | PSID のビット長                      |
| 1 アドレスあたりの共有ユーザー数 | 2^k = 256 | PSID 値の数                          |
| ユーザーあたり利用可能ポート数   | 240       | 後述の計算参照                       |

> v6プラスでは MAP Rule（BMR: Basic Mapping Rule）の IPv4/IPv6 プレフィックスおよび BR の IPv6 アドレスは、
> DHCPv6 の `OPTION_S46_CONT_MAPE`（code 94）では配布されない。
> 代わりに JPIX が事前に通告した専用サーバーから HTTP で取得する方式が採用されているが、
> このサーバーへのアクセスには別途契約が必要である。
> そのため、v6プラス用の MAP ルールはインターネット上の公開情報を元にアプリケーションに静的に埋め込むのが現実的である。

---

## MAP ルールの取得方式

### v6プラスにおける MAP ルール配布方式

v6プラスでは RFC 7598 で定義された DHCPv6 オプション（`OPTION_S46_CONT_MAPE`、code 94）による MAP ルール配布は行われない。
JPIX が運営する専用サーバーから HTTP で取得する方式が採用されているが、このサーバーへのアクセスには別途契約が必要である。

そのため、本実装では インターネット上の公開情報に基づき MAP ルールをアプリケーションに静的に埋め込む方針とする。

### 静的埋め込みが必要な情報

| 項目                             | 説明                           |
| -------------------------------- | ------------------------------ |
| IPv4 プレフィックス（prefix4）   | MAP ルールの IPv4 アドレス範囲 |
| IPv6 プレフィックス（rule_ipv6） | MAP ルールの IPv6 アドレス範囲 |
| EA-bits 長（ea-len）             | 埋め込みアドレスビット長       |
| BR の IPv6 アドレス              | ボーダーリレーのエンドポイント |

### 参考：RFC 7598 DHCPv6 オプション構造

他の MAP-E サービスでは RFC 7598 に従い DHCPv6 で MAP ルールを配布する場合がある。その構造を参考として示す。

```
OPTION_S46_CONT_MAPE (code 94)          ← MAP-E コンテナ
  └─ OPTION_S46_RULE (code 89)          ← BMR（Basic Mapping Rule）
       ├─ flags           (1 byte)       ← bit0: FMR フラグ
       ├─ ea-len          (1 byte)       ← EA-bits 長（ビット数）
       ├─ prefix4-len     (1 byte)       ← IPv4 プレフィックス長
       ├─ ipv4-prefix     (4 bytes)      ← IPv4 プレフィックス
       ├─ ipv6-prefix-len (1 byte)       ← IPv6 プレフィックス長
       ├─ ipv6-prefix     (可変長)       ← IPv6 プレフィックス
       └─ OPTION_S46_PORTPARAMS (code 93)
            ├─ offset     (4 bits)       ← PSID offset a = 4
            ├─ psid-len   (4 bits)       ← PSID length k = 8
            └─ psid       (2 bytes)      ← この CE の PSID 値
  └─ OPTION_S46_BR (code 90)            ← BR の IPv6 アドレス（16 bytes）
```

- **ea-len**: EA-bits（Embedded Address bits）の長さ。IPv4 サフィックスと PSID の合計ビット数
- **PSID offset (a)**: 使用禁止ポート範囲の幅を `2^(a+k)` で定義する。a=4 の場合、R=0 のポート範囲（0〜4095）は使用禁止
- **PSID length (k)**: PSID のビット数。k=8 で 256 ユーザーが 1 つの IPv4 アドレスを共有
- **PSID**: この CE（Customer Edge）に割り当てられた Port Set ID

---

## IPv6 アドレスからのパラメータ導出

### EA-bits の抽出

IA_PD で委任された IPv6 プレフィックス（CE prefix）から EA-bits を抽出する。

```
CE IPv6 prefix:  [  MAP Rule IPv6 prefix  ][    EA-bits    ][ ... ]
                 |<---- rule-prefix-len --->|<-- ea-len --->|
```

**手順:**

1. DHCPv6 IA_PD で委任されたプレフィックス（例: `/48`）を取得する
2. MAP Rule の IPv6 プレフィックス長（rule-prefix-len）に続く ea-len ビットを抽出する
   ```
   ea_bits = (ce_prefix >> (prefix_len - rule_prefix_len - ea_len)) & ((1 << ea_len) - 1)
   ```

### IPv4 アドレスの導出

```
ipv4_suffix_len = 32 - prefix4_len
psid_bits       = ea_len - ipv4_suffix_len

ipv4_suffix = ea_bits >> psid_bits        ← EA-bits の上位ビット
psid        = ea_bits & ((1 << psid_bits) - 1)  ← EA-bits の下位ビット（= k ビット）

ipv4_addr   = ipv4_prefix | ipv4_suffix
```

> `psid_bits` は PSID length k と一致する。

### CE の IPv6 アドレスの構成

#### RFC 7597 Section 5.2 の定義

インターフェース識別子（下位 64 ビット）のレイアウト:

```
 63      48 47     16 15      0
+----------+----------+--------+
|    0x00  | IPv4 addr|  PSID  |
| (16 bits)| (32 bits)|(16 bits)|
+----------+----------+--------+
```

アドレス全体:

```
[  MAP Rule IPv6 prefix  ][ EA-bits ][ 0x0000 ][ IPv4 addr ][ PSID ]
 <-- rule_prefix_len ---->           <-16 pad-> <-- 32 --> <-- 16 -->
```

#### v6プラスの実装（[Internet Draft](https://datatracker.ietf.org/doc/html/draft-ietf-softwire-map-03#section-6) 準拠）

v6プラスではインターフェース識別子のレイアウトが RFC 7597 と異なる。
先頭パディングが 16 ビットではなく **8 ビット** となり、末尾に **8 ビット** のパディングが追加される。

```
 63   56 55     24 23      8 7     0
+-------+----------+--------+-------+
|  0x00 | IPv4 addr|  PSID  |  0x00 |
|(8bits)| (32 bits)|(16 bits)|(8bits)|
+-------+----------+--------+-------+
```

アドレス全体:

```
[  MAP Rule IPv6 prefix  ][ EA-bits ][ 0x00 ][ IPv4 addr ][ PSID ][ 0x00 ]
 <-- rule_prefix_len ---->           <-8pad-> <-- 32 --> <-- 16 --> <-8pad->
```

具体的な実装:

```
ce_ipv6 = rule_ipv6_prefix
ce_ipv6[rule_prefix_len : rule_prefix_len+ea_len] = ea_bits
ce_ipv6[128-56 : 128-24]                           = ipv4_addr   (32 bits)
ce_ipv6[128-24 : 128-8 ]                           = psid << (16 - k)
# ce_ipv6[128-8 : 128] は 0x00 (暗黙の 0 埋め)
```

> RFC 7597 では `ce_ipv6[128-48 : 128-16] = ipv4_addr` だが、
> v6プラスでは先頭パディングが 8 ビット短いため `128-56` から始まる点が異なる。

---

## ポートセットの計算（RFC 7597 Section 5.1）

PSID と offset、length から利用可能なポート番号集合を計算する。

### パラメータ

| 記号           | 値（v6プラス） | 説明                               |
| -------------- | -------------- | ---------------------------------- |
| a              | 4              | PSID offset                        |
| k              | 8              | PSID length                        |
| m = 2^a        | 16             | ポートインデックスの範囲           |
| N = 2^(16-a-k) | 16             | R の最大値 + 1（ポートブロック数） |

### ポート番号の算出式

```
Port(R, j) = R * 2^(a+k) + PSID * 2^a + j

ただし:
  R ∈ [1, N-1]  = [1, 15]    （R=0 は禁止ポート範囲）
  j ∈ [0, m-1]  = [0, 15]
```

### ポートセット例（PSID=5 の場合）

```
R=1:  1 * 4096 + 5 * 16 + [0..15] = 4176 〜 4191
R=2:  2 * 4096 + 5 * 16 + [0..15] = 8272 〜 8287
...
R=15: 15 * 4096 + 5 * 16 + [0..15] = 61536 〜 61551
```

合計: 15 範囲 × 16 ポート = **240 ポート / ユーザー**

### 禁止ポート範囲

R=0 に該当するポート（0〜4095）は使用禁止。ウェルノウンポート（0〜1023）を含む。

---

## nftables による NAPT 設定

MAP-E では PSID に属さないポートからの送出を禁止する必要がある。

### ポートマスクを使った判定

v6プラスの場合（a=4, k=8）、ポート番号の構造は以下の通り:

```
Port [15:12] = R     (4 bits)
Port [11:4]  = PSID  (8 bits)
Port [3:0]   = j     (4 bits)
```

あるポート `p` が自分の PSID に属するかの判定:

```
(p >> 4) & 0xFF == PSID  AND  (p >> 12) != 0
```

---

## トンネル設定

### インターフェースタイプ

`ip6tnl` タイプのトンネルを使用する（Linux kernel の `ip6_tunnel` モジュール）。

```bash
# 相当する ip コマンド（実装では Netlink を直接使用）
ip tunnel add mape0 mode ip4ip6 \
  local <CE_IPv6_addr> \
  remote <BR_IPv6_addr> \
  dev <wan_iface>
ip link set mape0 up
ip addr add <CE_IPv4_addr>/32 dev mape0
ip route add default dev mape0
```

### MTU

MAP-E では IPv6 カプセル化により MTU が減少する。

| 項目                           | 値         |
| ------------------------------ | ---------- |
| IPv6 ヘッダーオーバーヘッド    | 40 bytes   |
| 推奨 MTU（WAN が 1500 の場合） | 1460 bytes |

MSS クランプも併せて設定することが望ましい。

---

## 実装上の考慮事項

### MAP ルールの管理

v6プラスの MAP ルールはアプリケーションに静的に埋め込まれている。
IA_PD で委任された IPv6 プレフィックスが取得できれば、埋め込みルールを用いてすべてのパラメータを計算できる。

- mapecd は `/run/systemd/netif/leases/<ifindex>` の変化を監視して IA_PD プレフィックスの更新を検知する
- MAP ルール自体の変更は実装のアップデートとして扱う

### リース更新時の挙動

| 変化                     | 対応                                   |
| ------------------------ | -------------------------------------- |
| IA_PD プレフィックス変化 | 全パラメータ再計算・全設定更新         |
| MAP Rule 変化            | 実装アップデートとして扱う             |
| BR アドレス変化          | トンネルリモートエンドポイントのみ更新 |
| PSID 変化                | ポートセット・nftables ルール更新      |
| 変化なし                 | 何もしない                             |

### systemd-networkd との競合回避

- mapecd は IA_PD の取得を systemd-networkd に委ねる
- DHCPv6 クライアントポート（UDP 546）を直接使用しないため、競合は発生しない

---

## 関連仕様・参考資料

- [RFC 7597](https://www.rfc-editor.org/rfc/rfc7597) — MAP-E アーキテクチャとアドレスマッピングルール
- [RFC 7598](https://www.rfc-editor.org/rfc/rfc7598) — DHCPv6 Options for MAP-E (`OPTION_S46_CONT_MAPE`)
- [RFC 7599](https://www.rfc-editor.org/rfc/rfc7599) — MAP-E アドレスマッピングルール詳細
- [v6プラス サービス](https://www.v6plus.jp/) — JPIX 公式サービスページ
