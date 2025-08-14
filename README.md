# rustpass

ローカル完結型のパスワード管理 CLI ツール。  
保存データは **Argon2id + ChaCha20-Poly1305** により暗号化され、ディスク上には平文が残りません。  
マスターパスワードを入力することで暗号化された金庫（Vault）を復号し、エントリの追加・取得・一覧表示・パスワード生成が可能です。

---

## 🔒 主な特徴
- **ローカル完結**：クラウド送信なし
- **強固な暗号化**：
  - KDF: Argon2id（メモリ負荷・反復回数調整可能）
  - 暗号化: ChaCha20-Poly1305 (AEAD)
- **マルチプラットフォーム対応**（Linux / macOS / Windows）
- **ランダムパスワード生成機能**搭載
- JSON構造で保存（暗号化されているため中身は不可視）

---

## 📦 インストール

Rustがインストールされていない場合は、まず [Rust公式サイト](https://www.rust-lang.org/) の手順で導入してください。

```bash
git clone https://github.com/ishii-kanade/rustpass.git
cd rustpass
cargo build --release
````

実行ファイルは `target/release/rustpass` に生成されます。

---

## 📂 保存場所

| OS      | パス                                                 |
| ------- | -------------------------------------------------- |
| Linux   | `~/.local/share/rustpass/vault.bin`                |
| macOS   | `~/Library/Application Support/rustpass/vault.bin` |
| Windows | `%LOCALAPPDATA%\rustpass\vault.bin`                |

---

## 🚀 使い方

### 1. 金庫作成

```bash
cargo run -- new
```

新しい空の金庫を作成します（すでに存在する場合はエラー）。

---

### 2. エントリ追加

```bash
cargo run -- add <名前> [-u <ユーザー名>] [--gen] [--len <長さ>] [--symbols] [--allow-ambiguous]
```

* `<名前>`：エントリの識別名（例：サービス名やサイト名）
* `-u, --user`：ユーザー名（省略すると入力待ち）
* `--gen`：パスワードを自動生成
* `--len`：生成パスワードの長さ（デフォルト20）
* `--symbols`：記号を含める
* `--allow-ambiguous`：紛らわしい文字（0/O/o/1/l/I/| など）も許可

**例:**

```bash
# 手入力で追加
cargo run -- add github -u alice

# 自動生成で追加（28文字・記号あり）
cargo run -- add github -u alice --gen --len 28 --symbols
```

---

### 3. 一覧表示

```bash
cargo run -- list
```

保存されているエントリ一覧を表示します。

---

### 4. エントリ取得

```bash
cargo run -- get <名前> [--show]
```

* `--show` を付けるとパスワードも表示（自己責任）。

**例:**

```bash
cargo run -- get github
cargo run -- get github --show
```

---

### 5. ランダムパスワード生成のみ

```bash
cargo run -- gen [--len <長さ>] [--symbols] [--allow-ambiguous]
```

保存はせず、生成結果を表示します。

**例:**

```bash
cargo run -- gen --len 32 --symbols
```

---

## 🛡 セキュリティ上の注意

* 金庫ファイルは必ず権限を制限してください（例：`chmod 600`）。
* クリップボードコピー機能は未実装。必要なら手動で貼り付け後に速やかに削除してください。
* キーロガーや実行中メモリの覗き見は防げません。OSレベルのセキュリティ対策も行ってください。
