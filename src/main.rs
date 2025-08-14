use anyhow::{anyhow, Result};
use argon2::{Argon2, Algorithm, Params, Version};
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};
use clap::{Parser, Subcommand};
use rand::{rngs::OsRng, Rng};
use rand::seq::SliceRandom;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf, io::{self, Write}};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroize;

const MAGIC: &[u8] = b"RPSS";
const VERSION: u8 = 1;

#[derive(Parser)]
#[command(name="rustpass", about="Local-only password vault (Rust)")]
struct Cli {
    #[command(subcommand)] cmd: Cmd
}

#[derive(Subcommand)]
enum Cmd {
    /// 新規ボールトを作成
    New,
    /// エントリ追加（--genでランダム生成して保存）
    Add {
        name: String,
        #[arg(short, long)] user: Option<String>,
        #[arg(long)] gen: bool,
        #[arg(long, default_value_t = 20)] len: usize,
        #[arg(long)] symbols: bool,
        #[arg(long)] allow_ambiguous: bool,
    },
    /// 一覧表示
    List,
    /// 取得（--show でパスワード表示）
    Get { name: String, #[arg(long)] show: bool },
    /// ランダムパスワード生成のみ
    Gen {
        #[arg(long, default_value_t = 20)] len: usize,
        #[arg(long)] symbols: bool,
        #[arg(long)] allow_ambiguous: bool,
    },
}

#[derive(Serialize, Deserialize, Clone)]
struct Entry {
    id: String,
    name: String,
    username: String,
    password: String,
    url: Option<String>,
    notes: Option<String>,
    updated_at: String,
}

#[derive(Serialize, Deserialize, Default)]
struct Vault { entries: Vec<Entry> }

fn vault_path() -> Result<PathBuf> {
    let base = dirs::data_local_dir().ok_or(anyhow!("data dir not found"))?;
    let dir = base.join("rustpass");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("vault.bin"))
}

// マスターパスワードから鍵を導出（Argon2id）
fn derive_key_from_password(password: &str, salt: &[u8], params: &Params) -> Result<[u8;32]> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params.clone());
      let mut key = [0u8; 32];
      argon
          .hash_password_into(password.as_bytes(), salt, &mut key)
          .map_err(|e| anyhow!("argon2 hash_password_into failed: {e:?}"))?;
      Ok(key)
}


fn default_params() -> Params {
    // 初期は控えめ。必要なら m/t を上げて総当たり耐性を強化
    // m = 64 MiB, t = 3, p = 1
    Params::new(64 * 1024, 3, 1, None).expect("argon2 params")
}

fn now_iso() -> String {
    OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339).unwrap()
}

fn encrypt_vault(vault: &Vault, password: &str, params: Params) -> Result<Vec<u8>> {
    let mut salt = [0u8;16];
    OsRng.fill(&mut salt);
    let key_bytes = derive_key_from_password(password, &salt, &params)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8;12];
    OsRng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(vault)?;
    let ciphertext = cipher
    .encrypt(nonce, plaintext.as_ref())
    .map_err(|e| anyhow!("aead encrypt failed: {e:?}"))?;


    let mut out = Vec::with_capacity(4+1+4*3+16+12+ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&(params.m_cost() as u32).to_le_bytes());
    out.extend_from_slice(&(params.t_cost() as u32).to_le_bytes());
    out.extend_from_slice(&(params.p_cost() as u32).to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    // 秘匿データの消去（最低限）
    let mut pw = password.to_string();
    pw.zeroize();
    // key_bytes はスコープアウトで破棄
    Ok(out)
}

fn decrypt_vault(data: &[u8], password: &str) -> Result<Vault> {
    if data.len() < 4+1+4*3+16+12 { return Err(anyhow!("file too small")); }
    if &data[..4] != MAGIC { return Err(anyhow!("bad magic")); }
    if data[4] != VERSION { return Err(anyhow!("unsupported version")); }
    let mut idx = 5;
    let read_u32 = |i: usize| u32::from_le_bytes(data[i..i+4].try_into().unwrap());
    let m = read_u32(idx) as u32; idx+=4;
    let t = read_u32(idx) as u32; idx+=4;
    let p = read_u32(idx) as u32; idx+=4;
    let params = Params::new(m, t, p, None)
    .map_err(|e| anyhow!("argon2 params invalid: {e:?}"))?;

    let salt = &data[idx..idx+16]; idx+=16;
    let nonce_bytes = &data[idx..idx+12]; idx+=12;
    let ciphertext = &data[idx..];

    let key_bytes = derive_key_from_password(password, salt, &params)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
    .decrypt(nonce, ciphertext)
    .map_err(|e| anyhow!("aead decrypt failed (bad password or corrupted file): {e:?}"))?;

    let vault: Vault = serde_json::from_slice(&plaintext)?;
    Ok(vault)
}

fn load_or_init(password: &str) -> Result<Vault> {
    let path = vault_path()?;
    if path.exists() {
        let data = fs::read(path)?;
        decrypt_vault(&data, password)
    } else {
        Ok(Vault::default())
    }
}

fn save(password: &str, vault: &Vault, params: Params) -> Result<()> {
    let bytes = encrypt_vault(vault, password, params)?;
    let path = vault_path()?;
    fs::write(path, bytes)?;
    Ok(())
}

// ランダムパスワード生成（各カテゴリ最低1文字保証）
fn generate_password(len: usize, use_symbols: bool, allow_ambiguous: bool) -> Result<String> {
    if len < 4 { return Err(anyhow!("len must be >= 4")); }

    let mut lower = "abcdefghijklmnopqrstuvwxyz".to_string();
    let mut upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string();
    let mut digits = "0123456789".to_string();
    let mut symbols = "!@#$%^&*()-_=+[]{};:,.<>/?~".to_string();

    if !allow_ambiguous {
        let ambiguous = "O0o1lI|`'\"{}[]()/\\;:.,<>";
        let strip = |s: &mut String| s.retain(|c| !ambiguous.contains(c));
        strip(&mut lower); strip(&mut upper); strip(&mut digits);
        if use_symbols { strip(&mut symbols); }
    }

    let mut pools: Vec<Vec<u8>> = vec![
        lower.as_bytes().to_vec(),
        upper.as_bytes().to_vec(),
        digits.as_bytes().to_vec(),
    ];
    if use_symbols { pools.push(symbols.as_bytes().to_vec()); }
    if pools.iter().any(|p| p.is_empty()) {
        return Err(anyhow!("character pool empty; try --allow-ambiguous or disable --symbols"));
    }

    let mut all = Vec::new();
    for p in &pools { all.extend_from_slice(p); }

    let mut rng = OsRng;
    let mut bytes: Vec<u8> = Vec::with_capacity(len);
    for p in &pools {
        let idx = rng.gen_range(0..p.len());
        bytes.push(p[idx]);
    }
    for _ in bytes.len()..len {
        let idx = rng.gen_range(0..all.len());
        bytes.push(all[idx]);
    }
    bytes.shuffle(&mut rng);

    Ok(String::from_utf8(bytes)?)
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let password = prompt_password("Master password: ")?;
    let params = default_params();

    match cli.cmd {
        Cmd::New => {
            if vault_path()?.exists() {
                return Err(anyhow!("vault already exists"));
            }
            save(&password, &Vault::default(), params)?;
            println!("Created new vault at {:?}", vault_path()?);
        }
        Cmd::Add { name, user, gen, len, symbols, allow_ambiguous } => {
            let mut v = load_or_init(&password)?;
            let username = user.unwrap_or_else(|| {
                print!("Username: "); io::stdout().flush().unwrap();
                let mut s = String::new(); io::stdin().read_line(&mut s).unwrap(); s.trim().to_string()
            });
            let pass = if gen {
                let g = generate_password(len, symbols, allow_ambiguous)?;
                println!("Generated password (len={}): {}", len, g); // 必要なら伏せてもOK
                g
            } else {
                prompt_password("Password (hidden): ")?
            };
            v.entries.retain(|e| e.name != name);
            v.entries.push(Entry {
                id: Uuid::new_v4().to_string(),
                name, username,
                password: pass,
                url: None, notes: None,
                updated_at: now_iso(),
            });
            save(&password, &v, params)?;
            println!("Saved.");
        }
        Cmd::List => {
            let v = load_or_init(&password)?;
            for e in v.entries.iter() {
                println!("{}  ({})  updated {}", e.name, e.username, e.updated_at);
            }
        }
        Cmd::Get { name, show } => {
            let v = load_or_init(&password)?;
            if let Some(e) = v.entries.iter().find(|e| e.name == name) {
                println!("username: {}", e.username);
                if show { println!("password: {}", e.password); }
                else { println!("password: ******  (use --show to reveal)"); }
            } else {
                println!("not found");
            }
        }
        Cmd::Gen { len, symbols, allow_ambiguous } => {
            let s = generate_password(len, symbols, allow_ambiguous)?;
            println!("{}", s);
        }
    }
    Ok(())
}
