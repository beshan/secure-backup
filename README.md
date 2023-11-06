## Intro
This crate takes an incremental backup from a directory while encrypting its entire content, including filenames. It supports [AES256](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) and [Chacha20](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant) ciphers and uses the [OpenSSL library](https://github.com/openssl/openssl) via [openssl crate](https://docs.rs/openssl/latest/openssl/index.html). 

## Usage

The OpenSSL library must be already installed on the host OS:

```bash
# On Debian
$ sudo apt install libssl-dev
```

```toml
[dependencies]
secure_backup = "0.1"
```

```rust
  use std::{env, path::Path};

  use secure_backup::{
    backup::take_backup,
    restore::restore_backup,
    common::Cipher
  };

  let current_dir = env::current_dir().unwrap();
  let password = "password";
  let salt = "salt";
  let ignore_list = vec!["*.ignore"];

  let source_dir = current_dir.join(Path::new("path_to_the_src_dir")).to_path_buf();
  let backup_dir = env::temp_dir().join("path_to_the_backup_dir").to_path_buf();

  // Take a backup
  take_backup(&source_dir, &backup_dir, Cipher::AES256, password, salt, &ignore_list);  

  // Restore the backup
  let restore_dir = env::temp_dir().join("path_to_the_restore_dir").to_path_buf();
  restore_backup(Cipher::AES256, &backup_dir, &restore_dir, password, salt);  
```

# License
[MIT License](./LICENSE)