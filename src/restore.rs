use crate::common;
use crate::db::Database;
use crate::util::{decode, decrypt_file, derive_key, get_files};
use openssl::symm::Cipher;
use std::ffi::OsString;
use std::fs::{self};
use std::os::unix::prelude::OsStringExt;
use std::path::Path;
use std::sync::{Arc, RwLock};

pub fn restore_backup(
  cipher_type: common::Cipher,
  backup_dir: &Path,
  restore_dir: &Path,
  password: &str,
  salt: &str,
) {
  let cipher: Cipher = match cipher_type {
    common::Cipher::AES256 => Cipher::aes_256_ctr(),
    common::Cipher::ChaCha20 => Cipher::chacha20(),
  };
  let key = derive_key(password, salt, cipher.key_len());

  let db_path = Path::new(&backup_dir).join(Path::new("db.json"));
  let backup_files_dir = Path::new(&backup_dir).join(Path::new("files"));

  fs::create_dir(restore_dir).expect("Restore directory exists.");

  let db = Arc::new(RwLock::new(Database::new(cipher, &key, &db_path)));
  let mut db_writer = db.write().unwrap();
  db_writer.init();
  drop(db_writer);

  get_files(&backup_files_dir, &|file| {
    let db_reader = db.read().unwrap();
    let file_id = decode(&file.file_name().into_string().unwrap());
    let file_record = db_reader.find_file_record(&file_id);
    drop(db_reader);

    if file_record.is_none() {
      return;
    }

    let (_, file_info) = file_record.unwrap();
    let restore_path =
      Path::new(restore_dir).join(Path::new(&OsString::from_vec(file_info.source_path)));

    fs::create_dir_all(&restore_path.parent().unwrap()).unwrap();

    decrypt_file(cipher, &key, &file_info.encryption_iv, &file.path(), &restore_path);
  });
}
