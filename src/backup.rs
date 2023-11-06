use crate::common;
use crate::db::{Database, FileInfo};
use crate::util::{
  calc_file_checksum, derive_key, encode, encrypt_file, file_ignored, generate_iv, get_files,
  get_relative_path, sign_file, write_file_safely,
};
use openssl::symm::Cipher;

use std::{
  fs,
  path::Path,
  sync::{Arc, RwLock},
};

// const DEFAULT_IV_SIZE: usize = 16;

pub fn take_backup(
  source_dir: &Path,
  backup_dir: &Path,
  cipher_type: common::Cipher,
  password: &str,
  salt: &str,
  ignore_list: &Vec<&str>,
) {
  let cipher: Cipher = match cipher_type {
    common::Cipher::AES256 => Cipher::aes_256_ctr(),
    common::Cipher::ChaCha20 => Cipher::chacha20(),
  };

  let key = derive_key(password, salt, cipher.key_len());

  let db_path = Path::new(&backup_dir).join(Path::new("db.json"));
  let backup_files_dir = Path::new(&backup_dir).join(Path::new("files"));

  fs::create_dir_all(backup_dir).unwrap();
  fs::create_dir_all(&backup_files_dir).unwrap();

  let db = Arc::new(RwLock::new(Database::new(cipher, &key, &db_path)));
  let mut db_writer = db.write().unwrap();
  db_writer.init();
  drop(db_writer);

  get_files(source_dir, &|file| {
    if file_ignored(&ignore_list, &file.path()) {
      return;
    }

    let source_checksum = calc_file_checksum(&file.path());
    let source_path = get_relative_path(&source_dir, &file.path()).as_bytes().to_vec();

    let db_reader = db.read().unwrap();
    let file_record = db_reader.find_file_record_by_source_path(&source_path);
    drop(db_reader);

    let (file_id, source_path, encryption_iv, backup_path) = if file_record.is_some() {
      let (file_id, file_info) = file_record.unwrap();
      let backup_path = backup_files_dir.join(Path::new(&encode(&file_id)));
      // Skip taking the backup if the file and its backup haven't changed
      // The backup file can be accidentally deleted
      if source_checksum == file_info.source_checksum
        && backup_path.exists()
        && calc_file_checksum(&backup_path) == file_info.backup_checksum
      {
        return;
      }
      (file_id, file_info.source_path, file_info.encryption_iv, backup_path)
    } else {
      let iv_len = cipher.iv_len().unwrap();
      let file_id = generate_iv(iv_len);
      let encryption_iv = generate_iv(iv_len);
      let backup_path = Path::new(&backup_files_dir).join(Path::new(&encode(&file_id)));
      (file_id, source_path, encryption_iv, backup_path)
    };

    encrypt_file(cipher, &key, &encryption_iv, &file.path(), &backup_path).unwrap();

    let backup_checksum = calc_file_checksum(&backup_path);

    let mut db_writer = db.write().unwrap();
    db_writer.add_file_record(
      file_id,
      FileInfo { source_path, encryption_iv, source_checksum, backup_checksum },
    );
  });

  let db_sig = sign_file(&key, &db_path);
  let db_sig_path = Path::new(&backup_dir).join(Path::new("db.sig")).to_path_buf();
  write_file_safely(&db_sig_path, &db_sig).unwrap();
}
