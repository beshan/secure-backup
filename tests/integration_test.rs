use std::{env, fs, path::Path};

use secure_backup::{
  backup::take_backup,
  common::Cipher,
  restore::restore_backup,
  util::{compare_dirs, file_ignored},
};

fn backup_restore(cipher: Cipher) {
  let current_dir = env::current_dir().unwrap();
  let password = "password";
  let salt = "salt";
  let ignore_list = vec!["*.ignore"];

  let source_dir = current_dir.join(Path::new("tests/sample_data/sample_folder")).to_path_buf();
  let backup_dir = env::temp_dir().join("backup_test_folder").to_path_buf();
  let restore_dir = env::temp_dir().join("restore_test_folder").to_path_buf();

  let result = take_backup(&source_dir, &backup_dir, cipher, password, salt, &ignore_list);
  assert_eq!(result, ());

  let result = restore_backup(cipher, &backup_dir, &restore_dir, password, salt);
  assert_eq!(result, ());

  let diffs = compare_dirs(&source_dir, &restore_dir);
  assert!(diffs.keys().all(|k| file_ignored(&ignore_list, &source_dir.join(k))));

  // test incremental backup

  fs::remove_dir_all(&backup_dir).unwrap();
  fs::remove_dir_all(&restore_dir).unwrap();
}

#[test]
fn test_backup_restore() {
  backup_restore(Cipher::AES256);
  backup_restore(Cipher::ChaCha20);
}
