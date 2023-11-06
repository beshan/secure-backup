use openssl::symm::{decrypt, encrypt, Cipher};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Seek;
use std::path::Path;
use std::{
  collections::BTreeMap,
  fs::{self, File},
};

use crate::util::{decode, encode};

#[derive(Serialize, Deserialize)]
pub struct FileInfo {
  pub source_path: Vec<u8>,
  pub encryption_iv: Vec<u8>,
  pub backup_checksum: Vec<u8>,
  pub source_checksum: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Data {
  files: BTreeMap<String, String>,
}

impl Data {
  pub fn new() -> Data {
    Data { files: BTreeMap::new() }
  }
}

pub struct Database {
  cipher: Cipher,
  key: Vec<u8>,
  storage: File,
  data: Data,
  source_path_index_entries: HashMap<Vec<u8>, Vec<u8>>,
}

impl Database {
  pub fn new(cipher: Cipher, key: &Vec<u8>, path: &Path) -> Database {
    let storage =
      fs::OpenOptions::new().write(true).read(true).create(true).append(false).open(path).unwrap();
    let data = serde_json::from_reader(&storage).unwrap_or(Data::new());

    return Database {
      cipher,
      key: key.to_vec(),
      storage,
      data,
      source_path_index_entries: HashMap::new(),
    };
  }

  pub fn init(&mut self) {
    self.create_indexes();
  }

  pub fn add_file_record(&mut self, id: Vec<u8>, info: FileInfo) {
    let value = serde_json::to_string(&(
      &encode(&info.source_path),
      &encode(&info.encryption_iv),
      &encode(&info.backup_checksum),
      &encode(&info.source_checksum),
    ))
    .unwrap();
    let encrypted_value = encrypt(self.cipher, &self.key, Some(&id), &value.as_bytes()).unwrap();
    self.data.files.insert(encode(&id), encode(&encrypted_value));
    self.storage.rewind().unwrap();
    serde_json::to_writer(&self.storage, &self.data).unwrap();
  }

  pub fn create_indexes(&mut self) {
    for entry in &self.data.files {
      let info = self.parse_file_info(entry.0, entry.1);
      self.source_path_index_entries.insert(info.source_path, decode(entry.0));
    }
  }

  pub fn find_file_record_by_source_path(
    &self,
    source_path: &Vec<u8>,
  ) -> Option<(Vec<u8>, FileInfo)> {
    let file_id = self.source_path_index_entries.get(source_path);

    if file_id.is_some() {
      let file_id = file_id.unwrap();
      return Some(self.find_file_record(file_id).unwrap());
    }

    None
  }

  pub fn find_file_record(&self, id: &Vec<u8>) -> Option<(Vec<u8>, FileInfo)> {
    let id_vec = id;
    let id = encode(&id_vec);
    let value = self.data.files.get(&id);
    if value.is_some() {
      let value = self.parse_file_info(&id, value.unwrap());
      return Some((id_vec.to_vec(), value));
    }

    None
  }

  fn parse_file_info(&self, id: &str, value: &str) -> FileInfo {
    let value = decrypt(self.cipher, &self.key, Some(&decode(&id)), &decode(&value)).unwrap();

    let value: (String, String, String, String) =
      serde_json::from_str(&String::from_utf8(value).unwrap()).unwrap();

    FileInfo {
      source_path: decode(&value.0),
      encryption_iv: decode(&value.1),
      backup_checksum: decode(&value.2),
      source_checksum: decode(&value.3),
    }
  }
}
