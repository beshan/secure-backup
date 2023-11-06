use glob::{MatchOptions, Pattern};
use openssl::{
  base64::{self},
  hash::{Hasher, MessageDigest},
  pkcs5::scrypt,
  pkey::PKey,
  rand::rand_bytes,
  sign::Signer,
  symm::{Cipher, Crypter, Mode},
};

use std::{
  cell::RefCell,
  collections::HashMap,
  fs::{self, DirEntry},
  io::{self, Read, Write},
  path::{Path, PathBuf},
};

pub fn get_files(dir: &Path, cb: &dyn Fn(&DirEntry)) {
  if !dir.is_dir() {
    panic!("{} isn't a directory.", dir.display());
  }

  for entry in fs::read_dir(dir).unwrap() {
    let _entry = entry.unwrap();
    let path = _entry.path();
    if path.is_symlink() {
      panic!("Taking backup from a symbolic link is not supported. Path: {}", path.display())
    }
    if path.is_dir() {
      get_files(&path, cb);
    } else {
      cb(&_entry);
    }
  }
}

pub fn encrypt_file(
  cipher: Cipher,
  key: &Vec<u8>,
  iv: &Vec<u8>,
  file_path: &Path,
  output_path: &Path,
) -> io::Result<()> {
  /* If the output file already exists then take a backup of it and
  restore it when the encryption process fails */
  let output_file_exists = output_path.try_exists();
  let output_backup_path = PathBuf::from(format!("{}{}", &output_path.display(), ".bak"));
  if matches!(output_file_exists, Ok(true)) {
    fs::rename(&output_path, &output_backup_path).unwrap();
  }

  let result = (|| -> io::Result<()> {
    let mut encrypting_file = fs::OpenOptions::new().read(true).open(file_path)?;

    let mut output_file =
      fs::OpenOptions::new().create(true).write(true).append(true).open(output_path)?;

    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, Some(&iv))?;

    let block_size = cipher.block_size();
    let read_buffer_size = 1024; // 1 KiB
    let encryption_buffer_size = block_size + read_buffer_size;
    let output_buffer_size = read_buffer_size * 1024; // 1 MiB
    let mut output_buffer = Vec::with_capacity(output_buffer_size);

    // Read and encrypt the file in chunks and write multiple chunks into the output file at once
    loop {
      let mut read_buffer = Vec::with_capacity(read_buffer_size);
      let mut encryption_buffer = vec![0; encryption_buffer_size];

      // Read a chunk of the encrypting file into the read buffer
      Read::by_ref(&mut encrypting_file)
        .take(read_buffer_size as u64)
        .read_to_end(&mut read_buffer)?;

      let read_completed = read_buffer.len() == 0;

      /* Encrypt the read buffer and write it into the encryption buffer or
      finalize the encryption process if there is no more data to read */
      let encryption_output_len = if read_completed {
        crypter.finalize(&mut encryption_buffer)?
      } else {
        crypter.update(&read_buffer, &mut encryption_buffer)?
      };

      /* The encryption output size can be smaller than the encryption buffer size so
      the buffer should be truncated */
      if encryption_output_len < encryption_buffer.len() {
        encryption_buffer.truncate(encryption_output_len);
      }
      output_buffer.append(&mut encryption_buffer);

      /* If the output buffer is full or there is no more data to read then
      write the buffer to the output file */
      if output_buffer.len() == output_buffer_size || read_completed {
        output_file.write_all(&output_buffer)?;
        output_buffer.flush()?;
        output_buffer.clear();
      }

      if read_completed {
        break;
      }
    }

    Ok(())
  })();

  if let Ok(_) = result {
    if matches!(output_file_exists, Ok(true)) {
      fs::remove_file(output_backup_path).unwrap();
    }
  } else {
    if matches!(output_file_exists, Ok(true)) {
      fs::rename(output_backup_path, &output_path).unwrap();
    }
  }

  return result;
}

pub fn decrypt_file(
  cipher: Cipher,
  key: &Vec<u8>,
  iv: &Vec<u8>,
  file_path: &Path,
  output_path: &Path,
) {
  let key = &key[0..cipher.key_len()].to_vec();

  let mut decryptor = Crypter::new(cipher, Mode::Decrypt, key, Some(&iv)).unwrap();

  let mut decrypting_file = fs::OpenOptions::new().read(true).open(file_path).unwrap();
  let mut output_file =
    fs::OpenOptions::new().create(true).write(true).append(true).open(output_path).unwrap();

  let block_size = cipher.block_size();
  let chunk_size = block_size * 1024; // n kilobytes (n==block_size)
  let output_buffer_size = chunk_size * 1024; // n megabytes
  let mut output_buffer = Vec::with_capacity(output_buffer_size);

  // Read and decrypt the file in chunks and write multiple chunks into the output buffer at once
  loop {
    let mut chunk = Vec::with_capacity(chunk_size);

    // Read a chunk of the decrypting file
    Read::by_ref(&mut decrypting_file).take(chunk_size as u64).read_to_end(&mut chunk).unwrap();
    if chunk.len() == 0 {
      break;
    }

    let mut decryption_buffer = vec![0; chunk_size + block_size];
    // Decrypt the chunk and write it into the output buffer
    let decrypted_output_len = decryptor.update(&chunk, &mut decryption_buffer).unwrap();
    // The last output's size can be smaller than the decryption buffer the buffer should be truncated
    if decrypted_output_len < decryption_buffer.len() {
      decryption_buffer.truncate(decrypted_output_len);
    }
    output_buffer.append(&mut decryption_buffer);

    // When the buffer is full write it into the output file
    if output_buffer.len() == output_buffer_size {
      output_file.write_all(&output_buffer).unwrap();
      output_buffer.clear();
    }
  }

  if !output_buffer.is_empty() {
    output_file.write_all(&output_buffer).unwrap();
    output_buffer.clear();
  }
}

pub fn generate_iv(size: usize) -> Vec<u8> {
  let mut buf = vec![0; size];
  rand_bytes(&mut buf).unwrap();
  buf
}

pub fn get_relative_path(root_path: &Path, nested_path: &Path) -> String {
  let mut root_path = fs::canonicalize(&root_path).unwrap().display().to_string();
  if !root_path.ends_with("/") {
    root_path.insert(root_path.len(), '/');
  }
  let nested_path = fs::canonicalize(&nested_path).unwrap().display().to_string();

  nested_path.to_string()[root_path.len()..nested_path.len()].to_string()
}

pub fn encode(data: &[u8]) -> String {
  base64::encode_block(&data)
    .chars()
    .map(|c: char| match c {
      '/' => '_',
      '+' => '-',
      '=' => ' ',
      _ => c,
    })
    .collect::<String>()
    .trim_end()
    .to_string()
}

pub fn decode(string: &str) -> Vec<u8> {
  let mut string = string
    .chars()
    .map(|c: char| match c {
      '-' => '+',
      '_' => '/',
      _ => c,
    })
    .collect::<String>();

  if string.len() % 4 == 2 {
    string.push('=');
  }
  if string.len() % 4 == 3 {
    string.push('=');
  }

  base64::decode_block(&string).unwrap()
}

pub fn derive_key(password: &str, salt: &str, len: usize) -> Vec<u8> {
  let mut key = vec![0; len];
  let mem_size = 1024 * 2014; // 1mb
  scrypt(password.as_bytes(), salt.as_bytes(), 1024, 8, 16, mem_size, &mut key).unwrap();
  key
}

pub fn calc_file_checksum(path: &Path) -> Vec<u8> {
  let mut hasher = Hasher::new(MessageDigest::md5()).unwrap();
  let mut file = fs::File::open(path).unwrap();

  loop {
    let mut buffer = vec![0; 1024];
    let read_len = file.read(&mut buffer).unwrap();
    if read_len != 0 {
      if read_len < buffer.len() {
        buffer.truncate(read_len);
      }
      hasher.update(&buffer).unwrap();
    } else {
      break;
    }
  }

  hasher.finish().unwrap().to_vec()
}

pub fn sign_file(key: &[u8], path: &Path) -> Vec<u8> {
  let mut file = fs::File::open(path).unwrap();

  let key = PKey::hmac(key).unwrap();
  let mut signer = Signer::new(MessageDigest::sha3_512(), &key).unwrap();

  loop {
    let mut buffer = vec![0; 1024];
    let read_len = file.read(&mut buffer).unwrap();
    if read_len != 0 {
      if read_len < buffer.len() {
        buffer.truncate(read_len);
      }
      signer.update(&buffer).unwrap();
    } else {
      break;
    }
  }

  signer.sign_to_vec().unwrap()
}

pub fn write_file_safely(output_path: &Path, data: &[u8]) -> io::Result<()> {
  let output_file_exists = output_path.try_exists();
  let output_backup_path = PathBuf::from(format!("{}{}", &output_path.display(), ".bak"));
  if matches!(output_file_exists, Ok(true)) {
    fs::rename(&output_path, &output_backup_path)?;
  }

  let result = (|| -> io::Result<()> {
    let mut output_file = fs::OpenOptions::new().create(true).write(true).open(output_path)?;
    output_file.write_all(&encode(&data).as_bytes())?;

    Ok(())
  })();

  if let Ok(_) = result {
    if matches!(output_file_exists, Ok(true)) {
      fs::remove_file(output_backup_path)?;
    }
  } else {
    if matches!(output_file_exists, Ok(true)) {
      fs::rename(output_backup_path, &output_path)?;
    }
  }

  return result;
}

pub enum FileDiffReason {
  DataMismatch,
  OnlyInRight,
  OnlyInLeft,
}

pub fn compare_dirs(right_dir: &Path, left_dir: &Path) -> HashMap<String, FileDiffReason> {
  let get_diffs = |right_dir: &Path,
                   left_dir: &Path,
                   reverse: bool,
                   diffs: &RefCell<HashMap<String, FileDiffReason>>| {
    let _right_dir = right_dir;
    let right_dir = if !reverse { right_dir } else { left_dir };
    let left_dir = if !reverse { left_dir } else { _right_dir };
    get_files(right_dir, &|right_file| {
      let right_file_path = &right_file.path();
      let relative_path = get_relative_path(right_dir, right_file_path);
      let left_file_path = &Path::new(left_dir).join(&relative_path);
      let left_file_exists = left_file_path.try_exists();
      if matches!(left_file_exists, Ok(true)) {
        let right_file_checksum = calc_file_checksum(right_file_path);
        let left_file_checksum = calc_file_checksum(left_file_path);
        if right_file_checksum != left_file_checksum {
          diffs.borrow_mut().insert(relative_path, FileDiffReason::DataMismatch);
        }
      } else {
        diffs.borrow_mut().insert(
          relative_path,
          if !reverse { FileDiffReason::OnlyInRight } else { FileDiffReason::OnlyInLeft },
        );
      }
    });
  };

  let diffs = RefCell::new(HashMap::<String, FileDiffReason>::new());
  get_diffs(right_dir, left_dir, false, &diffs);
  get_diffs(right_dir, left_dir, true, &diffs);

  diffs.into_inner()
}

pub fn file_ignored(ignore_list: &Vec<&str>, file_path: &Path) -> bool {
  let options = MatchOptions {
    case_sensitive: false,
    require_literal_separator: false,
    require_literal_leading_dot: false,
  };
  for entry in ignore_list.into_iter() {
    let pattern = Pattern::new(&entry).unwrap();
    if pattern.matches_path_with(&file_path, options) {
      return true;
    }
  }

  false
}

#[macro_export]
macro_rules! hashmap {
  ($( $key: expr => $val: expr ),*) => {{
      let mut map = ::std::collections::HashMap::new();
      $( map.insert($key, $val); )*
      map
  }}
}

#[cfg(test)]
mod tests {
  use std::env;
  use std::{ffi::OsString, os::unix::prelude::OsStringExt};

  use super::*;

  #[test]
  fn test_get_files() {
    let current_dir = env::current_dir().unwrap();
    let files = RefCell::new(vec![]);

    let path = current_dir.join(Path::new("tests/sample_data/sample_folder"));
    get_files(&path, &|file| {
      files.borrow_mut().push(file.path());
    });

    assert_eq!(files.into_inner().len(), 10);
  }

  #[test]
  fn test_encode_decode() {
    let encoded = encode(&String::from("hello world!").as_bytes().to_vec());
    let decoded = OsString::from_vec(decode(&encoded)).to_str().unwrap().to_string();
    assert_eq!(decoded, String::from("hello world!"));
  }

  #[test]
  fn test_get_relative_path() {
    let current_dir = env::current_dir().unwrap();
    let root_path = current_dir.join(Path::new("tests"));
    let nested_path = current_dir.join(Path::new("tests/sample_data/sample_folder"));
    let relative_path = get_relative_path(&root_path, &nested_path);
    assert_eq!(relative_path, "sample_data/sample_folder");

    let root_path = current_dir.join(Path::new("tests/sample_data/"));
    let nested_path = current_dir.join(Path::new("tests/sample_data/sample_folder"));
    let relative_path = get_relative_path(&root_path, &nested_path);
    assert_eq!(relative_path, "sample_folder");

    let root_path = current_dir.join(Path::new("tests/sample_data/sample_folder/this is a folder"));
    let nested_path =
      current_dir.join(Path::new("tests/sample_data/sample_folder/this is a folder/text.txt"));
    let relative_path = get_relative_path(&root_path, &nested_path);
    assert_eq!(relative_path, "text.txt");
  }

  #[test]
  fn test_encrypt_file() {
    let data = b"Hello world!";
    let temp_dir = env::temp_dir();
    let cipher = Cipher::aes_256_ctr();
    let file_path = Path::new(temp_dir.as_path()).join("hello.txt");
    let output_path = Path::new(temp_dir.as_path()).join("hello.txt.enc");
    let key = derive_key("password", "salt", cipher.key_len());

    let mut encrypting_file = fs::File::create(&file_path).unwrap();
    encrypting_file.write_all(data).expect("Failed to write to the hello.txt file.");
    let iv = derive_key("password", "salt", cipher.iv_len().unwrap_or(12));
    encrypt_file(cipher, &key, &iv, &file_path, &output_path).unwrap();

    let mut output_file = fs::File::open(&output_path).unwrap();
    let mut output = vec![];
    output_file.read_to_end(&mut output).unwrap();

    fs::remove_file(file_path).unwrap();
    fs::remove_file(output_path).unwrap();

    assert_eq!([246, 128, 226, 42, 34, 82, 35, 61, 245, 216, 185, 217], &output[..]);
  }

  #[test]
  fn test_compare_dirs() {
    let current_dir = env::current_dir().unwrap();
    let right_dir =
      current_dir.join(Path::new("tests/sample_data/sample_folder/this is a folder")).to_path_buf();
    let left_dir = current_dir
      .join(Path::new("tests/sample_data/sample_folder/Αυτός είναι ένας φάκελος (2)"))
      .to_path_buf();
    let diffs = compare_dirs(&right_dir, &left_dir);

    let expected = hashmap!(
      "this is a folder/text.txt".to_string() => FileDiffReason::OnlyInLeft,
      "Αυτός είναι ένας φάκελος/binary-file.bin".to_string() => FileDiffReason::OnlyInRight,
      "text.txt".to_string() => FileDiffReason::DataMismatch,
      "Αυτός είναι ένας φάκελος/UTF-8 Sampler.txt".to_string() => FileDiffReason::OnlyInRight
    );

    assert!(diffs.len() == expected.len() && diffs.keys().all(|k| expected.contains_key(k)));
  }

  #[test]
  fn test_path_ignored() {
    let ignore_list = vec!["*.ignore", "**/empty_file", "**/Αυτός είναι ένας φάκελος/**"];
    let ignored_files = RefCell::new(Vec::new());

    let current_dir = env::current_dir().unwrap();
    let sample_folder =
      current_dir.join(Path::new("tests/sample_data/sample_folder")).to_path_buf();

    get_files(&sample_folder, &|file| {
      let file_path = file.path().to_path_buf();
      if file_ignored(&ignore_list, &file_path) {
        ignored_files.borrow_mut().push(file_path.clone());
      }
    });

    let expected: Vec<PathBuf> = vec![
      sample_folder.join("file.ignore"),
      sample_folder.join("this is a folder/empty_file"),
      sample_folder.join("this is a folder/file.ignore"),
      sample_folder.join("this is a folder/Αυτός είναι ένας φάκελος/binary-file.bin"),
      sample_folder.join("this is a folder/Αυτός είναι ένας φάκελος/UTF-8 Sampler.txt"),
      sample_folder.join("Αυτός είναι ένας φάκελος (2)/empty_file"),
      sample_folder.join("Αυτός είναι ένας φάκελος (2)/file.ignore"),
    ];
    assert_eq!(ignored_files.into_inner(), expected);
  }
}
