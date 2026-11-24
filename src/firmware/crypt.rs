/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Decryption of `encrcdsa` (FileVault v2 style) disk images, which is how
//! iPhone OS root filesystem images are shipped inside IPSWs.
//!
//! The image is split into fixed-size chunks, each encrypted with AES-128-CBC.
//! The IV for chunk `n` is the first 16 bytes of HMAC-SHA1(hmac_key, n).

use super::{be32, be64, ReadAt};
use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use std::cell::RefCell;
use std::io;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

pub struct EncryptedImage<R: ReadAt> {
    inner: R,
    aes_key: [u8; 16],
    hmac_key: [u8; 20],
    chunk_size: u64,
    data_size: u64,
    data_offset: u64,
    /// Most recently decrypted chunk.
    cache: RefCell<Option<(u64, Vec<u8>)>>,
}

impl<R: ReadAt> EncryptedImage<R> {
    /// `key` is the 36-byte root filesystem key the user supplies
    /// (16-byte AES key followed by the 20-byte HMAC key).
    pub fn new(inner: R, key: &[u8]) -> Result<Self, String> {
        if key.len() != 36 {
            return Err(format!(
                "Root filesystem key must be 36 bytes (72 hex digits), got {}",
                key.len()
            ));
        }
        let mut header = [0u8; 0x48];
        inner
            .read_exact_at(&mut header, 0)
            .map_err(|e| e.to_string())?;
        if &header[0..8] != b"encrcdsa" || be32(&header[8..]) != 2 {
            return Err("Not an encrcdsa v2 image".to_string());
        }
        let chunk_size = be32(&header[0x34..]) as u64;
        if chunk_size == 0 || !chunk_size.is_multiple_of(16) || chunk_size > 1 << 20 {
            return Err(format!("Bad encrcdsa chunk size {chunk_size}"));
        }
        Ok(EncryptedImage {
            inner,
            aes_key: key[0..16].try_into().unwrap(),
            hmac_key: key[16..36].try_into().unwrap(),
            chunk_size,
            data_size: be64(&header[0x38..]),
            data_offset: be64(&header[0x40..]),
            cache: RefCell::new(None),
        })
    }

    pub fn len(&self) -> u64 {
        self.data_size
    }

    fn decrypt_chunk(&self, index: u64) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.chunk_size as usize];
        self.inner
            .read_exact_at(&mut buf, self.data_offset + index * self.chunk_size)?;
        let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&self.hmac_key).unwrap();
        mac.update(&(index as u32).to_be_bytes());
        let iv: [u8; 16] = mac.finalize().into_bytes()[0..16].try_into().unwrap();
        Aes128CbcDec::new(&self.aes_key.into(), &iv.into())
            .decrypt_padded_mut::<NoPadding>(&mut buf)
            .map_err(|_| io::Error::other("Bad encrcdsa chunk"))?;
        Ok(buf)
    }
}

impl<R: ReadAt> ReadAt for EncryptedImage<R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if offset >= self.data_size {
            return Ok(0);
        }
        let len = (buf.len() as u64).min(self.data_size - offset) as usize;
        let mut done = 0;
        while done < len {
            let pos = offset + done as u64;
            let index = pos / self.chunk_size;
            let within = (pos % self.chunk_size) as usize;
            let mut cache = self.cache.borrow_mut();
            if cache.as_ref().is_none_or(|(i, _)| *i != index) {
                *cache = Some((index, self.decrypt_chunk(index)?));
            }
            let chunk = &cache.as_ref().unwrap().1;
            let n = (chunk.len() - within).min(len - done);
            buf[done..done + n].copy_from_slice(&chunk[within..within + n]);
            done += n;
        }
        Ok(len)
    }
}
