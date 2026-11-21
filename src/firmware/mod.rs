/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Reading the iPhone OS root filesystem out of a user-provided IPSW.
//!
//! An IPSW is a zip archive. Its `Restore.plist` names the root filesystem
//! image, which is an `encrcdsa`-encrypted UDIF disk image containing an
//! HFSX volume. Nothing from the firmware is bundled with touchHLE: the user
//! supplies the IPSW, and the root filesystem is extracted from it into the
//! user data directory on first use.

mod crypt;
pub mod hfs;
mod udif;

use std::cell::RefCell;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

pub fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes(b[..2].try_into().unwrap())
}
pub fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes(b[..4].try_into().unwrap())
}
pub fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().unwrap())
}

/// Random-access reads, implemented by each layer of the image stack.
pub trait ReadAt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize>;

    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        if self.read_at(buf, offset)? == buf.len() {
            Ok(())
        } else {
            Err(io::ErrorKind::UnexpectedEof.into())
        }
    }
}

impl<T: ReadAt + ?Sized> ReadAt for Box<T> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        (**self).read_at(buf, offset)
    }
}

pub struct FileReadAt(RefCell<std::fs::File>);

impl ReadAt for FileReadAt {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let mut file = self.0.borrow_mut();
        file.seek(SeekFrom::Start(offset))?;
        let mut done = 0;
        while done < buf.len() {
            match file.read(&mut buf[done..])? {
                0 => break,
                n => done += n,
            }
        }
        Ok(done)
    }
}

/// Root filesystem keys for IPSWs whose root filesystem images are
/// encrypted. These keys are published by the iOS research community
/// (e.g. via the ipsw.me API); the encrypted images themselves are not.
const ROOTFS_KEYS: &[(&str, &str, &str)] = &[
    (
        "iPhone1,2",
        "8A293",
        "09e054a8dd6c11c7f41ad9e614a8d564aa7d0c653585f29c0b07d1f0a1e1dc0040624a16",
    ),
    (
        "iPhone1,2",
        "8B117",
        "4c3c83d3899ea9bef415b1c9c656aaef966b2362494d2c9093a9283d388257562a228c86",
    ),
    (
        "iPhone1,2",
        "8C148",
        "82c9280927224637c77a96a26d22f42f2ca08fa9a798a8d06fbc8202fc83ec7f45dda79e",
    ),
];

fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Key must be an even number of hex digits".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[derive(Debug, Clone)]
pub struct IpswInfo {
    pub product_type: String,
    pub product_version: String,
    pub build: String,
    pub rootfs_name: String,
}

pub fn read_ipsw_info(ipsw_path: &Path) -> Result<IpswInfo, String> {
    let file = std::fs::File::open(ipsw_path).map_err(|e| format!("{ipsw_path:?}: {e}"))?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| format!("Not an IPSW: {e}"))?;
    let mut restore = Vec::new();
    zip.by_name("Restore.plist")
        .map_err(|_| "IPSW has no Restore.plist".to_string())?
        .read_to_end(&mut restore)
        .map_err(|e| e.to_string())?;
    let plist = plist::Value::from_reader(io::Cursor::new(restore)).map_err(|e| e.to_string())?;
    let dict = plist.as_dictionary().ok_or("Bad Restore.plist")?;
    let get = |key: &str| {
        dict.get(key)
            .and_then(|v| v.as_string())
            .map(str::to_string)
            .ok_or(format!("Restore.plist has no {key}"))
    };
    let rootfs_name = dict
        .get("SystemRestoreImages")
        .and_then(|d| d.as_dictionary())
        .and_then(|d| d.get("User"))
        .and_then(|v| v.as_string())
        .ok_or("Restore.plist does not name a root filesystem")?
        .to_string();
    if rootfs_name.is_empty() || rootfs_name.contains(['/', '\\']) || rootfs_name.starts_with('.') {
        return Err(format!("Bad root filesystem name {rootfs_name:?}"));
    }
    Ok(IpswInfo {
        product_type: get("ProductType")?,
        product_version: get("ProductVersion")?,
        build: get("ProductBuildVersion")?,
        rootfs_name,
    })
}

/// The iPhone OS root filesystem of an IPSW.
pub struct Firmware {
    pub info: IpswInfo,
    pub volume: hfs::Volume<Box<dyn ReadAt>>,
}

impl Firmware {
    /// Opens the root filesystem of an IPSW, extracting the image into
    /// `cache_dir` the first time. `key` overrides the built-in key table.
    pub fn open(ipsw_path: &Path, cache_dir: &Path, key: Option<&str>) -> Result<Self, String> {
        let info = read_ipsw_info(ipsw_path)?;
        log!(
            "Firmware: {} iOS {} ({}), root filesystem {}",
            info.product_type,
            info.product_version,
            info.build,
            info.rootfs_name
        );
        let image_path = Self::extract_rootfs(ipsw_path, cache_dir, &info)?;
        let file = std::fs::File::open(&image_path).map_err(|e| e.to_string())?;
        let len = file.metadata().map_err(|e| e.to_string())?.len();
        let file = FileReadAt(RefCell::new(file));

        let mut magic = [0u8; 8];
        file.read_exact_at(&mut magic, 0)
            .map_err(|e| e.to_string())?;
        let (image, len): (Box<dyn ReadAt>, u64) = if &magic == b"encrcdsa" {
            let key = match key {
                Some(key) => key.to_string(),
                None => ROOTFS_KEYS
                    .iter()
                    .find(|(p, b, _)| *p == info.product_type && *b == info.build)
                    .map(|(_, _, k)| k.to_string())
                    .ok_or(format!(
                        "No root filesystem key known for {} {}",
                        info.product_type, info.build
                    ))?,
            };
            let image = crypt::EncryptedImage::new(file, &parse_hex(&key)?)?;
            let len = image.len();
            (Box::new(image), len)
        } else {
            (Box::new(file), len)
        };
        let udif = udif::UdifImage::new(image, len)?;
        let partition = udif
            .partitions
            .iter()
            .find(|p| p.name.contains("Apple_HFS"))
            .ok_or("Disk image has no HFS partition")?;
        let base = partition.first_sector * 512;
        let volume = hfs::Volume::new(Box::new(udif) as Box<dyn ReadAt>, base)?;
        Ok(Firmware { info, volume })
    }

    fn extract_rootfs(
        ipsw_path: &Path,
        cache_dir: &Path,
        info: &IpswInfo,
    ) -> Result<PathBuf, String> {
        let out_path = cache_dir.join(format!(
            "{}_{}_{}",
            info.product_type, info.build, info.rootfs_name
        ));
        let file = std::fs::File::open(ipsw_path).map_err(|e| e.to_string())?;
        let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
        let mut entry = zip
            .by_name(&info.rootfs_name)
            .map_err(|_| format!("IPSW has no {}", info.rootfs_name))?;
        if std::fs::metadata(&out_path).is_ok_and(|m| m.len() == entry.size()) {
            return Ok(out_path);
        }
        log!("Extracting root filesystem image to {}", out_path.display());
        std::fs::create_dir_all(cache_dir).map_err(|e| e.to_string())?;
        let tmp_path = out_path.with_extension("part");
        let mut out = std::fs::File::create(&tmp_path).map_err(|e| e.to_string())?;
        io::copy(&mut entry, &mut out).map_err(|e| e.to_string())?;
        drop(out);
        std::fs::rename(&tmp_path, &out_path).map_err(|e| e.to_string())?;
        Ok(out_path)
    }
}

/// `--firmware-info`: prints what touchHLE can see of an IPSW.
pub fn print_info(ipsw_path: &Path, key: Option<&str>) -> Result<(), String> {
    let cache_dir = crate::paths::user_data_base_path().join(crate::paths::FIRMWARE_DIR);
    let fw = Firmware::open(ipsw_path, &cache_dir, key)?;
    echo!(
        "{} iOS {} ({})",
        fw.info.product_type,
        fw.info.product_version,
        fw.info.build
    );
    echo!("Root directory:");
    let mut root: Vec<_> = fw.volume.children(hfs::ROOT_FOLDER_ID).collect();
    root.sort_by(|a, b| a.name.cmp(&b.name));
    for node in root {
        let target = if node.is_symlink() {
            let target = fw.volume.read_all(node).map_err(|e| e.to_string())?;
            format!(" -> {}", String::from_utf8_lossy(&target))
        } else {
            String::new()
        };
        echo!(
            "  {:o} {}:{} {} {}{}",
            node.mode,
            node.uid,
            node.gid,
            node.mtime,
            fw.volume.path_of(node.id),
            target
        );
    }
    for path in [
        "/usr/lib/dyld",
        "/usr/lib/libSystem.B.dylib",
        "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv6",
        "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv7",
        "/System/Library/CoreServices/SpringBoard.app/SpringBoard",
        "/sbin/launchd",
    ] {
        match fw.volume.lookup(path, true) {
            Some(node) => {
                let size = fw.volume.size(node);
                let mut magic = [0u8; 8];
                fw.volume
                    .read(node, &mut magic, 0)
                    .map_err(|e| e.to_string())?;
                echo!("{path}: {size} bytes, starts with {magic:02x?}");
            }
            None => echo!("{path}: not present"),
        }
    }
    Ok(())
}
