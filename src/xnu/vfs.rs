/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! The guest filesystem: the firmware's read-only root filesystem, with a
//! writable host directory layered over it. Files that are written to are
//! copied up into the overlay first.

use crate::firmware::hfs::Node;
use crate::firmware::Firmware;
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

pub const ENOENT: u32 = 2;
pub const EBADF: u32 = 9;
pub const EACCES: u32 = 13;
pub const EEXIST: u32 = 17;
pub const ENOTDIR: u32 = 20;
pub const EISDIR: u32 = 21;
pub const EINVAL: u32 = 22;
pub const EROFS: u32 = 30;

pub const O_RDWR: u32 = 2;
pub const O_APPEND: u32 = 8;
pub const O_CREAT: u32 = 0x200;
pub const O_TRUNC: u32 = 0x400;
pub const O_EXCL: u32 = 0x800;

#[derive(Debug, Clone)]
pub struct Stat {
    pub mode: u16,
    pub ino: u64,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub nlink: u16,
}

/// Registered `EVFILT_USER` events.
#[derive(Default)]
pub struct Kqueue {
    pub user: Vec<UserEvent>,
}

impl Kqueue {
    /// Whether `kevent` would return an event without waiting.
    pub fn pending(&self) -> bool {
        const EV_DISABLE: u16 = 0x0008;
        self.user
            .iter()
            .any(|e| e.triggered && e.flags & EV_DISABLE == 0)
    }
}

pub struct UserEvent {
    pub ident: u32,
    pub udata: u32,
    pub fflags: u32,
    /// `EV_ONESHOT`, `EV_CLEAR` and `EV_DISABLE` as last registered.
    pub flags: u16,
    pub triggered: bool,
}

/// A POSIX shared memory object's contents while it isn't mapped.
#[derive(Default)]
pub struct Shm {
    pub data: Vec<u8>,
}

/// A live mapping of a shared memory object. A process's mappings that fit
/// share one region.
pub struct ShmMap {
    pub pid: u32,
    pub addr: u32,
    pub len: u32,
    pub refs: u32,
    pub shm: std::rc::Rc<std::cell::RefCell<Shm>>,
}

/// A writable `MAP_SHARED` mapping of a host file. Each process has its own
/// memory here, so the pages go back to the file when they are unmapped.
pub struct FileMap {
    pub pid: u32,
    pub addr: u32,
    pub len: u32,
    pub offset: u64,
    pub file: std::fs::File,
}

pub enum FileKind {
    Firmware {
        node: u32,
    },
    Host(std::fs::File),
    Dir {
        path: String,
        entries: Vec<(String, u8, u64)>,
        pos: usize,
    },
    /// Character devices like /dev/null and the console.
    Null,
    Console,
    Random,
    Socket(Box<super::lockdown::Socket>),
    /// A kqueue, shared by its duplicated descriptors. Only `EVFILT_USER`
    /// events fire.
    Kqueue(std::rc::Rc<std::cell::RefCell<Kqueue>>),
    Shm(std::rc::Rc<std::cell::RefCell<Shm>>),
}

pub struct OpenFile {
    pub kind: FileKind,
    pub offset: u64,
    pub path: String,
    pub flags: u32,
}

#[cfg(any(target_os = "emscripten", test))]
#[derive(Clone, Copy, PartialEq, Eq)]
struct MappingKey {
    node: u32,
    offset: u64,
    len: u32,
}

/// Pristine firmware bytes reused across processes, not shared guest memory.
#[cfg(any(target_os = "emscripten", test))]
#[derive(Default)]
struct MappingCache {
    entries: std::collections::VecDeque<(MappingKey, Rc<Vec<u8>>)>,
}

#[cfg(any(target_os = "emscripten", test))]
impl MappingCache {
    const BUDGET: usize = 48 * 1024 * 1024;

    fn get(&mut self, key: MappingKey) -> Option<Rc<Vec<u8>>> {
        let i = self.entries.iter().position(|(k, _)| *k == key)?;
        let entry = self.entries.remove(i).unwrap();
        let bytes = Rc::clone(&entry.1);
        self.entries.push_back(entry);
        Some(bytes)
    }

    fn insert(&mut self, key: MappingKey, bytes: Rc<Vec<u8>>) {
        if bytes.capacity() > Self::BUDGET {
            return;
        }
        let mut used: usize = self.entries.iter().map(|(_, data)| data.capacity()).sum();
        while used + bytes.capacity() > Self::BUDGET {
            used -= self.entries.pop_front().unwrap().1.capacity();
        }
        self.entries.push_back((key, bytes));
    }
}

pub struct Vfs {
    pub(super) overlay: PathBuf,
    pub fds: HashMap<u32, OpenFile>,
    pub cwd: String,
    /// Firmware paths deleted or renamed away by the guest.
    pub(super) deleted: std::collections::HashSet<String>,
    /// Shared memory objects by `shm_open` name.
    pub shm: HashMap<String, std::rc::Rc<std::cell::RefCell<Shm>>>,
    pub shm_maps: Vec<ShmMap>,
    pub file_maps: Vec<FileMap>,
    #[cfg(target_os = "emscripten")]
    mapping_cache: MappingCache,
}

pub enum Resolved<'a> {
    Firmware(&'a Node),
    Host(PathBuf),
}

pub fn normalize(cwd: &str, path: &str) -> String {
    let full = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("{cwd}/{path}")
    };
    let mut parts: Vec<&str> = Vec::new();
    for c in full.split('/') {
        match c {
            "" | "." => (),
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    format!("/{}", parts.join("/"))
}

impl Vfs {
    /// A new process's standard input, output and error.
    pub fn stdio() -> HashMap<u32, OpenFile> {
        let mut fds = HashMap::new();
        for fd in 0..3 {
            fds.insert(
                fd,
                OpenFile {
                    kind: FileKind::Console,
                    offset: 0,
                    path: "/dev/console".into(),
                    flags: O_RDWR,
                },
            );
        }
        fds
    }

    pub fn new(overlay: &Path) -> Vfs {
        let _ = std::fs::create_dir_all(overlay);
        Vfs {
            overlay: overlay.to_path_buf(),
            fds: Self::stdio(),
            cwd: "/".into(),
            deleted: Default::default(),
            shm: HashMap::new(),
            shm_maps: Vec::new(),
            file_maps: Vec::new(),
            #[cfg(target_os = "emscripten")]
            mapping_cache: MappingCache::default(),
        }
    }

    pub fn alloc_fd(&mut self, file: OpenFile) -> u32 {
        let fd = (0..).find(|fd| !self.fds.contains_key(fd)).unwrap();
        self.fds.insert(fd, file);
        fd
    }

    /// Only the data partition is writable; the system partition is mounted
    /// read-only, as on the device.
    fn writable(canon: &str) -> bool {
        canon == "/private/var" || canon.starts_with("/private/var/")
    }

    pub fn host_path(&self, path: &str) -> PathBuf {
        // Characters a host may treat as path syntax (e.g. "/C:/x" on
        // Windows) are escaped so no guest path can leave the overlay.
        let mut p = self.overlay.clone();
        for c in path.split('/') {
            if !c.is_empty() && c != "." && c != ".." {
                p.push(
                    c.replace('%', "%25")
                        .replace(':', "%3A")
                        .replace('\\', "%5C"),
                );
            }
        }
        p
    }

    /// Resolves symlinks in the firmware's directories so the overlay sees
    /// canonical paths (e.g. /var -> /private/var).
    pub fn canonical(&self, fw: &Firmware, path: &str) -> String {
        let path = normalize(&self.cwd, path);
        let mut out = String::new();
        let comps: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        for (i, c) in comps.iter().enumerate() {
            let candidate = format!("{out}/{c}");
            if i + 1 < comps.len() {
                if let Some(n) = fw.volume.lookup(&candidate, false) {
                    if n.is_symlink() {
                        if let Ok(t) = fw.volume.read_all(n) {
                            let t = String::from_utf8_lossy(&t).into_owned();
                            out = normalize(if out.is_empty() { "/" } else { &out }, &t);
                            continue;
                        }
                    }
                }
            }
            out = candidate;
        }
        if out.is_empty() {
            "/".into()
        } else {
            out
        }
    }

    /// Like [Self::canonical], but also follows a symlink in the last
    /// component, as listing a directory does.
    pub fn canonical_dir(&self, fw: &Firmware, path: &str) -> String {
        let c = self.canonical(fw, &format!("{path}/_"));
        c.strip_suffix("/_")
            .filter(|c| !c.is_empty())
            .unwrap_or("/")
            .to_string()
    }

    pub fn resolve<'a>(&self, fw: &'a Firmware, path: &str, follow: bool) -> Option<Resolved<'a>> {
        let path = self.canonical(fw, path);
        let host = self.host_path(&path);
        if std::fs::symlink_metadata(&host).is_ok() {
            return Some(Resolved::Host(host));
        }
        if self.deleted.contains(&path) {
            return None;
        }
        fw.volume.lookup(&path, follow).map(Resolved::Firmware)
    }

    pub fn stat(&self, fw: &Firmware, path: &str, follow: bool) -> Result<Stat, u32> {
        if let Some(dev) = Self::device(path) {
            return Ok(Stat {
                mode: 0o20666,
                ino: 1000 + dev as u64,
                size: 0,
                uid: 0,
                gid: 0,
                mtime: 0,
                nlink: 1,
            });
        }
        match self.resolve(fw, path, follow).ok_or(ENOENT)? {
            Resolved::Firmware(n) => Ok(Self::node_stat(fw, n)),
            Resolved::Host(p) => Self::host_stat(&p),
        }
    }

    pub fn node_stat(fw: &Firmware, n: &Node) -> Stat {
        Stat {
            mode: n.mode,
            ino: n.id as u64,
            size: if n.is_dir() { 0 } else { fw.volume.size(n) },
            uid: n.uid,
            gid: n.gid,
            mtime: n.mtime,
            nlink: 1,
        }
    }

    fn host_stat(p: &Path) -> Result<Stat, u32> {
        let m = std::fs::symlink_metadata(p).map_err(|_| ENOENT)?;
        let mode = if m.is_dir() {
            0o40755
        } else if m.file_type().is_symlink() {
            0o120755
        } else {
            Self::host_file_mode(&m)
        };
        let mtime = m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs() as u32);
        Ok(Stat {
            mode,
            ino: Self::host_ino(&m),
            size: m.len(),
            uid: 501,
            gid: 501,
            mtime,
            nlink: 1,
        })
    }

    /// A host file's permission bits, so an installed app's executable
    /// stays executable.
    #[cfg(unix)]
    fn host_file_mode(m: &std::fs::Metadata) -> u16 {
        use std::os::unix::fs::PermissionsExt;
        0o100000 | (m.permissions().mode() & 0o777) as u16
    }

    #[cfg(not(unix))]
    fn host_file_mode(_: &std::fs::Metadata) -> u16 {
        0o100644
    }

    /// A host file's own inode number, so files stay apart. SQLite keys its
    /// locks by device and inode, and its databases hang or fail when all
    /// files share one.
    #[cfg(unix)]
    fn host_ino(m: &std::fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        0x10000000 + m.ino()
    }

    #[cfg(not(unix))]
    fn host_ino(_: &std::fs::Metadata) -> u64 {
        0x10000000
    }

    fn device(path: &str) -> Option<u8> {
        match path {
            "/dev/null" | "/dev/zero" => Some(0),
            "/dev/console" | "/dev/tty" => Some(1),
            "/dev/random" | "/dev/urandom" => Some(2),
            _ => None,
        }
    }

    pub fn open(&mut self, fw: &Firmware, path: &str, flags: u32) -> Result<u32, u32> {
        if let Some(dev) = Self::device(path) {
            let kind = match dev {
                0 => FileKind::Null,
                1 => FileKind::Console,
                _ => FileKind::Random,
            };
            return Ok(self.alloc_fd(OpenFile {
                kind,
                offset: 0,
                path: path.into(),
                flags,
            }));
        }
        let canon = self.canonical(fw, path);
        let writing = flags & 3 != 0 || flags & (O_CREAT | O_TRUNC) != 0;
        let existing = self.resolve(fw, &canon, true);
        if existing.is_some() && flags & O_CREAT != 0 && flags & O_EXCL != 0 {
            return Err(EEXIST);
        }
        let kind = match existing {
            Some(Resolved::Firmware(n)) if n.is_dir() => {
                let entries = self.list_dir(fw, &self.canonical_dir(fw, &canon));
                FileKind::Dir {
                    path: canon.clone(),
                    entries,
                    pos: 0,
                }
            }
            Some(Resolved::Firmware(n)) if !writing => FileKind::Firmware { node: n.id },
            Some(Resolved::Host(p)) if p.is_dir() => {
                let entries = self.list_dir(fw, &self.canonical_dir(fw, &canon));
                FileKind::Dir {
                    path: canon.clone(),
                    entries,
                    pos: 0,
                }
            }
            existing => {
                if !Self::writable(&canon) {
                    return Err(if existing.is_none() && flags & O_CREAT == 0 {
                        ENOENT
                    } else {
                        EROFS
                    });
                }
                // A missing file is only made with O_CREAT, so a failed open
                // must not leave its parent directories behind either.
                if existing.is_none() && flags & O_CREAT == 0 {
                    return Err(ENOENT);
                }
                // Copy up (or create) in the overlay.
                let host = self.host_path(&canon);
                if let Some(parent) = host.parent() {
                    std::fs::create_dir_all(parent).map_err(|_| EACCES)?;
                }
                match existing {
                    Some(Resolved::Firmware(n)) if !host.exists() && flags & O_TRUNC == 0 => {
                        std::fs::write(&host, fw.volume.read_all(n).map_err(|_| EACCES)?)
                            .map_err(|_| EACCES)?;
                    }
                    _ => (),
                }
                let mut opts = std::fs::OpenOptions::new();
                opts.read(true)
                    .write(writing)
                    .create(flags & O_CREAT != 0)
                    .truncate(flags & O_TRUNC != 0);
                FileKind::Host(opts.open(&host).map_err(|_| EACCES)?)
            }
        };
        self.deleted.remove(&canon);
        Ok(self.alloc_fd(OpenFile {
            kind,
            offset: 0,
            path: canon,
            flags,
        }))
    }

    /// Directory entries (name, DT_* type, inode), merging firmware and
    /// overlay.
    pub fn list_dir(&self, fw: &Firmware, canon: &str) -> Vec<(String, u8, u64)> {
        let mut entries: Vec<(String, u8, u64)> = vec![(".".into(), 4, 2), ("..".into(), 4, 2)];
        if let Some(dir) = fw.volume.lookup(canon, true) {
            for n in fw.volume.children(dir.id) {
                if self
                    .deleted
                    .contains(&format!("{}/{}", canon.trim_end_matches('/'), n.name))
                {
                    continue;
                }
                let t = if n.is_dir() {
                    4
                } else if n.is_symlink() {
                    10
                } else {
                    8
                };
                entries.push((n.name.clone(), t, n.id as u64));
            }
        }
        if let Ok(rd) = std::fs::read_dir(self.host_path(canon)) {
            for e in rd.flatten() {
                let name = e
                    .file_name()
                    .to_string_lossy()
                    .replace("%5C", "\\")
                    .replace("%3A", ":")
                    .replace("%25", "%");
                if entries.iter().any(|(n, _, _)| *n == name) {
                    continue;
                }
                let t = if e.path().is_dir() { 4 } else { 8 };
                entries.push((name, t, 0x10000000 + entries.len() as u64));
            }
        }
        entries
    }

    pub fn read_mapping(
        &mut self,
        fw: &Firmware,
        fd: u32,
        len: u32,
        offset: u64,
    ) -> Result<Rc<Vec<u8>>, u32> {
        #[cfg(target_os = "emscripten")]
        let key = match &self.fds.get(&fd).ok_or(EBADF)?.kind {
            // Admit large reads without letting one file fill the whole cache.
            FileKind::Firmware { node } if (256 * 1024..=32 * 1024 * 1024).contains(&len) => {
                Some(MappingKey {
                    node: *node,
                    offset,
                    len,
                })
            }
            _ => None,
        };
        #[cfg(target_os = "emscripten")]
        if let Some(bytes) = key.and_then(|key| self.mapping_cache.get(key)) {
            return Ok(bytes);
        }
        let mut data = vec![0; len as usize];
        let n = self.read(fw, fd, &mut data, Some(offset))?;
        data.truncate(n);
        let data = Rc::new(data);
        #[cfg(target_os = "emscripten")]
        if let Some(key) = key {
            self.mapping_cache.insert(key, Rc::clone(&data));
        }
        Ok(data)
    }

    pub fn read(
        &mut self,
        fw: &Firmware,
        fd: u32,
        buf: &mut [u8],
        offset: Option<u64>,
    ) -> Result<usize, u32> {
        let f = self.fds.get_mut(&fd).ok_or(EBADF)?;
        let pos = offset.unwrap_or(f.offset);
        let n = match &mut f.kind {
            FileKind::Firmware { node } => {
                let node = fw.volume.lookup_id(*node).ok_or(EBADF)?;
                fw.volume.read(node, buf, pos).map_err(|_| EACCES)?
            }
            FileKind::Host(file) => {
                file.seek(SeekFrom::Start(pos)).map_err(|_| EINVAL)?;
                file.read(buf).map_err(|_| EACCES)?
            }
            FileKind::Null | FileKind::Console => 0,
            FileKind::Random => {
                use std::hash::{BuildHasher, Hasher};
                for chunk in buf.chunks_mut(8) {
                    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
                    h.write_u64(pos);
                    let n = chunk.len();
                    chunk.copy_from_slice(&h.finish().to_le_bytes()[..n]);
                }
                buf.len()
            }
            FileKind::Socket(s) => s.read(buf),
            FileKind::Kqueue(_) | FileKind::Shm(_) => return Err(EINVAL),
            FileKind::Dir { .. } => return Err(EISDIR),
        };
        if offset.is_none() {
            f.offset = pos + n as u64;
        }
        Ok(n)
    }

    pub fn write(&mut self, fd: u32, buf: &[u8], offset: Option<u64>) -> Result<usize, u32> {
        let f = self.fds.get_mut(&fd).ok_or(EBADF)?;
        match &mut f.kind {
            FileKind::Console => {
                echo!("[guest] {}", String::from_utf8_lossy(buf).trim_end());
                Ok(buf.len())
            }
            FileKind::Null | FileKind::Random => Ok(buf.len()),
            FileKind::Socket(s) => Ok(s.write(buf)),
            FileKind::Kqueue(_) | FileKind::Shm(_) => Err(EINVAL),
            FileKind::Host(file) => {
                let pos = if f.flags & O_APPEND != 0 {
                    file.seek(SeekFrom::End(0)).map_err(|_| EINVAL)?
                } else {
                    offset.unwrap_or(f.offset)
                };
                file.seek(SeekFrom::Start(pos)).map_err(|_| EINVAL)?;
                file.write_all(buf).map_err(|_| EACCES)?;
                if offset.is_none() {
                    f.offset = pos + buf.len() as u64;
                }
                Ok(buf.len())
            }
            FileKind::Firmware { .. } | FileKind::Dir { .. } => Err(EBADF),
        }
    }

    pub fn fstat(&self, fw: &Firmware, fd: u32) -> Result<Stat, u32> {
        let f = self.fds.get(&fd).ok_or(EBADF)?;
        match &f.kind {
            FileKind::Firmware { node } => Ok(Self::node_stat(
                fw,
                fw.volume.lookup_id(*node).ok_or(EBADF)?,
            )),
            FileKind::Host(file) => {
                let m = file.metadata().map_err(|_| EBADF)?;
                Ok(Stat {
                    mode: Self::host_file_mode(&m),
                    ino: Self::host_ino(&m),
                    size: m.len(),
                    uid: 501,
                    gid: 501,
                    mtime: 0,
                    nlink: 1,
                })
            }
            FileKind::Dir { path, .. } => self.stat(fw, &path.clone(), true),
            FileKind::Shm(shm) => Ok(Stat {
                mode: 0o100600,
                ino: 2000,
                size: shm.borrow().data.len() as u64,
                uid: 501,
                gid: 501,
                mtime: 0,
                nlink: 1,
            }),
            _ => Ok(Stat {
                mode: 0o20666,
                ino: 1000,
                size: 0,
                uid: 0,
                gid: 0,
                mtime: 0,
                nlink: 1,
            }),
        }
    }

    pub fn mkdir(&self, fw: &Firmware, path: &str) -> Result<(), u32> {
        if self.resolve(fw, path, false).is_some() {
            return Err(EEXIST);
        }
        let canon = self.canonical(fw, path);
        if !Self::writable(&canon) {
            return Err(EROFS);
        }
        std::fs::create_dir_all(self.host_path(&canon)).map_err(|_| EACCES)
    }

    pub fn unlink(&mut self, fw: &Firmware, path: &str) -> Result<(), u32> {
        let canon = self.canonical(fw, path);
        match self.resolve(fw, path, false).ok_or(ENOENT)? {
            Resolved::Host(p) => {
                std::fs::remove_file(&p)
                    .or_else(|_| std::fs::remove_dir(&p))
                    .map_err(|_| EACCES)?;
                if fw.volume.lookup(&canon, false).is_some() {
                    self.deleted.insert(canon);
                }
                Ok(())
            }
            Resolved::Firmware(_) => Err(EACCES),
        }
    }

    pub fn rename(&mut self, fw: &Firmware, from: &str, to: &str) -> Result<(), u32> {
        let (from_canon, to_canon) = (self.canonical(fw, from), self.canonical(fw, to));
        if !Self::writable(&to_canon) {
            return Err(EROFS);
        }
        match self.resolve(fw, from, false).ok_or(ENOENT)? {
            Resolved::Host(p) => {
                let dest = self.host_path(&to_canon);
                if let Some(parent) = dest.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                std::fs::rename(p, dest).map_err(|_| EACCES)?;
                if fw.volume.lookup(&from_canon, false).is_some() {
                    self.deleted.insert(from_canon);
                }
                self.deleted.remove(&to_canon);
                Ok(())
            }
            Resolved::Firmware(_) => Err(EACCES),
        }
    }

    pub fn readlink(&self, fw: &Firmware, path: &str) -> Result<Vec<u8>, u32> {
        match self.resolve(fw, path, false).ok_or(ENOENT)? {
            Resolved::Firmware(n) if n.is_symlink() => fw.volume.read_all(n).map_err(|_| EACCES),
            Resolved::Host(p) => std::fs::read_link(p)
                .map(|t| t.to_string_lossy().into_owned().into_bytes())
                .map_err(|_| EINVAL),
            _ => Err(EINVAL),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MappingCache, MappingKey, Rc};

    #[test]
    fn firmware_mapping_cache_matches_ranges_and_evicts_least_recently_used() {
        let mut cache = MappingCache::default();
        let key = |offset| MappingKey {
            node: 1,
            offset,
            len: 1024,
        };
        let entry = || Rc::new(Vec::with_capacity(MappingCache::BUDGET / 3 + 1));
        let first = entry();
        cache.insert(key(0), Rc::clone(&first));
        cache.insert(key(1024), entry());
        assert!(cache.get(MappingKey { len: 512, ..key(0) }).is_none());
        assert!(cache.get(MappingKey { node: 2, ..key(0) }).is_none());
        assert!(Rc::ptr_eq(&cache.get(key(0)).unwrap(), &first));
        cache.insert(key(2048), entry());
        assert!(cache.get(key(1024)).is_none());
        assert!(cache.get(key(0)).is_some());
        assert!(cache.get(key(2048)).is_some());
    }
}
