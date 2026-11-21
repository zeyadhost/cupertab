/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Read-only HFS+/HFSX volume reader.
//!
//! The catalog and extents-overflow B-trees are indexed in full when the
//! volume is opened (an iPhone OS root filesystem has ~20k entries), which
//! avoids needing HFS+ key comparison rules for lookups.

use super::{be16, be32, be64, ReadAt};
use std::collections::HashMap;
use std::io;

pub const ROOT_FOLDER_ID: u32 = 2;
const S_IFMT: u16 = 0o170000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFREG: u16 = 0o100000;
pub const S_IFLNK: u16 = 0o120000;

#[derive(Debug, Clone, Copy, Default)]
struct Extent {
    start: u32,
    count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Fork {
    pub size: u64,
    extents: Vec<Extent>,
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: u32,
    pub parent: u32,
    pub name: String,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    /// Hard link target (`iNode<n>`) for files that are hard links.
    link_inode: Option<u32>,
    pub data: Fork,
}

impl Node {
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & S_IFMT == S_IFLNK
    }
}

pub struct Volume<R: ReadAt> {
    dev: R,
    /// Byte offset of the volume within `dev`.
    base: u64,
    block_size: u64,
    nodes: HashMap<u32, Node>,
    children: HashMap<u32, Vec<u32>>,
    by_name: HashMap<(u32, String), u32>,
    private_dir: Option<u32>,
}

/// HFS+ dates are seconds since 1904; convert to the Unix epoch.
fn hfs_to_unix(t: u32) -> u32 {
    t.wrapping_sub(2082844800)
}

fn parse_fork(b: &[u8]) -> Fork {
    let mut extents = Vec::new();
    for i in 0..8 {
        let e = &b[16 + i * 8..];
        let count = be32(&e[4..]);
        if count != 0 {
            extents.push(Extent {
                start: be32(e),
                count,
            });
        }
    }
    Fork {
        size: be64(b),
        extents,
    }
}

impl<R: ReadAt> Volume<R> {
    pub fn new(dev: R, base: u64) -> Result<Self, String> {
        let mut vh = [0u8; 512];
        dev.read_exact_at(&mut vh, base + 1024)
            .map_err(|e| e.to_string())?;
        if &vh[0..2] != b"H+" && &vh[0..2] != b"HX" {
            return Err("Not an HFS+ volume".to_string());
        }
        let mut vol = Volume {
            dev,
            base,
            block_size: be32(&vh[0x28..]) as u64,
            nodes: HashMap::new(),
            children: HashMap::new(),
            by_name: HashMap::new(),
            private_dir: None,
        };
        let extents_file = parse_fork(&vh[0xc0..]);
        let mut catalog_file = parse_fork(&vh[0x110..]);

        let mut overflow: HashMap<u32, Vec<(u32, Vec<Extent>)>> = HashMap::new();
        vol.walk_btree(&extents_file, |key, rec| {
            // Key: keyLength, forkType, pad, fileID, startBlock
            if key.len() < 12 || key[2] != 0 {
                return; // resource fork extents are of no interest
            }
            let file_id = be32(&key[4..]);
            let start = be32(&key[8..]);
            let extents = parse_fork(&[&[0u8; 16][..], &rec[..64]].concat()).extents;
            overflow.entry(file_id).or_default().push((start, extents));
        })?;

        const CATALOG_FILE_ID: u32 = 4;
        if let Some(records) = overflow.get_mut(&CATALOG_FILE_ID) {
            records.sort_by_key(|(start, _)| *start);
            for (_, extents) in records.iter() {
                catalog_file.extents.extend(extents);
            }
        }

        let mut catalog_err = None;
        let mut nodes = HashMap::new();
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut by_name = HashMap::new();
        vol.walk_btree(&catalog_file, |key, rec| {
            let parent = be32(&key[2..]);
            let name_len = be16(&key[6..]) as usize;
            let name_units: Vec<u16> = (0..name_len).map(|i| be16(&key[8 + i * 2..])).collect();
            let name = String::from_utf16_lossy(&name_units);
            let kind = be16(rec);
            if kind != 1 && kind != 2 {
                return; // thread records
            }
            if rec.len() < 88 {
                catalog_err = Some("short catalog record".to_string());
                return;
            }
            let id = be32(&rec[8..]);
            let mut mode = be16(&rec[42..]);
            let mut node = Node {
                id,
                parent,
                name: name.clone(),
                mode: 0,
                uid: be32(&rec[32..]),
                gid: be32(&rec[36..]),
                mtime: hfs_to_unix(be32(&rec[16..])),
                link_inode: None,
                data: Fork::default(),
            };
            if kind == 1 {
                if mode & S_IFMT == 0 {
                    mode |= S_IFDIR | 0o755;
                }
            } else {
                if &rec[48..52] == b"hlnk" && &rec[52..56] == b"hfs+" {
                    node.link_inode = Some(be32(&rec[44..]));
                }
                if mode & S_IFMT == 0 {
                    mode |= S_IFREG | 0o644;
                }
                node.data = parse_fork(&rec[88..168]);
            }
            node.mode = mode;
            by_name.insert((parent, name), id);
            children.entry(parent).or_default().push(id);
            nodes.insert(id, node);
        })?;
        vol.nodes = nodes;
        vol.children = children;
        vol.by_name = by_name;
        if let Some(e) = catalog_err {
            return Err(e);
        }

        // Append overflow extents to forks that need them.
        for (file_id, mut records) in overflow {
            records.sort_by_key(|(start, _)| *start);
            if let Some(node) = vol.nodes.get_mut(&file_id) {
                for (_, extents) in records {
                    node.data.extents.extend(extents);
                }
            }
        }
        vol.private_dir = vol
            .by_name
            .get(&(ROOT_FOLDER_ID, "\0\0\0\0HFS+ Private Data".to_string()))
            .copied();
        Ok(vol)
    }

    fn read_fork(&self, fork: &Fork, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        if offset >= fork.size {
            return Ok(0);
        }
        let len = (buf.len() as u64).min(fork.size - offset) as usize;
        let mut done = 0;
        let mut ext_start = 0u64;
        for ext in &fork.extents {
            let ext_len = ext.count as u64 * self.block_size;
            let pos = offset + done as u64;
            if done < len && pos < ext_start + ext_len {
                let within = pos - ext_start;
                let n = ((ext_len - within) as usize).min(len - done);
                self.dev.read_exact_at(
                    &mut buf[done..done + n],
                    self.base + ext.start as u64 * self.block_size + within,
                )?;
                done += n;
            }
            ext_start += ext_len;
        }
        if done < len {
            return Err(io::Error::other("HFS+ fork shorter than its extents"));
        }
        Ok(len)
    }

    /// Calls `f(key, record)` for every leaf record of a B-tree.
    fn walk_btree(&self, fork: &Fork, mut f: impl FnMut(&[u8], &[u8])) -> Result<(), String> {
        let mut header = [0u8; 512];
        self.read_fork(fork, &mut header, 0)
            .map_err(|e| e.to_string())?;
        let node_size = be16(&header[14 + 18..]) as u64;
        let total_nodes = be32(&header[14 + 22..]);
        let mut node_idx = be32(&header[14 + 10..]);
        if node_size < 512 {
            return Err("Bad B-tree node size".to_string());
        }
        let bad = || "Corrupt B-tree node".to_string();
        let mut node = vec![0u8; node_size as usize];
        let mut visited = 0;
        while node_idx != 0 {
            visited += 1;
            if visited > total_nodes || node_idx >= total_nodes {
                return Err(bad());
            }
            self.read_fork(fork, &mut node, node_idx as u64 * node_size)
                .map_err(|e| e.to_string())?;
            let num_records = be16(&node[10..]) as usize;
            if 14 + 2 * (num_records + 1) > node.len() {
                return Err(bad());
            }
            for i in 0..num_records {
                let off_pos = node_size as usize - 2 * (i + 1);
                let start = be16(&node[off_pos..]) as usize;
                let end = be16(&node[off_pos - 2..]) as usize;
                let key_len = be16(node.get(start..).ok_or_else(bad)?) as usize + 2;
                let key_end = start + key_len + (key_len & 1);
                if start < 14 || key_end > end || end > off_pos - 2 {
                    return Err(bad());
                }
                f(&node[start..start + key_len], &node[key_end..end]);
            }
            node_idx = be32(&node[0..]);
        }
        Ok(())
    }

    pub fn lookup_id(&self, id: u32) -> Option<&Node> {
        self.nodes.get(&id)
    }

    pub fn child(&self, dir: u32, name: &str) -> Option<&Node> {
        self.by_name
            .get(&(dir, name.to_string()))
            .and_then(|id| self.nodes.get(id))
    }

    pub fn children(&self, dir: u32) -> impl Iterator<Item = &Node> {
        self.children
            .get(&dir)
            .into_iter()
            .flatten()
            .filter_map(|id| self.nodes.get(id))
            .filter(|n| !n.name.starts_with('\0') && !n.name.starts_with(".HFS+ Private"))
    }

    /// Follows a hard link to the node holding the file contents.
    pub fn resolve_hard_link<'a>(&'a self, node: &'a Node) -> &'a Node {
        if let (Some(inode), Some(private)) = (node.link_inode, self.private_dir) {
            if let Some(target) = self.child(private, &format!("iNode{inode}")) {
                return target;
            }
        }
        node
    }

    pub fn read(&self, node: &Node, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let node = self.resolve_hard_link(node);
        self.read_fork(&node.data, buf, offset)
    }

    pub fn size(&self, node: &Node) -> u64 {
        self.resolve_hard_link(node).data.size
    }

    pub fn read_all(&self, node: &Node) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; self.size(node) as usize];
        self.read(node, &mut buf, 0)?;
        Ok(buf)
    }

    /// Resolves an absolute path, following symlinks (including in the last
    /// component if `follow` is set).
    pub fn lookup(&self, path: &str, follow: bool) -> Option<&Node> {
        self.lookup_depth(path, follow, 0)
    }

    fn lookup_depth(&self, path: &str, follow: bool, depth: u32) -> Option<&Node> {
        if depth > 16 {
            return None;
        }
        let mut stack: Vec<u32> = vec![ROOT_FOLDER_ID];
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        for (i, comp) in components.iter().enumerate() {
            let cur = *stack.last().unwrap();
            match *comp {
                "." => continue,
                ".." => {
                    if stack.len() > 1 {
                        stack.pop();
                    }
                    continue;
                }
                _ => (),
            }
            let node = self.child(cur, comp)?;
            let last = i == components.len() - 1;
            if node.is_symlink() && (!last || follow) {
                let target = String::from_utf8(self.read_all(node).ok()?).ok()?;
                let mut base = String::new();
                if !target.starts_with('/') {
                    for id in &stack[1..] {
                        base.push('/');
                        base.push_str(&self.nodes[id].name);
                    }
                    base.push('/');
                }
                let rest = components[i + 1..].join("/");
                let full = format!("{base}{target}/{rest}");
                return self.lookup_depth(&full, follow, depth + 1);
            }
            if last {
                return Some(node);
            }
            if !node.is_dir() {
                return None;
            }
            stack.push(node.id);
        }
        self.nodes.get(stack.last().unwrap())
    }

    pub fn path_of(&self, mut id: u32) -> String {
        let mut parts = Vec::new();
        while id != ROOT_FOLDER_ID {
            let Some(n) = self.nodes.get(&id) else { break };
            parts.push(n.name.clone());
            id = n.parent;
        }
        parts.reverse();
        format!("/{}", parts.join("/"))
    }
}
