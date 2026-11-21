/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! The I/O Registry behind the master port from `host_get_io_master`.
//!
//! IOKitLib in the firmware sends these MIG requests (the `iokit` subsystem,
//! IDs 2800 and up). The registry describes the device the IPSW is for, so
//! for example SpringBoard finds its `N82AP.plist` from `IODeviceTree:/`.

use super::mach::{le, ool_reply, reply, KObject, KERN_SUCCESS, MACH_MSG_TYPE_PORT_SEND};
use super::{write_bytes, Kernel};
use crate::firmware::IpswInfo;

const KIO_RETURN_NOT_FOUND: u32 = 0xe00002f0;

pub enum Prop {
    Data(Vec<u8>),
}

pub struct Entry {
    pub name: String,
    pub class: String,
    pub parent: Option<usize>,
    pub children: Vec<usize>,
    pub props: Vec<(String, Prop)>,
}

impl Entry {
    /// Every entry is an `IOService`, which is an `IORegistryEntry`.
    pub fn conforms_to(&self, class: &str) -> bool {
        self.class == class || class == "IOService" || class == "IORegistryEntry"
    }
}

pub struct Registry {
    pub entries: Vec<Entry>,
}

/// A device tree property: NUL-terminated strings back to back.
fn strings(parts: &[&str]) -> Prop {
    let mut v = Vec::new();
    for p in parts {
        v.extend(p.as_bytes());
        v.push(0);
    }
    Prop::Data(v)
}

impl Registry {
    pub fn new(info: &IpswInfo) -> Registry {
        let board = info.board_config.to_ascii_uppercase();
        let target = board.strip_suffix("AP").unwrap_or(&board).to_string();
        let mut r = Registry {
            entries: Vec::new(),
        };
        let root = r.add(
            None,
            "device-tree",
            "IOPlatformExpertDevice",
            vec![
                (
                    "compatible",
                    strings(&[&board, &info.product_type, "AppleARM"]),
                ),
                ("model", strings(&[&info.product_type])),
                ("name", strings(&["device-tree"])),
                ("target-type", strings(&[&target])),
                ("platform-name", strings(&[&info.platform])),
                ("serial-number", strings(&["TOUCHHLE000"])),
            ],
        );
        r.add(
            Some(root),
            "chosen",
            "IOService",
            vec![("name", strings(&["chosen"]))],
        );
        r
    }

    fn add(
        &mut self,
        parent: Option<usize>,
        name: &str,
        class: &str,
        props: Vec<(&str, Prop)>,
    ) -> usize {
        let idx = self.entries.len();
        self.entries.push(Entry {
            name: name.to_string(),
            class: class.to_string(),
            parent,
            children: Vec::new(),
            props: props.into_iter().map(|(k, v)| (k.to_string(), v)).collect(),
        });
        if let Some(p) = parent {
            self.entries[p].children.push(idx);
        }
        idx
    }

    /// Looks up a path like `IODeviceTree:/chosen`. Every plane shares the
    /// one tree.
    pub fn lookup_path(&self, path: &str) -> Option<usize> {
        let (_plane, rest) = path.split_once(':')?;
        let mut cur = 0;
        for comp in rest.split('/').filter(|c| !c.is_empty()) {
            cur = *self.entries[cur]
                .children
                .iter()
                .find(|&&c| self.entries[c].name == comp)?;
        }
        Some(cur)
    }

    /// Entries matching a serialized matching dictionary. Only
    /// `IOProviderClass` and `IONameMatch` with string values are understood.
    pub fn matching(&self, dict: &str) -> Vec<usize> {
        let value = |key: &str| {
            let k = format!("<key>{key}</key>");
            let rest = dict[dict.find(&k)? + k.len()..].trim_start();
            let rest = rest.strip_prefix("<string")?;
            let rest = &rest[rest.find('>')? + 1..];
            Some(&rest[..rest.find('<')?])
        };
        let (class, name) = (value("IOProviderClass"), value("IONameMatch"));
        if class.is_none() && name.is_none() {
            return Vec::new();
        }
        (0..self.entries.len())
            .filter(|&i| {
                let e = &self.entries[i];
                class.is_none_or(|c| e.conforms_to(c)) && name.is_none_or(|n| e.name == n)
            })
            .collect()
    }

    fn prop(&self, entry: usize, key: &str) -> Option<&Prop> {
        self.entries[entry]
            .props
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() {
                T[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// The XML format `IOCFUnserialize` reads.
fn serialize(p: &Prop, out: &mut String) {
    match p {
        Prop::Data(d) => *out += &format!("<data>{}</data>", base64(d)),
    }
}

/// A MIG `c_string` argument (offset, count, characters padded to 4 bytes)
/// at `off`; returns it and the offset after it.
fn in_string(msg: &[u8], off: usize) -> (String, usize) {
    let cnt = le(msg, off + 4) as usize;
    let start = (off + 8).min(msg.len());
    let bytes = &msg[start..(start + cnt).min(msg.len())];
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    let s = String::from_utf8_lossy(&bytes[..end]).into_owned();
    (s, off + 8 + cnt.div_ceil(4) * 4)
}

/// Reply body for a routine with one `c_string` out argument.
fn out_string(s: &str) -> Vec<u32> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.push(0);
    let mut body = vec![KERN_SUCCESS, 0, bytes.len() as u32];
    bytes.resize(bytes.len().div_ceil(4) * 4, 0);
    body.extend(
        bytes
            .chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap())),
    );
    body
}

/// Replies with `data` as an out-of-line buffer in fresh guest memory.
fn ool_data(k: &mut Kernel, msg: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let addr = k.vm_allocate(0, data.len() as u32, 0, 1, "iokit")?;
    write_bytes(&mut k.mem, addr, data);
    const MACH_MSG_OOL_DESCRIPTOR: u32 = 1;
    const MACH_MSG_VIRTUAL_COPY: u32 = 1;
    let flags = MACH_MSG_OOL_DESCRIPTOR << 24 | MACH_MSG_VIRTUAL_COPY << 8;
    Some(ool_reply(msg, addr, data.len() as u32, flags))
}

/// Handles an IOKit MIG request to `obj`, or returns `None` if unknown.
pub fn msg(k: &mut Kernel, obj: KObject, msg: &[u8]) -> Option<Vec<u8>> {
    let id = le(msg, 20);
    let port_reply = |name: u32| Some(reply(msg, &[], &[(name, MACH_MSG_TYPE_PORT_SEND)]));
    let err = |kr: u32| Some(reply(msg, &[kr], &[]));
    // Simple requests start their arguments after the header and NDR.
    const ARGS: usize = 32;
    match (id, obj) {
        // io_service_get_matching_services(master, matching)
        (2804, KObject::IoMaster) => {
            let (dict, _) = in_string(msg, ARGS);
            let items = k.iokit.matching(&dict);
            log_dbg!("xnu: IOKit matching {dict} -> {} entries", items.len());
            let it = k.ipc.new_kernel_port(KObject::IoIterator { items, pos: 0 });
            port_reply(it)
        }
        // io_registry_entry_from_path(master, path)
        (2809, KObject::IoMaster) => {
            let (path, _) = in_string(msg, ARGS);
            match k.iokit.lookup_path(&path) {
                Some(e) => port_reply(k.ipc.new_kernel_port(KObject::IoEntry(e))),
                None => err(KIO_RETURN_NOT_FOUND),
            }
        }
        // io_registry_get_root_entry(master)
        (2827, KObject::IoMaster) => port_reply(k.ipc.new_kernel_port(KObject::IoEntry(0))),
        // io_iterator_next(iterator)
        (2802, KObject::IoIterator { items, pos }) => {
            let port = le(msg, 8);
            if let Some(Some(KObject::IoIterator { pos, .. })) =
                k.ipc.ports.get_mut(&port).map(|p| p.kobject.as_mut())
            {
                *pos += 1;
            }
            let next = match items.get(pos) {
                Some(&e) => k.ipc.new_kernel_port(KObject::IoEntry(e)),
                None => 0,
            };
            port_reply(next)
        }
        // io_iterator_reset(iterator)
        (2803, KObject::IoIterator { .. }) => {
            let port = le(msg, 8);
            if let Some(Some(KObject::IoIterator { pos, .. })) =
                k.ipc.ports.get_mut(&port).map(|p| p.kobject.as_mut())
            {
                *pos = 0;
            }
            err(KERN_SUCCESS)
        }
        // io_iterator_is_valid(iterator)
        (2834, KObject::IoIterator { .. }) => Some(reply(msg, &[KERN_SUCCESS, 1], &[])),
        // io_object_get_class(object)
        (2800, KObject::IoEntry(e)) => {
            Some(reply(msg, &out_string(&k.iokit.entries[e].class), &[]))
        }
        (2800, KObject::IoIterator { .. }) => Some(reply(msg, &out_string("IOUserIterator"), &[])),
        // io_object_conforms_to(object, class)
        (2801, KObject::IoEntry(e)) => {
            let (class, _) = in_string(msg, ARGS);
            let conforms = k.iokit.entries[e].conforms_to(&class);
            Some(reply(msg, &[KERN_SUCCESS, conforms as u32], &[]))
        }
        // io_registry_entry_get_name(entry)
        (2810, KObject::IoEntry(e)) => Some(reply(msg, &out_string(&k.iokit.entries[e].name), &[])),
        // io_registry_entry_get_property(entry, name),
        // io_registry_entry_get_property_recursively(entry, plane, name,
        // options): kIORegistryIterateParents is the only option a single
        // tree needs
        (2805 | 2855, KObject::IoEntry(e)) => {
            let (key, p) = if id == 2805 {
                (
                    in_string(msg, ARGS).0,
                    k.iokit.prop(e, &in_string(msg, ARGS).0),
                )
            } else {
                let (_plane, next) = in_string(msg, ARGS);
                let (key, next) = in_string(msg, next);
                const K_IO_REGISTRY_ITERATE_PARENTS: u32 = 2;
                let parents = le(msg, next) & K_IO_REGISTRY_ITERATE_PARENTS != 0;
                let mut cur = Some(e);
                let mut found = None;
                while let (Some(c), None) = (cur, found) {
                    found = k.iokit.prop(c, &key);
                    cur = k.iokit.entries[c].parent.filter(|_| parents);
                }
                (key, found)
            };
            let Some(p) = p else {
                log_dbg!("xnu: IOKit {}: no property {key}", k.iokit.entries[e].name);
                return err(KIO_RETURN_NOT_FOUND);
            };
            let mut xml = String::new();
            serialize(p, &mut xml);
            let mut data = xml.into_bytes();
            data.push(0);
            ool_data(k, msg, &data)
        }
        // io_registry_entry_get_properties(entry)
        (2811, KObject::IoEntry(e)) => {
            let mut xml = String::from("<dict>");
            for (key, p) in &k.iokit.entries[e].props {
                xml += &format!("<key>{}</key>", escape(key));
                serialize(p, &mut xml);
            }
            xml += "</dict>";
            let mut data = xml.into_bytes();
            data.push(0);
            ool_data(k, msg, &data)
        }
        // io_registry_entry_get_property_bytes(entry, name, dataCnt)
        (2812, KObject::IoEntry(e)) => {
            let (key, next) = in_string(msg, ARGS);
            let max = le(msg, next) as usize;
            let mut bytes = match k.iokit.prop(e, &key) {
                Some(Prop::Data(d)) => d.clone(),
                None => return err(KIO_RETURN_NOT_FOUND),
            };
            bytes.truncate(max);
            let mut body = vec![KERN_SUCCESS, bytes.len() as u32];
            bytes.resize(bytes.len().div_ceil(4) * 4, 0);
            body.extend(
                bytes
                    .chunks(4)
                    .map(|c| u32::from_le_bytes(c.try_into().unwrap())),
            );
            Some(reply(msg, &body, &[]))
        }
        // io_registry_entry_get_child_iterator(entry, plane),
        // io_registry_entry_get_parent_iterator(entry, plane)
        (2813 | 2814, KObject::IoEntry(e)) => {
            let entry = &k.iokit.entries[e];
            let items = if id == 2813 {
                entry.children.clone()
            } else {
                entry.parent.into_iter().collect()
            };
            let it = k.ipc.new_kernel_port(KObject::IoIterator { items, pos: 0 });
            port_reply(it)
        }
        _ => None,
    }
}
