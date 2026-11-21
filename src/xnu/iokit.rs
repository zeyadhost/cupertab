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
use super::{read_u32, write_bytes, write_u32, Kernel};
use crate::firmware::IpswInfo;

const KIO_RETURN_NOT_FOUND: u32 = 0xe00002f0;
const KIO_RETURN_UNSUPPORTED: u32 = 0xe00002c7;
const MIG_BAD_ARGUMENTS: u32 = (-304i32) as u32;

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
    /// Every entry is an `IOService`, which is an `IORegistryEntry`, and the
    /// LCD controllers are `IOMobileFramebuffer`s.
    pub fn conforms_to(&self, class: &str) -> bool {
        self.class == class
            || class == "IOService"
            || class == "IORegistryEntry"
            || (class == "IOMobileFramebuffer" && self.class.ends_with("CLCD"))
    }
}

pub struct Registry {
    pub entries: Vec<Entry>,
    /// Surfaces made through `IOCoreSurfaceRoot`, by ID minus one.
    pub surfaces: Vec<Surface>,
    /// MBX2D's command buffer, allocated on first use.
    pub mbx_command_buffer: u32,
    /// Async notification ports set on user clients, by connection port.
    pub notify_ports: std::collections::HashMap<u32, u32>,
    /// Enabled framebuffer vsync callbacks, by connection port.
    pub vsyncs: std::collections::HashMap<u32, VSync>,
}

/// A framebuffer vsync callback, sent at 60 Hz as an async completion.
pub struct VSync {
    pub port: u32,
    pub callback: u32,
    pub refcon: u32,
    /// The absolute time of the next vsync.
    pub next: u64,
}

impl VSync {
    /// 24 MHz ticks per 60 Hz frame.
    pub const PERIOD: u64 = 400_000;

    /// The completion message IOKitLib dispatches to `callback(refcon,
    /// result, args, 6)`; the first two arguments are the time stamp.
    pub fn message(&self, time: u64) -> Vec<u8> {
        const OS_NOTIFICATION_MESSAGE_ID: u32 = 53;
        const ASYNC_COMPLETION_TYPE: u32 = 150;
        // The receiver sees a null remote port: IOKitLib skips the callout
        // when a remote port is set and it can't count its send rights.
        let mut words = vec![0, 92, 0, self.port, 0, OS_NOTIFICATION_MESSAGE_ID];
        words.extend([4 + 6 * 4, ASYNC_COMPLETION_TYPE]);
        words.extend([self.port, self.callback, self.refcon, 0, 0, 0, 0, 0]);
        words.extend([0, time as u32, (time >> 32) as u32, 0, 0, 0, 0]);
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}

/// An IOSurface: pixels in guest memory, shared by every client.
pub struct Surface {
    pub addr: u32,
    pub alloc_size: u32,
    pub width: u32,
    pub height: u32,
    pub bytes_per_row: u32,
    pub bytes_per_element: u32,
    pub pixel_format: u32,
    /// A small block whose word at offset 8 is the surface's seed.
    pub seed_block: u32,
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
            surfaces: Vec::new(),
            mbx_command_buffer: 0,
            notify_ports: Default::default(),
            vsyncs: Default::default(),
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
        // The LCD controller each SoC family has.
        let clcd = match info.platform.as_str() {
            "s5l8900x" => "AppleH1CLCD",
            "s5l8720x" | "s5l8920x" => "AppleM2CLCD",
            _ => "AppleCLCD",
        };
        r.add(Some(root), "clcd", clcd, vec![("name", strings(&["clcd"]))]);
        r.add(
            Some(root),
            "IOPMrootDomain",
            "IOPMrootDomain",
            vec![("name", strings(&["IOPMrootDomain"]))],
        );
        r.add(
            Some(root),
            "mbx",
            "AppleMBXDevice",
            vec![("name", strings(&["mbx"]))],
        );
        r.add(
            Some(root),
            "IOCoreSurfaceRoot",
            "IOCoreSurfaceRoot",
            vec![("name", strings(&["IOCoreSurfaceRoot"]))],
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
        let (plane, rest) = path.split_once(':')?;
        // Only the device tree plane is modelled as a hierarchy. In the other
        // planes, find a service by its own name, the path's last component.
        if plane != "IODeviceTree" {
            let Some(last) = rest.rsplit('/').find(|c| !c.is_empty()) else {
                return Some(0);
            };
            return self.entries.iter().position(|e| e.name == last);
        }
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
                None => {
                    log!("xnu: no I/O Registry entry at {path:?}");
                    err(KIO_RETURN_NOT_FOUND)
                }
            }
        }
        // io_service_open_extended(service, owning_task, connect_type, ndr,
        // properties): the reply carries the connection port, then the result.
        (2862, KObject::IoEntry(e)) => {
            let conn = k.ipc.new_kernel_port(KObject::IoConnect(e));
            Some(reply(
                msg,
                &[KERN_SUCCESS],
                &[(conn, MACH_MSG_TYPE_PORT_SEND)],
            ))
        }
        // io_connect_method(connection, selector, scalar_input, inband_input,
        // ool_input, ool_input_size, scalar_outputCnt, inband_outputCnt,
        // ool_output, ool_output_size)
        (2865, KObject::IoConnect(e)) => {
            // The guest controls every count here, so check each against the
            // message length.
            let word = |o: usize| msg.get(o..o + 4).map(|b| le(b, 0));
            let Some(n) = word(ARGS + 4).map(|n| n as usize).filter(|&n| n <= 16) else {
                return err(MIG_BAD_ARGUMENTS);
            };
            let inband_at = ARGS + 8 + 8 * n;
            let Some(inband_len) = word(inband_at).map(|n| n as usize).filter(|&n| n <= 4096)
            else {
                return err(MIG_BAD_ARGUMENTS);
            };
            let tail = inband_at + 4 + inband_len.div_ceil(4) * 4;
            if msg.len() < tail + 24 {
                return err(MIG_BAD_ARGUMENTS);
            }
            let selector = le(msg, ARGS);
            let scalars: Vec<u64> = (0..n)
                .map(|i| {
                    le(msg, ARGS + 8 + 8 * i) as u64 | (le(msg, ARGS + 12 + 8 * i) as u64) << 32
                })
                .collect();
            let inband = &msg[inband_at + 4..][..inband_len];
            let scalar_out_max = le(msg, tail + 8) as usize;
            let inband_out_max = le(msg, tail + 12) as usize;
            let class = k.iokit.entries[e].class.clone();
            if k.trace {
                echo!(
                    "xnu:   {class} selector {selector} {scalars:x?} inband {}",
                    inband.len()
                );
            }
            let result = if class.ends_with("CLCD") {
                framebuffer_method(k, le(msg, 8), selector, &scalars, inband)
            } else if class == "IOCoreSurfaceRoot" {
                surface_method(k, selector, &scalars, inband)
            } else if class == "AppleMBXDevice" {
                mbx_method(k, selector, &scalars)
            } else {
                None
            };
            let Some((scalar_out, inband_out)) = result else {
                log!("xnu: {class} user client: unhandled selector {selector} {scalars:x?}");
                return err(KIO_RETURN_UNSUPPORTED);
            };
            let mut body = vec![KERN_SUCCESS, scalar_out_max.min(scalar_out.len()) as u32];
            for &v in scalar_out.iter().take(scalar_out_max) {
                body.extend([v as u32, (v >> 32) as u32]);
            }
            let mut bytes = inband_out;
            bytes.truncate(inband_out_max);
            body.push(bytes.len() as u32);
            bytes.resize(bytes.len().div_ceil(4) * 4, 0);
            body.extend(bytes.chunks(4).map(|c| le(c, 0)));
            body.push(0); // ool_output_size
            Some(reply(msg, &body, &[]))
        }
        // io_connect_set_notification_port(connection, type, port, reference)
        // A complex request: the port descriptor comes first.
        (2818, KObject::IoConnect(_)) => {
            if le(msg, 0) & 0x80000000 != 0 && msg.len() >= 32 {
                k.iokit.notify_ports.insert(le(msg, 8), le(msg, 28));
            }
            err(KERN_SUCCESS)
        }
        // io_service_add_notification(master, notification_type, matching,
        // wake_port, reference): a complex request, so the strings follow the
        // port descriptor and NDR. Services never appear or go away, so a
        // publish notification's iterator holds the current matches, a
        // termination one is empty, and the wake port is never sent to.
        (2849, KObject::IoMaster) => {
            let (kind, next) = in_string(msg, 48);
            let (dict, _) = in_string(msg, next);
            let items = if kind.contains("Terminate") {
                Vec::new()
            } else {
                k.iokit.matching(&dict)
            };
            port_reply(k.ipc.new_kernel_port(KObject::IoIterator { items, pos: 0 }))
        }
        // io_service_add_interest_notification(service, type_of_interest,
        // wake_port, reference): complex, like 2849. Nothing ever changes
        // state, so the returned notification object never fires.
        (2850, KObject::IoEntry(_)) => port_reply(k.ipc.new_kernel_port(KObject::IoIterator {
            items: Vec::new(),
            pos: 0,
        })),
        // io_service_close(connection)
        (2816, KObject::IoConnect(_)) => {
            k.iokit.notify_ports.remove(&le(msg, 8));
            k.iokit.vsyncs.remove(&le(msg, 8));
            err(KERN_SUCCESS)
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

/// `IOMobileFramebuffer` user client selectors, answered for a display of the
/// device's size. Returns scalar and struct outputs.
fn framebuffer_method(
    k: &mut Kernel,
    connection: u32,
    selector: u32,
    scalars: &[u64],
    _inband: &[u8],
) -> Option<(Vec<u64>, Vec<u8>)> {
    let (w, h) = display_size(&k.fw.info.product_type);
    Some(match selector {
        // Display size in pixels.
        8 => (vec![w as u64, h as u64], Vec::new()),
        // Gamma table: three 256-entry ramps of 32-bit values.
        27 => {
            let mut t = Vec::with_capacity(3 * 256 * 4);
            for _ in 0..3 {
                for i in 0..256u32 {
                    t.extend((i * 0x101).to_le_bytes());
                }
            }
            (Vec::new(), t)
        }
        3 | 4 | 5 | 7 | 12 | 15 | 17 | 19 | 22 | 33 => (vec![0], Vec::new()),
        // Enable vsync notifications with (callback, refcon), or disable
        // them with a null callback.
        9 => {
            let callback = *scalars.first()? as u32;
            let refcon = scalars.get(1).map_or(0, |&v| v as u32);
            match k.iokit.notify_ports.get(&connection) {
                Some(&port) if callback != 0 => {
                    let next = k.absolute_time() + VSync::PERIOD;
                    let v = VSync {
                        port,
                        callback,
                        refcon,
                        next,
                    };
                    k.iokit.vsyncs.insert(connection, v);
                }
                _ => {
                    k.iokit.vsyncs.remove(&connection);
                }
            }
            (Vec::new(), Vec::new())
        }
        _ => return None,
    })
}

/// An integer in a property dictionary serialized by `IOCFSerialize`.
fn dict_int(dict: &str, key: &str) -> Option<u32> {
    let k = format!("<key>{key}</key>");
    let rest = dict[dict.find(&k)? + k.len()..].trim_start();
    let rest = rest.strip_prefix("<integer")?;
    let rest = &rest[rest.find('>')? + 1..];
    let v = rest[..rest.find('<')?].trim();
    match v.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => v.parse::<i64>().ok().map(|v| v as u32),
    }
}

/// The 0x4bc-byte description IOSurface.framework keeps for a surface.
fn surface_info(id: u32, s: &Surface) -> Vec<u8> {
    let mut out = vec![0u8; 0x4bc];
    let mut put = |o: usize, v: u32| out[o..o + 4].copy_from_slice(&v.to_le_bytes());
    put(0x00, s.addr);
    put(0x04, id);
    put(0x08, s.alloc_size);
    put(0x0c, s.width);
    put(0x10, s.height);
    put(0x14, s.bytes_per_row);
    put(0x1c, s.pixel_format);
    put(0x34, s.seed_block);
    out[0x2c..0x2e].copy_from_slice(&(s.bytes_per_element as u16).to_le_bytes());
    out[0x2e] = 1;
    out[0x2f] = 1;
    out
}

/// `IOCoreSurfaceRoot` user client methods, as IOSurface.framework calls
/// them.
/// MBX2D opens a device client (type 0), asks it for a token with selector 0,
/// then opens a shared client (type 1) and passes the token back to selector
/// 0 there before querying it with selector 2.
///
/// Selector 2 with an IOSurface ID maps that surface for the GPU. The reply
/// is a 20-byte struct: the handle MBX2D keys its surface table by, the
/// surface's address, and (fourth word) a pointer to a status word that
/// MBX2D sets to 1.
fn mbx_method(k: &mut Kernel, selector: u32, scalars: &[u64]) -> Option<(Vec<u64>, Vec<u8>)> {
    const SHARED_TOKEN: u64 = 1;
    Some(match (selector, scalars) {
        (0, []) => (vec![SHARED_TOKEN], Vec::new()),
        (0, [SHARED_TOKEN, ..]) => (Vec::new(), Vec::new()),
        // The command buffer: a header of capacity, bytes used, an unknown
        // word and the address of the commands. Selector 3 submits it and
        // returns the buffer to write next.
        (2, []) | (3, [_]) => {
            const CAPACITY: u32 = 0x10000;
            if k.iokit.mbx_command_buffer == 0 {
                let header = k.vm_allocate(0, 0x1000 + CAPACITY, 0, 1, "MBX commands")?;
                for (i, w) in [CAPACITY, 0, 0, header + 0x1000].into_iter().enumerate() {
                    write_u32(&mut k.mem, header + 4 * i as u32, w);
                }
                k.iokit.mbx_command_buffer = header;
            }
            let header = k.iokit.mbx_command_buffer;
            if selector == 3 {
                let used: u32 = read_u32(&k.mem, header + 4);
                if k.trace {
                    let words: Vec<u32> = (0..used.min(0x200) / 4)
                        .map(|i| read_u32(&k.mem, header + 0x1000 + 4 * i))
                        .collect();
                    echo!("xnu:   MBX commands ({used} bytes): {words:x?}");
                }
                run_mbx_commands(k, header + 0x1000, used.min(CAPACITY));
                write_u32(&mut k.mem, header + 4, 0);
            }
            (vec![header as u64], Vec::new())
        }
        // Unmap a surface.
        (5, [_]) => (Vec::new(), Vec::new()),
        (2, [id, _]) => {
            let id = u32::try_from(*id).ok().filter(|&id| id != 0)?;
            let addr = k.iokit.surfaces.get(id as usize - 1)?.addr;
            // The status word lives in the surface's own spare page, after
            // the seed.
            let status = k.iokit.surfaces.get(id as usize - 1)?.seed_block + 0x10;
            let words = [id, addr, 0, status, 0];
            (
                Vec::new(),
                words.iter().flat_map(|w| w.to_le_bytes()).collect(),
            )
        }
        _ => return None,
    })
}

/// Runs the 2D packets MBX2D wrote: each is a byte length followed by that
/// many bytes. Only solid fills (raster op 0xF0, pattern copy) are drawn so
/// far; their words are the packet type 4, flags, the destination surface,
/// addresses, the format, the raster op, the ARGB color and the corners as
/// `x << 16 | y`.
fn run_mbx_commands(k: &mut Kernel, start: u32, len: u32) {
    let mut at = start;
    let end = start + len;
    while at + 4 <= end {
        let n = read_u32(&k.mem, at);
        if n == 0 || !n.is_multiple_of(4) || n > end - at - 4 {
            break;
        }
        let w: Vec<u32> = (1..=n / 4).map(|i| read_u32(&k.mem, at + 4 * i)).collect();
        if w.len() >= 15 && w[0] == 4 && w[11] & 0xff == 0xf0 {
            let corner = |v: u32| (v >> 16, v & 0xffff);
            mbx_fill(k, w[4], w[12], corner(w[13]), corner(w[14]));
        }
        at += 4 + n;
    }
}

fn mbx_fill(k: &mut Kernel, id: u32, color: u32, (x0, y0): (u32, u32), (x1, y1): (u32, u32)) {
    let Some(s) = id
        .checked_sub(1)
        .and_then(|i| k.iokit.surfaces.get(i as usize))
    else {
        return;
    };
    if s.bytes_per_element != 4 {
        return;
    }
    let (x1, y1) = (x1.min(s.width), y1.min(s.height));
    if x0 >= x1 {
        return;
    }
    let row: Vec<u8> = (x0..x1).flat_map(|_| color.to_le_bytes()).collect();
    let (addr, bytes_per_row) = (s.addr, s.bytes_per_row);
    for y in y0..y1 {
        write_bytes(&mut k.mem, addr + y * bytes_per_row + x0 * 4, &row);
    }
}

fn surface_method(
    k: &mut Kernel,
    selector: u32,
    scalars: &[u64],
    inband: &[u8],
) -> Option<(Vec<u64>, Vec<u8>)> {
    let surface_id = || {
        scalars
            .first()
            .map(|&v| v as u32)
            .or_else(|| inband.get(..4).map(|b| le(b, 0)))
    };
    Some(match selector {
        // Create, from the serialized property dictionary.
        0 => {
            let dict = String::from_utf8_lossy(inband);
            let width = dict_int(&dict, "IOSurfaceWidth")?;
            let height = dict_int(&dict, "IOSurfaceHeight")?;
            let bytes_per_element = dict_int(&dict, "IOSurfaceBytesPerElement").unwrap_or(4);
            let bytes_per_row = dict_int(&dict, "IOSurfaceBytesPerRow")
                .unwrap_or(width * bytes_per_element)
                .next_multiple_of(16);
            let alloc_size = dict_int(&dict, "IOSurfaceAllocSize")
                .unwrap_or(0)
                .max(bytes_per_row.checked_mul(height)?);
            let pixel_format = dict_int(&dict, "IOSurfacePixelFormat").unwrap_or(0);
            let pages = alloc_size.checked_add(0xfff)? & !0xfff;
            let addr = k.vm_allocate(0, pages + 0x1000, 0, 1, "IOSurface")?;
            let surface = Surface {
                addr,
                alloc_size,
                width,
                height,
                bytes_per_row,
                bytes_per_element,
                pixel_format,
                seed_block: addr + pages,
            };
            let id = k.iokit.surfaces.len() as u32 + 1;
            log_dbg!("xnu: IOSurface {id}: {width}x{height}, {bytes_per_row} bytes/row");
            let info = surface_info(id, &surface);
            k.iokit.surfaces.push(surface);
            (Vec::new(), info)
        }
        // Limits: row alignment, then the largest width, height, row and
        // allocation.
        16 => {
            let limits = [1u32, 16, 4096, 4096 * 4, 64 << 20];
            (
                Vec::new(),
                limits.iter().flat_map(|v| v.to_le_bytes()).collect(),
            )
        }
        // Release, lock and unlock: the memory stays mapped and coherent.
        1..=3 => (Vec::new(), Vec::new()),
        // Look up by ID.
        6 => {
            let id = surface_id()?;
            let s = k.iokit.surfaces.get((id as usize).checked_sub(1)?)?;
            (Vec::new(), surface_info(id, s))
        }
        _ => return None,
    })
}

/// The panel size of a device, by product type.
pub fn display_size(product_type: &str) -> (u32, u32) {
    if product_type.starts_with("iPhone3,") || product_type.starts_with("iPod4,") {
        (640, 960)
    } else if product_type.starts_with("iPad") {
        (768, 1024)
    } else {
        (320, 480)
    }
}
