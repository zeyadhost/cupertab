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
use super::{read_u32, write_bytes, write_u32, Kernel, Mem};
use crate::firmware::IpswInfo;
use crate::mem::Ptr;

const KIO_RETURN_NOT_FOUND: u32 = 0xe00002f0;
const KIO_RETURN_UNSUPPORTED: u32 = 0xe00002c7;
const MIG_BAD_ARGUMENTS: u32 = (-304i32) as u32;

pub enum Prop {
    Data(Vec<u8>),
    Number(u32),
    Str(String),
    Dict(Vec<(String, Prop)>),
}

/// The touchscreen's class. IOHIDLib's generic event service plugin drives
/// it, so touches arrive as serialized `IOHIDEvent`s in a shared queue.
pub const HID_DRIVER: &str = "IOHIDEventDriver";
/// `kIOHIDServicePlugInTypeID`, which `IOHIDLib.plugin` provides.
const HID_SERVICE_PLUGIN_TYPE: &str = "0516B563-B15B-11DA-96EB-0014519758EF";
/// The size of each HID event queue, header included.
const HID_QUEUE_SIZE: u32 = 0x4000;

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
            || (class == "IOHIDEventService" && self.class == HID_DRIVER)
    }
}

pub struct Registry {
    pub entries: Vec<Entry>,
    /// Surfaces made through `IOCoreSurfaceRoot`, by ID minus one.
    pub surfaces: Vec<Surface>,
    /// The IOSurface the LCD shows, from the last swap.
    pub presented_surface: u32,
    /// The window server, the one process whose swaps reach the LCD.
    pub lcd_owner: Option<u32>,
    /// MBX2D's command buffer, allocated on first use.
    pub mbx_command_buffer: u32,
    /// Surfaces mapped for MBX2D: the IOSurface ID by mapping handle.
    pub mbx_handles: std::collections::HashMap<u32, u32>,
    pub next_mbx_handle: u32,
    /// Async notification ports set on user clients, by connection port.
    pub notify_ports: std::collections::HashMap<u32, u32>,
    /// Enabled framebuffer vsync callbacks, by connection port.
    pub vsyncs: std::collections::HashMap<u32, VSync>,
    /// Mapped HID event queues (`IODataQueueMemory`), by connection port.
    /// Each HID connection's event queue: the mapping process and address.
    pub hid_queues: std::collections::HashMap<u32, (u32, u32)>,
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
        let frame = time / Self::PERIOD;
        words.push(0);
        for v in [time, time, frame] {
            words.extend([v as u32, (v >> 32) as u32]);
        }
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}

/// An IOSurface: pixels in guest memory, shared by every client.
pub struct Surface {
    /// The process whose memory holds the pixels.
    pub pid: u32,
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
            presented_surface: 0,
            lcd_owner: None,
            mbx_command_buffer: 0,
            mbx_handles: Default::default(),
            // MBX2D keeps mapping handles and surface IDs in one table, so
            // handles start far above any surface ID.
            next_mbx_handle: 0x10000,
            notify_ports: Default::default(),
            vsyncs: Default::default(),
            hid_queues: Default::default(),
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
        r.add(
            Some(root),
            "multi-touch",
            HID_DRIVER,
            vec![
                (
                    "IOCFPlugInTypes",
                    Prop::Dict(vec![(
                        HID_SERVICE_PLUGIN_TYPE.into(),
                        Prop::Str("IOHIDFamily.kext/PlugIns/IOHIDLib.plugin".into()),
                    )]),
                ),
                // Digitizer, touch screen.
                ("PrimaryUsagePage", Prop::Number(0x0d)),
                ("PrimaryUsage", Prop::Number(0x04)),
                ("Transport", Prop::Str("SPI".into())),
            ],
        );
        r.add(Some(root), "AppleKeyStore", "AppleKeyStore", vec![]);
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
        Prop::Number(n) => *out += &format!("<integer size=\"32\">{n}</integer>"),
        Prop::Str(v) => *out += &format!("<string>{}</string>", escape(v)),
        Prop::Dict(items) => {
            *out += "<dict>";
            for (key, p) in items {
                *out += &format!("<key>{}</key>", escape(key));
                serialize(p, out);
            }
            *out += "</dict>";
        }
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
            } else if class == "AppleKeyStore" {
                // Selectors 0 and 1 open and close the client. Selector 17 is
                // the device lock state: no passcode is set
                // (kMobileKeyBagDisabled), so SpringBoard unlocks on a slide.
                match selector {
                    0 | 1 => Some((Vec::new(), Vec::new())),
                    17 => Some((vec![3], Vec::new())),
                    _ => None,
                }
            } else if class == HID_DRIVER {
                // Open (with options) and close; events come through the queue.
                matches!(selector, 0 | 1).then(|| (Vec::new(), Vec::new()))
            } else {
                None
            };
            let Some((scalar_out, inband_out)) = result else {
                log!(
                    "xnu: {class} user client: unhandled selector {selector} {scalars:x?} \
                     (inband {}, wants {scalar_out_max} scalars, {inband_out_max} bytes)",
                    inband.len()
                );
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
            k.iokit.hid_queues.remove(&le(msg, 8));
            err(KERN_SUCCESS)
        }
        // io_connect_map_memory(connection, memory_type, into_task, address,
        // size, flags): a complex request with the task port first. Only
        // the touchscreen's event queue (type 0) can be mapped.
        (2819, KObject::IoConnect(e))
            if k.iokit.entries[e].class == HID_DRIVER && msg.len() >= 64 && le(msg, 48) == 0 =>
        {
            let conn = le(msg, 8);
            let addr = match k.iokit.hid_queues.get(&conn) {
                Some(&(_, addr)) => addr,
                None => {
                    let addr = k.vm_allocate(0, HID_QUEUE_SIZE, 0, 1, "IOHIDEventQueue")?;
                    write_u32(&mut k.mem, addr, HID_QUEUE_SIZE - 12);
                    write_u32(&mut k.mem, addr + 4, 0);
                    write_u32(&mut k.mem, addr + 8, 0);
                    k.iokit.hid_queues.insert(conn, (k.pid, addr));
                    addr
                }
            };
            Some(reply(msg, &[KERN_SUCCESS, addr, HID_QUEUE_SIZE], &[]))
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
                _ => return err(KIO_RETURN_NOT_FOUND),
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
    inband: &[u8],
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
        // Swap: the second word of the 140-byte request is the IOSurface to
        // show, or 0 for none.
        5 if inband.len() >= 8 => {
            if *k.iokit.lcd_owner.get_or_insert(k.pid) == k.pid {
                k.iokit.presented_surface = le(inband, 4);
            }
            (vec![0], Vec::new())
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
/// is a 20-byte struct: the handle MBX2D keys its surface table and its
/// packets by (new for every mapping, since MBX2D aborts on a handle it still
/// holds, and a surface can be mapped more than once), the
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
        // A scratch surface MBX2D allocates for itself (format, width,
        // height), e.g. to scale down a launch image. It is mapped like
        // selector 2, with one more word in the reply.
        (6, [_format, width, height]) => {
            let width = u32::try_from(*width).ok().filter(|&w| w > 0 && w <= 4096)?;
            let height = u32::try_from(*height)
                .ok()
                .filter(|&h| h > 0 && h <= 4096)?;
            let bytes_per_row = (width * 4).next_multiple_of(16);
            let alloc_size = bytes_per_row * height;
            let pages = alloc_size.next_multiple_of(0x1000);
            let addr = k.vm_allocate(0, pages + 0x1000, 0, 1, "MBX scratch surface")?;
            k.iokit.surfaces.push(Surface {
                pid: k.pid,
                addr,
                alloc_size,
                width,
                height,
                bytes_per_row,
                bytes_per_element: 4,
                pixel_format: 0,
                seed_block: addr + pages,
            });
            let id = k.iokit.surfaces.len() as u32;
            let handle = k.iokit.next_mbx_handle;
            k.iokit.next_mbx_handle = handle.checked_add(1)?;
            k.iokit.mbx_handles.insert(handle, id);
            let words = [handle, addr, 0, addr + pages + 0x10, 0, 0];
            (
                Vec::new(),
                words.iter().flat_map(|w| w.to_le_bytes()).collect(),
            )
        }
        // Wait for a mapped surface to go idle: drawing here is synchronous.
        (10, [_handle]) => (Vec::new(), Vec::new()),
        // Unmap a surface.
        (5, [handle]) => {
            if let Ok(handle) = u32::try_from(*handle) {
                k.iokit.mbx_handles.remove(&handle);
            }
            (Vec::new(), Vec::new())
        }
        (2, [id, _]) => {
            let id = u32::try_from(*id).ok().filter(|&id| id != 0)?;
            let addr = k.iokit.surfaces.get(id as usize - 1)?.addr;
            // The status word lives in the surface's own spare page, after
            // the seed.
            let status = k.iokit.surfaces.get(id as usize - 1)?.seed_block + 0x10;
            let handle = k.iokit.next_mbx_handle;
            k.iokit.next_mbx_handle = handle.checked_add(1)?;
            k.iokit.mbx_handles.insert(handle, id);
            let words = [handle, addr, 0, status, 0];
            (
                Vec::new(),
                words.iter().flat_map(|w| w.to_le_bytes()).collect(),
            )
        }
        _ => return None,
    })
}

/// A 32-bit surface as MBX2D draws it: address, bytes per row, width and
/// height.
type MbxSurface = (u32, u32, u32, u32);

fn mbx_surface(k: &Kernel, id: u32) -> Option<MbxSurface> {
    id.checked_sub(1)
        .and_then(|i| k.iokit.surfaces.get(i as usize))
        .filter(|s| s.bytes_per_element == 4)
        .map(|s| (s.addr, s.bytes_per_row, s.width, s.height))
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
        let mut w: Vec<u32> = (1..=n / 4).map(|i| read_u32(&k.mem, at + 4 * i)).collect();
        // Packets name surfaces by mapping handle.
        for i in [4, 5] {
            if let Some(h) = w.get_mut(i) {
                *h = k.iokit.mbx_handles.get(h).copied().unwrap_or(0);
            }
        }
        if w.len() >= 15 && w[0] == 4 && w[11] & 0xff == 0xf0 {
            if let Some(s) = mbx_surface(k, w[4]) {
                let corner = |v: u32| (v >> 16, v & 0xffff);
                mbx_fill(&mut k.mem, s, w[12], corner(w[13]), corner(w[14]));
            }
        }
        // Copy, raster op 0xCC: source and destination surface IDs, the
        // source origin (x in bits 14-23, y below) and destination corners.
        // Packets with blend state (0x48 bytes) carry two more words before
        // the raster op, whose bit 17 enables premultiplied source-over.
        let rop_at = if w.get(1) == Some(&0x48) { 14 } else { 12 };
        if w.len() >= rop_at + 4 && w[0] == 5 && w[rop_at] & 0xff == 0xcc {
            if let (Some(src), Some(dst)) = (mbx_surface(k, w[4]), mbx_surface(k, w[5])) {
                let corner = |v: u32| (v >> 16, v & 0xffff);
                let src_origin = ((w[10] >> 14) & 0x3ff, w[10] & 0x3fff);
                let blend = w[rop_at] & 0x20000 != 0;
                let (c0, c1) = (corner(w[rop_at + 2]), corner(w[rop_at + 3]));
                mbx_copy(&mut k.mem, src, dst, src_origin, c0, c1, blend);
            }
        }
        // Textured quads: type 9, and type 8 with the same layout up to the
        // modulation color.
        if w.len() >= 44 && (w[0] == 8 || w[0] == 9) {
            if let (Some(src), Some(dst)) = (mbx_surface(k, w[4]), mbx_surface(k, w[5])) {
                mbx_draw_quad(&mut k.mem, src, dst, &w);
            }
        }
        at += 4 + n;
    }
}

/// Textured quad, blended source-over (premultiplied) into the destination:
/// source and destination surface IDs, the destination bounds, then four
/// strip-ordered vertices and their texture coordinates, normalized to the
/// texture's size rounded up to powers of two, and an RGBA modulation color.
fn mbx_draw_quad(mem: &mut Mem, src: MbxSurface, dst: MbxSurface, w: &[u32]) {
    let f = |i: usize| f32::from_bits(w[i]);
    if src.2 == 0 || src.3 == 0 {
        return;
    }
    let p = |i: usize| (f(21 + 2 * i), f(22 + 2 * i));
    let t = |i: usize| (f(29 + 2 * i), f(30 + 2 * i));
    let (p0, p1, p2) = (p(0), p(1), p(2));
    let (e1, e2) = ((p1.0 - p0.0, p1.1 - p0.1), (p2.0 - p0.0, p2.1 - p0.1));
    let det = e1.0 * e2.1 - e1.1 * e2.0;
    if det == 0.0 || !det.is_finite() {
        return;
    }
    let (t0, t1, t2) = (t(0), t(1), t(2));
    let (du, dv) = ((t1.0 - t0.0, t2.0 - t0.0), (t1.1 - t0.1, t2.1 - t0.1));
    let norm = (
        src.2.next_power_of_two() as f32,
        src.3.next_power_of_two() as f32,
    );
    let color = [f(40), f(41), f(42), f(43)];
    let clip = |v: f32, max: u32| (v.max(0.0) as u32).min(max);
    let (x0, y0) = (clip(f(6).min(f(8)), dst.2), clip(f(7).min(f(9)), dst.3));
    let (x1, y1) = (clip(f(6).max(f(8)), dst.2), clip(f(7).max(f(9)), dst.3));
    if x0 == x1 || y0 == y1 {
        return;
    }
    let inside = |v: f32| (0.0..=1.0).contains(&v);
    let bary = |x: u32, y: u32| {
        let d = (x as f32 + 0.5 - p0.0, y as f32 + 0.5 - p0.1);
        let a = (d.0 * e2.1 - d.1 * e2.0) / det;
        let b = (e1.0 * d.1 - e1.1 * d.0) / det;
        (a, b)
    };
    let texel = |a: f32, b: f32| {
        let u = t0.0 + a * du.0 + b * du.1;
        let v = t0.1 + a * dv.0 + b * dv.1;
        let tx = ((u * norm.0) as i64).clamp(0, src.2 as i64 - 1) as u32;
        let ty = ((v * norm.1) as i64).clamp(0, src.3 as i64 - 1) as u32;
        (tx, ty)
    };
    // One minus the modulated alpha, by source alpha. The blend leaves a
    // clear texel's pixel as it was if the color is finite, and gives an
    // opaque texel as it is if the color is white.
    let keep: [f32; 256] = std::array::from_fn(|a| 1.0 - a as f32 / 255.0 * color[3]);
    let skip_clear = color.iter().all(|c| c.is_finite());
    let copy_opaque = color == [1.0; 4];
    let put = |px: &mut [u8; 4], s: [u8; 4]| {
        let keep = keep[s[3] as usize];
        if copy_opaque && keep == 0.0 {
            *px = s;
        } else if !(skip_clear && s == [0; 4]) {
            // BGRA source, RGBA modulation color.
            for (i, c) in [2, 1, 0, 3].into_iter().enumerate() {
                px[i] = round_u8(s[i] as f32 * color[c] + px[i] as f32 * keep);
            }
        }
    };
    // With the quad and its texture axis-aligned, `a` and the texel column
    // depend only on x, and `b` and the texel row only on y.
    let separable = e1.1 == 0.0 && e2.0 == 0.0 && du.1 == 0.0 && dv.0 == 0.0 && src.2 <= src.1 / 4;
    let (mut xs, mut txs) = (Vec::new(), Vec::new());
    if separable {
        for x in x0..x1 {
            let a = bary(x, y0).0;
            if inside(a) {
                xs.push((x - x0) as usize);
                txs.push(texel(a, 0.0).0);
            }
        }
        if xs.is_empty() {
            return;
        }
    }
    let lo = txs.iter().copied().min().unwrap_or(0);
    let hi = txs.iter().copied().max().unwrap_or(0);
    let run = separable
        && xs.windows(2).all(|x| x[1] == x[0] + 1)
        && txs.windows(2).all(|t| t[1] == t[0] + 1);
    let mut texels = Vec::with_capacity((x1 - x0) as usize);
    for y in y0..y1 {
        texels.clear();
        if separable {
            let b = bary(x0, y).1;
            if !inside(b) {
                continue;
            }
            let at = Ptr::<u8, false>::from_bits(src.0 + texel(0.0, b).1 * src.1 + lo * 4);
            let line = mem.bytes_at(at, (hi - lo + 1) * 4).as_chunks::<4>().0;
            if run {
                texels.extend_from_slice(line);
            } else {
                texels.extend(txs.iter().map(|&tx| line[(tx - lo) as usize]));
            }
        } else {
            xs.clear();
            for x in x0..x1 {
                let (a, b) = bary(x, y);
                if inside(a) && inside(b) {
                    let (tx, ty) = texel(a, b);
                    xs.push((x - x0) as usize);
                    texels.push(read_u32(mem, src.0 + ty * src.1 + tx * 4).to_le_bytes());
                }
            }
        }
        let at = Ptr::from_bits(dst.0 + y * dst.1 + x0 * 4);
        let row = mem.bytes_at_mut(at, (x1 - x0) * 4).as_chunks_mut::<4>().0;
        if run {
            for (px, &s) in row[xs[0]..].iter_mut().zip(&texels) {
                put(px, s);
            }
        } else {
            for (&i, &s) in xs.iter().zip(&texels) {
                put(&mut row[i], s);
            }
        }
    }
}

/// `v.round().clamp(0.0, 255.0) as u8`, without a call to `roundf`.
fn round_u8(v: f32) -> u8 {
    if v.is_nan() || v <= 0.0 {
        return 0;
    }
    if v >= 255.0 {
        return 255;
    }
    let t = v as u8;
    t + (v - t as f32 >= 0.5) as u8
}

fn mbx_copy(
    mem: &mut Mem,
    src: MbxSurface,
    dst: MbxSurface,
    (sx, sy): (u32, u32),
    (x0, y0): (u32, u32),
    (x1, y1): (u32, u32),
    blend: bool,
) {
    let x1 = x1.min(dst.2).min((x0 + src.2).saturating_sub(sx));
    let y1 = y1.min(dst.3).min((y0 + src.3).saturating_sub(sy));
    if x0 >= x1 || y0 >= y1 {
        return;
    }
    let row_bytes = (x1 - x0) * 4;
    let src_row = |y: u32| Ptr::<u8, false>::from_bits(src.0 + (sy + y - y0) * src.1 + sx * 4);
    let dst_row = |y: u32| Ptr::<u8, true>::from_bits(dst.0 + y * dst.1 + x0 * 4);
    // The host bytes from the first row to the end of the last, if the rows
    // between lie in them.
    let span = |first: Ptr<u8, false>, last: Ptr<u8, false>, stride: u32| {
        let first = mem.bytes_at(first, row_bytes).as_ptr() as u64;
        let last = mem.bytes_at(last, row_bytes).as_ptr() as u64;
        let len = u64::from(y1 - y0 - 1) * u64::from(stride);
        (last.wrapping_sub(first) == len).then_some(first..last + u64::from(row_bytes))
    };
    let s = span(src_row(y0), src_row(y1 - 1), src.1);
    let d = span(
        dst_row(y0).cast_const(),
        dst_row(y1 - 1).cast_const(),
        dst.1,
    );
    // Rows go one at a time unless the rectangles may share memory, which
    // needs the whole source read first.
    let band = match (s, d) {
        (Some(s), Some(d)) if s.end <= d.start || d.end <= s.start => 1,
        _ => y1 - y0,
    };
    let mut pixels = Vec::with_capacity(row_bytes as usize * band as usize);
    for top in (y0..y1).step_by(band as usize) {
        pixels.clear();
        for y in top..top + band {
            pixels.extend_from_slice(mem.bytes_at(src_row(y), row_bytes));
        }
        for (y, row) in (top..).zip(pixels.chunks_exact(row_bytes as usize)) {
            let under = mem.bytes_at_mut(dst_row(y), row_bytes);
            if !blend {
                under.copy_from_slice(row);
                continue;
            }
            for (s, d) in row
                .as_chunks::<4>()
                .0
                .iter()
                .zip(under.as_chunks_mut::<4>().0)
            {
                match s[3] {
                    255 => *d = *s,
                    0 if *s == [0; 4] => {}
                    _ => {
                        let inv = 255 - s[3] as u32;
                        for i in 0..4 {
                            d[i] = (s[i] as u32 + (d[i] as u32 * inv + 127) / 255).min(255) as u8;
                        }
                    }
                }
            }
        }
    }
}

fn mbx_fill(mem: &mut Mem, s: MbxSurface, color: u32, (x0, y0): (u32, u32), (x1, y1): (u32, u32)) {
    let (x1, y1) = (x1.min(s.2), y1.min(s.3));
    if x0 >= x1 {
        return;
    }
    let row = color.to_le_bytes().repeat((x1 - x0) as usize);
    for y in y0..y1 {
        write_bytes(mem, s.0 + y * s.1 + x0 * 4, &row);
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
                pid: k.pid,
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
        // Wrap client memory (IOSurfaceClientWrapClientImage): width,
        // height, pixel format, bytes per element, bytes per row, size and
        // address. Each wrap gets a new ID, as on the device: MBX2D keeps its
        // own table by ID and aborts if an ID comes back while it holds it.
        8 if inband.len() >= 28 => {
            let w: Vec<u32> = inband.chunks(4).take(7).map(|c| le(c, 0)).collect();
            let [width, height, pixel_format, bytes_per_element, bytes_per_row, alloc_size, addr] =
                w[..]
            else {
                return None;
            };
            // The last row may stop at the image's edge.
            let row = width.checked_mul(bytes_per_element)?;
            if height == 0
                || row > bytes_per_row
                || bytes_per_row.checked_mul(height - 1)?.checked_add(row)? > alloc_size
            {
                return None;
            }
            let seed_block = k.vm_allocate(0, 0x1000, 0, 1, "IOSurface seed")?;
            k.iokit.surfaces.push(Surface {
                pid: k.pid,
                addr,
                alloc_size,
                width,
                height,
                bytes_per_row,
                bytes_per_element,
                pixel_format,
                seed_block,
            });
            let index = k.iokit.surfaces.len() - 1;
            let id = index as u32 + 1;
            (Vec::new(), surface_info(id, &k.iokit.surfaces[index]))
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

/// Touch phases the touchscreen reports.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TouchPhase {
    Down,
    Move,
    Up,
}

/// One serialized digitizer event, the layout `IOHIDEventCreateWithData`
/// copies into an `IOHIDEvent`: size, type, options, the position, then the
/// transducer fields and a quality orientation.
fn digitizer_record(out: &mut Vec<u8>, transducer: u32, phase: TouchPhase, (x, y): (f32, f32)) {
    const DIGITIZER_EVENT: u32 = 11;
    const FINGER: u32 = 2;
    // Range, touch, position and identity in the event mask.
    let mask = match phase {
        TouchPhase::Down => 0x1 | 0x2 | 0x20,
        TouchPhase::Move => 0x4,
        TouchPhase::Up => 0x1 | 0x2,
    };
    let touching = phase != TouchPhase::Up;
    let fixed = |f: f32| (f * 65536.0) as i32 as u32;
    let options = 1 | (touching as u32) << 16 | (touching as u32) << 17;
    let (index, identity) = if transducer == FINGER { (1, 2) } else { (0, 0) };
    let words = [
        0x5c,
        DIGITIZER_EVENT,
        0,
        0,
        options,
        fixed(x),
        fixed(y),
        0,
        index,
        transducer,
        identity,
        mask,
        0,
        touching as u32,
        fixed(if touching { 1.0 } else { 0.0 }),
        0,
        0,
        2, // quality orientation
        fixed(1.0),
        fixed(1.0),
        0,
        fixed(5.0),
        fixed(5.0),
    ];
    out.extend(words.iter().flat_map(|w| w.to_le_bytes()));
}

impl Kernel {
    /// Reports a one-finger touch at `pos` (0 to 1 across the screen) to
    /// every open touchscreen connection: a hand event with the finger as
    /// its child, the way the multitouch driver reports it.
    pub fn hid_touch(&mut self, phase: TouchPhase, pos: (f32, f32)) {
        const HAND: u32 = 3;
        const FINGER: u32 = 2;
        let time = self.absolute_time();
        let mut data = Vec::new();
        for w in [time as u32, (time >> 32) as u32, 0, 0, 0, 2] {
            data.extend(w.to_le_bytes());
        }
        digitizer_record(&mut data, HAND, phase, pos);
        digitizer_record(&mut data, FINGER, phase, pos);
        self.hid_post(&data);
    }

    /// Presses or releases a button, as a keyboard event (usage page and
    /// usage). The home button is the consumer page's Menu usage.
    pub fn hid_button(&mut self, usage_page: u16, usage: u16, down: bool) {
        const KEYBOARD_EVENT: u32 = 3;
        let time = self.absolute_time();
        let mut data = Vec::new();
        let words = [
            time as u32,
            (time >> 32) as u32,
            0,
            0,
            0,
            1,
            0x1c,
            KEYBOARD_EVENT,
            0,
            0,
            1,
            usage_page as u32 | (usage as u32) << 16,
            down as u32,
        ];
        for w in words {
            data.extend(w.to_le_bytes());
        }
        self.hid_post(&data);
    }

    fn hid_post(&mut self, data: &[u8]) {
        let queues: Vec<(u32, (u32, u32))> = self
            .iokit
            .hid_queues
            .iter()
            .map(|(&c, &q)| (c, q))
            .collect();
        for (conn, (pid, addr)) in queues {
            if !self
                .mem_for(pid)
                .is_some_and(|mem| hid_enqueue(mem, addr, data))
            {
                continue;
            }
            let Some(&port) = self.iokit.notify_ports.get(&conn) else {
                continue;
            };
            // IODataQueue's data-available message: a bare header. One
            // pending message is enough, since the client drains the queue.
            let mut m = Vec::with_capacity(24);
            for w in [0u32, 24, 0, port, 0, 0] {
                m.extend(w.to_le_bytes());
            }
            if let Some(p) = self.ipc.ports.get_mut(&port) {
                if p.queue.is_empty() {
                    p.queue.push_back((m, 1, Vec::new()));
                }
            }
        }
    }
}

/// Appends an entry to an `IODataQueueMemory` (queue size, head, tail,
/// then entries of a size word and the data), wrapping like IODataQueue.
fn hid_enqueue(mem: &mut Mem, addr: u32, data: &[u8]) -> bool {
    let size = read_u32(mem, addr);
    let head = read_u32(mem, addr + 4);
    let tail = read_u32(mem, addr + 8);
    let entry = 4 + data.len() as u32;
    if size > HID_QUEUE_SIZE - 12 || head > size || tail > size {
        return false;
    }
    let at = if tail >= head {
        if tail + entry <= size {
            tail
        } else if entry < head {
            if tail + 4 <= size {
                write_u32(mem, addr + 12 + tail, data.len() as u32);
            }
            0
        } else {
            return false;
        }
    } else if tail + entry < head {
        tail
    } else {
        return false;
    };
    write_u32(mem, addr + 12 + at, data.len() as u32);
    write_bytes(mem, addr + 16 + at, data);
    write_u32(mem, addr + 8, at + entry);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xnu::read_bytes;

    fn old_draw_quad(mem: &mut Mem, src: MbxSurface, dst: MbxSurface, w: &[u32]) {
        let f = |i: usize| f32::from_bits(w[i]);
        if src.2 == 0 || src.3 == 0 {
            return;
        }
        let p = |i: usize| (f(21 + 2 * i), f(22 + 2 * i));
        let t = |i: usize| (f(29 + 2 * i), f(30 + 2 * i));
        let (p0, p1, p2) = (p(0), p(1), p(2));
        let (e1, e2) = ((p1.0 - p0.0, p1.1 - p0.1), (p2.0 - p0.0, p2.1 - p0.1));
        let det = e1.0 * e2.1 - e1.1 * e2.0;
        if det == 0.0 || !det.is_finite() {
            return;
        }
        let (t0, t1, t2) = (t(0), t(1), t(2));
        let norm = (
            src.2.next_power_of_two() as f32,
            src.3.next_power_of_two() as f32,
        );
        let color = [f(40), f(41), f(42), f(43)];
        let clip = |v: f32, max: u32| (v.max(0.0) as u32).min(max);
        let (x0, y0) = (clip(f(6).min(f(8)), dst.2), clip(f(7).min(f(9)), dst.3));
        let (x1, y1) = (clip(f(6).max(f(8)), dst.2), clip(f(7).max(f(9)), dst.3));
        if x0 == x1 || y0 == y1 {
            return;
        }
        let row_bytes = (x1 - x0) * 4;
        let mut row = vec![0; row_bytes as usize];
        for y in y0..y1 {
            let start = Ptr::from_bits(dst.0 + y * dst.1 + x0 * 4);
            row.copy_from_slice(mem.bytes_at(start.cast_const(), row_bytes));
            for (x, px) in (x0..x1).zip(row.chunks_mut(4)) {
                let d = (x as f32 + 0.5 - p0.0, y as f32 + 0.5 - p0.1);
                let a = (d.0 * e2.1 - d.1 * e2.0) / det;
                let b = (e1.0 * d.1 - e1.1 * d.0) / det;
                if !(0.0..=1.0).contains(&a) || !(0.0..=1.0).contains(&b) {
                    continue;
                }
                let u = t0.0 + a * (t1.0 - t0.0) + b * (t2.0 - t0.0);
                let v = t0.1 + a * (t1.1 - t0.1) + b * (t2.1 - t0.1);
                let tx = ((u * norm.0) as i64).clamp(0, src.2 as i64 - 1) as u32;
                let ty = ((v * norm.1) as i64).clamp(0, src.3 as i64 - 1) as u32;
                let s = read_u32(mem, src.0 + ty * src.1 + tx * 4).to_le_bytes();
                let alpha = s[3] as f32 / 255.0 * color[3];
                let c = [
                    s[0] as f32 * color[2],
                    s[1] as f32 * color[1],
                    s[2] as f32 * color[0],
                    s[3] as f32 * color[3],
                ];
                for i in 0..4 {
                    px[i] = (c[i] + px[i] as f32 * (1.0 - alpha))
                        .round()
                        .clamp(0.0, 255.0) as u8;
                }
            }
            mem.bytes_at_mut(start, row_bytes).copy_from_slice(&row);
        }
    }

    fn old_copy(
        mem: &mut Mem,
        src: MbxSurface,
        dst: MbxSurface,
        (sx, sy): (u32, u32),
        (x0, y0): (u32, u32),
        (x1, y1): (u32, u32),
        blend: bool,
    ) {
        let x1 = x1.min(dst.2).min((x0 + src.2).saturating_sub(sx));
        let y1 = y1.min(dst.3).min((y0 + src.3).saturating_sub(sy));
        if x0 >= x1 || y0 >= y1 {
            return;
        }
        let row_bytes = (x1 - x0) * 4;
        let mut pixels = Vec::with_capacity(row_bytes as usize * (y1 - y0) as usize);
        for y in y0..y1 {
            let at = Ptr::<u8, false>::from_bits(src.0 + (sy + y - y0) * src.1 + sx * 4);
            pixels.extend_from_slice(mem.bytes_at(at, row_bytes));
        }
        for (y, row) in (y0..y1).zip(pixels.chunks_exact(row_bytes as usize)) {
            let at = Ptr::from_bits(dst.0 + y * dst.1 + x0 * 4);
            let under = mem.bytes_at_mut(at, row_bytes);
            if blend {
                for (s, d) in row
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .zip(under.as_chunks_mut::<4>().0)
                {
                    let inv = 255 - s[3] as u32;
                    for i in 0..4 {
                        d[i] = (s[i] as u32 + (d[i] as u32 * inv + 127) / 255).min(255) as u8;
                    }
                }
            } else {
                under.copy_from_slice(row);
            }
        }
    }

    fn old_fill(
        mem: &mut Mem,
        s: MbxSurface,
        color: u32,
        (x0, y0): (u32, u32),
        (x1, y1): (u32, u32),
    ) {
        let (x1, y1) = (x1.min(s.2), y1.min(s.3));
        if x0 >= x1 {
            return;
        }
        let row: Vec<u8> = (x0..x1).flat_map(|_| color.to_le_bytes()).collect();
        for y in y0..y1 {
            write_bytes(mem, s.0 + y * s.1 + x0 * 4, &row);
        }
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 32) as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
        fn unit(&mut self) -> f32 {
            (self.next() >> 8) as f32 / (1 << 24) as f32
        }
        fn pick<T: Copy>(&mut self, v: &[T]) -> T {
            v[self.below(v.len() as u32) as usize]
        }
        fn pixel(&mut self) -> [u8; 4] {
            let [b, g, r, a] = self.next().to_le_bytes();
            let pm = |c: u8, a: u8| (c as u32 * a as u32 / 255) as u8;
            match self.below(8) {
                0 | 1 => [0; 4],
                2 | 3 => [b, g, r, 255],
                4 | 5 => [pm(b, a), pm(g, a), pm(r, a), a],
                6 => [b, g, r, 0],
                _ => [b, g, r, a],
            }
        }
    }

    const ARENA: u32 = 0x1000_0000;
    const ARENA_SIZE: u32 = 1 << 20;

    /// Fresh surfaces with random pixels, packed into the arena from `at`.
    fn surface(rng: &mut Rng, mem: &mut Mem, at: &mut u32, max: u32) -> MbxSurface {
        let (w, h) = (1 + rng.below(max), 1 + rng.below(max));
        let bpr = match rng.below(10) {
            0 => (w * 4 - rng.below(w * 4)).max(4),
            1 => (w * 4).next_multiple_of(16) + 16 * (1 + rng.below(4)),
            _ => (w * 4).next_multiple_of(16),
        };
        let s = (*at, bpr, w, h);
        let size = bpr * h + w * 4;
        let pixels: Vec<u8> = (0..size / 4).flat_map(|_| rng.pixel()).collect();
        write_bytes(mem, *at, &pixels);
        *at += size.next_multiple_of(64) + 64 * rng.below(2);
        assert!(*at < ARENA + ARENA_SIZE);
        s
    }

    fn quad_packet(
        p: [(f32, f32); 4],
        t: [(f32, f32); 4],
        bounds: [f32; 4],
        color: [f32; 4],
    ) -> Vec<u32> {
        let mut w = vec![0; 44];
        w[0] = 9;
        for i in 0..4 {
            w[6 + i] = bounds[i].to_bits();
            w[21 + 2 * i] = p[i].0.to_bits();
            w[22 + 2 * i] = p[i].1.to_bits();
            w[29 + 2 * i] = t[i].0.to_bits();
            w[30 + 2 * i] = t[i].1.to_bits();
            w[40 + i] = color[i].to_bits();
        }
        w
    }

    fn random_quad(rng: &mut Rng, src: MbxSurface, dst: MbxSurface) -> Vec<u32> {
        let norm = (
            src.2.next_power_of_two() as f32,
            src.3.next_power_of_two() as f32,
        );
        let fraction = [
            0.5, 0.25, 0.75, 0.1, 0.9, 0.49999997, 0.50000006, 0.99999994,
        ];
        let coord = |rng: &mut Rng, max: u32| {
            let v = rng.below(max + 16) as f32 - 8.0;
            match rng.below(4) {
                0 => v + rng.pick(&fraction),
                1 => v + rng.unit(),
                _ => v,
            }
        };
        let (x, y) = (coord(rng, dst.2), coord(rng, dst.3));
        let kind = rng.below(10);
        let (w, h, u0, v0, u1, v1) = if kind < 5 {
            let (w, h) = (1 + rng.below(src.2), 1 + rng.below(src.3));
            let (u, v) = (rng.below(src.2 + 1 - w), rng.below(src.3 + 1 - h));
            let (u, v, w, h) = (u as f32, v as f32, w as f32, h as f32);
            (w, h, u, v, u + w, v + h)
        } else {
            let size = |rng: &mut Rng, max: u32| 0.5 + rng.unit() * 1.5 * max as f32;
            let tex = |rng: &mut Rng, max: u32| rng.unit() * (max + 4) as f32 - 2.0;
            let (w, h) = (size(rng, dst.2), size(rng, dst.3));
            let (u0, u1) = (tex(rng, src.2), tex(rng, src.2));
            let (v0, v1) = (tex(rng, src.3), tex(rng, src.3));
            (w, h, u0, v0, u1, v1)
        };
        let angle = match kind {
            7 => rng.unit() * std::f32::consts::TAU,
            8 => rng.below(4) as f32 * std::f32::consts::FRAC_PI_2,
            _ => 0.0,
        };
        let p = if angle == 0.0 {
            [(x, y), (x + w, y), (x, y + h), (x + w, y + h)]
        } else {
            let (sin, cos) = angle.sin_cos();
            let c = (x + w / 2.0, y + h / 2.0);
            [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)].map(|(i, j): (f32, f32)| {
                let (dx, dy) = (i * w / 2.0, j * h / 2.0);
                (c.0 + dx * cos - dy * sin, c.1 + dx * sin + dy * cos)
            })
        };
        let t = [(u0, v0), (u1, v0), (u0, v1), (u1, v1)].map(|(u, v)| (u / norm.0, v / norm.1));
        let (lo, hi) = p.iter().fold(
            ((f32::MAX, f32::MAX), (f32::MIN, f32::MIN)),
            |(lo, hi), q| {
                (
                    (lo.0.min(q.0), lo.1.min(q.1)),
                    (hi.0.max(q.0), hi.1.max(q.1)),
                )
            },
        );
        let bounds = match rng.below(6) {
            0 => [0.0, 0.0, dst.2 as f32 + 5.0, dst.3 as f32 + 5.0],
            1 => [hi.0, hi.1, lo.0, lo.1],
            2 => [
                lo.0 + rng.unit() * 4.0,
                lo.1 - 1.0,
                hi.0 - rng.unit() * 4.0,
                hi.1 + 1.5,
            ],
            _ => [lo.0, lo.1, hi.0, hi.1],
        };
        let o = rng.unit();
        let color = match rng.below(8) {
            0..=3 => [1.0; 4],
            4 => [o; 4],
            5 => [1.0, 1.0, 1.0, o],
            6 => [rng.unit(), rng.unit(), rng.unit(), rng.unit()],
            _ => {
                let special = [
                    f32::NAN,
                    f32::INFINITY,
                    -f32::INFINITY,
                    -0.0,
                    0.0,
                    2.0,
                    -1.0,
                    1.0000001,
                    0.99999994,
                ];
                let mut c = [1.0; 4];
                c[rng.below(4) as usize] = rng.pick(&special);
                c
            }
        };
        let mut w = quad_packet(p, t, bounds, color);
        if kind == 6 {
            let i = rng.pick(&[21, 22, 23, 24, 25, 26, 29, 30, 31, 32, 33, 34]);
            w[i] = w[i].wrapping_add(rng.pick(&[1, u32::MAX]));
        }
        if kind == 9 {
            let special = [
                f32::NAN,
                f32::INFINITY,
                -f32::INFINITY,
                -0.0,
                0.0,
                1e30,
                -1e30,
                1e-30,
            ];
            for _ in 0..1 + rng.below(3) {
                let i = rng.pick(&[
                    6, 7, 8, 9, 21, 22, 23, 24, 25, 26, 29, 30, 31, 32, 33, 34, 40, 41, 42, 43,
                ]);
                w[i] = match rng.below(3) {
                    0 => rng.next(),
                    _ => rng.pick(&special).to_bits(),
                };
            }
        }
        w
    }

    /// Runs `old` and `new` on the same arena and compares every byte.
    fn same(
        mem: &mut Mem,
        case: impl std::fmt::Debug,
        old: impl FnOnce(&mut Mem),
        new: impl FnOnce(&mut Mem),
    ) {
        let before = read_bytes(mem, ARENA, ARENA_SIZE);
        old(mem);
        let want = read_bytes(mem, ARENA, ARENA_SIZE);
        write_bytes(mem, ARENA, &before);
        new(mem);
        let got = read_bytes(mem, ARENA, ARENA_SIZE);
        if let Some(i) = (0..want.len()).find(|&i| want[i] != got[i]) {
            panic!(
                "{case:x?}: byte {:#x} is {:#x}, not {:#x}",
                ARENA + i as u32,
                got[i],
                want[i]
            );
        }
    }

    #[test]
    fn mbx_draw_quad_matches_reference() {
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut mem = Mem::new();
        for case in 0..6000 {
            let mut at = ARENA;
            let max = if case % 16 == 0 { 160 } else { 40 };
            let src = surface(&mut rng, &mut mem, &mut at, max);
            let dst = if rng.below(8) == 0 {
                src
            } else {
                surface(&mut rng, &mut mem, &mut at, max)
            };
            let w = random_quad(&mut rng, src, dst);
            same(
                &mut mem,
                (case, src, dst, &w),
                |mem| old_draw_quad(mem, src, dst, &w),
                |mem| mbx_draw_quad(mem, src, dst, &w),
            );
        }
    }

    #[test]
    fn mbx_draw_quad_scales_texture_by_power_of_two_width() {
        // An 86-pixel-wide label in rows of 88 pixels, drawn 1:1 as SpringBoard
        // draws it: u runs to 86 / 128.
        let mut mem = Mem::new();
        let src = (ARENA, 88 * 4, 86, 16);
        let dst = (ARENA + 0x10000, 128 * 4, 128, 16);
        let pixels: Vec<u8> = (0..88 * 16u32)
            .flat_map(|i| [i as u8, (i >> 8) as u8, 7, 255])
            .collect();
        write_bytes(&mut mem, src.0, &pixels);
        let u = 86.0 / 128.0;
        let p = [(0.0, 0.0), (86.0, 0.0), (0.0, 16.0), (86.0, 16.0)];
        let t = [(0.0, 0.0), (u, 0.0), (0.0, 1.0), (u, 1.0)];
        let w = quad_packet(p, t, [0.0, 0.0, 86.0, 16.0], [1.0; 4]);
        mbx_draw_quad(&mut mem, src, dst, &w);
        for y in 0..16 {
            assert_eq!(
                read_bytes(&mem, dst.0 + y * dst.1, 86 * 4),
                read_bytes(&mem, src.0 + y * src.1, 86 * 4),
                "row {y}"
            );
        }
    }

    #[test]
    fn mbx_copy_and_fill_match_reference() {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let mut mem = Mem::new();
        for case in 0..4000 {
            let mut at = ARENA;
            let max = if case % 16 == 0 { 160 } else { 40 };
            let src = surface(&mut rng, &mut mem, &mut at, max);
            let dst = match rng.below(6) {
                0 => src,
                1 => (src.0 + 4 * rng.below(src.2 + 8), src.1, src.2, src.3),
                2 => (src.0 + rng.below(src.3 + 2) * src.1, src.1, src.2, src.3),
                _ => surface(&mut rng, &mut mem, &mut at, max),
            };
            let point = |rng: &mut Rng, s: MbxSurface| (rng.below(s.2 + 8), rng.below(s.3 + 8));
            let (c0, c1) = (point(&mut rng, dst), point(&mut rng, dst));
            if rng.below(4) == 0 {
                let color = rng.next();
                same(
                    &mut mem,
                    (case, dst, color, c0, c1),
                    |mem| old_fill(mem, dst, color, c0, c1),
                    |mem| mbx_fill(mem, dst, color, c0, c1),
                );
                continue;
            }
            let origin = point(&mut rng, src);
            let blend = rng.below(3) != 0;
            same(
                &mut mem,
                (case, src, dst, origin, c0, c1, blend),
                |mem| old_copy(mem, src, dst, origin, c0, c1, blend),
                |mem| mbx_copy(mem, src, dst, origin, c0, c1, blend),
            );
        }
    }

    #[test]
    fn round_u8_matches_round_clamp() {
        let near_halves = (0..=256).flat_map(|k| {
            let v = k as f32 + 0.5;
            (-64..=64).flat_map(move |d: i32| {
                [v, k as f32].map(|v| f32::from_bits(v.to_bits().wrapping_add_signed(d)))
            })
        });
        let spread = (0..u32::MAX / 4099).map(|i| f32::from_bits(i * 4099));
        let special = [
            0.0,
            -0.0,
            f32::NAN,
            f32::INFINITY,
            -f32::INFINITY,
            f32::MIN_POSITIVE,
        ];
        for v in near_halves.chain(spread).chain(special) {
            assert_eq!(round_u8(v), v.round().clamp(0.0, 255.0) as u8, "{v:e}");
        }
    }

    /// Every f32, which takes a while: `cargo test --release round_u8_all
    /// -- --ignored`.
    #[test]
    #[ignore]
    fn round_u8_all() {
        for bits in 0..=u32::MAX {
            let v = f32::from_bits(bits);
            assert_eq!(round_u8(v), v.round().clamp(0.0, 255.0) as u8, "{v:e}");
        }
    }

    /// Old and new speed for typical SpringBoard drawing: `cargo test
    /// --release mbx_bench -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn mbx_bench() {
        let mut rng = Rng(0x1234_5678_9abc_def1);
        let mut mem = Mem::new();
        type Paint<'a> = &'a mut dyn FnMut(&mut Rng, u32, u32) -> [u8; 4];
        let mut put = |s: MbxSurface, px: Paint| {
            for y in 0..s.3 {
                let row: Vec<u8> = (0..s.1 / 4).flat_map(|x| px(&mut rng, x, y)).collect();
                write_bytes(&mut mem, s.0 + y * s.1, &row);
            }
        };
        let screen = (ARENA, 1280, 320, 480);
        let wallpaper = (ARENA + 0x10_0000, 1280, 320, 480);
        let icon = (ARENA + 0x20_0000, 240, 57, 57);
        let overlay = (ARENA + 0x30_0000, 1280, 320, 480);
        put(screen, &mut |rng, _, _| rng.pixel());
        put(wallpaper, &mut |rng, _, _| {
            let [b, g, r, _] = rng.next().to_le_bytes();
            [b, g, r, 255]
        });
        // A rounded square: opaque inside, clear corners, soft edges.
        put(icon, &mut |rng, x, y| {
            let d = |v: u32| (v as f32 - 28.0).abs() - 18.0;
            let edge = (d(x).max(0.0).hypot(d(y).max(0.0)) - 10.0).clamp(-1.0, 0.0);
            let a = (-edge * 255.0) as u32;
            let [b, g, r, _] = rng.next().to_le_bytes();
            let pm = |c: u8| (c as u32 * a / 255) as u8;
            [pm(b), pm(g), pm(r), a as u8]
        });
        // A status bar style overlay: mostly clear with a translucent band.
        put(overlay, &mut |_, _, y| {
            if y < 20 {
                [0, 0, 0, 128]
            } else {
                [0; 4]
            }
        });
        let quad = |x: f32, y: f32, w: f32, h: f32, s: MbxSurface, angle: f32, color: [f32; 4]| {
            let norm = (
                s.2.next_power_of_two() as f32,
                s.3.next_power_of_two() as f32,
            );
            let (sin, cos) = angle.sin_cos();
            let c = (x + w / 2.0, y + h / 2.0);
            let p =
                [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)].map(|(i, j): (f32, f32)| {
                    let (dx, dy) = (i * w / 2.0, j * h / 2.0);
                    if angle == 0.0 {
                        (c.0 + dx, c.1 + dy)
                    } else {
                        (c.0 + dx * cos - dy * sin, c.1 + dx * sin + dy * cos)
                    }
                });
            let t = [(0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0)]
                .map(|(u, v): (f32, f32)| (u * s.2 as f32 / norm.0, v * s.3 as f32 / norm.1));
            let (lo, hi) = p.iter().fold(
                ((f32::MAX, f32::MAX), (f32::MIN, f32::MIN)),
                |(lo, hi), q| {
                    (
                        (lo.0.min(q.0), lo.1.min(q.1)),
                        (hi.0.max(q.0), hi.1.max(q.1)),
                    )
                },
            );
            quad_packet(p, t, [lo.0, lo.1, hi.0, hi.1], color)
        };
        let white = [1.0; 4];
        type Case = (&'static str, u32, Box<dyn Fn(&mut Mem, bool)>);
        let cases: Vec<Case> = vec![
            (
                "fill 320x480",
                320 * 480,
                Box::new(move |mem, new| {
                    let f = if new { mbx_fill } else { old_fill };
                    f(mem, screen, 0xff336699, (0, 0), (320, 480))
                }),
            ),
            (
                "copy 320x480",
                320 * 480,
                Box::new(move |mem, new| {
                    let f = if new { mbx_copy } else { old_copy };
                    f(mem, wallpaper, screen, (0, 0), (0, 0), (320, 480), false)
                }),
            ),
            (
                "copy blend 320x480 overlay",
                320 * 480,
                Box::new(move |mem, new| {
                    let f = if new { mbx_copy } else { old_copy };
                    f(mem, overlay, screen, (0, 0), (0, 0), (320, 480), true)
                }),
            ),
            (
                "quad 320x480 wallpaper",
                320 * 480,
                Box::new(move |mem, new| {
                    let f = if new { mbx_draw_quad } else { old_draw_quad };
                    f(
                        mem,
                        wallpaper,
                        screen,
                        &quad(0.0, 0.0, 320.0, 480.0, wallpaper, 0.0, white),
                    )
                }),
            ),
            (
                "quad 320x480 overlay",
                320 * 480,
                Box::new(move |mem, new| {
                    let f = if new { mbx_draw_quad } else { old_draw_quad };
                    f(
                        mem,
                        overlay,
                        screen,
                        &quad(0.0, 0.0, 320.0, 480.0, overlay, 0.0, white),
                    )
                }),
            ),
            (
                "quad 57x57 icon",
                57 * 57,
                Box::new(move |mem, new| {
                    let f = if new { mbx_draw_quad } else { old_draw_quad };
                    f(
                        mem,
                        icon,
                        screen,
                        &quad(19.0, 40.0, 57.0, 57.0, icon, 0.0, white),
                    )
                }),
            ),
            (
                "quad 57x57 icon, 50% opacity",
                57 * 57,
                Box::new(move |mem, new| {
                    let f = if new { mbx_draw_quad } else { old_draw_quad };
                    f(
                        mem,
                        icon,
                        screen,
                        &quad(19.0, 40.0, 57.0, 57.0, icon, 0.0, [0.5; 4]),
                    )
                }),
            ),
            (
                "quad 57x57 icon scaled to 74x74 at x.3",
                74 * 74,
                Box::new(move |mem, new| {
                    let f = if new { mbx_draw_quad } else { old_draw_quad };
                    f(
                        mem,
                        icon,
                        screen,
                        &quad(19.3, 40.3, 74.1, 74.1, icon, 0.0, white),
                    )
                }),
            ),
            (
                "quad 57x57 icon rotated 30 degrees",
                57 * 57,
                Box::new(move |mem, new| {
                    let f = if new { mbx_draw_quad } else { old_draw_quad };
                    f(
                        mem,
                        icon,
                        screen,
                        &quad(
                            19.0,
                            40.0,
                            57.0,
                            57.0,
                            icon,
                            std::f32::consts::FRAC_PI_6,
                            white,
                        ),
                    )
                }),
            ),
        ];
        for (name, pixels, run) in &cases {
            same(&mut mem, name, |mem| run(mem, false), |mem| run(mem, true));
            let mut ns = [0.0; 2];
            for (new, ns) in [false, true].into_iter().zip(&mut ns) {
                let reps = 20_000_000 / pixels;
                let start = std::time::Instant::now();
                for _ in 0..reps {
                    run(&mut mem, new);
                }
                *ns = start.elapsed().as_nanos() as f64 / (reps * pixels) as f64;
            }
            println!(
                "{name}: old {:.2} ns/px, new {:.2} ns/px, {:.1}x",
                ns[0],
                ns[1],
                ns[0] / ns[1]
            );
        }
    }
}
