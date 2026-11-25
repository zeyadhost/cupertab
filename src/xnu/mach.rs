/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Mach traps (negative syscall numbers) and Mach IPC. There is one task, so
//! there is one port name space; port names are also the port identities.
//! Messages to kernel objects (the task, threads, the host, semaphores) are
//! handled as MIG requests here.

use super::bsd::Ret;
use super::vm::Prot;
use super::{read_bytes, read_u32, write_bytes, write_u32, Block, Kernel};
use crate::mem::Ptr;
use std::collections::{HashMap, VecDeque};

pub const KERN_SUCCESS: u32 = 0;
pub const KERN_INVALID_ADDRESS: u32 = 1;
pub const KERN_INVALID_ARGUMENT: u32 = 4;
pub const KERN_NO_SPACE: u32 = 3;
pub const KERN_INVALID_NAME: u32 = 15;
pub const KERN_ALREADY_IN_SET: u32 = 11;
pub const MACH_SEND_INVALID_DEST: u32 = 0x10000003;
pub const MACH_RCV_TIMED_OUT: u32 = 0x10004003;
pub const MACH_RCV_TOO_LARGE: u32 = 0x10004004;
/// Disposition of a received send right.
const MACH_MSG_TYPE_PORT_SEND_ONCE: u32 = 18;
pub const MACH_MSG_TYPE_PORT_SEND: u32 = 17;
pub const MIG_BAD_ID: u32 = (-303i32) as u32;

#[derive(Debug, Clone, PartialEq)]
pub enum KObject {
    Task(u32),
    Thread(u32),
    Host,
    Semaphore {
        count: i32,
    },
    Clock,
    IoMaster,
    /// An I/O Registry entry, by index.
    IoEntry(usize),
    IoIterator {
        items: Vec<usize>,
        pos: usize,
    },
    /// A user client connection to an I/O Registry entry.
    IoConnect(usize),
    /// notifyd's `com.apple.system.notification_center` server.
    Notifyd,
    /// installd's `com.apple.mobile.installd` server.
    Installd,
    MediaServer {
        system_sound_port: u32,
    },
    SystemSound,
}

#[derive(Debug, Default)]
pub struct Port {
    pub kobject: Option<KObject>,
    /// Queued messages and the PID of each one's sender.
    /// Messages with their sender's PID and the contents of their
    /// out-of-line descriptors, copied when they were sent.
    pub queue: VecDeque<(Vec<u8>, u32, Vec<Vec<u8>>)>,
    /// Port sets this port belongs to. As in XNU, a port can be in several:
    /// CFRunLoop adds each source's port to every mode's set.
    pub sets: Vec<u32>,
    pub is_set: bool,
}

pub struct Ipc {
    pub ports: HashMap<u32, Port>,
    pub(super) next_name: u32,
    pub task_port: u32,
    pub host_port: u32,
    pub bootstrap_port: u32,
    /// Bootstrap services by name.
    pub services: HashMap<String, u32>,
    /// Missing services already reported, so repeated look-ups stay quiet.
    pub missing_services: std::collections::HashSet<String>,
    /// mk_timer ports and their armed deadlines (absolute time).
    pub timers: HashMap<u32, Option<u64>>,
    pub notifyd: super::notifyd::Notifyd,
}

impl Ipc {
    pub fn new() -> Ipc {
        let mut ipc = Ipc {
            ports: HashMap::new(),
            next_name: 0x103,
            task_port: 0,
            host_port: 0,
            bootstrap_port: 0,
            services: HashMap::new(),
            missing_services: Default::default(),
            timers: HashMap::new(),
            notifyd: Default::default(),
        };
        ipc.task_port = ipc.new_kernel_port(KObject::Task(1));
        ipc.host_port = ipc.new_kernel_port(KObject::Host);
        ipc.bootstrap_port = ipc.new_port();
        let notifyd = ipc.new_kernel_port(KObject::Notifyd);
        ipc.services
            .insert("com.apple.system.notification_center".to_string(), notifyd);
        let installd = ipc.new_kernel_port(KObject::Installd);
        ipc.services
            .insert("com.apple.mobile.installd".to_string(), installd);
        let system_sound_port = ipc.new_kernel_port(KObject::SystemSound);
        let mediaserverd = ipc.new_kernel_port(KObject::MediaServer { system_sound_port });
        ipc.services
            .insert("com.apple.mediaserverd".to_string(), mediaserverd);
        ipc
    }
    pub fn new_port(&mut self) -> u32 {
        let name = self.next_name;
        self.next_name += 0x100;
        self.ports.insert(name, Port::default());
        name
    }
    pub fn new_kernel_port(&mut self, obj: KObject) -> u32 {
        let name = self.new_port();
        self.ports.get_mut(&name).unwrap().kobject = Some(obj);
        name
    }
}

pub(super) fn le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// Builds a MIG reply as received by the client. A simple reply carries
/// NDR + return code + `body`; a complex reply carries its port descriptors,
/// then NDR + `body` only if there is more data.
/// A complex reply with one out-of-line descriptor, then NDR + `count`.
/// The 32-bit descriptor layout is address, count, then the flag bytes.
pub(super) fn ool_reply(req: &[u8], addr: u32, count: u32, flags: u32) -> Vec<u8> {
    let mut m = reply(req, &[count], &[(0, 0)]);
    for (o, w) in [(28, addr), (32, count), (36, flags)] {
        m[o..o + 4].copy_from_slice(&w.to_le_bytes());
    }
    m
}

pub(super) fn reply(req: &[u8], body: &[u32], complex_ports: &[(u32, u32)]) -> Vec<u8> {
    let complex = !complex_ports.is_empty();
    let mut out = Vec::new();
    if complex {
        out.extend((complex_ports.len() as u32).to_le_bytes());
        for &(name, disp) in complex_ports {
            out.extend(name.to_le_bytes());
            out.extend(0u32.to_le_bytes());
            out.extend((disp << 16).to_le_bytes());
        }
    }
    if !complex || !body.is_empty() {
        out.extend([0u8, 0, 0, 0, 1, 0, 0, 0]); // NDR: little-endian ints
        for w in body {
            out.extend(w.to_le_bytes());
        }
    }
    // The reply port is the local port, with a send-once right.
    let bits = 0x1200 | if complex { 0x80000000 } else { 0 };
    let mut msg = Vec::new();
    for w in [
        bits,
        24 + out.len() as u32,
        0,
        le(req, 12),
        0,
        le(req, 20) + 100,
    ] {
        msg.extend(w.to_le_bytes());
    }
    msg.extend(out);
    msg
}

impl Kernel {
    /// Queues the expiry message of every mk_timer whose deadline passed.
    fn fire_timers(&mut self) {
        let now = self.absolute_time();
        for (&port, deadline) in self.ipc.timers.iter_mut() {
            if deadline.is_some_and(|d| d <= now) {
                *deadline = None;
                let mut m = Vec::with_capacity(48);
                for w in [0u32, 48, 0, port, 0, 0] {
                    m.extend(w.to_le_bytes());
                }
                m.resize(48, 0);
                if let Some(p) = self.ipc.ports.get_mut(&port) {
                    p.queue.push_back((m, 1, Vec::new()));
                }
            }
        }
        for v in self.iokit.vsyncs.values_mut() {
            if v.next <= now {
                v.next = now + super::iokit::VSync::PERIOD;
                let m = v.message(now);
                // One frame waits at most, as a display only has one.
                if let Some(p) = self.ipc.ports.get_mut(&v.port) {
                    if p.queue.is_empty() {
                        p.queue.push_back((m, 1, Vec::new()));
                    }
                }
            }
        }
    }

    /// Sets r0 and the carry flag the way a BSD syscall returns.
    pub fn set_bsd_result(&mut self, r: Result<u32, u32>) {
        let (r0, carry) = match r {
            Ok(v) => (v, 0),
            Err(e) => (e, 1 << 29),
        };
        self.cpu.regs_mut()[0] = r0;
        let cpsr = (self.cpu.cpsr() & !(1 << 29)) | carry;
        self.cpu.set_cpsr(cpsr);
    }

    pub fn semaphore_signal(&mut self, port: u32) {
        if let Some(Some(KObject::Semaphore { count })) =
            self.ipc.ports.get_mut(&port).map(|p| p.kobject.as_mut())
        {
            *count += 1;
        }
    }

    /// vm_allocate/vm_map semantics: VM_FLAGS_ANYWHERE picks a free range;
    /// otherwise the range must be free unless VM_FLAGS_OVERWRITE is set.
    pub(super) fn vm_allocate(
        &mut self,
        addr: u32,
        size: u32,
        mask: u32,
        flags: u32,
        tag: &str,
    ) -> Option<u32> {
        const VM_FLAGS_ANYWHERE: u32 = 1;
        const VM_FLAGS_OVERWRITE: u32 = 0x4000;
        if size == 0 {
            return None;
        }
        if flags & VM_FLAGS_ANYWHERE != 0 {
            self.vm.map_anywhere(addr, size, mask, Prot::RW, tag.into())
        } else if (flags & VM_FLAGS_OVERWRITE != 0
            || self.vm.is_free(addr & !0xfff, super::vm::round_up(size)))
            && self.vm.may_map_fixed(addr, size)
        {
            self.vm
                .map_fixed(addr, size, Prot::RW, tag.into())
                .ok()
                .map(|_| addr)
        } else {
            None
        }
    }

    /// Handles a MIG request to a kernel object. Returns the reply message.
    fn kernel_msg(&mut self, obj: KObject, msg: &[u8]) -> Option<Vec<u8>> {
        let id = le(msg, 20);
        // Port descriptors of complex messages come before the NDR record.
        let descs = if le(msg, 0) & 0x80000000 != 0 {
            4 + 12 * le(msg, 24) as usize
        } else {
            0
        };
        // The guest sizes the request, so a word past its end reads as 0.
        let body = msg.get(24 + descs..).unwrap_or(&[]);
        let arg = |i: usize| body.get(8 + 4 * i..12 + 4 * i).map_or(0, |b| le(b, 0));
        let r = |kr: u32| Some(reply(msg, &[kr], &[]));
        if matches!(
            obj,
            KObject::IoMaster
                | KObject::IoEntry(_)
                | KObject::IoIterator { .. }
                | KObject::IoConnect(_)
        ) {
            let rep = super::iokit::msg(self, obj.clone(), msg);
            if rep.is_none() {
                log!("xnu: unhandled IOKit request {id} to {obj:?}");
                return r(MIG_BAD_ID);
            }
            return rep;
        }
        if matches!(obj, KObject::Notifyd) {
            return super::notifyd::msg(self, msg);
        }
        if matches!(obj, KObject::Installd) {
            return super::installd::msg(self, msg);
        }
        if let KObject::MediaServer { system_sound_port } = obj {
            return Some(media_server_reply(msg, system_sound_port));
        }
        if obj == KObject::SystemSound {
            return match id {
                // One-way AudioServices set-active and play requests. No host
                // audio is played by this stub.
                24007 | 24010 if le(msg, 12) == 0 => None,
                _ => r(MIG_BAD_ID),
            };
        }
        match id {
            // mach_port_allocate(task, right, &name)
            3204 => {
                let right = arg(0);
                let name = self.ipc.new_port();
                if right == 3 {
                    self.ipc.ports.get_mut(&name).unwrap().is_set = true;
                }
                Some(reply(msg, &[KERN_SUCCESS, name], &[]))
            }
            // mach_port_type(task, name): kernel objects are held as send
            // rights, ports the task allocated as receive and send rights.
            3201 => {
                const KERN_INVALID_NAME: u32 = 15;
                const TYPE_SEND: u32 = 1 << 16;
                const TYPE_RECEIVE: u32 = 1 << 17;
                const TYPE_PORT_SET: u32 = 1 << 19;
                match self.ipc.ports.get(&arg(0)) {
                    Some(p) if p.is_set => Some(reply(msg, &[KERN_SUCCESS, TYPE_PORT_SET], &[])),
                    Some(p) if p.kobject.is_some() => {
                        Some(reply(msg, &[KERN_SUCCESS, TYPE_SEND], &[]))
                    }
                    Some(_) => Some(reply(msg, &[KERN_SUCCESS, TYPE_SEND | TYPE_RECEIVE], &[])),
                    None => r(KERN_INVALID_NAME),
                }
            }
            // mach_port_destroy, mach_port_deallocate
            3205 | 3206 => r(KERN_SUCCESS),
            // mach_port_get_refs(task, name, right): one of each.
            3207 => Some(reply(msg, &[KERN_SUCCESS, 1], &[])),
            // vm_purgable_control(task, address, control, &state): memory is
            // never purged, so it stays nonvolatile.
            4818 => Some(reply(msg, &[KERN_SUCCESS, 0], &[])),
            // mach_port_mod_refs(task, name, right, delta)
            3208 => r(KERN_SUCCESS),
            // mach_port_move_member(task, member, after): leaves every set
            // for `after`, or for none if it is null.
            3212 => {
                let (member, set) = (arg(0), arg(1));
                if let Some(p) = self.ipc.ports.get_mut(&member) {
                    p.sets.clear();
                    if set != 0 {
                        p.sets.push(set);
                    }
                }
                r(KERN_SUCCESS)
            }
            // mach_port_insert_member(task, member, set)
            3226 => {
                let (member, set) = (arg(0), arg(1));
                match self.ipc.ports.get_mut(&member) {
                    Some(p) if p.sets.contains(&set) => r(KERN_ALREADY_IN_SET),
                    Some(p) => {
                        p.sets.push(set);
                        r(KERN_SUCCESS)
                    }
                    None => r(KERN_INVALID_NAME),
                }
            }
            // mach_port_request_notification: there is no previous port
            3213 => Some(reply(msg, &[], &[(0, MACH_MSG_TYPE_PORT_SEND_ONCE)])),
            // mach_port_extract_member(task, member, set)
            3227 => {
                let (member, set) = (arg(0), arg(1));
                if let Some(p) = self.ipc.ports.get_mut(&member) {
                    p.sets.retain(|&s| s != set);
                }
                r(KERN_SUCCESS)
            }
            // mach_port_get_attributes(task, name, flavor, &info, &count): the
            // queue limit, receive status or dead-name table size, as XNU
            // reports them for a fresh port.
            3217 => {
                const QLIMIT_DEFAULT: u32 = 5;
                let info: &[u32] = match arg(1) {
                    1 => &[QLIMIT_DEFAULT],
                    2 => &[0, 0, 0, QLIMIT_DEFAULT, 0, 0, 0, 0, 0, 0],
                    3 => &[0],
                    _ => return r(KERN_INVALID_ARGUMENT),
                };
                let count = info.len().min(arg(2) as usize);
                let mut words = vec![KERN_SUCCESS, count as u32];
                words.extend_from_slice(&info[..count]);
                Some(reply(msg, &words, &[]))
            }
            // mach_port_insert_right, set_attributes and the like
            3214..=3230 => r(KERN_SUCCESS),
            // host_get_io_master
            205 => {
                let port = self.ipc.new_kernel_port(KObject::IoMaster);
                Some(reply(msg, &[], &[(port, MACH_MSG_TYPE_PORT_SEND)]))
            }
            // task_get_special_port(task, which)
            3409 => {
                let which = arg(0);
                let port = match which {
                    4 => self.ipc.bootstrap_port,
                    1 => self.ipc.task_port,
                    2 => self.ipc.host_port,
                    _ => 0,
                };
                Some(reply(msg, &[], &[(port, MACH_MSG_TYPE_PORT_SEND)]))
            }
            // task_set_special_port
            3410 => r(KERN_SUCCESS),
            // task_threads(task): an out-of-line array of thread ports
            3402 => {
                let ports: Vec<u32> = self
                    .threads
                    .iter()
                    .filter(|t| !t.exited)
                    .map(|t| t.port)
                    .collect();
                let bytes: Vec<u8> = ports.iter().flat_map(|p| p.to_le_bytes()).collect();
                let addr = self.vm_allocate(0, bytes.len() as u32, 0, 1, "task_threads")?;
                write_bytes(&mut self.mem, addr, &bytes);
                const MACH_MSG_OOL_PORTS_DESCRIPTOR: u32 = 2;
                const MACH_MSG_VIRTUAL_COPY: u32 = 1;
                let flags = MACH_MSG_OOL_PORTS_DESCRIPTOR << 24
                    | MACH_MSG_TYPE_PORT_SEND << 16
                    | MACH_MSG_VIRTUAL_COPY << 8;
                Some(ool_reply(msg, addr, ports.len() as u32, flags))
            }
            // semaphore_create(task, policy, value)
            3418 => {
                let value = arg(1) as i32;
                let port = self
                    .ipc
                    .new_kernel_port(KObject::Semaphore { count: value });
                Some(reply(msg, &[], &[(port, MACH_MSG_TYPE_PORT_SEND)]))
            }
            // semaphore_destroy
            3419 => r(KERN_SUCCESS),
            // vm_allocate(task, &addr, size, flags) / mach_vm_allocate
            3801 | 4800 => {
                // On 32-bit ARM, mach_vm_address_t and mach_vm_size_t are
                // 32-bit.
                let (addr, size, flags) = (arg(0), arg(1), arg(2));
                let got = self.vm_allocate(addr, size, 0, flags, "vm_allocate");
                if self.trace {
                    echo!("xnu:   vm_allocate({addr:#x}, {size:#x}, {flags:#x}) = {got:x?}");
                }
                let addr = got;
                match addr {
                    Some(a) => {
                        write_bytes(
                            &mut self.mem,
                            a,
                            &vec![0; super::vm::round_up(size) as usize],
                        );
                        Some(reply(msg, &[KERN_SUCCESS, a], &[]))
                    }
                    None => r(KERN_NO_SPACE),
                }
            }
            // mach_vm_map(task, &addr u64, size u64, mask u64, flags, [object],
            // offset u64, copy, cur, max, inherit)
            4811 | 3812 => {
                let (addr, size, mask, flags) = (arg(0), arg(1), arg(2), arg(3));
                let obj = if descs != 0 { le(msg, 28) } else { 0 };
                if self.trace {
                    echo!("xnu:   vm_map addr {addr:#x} size {size:#x} mask {mask:#x} flags {flags:#x} obj {obj:#x} bits {:#x}", le(msg, 0));
                }
                if obj != 0 {
                    log!("xnu: vm_map of memory object {obj:#x} unsupported");
                    return r(KERN_INVALID_ARGUMENT);
                }
                let a = self.vm_allocate(addr, size, mask, flags, "vm_map");
                match a {
                    Some(a) => {
                        write_bytes(
                            &mut self.mem,
                            a,
                            &vec![0; super::vm::round_up(size) as usize],
                        );
                        Some(reply(msg, &[KERN_SUCCESS, a], &[]))
                    }
                    None => r(KERN_NO_SPACE),
                }
            }
            // vm_deallocate / mach_vm_deallocate
            3802 | 4801 => {
                let (addr, size) = (arg(0), arg(1));
                self.vm.unmap(addr, size);
                r(KERN_SUCCESS)
            }
            // vm_copy / mach_vm_copy(task, src, size, dst), 32-bit addresses
            3808 | 4807 => {
                let (src, size, dst) = (arg(0), arg(1), arg(2));
                // Every page of both ranges has to be mapped.
                let mapped = |a: u32| {
                    let end = a as u64 + size as u64;
                    let mut at = a as u64;
                    while at < end {
                        match self.vm.region_at(at as u32) {
                            Some((base, region)) if a != 0 && end <= 1 << 32 => {
                                at = base as u64 + region.size as u64;
                            }
                            _ => return false,
                        }
                    }
                    true
                };
                if !mapped(src) || !mapped(dst) {
                    return r(KERN_INVALID_ADDRESS);
                }
                let bytes = read_bytes(&self.mem, src, size);
                write_bytes(&mut self.mem, dst, &bytes);
                r(KERN_SUCCESS)
            }
            // vm_protect / mach_vm_protect
            3803 | 4802 => r(KERN_SUCCESS),
            // mach_vm_remap(target, &addr, size, mask, flags, src_task,
            // src_addr, copy, &cur, &max, inherit). Each process has its own
            // memory here, so the pages are copied either way.
            4813 => {
                let (addr, size, mask, flags, src_addr) = (arg(0), arg(1), arg(2), arg(3), arg(4));
                let src_pid = self
                    .ipc
                    .ports
                    .get(&le(msg, 28))
                    .and_then(|p| match p.kobject {
                        Some(KObject::Task(pid)) => Some(pid),
                        _ => None,
                    });
                let Some(src_pid) = src_pid else {
                    return r(KERN_INVALID_ARGUMENT);
                };
                if matches!(obj, KObject::Task(t) if t != self.pid) {
                    // Only remapping into the calling task is supported.
                    return r(KERN_INVALID_ARGUMENT);
                }
                let offset = src_addr % super::vm::PAGE;
                let base = src_addr - offset;
                let end = base as u64 + ((offset as u64 + size as u64 + 0xfff) & !0xfff);
                if size == 0 || end > 1 << 32 {
                    return r(KERN_INVALID_ARGUMENT);
                }
                let len = (end - base as u64) as u32;
                // Every source page has to be mapped.
                let src_vm = if src_pid == self.pid {
                    &self.vm
                } else {
                    match self.parked.get(&src_pid) {
                        Some(p) => &p.vm,
                        None => return r(KERN_INVALID_ARGUMENT),
                    }
                };
                let mut at = base as u64;
                while at < end {
                    match src_vm.region_at(at as u32) {
                        Some((b, region)) => at = b as u64 + region.size as u64,
                        None => return r(KERN_INVALID_ADDRESS),
                    }
                }
                let bytes = match self.mem_for(src_pid) {
                    Some(mem) => read_bytes(mem, base, len),
                    None => return r(KERN_INVALID_ARGUMENT),
                };
                match self.vm_allocate(addr, len, mask, flags, "vm_remap") {
                    Some(a) => {
                        write_bytes(&mut self.mem, a, &bytes);
                        Some(reply(msg, &[KERN_SUCCESS, a + offset, 3, 7], &[]))
                    }
                    None => r(KERN_NO_SPACE),
                }
            }
            // vm_region / mach_vm_region(task, addr, flavor, count). On
            // 32-bit ARM mach_vm addresses are 32-bit too.
            3800 | 4816 => {
                let addr = arg(0);
                let count = arg(2).min(10);
                let pid = match obj {
                    KObject::Task(pid) => pid,
                    _ => self.pid,
                };
                let vm = if pid == self.pid {
                    &self.vm
                } else {
                    match self.parked.get(&pid) {
                        Some(p) => &p.vm,
                        None => return r(KERN_INVALID_ARGUMENT),
                    }
                };
                let Some((base, region)) = vm.region_from(addr) else {
                    return r(KERN_INVALID_ADDRESS);
                };
                // protection, max_protection, inheritance (copy), the rest 0.
                let mut info = vec![region.prot.0, 7, 1];
                info.resize(count as usize, 0);
                let mut words = vec![base, region.size];
                words.push(count);
                words.extend(info);
                Some(reply(msg, &words, &[(0, MACH_MSG_TYPE_PORT_SEND)]))
            }
            // host_info, host_statistics, task_info, thread_info: zeros
            200 | 219 | 3405 | 3612 => {
                let count = arg(1);
                let mut words = vec![KERN_SUCCESS, count.min(64)];
                words.extend(std::iter::repeat_n(0, count.min(64) as usize));
                if id == 200 && arg(0) == 1 {
                    // HOST_BASIC_INFO: max_cpus, avail_cpus, memory_size,
                    // cpu_type, cpu_subtype
                    words[2..7].copy_from_slice(&[1, 1, 128 << 20, 12, 6]);
                }
                if id == 200 && arg(0) == 5 && count >= 8 {
                    // HOST_PRIORITY_INFO
                    words[2..10].copy_from_slice(&[81, 81, 63, 31, 0, 0, 0, 127]);
                }
                Some(reply(msg, &words, &[]))
            }
            // host_get_clock_service
            206 => {
                let port = self.ipc.new_kernel_port(KObject::Clock);
                Some(reply(msg, &[], &[(port, MACH_MSG_TYPE_PORT_SEND)]))
            }
            // clock_get_time
            1000 => {
                let ns = self.now_ns();
                Some(reply(
                    msg,
                    &[
                        KERN_SUCCESS,
                        (ns / 1_000_000_000) as u32,
                        (ns % 1_000_000_000) as u32,
                    ],
                    &[],
                ))
            }
            // thread_policy_set, thread_set_exception_ports,
            // task_set_exception_ports
            3413 | 3613 | 3616 | 3617 => r(KERN_SUCCESS),
            // thread_get_state(thread, flavor, &state, &count)
            3603 => {
                const ARM_THREAD_STATE: u32 = 1;
                let KObject::Thread(t) = obj else {
                    return r(KERN_INVALID_ARGUMENT);
                };
                if arg(0) != ARM_THREAD_STATE || arg(1) < 17 {
                    return r(KERN_INVALID_ARGUMENT);
                }
                match self.thread_regs(t as usize) {
                    Some(state) => {
                        let mut words = vec![KERN_SUCCESS, 17];
                        words.extend(state);
                        Some(reply(msg, &words, &[]))
                    }
                    None => r(KERN_INVALID_ARGUMENT),
                }
            }
            // mach_ports_lookup: no registered ports
            3404 => r(5),
            _ => {
                log!("xnu: unhandled MIG request {id} to {obj:?}");
                if self.trace {
                    let text: String = msg[24..]
                        .iter()
                        .map(|&b| if b.is_ascii_graphic() { b as char } else { ' ' })
                        .collect();
                    echo!(
                        "xnu:   payload: {}",
                        text.split_whitespace().collect::<Vec<_>>().join(" ")
                    );
                }
                r(MIG_BAD_ID)
            }
        }
    }

    fn mach_msg(&mut self) -> Option<u32> {
        let (msg, option, send_size, rcv_size, rcv_name, timeout) = (
            self.arg(0),
            self.arg(1),
            self.arg(2),
            self.arg(3),
            self.arg(4),
            self.arg(5),
        );
        const MACH_SEND_MSG: u32 = 1;
        const MACH_RCV_MSG: u32 = 2;
        const MACH_RCV_TIMEOUT: u32 = 0x100;
        if option & MACH_SEND_MSG != 0 {
            let request = self
                .mem
                .bytes_at(Ptr::<u8, false>::from_bits(msg), send_size);
            let (remote, local) = (le(request, 8), le(request, 12));
            if self.trace {
                echo!(
                    "xnu:   mach_msg send id {} to {remote:#x} reply {local:#x}",
                    le(request, 20)
                );
            }
            let Some(port) = self.ipc.ports.get(&remote) else {
                if self.trace {
                    log!(
                        "xnu: mach_msg to invalid port {remote:#x} (id {})",
                        le(request, 20)
                    );
                    self.backtrace();
                }
                return Some(MACH_SEND_INVALID_DEST);
            };
            let mut data = request.to_vec();
            let bits = le(&data, 0);
            // MIG clients leave msgh_size to the kernel, which sets it from
            // the send size.
            data[4..8].copy_from_slice(&send_size.to_le_bytes());
            // Swap remote/local for the receiver's view, as the kernel does.
            data[8..12].copy_from_slice(&local.to_le_bytes());
            data[12..16].copy_from_slice(&remote.to_le_bytes());
            let reply_bits = (bits >> 8) & 0xff;
            data[0..4].copy_from_slice(
                &((bits & !0xffff)
                    | received_disposition(reply_bits)
                    | (received_disposition(bits & 0xff) << 8))
                    .to_le_bytes(),
            );
            translate_descriptors(&mut data);
            if let Some(obj) = port.kobject.clone() {
                if let Some(rep) = self.kernel_msg(obj, &read_bytes(&self.mem, msg, send_size)) {
                    if local != 0 {
                        if let Some(p) = self.ipc.ports.get_mut(&local) {
                            p.queue.push_back((rep, self.pid, Vec::new()));
                        }
                    }
                }
            } else if remote == self.ipc.bootstrap_port {
                if let Some(rep) = super::mach::bootstrap_msg(self, &data) {
                    if let Some(p) = self.ipc.ports.get_mut(&local) {
                        p.queue.push_back((rep, self.pid, Vec::new()));
                    }
                }
            } else {
                let ool = ool_descriptors(&data)
                    .map(|(_, addr, size)| read_bytes(&self.mem, addr, size))
                    .collect();
                self.ipc
                    .ports
                    .get_mut(&remote)
                    .unwrap()
                    .queue
                    .push_back((data, self.pid, ool));
            }
        }
        if option & MACH_RCV_MSG != 0 {
            if self.trace {
                let sets = self.ipc.ports.get(&rcv_name).map(|p| p.sets.clone());
                log!("xnu:   mach_msg receive on {rcv_name:#x} (in sets {sets:x?})");
            }
            if let Some(kr) = self.try_receive(msg, option, rcv_size, rcv_name) {
                return Some(kr);
            }
            if option & MACH_RCV_TIMEOUT != 0 && timeout == 0 {
                return Some(MACH_RCV_TIMED_OUT);
            }
            let deadline = (option & MACH_RCV_TIMEOUT != 0)
                .then(|| self.absolute_time() + timeout as u64 * 24_000);
            self.current_thread().blocked = Some(Block::MachReceive {
                name: rcv_name,
                deadline,
            });
            return None;
        }
        Some(KERN_SUCCESS)
    }

    fn try_receive(&mut self, msg: u32, option: u32, rcv_size: u32, name: u32) -> Option<u32> {
        // MACH_RCV_TRAILER_ELEMENTS: the null, seqno, sender (security token),
        // audit, context and MAC trailers. launchd's MIG replies are checked
        // for the audit one. Every sender is the kernel or this one task, so
        // the tokens are zero apart from the audit token's PID, which servers
        // such as UIKit's status bar compare with getpid().
        let trailer_size = match (option >> 24) & 0xf {
            0 => 8,
            1 => 12,
            2 => 20,
            3 => 52,
            4 => 56,
            _ => 64,
        };
        self.fire_timers();
        let candidates: Vec<u32> = match self.ipc.ports.get(&name) {
            Some(p) if p.is_set => self
                .ipc
                .ports
                .iter()
                .filter(|(_, p)| p.sets.contains(&name))
                .map(|(&n, _)| n)
                .collect(),
            Some(_) => vec![name],
            None => return Some(KERN_INVALID_NAME),
        };
        for n in candidates {
            let p = self.ipc.ports.get_mut(&n).unwrap();
            if let Some((m, _, _)) = p.queue.front() {
                if m.len() as u32 + trailer_size > rcv_size {
                    return Some(MACH_RCV_TOO_LARGE);
                }
                let (mut m, sender, ool) = p.queue.pop_front().unwrap();
                if sender != self.pid {
                    // Another task's memory: give the receiver its own copy.
                    let offsets: Vec<usize> = ool_descriptors(&m).map(|(o, _, _)| o).collect();
                    for (o, bytes) in offsets.into_iter().zip(ool) {
                        let addr = if bytes.is_empty() {
                            0
                        } else {
                            let size = super::vm::round_up(bytes.len() as u32);
                            let Some(addr) =
                                self.vm
                                    .map_anywhere(0, size, 0, Prot::RW, "mach_msg ool".into())
                            else {
                                return Some(MACH_RCV_TOO_LARGE);
                            };
                            write_bytes(&mut self.mem, addr, &bytes);
                            addr
                        };
                        m[o..o + 4].copy_from_slice(&addr.to_le_bytes());
                    }
                }
                write_bytes(&mut self.mem, msg, &m);
                let mut trailer = vec![0u8; trailer_size as usize];
                trailer[4..8].copy_from_slice(&trailer_size.to_le_bytes());
                if trailer_size >= 52 {
                    // audit_token_t starts at offset 20; word 5 is the PID
                    trailer[40..44].copy_from_slice(&sender.to_le_bytes());
                }
                write_bytes(&mut self.mem, msg + m.len() as u32, &trailer);
                // msgh_local_port of the received message is the port it came
                // on
                write_u32(&mut self.mem, msg + 12, n);
                return Some(KERN_SUCCESS);
            }
        }
        None
    }
}

fn media_server_reply(msg: &[u8], system_sound_port: u32) -> Vec<u8> {
    const FIND_SUB_SERVER: u32 = 42000;
    const SYSTEM_SOUND: u32 = 1;
    // AudioToolbox retries this lookup on the caller's thread if it fails.
    // Hand it the silent System Sound endpoint rather than leaving it waiting.
    if msg.len() == 36
        && le(msg, 0) & 0x80000000 == 0
        && le(msg, 20) == FIND_SUB_SERVER
        && le(msg, 32) == SYSTEM_SOUND
    {
        reply(msg, &[], &[(system_sound_port, MACH_MSG_TYPE_PORT_SEND)])
    } else {
        reply(msg, &[MIG_BAD_ID], &[])
    }
}

/// The bootstrap port (launchd's job server). There is a single task, so
/// services registered or checked in are simply looked up by name.
const MACH_MSG_TYPE_PORT_SEND_ONCE_RCV: u32 = 18;

/// The right a receiver holds for a port right sent with `disposition`.
fn received_disposition(disposition: u32) -> u32 {
    match disposition {
        19 | 20 => MACH_MSG_TYPE_PORT_SEND,     // COPY_SEND, MAKE_SEND
        21 => MACH_MSG_TYPE_PORT_SEND_ONCE_RCV, // MAKE_SEND_ONCE
        d => d,
    }
}

/// Rewrites the dispositions of a complex message's port descriptors to the
/// rights the receiver gets, which MIG clients check.
fn translate_descriptors(m: &mut [u8]) {
    if m.len() < 28 || le(m, 0) & 0x80000000 == 0 {
        return;
    }
    for i in 0..le(m, 24) as usize {
        let o = 28 + i * 12;
        if o + 12 > m.len() {
            return;
        }
        let at = match m[o + 11] {
            0 => o + 10, // MACH_MSG_PORT_DESCRIPTOR
            2 => o + 10, // MACH_MSG_OOL_PORTS_DESCRIPTOR
            _ => continue,
        };
        m[at] = received_disposition(m[at].into()) as u8;
    }
}

/// The out-of-line memory and port array descriptors of a complex message:
/// each one's offset in the message, address and size in bytes.
fn ool_descriptors(m: &[u8]) -> impl Iterator<Item = (usize, u32, u32)> + '_ {
    const MACH_MSG_OOL_DESCRIPTOR: u32 = 1;
    const MACH_MSG_OOL_PORTS_DESCRIPTOR: u32 = 2;
    const MACH_MSG_OOL_VOLATILE_DESCRIPTOR: u32 = 3;
    let count = if m.len() >= 28 && le(m, 0) & 0x80000000 != 0 {
        le(m, 24) as usize
    } else {
        0
    };
    (0..count).filter_map(move |i| {
        let o = 28 + i * 12;
        if o + 12 > m.len() {
            return None;
        }
        // address, size (or port count), then flags with the type on top.
        match le(m, o + 8) >> 24 {
            MACH_MSG_OOL_DESCRIPTOR | MACH_MSG_OOL_VOLATILE_DESCRIPTOR => {
                Some((o, le(m, o), le(m, o + 4)))
            }
            MACH_MSG_OOL_PORTS_DESCRIPTOR => Some((o, le(m, o), le(m, o + 4).saturating_mul(4))),
            _ => None,
        }
    })
}

pub fn bootstrap_msg(k: &mut Kernel, msg: &[u8]) -> Option<Vec<u8>> {
    const BOOTSTRAP_UNKNOWN_SERVICE: u32 = 1102;
    const MACH_MSG_TYPE_PORT_RECEIVE: u32 = 16;
    let id = le(msg, 20);
    let descs = if le(msg, 0) & 0x80000000 != 0 {
        4 + 12 * le(msg, 24) as usize
    } else {
        0
    };
    let name_off = 24 + descs + 8;
    let name = {
        let s = &msg[name_off.min(msg.len())..(name_off + 128).min(msg.len())];
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        String::from_utf8_lossy(&s[..end]).into_owned()
    };
    match id {
        // bootstrap_check_in: hands out the receive right for a service.
        402 => {
            let port = *k.ipc.services.entry(name.clone()).or_insert(0);
            let port = if port == 0 {
                let p = k.ipc.new_port();
                k.ipc.services.insert(name.clone(), p);
                p
            } else {
                port
            };
            if k.trace {
                log!("xnu: bootstrap_check_in({name:?}) = {port:#x}");
            }
            Some(reply(msg, &[], &[(port, MACH_MSG_TYPE_PORT_RECEIVE)]))
        }
        // bootstrap_register(name, service_port)
        403 => {
            let port = le(msg, 28);
            if k.trace {
                log!("xnu: bootstrap_register({name:?}, {port:#x})");
            }
            k.ipc.services.insert(name, port);
            Some(reply(msg, &[KERN_SUCCESS], &[]))
        }
        // bootstrap_look_up
        404 => match k.ipc.services.get(&name).copied() {
            Some(port) => {
                if k.trace {
                    log!("xnu: bootstrap_look_up({name:?}) = {port:#x}");
                }
                Some(reply(msg, &[], &[(port, MACH_MSG_TYPE_PORT_SEND)]))
            }
            None if k.start_on_demand(&name).is_some() => {
                let port = k.ipc.services[&name];
                Some(reply(msg, &[], &[(port, MACH_MSG_TYPE_PORT_SEND)]))
            }
            None => {
                if k.trace || k.ipc.missing_services.insert(name.clone()) {
                    log!("xnu: bootstrap_look_up({name:?}): no such service");
                }
                Some(reply(msg, &[BOOTSTRAP_UNKNOWN_SERVICE], &[]))
            }
        },
        // vproc_mig_getsocket: the path of launchd's job socket, as a
        // 128-byte string.
        412 => {
            let mut path = [0u8; 128];
            let sock = super::lockdown::LAUNCHD_SOCKET.as_bytes();
            path[..sock.len()].copy_from_slice(sock);
            let mut body = vec![KERN_SUCCESS];
            body.extend(
                path.chunks(4)
                    .map(|c| u32::from_le_bytes(c.try_into().unwrap())),
            );
            Some(reply(msg, &body, &[]))
        }
        // vproc_mig_swap_integer(inkey, outkey, inval): job tunables such as
        // the Jetsam priority. Nothing is stored; every key reads as 0.
        416 => Some(reply(msg, &[KERN_SUCCESS, 0, 0], &[])),
        _ => {
            log!("xnu: unhandled bootstrap request {id}");
            Some(reply(msg, &[MIG_BAD_ID], &[]))
        }
    }
}

pub fn trap(k: &mut Kernel, num: u32) -> Option<u32> {
    match num {
        3 => {
            let t = k.absolute_time();
            k.cpu.regs_mut()[1] = (t >> 32) as u32;
            Some(t as u32)
        }
        26 => Some(k.ipc.new_port()),          // mach_reply_port
        27 => Some(k.threads[k.current].port), // thread_self_trap
        28 => Some(k.ipc.task_port),           // task_self_trap
        // task_name_for_pid, task_for_pid(target_tport, pid, *t)
        44 | 45 => match k.task_port_for(k.arg(1)) {
            Some(port) => {
                let out = k.arg(2);
                write_u32(&mut k.mem, out, port);
                Some(KERN_SUCCESS)
            }
            None => Some(5 /* KERN_FAILURE */),
        },
        // pid_for_task(t, *pid)
        46 => {
            let pid = k.ipc.ports.get(&k.arg(0)).and_then(|p| match p.kobject {
                Some(KObject::Task(pid)) => Some(pid),
                _ => None,
            });
            match pid {
                Some(pid) => {
                    let out = k.arg(1);
                    write_u32(&mut k.mem, out, pid);
                    Some(KERN_SUCCESS)
                }
                None => Some(5 /* KERN_FAILURE */),
            }
        }
        29 => Some(k.ipc.host_port), // host_self_trap
        31 => k.mach_msg(),
        // semaphore_signal, semaphore_signal_all, semaphore_signal_thread
        33..=35 => {
            k.semaphore_signal(k.arg(0));
            Some(KERN_SUCCESS)
        }
        // semaphore_wait, semaphore_wait_signal, semaphore_timedwait,
        // semaphore_timedwait_signal(wait, signal, sec, nsec)
        36..=39 => {
            let port = k.arg(0);
            let (signal, time_args) = match num {
                37 => (k.arg(1), None),
                38 => (0, Some((k.arg(1), k.arg(2)))),
                39 => (k.arg(1), Some((k.arg(2), k.arg(3)))),
                _ => (0, None),
            };
            if signal != 0 {
                k.semaphore_signal(signal);
            }
            let deadline = time_args.map(|(sec, nsec)| {
                k.absolute_time() + (sec as u64 * 1_000_000_000 + nsec as u64) * 3 / 125
            });
            let block = Block::Semaphore { port, deadline };
            if retry_blocked(k, &block) {
                Some(KERN_SUCCESS)
            } else {
                k.current_thread().blocked = Some(block);
                None
            }
        }
        // mk_timer_create
        91 => {
            let port = k.ipc.new_port();
            k.ipc.timers.insert(port, None);
            Some(port)
        }
        // mk_timer_destroy
        92 => {
            k.ipc.timers.remove(&k.arg(0));
            Some(KERN_SUCCESS)
        }
        // mk_timer_arm(port, expire_time)
        93 => {
            let deadline = k.arg(1) as u64 | (k.arg(2) as u64) << 32;
            match k.ipc.timers.get_mut(&k.arg(0)) {
                Some(t) => {
                    *t = Some(deadline);
                    Some(KERN_SUCCESS)
                }
                None => Some(KERN_INVALID_ARGUMENT),
            }
        }
        // mk_timer_cancel(port, &result_time)
        94 => {
            let (port, out) = (k.arg(0), k.arg(1));
            match k.ipc.timers.get_mut(&port) {
                Some(t) => {
                    let old = t.take().unwrap_or(0);
                    if out != 0 {
                        write_u32(&mut k.mem, out, old as u32);
                        write_u32(&mut k.mem, out + 4, (old >> 32) as u32);
                    }
                    Some(KERN_SUCCESS)
                }
                None => Some(KERN_INVALID_ARGUMENT),
            }
        }
        89 => {
            // mach_timebase_info: 125/3 ns per tick (24 MHz)
            let info = k.arg(0);
            write_u32(&mut k.mem, info, 125);
            write_u32(&mut k.mem, info + 4, 3);
            Some(KERN_SUCCESS)
        }
        90 => {
            let deadline = k.arg(0) as u64 | (k.arg(1) as u64) << 32;
            k.current_thread().blocked = Some(Block::Sleep { deadline });
            None
        }
        // thread_switch, swtch, swtch_pri
        59..=61 => {
            k.yield_requested = true;
            Some(KERN_SUCCESS)
        }
        _ => {
            log!(
                "xnu: unimplemented Mach trap -{num} (lr {:#x})",
                k.cpu.regs()[14]
            );
            Some(KERN_INVALID_ARGUMENT)
        }
    }
}

/// Retries a blocking operation for the current thread; on success the
/// result is already in r0.
pub fn retry_blocked(k: &mut Kernel, block: &Block) -> bool {
    match *block {
        Block::MachReceive { name, .. } => {
            let (msg, option, rcv_size) = (k.arg(0), k.arg(1), k.arg(3));
            match k.try_receive(msg, option, rcv_size, name) {
                Some(kr) => {
                    k.cpu.regs_mut()[0] = kr;
                    true
                }
                None => false,
            }
        }
        Block::Semaphore { port, .. } => {
            if let Some(Some(KObject::Semaphore { count })) =
                k.ipc.ports.get_mut(&port).map(|p| p.kobject.as_mut())
            {
                if *count > 0 {
                    *count -= 1;
                    k.cpu.regs_mut()[0] = KERN_SUCCESS;
                    return true;
                }
            }
            false
        }
        Block::SemWait { port, .. } => {
            let sem = Block::Semaphore {
                port,
                deadline: None,
            };
            if port != 0 && retry_blocked(k, &sem) {
                k.set_bsd_result(Ok(0));
                true
            } else {
                false
            }
        }
        _ => false,
    }
}

pub fn timeout_blocked(k: &mut Kernel, block: &Block) {
    k.cpu.regs_mut()[0] = match block {
        Block::MachReceive { .. } => MACH_RCV_TIMED_OUT,
        Block::Semaphore { .. } => 49, // KERN_OPERATION_TIMED_OUT
        Block::SemWait { .. } => return k.set_bsd_result(Err(60)), // ETIMEDOUT
        _ => 60,                       // ETIMEDOUT
    };
}

/// Thread and synchronization syscalls that live alongside the Mach side.
pub fn bsd_extra(k: &mut Kernel, num: u32) -> Option<Ret> {
    match num {
        366 => {
            // bsdthread_register(threadstart, wqthread, pthsize)
            k.bsdthread_start = k.arg(0);
            k.pthread_size = k.arg(2);
            Some(Ret::Ok(0, 0))
        }
        // bsdthread_create(func, func_arg, stack, pthread, flags)
        360 => {
            const PTHREAD_START_CUSTOM: u32 = 0x01000000;
            let (func, func_arg, stack, pthread, flags) =
                (k.arg(0), k.arg(1), k.arg(2), k.arg(3), k.arg(4));
            let (sp, pthread) = if flags & PTHREAD_START_CUSTOM != 0 {
                (stack, pthread)
            } else {
                // The kernel allocates guard page, stack and pthread_t.
                let guard = super::vm::PAGE;
                let size = guard + stack + k.pthread_size;
                let Some(base) =
                    k.vm.map_anywhere(0, size, 0, super::vm::Prot::RW, "thread stack".into())
                else {
                    return Some(Ret::Err(12)); // ENOMEM
                };
                let size = super::vm::round_up(size);
                super::write_bytes(&mut k.mem, base, &vec![0; size as usize]);
                let top = base + guard + stack;
                (top, top)
            };
            let start = k.bsdthread_start;
            let port = k.spawn_thread(start, sp, pthread, |port| {
                [pthread, port, func, func_arg, stack, flags]
            });
            log_dbg!("xnu: bsdthread_create({func:#x}) = {pthread:#x}, port {port:#x}");
            Some(Ret::Ok(pthread, 0))
        }
        // bsdthread_terminate(stackaddr, freesize, port, sem)
        361 => {
            let (stack, size) = (k.arg(0), k.arg(1));
            if size != 0 {
                k.vm.unmap(stack, size);
            }
            if k.arg(3) != 0 {
                k.semaphore_signal(k.arg(3));
            }
            k.current_thread().exited = true;
            Some(Ret::Ok(0, 0))
        }
        // statfs64(path, buf), fstatfs64(fd, buf): one HFS+ volume
        345 | 346 => {
            let buf = k.arg(1);
            let mut st = vec![0u8; 2168];
            st[0..4].copy_from_slice(&4096u32.to_le_bytes()); // f_bsize
            st[4..8].copy_from_slice(&4096u32.to_le_bytes()); // f_iosize
            for (off, v) in [
                (8, 1u64 << 20),
                (16, 1 << 19),
                (24, 1 << 19),
                (32, 1 << 20),
                (40, 1 << 19),
            ] {
                st[off..off + 8].copy_from_slice(&v.to_le_bytes());
            }
            st[72..75].copy_from_slice(b"hfs");
            st[88] = b'/';
            st[1112..1121].copy_from_slice(b"/dev/disk");
            super::write_bytes(&mut k.mem, buf, &st);
            Some(Ret::Ok(0, 0))
        }
        // __semwait_signal(cond_sem, mutex_sem, timeout, relative, tv_sec,
        // tv_nsec), and its _nocancel twin
        334 | 423 => {
            let (cond, mutex) = (k.arg(0), k.arg(1));
            if mutex != 0 {
                k.semaphore_signal(mutex);
            }
            let deadline = (k.arg(2) != 0).then(|| {
                // tv_sec is 64-bit, so it takes r4-r5 and tv_nsec r6.
                let sec = k.arg(4) as u64 | (k.arg(5) as u64) << 32;
                let ns = sec * 1_000_000_000 + k.arg(6) as u64;
                let ns = if k.arg(3) != 0 {
                    ns
                } else {
                    ns.saturating_sub(k.guest_unix_ns())
                };
                k.absolute_time() + ns * 3 / 125
            });
            if cond == 0 && deadline.is_none() {
                return Some(Ret::Err(22)); // EINVAL
            }
            let block = Block::SemWait {
                port: cond,
                deadline,
            };
            if retry_blocked(k, &block) {
                return Some(Ret::Ok(0, 0));
            }
            k.current_thread().blocked = Some(block);
            Some(Ret::Blocked)
        }
        367 | 368 => Some(Ret::Err(45)),
        _ => {
            let _ = read_u32;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_server_only_resolves_system_sound() {
        let ipc = Ipc::new();
        let server = ipc.services["com.apple.mediaserverd"];
        let Some(KObject::MediaServer { system_sound_port }) = ipc.ports[&server].kobject else {
            panic!("missing media server");
        };
        assert_eq!(
            ipc.ports[&system_sound_port].kobject,
            Some(KObject::SystemSound)
        );
        let mut request = [0; 36];
        request[12..16].copy_from_slice(&0x503u32.to_le_bytes());
        request[20..24].copy_from_slice(&42000u32.to_le_bytes());
        request[32..36].copy_from_slice(&1u32.to_le_bytes());
        let response = media_server_reply(&request, system_sound_port);
        assert_eq!(response.len(), 40);
        assert_eq!(le(&response, 12), 0x503);
        assert_eq!(le(&response, 20), 42100);
        assert_eq!(le(&response, 24), 1);
        assert_eq!(le(&response, 28), system_sound_port);
        assert_eq!(response[38], MACH_MSG_TYPE_PORT_SEND as u8);

        request[32] = 2;
        let response = media_server_reply(&request, system_sound_port);
        assert_eq!(le(&response, 0) & 0x80000000, 0);
        assert_eq!(le(&response, 32), MIG_BAD_ID);
    }
}
