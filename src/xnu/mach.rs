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
use std::collections::{HashMap, VecDeque};

pub const KERN_SUCCESS: u32 = 0;
pub const KERN_INVALID_ARGUMENT: u32 = 4;
pub const KERN_NO_SPACE: u32 = 3;
pub const KERN_INVALID_NAME: u32 = 15;
pub const MACH_SEND_INVALID_DEST: u32 = 0x10000003;
pub const MACH_RCV_TIMED_OUT: u32 = 0x10004003;
pub const MACH_RCV_TOO_LARGE: u32 = 0x10004004;
/// Disposition of a received send right.
const MACH_MSG_TYPE_PORT_SEND: u32 = 17;
pub const MIG_BAD_ID: u32 = (-303i32) as u32;

#[derive(Debug, Clone, PartialEq)]
pub enum KObject {
    Task,
    Thread(u32),
    Host,
    Semaphore { count: i32 },
    Clock,
}

#[derive(Debug, Default)]
pub struct Port {
    pub kobject: Option<KObject>,
    pub queue: VecDeque<Vec<u8>>,
    /// Port set this port belongs to.
    pub set: Option<u32>,
    pub is_set: bool,
}

pub struct Ipc {
    pub ports: HashMap<u32, Port>,
    next_name: u32,
    pub task_port: u32,
    pub host_port: u32,
    pub bootstrap_port: u32,
}

impl Ipc {
    pub fn new() -> Ipc {
        let mut ipc = Ipc {
            ports: HashMap::new(),
            next_name: 0x103,
            task_port: 0,
            host_port: 0,
            bootstrap_port: 0,
        };
        ipc.task_port = ipc.new_kernel_port(KObject::Task);
        ipc.host_port = ipc.new_kernel_port(KObject::Host);
        ipc.bootstrap_port = ipc.new_port();
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

fn le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// Builds a MIG reply as received by the client. A simple reply carries
/// NDR + return code + `body`; a complex reply carries its port descriptors,
/// then NDR + `body` only if there is more data.
fn reply(req: &[u8], body: &[u32], complex_ports: &[(u32, u32)]) -> Vec<u8> {
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
    /// vm_allocate/vm_map semantics: VM_FLAGS_ANYWHERE picks a free range;
    /// otherwise the range must be free unless VM_FLAGS_OVERWRITE is set.
    fn vm_allocate(
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
        } else if flags & VM_FLAGS_OVERWRITE != 0
            || self.vm.is_free(addr & !0xfff, super::vm::round_up(size))
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
        let body = &msg[24 + descs..];
        let arg = |i: usize| le(body, 8 + 4 * i);
        let r = |kr: u32| Some(reply(msg, &[kr], &[]));
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
            // mach_port_destroy, mach_port_deallocate
            3205 | 3206 => r(KERN_SUCCESS),
            // mach_port_mod_refs(task, name, right, delta)
            3208 => r(KERN_SUCCESS),
            // mach_port_move_member(task, member, after)
            3213 => {
                let (member, set) = (arg(0), arg(1));
                if let Some(p) = self.ipc.ports.get_mut(&member) {
                    p.set = if set == 0 { None } else { Some(set) };
                }
                r(KERN_SUCCESS)
            }
            // mach_port_insert_right, mach_port_request_notification-ish, set_attributes
            3214..=3230 => {
                if id == 3216 {
                    // mach_port_request_notification: no previous port
                    return Some(reply(msg, &[KERN_SUCCESS, 0], &[]));
                }
                r(KERN_SUCCESS)
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
                // On 32-bit ARM, mach_vm_address_t and mach_vm_size_t are 32-bit.
                let (addr, size, flags) = (arg(0), arg(1), arg(2));
                let addr = self.vm_allocate(addr, size, 0, flags, "vm_allocate");
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
            // mach_vm_map(task, &addr u64, size u64, mask u64, flags, [object], offset u64, copy, cur, max, inherit)
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
            // vm_protect / mach_vm_protect
            3803 | 4802 => r(KERN_SUCCESS),
            // host_info, host_statistics, task_info, thread_info: zeros
            200 | 219 | 3405 | 3612 => {
                let count = arg(1);
                let mut words = vec![KERN_SUCCESS, count.min(64)];
                words.extend(std::iter::repeat_n(0, count.min(64) as usize));
                if id == 200 && arg(0) == 1 {
                    // HOST_BASIC_INFO: max_cpus, avail_cpus, memory_size, cpu_type, cpu_subtype
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
            // thread_policy_set, thread_set_exception_ports, task_set_exception_ports
            3413 | 3613 | 3616 | 3617 => r(KERN_SUCCESS),
            // mach_ports_lookup: no registered ports
            3404 => r(5),
            _ => {
                log!("xnu: unhandled MIG request {id} to {obj:?}");
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
            let mut data = read_bytes(&self.mem, msg, send_size);
            let bits = le(&data, 0);
            let (remote, local) = (le(&data, 8), le(&data, 12));
            // Swap remote/local for the receiver's view, as the kernel does.
            data[8..12].copy_from_slice(&local.to_le_bytes());
            data[12..16].copy_from_slice(&remote.to_le_bytes());
            let reply_bits = (bits >> 8) & 0xff;
            data[0..4].copy_from_slice(
                &((bits & !0xffff) | (reply_bits & 0xff) | ((bits & 0xff) << 8)).to_le_bytes(),
            );
            if self.trace {
                echo!(
                    "xnu:   mach_msg send id {} to {remote:#x} reply {local:#x}",
                    le(&data, 20)
                );
            }
            let Some(port) = self.ipc.ports.get(&remote) else {
                log!(
                    "xnu: mach_msg to invalid port {remote:#x} (id {})",
                    le(&data, 20)
                );
                return Some(MACH_SEND_INVALID_DEST);
            };
            if let Some(obj) = port.kobject.clone() {
                if let Some(rep) = self.kernel_msg(obj, &read_bytes(&self.mem, msg, send_size)) {
                    if local != 0 {
                        if let Some(p) = self.ipc.ports.get_mut(&local) {
                            p.queue.push_back(rep);
                        }
                    }
                }
            } else if remote == self.ipc.bootstrap_port {
                if let Some(rep) = super::mach::bootstrap_msg(self, &data) {
                    if let Some(p) = self.ipc.ports.get_mut(&local) {
                        p.queue.push_back(rep);
                    }
                }
            } else {
                self.ipc
                    .ports
                    .get_mut(&remote)
                    .unwrap()
                    .queue
                    .push_back(data);
            }
        }
        if option & MACH_RCV_MSG != 0 {
            if let Some(kr) = self.try_receive(msg, rcv_size, rcv_name) {
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

    fn try_receive(&mut self, msg: u32, rcv_size: u32, name: u32) -> Option<u32> {
        let candidates: Vec<u32> = match self.ipc.ports.get(&name) {
            Some(p) if p.is_set => self
                .ipc
                .ports
                .iter()
                .filter(|(_, p)| p.set == Some(name))
                .map(|(&n, _)| n)
                .collect(),
            Some(_) => vec![name],
            None => return Some(KERN_INVALID_NAME),
        };
        for n in candidates {
            let p = self.ipc.ports.get_mut(&n).unwrap();
            if let Some(m) = p.queue.front() {
                if m.len() as u32 > rcv_size {
                    return Some(MACH_RCV_TOO_LARGE);
                }
                let m = p.queue.pop_front().unwrap();
                write_bytes(&mut self.mem, msg, &m);
                // msgh_local_port of the received message is the port it came on
                write_u32(&mut self.mem, msg + 12, n);
                return Some(KERN_SUCCESS);
            }
        }
        None
    }
}

/// The bootstrap port (launchd). Lookups of services we do not provide fail.
pub fn bootstrap_msg(k: &mut Kernel, msg: &[u8]) -> Option<Vec<u8>> {
    let id = le(msg, 20);
    let name_at = |o: usize| {
        let s = &msg[o..(o + 128).min(msg.len())];
        String::from_utf8_lossy(&s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())])
            .into_owned()
    };
    match id {
        // bootstrap_look_up(bp, name[128])
        404 | 402 => {
            log!(
                "xnu: bootstrap_look_up({:?}) - no such service",
                name_at(32)
            );
            Some(reply(msg, &[1102], &[])) // BOOTSTRAP_UNKNOWN_SERVICE
        }
        _ => {
            log!("xnu: unhandled bootstrap request {id}");
            let _ = k;
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
        29 => Some(k.ipc.host_port),           // host_self_trap
        31 => k.mach_msg(),
        33 | 34 => {
            // semaphore_signal(_all)
            let port = k.arg(0);
            if let Some(Some(KObject::Semaphore { count })) =
                k.ipc.ports.get_mut(&port).map(|p| p.kobject.as_mut())
            {
                *count += 1;
            }
            Some(KERN_SUCCESS)
        }
        36 | 38 => {
            let port = k.arg(0);
            let deadline = (num == 38).then(|| {
                k.absolute_time() + (k.arg(1) as u64 * 1_000_000_000 + k.arg(2) as u64) * 3 / 125
            });
            let block = Block::Semaphore { port, deadline };
            if retry_blocked(k, &block) {
                Some(KERN_SUCCESS)
            } else {
                k.current_thread().blocked = Some(block);
                None
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
        59..=61 => Some(KERN_SUCCESS), // thread_switch, swtch, swtch_pri
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
            let (msg, rcv_size) = (k.arg(0), k.arg(3));
            match k.try_receive(msg, rcv_size, name) {
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
        _ => false,
    }
}

pub fn timeout_blocked(k: &mut Kernel, block: &Block) {
    k.cpu.regs_mut()[0] = match block {
        Block::MachReceive { .. } => MACH_RCV_TIMED_OUT,
        Block::Semaphore { .. } => 49, // KERN_OPERATION_TIMED_OUT
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
        367 | 368 => Some(Ret::Err(45)),
        _ => {
            let _ = read_u32;
            None
        }
    }
}
