/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Saves the booted system once SpringBoard is idle at the lock screen, and
//! boots a later page load from that state instead of from dyld. Only guest
//! state is kept; the window, JIT code and firmware image are made anew.
//!
//! The web page passes a saved state in as `DIR/restore.bin`, asks for one
//! with `DIR/save`, and keeps it in the browser's own storage.

use super::iokit::{Entry, Prop, Registry, Surface, VSync};
use super::lockdown::{Job, Launchd, Lockdownd, Service, Socket, Spawn, LAUNCHD};
use super::mach::{Ipc, KObject, Port};
use super::notifyd::{Delivery, Notifyd, Registration};
use super::vfs::{FileKind, Kqueue, OpenFile, Shm, ShmMap, UserEvent, Vfs};
use super::vm::{Prot, Region, VmMap};
use super::{Block, Kernel, Parked, Thread};
use crate::cpu::{Cpu, CpuContext};
use crate::firmware::{Firmware, IpswInfo};
use crate::mem::Mem;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

const DIR: &str = "/touchHLE-snapshot";
const PAGE: usize = 0x1000;
const WINDOW: usize = Mem::CPU_WINDOW_MASK as usize + 1;
static ZERO: [u8; PAGE] = [0; PAGE];
/// How long the data partition may stay busy once the lock screen is up.
const SETTLE: Duration = Duration::from_secs(3);

thread_local! {
    static WANT_SAVE: Cell<bool> = const { Cell::new(false) };
    static DISPLAY_SINCE: Cell<Option<u64>> = const { Cell::new(None) };
}

#[derive(Default)]
struct W {
    out: Vec<u8>,
    shms: Vec<Rc<RefCell<Shm>>>,
    kqueues: Vec<Rc<RefCell<Kqueue>>>,
}

struct R<'a> {
    b: &'a [u8],
    bad: bool,
    info: &'a IpswInfo,
    vfs: &'a Vfs,
    shms: Vec<Rc<RefCell<Shm>>>,
    kqueues: Vec<Rc<RefCell<Kqueue>>>,
}

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        if n > self.b.len() {
            self.bad = true;
            self.b = &[];
            return &[];
        }
        let (head, tail) = self.b.split_at(n);
        self.b = tail;
        head
    }
    fn len(&mut self) -> usize {
        let n = u32::get(self) as usize;
        if n > self.b.len() {
            self.bad = true;
            return 0;
        }
        n
    }
}

trait Put {
    fn put(&self, w: &mut W);
}
trait Get: Sized {
    fn get(r: &mut R) -> Self;
}

macro_rules! snap_int {
    ($($t:ty),*) => {$(
        impl Put for $t {
            fn put(&self, w: &mut W) {
                w.out.extend(self.to_le_bytes());
            }
        }
        impl Get for $t {
            fn get(r: &mut R) -> Self {
                r.take(size_of::<$t>())
                    .try_into()
                    .map_or(0, <$t>::from_le_bytes)
            }
        }
    )*};
}
snap_int!(u8, u16, u32, u64, i32);

macro_rules! snap_struct {
    ($t:ty: $($f:ident),*) => {
        impl Put for $t {
            fn put(&self, w: &mut W) {
                $(self.$f.put(w);)*
            }
        }
        impl Get for $t {
            fn get(r: &mut R) -> Self {
                Self { $($f: Get::get(r)),* }
            }
        }
    };
}

impl Put for usize {
    fn put(&self, w: &mut W) {
        (*self as u64).put(w)
    }
}
impl Get for usize {
    fn get(r: &mut R) -> Self {
        u64::get(r) as usize
    }
}
impl Put for bool {
    fn put(&self, w: &mut W) {
        (*self as u8).put(w)
    }
}
impl Get for bool {
    fn get(r: &mut R) -> Self {
        u8::get(r) != 0
    }
}
impl Put for str {
    fn put(&self, w: &mut W) {
        self.as_bytes().put(w)
    }
}
impl Put for String {
    fn put(&self, w: &mut W) {
        self.as_str().put(w)
    }
}
impl Get for String {
    fn get(r: &mut R) -> Self {
        let n = r.len();
        String::from_utf8_lossy(r.take(n)).into_owned()
    }
}
impl<T: Put + ?Sized> Put for &T {
    fn put(&self, w: &mut W) {
        (**self).put(w)
    }
}
impl<T: Put + ?Sized> Put for Box<T> {
    fn put(&self, w: &mut W) {
        (**self).put(w)
    }
}
impl<T: Get> Get for Box<T> {
    fn get(r: &mut R) -> Self {
        Box::new(T::get(r))
    }
}
impl<const N: usize> Put for [u32; N] {
    fn put(&self, w: &mut W) {
        self.iter().for_each(|v| v.put(w));
    }
}
impl<const N: usize> Get for [u32; N] {
    fn get(r: &mut R) -> Self {
        std::array::from_fn(|_| u32::get(r))
    }
}
impl<T: Put> Put for Option<T> {
    fn put(&self, w: &mut W) {
        self.is_some().put(w);
        if let Some(v) = self {
            v.put(w);
        }
    }
}
impl<T: Get> Get for Option<T> {
    fn get(r: &mut R) -> Self {
        bool::get(r).then(|| T::get(r))
    }
}

macro_rules! snap_tuple {
    ($($t:ident),*) => {
        impl<$($t: Put),*> Put for ($($t,)*) {
            #[allow(non_snake_case)]
            fn put(&self, w: &mut W) {
                let ($($t,)*) = self;
                $($t.put(w);)*
            }
        }
        impl<$($t: Get),*> Get for ($($t,)*) {
            fn get(r: &mut R) -> Self {
                ($($t::get(r),)*)
            }
        }
    };
}
snap_tuple!(A, B);
snap_tuple!(A, B, C);
snap_tuple!(A, B, C, D);

/// Byte strings are copied whole rather than element by element.
impl Put for [u8] {
    fn put(&self, w: &mut W) {
        (self.len() as u32).put(w);
        w.out.extend(self);
    }
}

macro_rules! snap_seq {
    ($($t:ident<$p:ident: $($b:path),*>),*) => {$(
        impl<$p: Put $(+ $b)*> Put for $t<$p> {
            fn put(&self, w: &mut W) {
                (self.len() as u32).put(w);
                for v in self {
                    v.put(w);
                }
            }
        }
        impl<$p: Get $(+ $b)*> Get for $t<$p> {
            fn get(r: &mut R) -> Self {
                let n = r.len();
                (0..n).map(|_| $p::get(r)).collect()
            }
        }
    )*};
}
snap_seq!(Vec<T:>, VecDeque<T:>, HashSet<T: Eq, Hash>);

impl<K: Put, V: Put> Put for HashMap<K, V> {
    fn put(&self, w: &mut W) {
        (self.len() as u32).put(w);
        for kv in self {
            kv.put(w);
        }
    }
}
impl<K: Get + Eq + Hash, V: Get> Get for HashMap<K, V> {
    fn get(r: &mut R) -> Self {
        let n = r.len();
        (0..n).map(|_| <(K, V)>::get(r)).collect()
    }
}
impl<V: Put> Put for BTreeMap<u32, V> {
    fn put(&self, w: &mut W) {
        (self.len() as u32).put(w);
        for kv in self {
            kv.put(w);
        }
    }
}
impl<V: Get> Get for BTreeMap<u32, V> {
    fn get(r: &mut R) -> Self {
        let n = r.len();
        (0..n).map(|_| <(u32, V)>::get(r)).collect()
    }
}

/// Objects shared by several descriptors or mappings are written once and
/// referred to by index after that.
macro_rules! snap_shared {
    ($t:ty, $pool:ident) => {
        impl Put for Rc<RefCell<$t>> {
            fn put(&self, w: &mut W) {
                match w.$pool.iter().position(|o| Rc::ptr_eq(o, self)) {
                    Some(i) => (i as u32).put(w),
                    None => {
                        (w.$pool.len() as u32).put(w);
                        w.$pool.push(self.clone());
                        self.borrow().put(w);
                    }
                }
            }
        }
        impl Get for Rc<RefCell<$t>> {
            fn get(r: &mut R) -> Self {
                let i = u32::get(r) as usize;
                if let Some(o) = r.$pool.get(i) {
                    return o.clone();
                }
                let o = Rc::new(RefCell::new(<$t>::get(r)));
                r.$pool.push(o.clone());
                o
            }
        }
    };
}
snap_shared!(Shm, shms);
snap_shared!(Kqueue, kqueues);

snap_struct!(CpuContext: regs, extregs, cpsr, fpscr);
snap_struct!(Region: size, prot, tag);
snap_struct!(VmMap: regions, low, high);
snap_struct!(Shm: data);
snap_struct!(Kqueue: user);
snap_struct!(UserEvent: ident, udata, fflags, flags, triggered);
snap_struct!(ShmMap: pid, addr, len, refs, shm);
snap_struct!(Port: kobject, queue, sets, is_set);
snap_struct!(Ipc: ports, next_name, task_port, host_port, bootstrap_port, services,
    missing_services, timers, notifyd);
snap_struct!(Notifyd: states, tokens, next_token, slots, shm);
snap_struct!(Registration: name, delivery);
snap_struct!(Entry: name, class, parent, children, props);
snap_struct!(Surface: pid, addr, alloc_size, width, height, bytes_per_row, bytes_per_element,
    pixel_format, seed_block);
snap_struct!(VSync: port, callback, refcon, next);
snap_struct!(Registry: entries, surfaces, presented_surface, lcd_owner, mbx_command_buffer,
    mbx_handles, next_mbx_handle, notify_ports, vsyncs, hid_queues);
snap_struct!(Socket: service, rx, tx);
snap_struct!(Job: label, pid, exit);
snap_struct!(Spawn: label, pid, program, args, env, mach_services);
snap_struct!(Launchd: jobs, spawns, kills, next_pid);
snap_struct!(Thread: id, tid, port, context, tls, blocked, exited, pid);

impl Put for Prot {
    fn put(&self, w: &mut W) {
        self.0.put(w)
    }
}
impl Get for Prot {
    fn get(r: &mut R) -> Self {
        Prot(u32::get(r))
    }
}

impl Put for Block {
    fn put(&self, w: &mut W) {
        match *self {
            Block::MachReceive { name, deadline } => (0u8, name, deadline).put(w),
            Block::Semaphore { port, deadline } => (1u8, port, deadline).put(w),
            Block::Sleep { deadline } => (2u8, 0u32, Some(deadline)).put(w),
            Block::SemWait { port, deadline } => (3u8, port, deadline).put(w),
        }
    }
}
impl Get for Block {
    fn get(r: &mut R) -> Self {
        let (tag, port, deadline) = <(u8, u32, Option<u64>)>::get(r);
        match tag {
            0 => Block::MachReceive {
                name: port,
                deadline,
            },
            1 => Block::Semaphore { port, deadline },
            2 => Block::Sleep {
                deadline: deadline.unwrap_or(0),
            },
            _ => Block::SemWait { port, deadline },
        }
    }
}

impl Put for KObject {
    fn put(&self, w: &mut W) {
        match self {
            KObject::Task(pid) => (0u8, pid).put(w),
            KObject::Thread(id) => (1u8, id).put(w),
            KObject::Host => 2u8.put(w),
            KObject::Semaphore { count } => (3u8, count).put(w),
            KObject::Clock => 4u8.put(w),
            KObject::IoMaster => 5u8.put(w),
            KObject::IoEntry(i) => (6u8, i).put(w),
            KObject::IoIterator { items, pos } => (7u8, items, pos).put(w),
            KObject::IoConnect(i) => (8u8, i).put(w),
            KObject::Notifyd => 9u8.put(w),
            KObject::Installd => 10u8.put(w),
            KObject::MediaServer { system_sound_port } => (11u8, system_sound_port).put(w),
            KObject::SystemSound => 12u8.put(w),
        }
    }
}
impl Get for KObject {
    fn get(r: &mut R) -> Self {
        match u8::get(r) {
            0 => KObject::Task(Get::get(r)),
            1 => KObject::Thread(Get::get(r)),
            2 => KObject::Host,
            3 => KObject::Semaphore { count: Get::get(r) },
            4 => KObject::Clock,
            5 => KObject::IoMaster,
            6 => KObject::IoEntry(Get::get(r)),
            7 => KObject::IoIterator {
                items: Get::get(r),
                pos: Get::get(r),
            },
            8 => KObject::IoConnect(Get::get(r)),
            9 => KObject::Notifyd,
            10 => KObject::Installd,
            11 => KObject::MediaServer {
                system_sound_port: Get::get(r),
            },
            _ => KObject::SystemSound,
        }
    }
}

impl Put for Prop {
    fn put(&self, w: &mut W) {
        match self {
            Prop::Data(d) => (0u8, d.as_slice()).put(w),
            Prop::Number(n) => (1u8, n).put(w),
            Prop::Str(s) => (2u8, s).put(w),
            Prop::Dict(d) => (3u8, d).put(w),
        }
    }
}
impl Get for Prop {
    fn get(r: &mut R) -> Self {
        match u8::get(r) {
            0 => Prop::Data(Get::get(r)),
            1 => Prop::Number(Get::get(r)),
            2 => Prop::Str(Get::get(r)),
            _ => Prop::Dict(Get::get(r)),
        }
    }
}

impl Put for Delivery {
    fn put(&self, w: &mut W) {
        match self {
            Delivery::Check { changed } => (0u8, changed).put(w),
            Delivery::MachPort { port, client_token } => (1u8, port, client_token).put(w),
        }
    }
}
impl Get for Delivery {
    fn get(r: &mut R) -> Self {
        match u8::get(r) {
            0 => Delivery::Check {
                changed: Get::get(r),
            },
            _ => Delivery::MachPort {
                port: Get::get(r),
                client_token: Get::get(r),
            },
        }
    }
}

/// lockdownd's answers only depend on the firmware, so it is made anew.
impl Put for Service {
    fn put(&self, w: &mut W) {
        matches!(self, Service::Launchd).put(w)
    }
}
impl Get for Service {
    fn get(r: &mut R) -> Self {
        if bool::get(r) {
            Service::Launchd
        } else {
            Service::Lockdownd(Lockdownd::new(r.info))
        }
    }
}

/// Host files are opened again by path.
impl Put for OpenFile {
    fn put(&self, w: &mut W) {
        (&self.path, self.flags, self.offset).put(w);
        match &self.kind {
            FileKind::Firmware { node } => (0u8, node).put(w),
            FileKind::Host(_) => 1u8.put(w),
            FileKind::Dir { path, entries, pos } => (2u8, path, entries, pos).put(w),
            FileKind::Null => 3u8.put(w),
            FileKind::Console => 4u8.put(w),
            FileKind::Random => 5u8.put(w),
            FileKind::Socket(s) => (6u8, s).put(w),
            FileKind::Kqueue(q) => (7u8, q).put(w),
            FileKind::Shm(s) => (8u8, s).put(w),
        }
    }
}
impl Get for OpenFile {
    fn get(r: &mut R) -> Self {
        let (path, flags, offset) = <(String, u32, u64)>::get(r);
        let kind = match u8::get(r) {
            0 => FileKind::Firmware { node: u32::get(r) },
            1 => match std::fs::OpenOptions::new()
                .read(true)
                .write(flags & 3 != 0)
                .open(r.vfs.host_path(&path))
            {
                Ok(f) => FileKind::Host(f),
                Err(e) => {
                    log!("snapshot: can't reopen {path}: {e}");
                    FileKind::Null
                }
            },
            2 => FileKind::Dir {
                path: Get::get(r),
                entries: Get::get(r),
                pos: Get::get(r),
            },
            3 => FileKind::Null,
            4 => FileKind::Console,
            5 => FileKind::Random,
            6 => FileKind::Socket(Get::get(r)),
            7 => FileKind::Kqueue(Get::get(r)),
            _ => FileKind::Shm(Get::get(r)),
        };
        OpenFile {
            kind,
            offset,
            path,
            flags,
        }
    }
}

/// The shared cache's mappings: address in the window, size, file offset.
fn cache_maps(cache: &[u8]) -> Vec<(usize, usize, usize)> {
    let le = |o: usize| u32::from_le_bytes(cache[o..o + 4].try_into().unwrap()) as usize;
    let (off, count) = (le(16), le(20));
    (0..count)
        .map(|i| off + i * 32)
        .map(|m| (le(m) & (WINDOW - 1), le(m + 8), le(m + 16)))
        .collect()
}

/// A page as a fresh process has it: the pristine shared cache, else zero.
fn base_page<'a>(
    maps: &[(usize, usize, usize)],
    cache: &'a [u8],
    at: usize,
    buf: &'a mut [u8; PAGE],
) -> &'a [u8] {
    let Some(&(addr, size, off)) = maps.iter().find(|m| at < m.0 + m.1 && at + PAGE > m.0) else {
        return &ZERO;
    };
    if at >= addr && at + PAGE <= addr + size {
        return &cache[off + at - addr..][..PAGE];
    }
    buf.fill(0);
    let start = at.max(addr);
    let end = (at + PAGE).min(addr + size);
    buf[start - at..end - at].copy_from_slice(&cache[off + start - addr..off + end - addr]);
    buf
}

/// Stores the pages that differ from a fresh process's, as runs.
fn put_mem(w: &mut W, cache: &[u8], mem: &mut Mem) -> [usize; 3] {
    let maps = cache_maps(cache);
    let window = unsafe { std::slice::from_raw_parts(mem.cpu_window(), WINDOW) };
    let mut buf = [0; PAGE];
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let (mut nonzero, mut pristine) = (0, 0);
    for page in 0..WINDOW / PAGE {
        let at = page * PAGE;
        let cur = &window[at..at + PAGE];
        let base = base_page(&maps, cache, at, &mut buf);
        if cur != ZERO {
            nonzero += 1;
        }
        if cur == base {
            pristine += (base != ZERO) as usize;
            continue;
        }
        match runs.last_mut() {
            Some((start, n)) if *start + *n == page => *n += 1,
            _ => runs.push((page, 1)),
        }
    }
    mem.null_segment_size().put(w);
    (runs.len() as u32).put(w);
    let mut stored = 0;
    for (start, n) in runs {
        (start as u32, n as u32).put(w);
        w.out.extend(&window[start * PAGE..(start + n) * PAGE]);
        stored += n;
    }
    [nonzero, pristine, stored]
}

fn get_mem(r: &mut R, cache: &[u8]) -> Mem {
    let mut mem = Mem::new();
    let _ = Kernel::map_shared_cache(&mut mem, &mut VmMap::new(0, 0), cache);
    let null = u32::get(r);
    let window = unsafe { std::slice::from_raw_parts_mut(mem.cpu_window(), WINDOW) };
    for _ in 0..u32::get(r) {
        let (start, n) = <(u32, u32)>::get(r);
        let (at, len) = (start as usize * PAGE, n as usize * PAGE);
        let bytes = r.take(len);
        if bytes.len() != len || at + len > WINDOW {
            r.bad = true;
            break;
        }
        window[at..at + len].copy_from_slice(bytes);
    }
    if null != 0 {
        mem.set_null_segment_size(null);
    }
    mem
}

/// The data partition's files, which live in the page's in-memory
/// filesystem and are gone after a reload. Returns how many were written.
fn put_overlay(w: &mut W, dir: &Path, rel: &str) -> u32 {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name());
    let mut count = 0;
    for e in entries {
        let rel = format!("{rel}/{}", e.file_name().to_string_lossy());
        let path = e.path();
        if path.is_dir() {
            (true, &rel).put(w);
            count += 1 + put_overlay(w, &path, &rel);
        } else if let Ok(data) = std::fs::read(&path) {
            (false, &rel, data.as_slice()).put(w);
            count += 1;
        }
    }
    count
}

fn get_overlay(r: &mut R, dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::create_dir_all(dir);
    for _ in 0..u32::get(r) {
        let is_dir = bool::get(r);
        let path = dir.join(String::get(r).trim_start_matches('/'));
        let done = if is_dir {
            std::fs::create_dir_all(&path)
        } else {
            let n = r.len();
            std::fs::write(&path, r.take(n))
        };
        if let Err(e) = done {
            log!("snapshot: can't restore {}: {e}", path.display());
        }
    }
}

fn capture(cpu: &mut Cpu) -> (CpuContext, u32) {
    let mut ctx = CpuContext::new();
    cpu.swap_context(&mut ctx);
    let state = ctx.clone();
    cpu.swap_context(&mut ctx);
    (state, cpu.tls())
}

/// A snapshot only fits the build that made it.
fn header() -> String {
    format!("touchHLE snapshot 2 {}\n", crate::VERSION)
}

fn save(k: &mut Kernel) -> Vec<u8> {
    let mut w = W::default();
    w.out.extend(header().as_bytes());

    let mut overlay = W::default();
    let count = put_overlay(&mut overlay, &k.vfs.overlay, "");
    count.put(&mut w);
    w.out.extend(&overlay.out);
    let overlay_size = overlay.out.len();

    (k.now_ns(), k.pid, k.current, k.next_tid).put(&mut w);
    let (live, live_tls) = capture(&mut k.cpu);
    (k.threads.len() as u32).put(&mut w);
    for (i, t) in k.threads.iter().enumerate() {
        let (context, tls) = if i == k.current {
            (Some(live.clone()), live_tls)
        } else if t.context.is_none() && !t.exited {
            match k.parked.get_mut(&t.pid) {
                Some(p) => {
                    let (c, tls) = capture(&mut p.cpu);
                    (Some(c), tls)
                }
                None => (None, t.tls),
            }
        } else {
            (t.context.as_deref().cloned(), t.tls)
        };
        (t.id, t.tid, t.port).put(&mut w);
        (context, tls, &t.blocked).put(&mut w);
        (t.exited, t.pid).put(&mut w);
    }

    let current = (
        k.pid,
        [
            k.ipc.task_port,
            k.bsdthread_start,
            k.pthread_size,
            k.iokit.mbx_command_buffer,
        ],
        &mut k.mem,
        &k.vm,
        &k.vfs.fds,
        &k.vfs.cwd,
    );
    let parked = k.parked.iter_mut().map(|(&pid, p)| {
        (
            pid,
            [
                p.task_port,
                p.bsdthread_start,
                p.pthread_size,
                p.mbx_command_buffer,
            ],
            &mut p.mem,
            &p.vm,
            &p.fds,
            &p.cwd,
        )
    });
    let procs: Vec<_> = std::iter::once(current).chain(parked).collect();
    (procs.len() as u32).put(&mut w);
    for (pid, words, mem, vm, fds, cwd) in procs {
        (pid, words, (vm, fds, cwd)).put(&mut w);
        let before = w.out.len();
        let [nonzero, pristine, stored] = put_mem(&mut w, &k.shared_cache, mem);
        log!(
            "snapshot: pid {pid}: {nonzero} non-zero pages, {pristine} pristine shared cache \
             pages, {stored} pages stored ({} KiB)",
            (w.out.len() - before) / 1024
        );
    }

    (&k.vfs.deleted, &k.vfs.shm, &k.vfs.shm_maps).put(&mut w);
    let before = w.out.len();
    (&k.ipc, &k.iokit).put(&mut w);
    LAUNCHD.with_borrow(|l| l.put(&mut w));
    log!(
        "snapshot: {} threads, {} ports, {} surfaces, overlay {count} entries ({} KiB), \
         kernel {} KiB",
        k.threads.len(),
        k.ipc.ports.len(),
        k.iokit.surfaces.len(),
        overlay_size / 1024,
        (w.out.len() - before) / 1024
    );
    w.out
}

fn restore(fw: Firmware, overlay: &Path, b: &[u8]) -> Result<Kernel, Box<Firmware>> {
    let Some(b) = b.strip_prefix(header().as_bytes()) else {
        log!("snapshot: made by another build of touchHLE");
        return Err(Box::new(fw));
    };
    let t = Instant::now();
    let shared_cache = match Kernel::read_shared_cache(&fw) {
        Ok(c) => c,
        Err(e) => {
            log!("snapshot: {e}");
            return Err(Box::new(fw));
        }
    };
    log!(
        "snapshot: read the shared cache in {} ms",
        t.elapsed().as_millis()
    );
    let mut vfs = Vfs::new(overlay);
    let mut r = R {
        b,
        bad: false,
        info: &fw.info,
        vfs: &vfs,
        shms: Vec::new(),
        kqueues: Vec::new(),
    };
    get_overlay(&mut r, overlay);
    let (now, pid, current, next_tid) = <(u64, u32, usize, u64)>::get(&mut r);
    let mut threads = Vec::<Thread>::get(&mut r);
    let mut procs = Vec::new();
    for _ in 0..u32::get(&mut r) {
        let (pid, words, (vm, fds, cwd)) =
            <(u32, [u32; 4], (VmMap, HashMap<u32, OpenFile>, String))>::get(&mut r);
        let mem = get_mem(&mut r, &shared_cache);
        procs.push((
            pid,
            Parked {
                mem,
                cpu: Cpu::new(None),
                vm,
                fds,
                cwd,
                task_port: words[0],
                bsdthread_start: words[1],
                pthread_size: words[2],
                mbx_command_buffer: words[3],
            },
        ));
    }
    let deleted: HashSet<String> = Get::get(&mut r);
    let shm: HashMap<String, Rc<RefCell<Shm>>> = Get::get(&mut r);
    let shm_maps: Vec<ShmMap> = Get::get(&mut r);
    let (ipc, iokit) = <(Ipc, Registry)>::get(&mut r);
    let launchd = Launchd::get(&mut r);
    let bad = r.bad || !r.b.is_empty() || current >= threads.len();
    drop(r);
    let running = procs.iter().position(|p| p.0 == pid);
    let (Some(running), false) = (running, bad) else {
        log!("snapshot: damaged snapshot");
        let _ = std::fs::remove_dir_all(overlay);
        return Err(Box::new(fw));
    };
    let (_, p) = procs.swap_remove(running);
    let mut cpu = p.cpu;
    if let Some(mut ctx) = threads[current].context.take() {
        cpu.swap_context(&mut ctx);
    }
    cpu.set_tls(threads[current].tls);
    vfs.fds = p.fds;
    vfs.cwd = p.cwd;
    vfs.deleted = deleted;
    vfs.shm = shm;
    vfs.shm_maps = shm_maps;
    LAUNCHD.with_borrow_mut(|l| *l = launchd);
    let mut ipc: Ipc = ipc;
    ipc.task_port = p.task_port;
    let mut iokit: Registry = iokit;
    iokit.mbx_command_buffer = p.mbx_command_buffer;
    let start = Instant::now() - Duration::from_nanos(now);
    Ok(Kernel {
        mem: p.mem,
        cpu,
        vm: p.vm,
        fw,
        shared_cache,
        vfs,
        ipc,
        iokit,
        threads,
        current,
        start,
        stalled: Duration::ZERO,
        display_on: false,
        last_tick: Instant::now(),
        last_now: Cell::new(now),
        exit_status: None,
        bsdthread_start: p.bsdthread_start,
        pthread_size: p.pthread_size,
        trace: std::env::var_os("TOUCHHLE_XNU_TRACE").is_some(),
        yield_requested: false,
        window: None,
        last_present: Instant::now(),
        shown: None,
        next_tid,
        pid,
        parked: procs.into_iter().collect(),
        test_input: Vec::new(),
    })
}

/// Boots from the snapshot the page passed in, if any, else from dyld.
pub fn boot(fw: Firmware, overlay: &Path, exe_path: &str) -> Result<Kernel, String> {
    let path = Path::new(DIR).join("restore.bin");
    let fw = match std::fs::read(&path) {
        Ok(bytes) => {
            let _ = std::fs::remove_file(&path);
            let t = Instant::now();
            match restore(fw, overlay, &bytes) {
                Ok(k) => {
                    log!(
                        "snapshot: restored {} MiB in {} ms",
                        bytes.len() >> 20,
                        t.elapsed().as_millis()
                    );
                    return Ok(k);
                }
                Err(fw) => {
                    extern "C" {
                        fn emscripten_run_script(script: *const std::ffi::c_char);
                    }
                    // The page deletes the snapshot and puts back the data
                    // partition, which restore() may have removed.
                    unsafe {
                        emscripten_run_script(c"globalThis.touchHLESnapshotFailed?.()".as_ptr())
                    };
                    *fw
                }
            }
        }
        Err(_) => fw,
    };
    // A first boot would put its one-time setup into every restore.
    WANT_SAVE.set(Path::new(DIR).join("save").exists() && overlay.exists());
    Kernel::boot(fw, overlay, exe_path, vec![exe_path.to_string()])
}

/// A SQLite rollback journal means a transaction is still open.
fn busy(dir: &Path) -> bool {
    std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| {
            e.file_name().to_string_lossy().ends_with("-journal")
                || e.file_type().is_ok_and(|t| t.is_dir()) && busy(&e.path())
        })
}

/// Called while every thread is blocked. Saves as soon as the lock screen is
/// up and the data partition is not mid-write, if the page asked for it.
/// SpringBoard turns the screen off a few seconds after the lock screen
/// appears, so a later save would leave a restore less of that time.
pub fn idle(k: &mut Kernel) {
    if !WANT_SAVE.get() || !k.display_on {
        return;
    }
    let now = k.now_ns();
    let since = DISPLAY_SINCE.get().unwrap_or(now);
    DISPLAY_SINCE.set(Some(since));
    if busy(&k.vfs.overlay) {
        if now - since > SETTLE.as_nanos() as u64 {
            WANT_SAVE.set(false);
            log!("snapshot: the data partition is still being written; not saved");
        }
        return;
    }
    WANT_SAVE.set(false);
    let t = Instant::now();
    let bytes = save(k);
    log!(
        "snapshot: saved {} MiB in {} ms",
        bytes.len() >> 20,
        t.elapsed().as_millis()
    );
    extern "C" {
        fn emscripten_run_script(script: *const std::ffi::c_char);
    }
    let script = format!(
        "globalThis.touchHLESnapshotSave?.({}, {})\0",
        bytes.as_ptr() as usize,
        bytes.len()
    );
    unsafe { emscripten_run_script(script.as_ptr().cast()) };
}
