/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! BSD syscalls (positive syscall numbers, `svc 0x80` with the number in r12).
//! Success clears the carry flag; failure sets it and returns errno in r0.

use super::vfs::{self, FileKind, OpenFile, Stat};
use super::vm::{round_up, Prot};
use super::{read_bytes, read_cstr, read_u32, write_bytes, write_u32, Kernel};

pub enum Ret {
    Ok(u32, u32),
    Err(u32),
    /// The thread blocked; its result is set when it wakes.
    Blocked,
}

const ENOMEM: u32 = 12;
const EINVAL: u32 = 22;
const ENOTTY: u32 = 25;
const ESPIPE: u32 = 29;
const ENOSYS: u32 = 78;
const ENOTSUP: u32 = 45;
const ENOTSOCK: u32 = 38;
const EAFNOSUPPORT: u32 = 47;

fn ok(v: u32) -> Ret {
    Ret::Ok(v, 0)
}
fn res(r: Result<u32, u32>) -> Ret {
    match r {
        Ok(v) => ok(v),
        Err(e) => Ret::Err(e),
    }
}

/// sysctl names that the userland reads, with their OIDs.
const SYSCTLS: &[(&str, &[u32])] = &[
    ("kern.ostype", &[1, 1]),
    ("kern.osrelease", &[1, 2]),
    ("kern.version", &[1, 4]),
    ("kern.hostname", &[1, 10]),
    ("kern.usrstack", &[1, 35]),
    ("kern.osversion", &[1, 65]),
    ("kern.boottime", &[1, 21]),
    ("kern.maxfiles", &[1, 7]),
    ("kern.argmax", &[1, 8]),
    ("hw.machine", &[6, 1]),
    ("hw.model", &[6, 2]),
    ("hw.ncpu", &[6, 3]),
    ("hw.byteorder", &[6, 4]),
    ("hw.physmem", &[6, 5]),
    ("hw.usermem", &[6, 6]),
    ("hw.pagesize", &[6, 7]),
    ("hw.memsize", &[6, 24]),
    ("hw.availcpu", &[6, 25]),
    ("hw.cpufamily", &[6, 108]),
    ("hw.cpusubtype", &[6, 109]),
    ("hw.cputype", &[6, 105]),
    ("hw.activecpu", &[6, 106]),
    ("hw.physicalcpu", &[6, 107]),
    ("hw.logicalcpu", &[6, 110]),
    ("hw.cpufrequency", &[6, 15]),
    ("hw.busfrequency", &[6, 14]),
    ("hw.tbfrequency", &[6, 23]),
    ("hw.cachelinesize", &[6, 13]),
];

impl Kernel {
    fn sysctl_value(&self, oid: &[u32]) -> Option<Vec<u8>> {
        let s = |v: &str| Some([v.as_bytes(), &[0]].concat());
        let i = |v: u32| Some(v.to_le_bytes().to_vec());
        let info = &self.fw.info;
        match oid {
            [1, 1] => s("Darwin"),
            [1, 2] => s("10.4.0"),
            [1, 4] => s("Darwin Kernel Version 10.4.0: touchHLE XNU personality; root:xnu-1504.58.28~3/RELEASE_ARM_S5L8900X"),
            [1, 10] => s("touchHLE"),
            [1, 35] => i(super::STACK_TOP),
            [1, 65] => s(&info.build),
            [1, 21] => Some([0u32.to_le_bytes(), 0u32.to_le_bytes()].concat()),
            [1, 7] => i(12288),
            [1, 8] => i(262144),
            [6, 1] => s(&info.product_type),
            [6, 2] => s("N82AP"),
            [6, 3] | [6, 25] | [6, 106] | [6, 107] | [6, 110] => i(1),
            [6, 4] => i(1234),
            [6, 5] | [6, 6] => i(128 << 20),
            [6, 7] => i(4096),
            [6, 24] => Some((128u64 << 20).to_le_bytes().to_vec()),
            [6, 108] => i(0xbd7f8e38),
            [6, 109] => i(6),
            [6, 105] => i(12),
            [6, 15] => i(412_000_000),
            [6, 14] => i(103_000_000),
            [6, 23] => i(24_000_000),
            [6, 13] => i(32),
            _ => None,
        }
    }

    fn sysctl(&mut self) -> Ret {
        let (name, namelen, oldp, oldlenp, newp, newlen) = (
            self.arg(0),
            self.arg(1),
            self.arg(2),
            self.arg(3),
            self.arg(4),
            self.arg(5),
        );
        let oid: Vec<u32> = (0..namelen.min(16))
            .map(|i| read_u32(&self.mem, name + i * 4))
            .collect();
        // sysctlbyname's name-to-OID lookup
        if oid == [0, 3] {
            let wanted = String::from_utf8_lossy(&read_bytes(&self.mem, newp, newlen))
                .trim_end_matches('\0')
                .to_string();
            let Some((_, found)) = SYSCTLS.iter().find(|(n, _)| *n == wanted) else {
                log_dbg!("xnu: unknown sysctl {wanted}");
                return Ret::Err(vfs::ENOENT);
            };
            let needed = found.len() as u32 * 4;
            if oldlenp == 0 || oldp == 0 || read_u32(&self.mem, oldlenp) < needed {
                return Ret::Err(ENOMEM);
            }
            for (j, v) in found.iter().enumerate() {
                write_u32(&mut self.mem, oldp + j as u32 * 4, *v);
            }
            write_u32(&mut self.mem, oldlenp, needed);
            return ok(0);
        }
        let Some(value) = self.sysctl_value(&oid) else {
            log!("xnu: unhandled sysctl {oid:?}");
            return Ret::Err(vfs::ENOENT);
        };
        if oldlenp != 0 {
            if oldp != 0 {
                let cap = read_u32(&self.mem, oldlenp) as usize;
                if cap < value.len() {
                    return Ret::Err(ENOMEM);
                }
                write_bytes(&mut self.mem, oldp, &value);
            }
            write_u32(&mut self.mem, oldlenp, value.len() as u32);
        }
        ok(0)
    }

    fn write_stat(&mut self, addr: u32, st: &Stat, is64: bool) {
        let mut b = vec![0u8; if is64 { 108 } else { 96 }];
        let put32 =
            |b: &mut Vec<u8>, o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
        let put16 =
            |b: &mut Vec<u8>, o: usize, v: u16| b[o..o + 2].copy_from_slice(&v.to_le_bytes());
        put32(&mut b, 0, 0x1000003);
        if is64 {
            put16(&mut b, 4, st.mode);
            put16(&mut b, 6, st.nlink);
            b[8..16].copy_from_slice(&st.ino.to_le_bytes());
            put32(&mut b, 16, st.uid);
            put32(&mut b, 20, st.gid);
            for o in [28, 36, 44, 52] {
                put32(&mut b, o, st.mtime);
            }
            b[60..68].copy_from_slice(&st.size.to_le_bytes());
            b[68..76].copy_from_slice(&st.size.div_ceil(512).to_le_bytes());
            put32(&mut b, 76, 4096);
        } else {
            put32(&mut b, 4, st.ino as u32);
            put16(&mut b, 8, st.mode);
            put16(&mut b, 10, st.nlink);
            put32(&mut b, 12, st.uid);
            put32(&mut b, 16, st.gid);
            for o in [24, 32, 40] {
                put32(&mut b, o, st.mtime);
            }
            b[48..56].copy_from_slice(&st.size.to_le_bytes());
            b[56..64].copy_from_slice(&st.size.div_ceil(512).to_le_bytes());
            put32(&mut b, 64, 4096);
        }
        write_bytes(&mut self.mem, addr, &b);
    }

    fn path_arg(&self, i: usize) -> String {
        let path = read_cstr(&self.mem, self.arg(i));
        if self.trace {
            echo!("xnu:   path {path:?}");
        }
        path
    }

    fn do_read(&mut self, fd: u32, buf: u32, len: u32, offset: Option<u64>) -> Ret {
        let mut tmp = vec![0u8; len as usize];
        match self.vfs.read(&self.fw, fd, &mut tmp, offset) {
            Ok(n) => {
                write_bytes(&mut self.mem, buf, &tmp[..n]);
                ok(n as u32)
            }
            Err(e) => Ret::Err(e),
        }
    }

    fn mmap_shm(
        &mut self,
        shm: std::rc::Rc<std::cell::RefCell<vfs::Shm>>,
        size: u32,
        prot: u32,
    ) -> Ret {
        let size = size.max(round_up(shm.borrow().size.min(u32::MAX as u64) as u32));
        if let Some(addr) = shm.borrow().addr {
            if !self.vm.is_free(addr, 1) {
                return ok(addr);
            }
        }
        let Some(base) = self
            .vm
            .map_anywhere(0, size, 0, Prot::from_bits(prot), "shm".into())
        else {
            return Ret::Err(ENOMEM);
        };
        write_bytes(&mut self.mem, base, &vec![0u8; size as usize]);
        shm.borrow_mut().addr = Some(base);
        ok(base)
    }

    fn mmap(&mut self) -> Ret {
        let (addr, len, prot, flags, fd) = (
            self.arg(0),
            self.arg(1),
            self.arg(2),
            self.arg(3),
            self.arg(4),
        );
        let offset = self.arg(5) as u64 | (self.arg(6) as u64) << 32;
        const MAP_FIXED: u32 = 0x10;
        const MAP_ANON: u32 = 0x1000;
        if len == 0 {
            return Ret::Err(EINVAL);
        }
        let size = round_up(len);
        if flags & MAP_ANON == 0 {
            if let Some(FileKind::Shm(shm)) = self.vfs.fds.get(&fd).map(|f| &f.kind) {
                return self.mmap_shm(shm.clone(), size, prot);
            }
        }
        // Read file contents before touching the address space, so a bad
        // descriptor leaves existing mappings intact.
        let contents = if flags & MAP_ANON == 0 {
            let mut tmp = vec![0u8; len as usize];
            match self.vfs.read(&self.fw, fd, &mut tmp, Some(offset)) {
                Ok(n) => {
                    tmp.truncate(n);
                    Some(tmp)
                }
                Err(e) => return Ret::Err(e),
            }
        } else {
            None
        };
        let base = if flags & MAP_FIXED != 0 {
            if self
                .vm
                .map_fixed(addr, size, Prot::from_bits(prot), "mmap".into())
                .is_err()
            {
                return Ret::Err(ENOMEM);
            }
            addr
        } else {
            let hint = if addr != 0 && self.vm.is_free(addr, size) {
                addr
            } else {
                0
            };
            match self
                .vm
                .map_anywhere(hint, size, 0, Prot::from_bits(prot), "mmap".into())
            {
                Some(a) => a,
                None => return Ret::Err(ENOMEM),
            }
        };
        write_bytes(&mut self.mem, base, &vec![0u8; size as usize]);
        if let Some(contents) = contents {
            write_bytes(&mut self.mem, base, &contents);
            self.cpu.invalidate_cache_range(base, size);
        }
        ok(base)
    }

    fn getdirentries(&mut self, is64: bool) -> Ret {
        let (fd, buf, nbytes, basep) = (self.arg(0), self.arg(1), self.arg(2), self.arg(3));
        let Some(f) = self.vfs.fds.get_mut(&fd) else {
            return Ret::Err(vfs::EBADF);
        };
        let FileKind::Dir { entries, pos, .. } = &mut f.kind else {
            return Ret::Err(vfs::ENOTDIR);
        };
        let mut out = Vec::new();
        while *pos < entries.len() {
            let (name, ty, ino) = &entries[*pos];
            let name = name.as_bytes();
            let mut rec = Vec::new();
            if is64 {
                // struct direntry: ino u64, seekoff u64, reclen u16, namlen
                // u16, type u8, name[1024]
                let reclen = (8 + 8 + 2 + 2 + 1 + name.len() + 1).next_multiple_of(4);
                rec.extend_from_slice(&ino.to_le_bytes());
                rec.extend_from_slice(&(*pos as u64 + 1).to_le_bytes());
                rec.extend_from_slice(&(reclen as u16).to_le_bytes());
                rec.extend_from_slice(&(name.len() as u16).to_le_bytes());
                rec.push(*ty);
                rec.extend_from_slice(name);
                rec.resize(reclen, 0);
            } else {
                // struct dirent: ino u32, reclen u16, type u8, namlen u8,
                // name[256]
                let reclen = (4 + 2 + 1 + 1 + name.len() + 1).next_multiple_of(4);
                rec.extend_from_slice(&(*ino as u32).to_le_bytes());
                rec.extend_from_slice(&(reclen as u16).to_le_bytes());
                rec.push(*ty);
                rec.push(name.len() as u8);
                rec.extend_from_slice(name);
                rec.resize(reclen, 0);
            }
            if out.len() + rec.len() > nbytes as usize {
                break;
            }
            out.extend_from_slice(&rec);
            *pos += 1;
        }
        let pos = *pos as u32;
        write_bytes(&mut self.mem, buf, &out);
        if basep != 0 {
            write_u32(&mut self.mem, basep, pos);
            if is64 {
                write_u32(&mut self.mem, basep + 4, 0);
            }
        }
        ok(out.len() as u32)
    }
}

pub fn syscall(k: &mut Kernel, num: u32, args_from: usize) -> Ret {
    // For the indirect syscall, arguments are shifted by one register.
    if args_from == 1 {
        let regs = *k.cpu.regs();
        k.cpu.regs_mut()[..6].copy_from_slice(&regs[1..7]);
    }
    let args: [u32; 8] = std::array::from_fn(|i| k.arg(i));
    match num {
        1 => {
            k.exit_status = Some(args[0] as i32);
            ok(0)
        }
        3 | 396 => k.do_read(args[0], args[1], args[2], None),
        4 | 397 => {
            let data = read_bytes(&k.mem, args[1], args[2]);
            res(k.vfs.write(args[0], &data, None).map(|n| n as u32))
        }
        5 | 398 => {
            let path = k.path_arg(0);
            let r = k.vfs.open(&k.fw, &path, args[1]);
            log_dbg!("xnu: open({path:?}, {:#x}) = {r:?}", args[1]);
            res(r)
        }
        6 | 399 => res(k.vfs.fds.remove(&args[0]).map(|_| 0).ok_or(vfs::EBADF)),
        10 => res(k.vfs.unlink(&k.fw, &k.path_arg(0)).map(|_| 0)),
        12 => {
            let path = k.path_arg(0);
            match k.vfs.stat(&k.fw, &path, true) {
                Ok(st) if st.mode & 0o170000 == 0o040000 => {
                    k.vfs.cwd = k.vfs.canonical(&k.fw, &path);
                    ok(0)
                }
                Ok(_) => Ret::Err(vfs::ENOTDIR),
                Err(e) => Ret::Err(e),
            }
        }
        15 | 16 | 124 | 123 | 34 | 35 | 95 | 408 | 131 | 138 | 139 => ok(0), // chmod, chown, fchmod, fchown, chflags, fchflags, fsync, flock, utimes, futimes
        20 => ok(1),        // getpid: we are the only process
        24 | 25 => ok(501), // getuid, geteuid: mobile
        43 | 47 => ok(501), // getegid, getgid
        39 => ok(1),
        33 => {
            let path = k.path_arg(0);
            res(k.vfs.stat(&k.fw, &path, true).map(|_| 0))
        }
        37 => ok(0), // kill
        // recvfrom(fd, buf, len, flags, from, fromlen)
        29 => {
            const MSG_PEEK: u32 = 2;
            match k.vfs.fds.get(&args[0]).map(|f| &f.kind) {
                Some(FileKind::Socket(s)) if args[3] & MSG_PEEK != 0 => {
                    let mut tmp = vec![0u8; args[2] as usize];
                    let n = s.peek(&mut tmp);
                    write_bytes(&mut k.mem, args[1], &tmp[..n]);
                    ok(n as u32)
                }
                _ => k.do_read(args[0], args[1], args[2], None),
            }
        }
        // socket(domain, type, protocol): only AF_UNIX
        97 if args[0] == 1 => ok(k.vfs.alloc_fd(OpenFile {
            kind: FileKind::Socket(Default::default()),
            offset: 0,
            path: String::new(),
            flags: 2,
        })),
        97 => Ret::Err(EAFNOSUPPORT),
        // connect(fd, sockaddr_un, len)
        98 => {
            let path = read_cstr(&k.mem, args[1] + 2);
            let Some(FileKind::Socket(s)) = k.vfs.fds.get_mut(&args[0]).map(|f| &mut f.kind) else {
                return Ret::Err(ENOTSOCK);
            };
            if path == super::lockdown::LOCKDOWN_SOCKET {
                s.service = Some(super::lockdown::Lockdownd::new(&k.fw.info));
                ok(0)
            } else {
                log!("xnu: connect({path:?}): no such socket");
                Ret::Err(vfs::ENOENT)
            }
        }
        105 => ok(0), // setsockopt
        362 => ok(k.vfs.alloc_fd(OpenFile {
            kind: FileKind::Kqueue(Default::default()),
            offset: 0,
            path: String::new(),
            flags: 2,
        })),
        363 => kevent(k, &args),
        // select(nfds, readfds, writefds, errorfds, timeout): never blocks.
        // A socket is readable once its service has replied and a kqueue
        // once an event fired; other descriptors are always ready.
        93 | 407 => {
            let mut ready = 0;
            for (set, reading) in [(args[1], true), (args[2], false), (args[3], false)] {
                if set == 0 {
                    continue;
                }
                for word in 0..args[0].div_ceil(32) {
                    let mut bits = read_u32(&k.mem, set + 4 * word);
                    for bit in 0..32 {
                        let fd = word * 32 + bit;
                        if fd >= args[0] {
                            bits &= !(1 << bit);
                            continue;
                        }
                        if bits & 1 << bit == 0 {
                            continue;
                        }
                        let is_ready = set != args[3]
                            && match k.vfs.fds.get(&fd).map(|f| &f.kind) {
                                Some(FileKind::Socket(s)) => !reading || s.readable(),
                                Some(FileKind::Kqueue(kq)) => !reading || kq.borrow().pending(),
                                Some(_) => true,
                                None => return Ret::Err(vfs::EBADF),
                            };
                        if is_ready {
                            ready += 1;
                        } else {
                            bits &= !(1 << bit);
                        }
                    }
                    write_u32(&mut k.mem, set + 4 * word, bits);
                }
            }
            ok(ready)
        }
        // sendto(fd, buf, len, flags, to, tolen)
        133 => {
            let data = read_bytes(&k.mem, args[1], args[2]);
            res(k.vfs.write(args[0], &data, None).map(|n| n as u32))
        }
        41 => {
            let fd = args[0];
            match k.vfs.fds.get(&fd) {
                Some(f) => {
                    let dup = match &f.kind {
                        FileKind::Host(h) => h.try_clone().map(FileKind::Host).ok(),
                        FileKind::Firmware { node } => Some(FileKind::Firmware { node: *node }),
                        FileKind::Console => Some(FileKind::Console),
                        FileKind::Null => Some(FileKind::Null),
                        FileKind::Random => Some(FileKind::Random),
                        FileKind::Kqueue(kq) => Some(FileKind::Kqueue(kq.clone())),
                        FileKind::Shm(shm) => Some(FileKind::Shm(shm.clone())),
                        _ => None,
                    };
                    match dup {
                        Some(kind) => {
                            let (path, flags, offset) = (f.path.clone(), f.flags, f.offset);
                            ok(k.vfs.alloc_fd(OpenFile {
                                kind,
                                offset,
                                path,
                                flags,
                            }))
                        }
                        None => Ret::Err(ENOTSUP),
                    }
                }
                None => Ret::Err(vfs::EBADF),
            }
        }
        46 | 48 | 53 | 329 | 331 => {
            // sigaction, sigprocmask, sigaltstack, __pthread_sigmask,
            // __disable_threadsignal
            if num == 46 && args[2] != 0 {
                write_bytes(&mut k.mem, args[2], &[0; 12]);
            }
            if (num == 48 || num == 329) && args[2] != 0 {
                write_u32(&mut k.mem, args[2], 0);
            }
            ok(0)
        }
        54 => Ret::Err(ENOTTY),
        58 => {
            let path = k.path_arg(0);
            match k.vfs.readlink(&k.fw, &path) {
                Ok(t) => {
                    let n = t.len().min(args[2] as usize);
                    write_bytes(&mut k.mem, args[1], &t[..n]);
                    ok(n as u32)
                }
                Err(e) => Ret::Err(e),
            }
        }
        60 => ok(0o022),
        73 => {
            // Shared memory keeps its pages, so the next mapping sees what
            // was written to it.
            if !k.vfs.shm.values().any(|s| s.borrow().addr == Some(args[0])) {
                k.vm.unmap(args[0], args[1]);
            }
            ok(0)
        }
        74 => {
            k.vm.protect(args[0], args[1], Prot::from_bits(args[2]));
            ok(0)
        }
        75 => ok(0), // madvise
        89 => ok(256),
        92 | 406 => {
            let (fd, cmd) = (args[0], args[1]);
            if !k.vfs.fds.contains_key(&fd) {
                return Ret::Err(vfs::EBADF);
            }
            match cmd {
                1 | 2 => ok(0),                // F_GETFD, F_SETFD
                3 => ok(k.vfs.fds[&fd].flags), // F_GETFL
                4 => {
                    // F_SETFL: only the status flags can change
                    const SETTABLE: u32 = vfs::O_APPEND | 0x4; // O_NONBLOCK
                    let f = k.vfs.fds.get_mut(&fd).unwrap();
                    f.flags = (f.flags & !SETTABLE) | (args[2] & SETTABLE);
                    ok(0)
                }
                50 => {
                    // F_GETPATH
                    let path = k.vfs.fds[&fd].path.clone();
                    write_bytes(&mut k.mem, args[2], &[path.as_bytes(), &[0]].concat());
                    ok(0)
                }
                // F_NOCACHE, F_RDADVISE, F_FULLFSYNC, F_SETLK..., F_ADDSIGS
                48 | 44 | 51 | 7 | 8 | 9 | 59 | 61 => ok(0),
                _ => {
                    log!("xnu: fcntl({fd}, {cmd}) unhandled");
                    Ret::Err(EINVAL)
                }
            }
        }
        116 => {
            let us = k.guest_unix_ns() / 1000;
            if args[0] != 0 {
                write_u32(&mut k.mem, args[0], (us / 1_000_000) as u32);
                write_u32(&mut k.mem, args[0] + 4, (us % 1_000_000) as u32);
            }
            Ret::Ok((us / 1_000_000) as u32, (us % 1_000_000) as u32)
        }
        121 | 412 => {
            let (fd, iov, cnt) = (args[0], args[1], args[2]);
            let mut data = Vec::new();
            for i in 0..cnt {
                let (base, len) = (
                    read_u32(&k.mem, iov + i * 8),
                    read_u32(&k.mem, iov + i * 8 + 4),
                );
                data.extend(read_bytes(&k.mem, base, len));
            }
            res(k.vfs.write(fd, &data, None).map(|n| n as u32))
        }
        128 => {
            let (from, to) = (k.path_arg(0), k.path_arg(1));
            res(k.vfs.rename(&k.fw, &from, &to).map(|_| 0))
        }
        136 => res(k.vfs.mkdir(&k.fw, &k.path_arg(0)).map(|_| 0)),
        137 => res(k.vfs.unlink(&k.fw, &k.path_arg(0)).map(|_| 0)),
        153 | 414 => {
            let off = args[3] as u64 | (args[4] as u64) << 32;
            k.do_read(args[0], args[1], args[2], Some(off))
        }
        154 | 415 => {
            let off = args[3] as u64 | (args[4] as u64) << 32;
            let data = read_bytes(&k.mem, args[1], args[2]);
            res(k.vfs.write(args[0], &data, Some(off)).map(|n| n as u32))
        }
        169 => {
            // csops: report a validly signed process
            if args[3] >= 4 && args[2] != 0 {
                write_u32(&mut k.mem, args[2], 0x1 | 0x4);
            }
            ok(0)
        }
        188 | 190 | 338 | 340 => {
            let path = k.path_arg(0);
            match k.vfs.stat(&k.fw, &path, num == 188 || num == 338) {
                Ok(st) => {
                    k.write_stat(args[1], &st, num >= 338);
                    ok(0)
                }
                Err(e) => {
                    log_dbg!("xnu: stat({path:?}) failed");
                    Ret::Err(e)
                }
            }
        }
        189 | 339 => match k.vfs.fstat(&k.fw, args[0]) {
            Ok(st) => {
                k.write_stat(args[1], &st, num == 339);
                ok(0)
            }
            Err(e) => Ret::Err(e),
        },
        194 => {
            // getrlimit: unlimited-ish
            write_bytes(
                &mut k.mem,
                args[1],
                &[(4096u64).to_le_bytes(), (u64::MAX >> 1).to_le_bytes()].concat(),
            );
            if args[0] == 8 {
                // RLIMIT_NOFILE
                write_bytes(
                    &mut k.mem,
                    args[1],
                    &[(256u64).to_le_bytes(), (10240u64).to_le_bytes()].concat(),
                );
            }
            ok(0)
        }
        195 => ok(0),
        196 => k.getdirentries(false),
        344 => k.getdirentries(true),
        197 => k.mmap(),
        201 => {
            let len = args[1] as u64 | (args[2] as u64) << 32;
            match k.vfs.fds.get(&args[0]).map(|f| &f.kind) {
                Some(FileKind::Shm(shm)) => {
                    shm.borrow_mut().size = len;
                    ok(0)
                }
                Some(FileKind::Host(file)) => match file.set_len(len) {
                    Ok(()) => ok(0),
                    Err(_) => Ret::Err(EINVAL),
                },
                Some(_) => Ret::Err(EINVAL),
                None => Ret::Err(vfs::EBADF),
            }
        }
        266 => {
            const O_CREAT: u32 = 0x200;
            const O_EXCL: u32 = 0x800;
            let (name, oflag) = (read_cstr(&k.mem, args[0]), args[1]);
            let shm = match k.vfs.shm.get(&name) {
                Some(_) if oflag & O_CREAT != 0 && oflag & O_EXCL != 0 => {
                    return Ret::Err(vfs::EEXIST)
                }
                Some(shm) => shm.clone(),
                None if oflag & O_CREAT != 0 => k.vfs.shm.entry(name.clone()).or_default().clone(),
                None => return Ret::Err(vfs::ENOENT),
            };
            ok(k.vfs.alloc_fd(OpenFile {
                kind: FileKind::Shm(shm),
                offset: 0,
                path: name,
                flags: oflag,
            }))
        }
        267 => match k.vfs.shm.remove(&read_cstr(&k.mem, args[0])) {
            Some(_) => ok(0),
            None => Ret::Err(vfs::ENOENT),
        },
        199 => {
            let fd = args[0];
            let off = (args[1] as u64 | (args[2] as u64) << 32) as i64;
            let whence = args[3];
            let size = match k.vfs.fstat(&k.fw, fd) {
                Ok(st) => st.size as i64,
                Err(e) => return Ret::Err(e),
            };
            let f = k.vfs.fds.get_mut(&fd).unwrap();
            if matches!(f.kind, FileKind::Console) {
                return Ret::Err(ESPIPE);
            }
            let new = match whence {
                0 => off,
                1 => f.offset as i64 + off,
                2 => size + off,
                _ => return Ret::Err(EINVAL),
            };
            if new < 0 {
                return Ret::Err(EINVAL);
            }
            f.offset = new as u64;
            Ret::Ok(new as u32, (new as u64 >> 32) as u32)
        }
        202 => k.sysctl(),
        220 => Ret::Err(ENOTSUP), // getattrlist
        294 => {
            // shared_region_check_np
            write_u32(&mut k.mem, args[0], super::SHARED_REGION_BASE);
            write_u32(&mut k.mem, args[0] + 4, 0);
            ok(0)
        }
        327 => ok(0), // issetugid
        336 => Ret::Err(ENOTSUP),
        // thread_selfid
        372 => {
            let tid = k.threads[k.current].tid + 100;
            Ret::Ok(tid as u32, (tid >> 32) as u32)
        }
        _ => super::mach::bsd_extra(k, num).unwrap_or_else(|| {
            log!(
                "xnu: unimplemented syscall {num} (r0-r3 {:#x} {:#x} {:#x} {:#x}, lr {:#x})",
                args[0],
                args[1],
                args[2],
                args[3],
                k.cpu.regs()[14]
            );
            Ret::Err(ENOSYS)
        }),
    }
}

/// kevent(kq, changelist, nchanges, eventlist, nevents, timeout).
///
/// Only `EVFILT_USER` events are tracked; other registrations are accepted
/// and never fire. `EV_RECEIPT` changes are echoed back at once, as libdispatch
/// expects. With nothing to report, the thread sleeps for at most 10ms (or
/// the timeout if shorter) and gets 0 events, so callers poll again for
/// events triggered meanwhile.
fn kevent(k: &mut Kernel, args: &[u32; 8]) -> Ret {
    const EVFILT_USER: i16 = -10;
    const EV_ADD: u16 = 0x1;
    const EV_DELETE: u16 = 0x2;
    const EV_ENABLE: u16 = 0x4;
    const EV_DISABLE: u16 = 0x8;
    const EV_ONESHOT: u16 = 0x10;
    const EV_CLEAR: u16 = 0x20;
    const EV_RECEIPT: u16 = 0x40;
    const EV_ERROR: u16 = 0x4000;
    const NOTE_TRIGGER: u32 = 0x0100_0000;
    const NOTE_FFAND: u32 = 0x4000_0000;
    const NOTE_FFOR: u32 = 0x8000_0000;
    const NOTE_FFCOPY: u32 = 0xc000_0000;
    const NOTE_FFCTRLMASK: u32 = 0xc000_0000;
    const NOTE_FFLAGSMASK: u32 = 0x00ff_ffff;
    const KEVENT_SIZE: u32 = 20;

    let (changes, nchanges, events, nevents) = (args[1], args[2], args[3], args[4]);
    let mut out: Vec<[u32; 5]> = Vec::new();
    {
        let Some(FileKind::Kqueue(kq)) = k.vfs.fds.get(&args[0]).map(|f| &f.kind) else {
            return Ret::Err(vfs::EBADF);
        };
        let kq = kq.clone();
        let mut kq = kq.borrow_mut();
        for i in 0..nchanges {
            let at = changes + i * KEVENT_SIZE;
            let ident = read_u32(&k.mem, at);
            let filter_flags = read_u32(&k.mem, at + 4);
            let (filter, flags) = (filter_flags as u16 as i16, (filter_flags >> 16) as u16);
            let fflags = read_u32(&k.mem, at + 8);
            let udata = read_u32(&k.mem, at + 16);
            if filter == EVFILT_USER {
                let pos = kq.user.iter().position(|e| e.ident == ident);
                if flags & EV_DELETE != 0 {
                    if let Some(p) = pos {
                        kq.user.remove(p);
                    }
                } else if let Some(p) = pos.or_else(|| {
                    (flags & EV_ADD != 0).then(|| {
                        kq.user.push(vfs::UserEvent {
                            ident,
                            udata,
                            fflags: 0,
                            flags: 0,
                            triggered: false,
                        });
                        kq.user.len() - 1
                    })
                }) {
                    let e = &mut kq.user[p];
                    if flags & EV_ADD != 0 {
                        e.udata = udata;
                        e.flags = flags & (EV_ONESHOT | EV_CLEAR);
                    }
                    if flags & EV_DISABLE != 0 {
                        e.flags |= EV_DISABLE;
                    } else if flags & EV_ENABLE != 0 {
                        e.flags &= !EV_DISABLE;
                    }
                    let bits = fflags & NOTE_FFLAGSMASK;
                    match fflags & NOTE_FFCTRLMASK {
                        NOTE_FFAND => e.fflags &= bits,
                        NOTE_FFOR => e.fflags |= bits,
                        NOTE_FFCOPY => e.fflags = bits,
                        _ => (),
                    }
                    e.triggered |= fflags & NOTE_TRIGGER != 0;
                }
            }
            if flags & EV_RECEIPT != 0 {
                out.push([
                    ident,
                    filter_flags | (EV_ERROR as u32) << 16,
                    fflags,
                    0,
                    udata,
                ]);
            }
        }
        if out.is_empty() {
            // Level-triggered events that were delivered go to the back, so
            // a short event list still reaches every pending event in turn.
            let mut keep = Vec::new();
            let mut requeue = Vec::new();
            for mut e in std::mem::take(&mut kq.user) {
                if out.len() >= nevents as usize || !e.triggered || e.flags & EV_DISABLE != 0 {
                    keep.push(e);
                    continue;
                }
                let filter_flags = EVFILT_USER as u16 as u32;
                out.push([e.ident, filter_flags, e.fflags, 0, e.udata]);
                if e.flags & EV_ONESHOT != 0 {
                    continue;
                }
                if e.flags & EV_CLEAR != 0 {
                    e.fflags = 0;
                    e.triggered = false;
                    keep.push(e);
                } else {
                    requeue.push(e);
                }
            }
            keep.extend(requeue);
            kq.user = keep;
        }
    }
    if !out.is_empty() || nevents == 0 {
        let n = out.len().min(nevents as usize);
        for (i, ev) in out.iter().take(n).enumerate() {
            for (j, w) in ev.iter().enumerate() {
                write_u32(
                    &mut k.mem,
                    events + i as u32 * KEVENT_SIZE + 4 * j as u32,
                    *w,
                );
            }
        }
        return ok(n as u32);
    }
    let mut wait_ns = 10_000_000;
    if args[5] != 0 {
        let ns =
            read_u32(&k.mem, args[5]) as u64 * 1_000_000_000 + read_u32(&k.mem, args[5] + 4) as u64;
        wait_ns = wait_ns.min(ns);
    }
    let deadline = k.absolute_time() + wait_ns * 3 / 125;
    let cpsr = k.cpu.cpsr() & !(1 << 29);
    k.cpu.set_cpsr(cpsr);
    k.current_thread().blocked = Some(super::Block::Sleep { deadline });
    Ret::Blocked
}
