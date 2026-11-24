/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Native versions of hot routines in the dyld shared cache.
//!
//! memmove, memset and bzero (found by their symbols in libSystem) and zlib
//! 1.2.3's inflate_fast (found by the content of its code in libz) have the
//! same effect as the guest routine under the ARM procedure call standard.
//!
//! objc_msgSend's method cache hit, libgcc's __udivsi3, the binary search of
//! a sorted method list in getMethodNoSuper_nolock and the loop of
//! __CFStringHash over 8-bit strings are exact: they leave
//! every register, flag and byte of memory as the guest code would, after
//! exactly as many guest instructions, which they count. Each is found by its
//! symbol and checked against a hash of the code it models.
//!
//! Anything else (a fault, a cache miss, a corrupt stream, too few ticks
//! left) is left to the guest code, which then does exactly what it would
//! have.

use super::Interp;
use crate::mem::{Mem, Ptr};

#[cfg(target_os = "emscripten")]
const LIMIT: u64 = Mem::CPU_WINDOW_MASK as u64 + 1;
#[cfg(not(target_os = "emscripten"))]
const LIMIT: u64 = u32::MAX as u64;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Routine {
    Memmove,
    Memset,
    Bzero,
    InflateFast,
    ObjcMsgSend,
    MethodSearch,
    Udivsi3,
    StringHash,
}

impl Routine {
    /// Whether the native version leaves the whole CPU state and memory as
    /// the guest code would, after the instructions it returns.
    #[cfg_attr(not(any(test, feature = "native-check")), allow(dead_code))]
    pub(super) fn exact(self) -> bool {
        matches!(
            self,
            Routine::ObjcMsgSend | Routine::MethodSearch | Routine::Udivsi3 | Routine::StringHash
        )
    }
}

/// (routine, image, symbol, offset of the entry from the symbol, start and
/// length of the code it models, FNV-1a of that code). An entry with bit 0
/// set is Thumb code.
const CHECKED: [(Routine, &[u8], &[u8], u32, u32, usize, u64); 4] = [
    (
        Routine::ObjcMsgSend,
        b"/usr/lib/libobjc.A.dylib",
        b"_objc_msgSend",
        0,
        0,
        0x58,
        0xb13f_dd4f_9fd7_f99f,
    ),
    (
        Routine::MethodSearch,
        b"/usr/lib/libobjc.A.dylib",
        b"__ZL23getMethodNoSuper_nolockP7class_tP13objc_selector",
        0x98,
        0x4c,
        0x54,
        0x9611_d124_20a3_a69f,
    ),
    (
        Routine::Udivsi3,
        b"/usr/lib/libgcc_s.1.dylib",
        b"___udivsi3",
        0,
        0,
        0x7c,
        0x587a_4b50_1ba6_45fb,
    ),
    (
        Routine::StringHash,
        b"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
        b"___CFStringHash",
        0x39,
        0x38,
        0x54,
        0x7c74_181d_452e_0e05,
    ),
];

/// FNV-1a of the 1200 bytes of iOS 4.2.1's inflate_fast (literal pool
/// excluded), which [Interp::inflate_fast] reproduces instruction for
/// instruction where results can differ.
const INFLATE_FAST_HASH: u64 = 0x5b74_0641_b09e_bc07;
const INFLATE_FAST_LEN: usize = 1200;
const INFLATE_FAST_START: [u8; 8] = [0x70, 0x4f, 0x2d, 0xe9, 0x34, 0xd0, 0x4d, 0xe2];

pub(super) struct Natives {
    /// Bit `pc >> 2 & 4095` is set for each entry, so most branches cost one
    /// test.
    filter: [u64; 64],
    entries: Vec<(u32, Routine)>,
}

impl Default for Natives {
    fn default() -> Self {
        Natives::new(Vec::new())
    }
}

impl Natives {
    /// Finds the routines in a `dyld_v1` shared cache.
    pub(super) fn find(cache: &[u8]) -> Self {
        let cache = Cache(cache);
        let mut entries = cache
            .image(b"/usr/lib/libSystem.B.dylib")
            .and_then(|header| cache.symbols(header, false))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(name, addr)| {
                let routine = match name {
                    b"_memmove" => Routine::Memmove,
                    b"_memset" => Routine::Memset,
                    b"_bzero" => Routine::Bzero,
                    _ => return None,
                };
                Some((addr, routine))
            })
            .collect::<Vec<_>>();
        if let Some(addr) = cache
            .image(b"/usr/lib/libz.1.dylib")
            .and_then(|header| cache.inflate_fast(header))
        {
            entries.push((addr, Routine::InflateFast));
        }
        for (routine, image, symbol, entry, start, len, hash) in CHECKED {
            let Some(addr) = cache
                .image(image)
                .and_then(|header| cache.symbols(header, entry & 1 != 0))
                .and_then(|symbols| symbols.into_iter().find(|s| s.0 == symbol))
                .map(|s| s.1 & !1)
            else {
                continue;
            };
            let code = cache
                .file_offset(addr + start)
                .and_then(|at| cache.0.get(at..at + len));
            if code.is_some_and(|code| fnv1a(code) == hash) {
                entries.push((addr + entry, routine));
            }
        }
        Natives::new(entries)
    }

    pub(super) fn new(entries: Vec<(u32, Routine)>) -> Self {
        let mut filter = [0; 64];
        for &(pc, _) in &entries {
            filter[(pc >> 8 & 63) as usize] |= 1 << (pc >> 2 & 63);
        }
        Natives { filter, entries }
    }

    /// Whether a routine may start at `pc`.
    #[inline(always)]
    pub(super) fn may_start(&self, pc: u32) -> bool {
        self.filter[(pc >> 8 & 63) as usize] & 1 << (pc >> 2 & 63) != 0
    }

    fn get(&self, key: u32) -> Option<Routine> {
        self.entries.iter().find(|e| e.0 == key).map(|e| e.1)
    }
}

struct Cache<'a>(&'a [u8]);

impl<'a> Cache<'a> {
    fn u32_at(&self, at: usize) -> Option<u32> {
        let bytes = self.0.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(bytes.try_into().unwrap()))
    }
    fn u64_at(&self, at: usize) -> Option<u64> {
        let bytes = self.0.get(at..at.checked_add(8)?)?;
        Some(u64::from_le_bytes(bytes.try_into().unwrap()))
    }
    fn cstr(&self, at: usize) -> Option<&'a [u8]> {
        let s = self.0.get(at..)?;
        Some(&s[..s.iter().position(|&b| b == 0)?])
    }

    fn file_offset(&self, addr: u32) -> Option<usize> {
        let (maps, count) = (self.u32_at(16)? as usize, self.u32_at(20)? as usize);
        (0..count).find_map(|i| {
            let m = maps + i * 32;
            let (start, size, offset) =
                (self.u64_at(m)?, self.u64_at(m + 8)?, self.u64_at(m + 16)?);
            let addr = u64::from(addr);
            (addr >= start && addr - start < size).then(|| (addr - start + offset) as usize)
        })
    }

    /// File offset of the Mach-O header of the image at `path`.
    fn image(&self, path: &[u8]) -> Option<usize> {
        if !self.0.starts_with(b"dyld_v1") {
            return None;
        }
        let (images, count) = (self.u32_at(24)? as usize, self.u32_at(28)? as usize);
        let header = (0..count).find_map(|i| {
            let image = images + i * 32;
            (self.cstr(self.u32_at(image + 24)? as usize)? == path)
                .then(|| self.file_offset(self.u64_at(image)? as u32))?
        })?;
        (self.u32_at(header)? == 0xfeed_face).then_some(header)
    }

    fn commands(&self, header: usize) -> impl Iterator<Item = (u32, usize)> + '_ {
        let count = self.u32_at(header + 16).unwrap_or(0);
        let mut at = header + 28;
        (0..count).map_while(move |_| {
            let command = (self.u32_at(at)?, at);
            at += self.u32_at(at + 4)? as usize;
            Some(command)
        })
    }

    /// ARM or Thumb functions in an image's symbol table.
    fn symbols(&self, header: usize, thumb: bool) -> Option<Vec<(&'a [u8], u32)>> {
        let (_, symtab) = self.commands(header).find(|&(cmd, _)| cmd == 2)?;
        let (symbols, count) = (self.u32_at(symtab + 8)? as usize, self.u32_at(symtab + 12)?);
        let strings = self.u32_at(symtab + 16)? as usize;
        let mut found = Vec::new();
        for i in 0..count as usize {
            let nlist = symbols + i * 12;
            let kind = *self.0.get(nlist + 4)?;
            let desc = self.u32_at(nlist + 4)? >> 16;
            // N_SECT, not a debug entry, and N_ARM_THUMB_DEF if Thumb.
            if kind & 0xee == 0x0e && (desc & 8 != 0) == thumb {
                let name = self.cstr(strings + self.u32_at(nlist)? as usize)?;
                found.push((name, self.u32_at(nlist + 8)?));
            }
        }
        Some(found)
    }

    /// Address of zlib's static inflate_fast in an image's text segment.
    fn inflate_fast(&self, header: usize) -> Option<u32> {
        let (addr, size) = self.commands(header).find_map(|(cmd, at)| {
            (cmd == 1 && self.0.get(at + 8..at + 24)? == b"__TEXT\0\0\0\0\0\0\0\0\0\0")
                .then(|| Some((self.u32_at(at + 24)?, self.u32_at(at + 28)? as usize)))?
        })?;
        let start = self.file_offset(addr)?;
        let text = self.0.get(start..start.checked_add(size)?)?;
        (0..text.len().saturating_sub(INFLATE_FAST_LEN))
            .step_by(4)
            .find(|&at| {
                text[at..].starts_with(&INFLATE_FAST_START)
                    && fnv1a(&text[at..at + INFLATE_FAST_LEN]) == INFLATE_FAST_HASH
            })
            .map(|at| addr + at as u32)
    }
}

fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

/// Whether `[addr, addr + len)` is memory the interpreter reaches without a
/// fault and without the browser window's address folding.
fn plain(mem: &Mem, addr: u32, len: u32) -> bool {
    addr >= mem.null_segment_size() && u64::from(addr) + u64::from(len) <= LIMIT
}

impl Interp {
    pub(crate) fn set_shared_cache(&mut self, cache: &[u8]) {
        self.natives = Natives::find(cache);
    }

    /// Runs the routine at the current PC natively and returns to LR, if
    /// there is one. Returns the guest instructions it stands in for.
    #[inline(never)]
    pub(super) fn run_native(&mut self, mem: &mut Mem, remaining: u64) -> Option<u32> {
        let routine = self.natives.get(self.regs[15] | u32::from(self.thumb))?;
        #[cfg(feature = "native-check")]
        return self.check_routine(mem, routine, remaining);
        #[cfg(not(feature = "native-check"))]
        self.run_routine(mem, routine, remaining)
    }

    pub(super) fn run_routine(
        &mut self,
        mem: &mut Mem,
        routine: Routine,
        remaining: u64,
    ) -> Option<u32> {
        let [r0, r1, r2] = [self.regs[0], self.regs[1], self.regs[2]];
        let len = match routine {
            Routine::ObjcMsgSend => return self.objc_msg_send(mem, remaining),
            Routine::MethodSearch => return self.method_search(mem, remaining),
            Routine::Udivsi3 => return self.udivsi3(mem, remaining),
            Routine::StringHash => return self.string_hash(mem, remaining),
            Routine::Memmove => {
                if r2 != 0 && r0 != r1 {
                    if !plain(mem, r0, r2) || !plain(mem, r1, r2) {
                        return None;
                    }
                    let low = r0.min(r1);
                    let span = r0.max(r1) - low + r2;
                    let (src, dst) = ((r1 - low) as usize, (r0 - low) as usize);
                    mem.bytes_at_mut(Ptr::from_bits(low), span)
                        .copy_within(src..src + r2 as usize, dst);
                }
                r2
            }
            Routine::Memset => {
                if r2 != 0 {
                    if !plain(mem, r0, r2) {
                        return None;
                    }
                    mem.bytes_at_mut(Ptr::from_bits(r0), r2).fill(r1 as u8);
                }
                r2
            }
            Routine::Bzero => {
                if r1 != 0 {
                    if !plain(mem, r0, r1) {
                        return None;
                    }
                    mem.bytes_at_mut(Ptr::from_bits(r0), r1).fill(0);
                }
                r1
            }
            Routine::InflateFast => return self.inflate_fast(mem),
        };
        self.bx(self.regs[14]);
        Some(8 + len / 16)
    }

    /// Flags of `cmp a, b`.
    fn compare(&mut self, a: u32, b: u32) {
        let (res, c, v) = super::add_with_carry(a, !b, true);
        self.set_nz(res);
        self.c = c;
        self.v = v;
    }

    /// objc_msgSend when the selector is in the receiver's method cache, or
    /// the receiver is nil.
    fn objc_msg_send(&mut self, mem: &mut Mem, remaining: u64) -> Option<u32> {
        let [r0, r1, r3, r4, r5, r6] = [0, 1, 3, 4, 5, 6].map(|r| self.regs[r]);
        if r0 == 0 {
            if remaining < 3 {
                return None;
            }
            self.set_nz(0);
            self.regs[1] = 0;
            self.bx(self.regs[14]);
            return Some(3);
        }
        let word = |addr: u32| mem.cpu_read::<4>(addr).map(u32::from_le_bytes);
        let cache = word(word(r0)?.wrapping_add(8))?;
        let mask = word(cache)?;
        let buckets = cache.wrapping_add(8);
        let mut index = mask & r1 >> 2;
        let mut probes = 0u64;
        let method = loop {
            probes += 1;
            let method = word(buckets.wrapping_add(index << 2))?;
            if method == 0 || probes > u64::from(mask) + 1 || 13 + 8 * probes > remaining {
                return None;
            }
            index = index.wrapping_add(1) & mask;
            if word(method)? == r1 {
                break method;
            }
        };
        let imp = word(method.wrapping_add(8))?;
        let sp = self.regs[13];
        for (i, value) in [r3, r4, r5, r6].into_iter().enumerate() {
            if !mem.cpu_write(sp.wrapping_sub(16 - 4 * i as u32), value.to_le_bytes()) {
                return None;
            }
        }
        self.regs[12] = imp;
        self.set_nz(0);
        self.bx(imp);
        Some(13 + 8 * probes as u32)
    }

    /// The binary search of a sorted method list in getMethodNoSuper_nolock,
    /// from the loop test with `ip` entries left at `lr`, until it finds the
    /// selector in `r1` or runs out of entries.
    fn method_search(&mut self, mem: &mut Mem, remaining: u64) -> Option<u32> {
        let sel = self.regs[1];
        let [mut r0, mut r2, mut r3, mut ip, mut lr] = [0, 2, 3, 12, 14].map(|r| self.regs[r]);
        let mut count = 2u64;
        let mut found = false;
        while ip != 0 {
            r2 = ip >> 1;
            r3 = r2.wrapping_mul(12);
            r0 = r3.wrapping_add(lr);
            r3 = mem.cpu_read::<4>(r0).map(u32::from_le_bytes)?;
            count += 7;
            if sel == r3 {
                found = true;
                break;
            }
            if sel > r3 {
                ip = ip.wrapping_sub(1);
                lr = r0.wrapping_add(12);
                r2 = ip >> 1;
            }
            ip = r2;
            count += 6;
        }
        if count > remaining {
            return None;
        }
        for (r, value) in [(0, r0), (2, r2), (3, r3), (12, ip), (14, lr)] {
            self.regs[r] = value;
        }
        if found {
            self.compare(sel, r3);
            self.regs[15] = self.regs[15] - 0x30;
        } else {
            self.compare(ip, 0);
            self.regs[15] += 8;
        }
        self.branched = true;
        Some(count as u32)
    }

    /// libgcc's __udivsi3: shift and subtract, one quotient bit per loop.
    fn udivsi3(&mut self, mem: &mut Mem, remaining: u64) -> Option<u32> {
        let [n, d] = [self.regs[0], self.regs[1]];
        let mut regs = self.regs;
        let (count, flags) = if d == 0 || n == 0 {
            regs[0] = 0;
            (6, (0, 0))
        } else {
            let shift = d.leading_zeros().wrapping_sub(n.leading_zeros());
            [regs[2], regs[3], regs[14]] = [d.leading_zeros(), n.leading_zeros(), shift];
            if shift > 31 {
                regs[0] = 0;
                (13, (shift, 31))
            } else if shift == 31 {
                (12, (shift, 31))
            } else {
                let (mut r0, mut ip, mut sb) = (n >> (shift + 1), n << (31 - shift), 0);
                for _ in 0..=shift {
                    r0 <<= 1;
                    regs[2] = r0 | ip >> 31;
                    regs[3] = d.wrapping_sub(regs[2]).wrapping_sub(1);
                    r0 = regs[2].wrapping_sub(d & (regs[3] as i32 >> 31) as u32);
                    ip = sb | ip << 1;
                    sb = regs[3] >> 31;
                }
                [regs[0], regs[9], regs[12], regs[14]] = [sb | ip << 1, sb, ip, u32::MAX];
                (19 + 10 * (shift + 1), (0, 1))
            }
        };
        if u64::from(count) > remaining {
            return None;
        }
        let sp = self.regs[13];
        for (i, r) in [7, 14].into_iter().enumerate() {
            let value = self.regs[r];
            if !mem.cpu_write(sp.wrapping_sub(8 - 4 * i as u32), value.to_le_bytes()) {
                return None;
            }
        }
        let lr = self.regs[14];
        self.regs = regs;
        self.compare(flags.0, flags.1);
        self.bx(lr);
        Some(count)
    }

    /// The loop of __CFStringHash over an 8-bit string of at most 96
    /// characters at `r4` with length in `sb`: four characters at a time,
    /// mapped to Unicode through a table, until fewer than four are left.
    fn string_hash(&mut self, mem: &mut Mem, remaining: u64) -> Option<u32> {
        let entry = self.regs[15];
        let word = |addr: u32| mem.cpu_read::<4>(addr).map(u32::from_le_bytes);
        let [mut r0, mut r1, mut r4, mut r6, len] = [0, 1, 4, 6, 9].map(|r| self.regs[r]);
        let mut r2 = len & !3;
        let mut r3 = r4.wrapping_add(len);
        let r5 = r4.wrapping_add(r2);
        let ip = r3;
        let mut count = 9u64;
        if r4 < r5 {
            r0 = word(word(entry + 0x2c2)?.wrapping_add(entry + 0x18))?;
            let (k1, k2) = (word(entry + 0x2c6)?, word(entry + 0x2ca)?);
            let unichar = |c: u32| {
                mem.cpu_read::<1>(c)
                    .and_then(|c| mem.cpu_read::<2>((u32::from(c[0]) << 1).wrapping_add(r0)))
                    .map(|u| u32::from(u16::from_le_bytes(u)))
            };
            count += 3;
            while r4 < r5 {
                let [c0, c2, c3, c1] = [0, 2, 3, 1].map(|i| unichar(r4.wrapping_add(i)));
                r1 = c0?.wrapping_mul(k1);
                r2 = r1.wrapping_add(c2?.wrapping_mul(257));
                r1 = r2.wrapping_add(c3?);
                r4 = r4.wrapping_add(4);
                r2 = r1.wrapping_add(c1?.wrapping_mul(257 * 257));
                r3 = r6.wrapping_mul(k2);
                r6 = r2.wrapping_add(r3);
                count += 30;
            }
        }
        if count > remaining {
            return None;
        }
        for (r, value) in [
            (0, r0),
            (1, r1),
            (2, r2),
            (3, r3),
            (4, r4),
            (5, r5),
            (6, r6),
            (12, ip),
        ] {
            self.regs[r] = value;
        }
        if count == 9 {
            self.compare(r4, r5);
        } else {
            self.compare(r5, r4);
        }
        self.regs[15] = entry + 0x54;
        self.branched = true;
        Some(count as u32)
    }

    /// inflate_fast(strm, start) of zlib 1.2.3 as compiled in iOS 4.2.1,
    /// with its unsigned and signed comparisons and register shifts. Output
    /// bytes are written as they are produced, so falling back to the guest
    /// after a fault or an invalid code just writes them again.
    fn inflate_fast(&mut self, mem: &mut Mem) -> Option<u32> {
        fn word(mem: &Mem, addr: u32) -> Option<u32> {
            mem.cpu_read::<4>(addr).map(u32::from_le_bytes)
        }
        fn byte(mem: &Mem, addr: u32) -> Option<u32> {
            mem.cpu_read::<1>(addr).map(|b| u32::from(b[0]))
        }
        fn half(mem: &Mem, addr: u32) -> Option<u32> {
            Some(byte(mem, addr)? | byte(mem, addr.wrapping_add(1))? << 8)
        }
        fn lsl(x: u32, n: u32) -> u32 {
            x.checked_shl(n & 0xff).unwrap_or(0)
        }
        fn lsr(x: u32, n: u32) -> u32 {
            x.checked_shr(n & 0xff).unwrap_or(0)
        }
        fn low(x: u32, n: u32) -> u32 {
            x & lsl(1, n).wrapping_sub(1)
        }
        fn copy(mem: &mut Mem, from: &mut u32, out: &mut u32, len: u32) -> Option<()> {
            for _ in 0..len {
                let b = mem.cpu_read::<1>(*from)?;
                if !mem.cpu_write(*out, b) {
                    return None;
                }
                *from = from.wrapping_add(1);
                *out = out.wrapping_add(1);
            }
            Some(())
        }
        // A code is { u8 op, u8 bits, u16 val }; returns (op, val).
        fn take(code: u32, hold: &mut u32, bits: &mut u32) -> (u32, u32) {
            let n = code >> 8 & 0xff;
            *hold = lsr(*hold, n);
            *bits = bits.wrapping_sub(n);
            (code & 0xff, code >> 16)
        }

        let (strm, start) = (self.regs[0], self.regs[1]);
        let at = |base: u32, offset: u32| base.wrapping_add(offset);
        let next_in = word(mem, strm)?;
        let avail_in = word(mem, at(strm, 4))?;
        let next_out = word(mem, at(strm, 12))?;
        let avail_out = word(mem, at(strm, 16))?;
        let state = word(mem, at(strm, 28))?;
        let wsize = word(mem, at(state, 40))?;
        let whave = word(mem, at(state, 44))?;
        let write = word(mem, at(state, 48))?;
        let window = word(mem, at(state, 52))?;
        let mut hold = word(mem, at(state, 56))?;
        let mut bits = word(mem, at(state, 60))?;
        let lcode = word(mem, at(state, 76))?;
        let dcode = word(mem, at(state, 80))?;
        let lbits = word(mem, at(state, 84))?;
        let dbits = word(mem, at(state, 88))?;

        let last = next_in.wrapping_add(avail_in.wrapping_sub(5));
        let end = next_out.wrapping_add(avail_out.wrapping_sub(257));
        let beg = next_out.wrapping_sub(start.wrapping_sub(avail_out));
        let (mut inp, mut out) = (next_in, next_out);
        let mut end_of_block = false;
        let mut symbols = 0;
        loop {
            symbols += 1;
            if (bits as i32) < 15 {
                hold = hold.wrapping_add(lsl(half(mem, inp)?, bits));
                inp = inp.wrapping_add(2);
                bits = bits.wrapping_add(16);
            }
            let mut code = word(mem, at(lcode, low(hold, lbits) << 2))?;
            loop {
                let (op, val) = take(code, &mut hold, &mut bits);
                if op == 0 {
                    if !mem.cpu_write(out, [val as u8]) {
                        return None;
                    }
                    out = out.wrapping_add(1);
                    break;
                }
                if op & 16 != 0 {
                    let extra = op & 15;
                    let mut len = val;
                    if extra != 0 {
                        if extra > bits {
                            hold = hold.wrapping_add(lsl(byte(mem, inp)?, bits));
                            inp = inp.wrapping_add(1);
                            bits = bits.wrapping_add(8);
                        }
                        len = len.wrapping_add(low(hold, extra));
                        hold = lsr(hold, extra);
                        bits = bits.wrapping_sub(extra);
                    }
                    // The guest loads these two bytes whether or not it
                    // needs them.
                    let next = half(mem, inp)?;
                    if bits <= 14 {
                        hold = hold.wrapping_add(lsl(next, bits));
                        inp = inp.wrapping_add(2);
                        bits = bits.wrapping_add(16);
                    }
                    let mut code = word(mem, at(dcode, low(hold, dbits) << 2))?;
                    let dist = loop {
                        let (op, val) = take(code, &mut hold, &mut bits);
                        if op & 16 != 0 {
                            let extra = op & 15;
                            for _ in 0..2 {
                                if extra > bits {
                                    hold = hold.wrapping_add(lsl(byte(mem, inp)?, bits));
                                    inp = inp.wrapping_add(1);
                                    bits = bits.wrapping_add(8);
                                }
                            }
                            let dist = val.wrapping_add(low(hold, extra));
                            hold = lsr(hold, extra);
                            bits = bits.wrapping_sub(extra);
                            break dist;
                        }
                        if op & 64 != 0 || !(1..16).contains(&op) {
                            return None;
                        }
                        code = word(mem, at(dcode, val.wrapping_add(low(hold, op)) << 2))?;
                    };
                    let mut op = out.wrapping_sub(beg);
                    let mut from;
                    if dist > op {
                        op = dist - op;
                        if whave < op {
                            return None;
                        }
                        if write == 0 {
                            from = window.wrapping_add(wsize).wrapping_sub(op);
                            if len > op {
                                len -= op;
                                copy(mem, &mut from, &mut out, op)?;
                                from = out.wrapping_sub(dist);
                            }
                        } else if write < op {
                            from = window
                                .wrapping_add(wsize)
                                .wrapping_add(write)
                                .wrapping_sub(op);
                            op -= write;
                            if len > op {
                                len -= op;
                                copy(mem, &mut from, &mut out, op)?;
                                from = window;
                                if write < len {
                                    len -= write;
                                    copy(mem, &mut from, &mut out, write)?;
                                    from = out.wrapping_sub(dist);
                                }
                            }
                        } else {
                            from = window.wrapping_add(write).wrapping_sub(op);
                            if len > op {
                                len -= op;
                                copy(mem, &mut from, &mut out, op)?;
                                from = out.wrapping_sub(dist);
                            }
                        }
                    } else {
                        // The guest's do-while copies at least three bytes.
                        if len < 3 {
                            return None;
                        }
                        from = out.wrapping_sub(dist);
                    }
                    copy(mem, &mut from, &mut out, len)?;
                    break;
                }
                if op & 64 == 0 {
                    if !(1..16).contains(&op) {
                        return None;
                    }
                    code = word(mem, at(lcode, val.wrapping_add(low(hold, op)) << 2))?;
                    continue;
                }
                if op & 32 != 0 {
                    end_of_block = true;
                    break;
                }
                return None;
            }
            if end_of_block || inp >= last || out >= end {
                break;
            }
        }
        let rewind = bits >> 3;
        inp = inp.wrapping_sub(rewind);
        bits &= 7;
        hold = low(hold, bits);
        let fields = [
            (strm, inp),
            (at(strm, 12), out),
            (at(strm, 4), last.wrapping_add(5).wrapping_sub(inp)),
            (at(strm, 16), end.wrapping_add(257).wrapping_sub(out)),
            (at(state, 60), bits),
            (at(state, 56), hold),
        ];
        if end_of_block && !mem.cpu_write(state, 11u32.to_le_bytes()) {
            return None;
        }
        for (addr, value) in fields {
            if !mem.cpu_write(addr, value.to_le_bytes()) {
                return None;
            }
        }
        self.bx(self.regs[14]);
        Some(symbols * 12 + out.wrapping_sub(next_out) / 2)
    }
}

/// Runs each native routine and then the guest code from the same state,
/// compares the two, logs any difference and keeps the guest's result.
#[cfg(feature = "native-check")]
impl Interp {
    fn check_regions(&self, mem: &Mem, routine: Routine) -> Vec<(u32, u32)> {
        let [r0, r1, r2] = [self.regs[0], self.regs[1], self.regs[2]];
        let word = |addr: u32| mem.cpu_read::<4>(addr).map_or(0, u32::from_le_bytes);
        let mut regions = vec![(self.regs[13].wrapping_sub(64), 64)];
        match routine {
            Routine::Memmove => regions.extend([(r0, r2.min(1 << 22)), (r1, r2.min(1 << 22))]),
            Routine::Memset => regions.push((r0, r2.min(1 << 22))),
            Routine::Bzero => regions.push((r0, r1.min(1 << 22))),
            Routine::InflateFast => {
                let state = word(r0.wrapping_add(28));
                regions.push((r0, 32));
                regions.push((state, 96));
                regions.push((
                    word(r0.wrapping_add(12)),
                    word(r0.wrapping_add(16)).min(1 << 22),
                ));
            }
            Routine::ObjcMsgSend
            | Routine::MethodSearch
            | Routine::Udivsi3
            | Routine::StringHash => (),
        }
        regions
    }

    fn check_routine(&mut self, mem: &mut Mem, routine: Routine, remaining: u64) -> Option<u32> {
        use std::cell::RefCell;
        thread_local! {
            static STATS: RefCell<std::collections::HashMap<String, [u64; 4]>> =
                RefCell::default();
        }
        let regions = self.check_regions(mem, routine);
        let save = |mem: &Mem| -> Vec<Vec<u8>> {
            regions
                .iter()
                .map(|&(at, len)| {
                    (0..len)
                        .map(|i| mem.cpu_read::<1>(at.wrapping_add(i)).map_or(0, |b| b[0]))
                        .collect()
                })
                .collect()
        };
        let before = save(mem);
        let start = (self.regs, self.cpsr());
        let count = self.run_routine(mem, routine, remaining)?;
        let native = (self.regs, self.cpsr(), save(mem));
        for (&(at, _), bytes) in regions.iter().zip(&before) {
            for (i, &b) in bytes.iter().enumerate() {
                mem.cpu_write(at.wrapping_add(i as u32), [b]);
            }
        }
        self.regs = start.0;
        self.set_cpsr(start.1);
        let (ret, sp) = (self.regs[14] & !1, self.regs[13]);
        let mut steps = 0u64;
        let mut failed = false;
        loop {
            let done = if routine.exact() {
                steps == u64::from(count)
            } else {
                steps > 0 && self.regs[15] == ret && self.regs[13] == sp
            };
            if done {
                break;
            }
            if steps > 50_000_000 || self.step(mem).is_err() {
                failed = true;
                break;
            }
            steps += 1;
        }
        let guest = (self.regs, self.cpsr(), save(mem));
        let same = if routine.exact() {
            native == guest
        } else {
            // inflate_fast returns nothing, so r0 is scratch.
            let abi = |s: &([u32; 16], u32, Vec<Vec<u8>>)| {
                let mut regs = [0, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15].map(|r| s.0[r]);
                if routine == Routine::InflateFast {
                    regs[0] = 0;
                }
                (regs, s.1 & 0x20, s.2[1..].to_vec())
            };
            abi(&native) == abi(&guest)
        };
        let memory_same = native.2[1..] == guest.2[1..];
        let name = format!("{routine:?}");
        let calls = STATS.with_borrow_mut(|stats| {
            let entry = stats.entry(name.clone()).or_default();
            entry[0] += 1;
            entry[1] += u64::from(!same || failed);
            entry[2] += steps;
            entry[3] += u64::from(count);
            *entry
        });
        if !same || failed {
            if calls[1] <= 20 {
                echo!(
                    "native-check MISMATCH {name} failed={failed} memory_same={memory_same} start={:08x?} native={:08x?} {:08x} guest={:08x?} {:08x} steps={steps} count={count}",
                    start.0, native.0, native.1, guest.0, guest.1
                );
            }
        } else if calls[0].is_power_of_two() || calls[0] % 100_000 == 0 {
            echo!(
                "native-check {name} calls={} mismatches={} guest_instructions={} native_count={}",
                calls[0],
                calls[1],
                calls[2],
                calls[3]
            );
        }
        if failed {
            for (&(at, _), bytes) in regions.iter().zip(&before) {
                for (i, &b) in bytes.iter().enumerate() {
                    mem.cpu_write(at.wrapping_add(i as u32), [b]);
                }
            }
            self.regs = start.0;
            self.set_cpsr(start.1);
            return None;
        }
        Some(steps as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ENTRY: u32 = 0x2000;
    const RETURN: u32 = 0x3001;
    const DATA: u32 = 0x4000;

    fn call(mem: &mut Mem, routine: Routine, args: [u32; 3]) -> Option<Interp> {
        let mut cpu = Interp::new();
        cpu.natives = Natives::new(vec![(ENTRY, routine)]);
        cpu.regs[..3].copy_from_slice(&args);
        cpu.regs[14] = RETURN;
        cpu.regs[15] = ENTRY;
        cpu.run_native(mem, u64::MAX)?;
        assert_eq!((cpu.regs[15], cpu.thumb), (RETURN - 1, true));
        assert_eq!(cpu.regs[0], args[0]);
        Some(cpu)
    }

    fn bytes(mem: &Mem, len: u32) -> Vec<u8> {
        mem.bytes_at(Ptr::<u8, false>::from_bits(DATA), len)
            .to_vec()
    }

    #[test]
    fn memmove_memset_and_bzero() {
        let mut mem = Mem::new();
        mem.bytes_at_mut(Ptr::from_bits(DATA), 8)
            .copy_from_slice(b"abcdefgh");
        call(&mut mem, Routine::Memmove, [DATA + 2, DATA, 5]).unwrap();
        assert_eq!(bytes(&mem, 8), b"ababcdeh");
        call(&mut mem, Routine::Memmove, [DATA, DATA + 3, 5]).unwrap();
        assert_eq!(bytes(&mem, 8), b"bcdehdeh");
        call(&mut mem, Routine::Memset, [DATA + 1, 0x17a, 3]).unwrap();
        assert_eq!(bytes(&mem, 8), b"bzzzhdeh");
        call(&mut mem, Routine::Bzero, [DATA + 6, 2, 0]).unwrap();
        assert_eq!(bytes(&mem, 8), b"bzzzhd\0\0");
    }

    #[test]
    fn faults_are_left_to_the_guest() {
        let mut mem = Mem::new();
        mem.set_null_segment_size(0x1000);
        assert!(call(&mut mem, Routine::Memmove, [DATA, 0xff0, 4]).is_none());
        assert!(call(&mut mem, Routine::Memset, [0, 1, 4]).is_none());
        call(&mut mem, Routine::Bzero, [0, 0, 0]).unwrap();
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 16) as u32
        }
        fn below(&mut self, n: u32) -> u32 {
            self.next() % n
        }
        /// Mostly small or edge values, sometimes anything.
        fn value(&mut self) -> u32 {
            match self.below(6) {
                0 => self.below(16),
                1 => 1 << self.below(32),
                2 => u32::MAX - self.below(16),
                3 => self.next() >> self.below(32),
                _ => self.next(),
            }
        }
    }

    const STACK: u32 = 0x10_0000;
    const RET: u32 = 0x5000;
    const HEAP: u32 = 0x20_0000;

    type State = ([u32; 16], u32, Vec<u8>);

    fn state(cpu: &Interp, mem: &Mem, regions: &[(u32, u32)]) -> State {
        let mut bytes = Vec::new();
        for &(at, len) in regions {
            bytes.extend_from_slice(mem.bytes_at(Ptr::<u8, false>::from_bits(at), len));
        }
        (cpu.regs, cpu.cpsr(), bytes)
    }

    fn restore(mem: &mut Mem, regions: &[(u32, u32)], bytes: &[u8]) {
        let mut at = 0;
        for &(addr, len) in regions {
            mem.bytes_at_mut(Ptr::from_bits(addr), len)
                .copy_from_slice(&bytes[at..at + len as usize]);
            at += len as usize;
        }
    }

    /// Runs `routine` natively and then the guest code from the same state.
    /// Returns [None] if the native version declined, after checking that it
    /// changed nothing.
    fn differ(
        cpu: &mut Interp,
        mem: &mut Mem,
        routine: Routine,
        regions: &[(u32, u32)],
    ) -> Option<(State, State, u64)> {
        let start = state(cpu, mem, regions);
        let Some(count) = cpu.run_routine(mem, routine, u64::MAX) else {
            assert!(
                state(cpu, mem, regions) == start,
                "{routine:?} declined but changed state"
            );
            return None;
        };
        let native = state(cpu, mem, regions);
        restore(mem, regions, &start.2);
        cpu.regs = start.0;
        cpu.set_cpsr(start.1);
        let (ret, sp) = (cpu.regs[14] & !1, cpu.regs[13]);
        let mut steps = 0u64;
        while if routine.exact() {
            steps < u64::from(count)
        } else {
            steps == 0 || cpu.regs[15] != ret || cpu.regs[13] != sp
        } {
            assert!(cpu.step(mem).is_ok(), "{routine:?}: guest code faulted");
            steps += 1;
            assert!(steps < 10_000_000);
        }
        Some((native, state(cpu, mem, regions), steps))
    }

    fn random_cpu(rng: &mut Rng, entry: u32) -> Interp {
        let mut cpu = Interp::new();
        for r in 0..13 {
            cpu.regs[r] = rng.next();
        }
        cpu.regs[13] = STACK - 4 * rng.below(16);
        cpu.regs[14] = RET | rng.below(2);
        cpu.regs[15] = entry & !1;
        cpu.set_cpsr(rng.next() & 0xf80f_0000 | 0x10 | (entry & 1) << 5);
        cpu
    }

    fn load_cache() -> Option<Vec<u8>> {
        let path = option_env!("TOUCHHLE_TEST_SHARED_CACHE")?;
        Some(std::fs::read(path).expect("TOUCHHLE_TEST_SHARED_CACHE unreadable"))
    }

    /// Needs the decoded iOS 4.2.1 shared cache at the path in
    /// TOUCHHLE_TEST_SHARED_CACHE when building (and NODERAWFS for Wasm).
    /// Without it, it does nothing.
    #[test]
    fn same_as_guest_code_on_random_inputs() {
        let Some(bytes) = load_cache() else {
            eprintln!("TOUCHHLE_TEST_SHARED_CACHE not set, skipped");
            return;
        };
        let natives = Natives::find(&bytes);
        let cache = Cache(&bytes);
        let mut mem = Mem::new();
        let mut entry = |routine: Routine| {
            let pc = natives.entries.iter().find(|e| e.1 == routine).unwrap().0;
            let page = pc & !0xffff;
            let at = cache.file_offset(page).unwrap();
            mem.bytes_at_mut(Ptr::from_bits(page), 0x2_0000)
                .copy_from_slice(&bytes[at..at + 0x2_0000]);
            pc
        };
        let entries: Vec<_> = [
            Routine::Udivsi3,
            Routine::ObjcMsgSend,
            Routine::MethodSearch,
            Routine::Memmove,
            Routine::Memset,
            Routine::Bzero,
            Routine::StringHash,
        ]
        .map(|r| (r, entry(r)))
        .into();
        assert!(natives.entries.iter().any(|e| e.1 == Routine::InflateFast));
        let stack = [(STACK - 128, 128)];
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let mut totals = std::collections::HashMap::new();
        for &(routine, pc) in &entries {
            let (mut ran, mut declined, mut total) = (0u32, 0u32, 0u64);
            for _ in 0..3000 {
                let mut cpu = random_cpu(&mut rng, pc);
                let mut regions = stack.to_vec();
                match routine {
                    Routine::Udivsi3 => {
                        cpu.regs[0] = rng.value();
                        cpu.regs[1] = rng.value();
                    }
                    Routine::ObjcMsgSend => {
                        // Receiver, class, cache with 2^k buckets, methods.
                        let k = rng.below(6);
                        let mask = (1 << k) - 1;
                        let (obj, class, cache_at) = (HEAP, HEAP + 0x40, HEAP + 0x80);
                        let methods = HEAP + 0x1000;
                        let words = [(obj, class), (class + 8, cache_at), (cache_at, mask)];
                        for (at, v) in words {
                            mem.write(Ptr::from_bits(at), v);
                        }
                        let sels: Vec<u32> =
                            (0..=mask).map(|_| rng.next() & !3 | 0x1000_0000).collect();
                        for i in 0..=mask {
                            let method = if rng.below(4) == 0 {
                                0
                            } else {
                                methods + 12 * i
                            };
                            mem.write(Ptr::from_bits(cache_at + 8 + 4 * i), method);
                            mem.write(Ptr::from_bits(methods + 12 * i), sels[i as usize]);
                            mem.write(Ptr::from_bits(methods + 12 * i + 8), rng.next());
                        }
                        cpu.regs[0] = if rng.below(8) == 0 { 0 } else { obj };
                        cpu.regs[1] = if rng.below(4) == 0 {
                            rng.next()
                        } else {
                            sels[rng.below(mask + 1) as usize]
                        };
                        regions.push((HEAP, 0x1000 + 12 * 32));
                    }
                    Routine::MethodSearch => {
                        // A sorted method list of 12-byte entries at lr.
                        let n = rng.below(40);
                        let mut names: Vec<u32> = (0..n).map(|_| rng.value()).collect();
                        names.sort_unstable();
                        for (i, &name) in names.iter().enumerate() {
                            mem.write(Ptr::from_bits(HEAP + 12 * i as u32), name);
                        }
                        cpu.regs[14] = HEAP;
                        cpu.regs[12] = n;
                        cpu.regs[1] = if n > 0 && rng.below(3) != 0 {
                            names[rng.below(n) as usize]
                        } else {
                            rng.value()
                        };
                        regions.push((HEAP, 12 * 40));
                    }
                    Routine::Memmove | Routine::Memset | Routine::Bzero => {
                        let len = match rng.below(3) {
                            0 => rng.below(16),
                            1 => rng.below(300),
                            _ => rng.below(5000),
                        };
                        let dst = HEAP + rng.below(64);
                        let src = HEAP + rng.below(6000);
                        let fill: Vec<u8> = (0..12_000).map(|_| rng.next() as u8).collect();
                        mem.bytes_at_mut(Ptr::from_bits(HEAP), 12_000)
                            .copy_from_slice(&fill);
                        cpu.regs[0] = dst;
                        cpu.regs[1] = if routine == Routine::Memmove {
                            src
                        } else if routine == Routine::Bzero {
                            len
                        } else {
                            rng.next()
                        };
                        cpu.regs[2] = len;
                        regions.push((HEAP, 12_000));
                    }
                    Routine::StringHash => {
                        let entry = pc & !1;
                        let slot = mem
                            .read(Ptr::<u32, false>::from_bits(entry + 0x2c2))
                            .wrapping_add(entry + 0x18);
                        mem.write(Ptr::from_bits(slot), HEAP + 0x8000);
                        let fill: Vec<u8> = (0..0x8200).map(|_| rng.next() as u8).collect();
                        mem.bytes_at_mut(Ptr::from_bits(HEAP), 0x8200)
                            .copy_from_slice(&fill);
                        cpu.regs[4] = HEAP + rng.below(256);
                        cpu.regs[9] = if rng.below(4) == 0 {
                            rng.value() & 0xff
                        } else {
                            rng.below(97)
                        };
                        if rng.below(2) == 0 {
                            cpu.regs[6] = cpu.regs[9];
                        }
                        regions.push((HEAP, 0x8200));
                    }
                    Routine::InflateFast => unreachable!(),
                }
                let Some((native, guest, steps)) = differ(&mut cpu, &mut mem, routine, &regions)
                else {
                    declined += 1;
                    continue;
                };
                ran += 1;
                total += steps;
                if routine.exact() {
                    let byte = native.2.iter().zip(&guest.2).position(|(a, b)| a != b);
                    assert!(
                        native == guest,
                        "{routine:?} differs at byte {byte:?}:\nnative {:08x?} {:08x}\nguest  {:08x?} {:08x}",
                        native.0, native.1, guest.0, guest.1
                    );
                } else {
                    // Under the procedure call standard: r0, callee-saved
                    // registers, sp, pc, the instruction set and memory
                    // above the stack pointer.
                    let abi = |s: &State| {
                        let r = [0, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15].map(|i| s.0[i]);
                        (r, s.1 & 0x20, s.2[128..].to_vec())
                    };
                    assert!(abi(&native) == abi(&guest), "{routine:?} differs");
                }
            }
            assert!(ran > 0);
            totals.insert(format!("{routine:?}"), (ran, declined, total));
        }
        eprintln!("ran, declined, guest instructions: {totals:?}");
    }
}
