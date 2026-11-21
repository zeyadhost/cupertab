/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Portable ARMv6 interpreter, used where the dynarmic JIT is unavailable
//! (notably WebAssembly).
//!
//! Covers the ARM and Thumb-1 instruction sets, the ARMv6 media extensions
//! and VFPv2 (scalar only).

mod arm;
mod thumb;
mod vfp;

use crate::mem::Mem;

/// Saved CPU state, laid out like dynarmic's context.
#[repr(C)]
#[derive(Clone)]
pub struct InterpContext {
    pub regs: [u32; 16],
    pub extregs: [u32; 64],
    pub cpsr: u32,
    pub fpscr: u32,
}
impl InterpContext {
    pub fn new() -> Self {
        InterpContext {
            regs: [0; 16],
            extregs: [0; 64],
            cpsr: 0x10,
            fpscr: 0,
        }
    }
}
impl Default for InterpContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Why execution of a single instruction stopped the run loop.
pub enum Exit {
    Svc(u32),
    MemoryError,
    Undefined,
    Breakpoint,
}

type Res = Result<(), Exit>;

pub struct Interp {
    pub regs: [u32; 16],
    pub ext: [u32; 64],
    pub fpscr: u32,
    n: bool,
    z: bool,
    c: bool,
    v: bool,
    q: bool,
    ge: u32,
    thumb: bool,
    /// Value read for r15 by the current instruction.
    pc_read: u32,
    /// Set when the current instruction wrote r15.
    branched: bool,
    exclusive: bool,
}

impl Interp {
    pub fn new() -> Self {
        Interp {
            regs: [0; 16],
            ext: [0; 64],
            fpscr: 0,
            n: false,
            z: false,
            c: false,
            v: false,
            q: false,
            ge: 0,
            thumb: false,
            pc_read: 0,
            branched: false,
            exclusive: false,
        }
    }

    pub fn cpsr(&self) -> u32 {
        (self.n as u32) << 31
            | (self.z as u32) << 30
            | (self.c as u32) << 29
            | (self.v as u32) << 28
            | (self.q as u32) << 27
            | (self.ge & 0xf) << 16
            | (self.thumb as u32) << 5
            | 0x10
    }
    pub fn set_cpsr(&mut self, cpsr: u32) {
        self.n = cpsr & (1 << 31) != 0;
        self.z = cpsr & (1 << 30) != 0;
        self.c = cpsr & (1 << 29) != 0;
        self.v = cpsr & (1 << 28) != 0;
        self.q = cpsr & (1 << 27) != 0;
        self.ge = (cpsr >> 16) & 0xf;
        self.thumb = cpsr & (1 << 5) != 0;
    }

    pub fn swap_context(&mut self, ctx: &mut InterpContext) {
        std::mem::swap(&mut self.regs, &mut ctx.regs);
        std::mem::swap(&mut self.ext, &mut ctx.extregs);
        std::mem::swap(&mut self.fpscr, &mut ctx.fpscr);
        let cpsr = self.cpsr();
        self.set_cpsr(ctx.cpsr);
        ctx.cpsr = cpsr;
        self.exclusive = false;
    }

    /// Run until `ticks` runs out (or for one instruction if [None]).
    pub fn run(&mut self, mem: &mut Mem, ticks: Option<&mut u64>) -> Option<Exit> {
        match ticks {
            None => self.step(mem).err(),
            Some(ticks) => {
                let mut remaining = *ticks;
                let mut result = None;
                while remaining > 0 {
                    remaining -= 1;
                    if let Err(e) = self.step(mem) {
                        result = Some(e);
                        break;
                    }
                }
                *ticks = remaining;
                result
            }
        }
    }

    #[inline(always)]
    fn step(&mut self, mem: &mut Mem) -> Res {
        let pc = self.regs[15];
        self.branched = false;
        let res = if self.thumb {
            self.pc_read = pc.wrapping_add(4);
            let Some(ins) = mem.cpu_read::<2>(pc) else {
                return Err(Exit::MemoryError);
            };
            let ins = u16::from_le_bytes(ins);
            if ins >> 11 >= 0b11101 {
                let Some(lo) = mem.cpu_read::<2>(pc.wrapping_add(2)) else {
                    return Err(Exit::MemoryError);
                };
                let ins32 = (ins as u32) << 16 | u16::from_le_bytes(lo) as u32;
                let r = self.exec_thumb32(mem, ins32);
                if r.is_ok() && !self.branched {
                    self.regs[15] = pc.wrapping_add(4);
                }
                r
            } else {
                let r = self.exec_thumb(mem, ins);
                if r.is_ok() && !self.branched {
                    self.regs[15] = pc.wrapping_add(2);
                }
                r
            }
        } else {
            self.pc_read = pc.wrapping_add(8);
            let Some(ins) = mem.cpu_read::<4>(pc) else {
                return Err(Exit::MemoryError);
            };
            let r = self.exec_arm(mem, u32::from_le_bytes(ins));
            if r.is_ok() && !self.branched {
                self.regs[15] = pc.wrapping_add(4);
            }
            r
        };
        match res {
            Err(Exit::Svc(_)) => {
                // PC points after the SVC, like dynarmic.
                self.regs[15] = pc.wrapping_add(if self.thumb { 2 } else { 4 });
                res
            }
            Err(_) => {
                self.regs[15] = pc;
                res
            }
            Ok(()) => res,
        }
    }

    // Register access

    #[inline(always)]
    fn get(&self, r: u32) -> u32 {
        if r == 15 {
            self.pc_read
        } else {
            self.regs[r as usize]
        }
    }
    /// Write a register; writes to PC are plain branches (no interworking).
    #[inline(always)]
    fn set(&mut self, r: u32, v: u32) {
        if r == 15 {
            self.branch_to(v);
        } else {
            self.regs[r as usize] = v;
        }
    }
    /// Write a register; writes to PC interwork (bit 0 selects Thumb).
    #[inline(always)]
    fn set_bx(&mut self, r: u32, v: u32) {
        if r == 15 {
            self.bx(v);
        } else {
            self.regs[r as usize] = v;
        }
    }
    #[inline(always)]
    fn branch_to(&mut self, v: u32) {
        self.regs[15] = if self.thumb { v & !1 } else { v & !3 };
        self.branched = true;
    }
    #[inline(always)]
    fn bx(&mut self, v: u32) {
        self.thumb = v & 1 != 0;
        self.regs[15] = if self.thumb { v & !1 } else { v & !3 };
        self.branched = true;
    }

    // Flags

    #[inline(always)]
    fn cond(&self, cond: u32) -> bool {
        match cond {
            0 => self.z,
            1 => !self.z,
            2 => self.c,
            3 => !self.c,
            4 => self.n,
            5 => !self.n,
            6 => self.v,
            7 => !self.v,
            8 => self.c && !self.z,
            9 => !self.c || self.z,
            10 => self.n == self.v,
            11 => self.n != self.v,
            12 => !self.z && self.n == self.v,
            13 => self.z || self.n != self.v,
            _ => true,
        }
    }
    #[inline(always)]
    fn set_nz(&mut self, v: u32) {
        self.n = (v as i32) < 0;
        self.z = v == 0;
    }

    // Memory access

    #[inline(always)]
    fn read32(&self, mem: &Mem, addr: u32) -> Result<u32, Exit> {
        mem.cpu_read::<4>(addr)
            .map(u32::from_le_bytes)
            .ok_or(Exit::MemoryError)
    }
    #[inline(always)]
    fn read16(&self, mem: &Mem, addr: u32) -> Result<u32, Exit> {
        mem.cpu_read::<2>(addr)
            .map(|b| u16::from_le_bytes(b) as u32)
            .ok_or(Exit::MemoryError)
    }
    #[inline(always)]
    fn read8(&self, mem: &Mem, addr: u32) -> Result<u32, Exit> {
        mem.cpu_read::<1>(addr)
            .map(|b| b[0] as u32)
            .ok_or(Exit::MemoryError)
    }
    #[inline(always)]
    fn write32(&self, mem: &mut Mem, addr: u32, v: u32) -> Res {
        if mem.cpu_write(addr, v.to_le_bytes()) {
            Ok(())
        } else {
            Err(Exit::MemoryError)
        }
    }
    #[inline(always)]
    fn write16(&self, mem: &mut Mem, addr: u32, v: u32) -> Res {
        if mem.cpu_write(addr, (v as u16).to_le_bytes()) {
            Ok(())
        } else {
            Err(Exit::MemoryError)
        }
    }
    #[inline(always)]
    fn write8(&self, mem: &mut Mem, addr: u32, v: u32) -> Res {
        if mem.cpu_write(addr, [v as u8]) {
            Ok(())
        } else {
            Err(Exit::MemoryError)
        }
    }
}

// ALU helpers shared by ARM and Thumb.

#[inline(always)]
fn add_with_carry(a: u32, b: u32, carry: bool) -> (u32, bool, bool) {
    let sum = a as u64 + b as u64 + carry as u64;
    let res = sum as u32;
    let c = sum >> 32 != 0;
    let v = ((a ^ res) & (b ^ res)) >> 31 != 0;
    (res, c, v)
}

/// Shift with register-specified amount semantics (`n` may be 0 or >= 32).
/// `ty`: 0 LSL, 1 LSR, 2 ASR, 3 ROR.
#[inline(always)]
fn shift_c(x: u32, ty: u32, n: u32, c: bool) -> (u32, bool) {
    if n == 0 {
        return (x, c);
    }
    match ty {
        0 => match n {
            1..=31 => (x << n, (x >> (32 - n)) & 1 != 0),
            32 => (0, x & 1 != 0),
            _ => (0, false),
        },
        1 => match n {
            1..=31 => (x >> n, (x >> (n - 1)) & 1 != 0),
            32 => (0, x >> 31 != 0),
            _ => (0, false),
        },
        2 => {
            if n < 32 {
                (((x as i32) >> n) as u32, ((x as i32) >> (n - 1)) & 1 != 0)
            } else {
                let s = ((x as i32) >> 31) as u32;
                (s, s & 1 != 0)
            }
        }
        _ => {
            let r = n & 31;
            if r == 0 {
                (x, x >> 31 != 0)
            } else {
                let v = x.rotate_right(r);
                (v, v >> 31 != 0)
            }
        }
    }
}

/// Shift with immediate-encoded semantics (`imm5` == 0 has special meanings).
#[inline(always)]
fn shift_imm_c(x: u32, ty: u32, imm5: u32, c: bool) -> (u32, bool) {
    match (ty, imm5) {
        (0, 0) => (x, c),
        (1, 0) | (2, 0) => shift_c(x, ty, 32, c),
        (3, 0) => (((c as u32) << 31) | (x >> 1), x & 1 != 0),
        _ => shift_c(x, ty, imm5, c),
    }
}

fn signed_sat(v: i64, bits: u32) -> (u32, bool) {
    let max = (1i64 << (bits - 1)) - 1;
    let min = -(1i64 << (bits - 1));
    if v > max {
        (max as u32, true)
    } else if v < min {
        (min as u32, true)
    } else {
        (v as u32, false)
    }
}
fn unsigned_sat(v: i64, bits: u32) -> (u32, bool) {
    let max = if bits == 32 {
        u32::MAX as i64
    } else {
        (1i64 << bits) - 1
    };
    if v > max {
        (max as u32, true)
    } else if v < 0 {
        (0, true)
    } else {
        (v as u32, false)
    }
}
