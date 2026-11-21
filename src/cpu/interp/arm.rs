/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! ARM (A32) instruction set.

use super::{add_with_carry, shift_c, shift_imm_c, signed_sat, unsigned_sat, Exit, Interp, Res};
use crate::mem::Mem;

#[inline(always)]
fn bits(ins: u32, hi: u32, lo: u32) -> u32 {
    (ins >> lo) & ((1 << (hi - lo + 1)) - 1)
}
#[inline(always)]
fn bit(ins: u32, b: u32) -> bool {
    (ins >> b) & 1 != 0
}

impl Interp {
    pub(super) fn exec_arm(&mut self, mem: &mut Mem, ins: u32) -> Res {
        let cond = ins >> 28;
        if cond == 0xf {
            return self.exec_arm_unconditional(ins);
        }
        if !self.cond(cond) {
            return Ok(());
        }
        match bits(ins, 27, 25) {
            0 => {
                if ins & 0x90 == 0x90 {
                    self.arm_mul_extra(mem, ins)
                } else if ins & 0x01900000 == 0x01000000 {
                    self.arm_misc(ins)
                } else {
                    let (op2, c) = self.arm_shifted_reg(ins);
                    self.arm_data_processing(ins, op2, c)
                }
            }
            1 => {
                if ins & 0x01900000 == 0x01000000 {
                    if bit(ins, 21) {
                        // MSR immediate
                        let imm = bits(ins, 7, 0).rotate_right(bits(ins, 11, 8) * 2);
                        self.msr(bits(ins, 19, 16), imm);
                        Ok(())
                    } else {
                        // MOVW / MOVT
                        let imm16 = bits(ins, 19, 16) << 12 | bits(ins, 11, 0);
                        let rd = bits(ins, 15, 12);
                        if bit(ins, 22) {
                            let v = (self.get(rd) & 0xffff) | imm16 << 16;
                            self.set(rd, v);
                        } else {
                            self.set(rd, imm16);
                        }
                        Ok(())
                    }
                } else {
                    let rot = bits(ins, 11, 8) * 2;
                    let imm = bits(ins, 7, 0).rotate_right(rot);
                    let c = if rot == 0 { self.c } else { imm >> 31 != 0 };
                    self.arm_data_processing(ins, imm, c)
                }
            }
            2 => {
                let off = bits(ins, 11, 0);
                self.arm_ldr_str(mem, ins, off)
            }
            3 => {
                if bit(ins, 4) {
                    self.arm_media(ins)
                } else {
                    let rm = self.get(bits(ins, 3, 0));
                    let (off, _) = shift_imm_c(rm, bits(ins, 6, 5), bits(ins, 11, 7), self.c);
                    self.arm_ldr_str(mem, ins, off)
                }
            }
            4 => self.arm_ldm_stm(mem, ins),
            5 => {
                let off = ((ins << 8) as i32 >> 6) as u32;
                if bit(ins, 24) {
                    self.regs[14] = self.regs[15].wrapping_add(4);
                }
                let target = self.pc_read.wrapping_add(off);
                self.branch_to(target);
                Ok(())
            }
            6 => {
                let cp = bits(ins, 11, 8);
                if cp == 10 || cp == 11 {
                    self.vfp_load_store(mem, ins)
                } else {
                    Err(Exit::Undefined)
                }
            }
            _ => {
                if bit(ins, 24) {
                    return Err(Exit::Svc(bits(ins, 23, 0)));
                }
                let cp = bits(ins, 11, 8);
                if cp == 10 || cp == 11 {
                    self.vfp_op(ins)
                } else if cp == 15 {
                    self.cp15(ins)
                } else {
                    Err(Exit::Undefined)
                }
            }
        }
    }

    fn exec_arm_unconditional(&mut self, ins: u32) -> Res {
        if bits(ins, 27, 25) == 0b101 {
            // BLX immediate
            let off = ((ins << 8) as i32 >> 6) as u32 | ((bit(ins, 24) as u32) << 1);
            self.regs[14] = self.regs[15].wrapping_add(4);
            let target = self.pc_read.wrapping_add(off);
            self.thumb = true;
            self.branch_to(target);
            return Ok(());
        }
        // PLD, CLREX, DMB/DSB/ISB, CPS, SETEND: no effect for us.
        if ins & 0x0D70F000 == 0x0550F000 || ins & 0x0FF00000 == 0x05700000 {
            if ins & 0x0FFFFFFF == 0x057FF01F {
                self.exclusive = false;
            }
            return Ok(());
        }
        if ins & 0x0FF10000 == 0x01000000 {
            return Ok(());
        }
        Err(Exit::Undefined)
    }

    pub(super) fn cp15(&mut self, ins: u32) -> Res {
        // Barrier operations (c7, c10, 4/5) and other cache maintenance are
        // no-ops for an interpreter. Reads return 0, except the user
        // read-only thread ID register (c13, c0, 3), used as the thread
        // pointer by libSystem.
        if bit(ins, 4) && bit(ins, 20) {
            let rt = bits(ins, 15, 12);
            let is_tpidruro = bits(ins, 23, 21) == 0
                && bits(ins, 19, 16) == 13
                && bits(ins, 3, 0) == 0
                && bits(ins, 7, 5) == 3;
            if rt != 15 {
                self.regs[rt as usize] = if is_tpidruro { self.tls } else { 0 };
            }
        }
        Ok(())
    }

    fn msr(&mut self, mask: u32, v: u32) {
        let mut cpsr = self.cpsr();
        if mask & 8 != 0 {
            cpsr = (cpsr & 0x00ffffff) | (v & 0xf8000000);
        }
        if mask & 4 != 0 {
            cpsr = (cpsr & !0x000f0000) | (v & 0x000f0000);
        }
        self.set_cpsr(cpsr);
    }

    /// Operand 2 for data processing with a register (immediate or
    /// register shift).
    #[inline(always)]
    fn arm_shifted_reg(&self, ins: u32) -> (u32, bool) {
        let ty = bits(ins, 6, 5);
        if bit(ins, 4) {
            let rm = bits(ins, 3, 0);
            let rm_v = if rm == 15 {
                self.pc_read + 4
            } else {
                self.regs[rm as usize]
            };
            let amount = self.get(bits(ins, 11, 8)) & 0xff;
            shift_c(rm_v, ty, amount, self.c)
        } else {
            shift_imm_c(self.get(bits(ins, 3, 0)), ty, bits(ins, 11, 7), self.c)
        }
    }

    #[inline(always)]
    fn arm_data_processing(&mut self, ins: u32, op2: u32, shift_carry: bool) -> Res {
        let opc = bits(ins, 24, 21);
        let s = bit(ins, 20);
        let rn = self.get(bits(ins, 19, 16));
        let rd = bits(ins, 15, 12);
        let (res, write) = self.alu(opc, s, rn, op2, shift_carry);
        if write {
            self.set_bx(rd, res);
        }
        Ok(())
    }

    /// Shared 16-operation ALU; returns (result, writes_destination).
    #[inline(always)]
    pub(super) fn alu(
        &mut self,
        opc: u32,
        s: bool,
        a: u32,
        b: u32,
        shift_carry: bool,
    ) -> (u32, bool) {
        let logical = |this: &mut Self, r: u32| {
            if s {
                this.set_nz(r);
                this.c = shift_carry;
            }
            r
        };
        let arith = |this: &mut Self, (r, c, v): (u32, bool, bool)| {
            if s {
                this.set_nz(r);
                this.c = c;
                this.v = v;
            }
            r
        };
        match opc {
            0 => (logical(self, a & b), true),
            1 => (logical(self, a ^ b), true),
            2 => (arith(self, add_with_carry(a, !b, true)), true),
            3 => (arith(self, add_with_carry(b, !a, true)), true),
            4 => (arith(self, add_with_carry(a, b, false)), true),
            5 => {
                let c = self.c;
                (arith(self, add_with_carry(a, b, c)), true)
            }
            6 => {
                let c = self.c;
                (arith(self, add_with_carry(a, !b, c)), true)
            }
            7 => {
                let c = self.c;
                (arith(self, add_with_carry(b, !a, c)), true)
            }
            8 => {
                let r = a & b;
                self.set_nz(r);
                self.c = shift_carry;
                (r, false)
            }
            9 => {
                let r = a ^ b;
                self.set_nz(r);
                self.c = shift_carry;
                (r, false)
            }
            10 => {
                let (r, c, v) = add_with_carry(a, !b, true);
                self.set_nz(r);
                self.c = c;
                self.v = v;
                (r, false)
            }
            11 => {
                let (r, c, v) = add_with_carry(a, b, false);
                self.set_nz(r);
                self.c = c;
                self.v = v;
                (r, false)
            }
            12 => (logical(self, a | b), true),
            13 => (logical(self, b), true),
            14 => (logical(self, a & !b), true),
            _ => (logical(self, !b), true),
        }
    }

    fn arm_misc(&mut self, ins: u32) -> Res {
        if ins & 0x0FBF0FFF == 0x010F0000 {
            // MRS
            let v = if bit(ins, 22) { 0 } else { self.cpsr() };
            self.set(bits(ins, 15, 12), v);
            return Ok(());
        }
        if ins & 0x0FB0FFF0 == 0x0120F000 {
            let v = self.get(bits(ins, 3, 0));
            if !bit(ins, 22) {
                self.msr(bits(ins, 19, 16), v);
            }
            return Ok(());
        }
        if ins & 0x0FFFFFC0 == 0x012FFF00 {
            // BX, BXJ, BLX (register)
            let target = self.get(bits(ins, 3, 0));
            if bits(ins, 5, 4) == 3 {
                self.regs[14] = self.regs[15].wrapping_add(4);
            } else if bits(ins, 5, 4) == 0 {
                return Err(Exit::Undefined);
            }
            self.bx(target);
            return Ok(());
        }
        if ins & 0x0FFF0FF0 == 0x016F0F10 {
            let v = self.get(bits(ins, 3, 0)).leading_zeros();
            self.set(bits(ins, 15, 12), v);
            return Ok(());
        }
        if ins & 0x0FF000F0 == 0x01200070 {
            return Err(Exit::Breakpoint);
        }
        if ins & 0x0F900FF0 == 0x01000050 {
            // QADD, QSUB, QDADD, QDSUB
            let rm = self.get(bits(ins, 3, 0)) as i32 as i64;
            let mut rn = self.get(bits(ins, 19, 16)) as i32 as i64;
            let op = bits(ins, 22, 21);
            if op & 2 != 0 {
                let (d, sat) = signed_sat(rn * 2, 32);
                rn = d as i32 as i64;
                self.q |= sat;
            }
            let (r, sat) = signed_sat(if op & 1 != 0 { rm - rn } else { rm + rn }, 32);
            self.q |= sat;
            self.set(bits(ins, 15, 12), r);
            return Ok(());
        }
        if ins & 0x0F900090 == 0x01000080 {
            // Signed 16-bit multiplies
            let rd = bits(ins, 19, 16);
            let ra = self.get(bits(ins, 15, 12));
            let rs = self.get(bits(ins, 11, 8));
            let rm = self.get(bits(ins, 3, 0));
            let x = bit(ins, 5);
            let y = bit(ins, 6);
            let half = |v: u32, top: bool| -> i64 {
                if top {
                    (v >> 16) as i16 as i64
                } else {
                    v as i16 as i64
                }
            };
            match bits(ins, 22, 21) {
                0 => {
                    let p = half(rm, x) * half(rs, y);
                    let r = p + ra as i32 as i64;
                    if r != r as i32 as i64 {
                        self.q = true;
                    }
                    self.set(rd, r as u32);
                }
                1 => {
                    let p = (rm as i32 as i64 * half(rs, y)) >> 16;
                    if x {
                        self.set(rd, p as u32);
                    } else {
                        let r = p + ra as i32 as i64;
                        if r != r as i32 as i64 {
                            self.q = true;
                        }
                        self.set(rd, r as u32);
                    }
                }
                2 => {
                    let rdlo = bits(ins, 15, 12);
                    let acc = ((self.get(rd) as u64) << 32 | self.get(rdlo) as u64) as i64;
                    let r = acc.wrapping_add(half(rm, x) * half(rs, y)) as u64;
                    self.set(rdlo, r as u32);
                    self.set(rd, (r >> 32) as u32);
                }
                _ => {
                    let p = half(rm, x) * half(rs, y);
                    self.set(rd, p as u32);
                }
            }
            return Ok(());
        }
        Err(Exit::Undefined)
    }

    fn arm_mul_extra(&mut self, mem: &mut Mem, ins: u32) -> Res {
        let op = bits(ins, 6, 5);
        if op == 0 {
            if !bit(ins, 24) {
                return self.arm_multiply(ins);
            }
            let rn = self.get(bits(ins, 19, 16));
            let rd = bits(ins, 15, 12);
            if !bit(ins, 23) {
                // SWP / SWPB
                let rm = self.get(bits(ins, 3, 0));
                if bit(ins, 22) {
                    let old = self.read8(mem, rn)?;
                    self.write8(mem, rn, rm)?;
                    self.set(rd, old);
                } else {
                    let old = self.read32(mem, rn)?;
                    self.write32(mem, rn, rm)?;
                    self.set(rd, old.rotate_right((rn & 3) * 8));
                }
                return Ok(());
            }
            // LDREX/STREX family
            let size = bits(ins, 22, 21);
            if bit(ins, 20) {
                match size {
                    0 => {
                        let v = self.read32(mem, rn)?;
                        self.set(rd, v)
                    }
                    1 => {
                        let lo = self.read32(mem, rn)?;
                        let hi = self.read32(mem, rn.wrapping_add(4))?;
                        self.set(rd, lo);
                        self.set(rd + 1, hi);
                    }
                    2 => {
                        let v = self.read8(mem, rn)?;
                        self.set(rd, v)
                    }
                    _ => {
                        let v = self.read16(mem, rn)?;
                        self.set(rd, v)
                    }
                }
                self.exclusive = true;
            } else {
                let rt = bits(ins, 3, 0);
                if self.exclusive {
                    let v = self.get(rt);
                    match size {
                        0 => self.write32(mem, rn, v)?,
                        1 => {
                            self.write32(mem, rn, v)?;
                            let v2 = self.get(rt + 1);
                            self.write32(mem, rn.wrapping_add(4), v2)?;
                        }
                        2 => self.write8(mem, rn, v)?,
                        _ => self.write16(mem, rn, v)?,
                    }
                    self.set(rd, 0);
                } else {
                    self.set(rd, 1);
                }
                self.exclusive = false;
            }
            return Ok(());
        }
        // Extra load/store
        let p = bit(ins, 24);
        let u = bit(ins, 23);
        let w = bit(ins, 21);
        let l = bit(ins, 20);
        let rn_idx = bits(ins, 19, 16);
        let rd = bits(ins, 15, 12);
        let off = if bit(ins, 22) {
            bits(ins, 11, 8) << 4 | bits(ins, 3, 0)
        } else {
            self.get(bits(ins, 3, 0))
        };
        let base = self.get(rn_idx);
        let offset_addr = if u {
            base.wrapping_add(off)
        } else {
            base.wrapping_sub(off)
        };
        let addr = if p { offset_addr } else { base };
        let wb = !p || w;
        match (op, l) {
            (1, false) => {
                let v = self.get(rd);
                self.write16(mem, addr, v)?;
                if wb {
                    self.set(rn_idx, offset_addr);
                }
            }
            (2, false) => {
                // LDRD
                let lo = self.read32(mem, addr)?;
                let hi = self.read32(mem, addr.wrapping_add(4))?;
                if wb {
                    self.set(rn_idx, offset_addr);
                }
                self.set(rd, lo);
                self.set_bx(rd + 1, hi);
            }
            (3, false) => {
                // STRD
                let lo = self.get(rd);
                let hi = self.get(rd + 1);
                self.write32(mem, addr, lo)?;
                self.write32(mem, addr.wrapping_add(4), hi)?;
                if wb {
                    self.set(rn_idx, offset_addr);
                }
            }
            (_, true) => {
                let v = match op {
                    1 => self.read16(mem, addr)?,
                    2 => self.read8(mem, addr)? as u8 as i8 as i32 as u32,
                    _ => self.read16(mem, addr)? as u16 as i16 as i32 as u32,
                };
                if wb {
                    self.set(rn_idx, offset_addr);
                }
                self.set(rd, v);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn arm_multiply(&mut self, ins: u32) -> Res {
        let s = bit(ins, 20);
        let rd = bits(ins, 19, 16);
        let rn = bits(ins, 15, 12);
        let rs = self.get(bits(ins, 11, 8));
        let rm = self.get(bits(ins, 3, 0));
        match bits(ins, 23, 21) {
            0 | 1 | 3 => {
                let p = rm.wrapping_mul(rs);
                let r = match bits(ins, 23, 21) {
                    0 => p,
                    1 => p.wrapping_add(self.get(rn)),
                    _ => self.get(rn).wrapping_sub(p),
                };
                self.set(rd, r);
                if s {
                    self.set_nz(r);
                }
            }
            2 => {
                // UMAAL
                let r = rm as u64 * rs as u64 + self.get(rn) as u64 + self.get(rd) as u64;
                self.set(rn, r as u32);
                self.set(rd, (r >> 32) as u32);
            }
            op => {
                let acc = (self.get(rd) as u64) << 32 | self.get(rn) as u64;
                let p = if op & 2 != 0 {
                    (rm as i32 as i64 * rs as i32 as i64) as u64
                } else {
                    rm as u64 * rs as u64
                };
                let r = if op & 1 != 0 { p.wrapping_add(acc) } else { p };
                self.set(rn, r as u32);
                self.set(rd, (r >> 32) as u32);
                if s {
                    self.n = (r as i64) < 0;
                    self.z = r == 0;
                }
            }
        }
        Ok(())
    }

    fn arm_ldr_str(&mut self, mem: &mut Mem, ins: u32, off: u32) -> Res {
        let p = bit(ins, 24);
        let u = bit(ins, 23);
        let b = bit(ins, 22);
        let w = bit(ins, 21);
        let l = bit(ins, 20);
        let rn_idx = bits(ins, 19, 16);
        let rd = bits(ins, 15, 12);
        let base = self.get(rn_idx);
        let offset_addr = if u {
            base.wrapping_add(off)
        } else {
            base.wrapping_sub(off)
        };
        let addr = if p { offset_addr } else { base };
        let wb = !p || w;
        if l {
            let v = if b {
                self.read8(mem, addr)?
            } else {
                self.read32(mem, addr)?
            };
            if wb {
                self.set(rn_idx, offset_addr);
            }
            self.set_bx(rd, v);
        } else {
            let v = self.get(rd);
            if b {
                self.write8(mem, addr, v)?;
            } else {
                self.write32(mem, addr, v)?;
            }
            if wb {
                self.set(rn_idx, offset_addr);
            }
        }
        Ok(())
    }

    fn arm_ldm_stm(&mut self, mem: &mut Mem, ins: u32) -> Res {
        let p = bit(ins, 24);
        let u = bit(ins, 23);
        let w = bit(ins, 21);
        let l = bit(ins, 20);
        let rn_idx = bits(ins, 19, 16);
        let list = bits(ins, 15, 0);
        self.block_transfer(mem, rn_idx, list, p, u, w, l)
    }

    /// LDM/STM/PUSH/POP shared by ARM and Thumb.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn block_transfer(
        &mut self,
        mem: &mut Mem,
        rn_idx: u32,
        list: u32,
        p: bool,
        u: bool,
        w: bool,
        l: bool,
    ) -> Res {
        let count = list.count_ones();
        let base = self.get(rn_idx);
        let mut addr = match (p, u) {
            (false, true) => base,
            (true, true) => base.wrapping_add(4),
            (false, false) => base.wrapping_sub(4 * count).wrapping_add(4),
            (true, false) => base.wrapping_sub(4 * count),
        };
        let new_base = if u {
            base.wrapping_add(4 * count)
        } else {
            base.wrapping_sub(4 * count)
        };
        if l {
            let mut vals = [0u32; 16];
            let mut a = addr;
            for (r, val) in vals.iter_mut().enumerate() {
                if list & (1 << r) != 0 {
                    *val = self.read32(mem, a)?;
                    a = a.wrapping_add(4);
                }
            }
            if w && list & (1 << rn_idx) == 0 {
                self.set(rn_idx, new_base);
            }
            for (r, v) in vals.iter().enumerate() {
                if list & (1 << r) != 0 {
                    self.set_bx(r as u32, *v);
                }
            }
        } else {
            for r in 0..16 {
                if list & (1 << r) != 0 {
                    let v = self.get(r);
                    self.write32(mem, addr, v)?;
                    addr = addr.wrapping_add(4);
                }
            }
            if w {
                self.set(rn_idx, new_base);
            }
        }
        Ok(())
    }

    fn arm_media(&mut self, ins: u32) -> Res {
        let rn_idx = bits(ins, 19, 16);
        let rd = bits(ins, 15, 12);
        let rm = self.get(bits(ins, 3, 0));
        let op1 = bits(ins, 24, 20);
        let op2 = bits(ins, 7, 5);
        match op1 >> 3 {
            0 => self.parallel_add_sub(bits(ins, 22, 20), op2, self.get(rn_idx), rm, rd),
            1 => {
                if ins & 0x0FF00030 == 0x06800010 {
                    // PKHBT / PKHTB
                    let rn = self.get(rn_idx);
                    let imm = bits(ins, 11, 7);
                    let r = if bit(ins, 6) {
                        let (s, _) = shift_imm_c(rm, 2, imm, false);
                        (rn & 0xffff0000) | (s & 0xffff)
                    } else {
                        (rn & 0xffff) | ((rm << imm) & 0xffff0000)
                    };
                    self.set(rd, r);
                    Ok(())
                } else if ins & 0x0FF00FF0 == 0x06800FB0 {
                    // SEL
                    let rn = self.get(rn_idx);
                    let mut r = 0;
                    for i in 0..4 {
                        let src = if self.ge & (1 << i) != 0 { rn } else { rm };
                        r |= src & (0xff << (i * 8));
                    }
                    self.set(rd, r);
                    Ok(())
                } else if ins & 0x0FA00030 == 0x06A00010 {
                    // SSAT / USAT
                    let (v, _) = shift_imm_c(rm, bits(ins, 6, 5), bits(ins, 11, 7), false);
                    let sat_imm = bits(ins, 20, 16);
                    let (r, sat) = if bit(ins, 22) {
                        unsigned_sat(v as i32 as i64, sat_imm)
                    } else {
                        signed_sat(v as i32 as i64, sat_imm + 1)
                    };
                    self.q |= sat;
                    self.set(rd, r);
                    Ok(())
                } else if ins & 0x0FB00FF0 == 0x06A00F30 {
                    // SSAT16 / USAT16
                    let sat_imm = bits(ins, 19, 16);
                    let mut r = 0;
                    for i in 0..2 {
                        let h = (rm >> (16 * i)) as u16 as i16 as i64;
                        let (v, sat) = if bit(ins, 22) {
                            unsigned_sat(h, sat_imm)
                        } else {
                            signed_sat(h, sat_imm + 1)
                        };
                        self.q |= sat;
                        r |= (v & 0xffff) << (16 * i);
                    }
                    self.set(rd, r);
                    Ok(())
                } else if ins & 0x0F8000F0 == 0x06800070 {
                    // Extends (with optional add)
                    let rot = rm.rotate_right(bits(ins, 11, 10) * 8);
                    let acc = if rn_idx == 15 { 0 } else { self.get(rn_idx) };
                    let r = match bits(ins, 22, 20) {
                        0 | 4 => {
                            let (lo, hi) = if bits(ins, 22, 20) == 0 {
                                (
                                    rot as u8 as i8 as u32 & 0xffff,
                                    (rot >> 16) as u8 as i8 as u32 & 0xffff,
                                )
                            } else {
                                (rot & 0xff, (rot >> 16) & 0xff)
                            };
                            let lo = (acc as u16).wrapping_add(lo as u16) as u32;
                            let hi = ((acc >> 16) as u16).wrapping_add(hi as u16) as u32;
                            lo | hi << 16
                        }
                        2 => acc.wrapping_add(rot as u8 as i8 as u32),
                        3 => acc.wrapping_add(rot as u16 as i16 as u32),
                        6 => acc.wrapping_add(rot & 0xff),
                        7 => acc.wrapping_add(rot & 0xffff),
                        _ => return Err(Exit::Undefined),
                    };
                    self.set(rd, r);
                    Ok(())
                } else if ins & 0x0FFF0FF0 == 0x06BF0F30 {
                    self.set(rd, rm.swap_bytes());
                    Ok(())
                } else if ins & 0x0FFF0FF0 == 0x06BF0FB0 {
                    self.set(rd, rev16(rm));
                    Ok(())
                } else if ins & 0x0FFF0FF0 == 0x06FF0F30 {
                    self.set(rd, rm.reverse_bits());
                    Ok(())
                } else if ins & 0x0FFF0FF0 == 0x06FF0FB0 {
                    self.set(rd, revsh(rm));
                    Ok(())
                } else {
                    Err(Exit::Undefined)
                }
            }
            2 => {
                // Signed multiplies; here Rd is bits 19..16, Ra bits 15..12,
                // Rm bits 11..8 and Rn bits 3..0.
                let rd2 = rn_idx;
                let ra_idx = rd;
                let rn = rm;
                let rm = self.get(bits(ins, 11, 8));
                let rm = if bit(ins, 5) { rm.rotate_right(16) } else { rm };
                let lo = |v: u32| v as i16 as i64;
                let hi = |v: u32| (v >> 16) as i16 as i64;
                match bits(ins, 22, 20) {
                    0 => {
                        let p1 = lo(rn) * lo(rm);
                        let p2 = hi(rn) * hi(rm);
                        let sum = if bit(ins, 6) { p1 - p2 } else { p1 + p2 };
                        let acc = if ra_idx == 15 {
                            0
                        } else {
                            self.get(ra_idx) as i32 as i64
                        };
                        let r = sum + acc;
                        if r != r as i32 as i64 {
                            self.q = true;
                        }
                        self.set(rd2, r as u32);
                        Ok(())
                    }
                    4 => {
                        let p1 = lo(rn) * lo(rm);
                        let p2 = hi(rn) * hi(rm);
                        let sum = if bit(ins, 6) { p1 - p2 } else { p1 + p2 };
                        let acc = ((self.get(rd2) as u64) << 32 | self.get(ra_idx) as u64) as i64;
                        let r = acc.wrapping_add(sum) as u64;
                        self.set(ra_idx, r as u32);
                        self.set(rd2, (r >> 32) as u32);
                        Ok(())
                    }
                    5 => {
                        // SMMUL / SMMLA / SMMLS
                        let rm = self.get(bits(ins, 11, 8));
                        let p = (rn as i32 as i64) * (rm as i32 as i64);
                        let acc = if ra_idx == 15 {
                            0
                        } else {
                            (self.get(ra_idx) as i64) << 32
                        };
                        let mut r = if bit(ins, 6) {
                            acc.wrapping_sub(p)
                        } else {
                            acc.wrapping_add(p)
                        };
                        if bit(ins, 5) {
                            r = r.wrapping_add(0x80000000);
                        }
                        self.set(rd2, (r >> 32) as u32);
                        Ok(())
                    }
                    _ => Err(Exit::Undefined),
                }
            }
            _ => {
                if ins & 0x0FF000F0 == 0x07800010 {
                    // USAD8 / USADA8
                    let rn = self.get(bits(ins, 3, 0));
                    let rm = self.get(bits(ins, 11, 8));
                    let mut sum = 0u32;
                    for i in 0..4 {
                        let a = (rn >> (8 * i)) & 0xff;
                        let b = (rm >> (8 * i)) & 0xff;
                        sum += a.abs_diff(b);
                    }
                    if rd != 15 {
                        sum = sum.wrapping_add(self.get(rd));
                    }
                    self.set(rn_idx, sum);
                    Ok(())
                } else if ins & 0x0FA00070 == 0x07A00050 {
                    // SBFX / UBFX
                    let lsb = bits(ins, 11, 7);
                    let width = bits(ins, 20, 16) + 1;
                    let v = rm >> lsb;
                    let r = if width >= 32 {
                        v
                    } else if bit(ins, 22) {
                        v & ((1 << width) - 1)
                    } else {
                        ((v << (32 - width)) as i32 >> (32 - width)) as u32
                    };
                    self.set(rd, r);
                    Ok(())
                } else if ins & 0x0FE00070 == 0x07C00010 {
                    // BFC / BFI
                    let lsb = bits(ins, 11, 7);
                    let msb = bits(ins, 20, 16);
                    if msb < lsb {
                        return Err(Exit::Undefined);
                    }
                    let width = msb - lsb + 1;
                    let mask = if width >= 32 {
                        u32::MAX
                    } else {
                        ((1u32 << width) - 1) << lsb
                    };
                    let src = if bits(ins, 3, 0) == 15 { 0 } else { rm };
                    let r = (self.get(rd) & !mask) | ((src << lsb) & mask);
                    self.set(rd, r);
                    Ok(())
                } else {
                    Err(Exit::Undefined)
                }
            }
        }
    }

    pub(super) fn parallel_add_sub(
        &mut self,
        op1: u32,
        op2: u32,
        rn: u32,
        rm: u32,
        rd: u32,
    ) -> Res {
        // op1: 1 S, 2 Q, 3 SH, 5 U, 6 UQ, 7 UH
        let signed = op1 < 4;
        let kind = op1 & 3; // 1 modulo (sets GE), 2 saturating, 3 halving
        if kind == 0 {
            return Err(Exit::Undefined);
        }
        let (lanes, width) = match op2 {
            0..=3 => (2, 16),
            4 | 7 => (4, 8),
            _ => return Err(Exit::Undefined),
        };
        let lane = |v: u32, i: u32| -> i64 {
            let x = (v >> (i * width)) & ((1 << width) - 1);
            if signed {
                if width == 16 {
                    x as u16 as i16 as i64
                } else {
                    x as u8 as i8 as i64
                }
            } else {
                x as i64
            }
        };
        let mut result = 0u32;
        let mut ge = 0u32;
        for i in 0..lanes {
            let (a, b, add) = match op2 {
                0 | 4 => (lane(rn, i), lane(rm, i), true),
                3 | 7 => (lane(rn, i), lane(rm, i), false),
                // ASX: hi = hi + lo', lo = lo - hi'
                1 => {
                    if i == 0 {
                        (lane(rn, 0), lane(rm, 1), false)
                    } else {
                        (lane(rn, 1), lane(rm, 0), true)
                    }
                }
                // SAX: hi = hi - lo', lo = lo + hi'
                _ => {
                    if i == 0 {
                        (lane(rn, 0), lane(rm, 1), true)
                    } else {
                        (lane(rn, 1), lane(rm, 0), false)
                    }
                }
            };
            let r = if add { a + b } else { a - b };
            let out = match kind {
                1 => {
                    let set = if signed {
                        r >= 0
                    } else if add {
                        r >= 1 << width
                    } else {
                        r >= 0
                    };
                    if set {
                        ge |= if width == 16 { 3 << (i * 2) } else { 1 << i };
                    }
                    r as u32
                }
                2 => {
                    if signed {
                        signed_sat(r, width).0
                    } else {
                        unsigned_sat(r, width).0
                    }
                }
                _ => (r >> 1) as u32,
            };
            result |= (out & ((1 << width) - 1)) << (i * width);
        }
        if kind == 1 {
            self.ge = ge;
        }
        self.set(rd, result);
        Ok(())
    }
}

pub(super) fn rev16(v: u32) -> u32 {
    ((v & 0x00ff00ff) << 8) | ((v & 0xff00ff00) >> 8)
}
pub(super) fn revsh(v: u32) -> u32 {
    ((v as u16).swap_bytes() as i16) as i32 as u32
}
