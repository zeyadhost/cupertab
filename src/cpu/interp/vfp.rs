/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! VFPv2 (scalar operations only; FPSCR short vectors are not supported).

use super::{Exit, Interp, Res};
use crate::mem::Mem;

#[inline(always)]
fn bits(ins: u32, hi: u32, lo: u32) -> u32 {
    (ins >> lo) & ((1 << (hi - lo + 1)) - 1)
}
#[inline(always)]
fn bit(ins: u32, b: u32) -> u32 {
    (ins >> b) & 1
}

/// Register index from a 4-bit field and the extra bit: single precision
/// puts the extra bit at the bottom, double precision at the top.
#[inline(always)]
fn reg(ins: u32, field_lo: u32, extra: u32, double: bool) -> u32 {
    let f = bits(ins, field_lo + 3, field_lo);
    let x = bit(ins, extra);
    if double {
        x << 4 | f
    } else {
        f << 1 | x
    }
}

impl Interp {
    #[inline(always)]
    fn s(&self, i: u32) -> f32 {
        f32::from_bits(self.ext[i as usize])
    }
    #[inline(always)]
    fn set_s(&mut self, i: u32, v: f32) {
        self.ext[i as usize] = v.to_bits();
    }
    #[inline(always)]
    fn d(&self, i: u32) -> f64 {
        let i = (i * 2) as usize;
        f64::from_bits((self.ext[i + 1] as u64) << 32 | self.ext[i] as u64)
    }
    #[inline(always)]
    fn set_d(&mut self, i: u32, v: f64) {
        let i = (i * 2) as usize;
        let b = v.to_bits();
        self.ext[i] = b as u32;
        self.ext[i + 1] = (b >> 32) as u32;
    }

    fn fp_compare(&mut self, a: f64, b: f64) {
        let nzcv = if a.is_nan() || b.is_nan() {
            0b0011
        } else if a == b {
            0b0110
        } else if a < b {
            0b1000
        } else {
            0b0010
        };
        self.fpscr = (self.fpscr & 0x0fffffff) | nzcv << 28;
    }

    fn round_to_int(&self, v: f64, toward_zero: bool) -> f64 {
        if toward_zero {
            return v.trunc();
        }
        match (self.fpscr >> 22) & 3 {
            0 => v.round_ties_even(),
            1 => v.ceil(),
            2 => v.floor(),
            _ => v.trunc(),
        }
    }

    pub(super) fn vfp_op(&mut self, ins: u32) -> Res {
        let double = bit(ins, 8) != 0;
        if bit(ins, 4) == 0 {
            return self.vfp_data_processing(ins, double);
        }
        // Register transfers
        let rt = bits(ins, 15, 12);
        let load = bit(ins, 20) != 0;
        if ins & 0x0FE00F7F == 0x0E000A10 {
            // VMOV core <-> single
            let sn = reg(ins, 16, 7, false);
            if load {
                let v = self.ext[sn as usize];
                self.set(rt, v);
            } else {
                self.ext[sn as usize] = self.get(rt);
            }
            return Ok(());
        }
        if ins & 0x0F900F7F == 0x0E000B10 {
            // VMOV core <-> scalar (half of a double)
            let dn = reg(ins, 16, 7, true);
            let idx = (dn * 2 + bit(ins, 21)) as usize;
            if load {
                let v = self.ext[idx];
                self.set(rt, v);
            } else {
                self.ext[idx] = self.get(rt);
            }
            return Ok(());
        }
        if ins & 0x0FE00FFF == 0x0EE00A10 {
            // VMRS / VMSR
            let sysreg = bits(ins, 19, 16);
            if load {
                let v = match sysreg {
                    0 => 0x41011090, // FPSID: VFP11 (ARM1176)
                    1 => self.fpscr,
                    8 => 0x40000000, // FPEXC: enabled
                    _ => 0,
                };
                if rt == 15 {
                    let cpsr = (self.cpsr() & 0x0fffffff) | (self.fpscr & 0xf0000000);
                    self.set_cpsr(cpsr);
                } else {
                    self.set(rt, v);
                }
            } else if sysreg == 1 {
                self.fpscr = self.get(rt);
            }
            return Ok(());
        }
        Err(Exit::Undefined)
    }

    fn vfp_data_processing(&mut self, ins: u32, double: bool) -> Res {
        let pqrs = bit(ins, 23) << 3 | bits(ins, 21, 20) << 1 | bit(ins, 6);
        let vd = reg(ins, 12, 22, double);
        let vn = reg(ins, 16, 7, double);
        let vm = reg(ins, 0, 5, double);
        let rd = |t: &Self, i: u32| if double { t.d(i) } else { t.s(i) as f64 };
        let wr = |t: &mut Self, i: u32, v: f64| {
            if double {
                t.set_d(i, v)
            } else {
                t.set_s(i, v as f32)
            }
        };
        // Do single-precision arithmetic in f32 to get correct rounding.
        macro_rules! arith {
            (|$n:ident, $m:ident| $e:expr) => {{
                if double {
                    let ($n, $m) = (self.d(vn), self.d(vm));
                    let r = $e;
                    self.set_d(vd, r);
                } else {
                    let ($n, $m) = (self.s(vn), self.s(vm));
                    let r = $e;
                    self.set_s(vd, r);
                }
            }};
        }
        macro_rules! mac {
            ($negprod:expr, $negacc:expr) => {{
                if double {
                    let p = self.d(vn) * self.d(vm);
                    let p = if $negprod { -p } else { p };
                    let a = self.d(vd);
                    let a = if $negacc { -a } else { a };
                    self.set_d(vd, a + p);
                } else {
                    let p = self.s(vn) * self.s(vm);
                    let p = if $negprod { -p } else { p };
                    let a = self.s(vd);
                    let a = if $negacc { -a } else { a };
                    self.set_s(vd, a + p);
                }
            }};
        }
        match pqrs {
            0 => mac!(false, false), // VMLA
            1 => mac!(true, false),  // VMLS
            2 => mac!(false, true),  // VNMLS
            3 => mac!(true, true),   // VNMLA
            4 => arith!(|n, m| n * m),
            5 => arith!(|n, m| -(n * m)),
            6 => arith!(|n, m| n + m),
            7 => arith!(|n, m| n - m),
            8 => arith!(|n, m| n / m),
            14 => {
                // VMOV immediate (VFPv3)
                let imm8 = bits(ins, 19, 16) << 4 | bits(ins, 3, 0);
                let sign = imm8 >> 7;
                let b6 = (imm8 >> 6) & 1;
                let low = imm8 & 0x3f;
                if double {
                    let exp_hi: u64 = if b6 != 0 { 0x3fc } else { 0x400 };
                    let bits = (sign as u64) << 63 | exp_hi << 52 | (low as u64) << 46;
                    self.set_d(vd, f64::from_bits(bits));
                } else {
                    let exp_hi: u32 = if b6 != 0 { 0x1f } else { 0x20 };
                    let bits = sign << 31 | exp_hi << 25 | low << 19;
                    self.set_s(vd, f32::from_bits(bits));
                }
            }
            15 => {
                let op = bits(ins, 19, 16) << 1 | bit(ins, 7);
                match op {
                    0 => {
                        if double {
                            let v = self.d(vm);
                            self.set_d(vd, v)
                        } else {
                            self.ext[vd as usize] = self.ext[vm as usize]
                        }
                    }
                    1 => {
                        let v = rd(self, vm).abs();
                        wr(self, vd, v)
                    }
                    2 => {
                        let v = -rd(self, vm);
                        wr(self, vd, v)
                    }
                    3 => {
                        if double {
                            let v = self.d(vm).sqrt();
                            self.set_d(vd, v)
                        } else {
                            let v = self.s(vm).sqrt();
                            self.set_s(vd, v)
                        }
                    }
                    8 | 9 => {
                        let (a, b) = (rd(self, vd), rd(self, vm));
                        self.fp_compare(a, b)
                    }
                    10 | 11 => {
                        let a = rd(self, vd);
                        self.fp_compare(a, 0.0)
                    }
                    15 => {
                        // VCVT between single and double
                        if double {
                            let sd = reg(ins, 12, 22, false);
                            let v = self.d(vm) as f32;
                            self.set_s(sd, v);
                        } else {
                            let dd = reg(ins, 12, 22, true);
                            let v = self.s(reg(ins, 0, 5, false)) as f64;
                            self.set_d(dd, v);
                        }
                    }
                    16 | 17 => {
                        // VCVT int -> float; the source is always a single reg
                        let sm = reg(ins, 0, 5, false);
                        let raw = self.ext[sm as usize];
                        let v = if op == 17 {
                            raw as i32 as f64
                        } else {
                            raw as f64
                        };
                        wr(self, vd, v)
                    }
                    24..=27 => {
                        // VCVT float -> int; the destination is always single
                        let sd = reg(ins, 12, 22, false);
                        let v = self.round_to_int(rd(self, vm), op & 1 != 0);
                        let r = if op >= 26 { v as i32 as u32 } else { v as u32 };
                        self.ext[sd as usize] = r;
                    }
                    _ => return Err(Exit::Undefined),
                }
            }
            _ => return Err(Exit::Undefined),
        }
        Ok(())
    }

    pub(super) fn vfp_load_store(&mut self, mem: &mut Mem, ins: u32) -> Res {
        let double = bit(ins, 8) != 0;
        if ins & 0x0FE00E00 == 0x0C400A00 {
            // VMOV two core registers <-> two singles / one double
            let rt = bits(ins, 15, 12);
            let rt2 = bits(ins, 19, 16);
            let idx = if double {
                reg(ins, 0, 5, true) * 2
            } else {
                reg(ins, 0, 5, false)
            } as usize;
            if bit(ins, 20) != 0 {
                let (a, b) = (self.ext[idx], self.ext[idx + 1]);
                self.set(rt, a);
                self.set(rt2, b);
            } else {
                self.ext[idx] = self.get(rt);
                self.ext[idx + 1] = self.get(rt2);
            }
            return Ok(());
        }
        let p = bit(ins, 24) != 0;
        let u = bit(ins, 23) != 0;
        let w = bit(ins, 21) != 0;
        let load = bit(ins, 20) != 0;
        let rn = bits(ins, 19, 16);
        let imm8 = bits(ins, 7, 0);
        let vd = reg(ins, 12, 22, double);
        let base = if rn == 15 {
            self.pc_read & !3
        } else {
            self.get(rn)
        };
        let first = if double { vd * 2 } else { vd } as usize;
        if p && !w {
            // VLDR / VSTR
            let addr = if u {
                base.wrapping_add(imm8 << 2)
            } else {
                base.wrapping_sub(imm8 << 2)
            };
            let words = if double { 2 } else { 1 };
            for i in 0..words {
                let a = addr.wrapping_add(i as u32 * 4);
                if load {
                    self.ext[first + i] = self.read32(mem, a)?;
                } else {
                    self.write32(mem, a, self.ext[first + i])?;
                }
            }
            return Ok(());
        }
        // VLDM / VSTM (IA, or DB with writeback)
        if p == u {
            return Err(Exit::Undefined);
        }
        let words = if double { imm8 & !1 } else { imm8 } as usize;
        let mut addr = if u {
            base
        } else {
            base.wrapping_sub(imm8 << 2)
        };
        for i in 0..words {
            if first + i >= 64 {
                break;
            }
            if load {
                self.ext[first + i] = self.read32(mem, addr)?;
            } else {
                self.write32(mem, addr, self.ext[first + i])?;
            }
            addr = addr.wrapping_add(4);
        }
        if w {
            let nb = if u {
                base.wrapping_add(imm8 << 2)
            } else {
                base.wrapping_sub(imm8 << 2)
            };
            self.set(rn, nb);
        }
        Ok(())
    }
}
