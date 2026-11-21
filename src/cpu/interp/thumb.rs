/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Thumb (T16) instruction set, plus the 32-bit BL/BLX pair.

use super::arm::{rev16, revsh};
use super::{add_with_carry, shift_c, shift_imm_c, Exit, Interp, Res};
use crate::mem::Mem;

impl Interp {
    pub(super) fn exec_thumb(&mut self, mem: &mut Mem, ins: u16) -> Res {
        let ins = ins as u32;
        let lo3 = |s: u32| (ins >> s) & 7;
        match ins >> 12 {
            0 | 1 => {
                let rd = lo3(0);
                let rs = self.regs[lo3(3) as usize];
                let op = (ins >> 11) & 3;
                if op == 3 {
                    let operand = if ins & (1 << 10) != 0 {
                        lo3(6)
                    } else {
                        self.regs[lo3(6) as usize]
                    };
                    let (r, c, v) = if ins & (1 << 9) != 0 {
                        add_with_carry(rs, !operand, true)
                    } else {
                        add_with_carry(rs, operand, false)
                    };
                    self.set_nz(r);
                    self.c = c;
                    self.v = v;
                    self.regs[rd as usize] = r;
                } else {
                    let (r, c) = shift_imm_c(rs, op, (ins >> 6) & 31, self.c);
                    self.set_nz(r);
                    self.c = c;
                    self.regs[rd as usize] = r;
                }
                Ok(())
            }
            2 | 3 => {
                let rd = lo3(8);
                let imm = ins & 0xff;
                let a = self.regs[rd as usize];
                let opc = match (ins >> 11) & 3 {
                    0 => 13, // MOV
                    1 => 10, // CMP
                    2 => 4,  // ADD
                    _ => 2,  // SUB
                };
                let c = self.c;
                let (r, write) = self.alu(opc, true, a, imm, c);
                if write {
                    self.regs[rd as usize] = r;
                }
                Ok(())
            }
            4 => {
                if ins & 0x0800 != 0 {
                    // LDR (PC-relative)
                    let addr = (self.pc_read & !3).wrapping_add((ins & 0xff) << 2);
                    let v = self.read32(mem, addr)?;
                    self.regs[lo3(8) as usize] = v;
                    Ok(())
                } else if ins & 0x0400 != 0 {
                    self.thumb_hi_reg(ins)
                } else {
                    self.thumb_alu(ins)
                }
            }
            5 => {
                let rd = lo3(0);
                let addr = self.regs[lo3(3) as usize].wrapping_add(self.regs[lo3(6) as usize]);
                let v = self.regs[rd as usize];
                match (ins >> 9) & 7 {
                    0 => self.write32(mem, addr, v)?,
                    1 => self.write16(mem, addr, v)?,
                    2 => self.write8(mem, addr, v)?,
                    3 => self.regs[rd as usize] = self.read8(mem, addr)? as u8 as i8 as u32,
                    4 => self.regs[rd as usize] = self.read32(mem, addr)?,
                    5 => self.regs[rd as usize] = self.read16(mem, addr)?,
                    6 => self.regs[rd as usize] = self.read8(mem, addr)?,
                    _ => self.regs[rd as usize] = self.read16(mem, addr)? as u16 as i16 as u32,
                }
                Ok(())
            }
            6..=8 => {
                let rd = lo3(0);
                let base = self.regs[lo3(3) as usize];
                let imm = (ins >> 6) & 31;
                let load = ins & 0x0800 != 0;
                let (addr, size) = match ins >> 12 {
                    6 => (base.wrapping_add(imm << 2), 4),
                    7 => (base.wrapping_add(imm), 1),
                    _ => (base.wrapping_add(imm << 1), 2),
                };
                if load {
                    self.regs[rd as usize] = match size {
                        4 => self.read32(mem, addr)?,
                        2 => self.read16(mem, addr)?,
                        _ => self.read8(mem, addr)?,
                    };
                } else {
                    let v = self.regs[rd as usize];
                    match size {
                        4 => self.write32(mem, addr, v)?,
                        2 => self.write16(mem, addr, v)?,
                        _ => self.write8(mem, addr, v)?,
                    }
                }
                Ok(())
            }
            9 => {
                let rd = lo3(8) as usize;
                let addr = self.regs[13].wrapping_add((ins & 0xff) << 2);
                if ins & 0x0800 != 0 {
                    self.regs[rd] = self.read32(mem, addr)?;
                } else {
                    let v = self.regs[rd];
                    self.write32(mem, addr, v)?;
                }
                Ok(())
            }
            10 => {
                let base = if ins & 0x0800 != 0 {
                    self.regs[13]
                } else {
                    self.pc_read & !3
                };
                self.regs[lo3(8) as usize] = base.wrapping_add((ins & 0xff) << 2);
                Ok(())
            }
            11 => self.thumb_misc(mem, ins),
            12 => {
                let rn = lo3(8);
                let list = ins & 0xff;
                let load = ins & 0x0800 != 0;
                // LDMIA writes back only if the base is not in the list.
                let wb = !load || list & (1 << rn) == 0;
                self.block_transfer(mem, rn, list, false, true, wb, load)
            }
            13 => {
                let cond = (ins >> 8) & 0xf;
                match cond {
                    0xe => Err(Exit::Undefined),
                    0xf => Err(Exit::Svc(ins & 0xff)),
                    _ => {
                        if self.cond(cond) {
                            let off = ((ins << 24) as i32 >> 23) as u32;
                            let t = self.pc_read.wrapping_add(off);
                            self.branch_to(t);
                        }
                        Ok(())
                    }
                }
            }
            14 => {
                // B (unconditional); 0b11101 is handled as 32-bit.
                let off = ((ins << 21) as i32 >> 20) as u32;
                let t = self.pc_read.wrapping_add(off);
                self.branch_to(t);
                Ok(())
            }
            _ => Err(Exit::Undefined),
        }
    }

    fn thumb_alu(&mut self, ins: u32) -> Res {
        let rd = (ins & 7) as usize;
        let rm = self.regs[((ins >> 3) & 7) as usize];
        let a = self.regs[rd];
        let c = self.c;
        let r = match (ins >> 6) & 0xf {
            0 => self.alu(0, true, a, rm, c),
            1 => self.alu(1, true, a, rm, c),
            op @ 2..=4 | op @ 7 => {
                let ty = match op {
                    2 => 0,
                    3 => 1,
                    4 => 2,
                    _ => 3,
                };
                let (r, c) = shift_c(a, ty, rm & 0xff, self.c);
                self.set_nz(r);
                self.c = c;
                (r, true)
            }
            5 => self.alu(5, true, a, rm, c),
            6 => self.alu(6, true, a, rm, c),
            8 => self.alu(8, true, a, rm, c),
            9 => self.alu(3, true, rm, 0, c), // NEG = RSB #0
            10 => self.alu(10, true, a, rm, c),
            11 => self.alu(11, true, a, rm, c),
            12 => self.alu(12, true, a, rm, c),
            13 => {
                let r = a.wrapping_mul(rm);
                self.set_nz(r);
                (r, true)
            }
            14 => self.alu(14, true, a, rm, c),
            _ => self.alu(15, true, a, rm, c),
        };
        if r.1 {
            self.regs[rd] = r.0;
        }
        Ok(())
    }

    fn thumb_hi_reg(&mut self, ins: u32) -> Res {
        let rd = (ins & 7) | ((ins >> 4) & 8);
        let rm_idx = (ins >> 3) & 0xf;
        let rm = self.get(rm_idx);
        match (ins >> 8) & 3 {
            0 => {
                let r = self.get(rd).wrapping_add(rm);
                self.set(rd, r);
            }
            1 => {
                let a = self.get(rd);
                let (r, c, v) = add_with_carry(a, !rm, true);
                self.set_nz(r);
                self.c = c;
                self.v = v;
            }
            2 => self.set(rd, rm),
            _ => {
                if ins & 0x80 != 0 {
                    self.regs[14] = self.regs[15].wrapping_add(2) | 1;
                }
                self.bx(rm);
            }
        }
        Ok(())
    }

    fn thumb_misc(&mut self, mem: &mut Mem, ins: u32) -> Res {
        let rd = (ins & 7) as usize;
        let rm = self.regs[((ins >> 3) & 7) as usize];
        match (ins >> 8) & 0xf {
            0 => {
                let imm = (ins & 0x7f) << 2;
                self.regs[13] = if ins & 0x80 != 0 {
                    self.regs[13].wrapping_sub(imm)
                } else {
                    self.regs[13].wrapping_add(imm)
                };
                Ok(())
            }
            2 => {
                self.regs[rd] = match (ins >> 6) & 3 {
                    0 => rm as u16 as i16 as u32,
                    1 => rm as u8 as i8 as u32,
                    2 => rm & 0xffff,
                    _ => rm & 0xff,
                };
                Ok(())
            }
            4 | 5 => {
                // PUSH
                let list = (ins & 0xff) | ((ins & 0x100) << 6);
                self.block_transfer(mem, 13, list, true, false, true, false)
            }
            6 => Ok(()), // SETEND / CPS
            0xa => {
                self.regs[rd] = match (ins >> 6) & 3 {
                    0 => rm.swap_bytes(),
                    1 => rev16(rm),
                    3 => revsh(rm),
                    _ => return Err(Exit::Undefined),
                };
                Ok(())
            }
            0xc | 0xd => {
                // POP
                let list = (ins & 0xff) | ((ins & 0x100) << 7);
                self.block_transfer(mem, 13, list, false, true, true, true)
            }
            0xe => Err(Exit::Breakpoint),
            0xf if ins & 0xf == 0 => Ok(()), // NOP-compatible hints
            _ => Err(Exit::Undefined),
        }
    }

    pub(super) fn exec_thumb32(&mut self, _mem: &mut Mem, ins: u32) -> Res {
        let hw1 = ins >> 16;
        let hw2 = ins & 0xffff;
        // BL / BLX (immediate)
        if hw1 >> 11 == 0b11110 && (hw2 >> 14) == 0b11 && (hw2 & 0x1000 != 0 || hw2 & 1 == 0) {
            let s = (hw1 >> 10) & 1;
            let j1 = (hw2 >> 13) & 1;
            let j2 = (hw2 >> 11) & 1;
            let i1 = !(j1 ^ s) & 1;
            let i2 = !(j2 ^ s) & 1;
            let imm =
                (s << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3ff) << 12) | ((hw2 & 0x7ff) << 1);
            let off = ((imm << 7) as i32 >> 7) as u32;
            self.regs[14] = self.regs[15].wrapping_add(4) | 1;
            let target = self.pc_read.wrapping_add(off);
            if hw2 & 0x1000 == 0 {
                self.thumb = false;
                self.branch_to(target & !3);
            } else {
                self.branch_to(target);
            }
            return Ok(());
        }
        Err(Exit::Undefined)
    }
}
