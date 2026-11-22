/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use crate::mem::Mem;

#[derive(Clone, Copy)]
pub(super) enum Value {
    Reg(u32),
    Imm(u32),
    // ARM immediate shifter encoding (including the special zero cases).
    Shift(u32, u32, u32),
}

impl Value {
    fn reg(reg: u32, pc_read: u32) -> Self {
        if reg == 15 {
            Self::Imm(pc_read)
        } else {
            Self::Reg(reg)
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum Alu {
    And,
    Xor,
    Sub,
    Add,
    Adc,
    Sbc,
    Or,
    Mov,
    Bic,
    Not,
    Mul,
}

#[derive(Clone, Copy)]
pub(super) enum Width {
    Byte,
    Half,
    Word,
    SignedByte,
    SignedHalf,
}

#[derive(Clone, Copy)]
pub(super) enum Mode {
    Same,
    Arm,
    Thumb,
    Exchange,
}

#[derive(Clone, Copy)]
pub(super) enum Op {
    Alu {
        op: Alu,
        dst: Option<u32>,
        lhs: Value,
        rhs: Value,
        flags: bool,
        carry: Option<bool>,
    },
    Transfer {
        load: bool,
        width: Width,
        data: Value,
        base: Value,
        offset: Value,
        subtract: bool,
        pre: bool,
        wb: Option<u32>,
    },
    Multiple {
        load: bool,
        base: u32,
        regs: u32,
        up: bool,
        pre: bool,
        wb: bool,
    },
    Branch {
        target: Value,
        mode: Mode,
        link: Option<u32>,
    },
}

impl Op {
    pub(super) fn branches(self) -> bool {
        match self {
            Self::Alu { .. } => false,
            Self::Transfer { load, data, .. } => load && matches!(data, Value::Reg(15)),
            Self::Multiple { load, regs, .. } => load && regs & (1 << 15) != 0,
            Self::Branch { .. } => true,
        }
    }
}

pub(super) struct Instruction {
    pub(super) cond: u32,
    pub(super) op: Op,
}

pub(super) fn fetch(mem: &Mem, pc: u32, thumb: bool) -> Option<([u8; 4], usize, Instruction)> {
    if !thumb {
        let bytes = mem.cpu_read::<4>(pc)?;
        let ins = decode_arm(u32::from_le_bytes(bytes), pc)?;
        return Some((bytes, 4, ins));
    }
    let hi = mem.cpu_read::<2>(pc)?;
    let ins = u16::from_le_bytes(hi) as u32;
    if ins >> 11 >= 0b11101 {
        let lo = mem.cpu_read::<2>(pc.wrapping_add(2))?;
        let op = decode_thumb_call(ins, u16::from_le_bytes(lo) as u32, pc)?;
        Some(([hi[0], hi[1], lo[0], lo[1]], 4, op))
    } else {
        Some(([hi[0], hi[1], 0, 0], 2, decode_thumb(ins, pc)?))
    }
}

fn alu(code: u32, dst: u32, mut lhs: Value, mut rhs: Value, set: bool, carry: Option<bool>) -> Op {
    use Alu::*;
    let op = match code {
        0 | 8 => And,
        1 | 9 => Xor,
        2 | 10 => Sub,
        3 => {
            std::mem::swap(&mut lhs, &mut rhs);
            Sub
        }
        4 | 11 => Add,
        5 => Adc,
        6 => Sbc,
        7 => {
            std::mem::swap(&mut lhs, &mut rhs);
            Sbc
        }
        12 => Or,
        13 => Mov,
        14 => Bic,
        15 => Not,
        _ => unreachable!(),
    };
    let test = (8..=11).contains(&code);
    Op::Alu {
        op,
        dst: (!test).then_some(dst),
        lhs,
        rhs,
        flags: set || test,
        carry,
    }
}

fn bit(word: u32, index: u32) -> bool {
    word & (1 << index) != 0
}

fn decode_arm(word: u32, pc: u32) -> Option<Instruction> {
    use Value::{Imm, Reg, Shift};
    let read = pc.wrapping_add(8);
    let cond = word >> 28;
    let class = word >> 25 & 7;
    let rn = word >> 16 & 15;
    let rd = word >> 12 & 15;
    let rm = word & 15;
    let shift_ty = word >> 5 & 3;
    let shift_amt = word >> 7 & 31;
    let op = if class == 5 {
        let off = ((word << 8) as i32 >> 6) as u32;
        let off = off | if cond == 15 { (word >> 23) & 2 } else { 0 };
        Op::Branch {
            target: Imm(read.wrapping_add(off)),
            mode: if cond == 15 { Mode::Thumb } else { Mode::Same },
            link: (cond == 15 || bit(word, 24)).then_some(pc.wrapping_add(4)),
        }
    } else if cond == 15 {
        return None;
    } else if matches!(word & 0x0fff_fff0, 0x012f_ff10 | 0x012f_ff30) {
        Op::Branch {
            target: Value::reg(rm, read),
            mode: Mode::Exchange,
            link: bit(word, 5).then_some(pc.wrapping_add(4)),
        }
    } else if class == 0 && word & 0x90 == 0x90 {
        let op = word >> 5 & 3;
        if op == 0 && word & 0x01e0_0000 == 0 && rn != 15 {
            Op::Alu {
                op: Alu::Mul,
                dst: Some(rn),
                lhs: Value::reg(rm, read),
                rhs: Value::reg(word >> 8 & 15, read),
                flags: bit(word, 20),
                carry: None,
            }
        } else {
            let pre = bit(word, 24);
            let wb = !pre || bit(word, 21);
            let load = bit(word, 20);
            let width = match (op, load) {
                (1, _) => Width::Half,
                (2, true) => Width::SignedByte,
                (3, true) => Width::SignedHalf,
                _ => return None,
            };
            if (wb && rn == 15) || (load && rd == 15) {
                return None;
            }
            Op::Transfer {
                load,
                width,
                data: if load { Reg(rd) } else { Value::reg(rd, read) },
                base: Value::reg(rn, read),
                offset: if bit(word, 22) {
                    Imm((word >> 4 & 0xf0) | rm)
                } else {
                    Value::reg(rm, read)
                },
                subtract: !bit(word, 23),
                pre,
                wb: wb.then_some(rn),
            }
        }
    } else if class <= 1 && word & 0x0190_0000 != 0x0100_0000 && (class == 1 || !bit(word, 4)) {
        let code = word >> 21 & 15;
        if rd == 15 && !(8..=11).contains(&code) {
            return None;
        }
        let (rhs, carry) = if class == 1 {
            let rot = (word >> 8 & 15) * 2;
            let imm = (word & 255).rotate_right(rot);
            (Imm(imm), (rot != 0).then_some(bit(imm, 31)))
        } else if rm == 15 {
            let (val, carry) = super::super::shift_imm_c(read, shift_ty, shift_amt, false);
            if shift_ty == 3 && shift_amt == 0 {
                return None;
            }
            (Imm(val), (shift_ty != 0 || shift_amt != 0).then_some(carry))
        } else {
            (Shift(rm, shift_ty, shift_amt), None)
        };
        alu(code, rd, Value::reg(rn, read), rhs, bit(word, 20), carry)
    } else if class == 2 || (class == 3 && !bit(word, 4)) {
        let pre = bit(word, 24);
        let wb = !pre || bit(word, 21);
        if wb && rn == 15 {
            return None;
        }
        let offset = if class == 2 {
            Imm(word & 0xfff)
        } else if rm != 15 {
            Shift(rm, shift_ty, shift_amt)
        } else {
            return None;
        };
        let load = bit(word, 20);
        Op::Transfer {
            load,
            width: if bit(word, 22) {
                Width::Byte
            } else {
                Width::Word
            },
            data: if load { Reg(rd) } else { Value::reg(rd, read) },
            base: Value::reg(rn, read),
            offset,
            subtract: !bit(word, 23),
            pre,
            wb: wb.then_some(rn),
        }
    } else if class == 4 && rn != 15 {
        Op::Multiple {
            load: bit(word, 20),
            base: rn,
            regs: word & 0xffff,
            up: bit(word, 23),
            pre: bit(word, 24),
            wb: bit(word, 21),
        }
    } else {
        return None;
    };
    Some(Instruction {
        cond: cond.min(14),
        op,
    })
}

fn decode_thumb(word: u32, pc: u32) -> Option<Instruction> {
    use Value::{Imm, Reg, Shift};
    let read = pc.wrapping_add(4);
    let rd = word & 7;
    let rm = word >> 3 & 7;
    let imm5 = word >> 6 & 31;
    let imm8 = word & 255;
    let high = word >> 8 & 7;
    let memory = |load, width, reg, base, offset| Op::Transfer {
        load,
        width,
        data: Reg(reg),
        base,
        offset,
        subtract: false,
        pre: true,
        wb: None,
    };
    let mut cond = 14;
    let op = match word >> 12 {
        0 | 1 if word >> 11 & 3 != 3 => {
            alu(13, rd, Imm(0), Shift(rm, word >> 11 & 3, imm5), true, None)
        }
        1 => alu(
            if bit(word, 9) { 2 } else { 4 },
            rd,
            Reg(rm),
            if bit(word, 10) {
                Imm(imm5 & 7)
            } else {
                Reg(imm5 & 7)
            },
            true,
            None,
        ),
        2 | 3 => {
            let code = [13, 10, 4, 2][(word >> 11 & 3) as usize];
            alu(code, high, Reg(high), Imm(imm8), true, None)
        }
        4 if bit(word, 11) => memory(true, Width::Word, high, Imm(read & !3), Imm(imm8 << 2)),
        4 if bit(word, 10) => {
            let dst = rd | (word >> 4 & 8);
            let source = Value::reg(word >> 3 & 15, read);
            let code = word >> 8 & 3;
            match code {
                3 => Op::Branch {
                    target: source,
                    mode: Mode::Exchange,
                    link: bit(word, 7).then_some(pc.wrapping_add(2) | 1),
                },
                1 => alu(10, dst, Value::reg(dst, read), source, true, None),
                _ if dst != 15 => alu(
                    if code == 0 { 4 } else { 13 },
                    dst,
                    Reg(dst),
                    source,
                    false,
                    None,
                ),
                _ => return None,
            }
        }
        4 => {
            let code = match word >> 6 & 15 {
                code @ (0 | 1 | 5 | 6 | 8 | 10 | 11) => code,
                9 => {
                    return Some(Instruction {
                        cond,
                        op: alu(3, rd, Reg(rm), Imm(0), true, None),
                    })
                }
                12 => 12,
                13 => {
                    return Some(Instruction {
                        cond,
                        op: Op::Alu {
                            op: Alu::Mul,
                            dst: Some(rd),
                            lhs: Reg(rd),
                            rhs: Reg(rm),
                            flags: true,
                            carry: None,
                        },
                    })
                }
                code @ (14 | 15) => code,
                _ => return None,
            };
            alu(code, rd, Reg(rd), Reg(rm), true, None)
        }
        5 => {
            let op = word >> 9 & 7;
            let width = [
                Width::Word,
                Width::Half,
                Width::Byte,
                Width::SignedByte,
                Width::Word,
                Width::Half,
                Width::Byte,
                Width::SignedHalf,
            ][op as usize];
            memory(op >= 3, width, rd, Reg(rm), Reg(imm5 & 7))
        }
        6..=8 => {
            let (width, shift) = match word >> 12 {
                6 => (Width::Word, 2),
                7 => (Width::Byte, 0),
                _ => (Width::Half, 1),
            };
            memory(bit(word, 11), width, rd, Reg(rm), Imm(imm5 << shift))
        }
        9 => memory(bit(word, 11), Width::Word, high, Reg(13), Imm(imm8 << 2)),
        10 => alu(
            4,
            high,
            if bit(word, 11) {
                Reg(13)
            } else {
                Imm(read & !3)
            },
            Imm(imm8 << 2),
            false,
            None,
        ),
        11 if word >> 8 == 0xb0 => alu(
            if bit(word, 7) { 2 } else { 4 },
            13,
            Reg(13),
            Imm((word & 127) << 2),
            false,
            None,
        ),
        11 if matches!(word & 0xfe00, 0xb400 | 0xbc00) => {
            let load = bit(word, 11);
            let extra = if load { 15 } else { 14 };
            Op::Multiple {
                load,
                base: 13,
                regs: imm8 | (((word >> 8) & 1) << extra),
                up: load,
                pre: !load,
                wb: true,
            }
        }
        12 => Op::Multiple {
            load: bit(word, 11),
            base: high,
            regs: imm8,
            up: true,
            pre: false,
            wb: true,
        },
        13 if word >> 8 & 15 < 14 => {
            cond = word >> 8 & 15;
            Op::Branch {
                target: Imm(read.wrapping_add(((word << 24) as i32 >> 23) as u32)),
                mode: Mode::Same,
                link: None,
            }
        }
        14 => Op::Branch {
            target: Imm(read.wrapping_add(((word << 21) as i32 >> 20) as u32)),
            mode: Mode::Same,
            link: None,
        },
        _ => return None,
    };
    Some(Instruction { cond, op })
}

fn decode_thumb_call(hi: u32, lo: u32, pc: u32) -> Option<Instruction> {
    if hi >> 11 != 0b11110 || lo >> 14 != 0b11 || (lo & 0x1000 == 0 && lo & 1 != 0) {
        return None;
    }
    let s = hi >> 10 & 1;
    let i1 = !((lo >> 13) ^ s) & 1;
    let i2 = !((lo >> 11) ^ s) & 1;
    let imm = (s << 24) | (i1 << 23) | (i2 << 22) | ((hi & 0x3ff) << 12) | ((lo & 0x7ff) << 1);
    Some(Instruction {
        cond: 14,
        op: Op::Branch {
            target: Value::Imm(
                pc.wrapping_add(4)
                    .wrapping_add(((imm << 7) as i32 >> 7) as u32),
            ),
            mode: if lo & 0x1000 == 0 {
                Mode::Arm
            } else {
                Mode::Same
            },
            link: Some(pc.wrapping_add(4) | 1),
        },
    })
}
