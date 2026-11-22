/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use super::super::Interp;
use super::decode::{Alu, Instruction, Mode, Op, Value, Width};
use super::MASK;
use std::mem::offset_of;
use wasm_encoder::Instruction::*;
use wasm_encoder::{
    BlockType, CodeSection, EntityType, ExportKind, ExportSection, Function, FunctionSection,
    ImportSection, Instruction as Wasm, MemArg, MemoryType, Module, TypeSection, ValType,
};

// The module imports only linear memory. It must not call into JS or Rust,
// yield, or keep any pointers between executions.
const CPU: u32 = 0;
const WINDOW: u32 = 1;
const NULL_LIMIT: u32 = 2;
const TICKS: u32 = 3;
const A: u32 = 4;
const B: u32 = 5;
const R: u32 = 6;
const CARRY: u32 = 7;
const INDEX: u32 = 8;
const ADDR: u32 = 9;
const UPDATED: u32 = 10;
const SPENT: u32 = 11;

const N: usize = offset_of!(Interp, n);
const Z: usize = offset_of!(Interp, z);
const C: usize = offset_of!(Interp, c);
const V: usize = offset_of!(Interp, v);
const T: usize = offset_of!(Interp, thumb);

fn memarg(offset: usize, align: u32) -> MemArg {
    MemArg {
        offset: offset as u64,
        align,
        memory_index: 0,
    }
}

fn regarg(reg: u32) -> MemArg {
    memarg(offset_of!(Interp, regs) + reg as usize * 4, 2)
}

pub(super) fn module(start: u32, bytes: &[u8], insns: &[(u32, Instruction)]) -> Vec<u8> {
    use ValType::I32;
    let mut types = TypeSection::new();
    types.ty().function([I32; 4], [I32]);
    let mut imports = ImportSection::new();
    imports.import(
        "env",
        "memory",
        EntityType::Memory(MemoryType {
            minimum: 0,
            maximum: None,
            memory64: false,
            shared: false,
            page_size_log2: None,
        }),
    );
    let mut funcs = FunctionSection::new();
    funcs.function(0);
    let mut exports = ExportSection::new();
    exports.export("run", ExportKind::Func, 0);
    let (end, tail) = insns.last().unwrap();
    let backedge = matches!(
        tail.op,
        Op::Branch { target: Value::Imm(target), mode: Mode::Same, link: None }
        if target == start
    );
    let mut block = Block {
        f: Function::new([(if backedge { 8 } else { 7 }, I32)]),
        start,
        pc: start,
        next: start,
        end: *end,
        count: 0,
        backedge,
    };
    block.guard(start, bytes);
    if backedge {
        block.emit(Loop(BlockType::Empty));
    }
    for (next, insn) in insns {
        block.next = *next;
        block.count += 1;
        let conditional = insn.cond != 14;
        if conditional {
            block.condition(insn.cond);
            block.emit(If(BlockType::Empty));
        }
        block.instruction(insn.op, conditional);
        if conditional {
            block.emit(End);
        }
        block.pc = *next;
    }
    if backedge {
        block.emit(End);
    }
    block.set_pc(*end);
    block.executed(block.count);
    block.emit(End);
    let mut code = CodeSection::new();
    code.function(&block.f);
    let mut module = Module::new();
    module
        .section(&types)
        .section(&imports)
        .section(&funcs)
        .section(&exports)
        .section(&code);
    module.finish()
}

struct Block {
    f: Function,
    start: u32,
    pc: u32,
    next: u32,
    end: u32,
    count: i32,
    backedge: bool,
}

impl Block {
    fn emit(&mut self, ins: Wasm<'_>) {
        self.f.instruction(&ins);
    }

    fn seq(&mut self, insns: impl IntoIterator<Item = Wasm<'static>>) {
        for ins in insns {
            self.emit(ins);
        }
    }

    fn reg(&mut self, r: u32) {
        self.seq([LocalGet(CPU), I32Load(regarg(r))]);
    }

    fn flag(&mut self, offset: usize) {
        self.seq([LocalGet(CPU), I32Load8U(memarg(offset, 0))]);
    }

    fn set_pc(&mut self, pc: u32) {
        self.seq([LocalGet(CPU), I32Const(pc as i32), I32Store(regarg(15))]);
    }

    fn executed(&mut self, count: i32) {
        self.emit(I32Const(count));
        if self.backedge {
            self.seq([LocalGet(SPENT), I32Add]);
        }
    }

    fn guard(&mut self, start: u32, mut bytes: &[u8]) {
        // The whole block is in one guest page. Compare every encoded
        // byte before running, including writes through host-side slices.
        let mut index = (start & MASK) as usize;
        while !bytes.is_empty() {
            self.emit(LocalGet(WINDOW));
            if let Some((word, rest)) = bytes.split_first_chunk::<8>() {
                self.seq([
                    I64Load(memarg(index, 0)),
                    I64Const(i64::from_le_bytes(*word)),
                    I64Ne,
                ]);
                index += 8;
                bytes = rest;
            } else if let Some((word, rest)) = bytes.split_first_chunk::<4>() {
                self.seq([
                    I32Load(memarg(index, 0)),
                    I32Const(i32::from_le_bytes(*word)),
                    I32Ne,
                ]);
                index += 4;
                bytes = rest;
            } else {
                let (word, rest) = bytes.split_first_chunk::<2>().unwrap();
                self.seq([
                    I32Load16U(memarg(index, 0)),
                    I32Const(u16::from_le_bytes(*word) as i32),
                    I32Ne,
                ]);
                index += 2;
                bytes = rest;
            }
            self.seq([If(BlockType::Empty), I32Const(-1), Return, End]);
        }
    }

    fn condition(&mut self, cond: u32) {
        match cond >> 1 {
            0 => self.flag(Z),
            1 => self.flag(C),
            2 => self.flag(N),
            3 => self.flag(V),
            4 => {
                self.flag(C);
                self.flag(Z);
                self.seq([I32Eqz, I32And]);
            }
            5 => {
                self.flag(N);
                self.flag(V);
                self.emit(I32Eq);
            }
            6 => {
                self.flag(N);
                self.flag(V);
                self.emit(I32Eq);
                self.flag(Z);
                self.seq([I32Eqz, I32And]);
            }
            _ => unreachable!(),
        }
        if cond & 1 != 0 {
            self.emit(I32Eqz);
        }
    }

    fn value(&mut self, value: Value) {
        match value {
            Value::Reg(r) => self.reg(r),
            Value::Imm(n) => self.emit(I32Const(n as i32)),
            Value::Shift(r, ty, amount) => match (ty, amount) {
                (0, 0) => self.reg(r),
                (1, 0) => self.emit(I32Const(0)),
                (3, 0) => {
                    self.flag(C);
                    self.seq([I32Const(31), I32Shl]);
                    self.reg(r);
                    self.seq([I32Const(1), I32ShrU, I32Or]);
                }
                _ => {
                    self.reg(r);
                    self.emit(I32Const(if amount == 0 { 31 } else { amount as i32 }));
                    self.emit([I32Shl, I32ShrU, I32ShrS, I32Rotr][ty as usize].clone());
                }
            },
        }
    }

    fn shift_carry(&mut self, rhs: Value, carry: Option<bool>) {
        if let Some(carry) = carry {
            self.seq([
                LocalGet(CPU),
                I32Const(i32::from(carry)),
                I32Store8(memarg(C, 0)),
            ]);
        } else if let Value::Shift(r, ty, amount) = rhs {
            let bit = match (ty, amount) {
                (0, 0) => return,
                (0, _) => 32 - amount,
                (1 | 2, 0) => 31,
                (3, 0) => 0,
                _ => amount - 1,
            };
            self.emit(LocalGet(CPU));
            self.reg(r);
            self.seq([
                I32Const(bit as i32),
                I32ShrU,
                I32Const(1),
                I32And,
                I32Store8(memarg(C, 0)),
            ]);
        }
    }

    fn alu(
        &mut self,
        op: Alu,
        dst: Option<u32>,
        lhs: Value,
        rhs: Value,
        flags: bool,
        carry: Option<bool>,
    ) {
        use Alu::*;
        let arithmetic = matches!(op, Add | Adc | Sub | Sbc);
        let with_carry = matches!(op, Adc | Sbc);
        // Save the original operands if needed for the status flags.
        if let Some(rd) = dst {
            self.emit(LocalGet(CPU));
            debug_assert!(rd < 15);
        }
        if !matches!(op, Mov | Not) {
            self.value(lhs);
            if flags && arithmetic {
                self.emit(LocalTee(A));
            }
        }
        self.value(rhs);
        if flags && arithmetic {
            self.emit(LocalTee(B));
        }
        if with_carry {
            self.flag(C);
            if flags {
                self.emit(LocalTee(CARRY));
            }
            if matches!(op, Sbc) {
                self.emit(I32Eqz);
            }
            self.emit(I32Add);
        }
        if matches!(op, Bic | Not) {
            self.seq([I32Const(-1), I32Xor]);
        }
        match op {
            And | Bic => self.emit(I32And),
            Xor => self.emit(I32Xor),
            Sub | Sbc => self.emit(I32Sub),
            Add | Adc => self.emit(I32Add),
            Or => self.emit(I32Or),
            Mul => self.emit(I32Mul),
            Mov | Not => {}
        }
        if flags {
            self.emit(if dst.is_some() {
                LocalTee(R)
            } else {
                LocalSet(R)
            });
            // The shifter must still see the source register before writeback.
            if !arithmetic {
                self.shift_carry(rhs, carry);
            }
        }
        if let Some(rd) = dst {
            self.emit(I32Store(regarg(rd)));
        }
        if !flags {
            return;
        }
        self.seq([
            LocalGet(CPU),
            LocalGet(R),
            I32Const(31),
            I32ShrU,
            I32Store8(memarg(N, 0)),
        ]);
        self.seq([LocalGet(CPU), LocalGet(R), I32Eqz, I32Store8(memarg(Z, 0))]);
        if arithmetic {
            let sub = matches!(op, Sub | Sbc);
            self.emit(LocalGet(CPU));
            match op {
                Add => self.seq([LocalGet(R), LocalGet(A), I32LtU]),
                Adc => self.seq([
                    LocalGet(R),
                    LocalGet(A),
                    I32LtU,
                    LocalGet(R),
                    LocalGet(A),
                    I32Eq,
                    LocalGet(CARRY),
                    I32And,
                    I32Or,
                ]),
                Sub => self.seq([LocalGet(A), LocalGet(B), I32GeU]),
                Sbc => self.seq([
                    LocalGet(A),
                    LocalGet(B),
                    I32GtU,
                    LocalGet(A),
                    LocalGet(B),
                    I32Eq,
                    LocalGet(CARRY),
                    I32And,
                    I32Or,
                ]),
                _ => unreachable!(),
            }
            self.emit(I32Store8(memarg(C, 0)));
            self.seq([LocalGet(CPU), LocalGet(A), LocalGet(B), I32Xor]);
            if !sub {
                self.seq([I32Const(-1), I32Xor]);
            }
            self.seq([
                LocalGet(A),
                LocalGet(R),
                I32Xor,
                I32And,
                I32Const(31),
                I32ShrU,
                I32Store8(memarg(V, 0)),
            ]);
        }
    }

    // Bounds check a contiguous guest access or bail before any side effects.
    // A bulk transfer crossing the folded window is left to the interpreter.
    fn address(&mut self, size: u32) {
        self.seq([
            LocalTee(ADDR),
            LocalGet(NULL_LIMIT),
            I32LtU,
            LocalGet(ADDR),
            I32Const(MASK as i32),
            I32And,
            LocalTee(INDEX),
            I32Const((MASK - (size - 1)) as i32),
            I32GtU,
            I32Or,
            If(BlockType::Empty),
        ]);
        self.set_pc(self.pc);
        self.executed(self.count - 1);
        self.seq([Return, End]);
        self.seq([LocalGet(WINDOW), LocalGet(INDEX), I32Add, LocalSet(ADDR)]);
    }

    fn after_store(&mut self, size: u32) {
        if self.end == self.next {
            return;
        }
        // Return before executing any bytes overwritten by a guest store.
        // For a loop, this includes earlier bytes we are about to run again.
        let check_start = if self.backedge { self.start } else { self.next };
        self.seq([
            LocalGet(INDEX),
            I32Const((check_start & MASK) as i32),
            I32Sub,
            I32Const((size - 1) as i32),
            I32Add,
            I32Const((self.end.wrapping_sub(check_start) + size - 1) as i32),
            I32LtU,
            If(BlockType::Empty),
        ]);
        self.set_pc(self.next);
        self.executed(self.count);
        self.seq([Return, End]);
    }

    fn jump(&mut self, mode: Mode, link: Option<u32>) {
        // R already holds the target, even if the link register is the source.
        if let Some(link) = link {
            self.seq([LocalGet(CPU), I32Const(link as i32), I32Store(regarg(14))]);
        }
        match mode {
            Mode::Same => self.seq([LocalGet(CPU), LocalGet(R), I32Store(regarg(15))]),
            Mode::Arm | Mode::Thumb => {
                let thumb = matches!(mode, Mode::Thumb);
                self.seq([
                    LocalGet(CPU),
                    I32Const(i32::from(thumb)),
                    I32Store8(memarg(T, 0)),
                ]);
                self.seq([
                    LocalGet(CPU),
                    LocalGet(R),
                    I32Const(if thumb { -2 } else { -4 }),
                    I32And,
                    I32Store(regarg(15)),
                ]);
            }
            Mode::Exchange => {
                self.seq([
                    LocalGet(CPU),
                    LocalGet(R),
                    I32Const(1),
                    I32And,
                    LocalTee(A),
                    I32Store8(memarg(T, 0)),
                ]);
                self.seq([
                    LocalGet(CPU),
                    LocalGet(R),
                    I32Const(-2),
                    I32Const(-4),
                    LocalGet(A),
                    Select,
                    I32And,
                    I32Store(regarg(15)),
                ]);
            }
        }
        self.executed(self.count);
        self.emit(Return);
    }

    fn instruction(&mut self, op: Op, conditional: bool) {
        use Op::*;
        match op {
            Alu {
                op,
                dst,
                lhs,
                rhs,
                flags,
                carry,
            } => self.alu(op, dst, lhs, rhs, flags, carry),
            Branch { .. } if self.backedge && self.next == self.end => {
                self.executed(self.count);
                self.emit(LocalSet(SPENT));
                self.seq([
                    LocalGet(TICKS),
                    LocalGet(SPENT),
                    I32Sub,
                    I32Const(self.count),
                    I32GeU,
                    BrIf(u32::from(conditional)),
                ]);
                self.set_pc(self.start);
                self.seq([LocalGet(SPENT), Return]);
            }
            Branch { target, mode, link } => {
                self.value(target);
                self.emit(LocalSet(R));
                self.jump(mode, link);
            }
            Transfer {
                load,
                width,
                data,
                base,
                offset,
                subtract,
                pre,
                wb,
            } => {
                let size = match width {
                    Width::Byte | Width::SignedByte => 1,
                    Width::Half | Width::SignedHalf => 2,
                    Width::Word => 4,
                };
                self.value(base);
                if !pre {
                    self.emit(LocalTee(A));
                }
                self.value(offset);
                self.emit(if subtract { I32Sub } else { I32Add });
                if wb.is_some() {
                    self.emit(if pre {
                        LocalTee(UPDATED)
                    } else {
                        LocalSet(UPDATED)
                    });
                }
                if !pre {
                    self.emit(LocalGet(A));
                }
                self.address(size);
                if load {
                    self.emit(LocalGet(ADDR));
                    let arg = memarg(0, 0);
                    self.emit(match width {
                        Width::Byte => I32Load8U(arg),
                        Width::Half => I32Load16U(arg),
                        Width::Word => I32Load(arg),
                        Width::SignedByte => I32Load8S(arg),
                        Width::SignedHalf => I32Load16S(arg),
                    });
                    self.emit(LocalSet(R));
                } else {
                    self.emit(LocalGet(ADDR));
                    self.value(data);
                    let arg = memarg(0, 0);
                    self.emit(match size {
                        1 => I32Store8(arg),
                        2 => I32Store16(arg),
                        _ => I32Store(arg),
                    });
                }
                if let Some(r) = wb {
                    self.seq([LocalGet(CPU), LocalGet(UPDATED), I32Store(regarg(r))]);
                }
                if load {
                    let Value::Reg(r) = data else { unreachable!() };
                    if r == 15 {
                        self.jump(Mode::Exchange, None);
                    } else {
                        self.seq([LocalGet(CPU), LocalGet(R), I32Store(regarg(r))]);
                    }
                } else {
                    self.after_store(size);
                }
            }
            Multiple {
                load,
                base,
                regs,
                up,
                pre,
                wb,
            } => {
                let size = regs.count_ones() * 4;
                if size == 0 {
                    return;
                }
                let delta = if up { size as i32 } else { -(size as i32) };
                let offset = match (pre, up) {
                    (false, true) => 0,
                    (true, true) => 4,
                    (false, false) => delta + 4,
                    (true, false) => delta,
                };
                self.reg(base);
                self.seq([LocalTee(A), I32Const(offset), I32Add]);
                self.address(size);
                let mut offset = 0;
                for r in 0..16 {
                    if regs & (1 << r) == 0 {
                        continue;
                    }
                    let arg = memarg(offset, 0);
                    if load {
                        if r == 15 {
                            self.seq([LocalGet(ADDR), I32Load(arg), LocalSet(R)]);
                        } else {
                            self.seq([
                                LocalGet(CPU),
                                LocalGet(ADDR),
                                I32Load(arg),
                                I32Store(regarg(r)),
                            ]);
                        }
                    } else {
                        self.emit(LocalGet(ADDR));
                        if r == 15 {
                            self.emit(I32Const(self.next.wrapping_add(4) as i32));
                        } else {
                            self.reg(r);
                        }
                        self.emit(I32Store(arg));
                    }
                    offset += 4;
                }
                if wb && (!load || regs & (1 << base) == 0) {
                    self.seq([
                        LocalGet(CPU),
                        LocalGet(A),
                        I32Const(delta),
                        I32Add,
                        I32Store(regarg(base)),
                    ]);
                }
                if load && regs & (1 << 15) != 0 {
                    self.jump(Mode::Exchange, None);
                } else if !load {
                    self.after_store(size);
                }
            }
        }
    }
}
