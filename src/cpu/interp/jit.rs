/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Hot-block translation for the browser. All other instructions, faults,
//! and debugger single steps stay in the interpreter.

mod decode;
#[cfg(test)]
mod tests;
mod wasm;

use super::Interp;
use crate::mem::{Mem, PAGE_SIZE_ALIGN_MASK};
use std::collections::VecDeque;

const HOT: u16 = 2048;
const MAX_INSNS: usize = 32;
pub(super) const SAMPLE_MASK: u32 = 31;
const SLOTS: usize = 1 << 16;
const MAX_ACTIVE: usize = 8192;
const MASK: u32 = Mem::CPU_WINDOW_MASK;

unsafe extern "C" {
    fn touchhle_jit_enabled() -> bool;
    fn touchhle_jit_compile(bytes: *const u8, len: usize) -> usize;
    fn touchhle_jit_release(function: usize);
}

// Emscripten function pointers are Wasm table indices. The JS bridge only
// installs validated functions of this signature. Generated blocks import
// only memory and cannot suspend, so this call need not be Asyncified.
#[inline(never)]
#[unsafe(no_mangle)]
unsafe extern "C" fn touchhle_run_jit_block(
    function: usize,
    cpu: *mut Interp,
    window: *mut u8,
    null_limit: u32,
    ticks: u32,
) -> i32 {
    type Block = unsafe extern "C" fn(*mut Interp, *mut u8, u32, u32) -> i32;
    let run: Block = unsafe { std::mem::transmute(function) };
    unsafe { run(cpu, window, null_limit, ticks) }
}

#[derive(Clone, Copy, Default)]
struct Entry {
    key: u32,
    function: usize,
    hits: u16,
    bytes: u8,
    instructions: u8,
}

impl Entry {
    fn retire(&mut self) {
        let entry = std::mem::take(self);
        if entry.function != 0 {
            unsafe { touchhle_jit_release(entry.function) };
        }
    }
}

pub(super) struct Cache {
    slots: Box<[Entry]>,
    active: VecDeque<usize>,
    enabled: bool,
}

impl Cache {
    pub(super) fn new() -> Self {
        let enabled = unsafe { touchhle_jit_enabled() };
        Self {
            slots: if enabled {
                vec![Entry::default(); SLOTS].into_boxed_slice()
            } else {
                Box::default()
            },
            active: VecDeque::new(),
            enabled,
        }
    }

    #[inline(always)]
    pub(super) fn enabled(&self) -> bool {
        self.enabled
    }

    fn remove(&mut self, index: usize) {
        self.slots[index].retire();
        self.active.retain(|&slot| slot != index);
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        for &index in &self.active {
            self.slots[index].retire();
        }
    }
}

impl Interp {
    pub(crate) fn invalidate_cache_range(&mut self, base: u32, size: u32) {
        if size == 0 {
            return;
        }
        self.jit.active.retain(|&index| {
            let entry = &mut self.jit.slots[index];
            let start = entry.key & !1;
            // Guest addresses alias in the browser's folded memory window.
            if (start.wrapping_sub(base) & MASK) < size
                || (base.wrapping_sub(start) & MASK) < u32::from(entry.bytes)
            {
                entry.retire();
                false
            } else {
                true
            }
        });
    }

    #[inline(always)]
    pub(super) fn run_jit(&mut self, mem: &mut Mem, remaining: u64) -> u32 {
        let pc = self.regs[15];
        if pc & 1 != 0 {
            return 0;
        }
        let key = pc | u32::from(self.thumb);
        let index = ((pc >> 1) ^ (pc >> 16) ^ (u32::from(self.thumb) << 13)) as usize & (SLOTS - 1);
        let entry = &mut self.jit.slots[index];
        if entry.key != key {
            // Don't let cold code displace a live translation on collision.
            if entry.function == 0 {
                *entry = Entry {
                    key,
                    hits: 1,
                    ..Entry::default()
                };
            }
            return 0;
        }
        if entry.function == 0 {
            if entry.hits >= HOT {
                return 0;
            }
            entry.hits += 1;
            if entry.hits != HOT {
                return 0;
            }
            // Execute immediately so each suffix of the newly compiled
            // block doesn't hit the same threshold on this pass.
            self.compile_block(mem, index, pc);
        }
        let entry = self.jit.slots[index];
        if entry.function == 0
            || remaining < u64::from(entry.instructions)
            || pc < mem.null_segment_size()
        {
            return 0;
        }
        let result = unsafe {
            touchhle_run_jit_block(
                entry.function,
                self,
                mem.cpu_window(),
                mem.null_segment_size(),
                remaining.min(i32::MAX as u64) as u32,
            )
        };
        if result < 0 {
            self.jit.remove(index);
            0
        } else {
            result as u32
        }
    }

    #[cold]
    fn compile_block(&mut self, mem: &Mem, index: usize, start: u32) {
        let mut code = Vec::with_capacity(MAX_INSNS * 4);
        let mut insns = Vec::with_capacity(MAX_INSNS);
        let mut pc = start;
        if pc & (if self.thumb { 1 } else { 3 }) != 0 {
            return;
        }
        while insns.len() < MAX_INSNS {
            let Some((bytes, len, insn)) = decode::fetch(mem, pc, self.thumb) else {
                break;
            };
            if (start & PAGE_SIZE_ALIGN_MASK) + code.len() as u32 + len as u32
                > PAGE_SIZE_ALIGN_MASK + 1
            {
                break;
            }
            // A taken branch exits immediately; untaken forward branches
            // can keep executing in this block. Keep backedges as boundaries.
            let fallthrough = matches!(
                insn.op,
                decode::Op::Branch { target: decode::Value::Imm(target), .. }
                if insn.cond != 14 && target.wrapping_sub(pc) as i32 > 0
            );
            let end = insn.op.branches() && !fallthrough;
            pc = pc.wrapping_add(len as u32);
            code.extend_from_slice(&bytes[..len]);
            insns.push((pc, insn));
            if end || pc & PAGE_SIZE_ALIGN_MASK == 0 {
                break;
            }
        }
        if insns.is_empty() {
            return;
        }
        let module = wasm::module(start, &code, &insns);
        let function = unsafe { touchhle_jit_compile(module.as_ptr(), module.len()) };
        if function == 0 {
            self.jit.enabled = false;
        } else {
            if self.jit.active.len() == MAX_ACTIVE {
                let oldest = self.jit.active.pop_front().unwrap();
                self.jit.slots[oldest].retire();
            }
            self.jit.slots[index].function = function;
            self.jit.slots[index].bytes = code.len() as u8;
            self.jit.slots[index].instructions = insns.len() as u8;
            self.jit.active.push_back(index);
        }
    }
}
