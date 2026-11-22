/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use super::*;
use crate::mem::Ptr;

const PC: u32 = 0x2000;
const DATA: u32 = 0x4000;

fn arm(mem: &mut Mem, words: &[u32]) {
    for (i, word) in words.iter().enumerate() {
        assert!(mem.cpu_write(PC + i as u32 * 4, word.to_le_bytes()));
    }
}

fn thumb(mem: &mut Mem, words: &[u16]) {
    for (i, word) in words.iter().enumerate() {
        assert!(mem.cpu_write(PC + i as u32 * 2, word.to_le_bytes()));
    }
}

fn warm(cpu: &mut Interp, mem: &mut Mem) {
    cpu.regs[15] = PC;
    assert!(cpu.jit.enabled());
    for _ in 0..HOT {
        assert_eq!(cpu.run_jit(mem, 0), 0);
    }
    assert_eq!(cpu.jit.active.len(), 1);
}

fn compare(cpu: &mut Interp, mem: &mut Mem, count: u32) {
    let mut reference = Interp::new();
    reference.jit.enabled = false;
    reference.regs = cpu.regs;
    reference.set_cpsr(cpu.cpsr());
    let mut ticks = u64::from(count);
    assert!(reference.run(mem, Some(&mut ticks)).is_none());
    assert_eq!(cpu.run_jit(mem, u64::from(count)), count);
    assert_eq!(cpu.regs, reference.regs);
    assert_eq!(cpu.cpsr(), reference.cpsr());
}

#[test]
fn arm_predication_flags_memory_and_interworking() {
    let mut mem = Mem::new();
    let mut cpu = Interp::new();
    arm(
        &mut mem,
        &[
            0xe092_3001, // adds r3, r2, r1
            0x23a0_4009, // movcs r4, #9
            0x33a0_400b, // movcc r4, #11
            0xe0b2_5001, // adcs r5, r2, r1
            0xe0d1_6002, // sbcs r6, r1, r2
            0xe480_4004, // str r4, [r0], #4
            0xe510_7004, // ldr r7, [r0, #-4]
            0xe1b0_8064, // movs r8, r4, rrx
            0xe12f_ff3e, // blx lr
        ],
    );
    warm(&mut cpu, &mut mem);
    for (a, b) in [
        (0, 0),
        (0x8000_0000, 1),
        (0x7fff_ffff, 1),
        (u32::MAX, u32::MAX),
        (1, u32::MAX),
    ] {
        cpu.regs = [0; 16];
        cpu.regs[0] = DATA;
        cpu.regs[1] = a;
        cpu.regs[2] = b;
        cpu.regs[14] = DATA + 1;
        cpu.regs[15] = PC;
        cpu.set_cpsr(0x10);
        compare(&mut cpu, &mut mem, 9);
        assert_eq!(cpu.regs[15], DATA);
        assert_eq!(cpu.regs[14], PC + 36);
        assert!(cpu.thumb);
        assert_eq!(cpu.regs[4], cpu.regs[7]);
    }
}

#[test]
fn thumb_subword_access_and_stack_transfer() {
    let mut mem = Mem::new();
    let mut cpu = Interp::new();
    thumb(
        &mut mem,
        &[
            0x2180, // movs r1, #128
            0x7041, // strb r1, [r0, #1]
            0x5642, // ldrsb r2, [r0, r1]
            0xb506, // push {r1, r2, lr}
            0x2200, // movs r2, #0
            0xbd18, // pop {r3, r4, pc}
        ],
    );
    assert!(mem.cpu_write(DATA + 128, [0x80]));
    cpu.regs[0] = DATA;
    cpu.regs[13] = DATA + 0x1000;
    cpu.regs[14] = DATA;
    cpu.set_cpsr(0x30);
    warm(&mut cpu, &mut mem);
    compare(&mut cpu, &mut mem, 6);
    assert_eq!(cpu.regs[4], 0xffff_ff80);
    assert_eq!(cpu.regs[13], DATA + 0x1000);
    assert_eq!(cpu.regs[15], DATA);
    assert!(!cpu.thumb);
}

#[test]
fn code_guards_cover_host_and_guest_writes() {
    let mut mem = Mem::new();
    let mut cpu = Interp::new();
    arm(&mut mem, &[0xe580_1000, 0xe3a0_2001, 0xeaff_fffc]); // str; mov; b PC
    warm(&mut cpu, &mut mem);
    cpu.regs[0] = (PC + 4) | (MASK + 1); // Alias of the next instruction.
    cpu.regs[1] = 0xe3a0_2002;
    assert_eq!(cpu.run_jit(&mut mem, 3), 1);
    assert_eq!(cpu.regs[15], PC + 4);
    assert_eq!(cpu.regs[2], 0);
    assert!(cpu.step(&mut mem).is_ok());
    assert_eq!(cpu.regs[2], 2);
    cpu.regs[15] = PC;
    assert_eq!(cpu.run_jit(&mut mem, 3), 0);
    assert!(cpu.jit.active.is_empty());

    warm(&mut cpu, &mut mem);
    // Changes through host APIs need no explicit cache notification.
    mem.write(Ptr::from_bits(PC + 4), 0xe3a0_2003u32);
    assert_eq!(cpu.run_jit(&mut mem, 3), 0);
    assert!(cpu.jit.active.is_empty());
    warm(&mut cpu, &mut mem);
    cpu.invalidate_cache_range((PC + 1) | (MASK + 1), 1);
    assert!(cpu.jit.active.is_empty());
}

#[test]
fn faults_ticks_and_single_step() {
    let mut mem = Mem::new();
    mem.set_null_segment_size(0x1000);
    let mut cpu = Interp::new();
    arm(&mut mem, &[0xe3a0_1001, 0xe490_2004, 0xeaff_fffc]); // mov; ldr; b PC
    warm(&mut cpu, &mut mem);
    assert!(cpu.run(&mut mem, Some(&mut 1)).is_none());
    assert_eq!(cpu.regs[15], PC + 4);
    cpu.regs[15] = PC;
    cpu.regs[1] = 0;
    assert!(cpu.run(&mut mem, None).is_none());
    assert_eq!(cpu.regs[1], 1);
    assert_eq!(cpu.regs[15], PC + 4);
    cpu.regs[15] = PC;
    let mut ticks = 9;
    assert!(matches!(
        cpu.run(&mut mem, Some(&mut ticks)),
        Some(super::super::Exit::MemoryError)
    ));
    assert_eq!(ticks, 7);
    assert_eq!(cpu.regs[15], PC + 4);
    assert_eq!(cpu.regs[0], 0);
    for addr in [MASK - 1, u32::MAX] {
        cpu.regs[0] = addr;
        assert!(matches!(
            cpu.run(&mut mem, None),
            Some(super::super::Exit::MemoryError)
        ));
        assert_eq!(cpu.regs[0], addr);
    }
}

#[test]
fn loop_backedge_respects_budget_and_falls_through() {
    let mut mem = Mem::new();
    let mut cpu = Interp::new();
    arm(&mut mem, &[0xe250_0001, 0x1aff_fffd, 0xe12f_ff1e]); // subs; bne PC; bx lr
    warm(&mut cpu, &mut mem);
    cpu.regs[0] = 15;
    compare(&mut cpu, &mut mem, 10);
    assert_eq!(cpu.regs[0], 10);
    assert_eq!(cpu.regs[15], PC);
    assert_eq!(cpu.run_jit(&mut mem, 100), 20);
    assert_eq!(cpu.regs[0], 0);
    assert_eq!(cpu.regs[15], PC + 8);
}

#[test]
fn arm_forward_branch_and_extended_memory_operations() {
    let mut mem = Mem::new();
    let mut cpu = Interp::new();
    arm(
        &mut mem,
        &[
            0x0a00_0001, // beq PC+12
            0xe000_0291, // mul r0, r1, r2
            0xe1c3_00b2, // strh r0, [r3, #2]
            0xe1d3_40f2, // ldrsh r4, [r3, #2]
            0xe12f_ff1e, // bx lr
        ],
    );
    warm(&mut cpu, &mut mem);
    cpu.regs[1] = 0x4001;
    cpu.regs[2] = 2;
    cpu.regs[3] = DATA;
    cpu.regs[14] = DATA;
    compare(&mut cpu, &mut mem, 5);
    assert_eq!(cpu.regs[4], 0xffff_8002);
    assert_eq!(cpu.regs[15], DATA);
    cpu.z = true;
    cpu.regs[15] = PC;
    assert_eq!(cpu.run_jit(&mut mem, 5), 1);
    assert_eq!(cpu.regs[15], PC + 12);
}
