/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! An XNU personality: runs Apple's own iPhone OS userland (dyld, the dyld
//! shared cache, SpringBoard) from a user-provided IPSW, emulating only the
//! kernel interface underneath it: BSD syscalls, Mach traps and Mach IPC.
//!
//! This is separate from the rest of touchHLE, which reimplements the
//! frameworks in Rust. Here, none of the guest code is reimplemented.

mod bsd;
mod installd;
mod iokit;
mod loader;
pub mod lockdown;
mod mach;
mod notifyd;
mod vfs;
mod vm;

use crate::cpu::{Cpu, CpuContext, CpuState};
use crate::firmware::Firmware;
use crate::mem::{Mem, Ptr};
use std::path::Path;
use vm::{Prot, VmMap};

/// Base of the dyld shared cache, where the kernel's shared region lives.
pub const SHARED_REGION_BASE: u32 = 0x30000000;
const SHARED_CACHE_PATH: &str = "/System/Library/Caches/com.apple.dyld/dyld_shared_cache_armv6";
/// Main thread stack, just below dyld like on a device.
const STACK_TOP: u32 = 0x2fe00000;
const STACK_SIZE: u32 = 1024 * 1024;
/// The comm page: read-only kernel data mapped into every task.
pub const COMM_PAGE: u32 = 0xffff4000;

pub fn write_bytes(mem: &mut Mem, addr: u32, bytes: &[u8]) {
    if !bytes.is_empty() {
        mem.bytes_at_mut(Ptr::from_bits(addr), bytes.len() as u32)
            .copy_from_slice(bytes);
    }
}
pub fn read_bytes(mem: &Mem, addr: u32, len: u32) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    mem.bytes_at(Ptr::<u8, false>::from_bits(addr), len)
        .to_vec()
}
pub fn write_u32(mem: &mut Mem, addr: u32, v: u32) {
    write_bytes(mem, addr, &v.to_le_bytes())
}
pub fn read_u32(mem: &Mem, addr: u32) -> u32 {
    u32::from_le_bytes(read_bytes(mem, addr, 4).try_into().unwrap())
}
pub fn read_cstr(mem: &Mem, addr: u32) -> String {
    let p: Ptr<u8, false> = Ptr::from_bits(addr);
    String::from_utf8_lossy(mem.cstr_at(p)).into_owned()
}

#[derive(Debug, Clone, PartialEq)]
pub enum Block {
    /// Waiting for a message on a port or port set (receive name).
    MachReceive {
        name: u32,
        deadline: Option<u64>,
    },
    Semaphore {
        port: u32,
        deadline: Option<u64>,
    },
    Sleep {
        deadline: u64,
    },
    /// __semwait_signal: a BSD syscall, so it reports through the carry
    /// flag. `port` 0 is a plain timed sleep.
    SemWait {
        port: u32,
        deadline: Option<u64>,
    },
}

pub struct Thread {
    pub id: u32,
    /// thread_selfid: unique for the task's lifetime, unlike `id`.
    pub tid: u64,
    pub port: u32,
    context: Option<Box<CpuContext>>,
    tls: u32,
    pub blocked: Option<Block>,
    pub exited: bool,
}

pub struct Kernel {
    pub mem: Mem,
    pub cpu: Cpu,
    pub vm: VmMap,
    pub fw: Firmware,
    pub vfs: vfs::Vfs,
    pub ipc: mach::Ipc,
    pub iokit: iokit::Registry,
    pub threads: Vec<Thread>,
    pub current: usize,
    pub start: std::time::Instant,
    /// Host time the emulator was not scheduled for (a hidden browser tab, a
    /// suspended process), which the guest's clock skips.
    stalled: std::time::Duration,
    /// Whether the LCD showed a surface at the last frame, for the web page.
    display_on: bool,
    last_tick: std::time::Instant,
    /// The latest `now_ns()`, so a stall noticed late never rewinds the clock.
    last_now: std::cell::Cell<u64>,
    pub exit_status: Option<i32>,
    pub bsdthread_start: u32,
    pub pthread_size: u32,
    pub trace: bool,
    /// Set by thread_switch/swtch so another thread runs next.
    pub yield_requested: bool,
    /// Shows the LCD's surface, when booted with a window.
    pub window: Option<Box<crate::window::Window>>,
    pub last_present: std::time::Instant,
    next_tid: u64,
}

impl Kernel {
    pub fn boot(
        fw: Firmware,
        overlay_dir: &Path,
        exe_path: &str,
        argv: Vec<String>,
    ) -> Result<Kernel, String> {
        let mut mem = Mem::new();
        let mut vm = VmMap::new(0x1000, 0x2f000000);

        let exe = Self::read_fw_file(&fw, exe_path)?;
        let main = loader::map_macho(&mut mem, &mut vm, &exe)?;
        let dylinker_path = main
            .dylinker
            .clone()
            .ok_or("Executable has no dynamic linker")?;
        let dyld = loader::map_macho(&mut mem, &mut vm, &Self::read_fw_file(&fw, &dylinker_path)?)?;
        log!(
            "xnu: {exe_path} at {:#x}, dyld {dylinker_path} entry {:#x}",
            main.mach_header,
            dyld.entry
        );
        if main.page_zero != 0 {
            mem.set_null_segment_size(main.page_zero.min(0x1000));
        }

        // The shared region is set up by the kernel (as if launchd had already
        // mapped it), so dyld's shared_region_check_np finds it.
        let cache = Self::read_fw_file(&fw, SHARED_CACHE_PATH)?;
        Self::map_shared_cache(&mut mem, &mut vm, &cache)?;
        drop(cache);

        vm.map_fixed(STACK_TOP - STACK_SIZE, STACK_SIZE, Prot::RW, "stack".into())?;
        vm.map_fixed(COMM_PAGE, 0x1000, Prot(1), "commpage".into())?;
        Self::init_comm_page(&mut mem);

        let envp = vec![
            "HOME=/var/mobile".to_string(),
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin".to_string(),
        ];
        let apple = vec![exe_path.to_string()];
        let sp = loader::build_stack(&mut mem, STACK_TOP, main.mach_header, &argv, &envp, &apple);

        let mut cpu = Cpu::new(Some(&mut mem));
        cpu.regs_mut()[Cpu::SP] = sp;
        let entry = dyld.entry;
        cpu.regs_mut()[Cpu::PC] = entry & !1;
        cpu.set_cpsr(Cpu::CPSR_USER_MODE | if entry & 1 != 0 { Cpu::CPSR_THUMB } else { 0 });

        let mut ipc = mach::Ipc::new();
        let thread_port = ipc.new_kernel_port(mach::KObject::Thread(0));
        let iokit = iokit::Registry::new(&fw.info);
        Ok(Kernel {
            mem,
            cpu,
            vm,
            fw,
            vfs: vfs::Vfs::new(overlay_dir),
            iokit,
            ipc,
            threads: vec![Thread {
                id: 0,
                tid: 0,
                port: thread_port,
                context: None,
                tls: 0,
                blocked: None,
                exited: false,
            }],
            current: 0,
            start: std::time::Instant::now(),
            stalled: std::time::Duration::ZERO,
            display_on: false,
            last_tick: std::time::Instant::now(),
            last_now: std::cell::Cell::new(0),
            exit_status: None,
            bsdthread_start: 0,
            pthread_size: 0,
            trace: std::env::var_os("TOUCHHLE_XNU_TRACE").is_some(),
            yield_requested: false,
            window: None,
            last_present: std::time::Instant::now(),
            next_tid: 1,
        })
    }

    fn read_fw_file(fw: &Firmware, path: &str) -> Result<Vec<u8>, String> {
        let node = fw
            .volume
            .lookup(path, true)
            .ok_or(format!("{path} not found in firmware"))?;
        fw.volume.read_all(node).map_err(|e| format!("{path}: {e}"))
    }

    fn map_shared_cache(mem: &mut Mem, vm: &mut VmMap, cache: &[u8]) -> Result<(), String> {
        if !cache.starts_with(b"dyld_v1") {
            return Err("Bad dyld shared cache".to_string());
        }
        let le = |o: usize| u32::from_le_bytes(cache[o..o + 4].try_into().unwrap());
        let le64 = |o: usize| u64::from_le_bytes(cache[o..o + 8].try_into().unwrap());
        let (off, count) = (le(16) as usize, le(20) as usize);
        for i in 0..count {
            let m = off + i * 32;
            let (addr, size, file_off, init_prot) = (
                le64(m) as u32,
                le64(m + 8) as u32,
                le64(m + 16) as usize,
                le(m + 28),
            );
            vm.map_fixed(
                addr,
                size,
                Prot::from_bits(init_prot),
                "shared cache".into(),
            )?;
            write_bytes(
                mem,
                addr,
                cache
                    .get(file_off..file_off + size as usize)
                    .ok_or("Truncated shared cache")?,
            );
        }
        Ok(())
    }

    fn init_comm_page(mem: &mut Mem) {
        // _COMM_PAGE_SIGNATURE, _COMM_PAGE_VERSION
        write_bytes(mem, COMM_PAGE, b"commpage 32-bit\0");
        write_bytes(mem, COMM_PAGE + 0x1e, &3u16.to_le_bytes());
        // _COMM_PAGE_NCPUS
        write_bytes(mem, COMM_PAGE + 0x22, &[1]);
    }

    pub fn now_ns(&self) -> u64 {
        let now = self.start.elapsed().saturating_sub(self.stalled).as_nanos() as u64;
        let now = now.max(self.last_now.get());
        self.last_now.set(now);
        now
    }

    /// mach_absolute_time ticks: we use a 24 MHz timebase like the device.
    pub fn absolute_time(&self) -> u64 {
        self.now_ns() * 3 / 125
    }

    fn switch_to(&mut self, idx: usize) {
        if idx == self.current {
            return;
        }
        let tls = self.cpu.tls();
        let cur = &mut self.threads[self.current];
        cur.tls = tls;
        let mut ctx = cur
            .context
            .take()
            .unwrap_or_else(|| Box::new(CpuContext::new()));
        self.cpu.swap_context(&mut ctx);
        // ctx now holds the old thread's state
        let next_ctx = self.threads[idx].context.take();
        let cur = &mut self.threads[self.current];
        if cur.exited {
            // A finished thread's context and port are freed; its slot is
            // reused by the next spawn_thread.
            let port = cur.port;
            self.ipc.ports.remove(&port);
        } else {
            cur.context = Some(ctx);
        }
        if let Some(mut next_ctx) = next_ctx {
            self.cpu.swap_context(&mut next_ctx);
        }
        self.cpu.set_tls(self.threads[idx].tls);
        self.current = idx;
    }

    /// Creates a runnable thread starting at `pc` with stack `sp` and TLS
    /// `tls`. `regs` gets the new thread's port and returns r0-r5.
    pub fn spawn_thread(
        &mut self,
        pc: u32,
        sp: u32,
        tls: u32,
        regs: impl FnOnce(u32) -> [u32; 6],
    ) -> u32 {
        let reuse = (0..self.threads.len()).find(|&i| {
            i != self.current && self.threads[i].exited && self.threads[i].context.is_none()
        });
        let id = reuse.unwrap_or(self.threads.len()) as u32;
        let port = self.ipc.new_kernel_port(mach::KObject::Thread(id));
        let mut ctx = Box::new(CpuContext::new());
        // Build the context on the CPU, then swap the current thread back.
        self.cpu.swap_context(&mut ctx);
        for (i, v) in regs(port).into_iter().enumerate() {
            self.cpu.regs_mut()[i] = v;
        }
        self.cpu.regs_mut()[Cpu::SP] = sp;
        self.cpu.regs_mut()[Cpu::LR] = 0;
        self.cpu.regs_mut()[Cpu::PC] = pc & !1;
        self.cpu
            .set_cpsr(Cpu::CPSR_USER_MODE | if pc & 1 != 0 { Cpu::CPSR_THUMB } else { 0 });
        self.cpu.swap_context(&mut ctx);
        let tid = self.next_tid;
        self.next_tid += 1;
        let thread = Thread {
            id,
            tid,
            port,
            context: Some(ctx),
            tls,
            blocked: None,
            exited: false,
        };
        match reuse {
            Some(i) => self.threads[i] = thread,
            None => self.threads.push(thread),
        }
        port
    }

    pub fn current_thread(&mut self) -> &mut Thread {
        &mut self.threads[self.current]
    }

    /// Re-checks blocked threads, returning the next runnable one.
    fn pick_thread(&mut self) -> Option<usize> {
        let now = self.absolute_time();
        let n = self.threads.len();
        for i in 1..=n {
            let idx = (self.current + i) % n;
            if self.threads[idx].exited {
                continue;
            }
            if let Some(block) = self.threads[idx].blocked.clone() {
                if !self.try_unblock(idx, &block, now) {
                    continue;
                }
            }
            return Some(idx);
        }
        None
    }

    fn try_unblock(&mut self, idx: usize, block: &Block, now: u64) -> bool {
        let saved = self.current;
        self.switch_to(idx);
        let done = match *block {
            Block::Sleep { deadline } => {
                if now >= deadline {
                    self.set_result(0);
                    true
                } else {
                    false
                }
            }
            Block::MachReceive { deadline, .. }
            | Block::Semaphore { deadline, .. }
            | Block::SemWait { deadline, .. } => {
                if mach::retry_blocked(self, block) {
                    true
                } else if deadline.is_some_and(|d| now >= d) {
                    mach::timeout_blocked(self, block);
                    true
                } else {
                    false
                }
            }
        };
        if done {
            self.threads[idx].blocked = None;
        } else {
            self.switch_to(saved);
        }
        done
    }

    /// Sets the syscall return value in r0 (the caller handles carry).
    fn set_result(&mut self, r0: u32) {
        self.cpu.regs_mut()[0] = r0;
    }

    /// Copies the surface the LCD shows to the window and handles its
    /// events.
    fn present(&mut self) {
        self.last_present = std::time::Instant::now();
        let on = self.iokit.presented_surface != 0;
        if on != self.display_on {
            self.display_on = on;
            // The page says when the screen is still booting or has gone dark.
            #[cfg(target_os = "emscripten")]
            {
                extern "C" {
                    fn emscripten_run_script(script: *const std::ffi::c_char);
                }
                let script = if on {
                    c"globalThis.touchHLEDisplay?.(true)"
                } else {
                    c"globalThis.touchHLEDisplay?.(false)"
                };
                unsafe { emscripten_run_script(script.as_ptr()) };
            }
        }
        let Some(window) = self.window.as_mut() else {
            return;
        };
        let options = crate::options::Options::default();
        window.poll_for_events(&options);
        let (width, height) = self
            .iokit
            .presented_surface
            .checked_sub(1)
            .and_then(|i| self.iokit.surfaces.get(i as usize))
            .map_or((320, 480), |s| (s.width, s.height));
        let mut touches = Vec::new();
        let mut home = false;
        while let Some(event) = window.pop_event() {
            use crate::window::Event;
            use iokit::TouchPhase;
            let (phase, map) = match event {
                Event::Quit => {
                    self.exit_status.get_or_insert(0);
                    continue;
                }
                Event::TouchesDown(map) => (TouchPhase::Down, map),
                Event::TouchesMove(map) => (TouchPhase::Move, map),
                Event::TouchesUp(map) => (TouchPhase::Up, map),
                Event::HomeButton => {
                    home = true;
                    continue;
                }
                _ => continue,
            };
            // With the display off (the LCD shows no surface) a tap presses
            // Home, which wakes it, instead of going to a dark lock screen.
            if self.iokit.presented_surface == 0 {
                home |= phase == TouchPhase::Down;
                continue;
            }
            if let Some(&(x, y)) = map.values().next() {
                touches.push((phase, (x / width as f32, y / height as f32)));
            }
        }
        // The digitizer reports at most one move per frame, so moves queued
        // since the last frame collapse into the latest.
        touches.dedup_by(|next, prev| {
            next.0 == iokit::TouchPhase::Move && prev.0 == iokit::TouchPhase::Move && {
                prev.1 = next.1;
                true
            }
        });
        for (phase, pos) in touches {
            self.hid_touch(phase, pos);
        }
        if home {
            // The Home button is the Consumer page's Menu usage.
            self.hid_button(0x0c, 0x40, true);
            self.hid_button(0x0c, 0x40, false);
        }
        let Some(window) = self.window.as_mut() else {
            return;
        };
        let id = self.iokit.presented_surface;
        let Some(s) = id
            .checked_sub(1)
            .and_then(|i| self.iokit.surfaces.get(i as usize))
        else {
            // With no surface the LCD shows its black background.
            let black = crate::image::Image::from_pixel_vec(vec![0, 0, 0, 255], (1, 1));
            window.display_image(black);
            return;
        };
        if s.bytes_per_element != 4 {
            return;
        }
        let mut pixels = Vec::with_capacity((s.width * s.height * 4) as usize);
        for y in 0..s.height {
            let row = read_bytes(&self.mem, s.addr + y * s.bytes_per_row, s.width * 4);
            for bgra in row.chunks(4) {
                pixels.extend([bgra[2], bgra[1], bgra[0], 255]);
            }
        }
        let image = crate::image::Image::from_pixel_vec(pixels, (s.width, s.height));
        window.display_image(image);
    }

    /// A long gap since the last call means the host stopped running us
    /// (browsers throttle hidden tabs to about one timer a minute). The
    /// guest's clock skips it, so SpringBoard doesn't wake up to find its
    /// auto-lock long overdue.
    fn skip_stall(&mut self) {
        let now = std::time::Instant::now();
        let gap = now - self.last_tick;
        self.last_tick = now;
        if gap > std::time::Duration::from_millis(250) {
            self.stalled += gap - std::time::Duration::from_millis(16);
        }
    }

    pub fn run(&mut self) -> Result<i32, String> {
        let mut ticks_left: u64;
        loop {
            self.skip_stall();
            if self.last_present.elapsed() >= std::time::Duration::from_millis(16) {
                self.present();
                // Presenting yields to the browser, which may not come back
                // for a while.
                self.skip_stall();
            }
            if let Some(status) = self.exit_status {
                return Ok(status);
            }
            if self.threads[self.current].blocked.is_some() || self.threads[self.current].exited {
                match self.pick_thread() {
                    Some(idx) => self.switch_to(idx),
                    None => {
                        crate::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                }
            }
            ticks_left = 100_000;
            match self.cpu.run_or_step(&mut self.mem, Some(&mut ticks_left)) {
                CpuState::Normal => {
                    if let Some(idx) = self.pick_thread() {
                        self.switch_to(idx);
                    }
                }
                CpuState::Svc(0x80) => {
                    self.syscall();
                    if std::mem::take(&mut self.yield_requested) {
                        if let Some(idx) = self.pick_thread() {
                            self.switch_to(idx);
                        }
                    }
                }
                CpuState::Svc(other) => {
                    return Err(format!(
                        "Unexpected svc {other:#x} at {:#x}",
                        self.cpu.regs()[Cpu::PC]
                    ))
                }
                CpuState::Error(e) => {
                    self.cpu.dump_regs();
                    self.backtrace();
                    return Err(format!(
                        "CPU error {e:?} in thread {}",
                        self.threads[self.current].id
                    ));
                }
            }
        }
    }

    /// A thread's r0-r15 and CPSR, whether or not it is running.
    fn thread_regs(&mut self, idx: usize) -> Option<[u32; 17]> {
        let read = |cpu: &Cpu| {
            let mut state = [0; 17];
            state[..16].copy_from_slice(cpu.regs());
            state[16] = cpu.cpsr();
            state
        };
        if idx == self.current {
            return Some(read(&self.cpu));
        }
        let ctx = self.threads.get_mut(idx)?.context.as_mut()?;
        self.cpu.swap_context(ctx);
        let state = read(&self.cpu);
        self.cpu.swap_context(ctx);
        Some(state)
    }

    /// Walks the r7 frame chain, which Apple's ABI always maintains.
    fn backtrace(&self) {
        let mut fp = self.cpu.regs()[7];
        let mut frames = vec![format!("{:#x}", self.cpu.regs()[14])];
        for _ in 0..32 {
            if fp == 0 || fp & 3 != 0 || self.vm.region_at(fp).is_none() {
                break;
            }
            frames.push(format!("{:#x}", read_u32(&self.mem, fp + 4)));
            fp = read_u32(&self.mem, fp);
        }
        echo!("xnu: backtrace: {}", frames.join(" "));
        let pc = self.cpu.regs()[Cpu::PC];
        if let Some((base, r)) = self.vm.region_at(pc) {
            echo!("xnu: pc {pc:#x} is in {} (+{:#x})", r.tag, pc - base);
        }
    }

    fn syscall(&mut self) {
        let num = self.cpu.regs()[12] as i32;
        if self.trace {
            let r = self.cpu.regs();
            echo!(
                "xnu: [{}] svc {num} ({:#x}, {:#x}, {:#x}, {:#x}) lr {:#x}",
                self.current,
                r[0],
                r[1],
                r[2],
                r[3],
                r[14]
            );
        }
        if num as u32 == 0x80000000 {
            // Platform calls: r3 selects.
            match self.cpu.regs()[3] {
                0 | 1 => {
                    let (addr, len) = (self.cpu.regs()[0], self.cpu.regs()[1]);
                    self.cpu.invalidate_cache_range(addr, len);
                }
                2 => {
                    let tls = self.cpu.regs()[0];
                    self.cpu.set_tls(tls);
                }
                3 => {
                    let tls = self.cpu.tls();
                    self.cpu.regs_mut()[0] = tls;
                }
                other => {
                    log!("xnu: unknown platform call {other}");
                }
            }
        } else if num < 0 {
            let r0 = mach::trap(self, -num as u32);
            if self.trace {
                echo!("xnu:   = {r0:x?}");
            }
            if let Some(r0) = r0 {
                self.cpu.regs_mut()[0] = r0;
            }
        } else {
            let (num, args_from) = if num == 0 {
                (self.cpu.regs()[0], 1)
            } else {
                (num as u32, 0)
            };
            match bsd::syscall(self, num, args_from) {
                bsd::Ret::Ok(r0, r1) => {
                    if self.trace {
                        echo!("xnu:   = {r0:#x}");
                    }
                    self.cpu.regs_mut()[0] = r0;
                    self.cpu.regs_mut()[1] = r1;
                    let cpsr = self.cpu.cpsr() & !(1 << 29);
                    self.cpu.set_cpsr(cpsr);
                }
                bsd::Ret::Blocked => {
                    if self.trace {
                        echo!("xnu:   blocked");
                    }
                }
                bsd::Ret::Err(errno) => {
                    if self.trace {
                        echo!("xnu:   = errno {errno}");
                    }
                    self.cpu.regs_mut()[0] = errno;
                    let cpsr = self.cpu.cpsr() | (1 << 29);
                    self.cpu.set_cpsr(cpsr);
                }
            }
        }
    }

    /// Syscall argument `i`: r0-r6, then the stack (as saved by the wrapper).
    /// The guest's wall clock in Unix nanoseconds. It starts in late 2010,
    /// around when iOS 4.2 shipped, and advances with `now_ns`.
    pub fn guest_unix_ns(&self) -> u64 {
        self.now_ns() + 1_290_000_000_000_000_000
    }

    pub fn arg(&self, i: usize) -> u32 {
        if i < 7 {
            self.cpu.regs()[i]
        } else {
            read_u32(&self.mem, self.cpu.regs()[Cpu::SP] + 4 * (i as u32 - 7))
        }
    }
}

pub fn boot_firmware(
    ipsw_path: &Path,
    key: Option<&str>,
    exe_path: &str,
    headless: bool,
) -> Result<(), String> {
    let base = crate::paths::user_data_base_path().join(crate::paths::FIRMWARE_DIR);
    let fw = Firmware::open(ipsw_path, &base, key)?;
    let overlay = base.join(format!("{}_{}_data", fw.info.product_type, fw.info.build));
    let mut kernel = Kernel::boot(fw, &overlay, exe_path, vec![exe_path.to_string()])?;
    if !headless {
        kernel.window = Some(Box::new(crate::window::Window::new(
            "touchHLE (iPhone OS firmware)",
            None,
            None,
            &crate::options::Options::default(),
        )));
    }
    let status = kernel.run()?;
    log!("xnu: process exited with status {status}");
    Ok(())
}
