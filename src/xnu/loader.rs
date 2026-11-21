/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! What the kernel's `execve` does for a Mach-O: map the segments of the
//! executable and of its dynamic linker, and build the initial stack.

use super::vm::{Prot, VmMap};
use crate::mem::Mem;

const MH_MAGIC: u32 = 0xfeedface;
const MH_EXECUTE: u32 = 2;
const MH_DYLINKER: u32 = 7;
const LC_SEGMENT: u32 = 0x1;
const LC_UNIXTHREAD: u32 = 0x5;
const LC_LOAD_DYLINKER: u32 = 0xe;

pub struct Loaded {
    pub mach_header: u32,
    pub entry: u32,
    pub dylinker: Option<String>,
    /// Size of the __PAGEZERO segment, if any.
    pub page_zero: u32,
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

/// Maps a 32-bit ARM Mach-O at its preferred address (no slide).
pub fn map_macho(mem: &mut Mem, vm: &mut VmMap, file: &[u8]) -> Result<Loaded, String> {
    if file.len() < 28 || le32(file, 0) != MH_MAGIC {
        return Err("Not a 32-bit Mach-O".to_string());
    }
    let filetype = le32(file, 12);
    if filetype != MH_EXECUTE && filetype != MH_DYLINKER {
        return Err(format!("Unexpected Mach-O file type {filetype}"));
    }
    let ncmds = le32(file, 16);
    let mut off = 28;
    let mut loaded = Loaded {
        mach_header: 0,
        entry: 0,
        dylinker: None,
        page_zero: 0,
    };
    for _ in 0..ncmds {
        let cmd = le32(file, off);
        let size = le32(file, off + 4) as usize;
        match cmd {
            LC_SEGMENT => {
                let name = &file[off + 8..off + 24];
                let vmaddr = le32(file, off + 24);
                let vmsize = le32(file, off + 28);
                let fileoff = le32(file, off + 32) as usize;
                let filesize = le32(file, off + 36) as usize;
                let initprot = le32(file, off + 44);
                if name.starts_with(b"__PAGEZERO") {
                    loaded.page_zero = vmsize;
                    vm.map_fixed(vmaddr, vmsize, Prot(0), "__PAGEZERO".into())?;
                } else if vmsize != 0 {
                    vm.map_fixed(vmaddr, vmsize, Prot::from_bits(initprot), name_str(name))?;
                    let bytes = file
                        .get(fileoff..fileoff + filesize)
                        .ok_or("Segment outside file")?;
                    super::write_bytes(mem, vmaddr, bytes);
                    if fileoff == 0 && filesize != 0 {
                        loaded.mach_header = vmaddr;
                    }
                }
            }
            LC_UNIXTHREAD => {
                // flavor, count, then r0-r15, cpsr
                loaded.entry = le32(file, off + 16 + 15 * 4);
            }
            LC_LOAD_DYLINKER => {
                let name_off = le32(file, off + 8) as usize;
                let s = &file[off + name_off..off + size];
                let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
                loaded.dylinker = Some(String::from_utf8_lossy(&s[..end]).into_owned());
            }
            _ => (),
        }
        off += size;
    }
    Ok(loaded)
}

fn name_str(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Builds the stack dyld expects at `__dyld_start`:
/// `sp -> [mach_header, argc, argv..., 0, envp..., 0, apple..., 0]`.
pub fn build_stack(
    mem: &mut Mem,
    stack_top: u32,
    mach_header: u32,
    argv: &[String],
    envp: &[String],
    apple: &[String],
) -> u32 {
    let mut strings = Vec::new();
    let mut offsets = Vec::new();
    for s in argv.iter().chain(envp).chain(apple) {
        offsets.push(strings.len() as u32);
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
    }
    let strings_base = (stack_top - strings.len() as u32 - 16) & !15;
    super::write_bytes(mem, strings_base, &strings);
    let mut words = vec![mach_header, argv.len() as u32];
    let mut i = 0;
    for list in [argv, envp, apple] {
        for _ in list {
            words.push(strings_base + offsets[i]);
            i += 1;
        }
        words.push(0);
    }
    let sp = (strings_base - words.len() as u32 * 4) & !15;
    for (j, w) in words.iter().enumerate() {
        super::write_u32(mem, sp + j as u32 * 4, *w);
    }
    sp
}
