/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! The task's virtual memory map: which page ranges are allocated. Guest
//! memory itself is the flat [crate::mem::Mem] array; protections are
//! recorded but not enforced.

use std::collections::BTreeMap;

pub const PAGE: u32 = 0x1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prot(pub u32);
impl Prot {
    pub const RW: Prot = Prot(3);
    pub fn from_bits(b: u32) -> Prot {
        Prot(b & 7)
    }
}

#[derive(Debug, Clone)]
pub struct Region {
    pub size: u32,
    pub prot: Prot,
    pub tag: String,
}

pub struct VmMap {
    regions: BTreeMap<u32, Region>,
    /// Lowest and highest (exclusive) addresses handed out by `map_anywhere`.
    low: u32,
    high: u32,
}

pub fn round_up(v: u32) -> u32 {
    v.wrapping_add(PAGE - 1) & !(PAGE - 1)
}

impl VmMap {
    pub fn new(low: u32, high: u32) -> VmMap {
        VmMap {
            regions: BTreeMap::new(),
            low,
            high,
        }
    }

    pub fn is_free(&self, addr: u32, size: u32) -> bool {
        let end = addr as u64 + size as u64;
        if let Some((&base, r)) = self.regions.range(..end as u32).next_back() {
            if base as u64 + r.size as u64 > addr as u64 && (base as u64) < end {
                return false;
            }
        }
        true
    }

    pub fn map_fixed(
        &mut self,
        addr: u32,
        size: u32,
        prot: Prot,
        tag: String,
    ) -> Result<(), String> {
        let addr_aligned = addr & !(PAGE - 1);
        let size = round_up(size + (addr - addr_aligned));
        self.unmap(addr_aligned, size);
        self.regions
            .insert(addr_aligned, Region { size, prot, tag });
        Ok(())
    }

    /// Finds a free range at or above `hint` (or the map's floor).
    pub fn map_anywhere(
        &mut self,
        hint: u32,
        size: u32,
        align_mask: u32,
        prot: Prot,
        tag: String,
    ) -> Option<u32> {
        let size = round_up(size);
        let align = (align_mask | (PAGE - 1)).wrapping_add(1);
        let mut addr = hint.max(self.low);
        loop {
            addr = (addr + align - 1) & !(align - 1);
            if addr as u64 + size as u64 > self.high as u64 {
                // Like XNU, a hint with no room above it wraps to the bottom.
                if hint > self.low {
                    return self.map_anywhere(0, size, align_mask, prot, tag);
                }
                return None;
            }
            match self.regions.range(..addr.saturating_add(size)).next_back() {
                Some((&base, r)) if base as u64 + r.size as u64 > addr as u64 => {
                    addr = base + r.size;
                }
                _ => break,
            }
        }
        self.regions.insert(addr, Region { size, prot, tag });
        Some(addr)
    }

    /// Removes any mappings overlapping the range, splitting partial overlaps.
    pub fn unmap(&mut self, addr: u32, size: u32) {
        let end = addr as u64 + round_up(size) as u64;
        let overlapping: Vec<u32> = self
            .regions
            .range(..end as u32)
            .filter(|(&b, r)| b as u64 + r.size as u64 > addr as u64)
            .map(|(&b, _)| b)
            .collect();
        for base in overlapping {
            let r = self.regions.remove(&base).unwrap();
            let r_end = base as u64 + r.size as u64;
            if base < addr {
                self.regions.insert(
                    base,
                    Region {
                        size: addr - base,
                        ..r.clone()
                    },
                );
            }
            if r_end > end {
                self.regions.insert(
                    end as u32,
                    Region {
                        size: (r_end - end) as u32,
                        ..r
                    },
                );
            }
        }
    }

    pub fn protect(&mut self, addr: u32, size: u32, prot: Prot) {
        for (_, r) in self.regions.range_mut(addr..addr.saturating_add(size)) {
            r.prot = prot;
        }
    }

    pub fn region_at(&self, addr: u32) -> Option<(u32, &Region)> {
        self.regions
            .range(..=addr)
            .next_back()
            .filter(|(&b, r)| addr - b < r.size)
            .map(|(&b, r)| (b, r))
    }
}
