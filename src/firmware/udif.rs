/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Apple UDIF disk images (`.dmg`): a `koly` trailer pointing to an XML
//! property list whose `blkx` entries map runs of 512-byte sectors to
//! (usually zlib-compressed) chunks of the data fork.

use super::{be32, be64, ReadAt};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read};

const SECTOR: u64 = 512;

#[derive(Debug, Clone)]
struct Run {
    kind: u32,
    /// First sector covered, absolute within the disk.
    sector: u64,
    sector_count: u64,
    offset: u64,
    length: u64,
}

pub struct Partition {
    pub name: String,
    pub first_sector: u64,
}

pub struct UdifImage<R: ReadAt> {
    inner: R,
    /// Sorted by sector.
    runs: Vec<Run>,
    pub partitions: Vec<Partition>,
    sector_count: u64,
    cache: RefCell<VecDeque<(usize, Vec<u8>)>>,
}

const CACHE_RUNS: usize = 8;

impl<R: ReadAt> UdifImage<R> {
    pub fn new(inner: R, len: u64) -> Result<Self, String> {
        if len < 512 {
            return Err("Not a UDIF image (too short)".to_string());
        }
        let mut koly = [0u8; 512];
        inner
            .read_exact_at(&mut koly, len - 512)
            .map_err(|e| e.to_string())?;
        if &koly[0..4] != b"koly" {
            return Err("Not a UDIF image (no koly trailer)".to_string());
        }
        let data_fork_offset = be64(&koly[0x18..]);
        let xml_offset = be64(&koly[0xd8..]);
        let xml_length = be64(&koly[0xe0..]);
        if xml_length > 64 << 20 || xml_offset.saturating_add(xml_length) > len {
            return Err("Bad UDIF plist location".to_string());
        }
        let mut xml = vec![0u8; xml_length as usize];
        inner
            .read_exact_at(&mut xml, xml_offset)
            .map_err(|e| e.to_string())?;
        let plist = plist::Value::from_reader_xml(&xml[..]).map_err(|e| e.to_string())?;
        let blkx = plist
            .as_dictionary()
            .and_then(|d| d.get("resource-fork"))
            .and_then(|d| d.as_dictionary())
            .and_then(|d| d.get("blkx"))
            .and_then(|d| d.as_array())
            .ok_or("UDIF plist has no blkx list")?;

        let mut runs = Vec::new();
        let mut partitions = Vec::new();
        for entry in blkx {
            let entry = entry.as_dictionary().ok_or("bad blkx entry")?;
            let name = entry
                .get("Name")
                .and_then(|n| n.as_string())
                .unwrap_or("")
                .to_string();
            let mish = entry
                .get("Data")
                .and_then(|d| d.as_data())
                .ok_or("blkx entry has no data")?;
            if mish.len() < 0xcc || &mish[0..4] != b"mish" {
                return Err("bad mish block".to_string());
            }
            let first_sector = be64(&mish[8..]);
            let data_offset = be64(&mish[24..]);
            let count = be32(&mish[0xc8..]) as usize;
            if mish.len() < 0xcc + count * 40 {
                return Err("bad mish block".to_string());
            }
            for i in 0..count {
                let c = &mish[0xcc + i * 40..0xcc + (i + 1) * 40];
                let kind = be32(c);
                if kind == 0xffffffff || kind == 0x7ffffffe {
                    continue;
                }
                if be64(&c[16..]) > 1 << 24 {
                    return Err("UDIF run too large".to_string());
                }
                runs.push(Run {
                    kind,
                    sector: first_sector + be64(&c[8..]),
                    sector_count: be64(&c[16..]),
                    offset: data_fork_offset + data_offset + be64(&c[24..]),
                    length: be64(&c[32..]),
                });
            }
            partitions.push(Partition { name, first_sector });
        }
        runs.sort_by_key(|r| r.sector);
        let sector_count = runs.last().map(|r| r.sector + r.sector_count).unwrap_or(0);
        Ok(UdifImage {
            inner,
            runs,
            partitions,
            sector_count,
            cache: RefCell::new(VecDeque::new()),
        })
    }

    pub fn len(&self) -> u64 {
        self.sector_count * SECTOR
    }

    fn decode_run(&self, idx: usize) -> io::Result<Vec<u8>> {
        let run = &self.runs[idx];
        let size = (run.sector_count * SECTOR) as usize;
        match run.kind {
            // Zero-filled or unallocated.
            0x00000000 | 0x00000002 => Ok(vec![0; size]),
            // Raw.
            0x00000001 => {
                let mut buf = vec![0u8; size];
                self.inner.read_exact_at(&mut buf, run.offset)?;
                Ok(buf)
            }
            // zlib.
            0x80000005 => {
                let mut compressed = vec![0u8; run.length as usize];
                self.inner.read_exact_at(&mut compressed, run.offset)?;
                let mut out = Vec::with_capacity(size);
                flate2::read::ZlibDecoder::new(&compressed[..]).read_to_end(&mut out)?;
                out.resize(size, 0);
                Ok(out)
            }
            kind => Err(io::Error::other(format!(
                "Unsupported UDIF chunk type {kind:#x}"
            ))),
        }
    }

    fn with_run<T>(&self, idx: usize, f: impl FnOnce(&[u8]) -> T) -> io::Result<T> {
        let mut cache = self.cache.borrow_mut();
        if let Some(pos) = cache.iter().position(|(i, _)| *i == idx) {
            let entry = cache.remove(pos).unwrap();
            cache.push_front(entry);
        } else {
            let data = self.decode_run(idx)?;
            if cache.len() == CACHE_RUNS {
                cache.pop_back();
            }
            cache.push_front((idx, data));
        }
        Ok(f(&cache.front().unwrap().1))
    }
}

impl<R: ReadAt> ReadAt for UdifImage<R> {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<usize> {
        let len = (buf.len() as u64).min(self.len().saturating_sub(offset)) as usize;
        let mut done = 0;
        while done < len {
            let pos = offset + done as u64;
            let sector = pos / SECTOR;
            let idx = match self.runs.binary_search_by(|r| {
                if r.sector + r.sector_count <= sector {
                    std::cmp::Ordering::Less
                } else if r.sector > sector {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            }) {
                Ok(idx) => idx,
                Err(_) => {
                    // Gap between runs: reads as zeroes up to the next run.
                    buf[done] = 0;
                    done += 1;
                    continue;
                }
            };
            let run_start = self.runs[idx].sector * SECTOR;
            let within = (pos - run_start) as usize;
            done += self.with_run(idx, |data| {
                let n = (data.len() - within).min(len - done);
                buf[done..done + n].copy_from_slice(&data[within..within + n]);
                n
            })?;
        }
        Ok(len)
    }
}
