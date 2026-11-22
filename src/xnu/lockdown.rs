/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Unix-domain sockets, the lockdownd service behind
//! `/var/run/lockdown.sock` and launchd's job socket.
//!
//! liblockdown frames each message as a 4-byte big-endian length followed by
//! a property list, and parses replies in any plist format. Only the
//! `GetValue` queries that local clients make (device identity and
//! activation state) are answered with data.

use crate::firmware::IpswInfo;
use plist::{Dictionary, Value};
use std::cell::RefCell;
use std::collections::VecDeque;

pub const LOCKDOWN_SOCKET: &str = "/var/run/lockdown.sock";
pub const LAUNCHD_SOCKET: &str = "/var/tmp/launchd/sock";

pub enum Service {
    Lockdownd(Lockdownd),
    Launchd,
}

/// A stream socket. Writes go to the connected service, whose replies wait
/// in `rx` until the guest reads them.
#[derive(Default)]
pub struct Socket {
    pub service: Option<Service>,
    rx: VecDeque<u8>,
    tx: Vec<u8>,
}

impl Socket {
    pub fn readable(&self) -> bool {
        !self.rx.is_empty()
    }

    /// Copies queued bytes without consuming them, for `MSG_PEEK`.
    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.rx.len());
        for (b, v) in buf.iter_mut().zip(self.rx.iter()) {
            *b = *v;
        }
        n
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.rx.len());
        for (b, v) in buf.iter_mut().zip(self.rx.drain(..n)) {
            *b = v;
        }
        n
    }

    pub fn write(&mut self, buf: &[u8]) -> usize {
        if let Some(Service::Launchd) = self.service {
            self.tx.extend_from_slice(buf);
            launchd_frames(&mut self.tx, &mut self.rx);
        } else if let Some(Service::Lockdownd(service)) = &self.service {
            self.tx.extend_from_slice(buf);
            while self.tx.len() >= 4 {
                let len = u32::from_be_bytes(self.tx[..4].try_into().unwrap()) as usize;
                if self.tx.len() < 4 + len {
                    break;
                }
                let msg: Vec<u8> = self.tx.drain(..4 + len).skip(4).collect();
                let reply = service.handle(&msg);
                let mut out = Vec::new();
                Value::Dictionary(reply).to_writer_xml(&mut out).unwrap();
                self.rx.extend((out.len() as u32).to_be_bytes());
                self.rx.extend(out);
            }
        }
        buf.len()
    }
}

/// A launch_data tree. liblaunch packs each node as 24 little-endian bytes
/// (type, value, string length or child count), then its payload: string
/// bytes padded to 8 with a NUL, or a slot per child followed by the
/// children. A dictionary's children alternate keys and values.
enum LaunchData {
    Dict(Vec<(String, LaunchData)>),
    Str(String),
    Int(i64),
    Errno(u64),
    Other,
}

const LAUNCH_DICTIONARY: u64 = 1;
const LAUNCH_ARRAY: u64 = 2;
const LAUNCH_INTEGER: u64 = 4;
const LAUNCH_STRING: u64 = 7;
const LAUNCH_OPAQUE: u64 = 8;
const LAUNCH_ERRNO: u64 = 9;

fn u64_at(b: &[u8], o: usize) -> u64 {
    b.get(o..o + 8)
        .map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap()))
}

/// Unpacks the node at `at`, returning it and the offset after it.
fn unpack(b: &[u8], at: usize) -> Option<(LaunchData, usize)> {
    let (ty, value, n) = (u64_at(b, at), u64_at(b, at + 8), u64_at(b, at + 16));
    let n = usize::try_from(n).ok().filter(|&n| n <= b.len())?;
    let data = at.checked_add(24).filter(|&d| d <= b.len())?;
    Some(match ty {
        LAUNCH_DICTIONARY | LAUNCH_ARRAY => {
            let mut p = data + 8 * n;
            let mut items = Vec::new();
            for _ in 0..n {
                let (item, end) = unpack(b, p)?;
                items.push(item);
                p = end;
            }
            if ty == LAUNCH_ARRAY {
                return Some((LaunchData::Other, p));
            }
            let mut pairs = Vec::new();
            let mut items = items.into_iter();
            while let (Some(LaunchData::Str(k)), Some(v)) = (items.next(), items.next()) {
                pairs.push((k, v));
            }
            (LaunchData::Dict(pairs), p)
        }
        LAUNCH_STRING => {
            let s = b.get(data..data + n)?;
            let s = s.split(|&c| c == 0).next().unwrap_or(&[]);
            let s = String::from_utf8_lossy(s).into_owned();
            (LaunchData::Str(s), data + (n + 1).next_multiple_of(8))
        }
        LAUNCH_OPAQUE => (LaunchData::Other, data + n.next_multiple_of(8)),
        LAUNCH_INTEGER => (LaunchData::Int(value as i64), data),
        _ => (LaunchData::Other, data),
    })
}

fn pack(d: &LaunchData, out: &mut Vec<u8>) {
    let node = |out: &mut Vec<u8>, ty: u64, value: u64, n: u64| {
        for w in [ty, value, n] {
            out.extend(w.to_le_bytes());
        }
    };
    match d {
        LaunchData::Dict(pairs) => {
            node(out, LAUNCH_DICTIONARY, 0, 2 * pairs.len() as u64);
            out.resize(out.len() + 16 * pairs.len(), 0);
            for (k, v) in pairs {
                pack(&LaunchData::Str(k.clone()), out);
                pack(v, out);
            }
        }
        LaunchData::Str(s) => {
            node(out, LAUNCH_STRING, 0, s.len() as u64);
            out.extend(s.as_bytes());
            out.resize(out.len() + (s.len() + 1).next_multiple_of(8) - s.len(), 0);
        }
        LaunchData::Int(i) => node(out, LAUNCH_INTEGER, *i as u64, 0),
        LaunchData::Errno(e) => node(out, LAUNCH_ERRNO, *e, 0),
        LaunchData::Other => node(out, LAUNCH_ERRNO, 0, 0),
    }
}

/// launchd's job socket. Each message has a 16-byte header (magic, then the
/// total length) before its packed request, which names its command as a
/// string or as a dictionary's only key. Submitted jobs are remembered and
/// reported as running, but nothing is spawned for them.
fn launchd_frames(tx: &mut Vec<u8>, rx: &mut VecDeque<u8>) {
    thread_local! {
        // launchd's jobs outlive the connection that submitted them.
        static JOBS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }
    JOBS.with_borrow_mut(|jobs| launchd_frames_with(tx, rx, jobs));
}

fn launchd_frames_with(tx: &mut Vec<u8>, rx: &mut VecDeque<u8>, jobs: &mut Vec<String>) {
    const MAGIC: u64 = 0xd2fe_a023_66b3_9a41;
    const ESRCH: u64 = 3;
    // An arbitrary PID other than SpringBoard's own.
    const JOB_PID: i64 = 2;
    while tx.len() >= 16 {
        let len = u64_at(tx, 8) as usize;
        if u64_at(tx, 0) != MAGIC || len < 16 {
            tx.clear();
            return;
        }
        if tx.len() < len {
            return;
        }
        let msg: Vec<u8> = tx.drain(..len).skip(16).collect();
        let (command, arg) = match unpack(&msg, 0) {
            Some((LaunchData::Str(s), _)) => (s, None),
            Some((LaunchData::Dict(mut pairs), _)) if !pairs.is_empty() => {
                let (k, v) = pairs.swap_remove(0);
                (k, Some(v))
            }
            _ => (String::new(), None),
        };
        let label = |job: &LaunchData| match job {
            LaunchData::Dict(pairs) => pairs.iter().find_map(|(k, v)| match v {
                LaunchData::Str(s) if k == "Label" => Some(s.clone()),
                _ => None,
            }),
            LaunchData::Str(s) => Some(s.clone()),
            _ => None,
        };
        let job_label = arg.as_ref().and_then(label);
        let job = |l: String| {
            LaunchData::Dict(vec![
                ("Label".into(), LaunchData::Str(l)),
                ("PID".into(), LaunchData::Int(JOB_PID)),
            ])
        };
        log_dbg!("xnu: launchd {command:?} {job_label:?}");
        let reply = match command.as_str() {
            "SubmitJob" => {
                jobs.retain(|j| Some(j) != job_label.as_ref());
                jobs.extend(job_label);
                LaunchData::Errno(0)
            }
            "RemoveJob" => {
                jobs.retain(|j| Some(j) != job_label.as_ref());
                LaunchData::Errno(0)
            }
            "GetJob" => match job_label.filter(|l| jobs.contains(l)) {
                Some(l) => job(l),
                None => LaunchData::Errno(ESRCH),
            },
            "GetJobs" => {
                LaunchData::Dict(jobs.iter().map(|l| (l.clone(), job(l.clone()))).collect())
            }
            _ => LaunchData::Errno(0),
        };
        let mut out = Vec::new();
        pack(&reply, &mut out);
        rx.extend(MAGIC.to_le_bytes());
        rx.extend((16 + out.len() as u64).to_le_bytes());
        rx.extend(out);
    }
}

pub struct Lockdownd {
    values: Dictionary,
}

impl Lockdownd {
    pub fn new(info: &IpswInfo) -> Self {
        let mut values = Dictionary::new();
        let mut set = |k: &str, v: Value| {
            values.insert(k.to_string(), v);
        };
        set("ProductType", info.product_type.clone().into());
        set("ProductVersion", info.product_version.clone().into());
        set("BuildVersion", info.build.clone().into());
        set(
            "HardwareModel",
            info.board_config.to_ascii_uppercase().into(),
        );
        set("DeviceClass", "iPhone".into());
        set("DeviceName", "iPhone".into());
        set("CPUArchitecture", "armv6".into());
        set("SerialNumber", "touchHLE".into());
        set(
            "UniqueDeviceID",
            "0000000000000000000000000000000000000000".into(),
        );
        set("ActivationState", "Activated".into());
        set("ActivationStateAcknowledged", true.into());
        set("BrickState", false.into());
        Lockdownd { values }
    }

    fn handle(&self, msg: &[u8]) -> Dictionary {
        let mut reply = Dictionary::new();
        let Ok(Value::Dictionary(req)) = Value::from_reader(std::io::Cursor::new(msg)) else {
            reply.insert("Error".into(), "InvalidRequest".into());
            return reply;
        };
        let get = |k: &str| req.get(k).and_then(|v| v.as_string());
        let request = get("Request").unwrap_or("");
        log_dbg!(
            "xnu: lockdownd {request} {:?} {:?}",
            get("Domain"),
            get("Key")
        );
        reply.insert("Request".into(), request.into());
        for k in ["Domain", "Key"] {
            if let Some(v) = req.get(k) {
                reply.insert(k.into(), v.clone());
            }
        }
        match request {
            "QueryType" => {
                reply.insert("Type".into(), "com.apple.mobile.lockdown".into());
            }
            "GetValue" => {
                let domain = (get("Domain").is_none()).then_some(&self.values);
                match (get("Key"), domain) {
                    (None, Some(d)) => {
                        reply.insert("Value".into(), Value::Dictionary(d.clone()));
                    }
                    (None, None) => {
                        reply.insert("Value".into(), Value::Dictionary(Dictionary::new()));
                    }
                    (Some(key), d) => match d.and_then(|d| d.get(key)) {
                        Some(v) => {
                            reply.insert("Value".into(), v.clone());
                        }
                        None => {
                            log!("xnu: lockdownd has no value for {key:?}");
                            reply.insert("Error".into(), "MissingValue".into());
                        }
                    },
                }
            }
            "SetValue" | "RemoveValue" | "Goodbye" => (),
            _ => {
                log!("xnu: unhandled lockdownd request {request:?}");
                reply.insert("Error".into(), "InvalidRequest".into());
            }
        }
        reply
    }
}
