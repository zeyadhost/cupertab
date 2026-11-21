/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Unix-domain sockets and the lockdownd service behind
//! `/var/run/lockdown.sock`.
//!
//! liblockdown frames each message as a 4-byte big-endian length followed by
//! a property list, and parses replies in any plist format. Only the
//! `GetValue` queries that local clients make (device identity and
//! activation state) are answered with data.

use crate::firmware::IpswInfo;
use plist::{Dictionary, Value};
use std::collections::VecDeque;

pub const LOCKDOWN_SOCKET: &str = "/var/run/lockdown.sock";

/// A stream socket. Writes go to the connected service, whose replies wait
/// in `rx` until the guest reads them.
#[derive(Default)]
pub struct Socket {
    pub service: Option<Lockdownd>,
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
        if let Some(service) = &self.service {
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
