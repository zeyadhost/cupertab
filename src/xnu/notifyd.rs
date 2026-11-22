/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! A minimal notifyd: the `com.apple.system.notification_center` MIG server
//! behind libnotify (`notify_post`, `notify_register_*`, `notify_get_state`).
//!
//! Every name has a 64-bit state, 0 until set, except the thermal mitigation
//! thresholds thermalmonitord would publish. Posting a name bumps its counter
//! in the shared memory `notify_check` reads, marks its check tokens changed
//! and sends an empty message to each registered Mach port, with the client's
//! token as the message ID.

use super::mach::{le, reply, KERN_SUCCESS, MIG_BAD_ID};
use super::vfs::Shm;
use super::{read_bytes, write_u32, Kernel};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

const SHM_NAME: &str = "apple.shm.notification_center";
const SHM_SIZE: u32 = 0x1000;

const SUBSYSTEM: u32 = 78945668;
const NOTIFY_STATUS_OK: u32 = 0;
const NOTIFY_STATUS_INVALID_TOKEN: u32 = 2;

enum Delivery {
    Plain,
    Check { changed: bool },
    MachPort { port: u32, client_token: u32 },
}

struct Registration {
    name: String,
    delivery: Delivery,
}

#[derive(Default)]
pub struct Notifyd {
    states: HashMap<String, u64>,
    tokens: HashMap<u32, Registration>,
    next_token: u32,
    /// Check counter slots in the shared memory, by name.
    slots: HashMap<String, u32>,
    shm: Option<Rc<RefCell<Shm>>>,
}

/// `OSThermalNotificationLevel` at which each mitigation starts, as
/// thermalmonitord publishes them. SpringBoard shows its overheating screen
/// once the current level (`com.apple.system.thermalstatus`) reaches a
/// threshold, so they can't read as 0.
fn initial_state(name: &str) -> u64 {
    const BEHAVIORS: [&str; 9] = [
        "70percenttorch",
        "70percentbacklight",
        "50percenttorch",
        "50percentbacklight",
        "disabletorch",
        "25percentbacklight",
        "disablemapshalo",
        "appterminate",
        "devicerestart",
    ];
    name.strip_prefix("com.apple.system.thermalmitigation.")
        .and_then(|b| BEHAVIORS.iter().position(|&x| x == b))
        .map_or(0, |i| i as u64 + 1)
}

impl Notifyd {
    fn register(&mut self, name: String, delivery: Delivery) -> u32 {
        let token = self.next_token;
        self.next_token += 1;
        self.tokens.insert(token, Registration { name, delivery });
        token
    }

    fn state(&self, name: &str) -> u64 {
        self.states
            .get(name)
            .copied()
            .unwrap_or_else(|| initial_state(name))
    }
}

/// The shared memory libnotify maps to read check counters, created on the
/// first `notify_register_check`.
fn shm(k: &mut Kernel) -> Rc<RefCell<Shm>> {
    if let Some(shm) = &k.ipc.notifyd.shm {
        return shm.clone();
    }
    let shm = Rc::new(RefCell::new(Shm {
        data: vec![0; SHM_SIZE as usize],
    }));
    k.vfs.shm.insert(SHM_NAME.to_string(), shm.clone());
    k.ipc.notifyd.shm = Some(shm.clone());
    shm
}

/// Bumps a name's check counter, in the shared memory and every mapping.
fn bump(k: &mut Kernel, name: &str) {
    let (Some(&slot), Some(shm)) = (k.ipc.notifyd.slots.get(name), &k.ipc.notifyd.shm) else {
        return;
    };
    let o = slot as usize * 4;
    let value = {
        let data = &mut shm.borrow_mut().data;
        let value = u32::from_le_bytes(data[o..o + 4].try_into().unwrap()).wrapping_add(1);
        data[o..o + 4].copy_from_slice(&value.to_le_bytes());
        value
    };
    for m in &k.vfs.shm_maps {
        if Rc::ptr_eq(&m.shm, shm) && slot * 4 + 4 <= m.len {
            write_u32(&mut k.mem, m.addr + slot * 4, value);
        }
    }
}

/// The name, sent out-of-line in the first descriptor.
fn name(k: &Kernel, msg: &[u8]) -> Option<String> {
    if le(msg, 0) & 0x80000000 == 0 || msg.len() < 40 || msg[39] != 1 {
        return None;
    }
    let bytes = read_bytes(&k.mem, le(msg, 28), le(msg, 32).min(0x400));
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    Some(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

pub fn msg(k: &mut Kernel, msg: &[u8]) -> Option<Vec<u8>> {
    let id = le(msg, 20);
    let descs = if le(msg, 0) & 0x80000000 != 0 && msg.len() >= 28 {
        le(msg, 24) as usize
    } else {
        0
    };
    // Integer arguments after the NDR record and the name's count.
    let body = 28 + 12 * descs + 12;
    let arg = |i: usize| {
        msg.get(body + 4 * i..body + 4 * i + 4)
            .map_or(0, |b| le(b, 0))
    };
    let Some(name) = name(k, msg) else {
        return token_msg(k, msg, id.wrapping_sub(SUBSYSTEM));
    };
    if k.trace {
        log!("xnu: notifyd {} {name:?}", id.wrapping_sub(SUBSYSTEM));
    }
    let routine = id.wrapping_sub(SUBSYSTEM);
    if routine == 0 {
        bump(k, &name);
    } else if routine == 2 {
        shm(k);
    }
    let n = &mut k.ipc.notifyd;
    let words: &[u32] = &match routine {
        // _notify_server_post(name, &status)
        0 => {
            let mut sends = Vec::new();
            for r in n.tokens.values_mut().filter(|r| r.name == name) {
                match &mut r.delivery {
                    Delivery::Check { changed } => *changed = true,
                    &mut Delivery::MachPort { port, client_token } => {
                        sends.push((port, client_token))
                    }
                    Delivery::Plain => (),
                }
            }
            for (port, client_token) in sends {
                if let Some(p) = k.ipc.ports.get_mut(&port) {
                    let mut m = Vec::with_capacity(24);
                    for w in [0x12, 24, port, 0, 0, client_token] {
                        m.extend(u32::to_le_bytes(w));
                    }
                    p.queue.push_back(m);
                }
            }
            vec![KERN_SUCCESS, NOTIFY_STATUS_OK]
        }
        // _notify_server_register_plain(name, &token, &status)
        1 => {
            let token = n.register(name, Delivery::Plain);
            vec![KERN_SUCCESS, token, NOTIFY_STATUS_OK]
        }
        // _notify_server_register_check(name, &size, &slot, &token, &status)
        2 => {
            let next = n.slots.len() as u32;
            let slot = match n.slots.get(&name) {
                Some(&slot) => slot,
                None if next < SHM_SIZE / 4 => {
                    n.slots.insert(name.clone(), next);
                    next
                }
                None => u32::MAX,
            };
            let token = n.register(name, Delivery::Check { changed: true });
            vec![KERN_SUCCESS, SHM_SIZE, slot, token, NOTIFY_STATUS_OK]
        }
        // _notify_server_register_mach_port(name, port, token, &client_id,
        // &status)
        5 if descs >= 2 => {
            let port = le(msg, 40);
            let client_token = arg(0);
            let token = n.register(name, Delivery::MachPort { port, client_token });
            vec![KERN_SUCCESS, token, NOTIFY_STATUS_OK]
        }
        other => {
            log!("xnu: unhandled notifyd request {other} for {name:?}");
            vec![MIG_BAD_ID]
        }
    };
    Some(reply(msg, words, &[]))
}

/// Routines on a token, sent without a name.
fn token_msg(k: &mut Kernel, msg: &[u8], routine: u32) -> Option<Vec<u8>> {
    let arg = |i: usize| msg.get(32 + 4 * i..36 + 4 * i).map_or(0, |b| le(b, 0));
    let n = &mut k.ipc.notifyd;
    let token = arg(0);
    let Some(r) = n.tokens.get_mut(&token) else {
        log!("xnu: notifyd routine {routine} on unknown token {token}");
        let words: &[u32] = match routine {
            12 => &[KERN_SUCCESS, 0, NOTIFY_STATUS_INVALID_TOKEN],
            13 => &[KERN_SUCCESS, 0, 0, NOTIFY_STATUS_INVALID_TOKEN],
            _ => &[KERN_SUCCESS, NOTIFY_STATUS_INVALID_TOKEN],
        };
        return Some(reply(msg, words, &[]));
    };
    if k.trace {
        log!("xnu: notifyd {routine} on {:?}", r.name);
    }
    let words: &[u32] = &match routine {
        // _notify_server_cancel(token, &status)
        11 => {
            n.tokens.remove(&token);
            vec![KERN_SUCCESS, NOTIFY_STATUS_OK]
        }
        // _notify_server_check(token, &check, &status)
        12 => {
            let changed = match &mut r.delivery {
                Delivery::Check { changed } => std::mem::take(changed),
                _ => false,
            };
            vec![KERN_SUCCESS, changed as u32, NOTIFY_STATUS_OK]
        }
        // _notify_server_get_state(token, &state, &status)
        13 => {
            let name = r.name.clone();
            let state = n.state(&name);
            vec![
                KERN_SUCCESS,
                state as u32,
                (state >> 32) as u32,
                NOTIFY_STATUS_OK,
            ]
        }
        // _notify_server_set_state(token, state, &status)
        14 => {
            let state = arg(1) as u64 | (arg(2) as u64) << 32;
            let name = r.name.clone();
            n.states.insert(name, state);
            vec![KERN_SUCCESS, NOTIFY_STATUS_OK]
        }
        _ => {
            log!("xnu: unhandled notifyd routine {routine} on {:?}", r.name);
            vec![MIG_BAD_ID]
        }
    };
    Some(reply(msg, words, &[]))
}
