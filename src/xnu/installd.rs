/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! A minimal installd: the `com.apple.mobile.installd` server behind
//! MobileInstallation. SpringBoard builds its home screen from
//! `MobileInstallationLookup`, so without it the home screen is empty.
//!
//! Requests and replies are one MIG routine, `migSendBlob`: a binary plist
//! out of line, plus the client's reply port. Only the system apps in the
//! firmware's /Applications are installed.

use super::mach::le;
use super::{write_bytes, Kernel};
use crate::firmware::Firmware;
use plist::{Dictionary, Value};

const SEND_BLOB: u32 = 0xac7450;
const MACH_MSG_TYPE_MOVE_SEND: u32 = 17;

pub fn msg(k: &mut Kernel, msg: &[u8]) -> Option<Vec<u8>> {
    if msg.len() < 0x40 || le(msg, 0) & 0x8000_0000 == 0 || le(msg, 20) != SEND_BLOB {
        return None;
    }
    let (addr, len, reply_port) = (le(msg, 0x1c), le(msg, 0x20), le(msg, 0x28));
    let request =
        plist::Value::from_reader(std::io::Cursor::new(super::read_bytes(&k.mem, addr, len)))
            .ok()?;
    let request = request.as_dictionary()?;
    let command = request.get("Command").and_then(Value::as_string);
    log_dbg!("xnu: installd {:?}", command);
    let mut response = Dictionary::new();
    if command == Some("Lookup") {
        let wanted = request
            .get("ClientOptions")
            .and_then(Value::as_dictionary)
            .and_then(|o| o.get("ApplicationType"))
            .and_then(Value::as_string);
        let apps = if matches!(wanted, None | Some("System") | Some("Any")) {
            system_apps(&k.fw)
        } else {
            Dictionary::new()
        };
        response.insert("LookupResult".into(), Value::Dictionary(apps));
    }
    response.insert("Status".into(), "Complete".into());
    let mut data = Vec::new();
    Value::Dictionary(response)
        .to_writer_binary(&mut data)
        .ok()?;

    let out = k.vm_allocate(0, data.len() as u32, 0, 1, "installd")?;
    write_bytes(&mut k.mem, out, &data);
    let mut m = Vec::with_capacity(0x40);
    for w in [
        0x8000_0000 | MACH_MSG_TYPE_MOVE_SEND,
        0x40,
        0,
        reply_port,
        0,
        SEND_BLOB,
        // Two descriptors: the blob, then a port descriptor.
        2,
        out,
        data.len() as u32,
        // Out-of-line, virtual copy.
        1 << 24 | 1 << 8,
        0,
        0,
        MACH_MSG_TYPE_MOVE_SEND << 16,
        // NDR record: little-endian integers.
        0,
        1,
        data.len() as u32,
    ] {
        m.extend(w.to_le_bytes());
    }
    if let Some(p) = k.ipc.ports.get_mut(&reply_port) {
        p.queue.push_back(m);
    }
    None
}

/// The apps in /Applications by bundle identifier: each Info.plist, plus
/// its path and type.
fn system_apps(fw: &Firmware) -> Dictionary {
    let mut apps = Dictionary::new();
    let Some(dir) = fw.volume.lookup("/Applications", true) else {
        return apps;
    };
    for app in fw.volume.children(dir.id) {
        if !app.name.ends_with(".app") {
            continue;
        }
        let path = format!("/Applications/{}", app.name);
        let Ok(bytes) = Kernel::read_fw_file(fw, &format!("{path}/Info.plist")) else {
            continue;
        };
        let Some(Value::Dictionary(mut info)) =
            plist::Value::from_reader(std::io::Cursor::new(bytes)).ok()
        else {
            continue;
        };
        let Some(id) = info
            .get("CFBundleIdentifier")
            .and_then(Value::as_string)
            .map(str::to_string)
        else {
            continue;
        };
        info.insert("Path".into(), path.into());
        info.insert("ApplicationType".into(), "System".into());
        apps.insert(id, Value::Dictionary(info));
    }
    apps
}
