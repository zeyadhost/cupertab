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
//! out of line, plus the client's reply port. The system apps are the ones in
//! the firmware's /Applications; user apps are the IPAs installed into
//! /var/mobile/Applications on the data partition.

use super::mach::le;
use super::{write_bytes, Kernel};
use crate::firmware::Firmware;
use plist::{Dictionary, Value};
use std::io::Read;
use std::path::Path;

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
        let mut apps = Dictionary::new();
        if matches!(wanted, None | Some("System") | Some("Any")) {
            apps.extend(system_apps(&k.fw));
        }
        if matches!(wanted, None | Some("User") | Some("Any")) {
            apps.extend(user_apps(k));
        }
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
        p.queue.push_back((m, 1, Vec::new()));
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

/// The installed IPAs: each container in /var/mobile/Applications holds one
/// app bundle.
fn user_apps(k: &Kernel) -> Dictionary {
    let mut apps = Dictionary::new();
    let root = k.vfs.canonical(&k.fw, "/var/mobile/Applications");
    let Ok(containers) = std::fs::read_dir(k.vfs.host_path(&root)) else {
        return apps;
    };
    for container in containers.flatten() {
        let Some(uuid) = container.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(container.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !name.ends_with(".app") {
                continue;
            }
            let Ok(bytes) = std::fs::read(entry.path().join("Info.plist")) else {
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
            let container = format!("{root}/{uuid}");
            info.insert("Path".into(), format!("{container}/{name}").into());
            info.insert("Container".into(), container.into());
            info.insert("ApplicationType".into(), "User".into());
            apps.insert(id, Value::Dictionary(info));
        }
    }
    apps
}

/// Unpacks an IPA's `Payload/<name>.app` into a container in
/// /var/mobile/Applications named after the bundle, as installd would.
/// Returns the bundle's name.
pub fn install_ipa(k: &Kernel, ipa: &Path) -> Result<String, String> {
    let file = std::fs::File::open(ipa).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let app = zip
        .file_names()
        .filter_map(|n| n.strip_prefix("Payload/")?.split('/').next())
        .find(|a| a.ends_with(".app"))
        .map(str::to_string)
        .ok_or("no Payload/*.app in the IPA")?;

    // A stable container name, so reinstalling an app keeps its documents.
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    app.hash(&mut h);
    let a = h.finish();
    (a, &app).hash(&mut h);
    let b = h.finish();
    let uuid = format!(
        "{:08X}-{:04X}-{:04X}-{:04X}-{:012X}",
        a >> 32,
        (a >> 16) & 0xffff,
        a & 0xffff,
        b >> 48,
        b & 0xffff_ffff_ffff
    );
    let container = k.vfs.host_path(
        &k.vfs
            .canonical(&k.fw, &format!("/var/mobile/Applications/{uuid}")),
    );
    for dir in ["Documents", "Library/Preferences", "Library/Caches", "tmp"] {
        std::fs::create_dir_all(container.join(dir)).map_err(|e| e.to_string())?;
    }
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let Some(rel) = entry
            .enclosed_name()
            .and_then(|p| p.strip_prefix("Payload").ok())
            .map(Path::to_path_buf)
        else {
            continue;
        };
        if !rel.starts_with(&app) {
            continue;
        }
        // enclosed_name allows inner "..", which would leave the bundle once
        // the Payload prefix is stripped.
        if rel
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(format!("bad path in the IPA: {}", rel.display()));
        }
        let out = container.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;
            continue;
        }
        if let Some(parent) = out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(|e| e.to_string())?;
        std::fs::write(&out, data).map_err(|e| e.to_string())?;
    }
    Ok(app)
}
