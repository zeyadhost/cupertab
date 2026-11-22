/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */
//! Scripted input for testing firmware boots without a window.
//!
//! `TOUCHHLE_XNU_INPUT` is a comma-separated list of `seconds:action`, timed
//! on the guest clock: `home`, `swipe` (slide to unlock), `tap:x:y` (in
//! 0..1 screen units) or `dump:path` (the LCD's surface as a PPM).

use super::iokit::TouchPhase;
use super::{read_bytes, Kernel};

pub enum Action {
    Home,
    Touch(TouchPhase, (f32, f32)),
    Dump(String),
}

pub fn parse() -> Vec<(u64, Action)> {
    let Ok(script) = std::env::var("TOUCHHLE_XNU_INPUT") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for step in script.split(',') {
        let parts: Vec<&str> = step.split(':').collect();
        let Some(t) = parts.first().and_then(|t| t.parse::<f64>().ok()) else {
            continue;
        };
        let t = (t * 1e9) as u64;
        let f = |i: usize| parts.get(i).and_then(|v| v.parse::<f32>().ok()).unwrap_or(0.5);
        match parts.get(1).copied() {
            Some("home") => out.push((t, Action::Home)),
            Some("dump") => out.push((t, Action::Dump(parts[2..].join(":")))),
            Some("tap") => {
                out.push((t, Action::Touch(TouchPhase::Down, (f(2), f(3)))));
                out.push((t + 100_000_000, Action::Touch(TouchPhase::Up, (f(2), f(3)))));
            }
            Some("swipe") => {
                let n = 27;
                for i in 0..=n {
                    let x = 0.19 + (0.94 - 0.19) * i as f32 / n as f32;
                    let phase = match i {
                        0 => TouchPhase::Down,
                        i if i == n => TouchPhase::Up,
                        _ => TouchPhase::Move,
                    };
                    out.push((t + i as u64 * 30_000_000, Action::Touch(phase, (x, 0.9))));
                }
            }
            _ => continue,
        }
    }
    out.sort_by_key(|s| s.0);
    out.reverse();
    out
}

impl Kernel {
    pub(super) fn run_test_input(&mut self) {
        let now = self.now_ns();
        while self.test_input.last().is_some_and(|s| s.0 <= now) {
            let (_, action) = self.test_input.pop().unwrap();
            match action {
                Action::Home => {
                    self.hid_button(0x0c, 0x40, true);
                    self.hid_button(0x0c, 0x40, false);
                }
                Action::Touch(phase, pos) => self.hid_touch(phase, pos),
                Action::Dump(path) => self.dump_screen(&path),
            }
            log!("xnu: test input at {:.1}s", now as f64 / 1e9);
        }
    }

    fn dump_screen(&self, path: &str) {
        let Some(s) = self
            .iokit
            .presented_surface
            .checked_sub(1)
            .and_then(|i| self.iokit.surfaces.get(i as usize))
        else {
            log!("xnu: no surface to dump");
            return;
        };
        let mut out = format!("P6 {} {} 255\n", s.width, s.height).into_bytes();
        for y in 0..s.height {
            let row = read_bytes(&self.mem, s.addr + y * s.bytes_per_row, s.width * 4);
            for b in row.chunks(4) {
                out.extend([b[2], b[1], b[0]]);
            }
        }
        std::fs::write(path, out).ok();
    }
}
