// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Privileged end-to-end test.
//!
//! Run this inside a container with CAP_BPF, CAP_PERFMON, and
//! CAP_SYS_ADMIN:
//!
//! ```text
//! cargo test -p runtime --test privileged -- --ignored --nocapture
//! ```
//!
//! The test loads the process sensor, runs `/bin/true`, and reads the
//! ring buffer until it sees the matching exec event. It is ignored by
//! default because an unprivileged host cannot load the object.

use std::time::{Duration, Instant};

use runtime::{decode, Clock};

#[test]
#[ignore = "requires root, CAP_BPF, and CAP_PERFMON"]
fn process_sensor_reports_a_real_exec() {
    let sensors = bpf_loader::load(&["process"]).expect("load process sensor");
    assert!(
        !sensors.sensors.is_empty(),
        "process sensor did not attach: {:?}",
        sensors.coverage
    );

    let (ring, events) = sensors.ring_reader().expect("ring reader");
    let clock = Clock::new();

    let mut child = std::process::Command::new("/bin/true")
        .spawn()
        .expect("spawn /bin/true");
    let _ = child.wait();

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut saw_exec = false;
    while Instant::now() < deadline && !saw_exec {
        ring.poll(Duration::from_millis(100)).expect("poll");
        for sample in events.try_iter() {
            let Ok(event) = decode(&sample.sensor, &sample.bytes, &clock) else {
                continue;
            };
            if event.kind == "ProcessExec"
                && event
                    .path
                    .as_deref()
                    .map(|path| path.ends_with("/true"))
                    .unwrap_or(false)
            {
                saw_exec = true;
                break;
            }
        }
    }

    assert!(saw_exec, "no ProcessExec event for /bin/true");
}
