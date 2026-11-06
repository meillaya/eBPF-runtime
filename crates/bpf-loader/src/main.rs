// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Load the sensors and print what attached.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut json = false;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" => json = true,
            "--help" | "-h" => {
                println!("bpf-loader [--json]");
                println!();
                println!("Loads every embedded sensor and prints the attach result.");
                println!("Run as root or with CAP_BPF and CAP_PERFMON.");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("bpf-loader: unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }

    let sensors = match bpf_loader::load(&[]) {
        Ok(sensors) => sensors,
        Err(error) => {
            eprintln!("bpf-loader: {error}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        println!("{}", sensors.coverage_as_json());
        return ExitCode::SUCCESS;
    }

    println!(
        "{:<9} {:<9} {:>3} attached  {:>3} failed  {:>3} skipped",
        "sensor", "status", "n", "n", "n"
    );
    let mut failed = false;
    for sensor in &sensors.coverage.sensors {
        println!(
            "{:<9} {:<9} {:>3}         {:>3}         {:>3}",
            sensor.name,
            match sensor.status {
                bpf_loader::SensorStatus::Capable => "capable",
                bpf_loader::SensorStatus::Degraded => "degraded",
                bpf_loader::SensorStatus::Blocked => "blocked",
            },
            sensor.programs.len(),
            sensor.errors.len(),
            sensor.skipped.len()
        );
        for error in &sensor.errors {
            eprintln!("  {}: {error}", sensor.name);
            failed = true;
        }
        if sensor.status == bpf_loader::SensorStatus::Blocked {
            failed = true;
        }
    }

    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
