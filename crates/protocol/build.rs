// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Compile the transport protobuf contract.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &["../../proto/kernel/v1/transport/v1/transport.proto"],
            &["../../proto"],
        )?;
    println!("cargo:rerun-if-changed=../../proto/kernel/v1/transport/v1/transport.proto");
    Ok(())
}
