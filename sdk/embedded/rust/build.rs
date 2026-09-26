use std::{env, path::PathBuf, process::Command};
fn run(cmd: &mut Command) {
    let status = cmd
        .status()
        .expect("could not run the configured C toolchain");
    assert!(status.success(), "C toolchain command failed");
}
fn main() {
    for name in ["ORBIT_CC", "ORBIT_AR", "ORBIT_CFLAGS"] {
        println!("cargo:rerun-if-env-changed={name}");
    }
    if env::var_os("CARGO_FEATURE_EXTERNAL_C").is_some() {
        return;
    }
    let target = env::var("TARGET").unwrap();
    let host = env::var("HOST").unwrap();
    let cc = env::var("ORBIT_CC").unwrap_or_else(|_| {
        assert_eq!(
            target, host,
            "cross compilation requires ORBIT_CC and ORBIT_AR, or external-c"
        );
        "cc".into()
    });
    let ar = env::var("ORBIT_AR").unwrap_or_else(|_| "ar".into());
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let mut objects = Vec::new();
    for name in [
        "grant", "json", "prepare", "jwks", "client", "wire", "storage",
    ] {
        let src = format!("../src/orbit_{name}.c");
        println!("cargo:rerun-if-changed={src}");
        let object = out.join(format!("{name}.o"));
        let mut cmd = Command::new(&cc);
        cmd.args([
            "-std=c11",
            "-Os",
            "-ffunction-sections",
            "-fdata-sections",
            "-I../include",
            "-c",
            &src,
            "-o",
        ])
        .arg(&object);
        if let Ok(flags) = env::var("ORBIT_CFLAGS") {
            cmd.args(flags.split_whitespace());
        }
        run(&mut cmd);
        objects.push(object);
    }
    println!("cargo:rerun-if-changed=../include");
    let object = out.join("layout.o");
    let mut cmd = Command::new(&cc);
    cmd.args([
        "-std=c11",
        "-Os",
        "-ffunction-sections",
        "-I../include",
        "-c",
        "src/layout.c",
        "-o",
    ])
    .arg(&object);
    if let Ok(flags) = env::var("ORBIT_CFLAGS") {
        cmd.args(flags.split_whitespace());
    }
    run(&mut cmd);
    objects.push(object);
    println!("cargo:rerun-if-changed=src/layout.c");
    let archive = out.join("liborbit_embedded.a");
    run(Command::new(ar).arg("crs").arg(&archive).args(objects));
    println!("cargo:rustc-link-search=native={}", out.display());
    println!("cargo:rustc-link-lib=static=orbit_embedded");
}
