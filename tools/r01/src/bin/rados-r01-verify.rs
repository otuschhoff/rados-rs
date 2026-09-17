use std::path::Path;

fn main() {
    let mut arguments = std::env::args_os();
    let program = arguments.next().unwrap_or_default();
    let first = arguments.next();
    if first.as_deref() == Some(std::ffi::OsStr::new("source-digest")) {
        let Some(root) = arguments.next() else {
            usage(&program);
        };
        if arguments.next().is_some() {
            usage(&program);
        }
        match rados_r01_tools::source_digest(Path::new(&root)) {
            Ok(digest) => println!("{digest}"),
            Err(error) => fail(&error),
        }
        return;
    }
    if first.as_deref() == Some(std::ffi::OsStr::new("path-digest")) {
        let (Some(root), Some(path)) = (arguments.next(), arguments.next()) else {
            usage(&program);
        };
        if arguments.next().is_some() {
            usage(&program);
        }
        match rados_r01_tools::path_digest(Path::new(&root), Path::new(&path)) {
            Ok(digest) => println!("{digest}"),
            Err(error) => fail(&error),
        }
        return;
    }
    if first.as_deref() != Some(std::ffi::OsStr::new("verify")) {
        usage(&program);
    }
    let (Some(root), Some(report)) = (arguments.next(), arguments.next()) else {
        usage(&program);
    };
    if arguments.next().is_some() {
        usage(&program);
    }
    if let Err(error) = rados_r01_tools::verify_report_file(Path::new(&root), Path::new(&report)) {
        eprintln!("rados-r01-verify: {error}");
        std::process::exit(1);
    }
    println!("R01 bridge report verification passed");
}

fn usage(program: &std::ffi::OsStr) -> ! {
    eprintln!(
        "usage: {} verify ROOT REPORT | source-digest ROOT | path-digest ROOT PATH",
        Path::new(program).display()
    );
    std::process::exit(2);
}

fn fail(error: &str) -> ! {
    eprintln!("rados-r01-verify: {error}");
    std::process::exit(1);
}
