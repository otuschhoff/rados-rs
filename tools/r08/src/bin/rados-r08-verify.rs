use std::path::Path;

fn main() {
    let mut arguments = std::env::args_os();
    let program = arguments.next().unwrap_or_default();
    let (Some(root), Some(report)) = (arguments.next(), arguments.next()) else {
        usage(&program)
    };
    let remainder = arguments.collect::<Vec<_>>();
    let result = match remainder.as_slice() {
        [] => rados_r08_tools::verify_report_file(Path::new(&root), Path::new(&report)),
        [rust_binary, go_root, go_binary, native_binary] => {
            rados_r08_tools::verify_report_artifacts(
                Path::new(&root),
                Path::new(&report),
                Path::new(rust_binary),
                Path::new(go_root),
                Path::new(go_binary),
                Path::new(native_binary),
            )
        }
        _ => usage(&program),
    };
    if let Err(error) = result {
        eprintln!("rados-r08-verify: {error}");
        std::process::exit(1);
    }
    println!("R08 report verification passed");
}

fn usage(program: &std::ffi::OsStr) -> ! {
    eprintln!(
        "usage: {} ROOT REPORT [RUST_BINARY GO_ROOT GO_BINARY NATIVE_BINARY]",
        Path::new(program).display()
    );
    std::process::exit(2)
}
