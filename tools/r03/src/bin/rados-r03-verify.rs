use std::path::Path;

fn main() {
    let mut arguments = std::env::args_os();
    let program = arguments.next().unwrap_or_default();
    let Some(command) = arguments.next() else {
        usage(&program)
    };
    match command.to_str() {
        Some("verify") => {
            let (Some(root), Some(report)) = (arguments.next(), arguments.next()) else {
                usage(&program)
            };
            if arguments.next().is_some() {
                usage(&program);
            }
            if let Err(error) =
                rados_r03_tools::verify_report_file(Path::new(&root), Path::new(&report))
            {
                fail(&error);
            }
            println!("R03 bridge report verification passed");
        }
        Some("rust-source-digest" | "go-source-digest") => {
            let Some(root) = arguments.next() else {
                usage(&program)
            };
            if arguments.next().is_some() {
                usage(&program);
            }
            let result = if command == "rust-source-digest" {
                rados_r03_tools::rust_source_digest(Path::new(&root))
            } else {
                rados_r03_tools::go_source_digest(Path::new(&root))
            };
            match result {
                Ok(value) => println!("{value}"),
                Err(error) => fail(&error),
            }
        }
        Some("path-digest") => {
            let (Some(root), Some(path)) = (arguments.next(), arguments.next()) else {
                usage(&program)
            };
            if arguments.next().is_some() {
                usage(&program);
            }
            match rados_r03_tools::path_digest(Path::new(&root), Path::new(&path)) {
                Ok(value) => println!("{value}"),
                Err(error) => fail(&error),
            }
        }
        _ => usage(&program),
    }
}

fn usage(program: &std::ffi::OsStr) -> ! {
    eprintln!(
        "usage: {} verify ROOT REPORT | rust-source-digest ROOT | go-source-digest ROOT | path-digest ROOT PATH",
        Path::new(program).display()
    );
    std::process::exit(2)
}
fn fail(error: &str) -> ! {
    eprintln!("rados-r03-verify: {error}");
    std::process::exit(1)
}
