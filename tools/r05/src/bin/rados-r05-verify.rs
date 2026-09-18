use std::path::Path;

fn main() {
    let mut arguments = std::env::args_os();
    let program = arguments.next().unwrap_or_default();
    let Some(command) = arguments.next() else {
        usage(&program)
    };
    let result = match command.to_str() {
        Some("default-request") => {
            let Some(root) = arguments.next() else {
                usage(&program)
            };
            if arguments.next().is_some() {
                usage(&program);
            }
            rados_r05_tools::default_request_json(Path::new(&root)).map(|value| print!("{value}"))
        }
        Some("verify") => {
            let (Some(root), Some(report)) = (arguments.next(), arguments.next()) else {
                usage(&program)
            };
            if arguments.next().is_some() {
                usage(&program);
            }
            rados_r05_tools::verify_report_file(Path::new(&root), Path::new(&report))
                .map(|()| println!("R05 bridge report verification passed"))
        }
        Some("rust-source-digest" | "go-source-digest") => {
            let Some(root) = arguments.next() else {
                usage(&program)
            };
            if arguments.next().is_some() {
                usage(&program);
            }
            if command == "rust-source-digest" {
                rados_r05_tools::rust_source_digest(Path::new(&root))
            } else {
                rados_r05_tools::go_source_digest(Path::new(&root))
            }
            .map(|value| println!("{value}"))
        }
        Some("path-digest") => {
            let (Some(root), Some(path)) = (arguments.next(), arguments.next()) else {
                usage(&program)
            };
            if arguments.next().is_some() {
                usage(&program);
            }
            rados_r05_tools::path_digest(Path::new(&root), Path::new(&path))
                .map(|value| println!("{value}"))
        }
        _ => usage(&program),
    };
    if let Err(error) = result {
        eprintln!("rados-r05-verify: {error}");
        std::process::exit(1);
    }
}

fn usage(program: &std::ffi::OsStr) -> ! {
    eprintln!(
        "usage: {} default-request ROOT | verify ROOT REPORT | rust-source-digest ROOT | go-source-digest ROOT | path-digest ROOT PATH",
        Path::new(program).display()
    );
    std::process::exit(2)
}
