#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = rados::r04_integration::run_cli() {
        eprintln!("r04 live probe: {error}");
        std::process::exit(1);
    }
}
