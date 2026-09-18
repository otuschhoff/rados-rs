fn main() {
    if let Err(error) = rados::r05_integration::run_cli() {
        eprintln!("rados-r05-live: {error}");
        std::process::exit(1);
    }
}
