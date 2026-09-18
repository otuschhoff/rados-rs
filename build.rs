use std::path::Path;

fn main() {
    println!("cargo::rustc-check-cfg=cfg(rados_packaged_source)");
    if Path::new(".cargo_vcs_info.json").is_file() {
        println!("cargo::rustc-cfg=rados_packaged_source");
    }
}
