use std::path::Path;

fn main() {
    let mut arguments = std::env::args_os();
    let program = arguments.next().unwrap_or_default();
    let (Some(root), Some(report), None) = (arguments.next(), arguments.next(), arguments.next())
    else {
        eprintln!("usage: {} ROOT REPORT", Path::new(&program).display());
        std::process::exit(2);
    };
    if let Err(error) =
        rados_r08_tools::verify_fuzz_report_file(Path::new(&root), Path::new(&report))
    {
        eprintln!("rados-r08-verify-fuzz: {error}");
        std::process::exit(1);
    }
    println!("R08 fuzz report verification passed");
}
