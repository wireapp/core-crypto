fn main() {
    println!("cargo::rustc-check-cfg=cfg(ci)");
    // detects when running in Github action
    if let Ok("true") = std::env::var("CI").as_deref() {
        println!("cargo:rustc-cfg=ci")
    }
}
