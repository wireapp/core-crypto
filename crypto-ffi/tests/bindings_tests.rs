cfg_if::cfg_if! {
    if #[cfg(feature = "mobile")] {
        // #[test]
        // FIXME: This is weird, UniFFI support is undocumented and weird. I guess no tests for now
        // fn uniffi_foreign_language_testcase_kotlin() -> uniffi::deps::anyhow::Result<()> {
        //     const JNA_DOWNLOAD_ROOT: &str = "https://repo1.maven.org/maven2/net/java/dev/jna/jna";
        //     const JNA_VERSION: &str = "5.12.1";
        //     let pkg_dir = std::env::var("CARGO_MANIFEST_DIR").expect("Missing $CARGO_MANIFEST_DIR, cannot build tests for generated bindings");
        //     // Download JNA and put it in classpath
        //     if !std::env::var("CLASSPATH").is_ok() {
        //         let mut out: std::path::PathBuf = std::env::var("OUT_DIR").expect("Missing $OUT_DIR, cannot save JNA dependency").into();
        //         let file_name = format!("jna-{JNA_VERSION}.jar");
        //         let download_url = format!("{JNA_DOWNLOAD_ROOT}/{JNA_VERSION}/{file_name}");
        //         out.push(file_name);
        //         let res = attohttpc::get(&download_url).send()?;
        //         let file = std::fs::File::create(out.clone())?;
        //         res.write_to(file)?;

        //         std::env::set_var("CLASSPATH", out);
        //     }

        //     uniffi::testing::run_foreign_language_testcase(&pkg_dir, &["./src/CoreCrypto.udl"], "./bindings/kt/wire/CoreCrypto.test.kts")
        // }

        // #[test]
        // fn uniffi_foreign_language_testcase_swift() -> uniffi::deps::anyhow::Result<()> {
        //     let pkg_dir = env::var("CARGO_MANIFEST_DIR").expect("Missing $CARGO_MANIFEST_DIR, cannot build tests for generated bindings");
        //     uniffi::testing::run_foreign_language_testcase(&pkg_dir, "src/CoreCrypto.udl", "bindings/swift/Tests/CoreCryptoTests/CoreCryptoTests.swift")
        // }


    }
}
