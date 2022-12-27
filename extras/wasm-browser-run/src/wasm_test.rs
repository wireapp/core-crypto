use crate::{WasmBrowserRunError, WasmBrowserRunResult, WebdriverContext, WebdriverError};

fn test_result_to_color_fmt_pair(result: bool) -> (better_term::Color, &'static str) {
    if result {
        (better_term::Color::BrightGreen, "ok")
    } else {
        (better_term::Color::Red, "FAIL")
    }
}

#[derive(Debug)]
struct WasmTestFileContext {
    pub location: std::path::PathBuf,
    pub tests: Vec<String>,
    pub module: walrus::Module,
}

impl WasmTestFileContext {
    pub fn new(wasm_file_path: impl AsRef<std::path::Path>) -> WasmBrowserRunResult<Self> {
        let location = wasm_file_path.as_ref().to_owned();
        let mut module = walrus::Module::from_file(wasm_file_path).map_err(|e| eyre::eyre!("{e:?}"))?;
        let test_exports: Vec<String> = module
            .exports
            .iter()
            // exports starting with "__wbgt_" (wasm-bindgen-test) are `#[wasm_bindgen::test]`-marked functions
            .filter(|e| e.name.starts_with("__wbgt_"))
            .map(|e| e.name.to_string())
            .collect();

        if test_exports.is_empty() {
            return Ok(Self {
                location,
                module,
                tests: test_exports,
            });
        }

        let section = module
            .customs
            .remove_raw("__wasm_bindgen_test_unstable")
            .ok_or_else(|| WasmBrowserRunError::InvalidBuildTarget)?;

        if !section.data.contains(&0x01) {
            return Err(WasmBrowserRunError::InvalidWasmBindgenTestCustomSection(hex::encode(
                section.data,
            )));
        }

        let ctx = Self {
            location,
            tests: test_exports,
            module,
        };

        Ok(ctx)
    }

    // pub fn only_tests_starting_with(&mut self, filter: &str) {
    //     self.tests.retain(|t| t.contains(filter))
    // }

    /// This is for WASM bindgen compatibility purposes;
    ///
    /// See: https://github.com/rustwasm/wasm-bindgen/blob/main/crates/cli/src/bin/wasm-bindgen-test-runner/main.rs#L50
    async fn bindgen_get_tmpdir(&self) -> WasmBrowserRunResult<std::path::PathBuf> {
        let tmpdir = if self.location.to_string_lossy().starts_with("/tmp/rustdoc") {
            self.location.parent()
        } else {
            self.location
                .parent()
                .and_then(std::path::Path::parent)
                .and_then(std::path::Path::parent)
        }
        .map(|p| p.join("wbg-tmp"))
        .ok_or_else(|| eyre::eyre!("file to test doesn't follow the expected Cargo conventions"))?;

        // Make sure no stale state is there, and recreate tempdir
        tokio::fs::remove_dir_all(&tmpdir).await?;
        tokio::fs::create_dir(&tmpdir).await?;

        Ok(tmpdir)
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
struct TestResultSummary {
    pub successful: bool,
    pub success: u64,
    pub fail: u64,
    pub ignored: u64,
    pub total: u64,
}

impl TestResultSummary {
    pub fn ran_test_count(&self) -> u64 {
        self.success.saturating_add(self.fail).saturating_add(self.ignored)
    }
}

impl std::fmt::Display for TestResultSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (ignored, color, result_str) = if self.success.saturating_add(self.fail) == 0 {
            (self.total, better_term::Color::Yellow, "skipped")
        } else {
            let (color, result_str) = test_result_to_color_fmt_pair(self.successful);
            (self.ignored, color, result_str)
        };

        write!(
            f,
            "{color}{result_str}{}. {} passed; {} failed; {} ignored",
            better_term::Color::Default,
            self.success,
            self.fail,
            ignored,
        )
    }
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(transparent)]
#[repr(transparent)]
struct TestResult(pub (String, bool));

#[derive(Debug, Clone)]
struct ExpandedTestResult {
    pub test_name: String,
    pub successful: bool,
}

impl From<TestResult> for ExpandedTestResult {
    fn from(r: TestResult) -> Self {
        let TestResult((test_name, successful)) = r;
        Self { test_name, successful }
    }
}

impl std::fmt::Display for ExpandedTestResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (color, result_str) = test_result_to_color_fmt_pair(self.successful);
        writeln!(
            f,
            "test {} ... {color}{result_str}{}",
            self.test_name,
            better_term::Color::Default
        )
    }
}

/// interface TestResultContainer {
///     details: [string, boolean][],
///     summary: {
///         successful: boolean,
///         success: number,
///         fail: number,
///         ignored: number,
///     },
/// }
#[derive(Debug, Clone, serde::Deserialize)]
struct TestResultContainer {
    pub details: Vec<TestResult>,
    pub summary: TestResultSummary,
}

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum TestResultReport {
    Partial(TestResultContainer),
    Complete(TestResultContainer),
}

#[derive(Debug, Clone, Default)]
pub struct TestResultWrapper {
    results: Option<TestResultContainer>,
    test_started: Option<std::time::Instant>,
    expected_test_count: u64,
}

impl TestResultWrapper {
    pub fn start(&mut self, expected_test_count: u64) {
        self.expected_test_count = expected_test_count;
        println!("\nrunning {expected_test_count} tests\n");
        self.test_started = Some(std::time::Instant::now());
    }

    pub fn fail(expected_test_count: u64) -> Self {
        Self {
            results: None,
            test_started: None,
            expected_test_count,
        }
    }

    pub fn parse_full_results(&mut self, raw_results: serde_json::Value) -> WasmBrowserRunResult<()> {
        self.results = Some(serde_json::from_value(raw_results)?);
        Ok(())
    }
}

impl std::fmt::Display for TestResultWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.expected_test_count == 0 {
            return writeln!(f, "No tests to run!");
        }

        let Some(mut results) = self.results.clone() else {
            return Err(std::fmt::Error::default());
        };

        if results.summary.total == 0 {
            return writeln!(f, "No tests to run!");
        }

        let ran_test_count = results.summary.ran_test_count();

        if ran_test_count == 0 {
            results.summary.successful = true;
            results.summary.ignored = self.expected_test_count;
        }

        if results.summary.total != self.expected_test_count {
            writeln!(
                f,
                "{}WARN{} Test summary count differs from the tests list retrieved from parsing the binary",
                better_term::Color::Yellow,
                better_term::Color::Default,
            )?;
        }

        if results.details.len() as u64 != results.summary.success.saturating_add(results.summary.fail) {
            writeln!(f,
                "{}WARN{} Test details count differs from the tests list retrieved from parsing the binary. Some output might be missing.",
                better_term::Color::Yellow,
                better_term::Color::Default,
            )?;
        }

        for test in results.details.iter().cloned().map(ExpandedTestResult::from) {
            write!(f, "{test}")?;
        }

        writeln!(
            f,
            "\ntest result: {}; finished in {:.2}s",
            results.summary,
            self.test_started
                .map(|started| started.elapsed().as_secs_f64())
                .unwrap_or_else(|| 0.)
        )?;

        Ok(())
    }
}

impl WebdriverContext {
    #[allow(dead_code)]
    async fn get_text_from_div(browser: &fantoccini::Client, id: &str) -> WasmBrowserRunResult<String> {
        let element = browser
            .find(fantoccini::Locator::Id(id))
            .await
            .map_err(WebdriverError::from)?;

        Ok(element.text().await.map_err(WebdriverError::from)?)
    }

    pub async fn wasm_tests_list(
        &self,
        wasm_file_path: &std::path::Path,
        only_ignored: bool,
    ) -> WasmBrowserRunResult<Vec<String>> {
        // TODO: Support introspecting ignored tests
        if only_ignored {
            return Ok(vec![]);
        }

        if !wasm_file_path.exists() {
            return Err(WasmBrowserRunError::WasmFileNotFound(
                wasm_file_path.to_str().unwrap().into(),
            ));
        }

        let wasm_tests_ctx = WasmTestFileContext::new(wasm_file_path)?;

        Ok(wasm_tests_ctx.tests)
    }

    pub async fn run_wasm_tests(
        &self,
        wasm_file_path: &std::path::Path,
        test_filter: Option<String>,
        exact_test: Option<String>,
    ) -> WasmBrowserRunResult<TestResultWrapper> {
        if !wasm_file_path.exists() {
            return Err(WasmBrowserRunError::WasmFileNotFound(
                wasm_file_path.to_str().unwrap().into(),
            ));
        }

        let wasm_tests_ctx = WasmTestFileContext::new(wasm_file_path)?;

        log::warn!("Tests to run: {:?}", wasm_tests_ctx.tests);

        if wasm_tests_ctx.tests.is_empty() {
            return Ok(TestResultWrapper::fail(0));
        }

        log::warn!("Getting wasm-bindgen tmp dir");
        let tmpdir = wasm_tests_ctx.bindgen_get_tmpdir().await?;
        log::warn!("wasm-bindgen tmp dir: {tmpdir:?}");

        let module_name = wasm_file_path.file_name().unwrap().to_str().unwrap();

        let mut bindgen = wasm_bindgen_cli_support::Bindgen::new();
        bindgen
            .web(true)
            .map_err(|e| eyre::eyre!("{e}"))?
            .input_module(module_name, wasm_tests_ctx.module)
            .debug(false)
            .keep_debug(false)
            .emit_start(false)
            .generate(&tmpdir)
            .map_err(|e| eyre::eyre!("{e}"))?;

        let mount_point = self.compile_js_support(None).await?;
        let wasm_file_name: std::path::PathBuf = module_name.into();
        let mount_point_path = std::path::PathBuf::from(&mount_point);
        log::warn!("Mount point path: {mount_point_path:?}");
        let base = tmpdir.join(module_name);
        let dest = mount_point_path.join(&wasm_file_name).with_extension("");

        let from = base.with_extension("js");
        let to = dest.with_extension("js");
        log::warn!("cp {from:?} -> {to:?}");
        tokio::fs::copy(&from, &to).await?;

        let from = base.with_extension("wasm");
        let to = dest.with_extension("wasm");
        log::warn!("cp {from:?} -> {to:?}");
        tokio::fs::copy(&from, &to).await?;

        let (hwnd, socket_addr) = Self::spawn_http_server(&mount_point).await?;

        let test_file_name = dest.file_name().unwrap().to_string_lossy();

        let window = self.browser.new_window(true).await.map_err(WebdriverError::from)?;
        self.browser
            .switch_to_window(window.handle)
            .await
            .map_err(WebdriverError::from)?;

        self.browser
            .goto(&format!("http://{socket_addr}/"))
            .await
            .map_err(WebdriverError::from)?;

        let test_count = wasm_tests_ctx.tests.len();

        let mut test_results = TestResultWrapper::default();
        test_results.start(test_count as u64);

        let js_args = vec![
            test_file_name.clone().into(),
            wasm_tests_ctx.tests.into(),
            exact_test.or(test_filter).into(),
        ];

        if !self.avoid_bidi && self.webdriver_bidi_uri.is_some() {
            let mut stream = self.connect_bidi().await?;
            use crate::webdriver_bidi_protocol::{local::EventData, log::LogEvent};
            use futures_util::TryStreamExt as _;
            // Start tests
            self.browser
                .execute(
                    r#"
const [fileName, testsList, testFilter] = arguments;
window.runTests(fileName, testsList, testFilter);"#,
                    js_args,
                )
                .await
                .map_err(WebdriverError::from)?;

            let bar = indicatif::ProgressBar::new(test_count as u64);

            while let Some(event) = stream.try_next().await? {
                match event.data {
                    EventData::BrowsingContextEvent(data) => {
                        log::info!("Unimplemented event handling: {:?}", data);
                    }
                    EventData::ScriptEvent(data) => {
                        log::info!("Unimplemented event handling: {:?}", data);
                    }
                    EventData::LogEvent(log_event) => match log_event {
                        LogEvent::EntryAdded(log_entry) => {
                            if let Some(log_text) = log_entry.get_text() {
                                if self.nocapture {
                                    println!("{log_text}");
                                }
                                match serde_json::from_str::<TestResultReport>(log_text)? {
                                    TestResultReport::Partial(report) => {
                                        for test in report.details.into_iter().map(ExpandedTestResult::from) {
                                            bar.set_message(test.to_string());
                                            bar.inc(1);
                                        }
                                    }
                                    TestResultReport::Complete(report) => {
                                        test_results.results = Some(report);
                                        break;
                                    }
                                }
                            }
                        }
                    },
                }
            }

            bar.finish_and_clear();
        } else {
            // Fallback on no BiDi support

            let raw_results = self
                .browser
                .execute_async(
                    r#"
const [fileName, testsList, testFilter, callback] = arguments;
window.runTests(fileName, testsList, testFilter).then(callback)"#,
                    js_args,
                )
                .await
                .map_err(WebdriverError::from)?;
            test_results.parse_full_results(raw_results)?;
        }

        self.browser.close_window().await.map_err(WebdriverError::from)?;

        hwnd.abort();
        let _ = hwnd.await;

        Ok(test_results)
    }
}
