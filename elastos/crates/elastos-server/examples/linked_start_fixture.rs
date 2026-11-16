//! Native unit-test fixture. Cargo builds this example against the candidate library.

use std::os::unix::process::CommandExt;

const VERSION: &str = match option_env!("ELASTOS_LINKED_FIXTURE_VERSION") {
    Some(version) => version,
    None => "0.7.0",
};

fn fixture_setting(value: Option<&'static str>) -> &'static str {
    value.expect("build this fixture through the linked startup test driver")
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--version") {
        println!("elastos {VERSION}");
        return;
    }
    let test = if args.get(1).map(String::as_str) == Some("__update-controller") {
        if std::env::var_os("LINKED_START_RECOVERY_ONLY").is_some() {
            println!("fixture retained recovery controller entered");
            return;
        }
        std::env::set_var("LINKED_START_RECEIPT", &args[3]);
        std::env::set_var("LINKED_START_CONTROLLER", std::env::current_exe().unwrap());
        fixture_setting(option_env!("ELASTOS_LINKED_FIXTURE_CONTROLLER_TEST"))
    } else if std::env::var("ELASTOS_UPDATE_CONTROLLER_HOST").as_deref() == Ok("1") {
        std::env::set_var("RESTART_FIXTURE_VERSION", VERSION);
        fixture_setting(option_env!("ELASTOS_LINKED_FIXTURE_HOME_TEST"))
    } else {
        let sources = elastos_server::sources::load_trusted_sources(
            &elastos_server::sources::default_data_dir(),
        )
        .unwrap();
        let source = sources.default_source().expect("configured fixture source");
        let current = std::env::current_exe().unwrap();
        eprintln!("fixture current_exe: {}", current.display());
        eprintln!("fixture install_path: {}", source.install_path);
        if std::env::var_os("LINKED_START_REMOVE_CURRENT").is_some() {
            std::fs::remove_file(&current).unwrap();
        }
        elastos_server::update_controller::resume_restart_recovery().unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(elastos_server::update_controller::enter_browser_home())
            .unwrap();
        if std::env::var_os("LINKED_START_EXPECT_REFUSAL").is_some() {
            assert_ne!(
                std::fs::canonicalize(&source.install_path).unwrap(),
                std::fs::canonicalize(current).unwrap()
            );
            println!("fixture different executable refused");
        } else {
            println!("fixture ordinary Home startup continued without controller");
        }
        std::process::exit(42);
    };
    panic!(
        "fixture exec: {}",
        std::process::Command::new(fixture_setting(option_env!(
            "ELASTOS_LINKED_FIXTURE_TEST_EXE"
        )))
        .args(["--exact", test, "--ignored", "--nocapture"])
        .exec()
    );
}
