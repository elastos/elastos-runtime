#[cfg(not(test))]
use crate::open_browser;
#[cfg(test)]
use tests::record_open as open_browser;

pub async fn run_gateway(
    addr: String,
    public: bool,
    cache_dir: Option<std::path::PathBuf>,
    publish: Option<std::path::PathBuf>,
) -> anyhow::Result<()> {
    elastos_server::gateway_cmd::run_gateway_direct(
        addr,
        public,
        cache_dir,
        publish,
        setup_gateway_control_plane,
    )
    .await
}

pub async fn run_browser_home(no_open: bool) -> anyhow::Result<()> {
    elastos_server::update_controller::enter_browser_home(no_open).await?;
    let port = elastos_server::update_controller::BROWSER_HOME_PORT;
    // The controller checks before it starts Home; a source Home and an update
    // restart are checked here, after the earlier Home has stopped.
    elastos_server::update_controller::refuse_browser_home_port_in_use(
        &elastos_server::sources::default_data_dir(),
        port,
    )?;
    elastos_server::gateway_cmd::run_gateway_direct_with_ready(
        format!("localhost:{port}"),
        false,
        None,
        None,
        setup_control_plane,
        Some(browser_home_ready_callback(no_open)),
    )
    .await
}

fn browser_home_ready_callback(no_open: bool) -> fn(&str) {
    if no_open {
        browser_home_ready_no_open
    } else {
        browser_home_ready
    }
}

fn browser_home_ready(url: &str) {
    report_browser_home_ready(url, false);
}

fn browser_home_ready_no_open(url: &str) {
    report_browser_home_ready(url, true);
}

fn report_browser_home_ready(url: &str, no_open: bool) {
    if std::env::var("ELASTOS_UPDATE_RESTART").as_deref() == Ok("1") {
        return;
    }
    eprintln!("Home: {url}");
    eprintln!("Keep this terminal open. Press Ctrl+C to stop Home.");
    if !no_open {
        open_browser(url);
    }
}

async fn setup_control_plane() -> anyhow::Result<elastos_server::gateway_cmd::GatewayControlPlane> {
    let infra = crate::server_infra::setup_control_plane_infrastructure().await?;
    Ok(control_plane(infra))
}

async fn setup_gateway_control_plane(
) -> anyhow::Result<elastos_server::gateway_cmd::GatewayControlPlane> {
    let infra = crate::server_infra::setup_gateway_infrastructure().await?;
    Ok(control_plane(infra))
}

fn control_plane(
    infra: crate::server_infra::ServerInfrastructure,
) -> elastos_server::gateway_cmd::GatewayControlPlane {
    elastos_server::gateway_cmd::GatewayControlPlane {
        provider_registry: infra.provider_registry,
        host_helpers: infra.host_helpers,
        carrier_service: infra.carrier_service,
        collaboration_context: infra.collaboration_context,
        collaboration_service: infra.collaboration_service,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    thread_local! {
        static OPENED: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record_open(url: &str) {
        OPENED.with_borrow_mut(|opened| opened.push(url.into()));
    }

    #[test]
    fn home_browser_no_open_ready_callback() {
        for no_open in [false, true] {
            for restarting in [false, true] {
                for service in ["0", "1"] {
                    let output = std::process::Command::new(std::env::current_exe().unwrap())
                        .args([
                            "--exact",
                            "gateway_entry::tests::home_browser_ready_fixture",
                            "--ignored",
                            "--nocapture",
                        ])
                        .env("ELASTOS_SERVICE", service)
                        .env("ELASTOS_UPDATE_RESTART", if restarting { "1" } else { "0" })
                        .env("QUIET_START_TEST_NO_OPEN", if no_open { "1" } else { "0" })
                        .output()
                        .unwrap();
                    assert!(output.status.success(), "{output:?}");
                    let stderr = String::from_utf8(output.stderr).unwrap();
                    assert_eq!(stderr.contains("Home: http://localhost/home/"), !restarting);
                    assert_eq!(stderr.contains("Keep this terminal open."), !restarting);
                }
            }
        }
    }

    #[test]
    #[ignore = "isolated process for the real ready callback with a recording opener"]
    fn home_browser_ready_fixture() {
        let no_open = std::env::var("QUIET_START_TEST_NO_OPEN").unwrap() == "1";
        let restarting = std::env::var("ELASTOS_UPDATE_RESTART").unwrap() == "1";
        super::browser_home_ready_callback(no_open)("http://localhost/home/");
        OPENED.with_borrow(|opened| {
            let expected = if no_open || restarting {
                vec![]
            } else {
                vec!["http://localhost/home/".to_string()]
            };
            assert_eq!(*opened, expected);
        });
    }
}
