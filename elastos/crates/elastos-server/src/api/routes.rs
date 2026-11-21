//! API route handlers

use std::sync::Arc;

use axum::{
    extract::Path,
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use elastos_runtime::primitives::audit::{AuditLog, TrustLevel};
use serde::{Deserialize, Serialize};

use crate::runtime::Runtime;

const SERVER_VERSION: &str = env!("ELASTOS_VERSION");

// Health check

#[derive(Serialize)]
pub struct HealthResponse {
    status: String,
    version: String,
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: SERVER_VERSION.into(),
    })
}

/// One authenticated Runtime status route for managed Home and gateway control.
pub(crate) fn community_status_router(
    registry: Option<Arc<elastos_runtime::provider::ProviderRegistry>>,
    sessions: Arc<elastos_runtime::session::SessionRegistry>,
) -> axum::Router {
    let detach_sessions = sessions.clone();
    axum::Router::new()
        .route(
            "/api/community/status",
            axum::routing::get(move || community_status(registry.clone())),
        )
        .route(
            "/api/auth/detach",
            axum::routing::post(
                move |Extension(session): Extension<elastos_runtime::session::Session>| {
                    let sessions = detach_sessions.clone();
                    async move {
                        // The authenticated caller can release only its own token.
                        sessions.invalidate_session(&session.token).await;
                        StatusCode::NO_CONTENT
                    }
                },
            ),
        )
        .layer(axum::middleware::from_fn(
            super::middleware::shell_only_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            super::middleware::ApiState {
                session_registry: sessions,
            },
            super::middleware::auth_middleware,
        ))
}

pub(crate) async fn community_status(
    registry: Option<Arc<elastos_runtime::provider::ProviderRegistry>>,
) -> Json<serde_json::Value> {
    Json(
        match registry {
            Some(registry) => registry
                .send_runtime_provider_target_raw(
                    "collaboration.link.status",
                    &serde_json::json!({"op":"status"}),
                )
                .await
                .ok(),
            None => None,
        }
        .unwrap_or_else(|| {
            serde_json::json!({
                "state": "isolated", "connected": false,
                "detail": "Community is unavailable on this Home.", "next_retry_seconds": null,
            })
        }),
    )
}

// Capsule management

#[derive(Serialize)]
pub struct CapsuleListResponse {
    capsules: Vec<CapsuleInfoResponse>,
}

#[derive(Serialize)]
pub struct CapsuleInfoResponse {
    id: String,
    name: String,
    status: String,
}

pub async fn list_capsules(
    Extension(runtime): Extension<Arc<Runtime>>,
) -> Json<CapsuleListResponse> {
    let capsules = runtime
        .list_capsules()
        .await
        .into_iter()
        .map(|info| CapsuleInfoResponse {
            id: info.id,
            name: info.name,
            status: info.status,
        })
        .collect();

    Json(CapsuleListResponse { capsules })
}

#[derive(Deserialize)]
pub struct LaunchRequest {
    path: String,
    #[serde(default)]
    principal_id: Option<String>,
    #[serde(default)]
    launch_grant: Option<String>,
}

#[derive(Serialize)]
pub struct LaunchResponse {
    id: String,
    name: String,
    status: String,
}

pub async fn launch_capsule(
    Extension(runtime): Extension<Arc<Runtime>>,
    Extension(audit_log): Extension<Arc<AuditLog>>,
    Extension(data_dir): Extension<Option<std::path::PathBuf>>,
    Json(req): Json<LaunchRequest>,
) -> Result<Json<LaunchResponse>, (StatusCode, String)> {
    let path = std::path::Path::new(&req.path);
    let (principal_id, grant_name) = principal_from_launch_request(
        data_dir.as_deref(),
        path,
        req.principal_id,
        req.launch_grant,
    )?;

    match runtime
        .run_local_with_launch_grant(path, vec![], principal_id, grant_name.as_deref())
        .await
    {
        Ok(handle) => {
            let status = if handle.manifest.is_component_capsule() {
                "completed"
            } else {
                "launched"
            };
            audit_log.capsule_launch(
                &handle.id.0,
                &handle.manifest.name,
                None,
                TrustLevel::Untrusted,
            );
            Ok(Json(LaunchResponse {
                id: handle.id.0,
                name: handle.manifest.name,
                status: status.into(),
            }))
        }
        Err(e) => Err((StatusCode::BAD_REQUEST, e.to_string())),
    }
}

fn reject_raw_launch_principal_id(
    principal_id: Option<String>,
) -> Result<(), (StatusCode, String)> {
    if principal_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .is_some()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "principal_id is not launch authority; use signed launch_grant".to_string(),
        ));
    }
    Ok(())
}

type LaunchGrantBinding = (Option<String>, Option<String>);

fn principal_from_launch_request(
    data_dir: Option<&std::path::Path>,
    capsule_dir: &std::path::Path,
    principal_id: Option<String>,
    launch_grant: Option<String>,
) -> Result<LaunchGrantBinding, (StatusCode, String)> {
    reject_raw_launch_principal_id(principal_id)?;
    let launch_grant = launch_grant
        .map(|grant| grant.trim().to_string())
        .filter(|grant| !grant.is_empty());
    match launch_grant {
        None => Ok((None, None)),
        Some(grant) => {
            let data_dir = data_dir.ok_or((
                StatusCode::BAD_REQUEST,
                "principal launch grant unavailable".to_string(),
            ))?;
            let capsule_name = launch_capsule_name(capsule_dir)?;
            let mut headers = HeaderMap::new();
            let header_value = HeaderValue::from_str(&grant).map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    "invalid launch_grant header value".to_string(),
                )
            })?;
            headers.insert("x-elastos-home-token", header_value);
            let context = super::gateway::require_internal_shell_launch_grant_for_any_context(
                data_dir,
                &headers,
                &[capsule_name.as_str()],
            )
            .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
            Ok((Some(context.principal_id), Some(capsule_name)))
        }
    }
}

fn launch_capsule_name(capsule_dir: &std::path::Path) -> Result<String, (StatusCode, String)> {
    let manifest_path = capsule_dir.join("capsule.json");
    let bytes = elastos_common::capsule_manifest_file::read(&manifest_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("read capsule manifest for launch grant: {err}"),
        )
    })?;
    let manifest: elastos_common::CapsuleManifest =
        serde_json::from_slice(&bytes).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("parse capsule manifest for launch grant: {err}"),
            )
        })?;
    if manifest.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "capsule manifest name is required for launch grant".to_string(),
        ));
    }
    Ok(manifest.name)
}

pub async fn stop_capsule(
    Extension(runtime): Extension<Arc<Runtime>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match runtime.stop_capsule_by_id(&id).await {
        Ok(true) => (StatusCode::OK, format!("Capsule {} stopped", id)),
        Ok(false) => (StatusCode::NOT_FOUND, format!("Capsule {} not found", id)),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to stop capsule: {}", e),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::gateway;

    fn write_test_capsule(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
        let capsule_dir = dir.join(name);
        std::fs::create_dir_all(&capsule_dir).unwrap();
        std::fs::write(
            capsule_dir.join("capsule.json"),
            serde_json::json!({
                "schema": "elastos.capsule/v1",
                "version": "0.1.0",
                "name": name,
                "role": "app",
                "type": "wasm",
                "entrypoint": "main.wasm"
            })
            .to_string(),
        )
        .unwrap();
        capsule_dir
    }

    #[test]
    fn launch_without_grant_stays_principal_less() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");

        let principal =
            principal_from_launch_request(Some(dir.path()), &capsule_dir, None, None).unwrap();

        assert_eq!(principal, (None, None));
    }

    #[test]
    fn launch_principal_id_rejects_raw_values() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        for value in [
            "person:local:abc",
            "person/local/abc",
            "person\\local\\abc",
            "person..local",
            "person\nlocal",
        ] {
            let err = principal_from_launch_request(
                Some(dir.path()),
                &capsule_dir,
                Some(value.to_string()),
                None,
            )
            .unwrap_err();
            assert_eq!(err.0, StatusCode::BAD_REQUEST);
            assert!(err.1.contains("not launch authority"));
        }
    }

    #[test]
    fn principal_launch_rejects_raw_principal_id_even_with_grant() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::local_home_launch_token_context(dir.path()).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(dir.path(), "chat-wasm", &context)
                .unwrap();

        let err = principal_from_launch_request(
            Some(dir.path()),
            &capsule_dir,
            Some("person:local:alice".to_string()),
            Some(grant),
        )
        .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("not launch authority"));
    }

    #[test]
    fn principal_launch_accepts_home_launch_grant() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::local_home_launch_token_context(dir.path()).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(dir.path(), "chat-wasm", &context)
                .unwrap();

        let (principal, name) =
            principal_from_launch_request(Some(dir.path()), &capsule_dir, None, Some(grant))
                .unwrap();

        assert_eq!(name.as_deref(), Some("chat-wasm"));
        assert_eq!(principal.as_deref(), Some(context.principal_id.as_str()));
    }

    #[test]
    fn launch_route_passes_the_authorized_name_to_runtime() {
        use std::future::Future;
        use std::task::Poll;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap()
            .block_on(async {
                let dir = tempfile::tempdir().unwrap();
                let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
                let context = gateway::local_home_launch_token_context(dir.path()).unwrap();
                let grant = gateway::issue_home_launch_token_with_context(
                    dir.path(),
                    "chat-wasm",
                    &context,
                )
                .unwrap();
                let storage = Arc::new(
                    elastos_storage::providers::LocalFSProvider::new(dir.path().join("storage"))
                        .await
                        .unwrap(),
                );
                let runtime =
                    Arc::new(Runtime::with_providers_and_component(storage, vec![], None));
                let (started_tx, started_rx) = std::sync::mpsc::channel();
                let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
                let blocker = tokio::task::spawn_blocking(move || {
                    started_tx.send(()).unwrap();
                    let _ = release_rx.recv();
                });
                started_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                let mut launch = Box::pin(launch_capsule(
                    Extension(runtime),
                    Extension(Arc::new(AuditLog::new())),
                    Extension(Some(dir.path().to_path_buf())),
                    Json(LaunchRequest {
                        path: capsule_dir.to_str().unwrap().to_string(),
                        principal_id: None,
                        launch_grant: Some(grant),
                    }),
                ));
                // The only blocking worker holds the manifest read until after
                // route authorization. This makes the two reads deterministic.
                std::future::poll_fn(|cx| {
                    assert!(matches!(launch.as_mut().poll(cx), Poll::Pending));
                    Poll::Ready(())
                })
                .await;
                let manifest_path = capsule_dir.join("capsule.json");
                let mut manifest: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
                manifest["name"] = serde_json::json!("another-capsule");
                std::fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
                release_tx.send(()).unwrap();
                blocker.await.unwrap();
                let (status, message) =
                    launch.await.err().expect("the authorized name is required");
                assert_eq!(status, StatusCode::BAD_REQUEST);
                assert!(message.contains("launch grant mismatch"), "{message}");
            });
    }

    #[test]
    fn principal_launch_rejects_grant_without_runtime_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::local_home_launch_token_context(dir.path()).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(dir.path(), "chat-wasm", &context)
                .unwrap();

        let err = principal_from_launch_request(None, &capsule_dir, None, Some(grant)).unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert_eq!(err.1, "principal launch grant unavailable");
    }

    #[test]
    fn principal_launch_rejects_wrong_app_grant() {
        let dir = tempfile::tempdir().unwrap();
        let capsule_dir = write_test_capsule(dir.path(), "chat-wasm");
        let context = gateway::local_home_launch_token_context(dir.path()).unwrap();
        let grant =
            gateway::issue_home_launch_token_with_context(dir.path(), "system", &context).unwrap();

        let err = principal_from_launch_request(Some(dir.path()), &capsule_dir, None, Some(grant))
            .unwrap_err();

        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        assert!(err.1.contains("not authorized"));
    }
}
