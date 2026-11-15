use super::*;

pub(super) async fn marketplace_catalog(
    State(state): State<GatewayState>,
    headers: HeaderMap,
) -> Response {
    match {
        let data = state.data_dir.clone();
        let headers = headers.clone();
        blocking_capsule_inventory(move || require_capsule_catalog_token(&data, &headers)).await
    } {
        Ok(_) => Json(capsule_catalog_summary_async(&state.data_dir).await).into_response(),
        Err(err) => (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": err.to_string() })),
        )
            .into_response(),
    }
}
