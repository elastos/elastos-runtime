//! Bounded diagnostic labels for the two Add listing HTTP requests.
//! These labels never authorize a request or enter provider request bodies.

/// Internal response metadata, never serialized into the application body.
#[derive(Clone)]
pub(crate) struct Outcome(pub(crate) &'static str);

pub(crate) struct ActionTrace {
    span: tracing::Span,
    request_id: String,
    started: tokio::time::Instant,
    finished: bool,
}

impl ActionTrace {
    pub(crate) fn new(
        action: Option<&str>,
        operation: &'static str,
        start_kind: &str,
        cid: &str,
    ) -> Self {
        let request_id = format!("request-{:016x}", rand::random::<u64>());
        let action_id = action
            .filter(|value| {
                !value.is_empty()
                    && value.len() <= 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
            .map(str::to_owned)
            .unwrap_or_else(|| format!("action-{:016x}", rand::random::<u64>()));
        let span = tracing::info_span!(
            "action_trace",
            action_id,
            request_id,
            operation,
            start_kind,
            cid
        );
        span.in_scope(|| tracing::info!(event = "request_started", "Add listing request"));
        Self {
            span,
            request_id,
            started: tokio::time::Instant::now(),
            finished: false,
        }
    }

    pub(crate) fn span(&self) -> tracing::Span {
        self.span.clone()
    }

    pub(crate) fn finish(&mut self, outcome: &'static str, http_status: u16) {
        self.span.in_scope(|| {
            tracing::info!(
                event = "request_finished",
                outcome,
                http_status,
                elapsed_ms = elapsed_ms(self.started),
                "Add listing request"
            )
        });
        self.finished = true;
    }

    pub(crate) fn attach(&self, response: &mut axum::response::Response) {
        // Generated above from fixed ASCII; cannot contain a header delimiter.
        if let Ok(value) = axum::http::HeaderValue::from_str(&self.request_id) {
            response.headers_mut().insert("x-elastos-request-id", value);
        }
    }

    pub(crate) fn complete(&mut self, response: &mut axum::response::Response) {
        let outcome = response
            .extensions()
            .get::<Outcome>()
            .map(|outcome| outcome.0)
            .unwrap_or_else(|| {
                if response.status().is_success() {
                    "unknown"
                } else {
                    "refused"
                }
            });
        self.finish(outcome, response.status().as_u16());
        self.attach(response);
    }
}

impl Drop for ActionTrace {
    fn drop(&mut self) {
        if !self.finished {
            self.span.in_scope(|| {
                tracing::info!(
                    event = "request_cancelled",
                    outcome = "cancelled",
                    elapsed_ms = elapsed_ms(self.started),
                    "Add listing request"
                )
            });
        }
    }
}

/// A synchronous guard around a single awaited operation. Keeping the span
/// owned makes cancellation observable even after its future leaves the span.
pub(crate) struct Stage {
    span: tracing::Span,
    stage: String,
    started: tokio::time::Instant,
    finished: bool,
    enabled: bool,
}

impl Stage {
    pub(crate) fn new(stage: &str, provider_id: &'static str) -> Self {
        let parent = tracing::Span::current();
        let enabled = parent
            .metadata()
            .is_some_and(|metadata| metadata.name() == "action_trace");
        let span = if enabled {
            tracing::info_span!(parent: &parent, "action_trace", active_stage = stage, provider_id)
        } else {
            tracing::Span::none()
        };
        if enabled {
            span.in_scope(|| {
                tracing::info!(
                    event = "stage_started",
                    stage,
                    provider_id,
                    "Add listing stage"
                )
            });
        }
        Self {
            span,
            stage: stage.to_owned(),
            started: tokio::time::Instant::now(),
            finished: false,
            enabled,
        }
    }

    pub(crate) fn span(&self) -> tracing::Span {
        self.span.clone()
    }

    pub(crate) fn finish(&mut self, outcome: &'static str) {
        if self.enabled {
            self.span.in_scope(|| {
                tracing::info!(
                    event = "stage_finished",
                    stage = self.stage,
                    outcome,
                    elapsed_ms = elapsed_ms(self.started),
                    "Add listing stage"
                )
            });
        }
        self.finished = true;
    }

    pub(crate) fn result<T, E>(&mut self, result: &Result<T, E>) {
        self.finish(if result.is_ok() { "ok" } else { "failed" });
    }

    pub(crate) fn checked<T, E>(&mut self, result: Result<T, E>) -> Result<T, E> {
        if result.is_err() {
            self.finish("failed");
        }
        result
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        if self.enabled && !self.finished {
            self.span.in_scope(|| {
                tracing::info!(
                    event = "stage_cancelled",
                    stage = self.stage,
                    outcome = "cancelled",
                    elapsed_ms = elapsed_ms(self.started),
                    "Add listing stage"
                )
            });
        }
    }
}

fn elapsed_ms(started: tokio::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}
