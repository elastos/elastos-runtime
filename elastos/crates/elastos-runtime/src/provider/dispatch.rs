//! A revocable generation checked at the provider's actual dispatch boundary.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
type AsyncCheck =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>> + Send + Sync>;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

#[derive(Clone)]
pub struct DispatchFence {
    active: Arc<RwLock<bool>>,
    async_check: Option<AsyncCheck>,
    validate: Arc<dyn Fn() -> Result<(), String> + Send + Sync>,
}

impl DispatchFence {
    pub fn new(validate: impl Fn() -> Result<(), String> + Send + Sync + 'static) -> Self {
        Self {
            active: Arc::new(RwLock::new(true)),
            validate: Arc::new(validate),
            async_check: None,
        }
    }

    pub fn narrow(
        &self,
        validate: impl Fn() -> Result<(), String> + Send + Sync + 'static,
    ) -> Self {
        let parent = self.validate.clone();
        Self {
            active: self.active.clone(),
            async_check: self.async_check.clone(),
            validate: Arc::new(move || {
                parent()?;
                validate()
            }),
        }
    }

    pub fn with_async_check(
        mut self,
        check: impl Fn() -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
            + Send
            + Sync
            + 'static,
    ) -> Self {
        self.async_check = Some(Arc::new(check));
        self
    }

    pub async fn barrier(&self) -> tokio::sync::OwnedRwLockWriteGuard<bool> {
        self.active.clone().write_owned().await
    }

    /// Hold this guard through the write, or through registration of an owned copy.
    pub async fn enter(&self) -> Result<OwnedRwLockReadGuard<bool>, String> {
        let guard = self.active.clone().read_owned().await;
        if !*guard {
            return Err("Browser internet access has stopped".into());
        }
        (self.validate)()?;
        if let Some(check) = &self.async_check {
            check().await?;
        }
        Ok(guard)
    }

    /// Completed writes may finish at the provider. Queued writes cannot start.
    pub async fn revoke(&self) {
        *self.active.write().await = false;
    }

    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        CURRENT.scope(self.clone(), future).await
    }

    /// The fence the current task runs in, if any. A task spawned to own an
    /// operation captures it first and re-enters it with [`Self::scope`].
    pub fn current() -> Option<Self> {
        current()
    }
}

tokio::task_local! { static CURRENT: DispatchFence; }

pub(crate) fn current() -> Option<DispatchFence> {
    CURRENT.try_with(Clone::clone).ok()
}
