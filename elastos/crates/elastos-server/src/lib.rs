//! ElastOS Server
//!
//! HTTP API, CLI orchestration, and capsule loading for ElastOS.
//! This crate provides the transport layer (HTTP) and binary entry point.
//! The security-critical runtime logic lives in `elastos-runtime`.

pub mod api;
pub mod auth;
pub mod binaries;
pub mod browser_app_hosts;
pub(crate) mod capsule_record;
pub mod carrier;
pub mod carrier_service;
pub mod collaboration_carrier;
pub mod collaboration_config;
pub(crate) mod collaboration_contact_store;
pub(crate) mod collaboration_core;
/// Device signing authority is deliberately unavailable outside this crate.
///
/// ```compile_fail
/// use elastos_server::collaboration_device_authority::DefaultConversationDeviceAuthority;
/// ```
pub(crate) mod collaboration_custody_messages;
pub mod collaboration_default_conversation;
pub(crate) mod collaboration_delivery;
pub(crate) mod collaboration_device_authority;
pub(crate) mod collaboration_direct_messages;
pub(crate) mod collaboration_discovery;
pub(crate) mod collaboration_discovery_runtime;
pub(crate) mod collaboration_history;
pub mod collaboration_network;
pub mod collaboration_presence;
pub(crate) mod collaboration_presence_grant;
pub mod collaboration_product;
pub(crate) mod collaboration_profile_authority;
pub(crate) mod collaboration_profile_loader;
mod collaboration_profile_updates;
pub mod collaboration_protocol;
pub(crate) mod collaboration_rate_limit;
pub mod collaboration_release_network;
pub mod collaboration_startup;
pub(crate) mod collaboration_transport;
pub(crate) mod component;
pub mod content;
pub mod crypto;
pub(crate) mod custody_consent;
pub(crate) mod custody_consent_protocol;
pub(crate) mod custody_node_card;
pub(crate) mod custody_owner_requests;
pub(crate) mod custody_pool_descriptor;
pub(crate) mod custody_pool_notices;
pub(crate) mod custody_pool_resolver;
pub(crate) mod custody_pool_service;
pub mod custody_pool_setup;
pub(crate) mod custody_release_limits;
pub(crate) mod custody_surface;
pub mod documents;
pub mod esp_binding;
pub mod fetcher;
pub mod gateway_cmd;
pub mod host_lock;
pub(crate) mod host_trust;
/// A388-I1: the one host-trust entry the Runtime binary needs, at startup.
pub use host_trust::capture_at_startup as capture_host_trust_at_startup;
pub mod init;
pub mod inspect_provider;
mod install_transaction;
pub(crate) mod installed_release;
pub mod ipfs;
pub(crate) mod jev_approval_lens;
pub mod library;
pub mod local_http;
pub mod notifications;
pub mod operator_control;
pub mod ownership;
pub mod protected_content_config;
pub(crate) mod protected_content_elacity_metadata;
pub(crate) mod protected_content_market;
pub(crate) mod protected_content_pool_open;
pub mod protected_content_runtime;
pub mod provider_resource;
pub(crate) mod public_ipfs_store;
pub(crate) mod public_metadata_car;
pub(crate) mod public_metadata_consent;
pub(crate) mod public_metadata_publisher;
pub mod release_publication;
pub mod resource_bridge;
pub mod room_service;
pub mod runtime;
pub mod runtime_control;
pub mod setup;
pub mod shares;
pub mod sources;
pub mod supervisor;
#[cfg(all(test, unix))]
mod test_support;
pub mod update;
pub mod update_controller;
pub mod vm_provider;
