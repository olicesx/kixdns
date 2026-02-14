pub mod concurrency;
pub mod core;
pub mod execution;
pub mod matcher_adapter;
pub mod phases;
pub mod pipeline;
pub mod response;
pub mod rules;
pub mod transport;
pub mod types;
pub mod utils;
pub mod upstream;
pub mod refresh;

pub use core::Engine;
pub use matcher_adapter::*;
pub use pipeline::select_pipeline;
pub use types::{EngineInner, FastPathResponse};
pub use concurrency::PermitManager;

pub use rules::Decision;
pub use response::{extract_ttl_for_refresh, extract_ttl};
pub use utils::engine_helpers;
pub(crate) use response::make_static_ip_answer;


