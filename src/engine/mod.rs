pub mod concurrency;
pub mod core;
pub mod execution;
pub mod matcher_adapter;
pub mod phases;
pub mod pipeline;
pub mod refresh;
pub mod response;
pub mod rules;
pub mod transport;
pub mod types;
pub mod upstream;
pub mod utils;

pub use concurrency::PermitManager;
pub use core::Engine;
pub use matcher_adapter::*;
pub use pipeline::select_pipeline;
pub use types::{EngineInner, FastPathResponse};

pub(crate) use response::make_static_ip_answer;
pub use response::{extract_ttl, extract_ttl_for_refresh};
pub use rules::Decision;
pub use utils::engine_helpers;
