//! ArkIris transport core.
//!
//! The transport is intentionally split into focused modules so congestion
//! control, reliable send/receive state, replay protection and rate limiting
//! can evolve independently without turning one file into a networking junk drawer.

mod bbr;
mod cubic;
mod replay;
mod rate_limit;
mod pacer;
mod scheduler;
mod tx;
mod rx;

pub use bbr::Bbr;
pub use cubic::CubicState;
pub use replay::AntiReplay;
pub use rate_limit::RateLimiter;
pub use scheduler::{channel, LDT_MAX_PACKET, BULK_BATCH_SIZE};
pub use pacer::Pacer;
pub use tx::ReliableTx;
pub use rx::ReliableRx;
