#[cfg(feature = "bind9-check")]
#[path = "bind9.rs"]
mod bind9;

#[cfg(not(feature = "bind9-check"))]
#[path = "dummy.rs"]
mod bind9;

pub use bind9::*;
