//! Contains the async (tokio) version of service discovery

mod oneshot_resolver;
mod service_discovery;
mod simple_responder;

pub use oneshot_resolver::OneShotMdnsResolver;
pub use service_discovery::ServiceDiscovery;
pub use simple_responder::SimpleMdnsResponder;
