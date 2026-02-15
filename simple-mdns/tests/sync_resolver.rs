#![cfg(feature = "sync")]

use simple_mdns::sync_hostname_resolver::OneShotMdnsHostnameResolver;



#[test]
fn sync_resolver_hostname() {
    let mut resolver = OneShotMdnsHostnameResolver::new().expect("Failed to create resolver");
    let answer = resolver.query_hostname_address("volumio.local");
    
    assert!(answer.is_ok());
    resolver = OneShotMdnsHostnameResolver::new_with_scope( simple_mdns::NetworkScope::V6 ).expect("Failed to create resolver");
    let answer = resolver.query_hostname_address("volumio.local");
    assert!(answer.is_ok());
}
