#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
use std::collections::HashSet;

use resource_record_manager::DomainResourceFilter;
use simple_dns::{rdata::RData, Packet, TYPE};

pub mod conversion_utils;

mod instance_information;
pub use instance_information::InstanceInformation;

mod network_scope;
pub use network_scope::NetworkScope;

mod resource_record_manager;

mod simple_mdns_error;
pub use simple_mdns_error::SimpleMdnsError;

mod socket_helper;

#[cfg(feature = "async-tokio")]
pub mod async_discovery;

#[cfg(feature = "sync")]
pub mod sync_discovery;

#[allow(unused)]
const UNICAST_RESPONSE: bool = cfg!(not(test));

#[allow(unused)]
pub(crate) fn build_reply<'b>(
    packet: simple_dns::Packet,
    resources: &'b resource_record_manager::ResourceRecordManager<'b>,
) -> Option<(Packet<'b>, bool)> {
    let mut reply_packet = Packet::new_reply(packet.id());

    let mut unicast_response = false;
    let mut additional_query: HashSet<(&simple_dns::Name<'_>, TYPE)> = HashSet::new();

    for question in packet.questions.iter() {
        if question.unicast_response {
            unicast_response = question.unicast_response
        }

        // FIXME: send negative response for IPv4 or IPv6 if necessary
        for answer in resources
            .get_domain_resources(&question.qname, DomainResourceFilter::authoritative(true))
            .flatten()
            .filter(|r| r.match_qclass(question.qclass) && r.match_qtype(question.qtype))
        {
            reply_packet.answers.push(answer.clone());

            if let RData::SRV(srv) = &answer.rdata {
                additional_query.insert((&srv.target, TYPE::A));
                additional_query.insert((&srv.target, TYPE::AAAA));
            }

            if let RData::PTR(ptr) = &answer.rdata {
                additional_query.insert((ptr, TYPE::A));
                additional_query.insert((ptr, TYPE::AAAA));
                additional_query.insert((ptr, TYPE::TXT));
                additional_query.insert((ptr, TYPE::SRV));
            }
        }
    }

    for (domain, _type) in additional_query {
        let addr_records = resources
            .get_domain_resources(domain, DomainResourceFilter::authoritative(true))
            .flatten()
            .filter(|r| r.match_qtype(_type.into()))
            .cloned();

        reply_packet.additional_records.extend(addr_records);
    }

    if !reply_packet.answers.is_empty() {
        Some((reply_packet, unicast_response))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use simple_dns::Name;
    use std::{
        convert::TryInto,
        net::{Ipv4Addr, Ipv6Addr},
    };

    use simple_dns::Question;

    use simple_dns::ResourceRecord;

    use crate::{
        build_reply,
        conversion_utils::{ip_addr_to_resource_record, port_to_srv_record},
        resource_record_manager::ResourceRecordManager,
    };

    use super::*;

    fn get_resources() -> ResourceRecordManager<'static> {
        let mut resources = ResourceRecordManager::new();
        resources.add_authoritative_resource(port_to_srv_record(
            &Name::new_unchecked("_res1._tcp.com"),
            8080,
            0,
        ));
        resources.add_authoritative_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res1._tcp.com"),
            Ipv4Addr::LOCALHOST.into(),
            0,
        ));
        resources.add_authoritative_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res1._tcp.com"),
            Ipv6Addr::LOCALHOST.into(),
            0,
        ));

        resources.add_authoritative_resource(port_to_srv_record(
            &Name::new_unchecked("_res2._tcp.com"),
            8080,
            0,
        ));
        resources.add_authoritative_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res2._tcp.com"),
            Ipv4Addr::LOCALHOST.into(),
            0,
        ));
        resources
    }

    #[test]
    fn test_build_reply_with_no_questions() {
        let resources = get_resources();

        let packet = Packet::new_query(1);
        assert!(build_reply(packet, &resources).is_none());
    }

    #[test]
    fn test_build_reply_without_valid_answers() {
        let resources = get_resources();

        let mut packet = Packet::new_query(1);
        packet.questions.push(Question::new(
            "_res3._tcp.com".try_into().unwrap(),
            simple_dns::QTYPE::ANY,
            simple_dns::QCLASS::ANY,
            false,
        ));

        assert!(build_reply(packet, &resources).is_none());
    }

    #[test]
    fn test_build_reply_with_valid_answer() {
        let resources = get_resources();

        let mut packet = Packet::new_query(1);
        packet.questions.push(Question::new(
            "_res1._tcp.com".try_into().unwrap(),
            simple_dns::TYPE::A.into(),
            simple_dns::QCLASS::ANY,
            true,
        ));

        let (reply, unicast_response) = build_reply(packet, &resources).unwrap();

        assert!(unicast_response);
        assert_eq!(1, reply.answers.len());
        assert_eq!(0, reply.additional_records.len());
    }

    #[test]
    fn test_build_reply_for_ptr_includes_additional_records() {
        // RFC 6763 §12.1: PTR response must include SRV, TXT, and A/AAAA as additional records
        let instance_name = Name::new_unchecked("myinst._res3._tcp.com");
        let service_name = Name::new_unchecked("_res3._tcp.com");

        let mut resources = ResourceRecordManager::new();
        resources.add_authoritative_resource(ResourceRecord::new(
            service_name.clone(),
            simple_dns::CLASS::IN,
            0,
            simple_dns::rdata::RData::PTR(instance_name.clone().into()),
        ));
        resources.add_authoritative_resource(port_to_srv_record(&instance_name, 9090, 0));
        resources.add_authoritative_resource(ip_addr_to_resource_record(
            &instance_name,
            Ipv4Addr::LOCALHOST.into(),
            0,
        ));
        resources.add_authoritative_resource(
            crate::conversion_utils::hashmap_to_txt(&instance_name, Default::default(), 0).unwrap(),
        );

        let mut packet = Packet::new_query(1);
        packet.questions.push(Question::new(
            service_name,
            simple_dns::TYPE::PTR.into(),
            simple_dns::QCLASS::ANY,
            false,
        ));

        let (reply, _) = build_reply(packet, &resources).unwrap();

        assert_eq!(1, reply.answers.len(), "PTR should be the only answer");
        // additional records: SRV + TXT + A  = 3
        assert_eq!(
            3,
            reply.additional_records.len(),
            "SRV, TXT, and A should be additional records"
        );
    }

    #[test]
    fn test_build_reply_for_srv() {
        let resources = get_resources();

        let mut packet = Packet::new_query(1);
        packet.questions.push(Question::new(
            "_res1._tcp.com".try_into().unwrap(),
            simple_dns::TYPE::SRV.into(),
            simple_dns::QCLASS::ANY,
            false,
        ));

        let (reply, unicast_response) = build_reply(packet, &resources).unwrap();

        assert!(!unicast_response);
        assert_eq!(1, reply.answers.len());
        assert_eq!(2, reply.additional_records.len());
    }

    #[test]
    fn test_build_reply_for_meta_query() {
        let service_name = Name::new_unchecked("_res1._tcp.com");
        let meta_name = Name::new_unchecked("_services._dns-sd._udp.local");

        let info = InstanceInformation::new("my-instance".into())
            .with_socket_address("127.0.0.1:8080".parse().unwrap());

        let instance_full_name = format!("{}.{service_name}", info.escaped_instance_name());
        let instance_full_name = Name::new_unchecked(&instance_full_name);

        let resources = resource_record_manager::service_discovery_resource_manager(
            &service_name,
            &instance_full_name,
            300,
            info,
        )
        .expect("failed to create resource manager");

        let mut packet = Packet::new_query(1);
        packet.questions.push(Question::new(
            meta_name,
            simple_dns::TYPE::PTR.into(),
            simple_dns::QCLASS::ANY,
            false,
        ));

        let (reply, _) = dbg!(build_reply(packet, &resources).unwrap());

        assert_eq!(
            1,
            reply.answers.len(),
            "meta-query PTR should be the only answer"
        );
        // additional records: SRV + A + AAAA for _res1._tcp.com = 3
        assert_eq!(
            3,
            reply.additional_records.len(),
            "SRV, A, and AAAA for the service type should be additional records"
        );
    }
}
