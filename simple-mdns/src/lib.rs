#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
extern crate lazy_static;

use std::collections::HashSet;

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

const UNICAST_RESPONSE: bool = cfg!(not(test));

pub(crate) fn build_reply<'b>(
    packet: simple_dns::Packet,
    resources: &'b resource_record_manager::ResourceRecordManager<'b>,
) -> Option<(Packet<'b>, bool)> {
    let mut reply_packet = Packet::new_reply(packet.id());

    let mut unicast_response = false;
    let mut additional_records = HashSet::new();

    // TODO: fill the questions for the response
    // TODO: filter out questions with known answers
    for question in packet.questions.iter() {
        if question.unicast_response {
            unicast_response = question.unicast_response
        }

        for d_resources in resources.get_domain_resources(&question.qname, true, true) {
            for answer in d_resources
                .filter(|r| r.match_qclass(question.qclass) && r.match_qtype(question.qtype))
            {
                reply_packet.answers.push(answer.clone());

                if let RData::SRV(srv) = &answer.rdata {
                    let target = resources
                        .get_domain_resources(&srv.target, false, true)
                        .flatten()
                        .filter(|r| {
                            r.match_qtype(TYPE::A.into()) && r.match_qclass(question.qclass)
                        })
                        .cloned();

                    additional_records.extend(target);
                }
            }
        }
    }

    for additional_record in additional_records {
        reply_packet.additional_records.push(additional_record);
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

    use crate::{
        build_reply,
        conversion_utils::{ip_addr_to_resource_record, port_to_srv_record},
        resource_record_manager::ResourceRecordManager,
    };

    use super::*;

    fn get_resources() -> ResourceRecordManager<'static> {
        let mut resources = ResourceRecordManager::new();
        resources.add_owned_resource(port_to_srv_record(
            &Name::new_unchecked("_res1._tcp.com"),
            8080,
            0,
        ));
        resources.add_owned_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res1._tcp.com"),
            Ipv4Addr::LOCALHOST.into(),
            0,
        ));
        resources.add_owned_resource(ip_addr_to_resource_record(
            &Name::new_unchecked("_res1._tcp.com"),
            Ipv6Addr::LOCALHOST.into(),
            0,
        ));

        resources.add_owned_resource(port_to_srv_record(
            &Name::new_unchecked("_res2._tcp.com"),
            8080,
            0,
        ));
        resources.add_owned_resource(ip_addr_to_resource_record(
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
        assert!(build_reply(packet, &resources,).is_none());
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

        assert!(build_reply(packet, &resources,).is_none());
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
        assert_eq!(2, reply.answers.len());
        assert_eq!(0, reply.additional_records.len());
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
}
