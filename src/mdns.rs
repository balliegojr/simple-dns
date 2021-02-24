// use std::time::Duration;
// use std::{convert::TryInto, error::Error, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket}};
// use std::str::FromStr;

// use dns::Name;

// use crate::dns;

// //one shot query
// // continuous querying (advertising?)
// const MULTICAST_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
// //const MULTICAST_ADDR_IPV6: Ipv6Addr = "FF02::FB"
// const MULTICAST_PORT: u16 = 5353;



// pub struct MdnsService { 
//     service_name: String,
//     passive: bool,
//     advertise: bool
// }


// impl MdnsService {
//     pub fn oneshot_query(service_name: &str, timeout: Duration) -> crate::Result<std::net::IpAddr> {
//         let name = Name::new(service_name)?;
//         if !name.is_link_local() {
//             todo!() //raise error
//         }



//         todo!()
//         // dispatch a question
//         // wait for a response till timeout
//         // reply the first address received
//     }
// }

// fn create_socket() -> socket2::Socket {
//     let addrs = [
//         SocketAddr::from(([0, 0, 0, 0], MULTICAST_PORT)),
//         // SocketAddr::from(([0, 0, 0, 0], 0)),
//     ];

//     let socket = socket2::Socket::new(socket2::Domain::ipv4(), socket2::Type::dgram(), None).unwrap();
//     // socket.set_multicast_loop_v4(false);
//     socket.join_multicast_v4(&MULTICAST_ADDR_IPV4, &Ipv4Addr::new(0, 0, 0, 0));
//     socket.set_reuse_address(true);
//     socket.set_reuse_port(true);
//     socket.bind(&SocketAddr::from(([0, 0, 0, 0], MULTICAST_PORT)).into());

    
//     // let socket = std::net::UdpSocket::bind(&addrs[..]).unwrap();
//     // socket.set_multicast_loop_v4(false).unwrap();
//     // socket.join_multicast_v4(&MULTICAST_ADDR_IPV4, &Ipv4Addr::new(0, 0, 0, 0)).unwrap();

//     socket
// }

// fn query(socket: &socket2::Socket) {
//     // let mut builder = dns_parser::Builder::new_query(0, false);
//     // builder.add_question("srv._udp.local.", false, dns_parser::QueryType::All, dns_parser::QueryClass::IN);
//     // let buf = builder.build().unwrap();

//     let mut packet = dns::Packet::new_query(0, false)
//         .with_question(dns::Question::new("_srv._udp.local".try_into().unwrap(), dns::QTYPE::ANY, dns::QCLASS::IN, false).unwrap());

//     // let buf = dns::build_query(b"_srv._udp.local", dns::QTYPE::ANY, dns::QCLASS::ANY);
//     let buf = packet.to_bytes_vec(false).unwrap();
//     socket.send_to(&buf, &std::net::SocketAddr::new(MULTICAST_ADDR_IPV4.into(), MULTICAST_PORT).into()).unwrap();
// }

// fn wait_reply(socket: &socket2::Socket) {
    
//     let mut recv_buffer = vec![0; 4096];
//     loop {
//         let (count, _) = socket.recv_from(&mut recv_buffer).unwrap();
    
//         if count > 0 {
//             println!("count: {}", count);

//             match dns::Packet::parse(&recv_buffer[..count]) {
//                 Ok(raw_packet) => println!("{:?}", raw_packet),
//                 Err(err) => println!("{:?}", err)
//             }
    
//         }
//     }
// }


// #[cfg(test)]
// mod tests {
//     use std::thread;
//     use super::*;

//     #[test] 
//     fn test_query() {

//         let handle = thread::spawn(|| {
//             let socket = create_socket();
//             println!("{:?}", socket.local_addr().unwrap());
//             wait_reply(&socket);
//         });

//         let socket = create_socket();
//         println!("{:?}", socket.local_addr().unwrap());
//         query(&socket);
//         // wait_reply(&socket);

//         handle.join();
//     }
// }