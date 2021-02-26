// use std::time::Duration;
// use std::{convert::TryInto, error::Error, net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket}};
// use std::str::FromStr;

// use dns::{Name};
// use socket2::Socket;
// use futures::select;

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
//         let service_name = format_to_link_local(service_name);
//         let socket = create_socket();

//         send_link_local_question(&socket, service_name)?;
//         get_first_address(&socket, service_name, timeout)
//     }
// }

// fn format_to_link_local(name: &str) -> &str {
//     // TODO: format incomplete names to .local. ?
//     name
// }

// fn send_link_local_question(socket: &Socket, name: &str) -> crate::Result<()>{
//     let question = dns::Question::new(Name::new(name)?, dns::QTYPE::ANY, dns::QCLASS::IN, false);
//     let packet = dns::Packet::new_query(0, false)
//         .with_question(question)
//         .to_bytes_vec(false)?;

//     // TODO: also send to ipv6
//     // TODO: fix error response
//     socket.send_to(&packet, &std::net::SocketAddr::new(MULTICAST_ADDR_IPV4.into(), MULTICAST_PORT).into()).unwrap();
//     Ok(())
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

// fn get_first_address<'a>(socket: &'a Socket, name: &str, timeout: Duration) -> crate::Result<IpAddr> {
//     let name = Name::new(name)?;
    
//     let mut recv_buffer = vec![0; 4096];
//     loop {
//         let (count, _) = socket.recv_from(&mut recv_buffer).unwrap();
//             match dns::Packet::parse(&recv_buffer[..count]) {
//                 Ok(packet) => {
//                     for answer in packet.answers.iter().filter(|a| a.name == name) {
//                         if let dns::RData::A(ref a) = answer.rdata {
//                             return Ok(IpAddr::V4(Ipv4Addr::from(a.address)))
//                         }
//                     }
//                 }
//                 Err(err) => {
//                     //TODO: log invalid package
//                     continue;
//                 }
//             }
//     }
    
//     // select! {
        
//     // }


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
//         // query(&socket);
//         // wait_reply(&socket);

//         handle.join();
//     }
// }