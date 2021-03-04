// use std::time::Duration;
// use std::{convert::TryInto, net::{IpAddr, Ipv4Addr, SocketAddr}};

// use dns::Name;
// use tokio::{time, net::UdpSocket};
// use crate::{SimpleDnsError, dns};


// const MULTICAST_ADDR_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
// //const MULTICAST_ADDR_IPV6: Ipv6Addr = "FF02::FB"
// const MULTICAST_PORT: u16 = 5353;



// pub struct MdnsResolver { 
//     // service_name: String,
//     passive: bool,
//     advertise: bool,
//     enable_loopback: bool
// }

// impl MdnsResolver {
//     pub fn new() -> Self {
//         Self {
//             enable_loopback: false,
//             advertise: false,
//             passive: false
//         }   
//     }

//     pub async fn oneshot_query(&self, service_name: &str, timeout: Duration) -> crate::Result<Option<std::net::IpAddr>> {
//         let service_name = format_to_link_local(service_name);
//         let socket = create_udp_socket(self.enable_loopback).map_err(|_| SimpleDnsError::ErrorCreatingUDPSocket)?;
//         send_link_local_question(&socket, service_name).await?;
        
//         match time::timeout(timeout, get_first_address(&socket, service_name.try_into()?)).await {
//             Ok(addr) => Ok(Some(addr?)),
//             Err(_) => Ok(None)
//         }
//     }
// }

// fn format_to_link_local(name: &str) -> &str {
//     // TODO: format incomplete names to .local. ?
//     name
// }

// async fn send_link_local_question(socket: &UdpSocket, name: &str) -> crate::Result<()>{
//     let question = dns::Question::new(Name::new(name)?, dns::QTYPE::ANY, dns::QCLASS::IN, false);
//     let packet = dns::Packet::new_query(0, false)
//         .with_question(question)
//         .to_bytes_vec(false)?;

//     // TODO: also send to ipv6
//     let target_addr = std::net::SocketAddr::new(MULTICAST_ADDR_IPV4.into(), MULTICAST_PORT);
//     socket.send_to(&packet, target_addr)
//         .await
//         .map_err(|_| crate::SimpleDnsError::ErrorSendingDNSPacket)?;
//     Ok(())
// }

// fn create_udp_socket(multicast_loop: bool) -> Result<tokio::net::UdpSocket, Box<dyn std::error::Error>> {
//     // let addrs = [
//     //     SocketAddr::from(([0, 0, 0, 0], MULTICAST_PORT)),
//     //     // SocketAddr::from(([0, 0, 0, 0], 0)),
//     // ];

//     let socket = socket2::Socket::new(socket2::Domain::ipv4(), socket2::Type::dgram(), None).unwrap();
//     socket.set_multicast_loop_v4(multicast_loop)?;
//     socket.join_multicast_v4(&MULTICAST_ADDR_IPV4, &Ipv4Addr::new(0, 0, 0, 0))?;
//     socket.set_reuse_address(true)?;
//     socket.set_reuse_port(true)?;
//     socket.set_nonblocking(true)?;
    
//     socket.bind(&SocketAddr::from(([0, 0, 0, 0], MULTICAST_PORT)).into())?;
    
//     let socket = tokio::net::UdpSocket::from_std(socket.into_udp_socket())?;
//     Ok(socket)
// }

// async fn get_first_address<'a>(socket: &'a tokio::net::UdpSocket, name: Name<'a>) -> crate::Result<IpAddr> {
//     let mut recv_buffer = vec![0; 4096];
//     loop {
//         let (count, _) = socket.recv_from(&mut recv_buffer)
//             .await
//             .map_err(|_| crate::SimpleDnsError::ErrorReadingFromUDPSocket)?;

//         match dns::Packet::parse(&recv_buffer[..count]) {
//             Ok(packet) => {
//                 println!("{:?}", packet);
//                 for answer in packet.answers.iter().filter(|a| a.name == name) {
//                     if let dns::RData::A(ref a) = answer.rdata {
//                         return Ok(IpAddr::V4(Ipv4Addr::from(a.address)))
//                     }
//                 }
//             }
//             Err(_) => {
//                 // TODO: log invalid packet
//             }
//         }
            
//     }
// }

// struct SimpleMdnsResponder<'a> {
//     service_name: Name<'a>,
//     enable_loopback: bool
// }

// impl <'a> SimpleMdnsResponder<'a> {
//     fn new(service_name: Name<'a>) -> Self {
//         Self {
//             service_name,
//             enable_loopback: false
//         }
//     }

//     fn listen(&self) {
//         let enable_loopback = self.enable_loopback;
//         tokio::spawn(async move {
//             Self::wait_packages(enable_loopback).await
//         });
//     }

//     async fn wait_packages(enable_loopback: bool) -> crate::Result<()> {
//         let mut recv_buffer = vec![0; 4096];
        
//         let socket = create_udp_socket(enable_loopback)
//             .map_err(|_| SimpleDnsError::ErrorCreatingUDPSocket)?;
        
        
//         loop {
//             let (count, _) = socket.recv_from(&mut recv_buffer)
//                 .await
//                 .map_err(|_| crate::SimpleDnsError::ErrorReadingFromUDPSocket)?;
    
//             match dns::Packet::parse(&recv_buffer[..count]) {
//                 Ok(packet) => {
//                     for question in packet.questions {
                        
//                     }
//                 }
//                 Err(_) => {
//                     // TODO: log invalid packet
//                 }
//             }
                
//         }
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test] 
//     async fn one_shot_query() {
//         let mut responder = SimpleMdnsResponder::new("_srv._tcp.local".try_into().unwrap());
//         // responder.enable_loopback = true;
//         responder.listen();

//         let mut resolver = MdnsResolver::new();
//         resolver.enable_loopback = true;
//         resolver.oneshot_query("_srv._tcp.local", Duration::from_secs(5)).await;
//     }
// }