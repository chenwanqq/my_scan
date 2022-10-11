pub mod packet {
    use pnet_datalink::MacAddr;
    use pnet_packet::{
        ethernet::{self, EtherTypes, EthernetPacket, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{Ipv4Flags, MutableIpv4Packet,Ipv4Packet},
        tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpPacket, self}, Packet, ipv6::Ipv6Packet,
    };
    use std::{net::Ipv4Addr, fmt::Error, str::FromStr};

    use crate::result::result::{ScanResult, PortInfo};

    pub fn build_packet(
        source_ip: Ipv4Addr,
        src_mac_addr: MacAddr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        tmp_packet: &mut [u8],
    ) {
        const ETHERNET_HEADER_LEN: usize = 14;
        const IPV4_HEADER_LEN: usize = 20;

        {
            let mut eth_header =
                MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();
            eth_header.set_destination(MacAddr::broadcast());
            eth_header.set_ethertype(EtherTypes::Ipv4);
            eth_header.set_source(src_mac_addr);
        }

        {
            let mut ip_header = MutableIpv4Packet::new(
                &mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)],
            )
            .unwrap();
            ip_header.set_header_length(69);
            ip_header.set_total_length(52);
            ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_header.set_source(source_ip);
            ip_header.set_destination(dst_ip);
            ip_header.set_identification(rand::random::<u16>());
            ip_header.set_ttl(64);
            ip_header.set_version(4);
            ip_header.set_flags(Ipv4Flags::DontFragment);
            let checksum = pnet_packet::ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(checksum);
        }

        {
            let mut tcp_header =
                MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..])
                    .unwrap();
            tcp_header.set_source(rand::random::<u16>());
            tcp_header.set_destination(dst_port);
            tcp_header.set_flags(TcpFlags::SYN);
            tcp_header.set_window(64240);
            tcp_header.set_data_offset(8);
            tcp_header.set_urgent_ptr(0);
            tcp_header.set_sequence(0);
            tcp_header.set_options(&[
                TcpOption::mss(1460),
                TcpOption::sack_perm(),
                TcpOption::nop(),
                TcpOption::nop(),
                TcpOption::wscale(7),
            ]);

            let checksum =
                pnet_packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &source_ip, &dst_ip);
            tcp_header.set_checksum(checksum);
        }
    }
    pub async fn handle_receive_packet(
        rx: &mut Box<dyn pnet_datalink::DataLinkReceiver>,
        scanResult: &mut ScanResult,
    ) {
        loop {
            match rx.next() {
                Ok(_frame) => {
                    let frame = EthernetPacket::new(_frame).unwrap();
                    match frame.get_ethertype() {
                        pnet_packet::ethernet::EtherTypes::Ipv4 => {
                            match ipv4Handler(frame) {
                                Ok(port_info) => {
                                    scanResult.lock().unwrap().insert(port_info);        
                                },
                                Err(_) => {}
                            };
                            
                        },
                        pnet_packet::ethernet::EtherTypes::Ipv6 => {
                            match ipv6Handler(frame) {
                                Ok(port_info) => {
                                    scanResult.lock().unwrap().insert(port_info);        
                                },
                                Err(_) => {}
                            };
                        },
                        _ => {}
                    };
                }
                Err(_) => {}
            };
        }
    }
    fn ipv6Handler(frame: EthernetPacket) -> Result<PortInfo,&'static str> {
        match Ipv6Packet::new(frame.payload()) {
            Some(packet) => {
                if packet.get_next_header() == pnet_packet::ip::IpNextHeaderProtocols::Tcp {
                    if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                        let portInfo = PortInfo {
                            ip: Ipv4Addr::from_str("127.0.0.1").unwrap(),
                            port:tcp_packet.get_source()
                        };
                        println!("{},{}",portInfo.ip,portInfo.port);
                        if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::SYN | pnet_packet::tcp::TcpFlags::ACK {
                            return Ok(portInfo);
                        }

                    } else {
                        println!("ipv6 tcp handle wrong");
                        return Err("ipv6 tcp handle wrong");
                    }
                } else {
                    println!("only support tcp");
                    return Err("only support tcp");
                }
            },
            None => {
                println!("no legal ipv6 packet!");
                return Err("no legal ipv6 packet!");
            }
        }
        return Err("some ipv6 error");
    }
    fn ipv4Handler(frame: EthernetPacket) -> Result<PortInfo,&'static str> {
        match Ipv4Packet::new(frame.payload()) {
            Some(packet) => {
                if packet.get_next_level_protocol() == pnet_packet::ip::IpNextHeaderProtocols::Tcp {
                    if let Some(tcp_packet) = TcpPacket::new(packet.payload()) {
                        if tcp_packet.get_flags() == pnet_packet::tcp::TcpFlags::SYN | pnet_packet::tcp::TcpFlags::ACK {
                            let portInfo = PortInfo {
                                ip: packet.get_source(),
                                port:tcp_packet.get_source()
                            };
                            println!("{},{}",portInfo.ip,portInfo.port);
                            return Ok(portInfo);
                        }
                    } else {
                        return Err("ipv4 tcp handle wrong!");
                    }
                } else {
                    return Err("packet not supported");
                }
            },
            None => {
                return Err("no legal ipv4 packet!");
            }
        };
        return Err("");
    }
}
