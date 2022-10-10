use pnet_datalink::MacAddr;
use pnet_packet::{ethernet::{self, MutableEthernetPacket,EtherTypes}, ipv4::MutableIpv4Packet};
use std::net::Ipv4Addr;

fn build_packet(source_ip: Ipv4Addr, dst_ip: Ipv4Addr, dst_port: u16, src_mac_addr: MacAddr, tmp_packet:&mut [u8]) {
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV4_HEADER_LEN: usize = 20;

    {
        let mut eth_header =  MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();
        eth_header.set_destination(MacAddr::broadcast());
        eth_header.set_ethertype(EtherTypes::Ipv4);
        eth_header.set_source(src_mac_addr);
    }

    {
        let mut ip_header = MutableIpv4Packet::new(&mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN+IPV4_HEADER_LEN)]).unwrap();
        ip_header.set_header_length(69);
        ip_header
    }
}

fn main() {
    println!("Hello, world!");
}
