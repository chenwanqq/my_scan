use my_scan::tcp::packet::{build_packet,handle_receive_packet};
use pnet_datalink::Channel;
use std::collections::HashSet;
use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tokio::spawn;
use my_scan::result::result::ScanResult;
#[tokio::main]
async fn main() {
    //let args:Vec<String> = env::args().collect();
    let interface_name = "wlx08beac0c886c".to_string();
    let dstip_addr = "127.0.0.1";
    let start_port = "50";
    let end_port = "1000";
    let interfaces = pnet_datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|_interface| _interface.name == interface_name)
        .next()
        .expect(&format!("can not find interface {}", interface_name));

    let source_ip = match interface.ips.iter().nth(0) {
        Some(_ip) => match _ip.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4,
            std::net::IpAddr::V6(ipv6) => {
                panic!("don't support ipv6!");
            }
        },
        None => {
            panic!("this interface doesn't have an ip address!");
        }
    };
    let dst_ip = Ipv4Addr::from_str(dstip_addr).expect("not a valid dst ip");
    let src_mac_addr = interface.mac.unwrap();
    let (mut tx, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error happened {}", e),
    };

    let mut scanResult = Arc::new(Mutex::new(HashSet::new()));

    let send_thread = tokio::spawn(async move {
        let sp = u16::from_str(start_port).expect("start port no valid");
        let ep = u16::from_str(end_port).expect("end port no valid");
        for dst_port in sp..ep+1 {
            tx.build_and_send(1,66,&mut |packet: &mut[u8]| {
                build_packet(source_ip, src_mac_addr, dst_ip, dst_port, packet);
            });
        }
    });

    let mut scanResult = scanResult.clone();
    let receive_thread = tokio::spawn(async move {
        handle_receive_packet(&mut rx, &mut scanResult).await;
    });
    send_thread.await; 
    receive_thread.await;
}
