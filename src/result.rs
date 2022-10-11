pub mod result {
    use std::net::Ipv4Addr;
    use std::sync::{Arc, Mutex};
    use std::collections::HashSet;

    #[derive(PartialEq,Eq,Hash,Clone, Copy, Debug)]
    pub struct PortInfo {
        pub ip:Ipv4Addr,
        pub port:u16
    }
    pub type ScanResult = Arc<Mutex<HashSet<PortInfo>>>;
}