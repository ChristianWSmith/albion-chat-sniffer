#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref RE: regex::Regex = regex::Regex::new(r"s\.\.([a-z0-9]*?)\.s\.\.(.*?)\.b").unwrap();
}

fn list_sockets() -> Result<Vec<netstat::UdpSocketInfo>, Box<dyn std::error::Error>> {
    let af_flags = netstat::AddressFamilyFlags::IPV4;
    let proto_flags = netstat::ProtocolFlags::UDP;

    let sockets_info = netstat::get_sockets_info(af_flags, proto_flags)?;
    let mut system = sysinfo::System::new_all();
    system.refresh_all();
    let mut sockets = Vec::new();

    for si in sockets_info {
        match si.protocol_socket_info {
            netstat::ProtocolSocketInfo::Udp(udp_si) => {
                for pid in si.associated_pids {
                    if let Some(process) = system.process(sysinfo::Pid::from_u32(pid)) {
                        if (process.name() == "Albion-Online" && std::env::consts::OS != "windows")
                            || (process.name() == "Albion-Online.exe"
                                && std::env::consts::OS == "windows")
                        {
                            sockets.push(udp_si.clone());
                        }
                    }
                }
            }
            _ => (),
        }
    }

    Ok(sockets)
}

fn process_payload(payload_str: &str, raw: &[u8]) {    
    for caps in RE.captures_iter(payload_str) {
        if let (Some(first_capture), Some(second_capture)) = (caps.get(1), caps.get(2)) {
            if first_capture.as_str() != "System" {
                println!("{}: {} ({:?})", first_capture.as_str(), second_capture.as_str(), raw);
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let sockets = list_sockets()?;

    let mut local_addrs = Vec::new();
    let mut local_ports = Vec::new();

    for socket in sockets {
        local_addrs.push(socket.local_addr);
        local_ports.push(socket.local_port);
    }

    // Get the default network device
    let device = pcap::Device::lookup()?;
    println!("Using device: {}", device.name);

    // Create a Capture instance
    let mut cap = pcap::Capture::from_device(device)?
        .promisc(true)
        .snaplen(u16::MAX as i32)
        .immediate_mode(true)
        .open()?;

    let filter: String = local_ports
        .iter()
        .map(|port| format!("udp port {}", port))
        .collect::<Vec<String>>()
        .join(" or ");

    println!("Using filter: {}", filter);

    // Set the filter
    cap.filter(&filter)?;

    // Capture packets
    while let Ok(packet) = cap.next() {
        let ip_header_length = (packet[14] & 0x0F) as usize * 4; // IP header length in bytes
        let udp_offset = 14 + ip_header_length; // Start of UDP header

        let destination_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            packet[30], packet[31], packet[32], packet[33],
        ));

        let udp_length = ((packet[udp_offset + 4] as u16) << 8) | (packet[udp_offset + 5] as u16);

        // Calculate UDP payload length
        let udp_payload_offset = udp_offset + 8;
        let udp_payload_length = udp_length - 8;

        // Extract UDP payload
        if udp_payload_length > 0 {
            let udp_payload =
                &packet[udp_payload_offset..udp_payload_offset + udp_payload_length as usize];
            // let payload_str = String::from_utf8_lossy(udp_payload);
            let payload_str: String = udp_payload.iter().map(|&b| {
                match b {
                    // Alphanumeric characters and common symbols
                    0x20..=0x7E => b as char,
                    // Replace non-printable characters with '.'
                    _ => '.',
                }
            }).collect();

            if local_addrs.contains(&destination_ip) {
                process_payload(format!("{}", payload_str).as_str(), udp_payload);
            }
        }
    }

    Ok(())
}
