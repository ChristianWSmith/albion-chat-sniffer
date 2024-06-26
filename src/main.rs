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
        let source_port = ((packet[udp_offset + 0] as u16) << 8) | (packet[udp_offset + 1] as u16);
        let destination_port =
            ((packet[udp_offset + 2] as u16) << 8) | (packet[udp_offset + 3] as u16);
        let ip_header_length = (packet[14] & 0x0F) as usize * 4; // IP header length in bytes
        let udp_offset = 14 + ip_header_length; // Start of UDP header
        let source_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            packet[26], packet[27], packet[28], packet[29],
        ));
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

            if local_addrs.contains(&source_ip) {
                println!("Sent to remote Port: [{}], Payload: [{}], Raw: [{:?}]", destination_port, payload_str, udp_payload);
            }
            else if local_addrs.contains(&destination_ip) {
                println!("Received from remote port: [{}], Payload: [{}], Raw: [{:?}]", source_port, payload_str, udp_payload);

            }
            else {
                panic!("We somehow intercepted a packet that should be outside the filter's scope");
            }
        }
    }

    Ok(())
}
