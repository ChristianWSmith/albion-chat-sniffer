use netstat::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};
use pcap::{Capture, Device};
use sysinfo::{Pid, System};

fn list_ports() -> Result<Vec<u16>, Box<dyn std::error::Error>> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets_info = get_sockets_info(af_flags, proto_flags)?;
    let mut system = System::new_all();
    system.refresh_all();
    let mut ports = Vec::new();

    for si in sockets_info {
        match si.protocol_socket_info {
            netstat::ProtocolSocketInfo::Udp(udp_si) => {
                for pid in si.associated_pids {
                    if let Some(process) = system.process(Pid::from_u32(pid)) {
                        if (process.name() == "Albion-Online" && std::env::consts::OS != "windows")
                            || (process.name() == "Albion-Online.exe"
                                && std::env::consts::OS == "windows")
                        {
                            ports.push(udp_si.local_port);
                        }
                    }
                }
            }
            _ => (),
        }
    }

    Ok(ports)
}

fn main() {
    let ports = list_ports().unwrap();

    // Get the default network device
    let device = Device::lookup().unwrap();
    println!("Using device: {}", device.name);

    // Create a Capture instance
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(u16::MAX as i32)
        .open()
        .unwrap();

    let filter: String = ports
        .iter()
        .map(|port| format!("udp port {}", port))
        .collect::<Vec<String>>()
        .join(" or ");

    println!("Using filter: {}", filter);

    // Set the filter
    cap.filter(&filter).unwrap();

    // Capture packets
    while let Ok(packet) = cap.next() {
        println!("Received packet: {:?}", packet);
    }
}
