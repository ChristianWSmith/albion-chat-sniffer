use netstat::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};
use sysinfo::{Pid, System};
use pcap::{Device, Capture};

fn list_ports() -> Result<(), Box<dyn std::error::Error>> {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets_info = get_sockets_info(af_flags, proto_flags)?;
    let mut system = System::new_all();
    system.refresh_all();

    for si in sockets_info {
        match si.protocol_socket_info {
            netstat::ProtocolSocketInfo::Tcp(tcp_si) => {
                for pid in si.associated_pids {
                    if let Some(process) = system.process(Pid::from_u32(pid)) {
                        if (process.name() == "Albion-Online" && std::env::consts::OS != "windows")
                            || (process.name() == "Albion-Online.exe"
                                && std::env::consts::OS == "windows")
                        {
                            println!(
                                "TCP - Local: {}:{} -> Remote: {}:{} - PID: {} - Process: {}",
                                tcp_si.local_addr,
                                tcp_si.local_port,
                                tcp_si.remote_addr,
                                tcp_si.remote_port,
                                pid,
                                process.name()
                            );
                        }
                    }
                }
            }
            netstat::ProtocolSocketInfo::Udp(udp_si) => {
                for pid in si.associated_pids {
                    if let Some(process) = system.process(Pid::from_u32(pid)) {
                        if (process.name() == "Albion-Online" && std::env::consts::OS != "windows")
                            || (process.name() == "Albion-Online.exe"
                                && std::env::consts::OS == "windows")
                        {
                            println!(
                                "UDP - Local: {}:{} - PID: {} - Process: {}",
                                udp_si.local_addr,
                                udp_si.local_port,
                                pid,
                                process.name()
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = list_ports() {
        eprintln!("Error listing ports: {}", e);
    }

    // Define the local and remote ports
    // TODO: replace these with whatever we get out of list_ports
    let tcp_local_port = 47384;
    let tcp_remote_port = 57343;
    let udp_ports = [41815, 42222, 35405];

    // Get the default network device
    let device = Device::lookup().unwrap();
    println!("Using device: {}", device.name);

    // Create a Capture instance
    let mut cap = Capture::from_device(device)
        .unwrap()
        .promisc(true)
        .snaplen(65535)
        .open()
        .unwrap();

    // Create filter string
    let mut filter = format!(
        "(tcp port {} and tcp port {})",
        tcp_local_port, tcp_remote_port
    );

    for port in &udp_ports {
        filter.push_str(&format!(" or (udp port {})", port));
    }

    // Set the filter
    cap.filter(&filter).unwrap();

    // Capture packets
    while let Ok(packet) = cap.next() {
        println!("Received packet: {:?}", packet);
    }
}
