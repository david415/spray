
// GNU Public License goes here
// author David Stainton
// copyright 2015

// XXX correct?
#![feature(ip_addr)]

extern crate pnet;
extern crate getopts;

use std::env;
use std::net::{IpAddr};
use std::net::Ipv4Addr;
use getopts::Options;

use pnet::util::{NetworkInterface, MacAddr, get_network_interfaces};
use pnet::datalink::{datalink_channel};
use pnet::datalink::DataLinkChannelType::{Layer2};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum};
use pnet::packet::tcp::{MutableTcpPacket};
use pnet::transport::{TransportSender};
use pnet::transport::TransportProtocol::{Ipv4};
use pnet::transport::{TransportChannelType, transport_channel};
use pnet::transport::TransportChannelType::{Layer3};

struct PacketProbeOptions {
    interface_name: String,
    use_linux_raw_socket: bool,
}

struct PacketProbe {
    options: PacketProbeOptions,
}

impl PacketProbe {
    fn new(opts: PacketProbeOptions) -> PacketProbe {
        PacketProbe {
            options: opts,
            tx_sender: TransportSender,
            //ethernet_tx: ...
            //ip_tx: ...
        }
    }

    fn prepare_ip_chan(&mut self) {
        let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
        match transport_channel(4096, protocol) {
            Ok(tx) => self.ip_tx = tx,
            Err(e) => panic!("An error occurred when creating the transport channel: {}", e)
        };
    }

    fn prepare_ethernet_chan(&mut self) {
        let interface_names_match = |iface: &NetworkInterface| iface.name == self.options.interface_name;

        // Find the network interface with the provided name
        let interfaces = get_network_interfaces();
        let interface = interfaces.into_iter()
            .filter(interface_names_match)
            .next()
            .unwrap();

        // Create a new channel, dealing with layer 2 packets
        match datalink_channel(&interface, 4096, 4096, Layer2) {
            Ok(tx) => self.ethernet_tx = tx,
            Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
        };
    }

    fn send_ethernet() {
        match self.tx.send_to(&eth_immut, None) {
            Some(n) => match n {
                Ok(_) => println!("packet sent!"),
                Err(e) => panic!("oh no panic {}", e)
            },
            None => panic!("failed to send packet: fufu")
        }

    }
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} - composes and sends a single packet", program);
    print!("{}", opts.usage(&brief));
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optflag("r", "rawsocket", "send via ip Linux raw sock");
    opts.optopt("e", "ethernet", "send via ethernet", "NETWORK_INTERFACE");
    opts.optflag("h", "help", "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => { m }
        Err(f) => { panic!(f.to_string()) }
    };

    if matches.opt_present("help") {
        print_usage(&program, opts);
        return;
    }

    let probe_options = PacketProbeOptions {
        interface_name: matches.opt_str("ethernet").unwrap(),
        use_linux_raw_socket: matches.opt_present("rawsocket"),
    }
    let probe = PacketProbe::new(probe_options);

    // XXX send the packet 33 times
    probe.spray(repeat: 33)
}

fn compose_packet(with_ethernet: bool) &mut [u8] {
    const ETHERNET_HEADER_LEN: usize = 14;
    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 20;
    const TCP_OPTIONS_LEN: usize = 4;
    const PAYLOAD_LEN: usize = 4;

    if with_ethernet {
        let mut packet = [0u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_OPTIONS_LEN + PAYLOAD_LEN];
        compose_ethernet_header(&mut packet[ETHERNET_HEADER_LEN ..]);
    } else {
        let mut packet = [0u8; IPV4_HEADER_LEN + TCP_HEADER_LEN + TCP_OPTIONS_LEN + PAYLOAD_LEN];
        compose_tcp_ip_headers(&mut packet[..]);
    }
    return packet
}

fn compose_tcp_header(packet: &mut [u8]) {
    let mut tcp_header = MutableTcpPacket::new(&mut packet[..]).unwrap();
    tcp_header.set_source(44342);
    tcp_header.set_destination(9666);
    tcp_header.set_sequence(1337638892);
    tcp_header.set_acknowledgement(1840557363);
    tcp_header.set_data_offset(0x7);
    tcp_header.set_reserved(0x0);
    tcp_header.set_control_bits(0x18);
    tcp_header.set_window(0x02ab);
    tcp_header.set_checksum(0x198f);
    tcp_header.set_urgent_pointer(0x0000);
}

fn compose_ipv4_header(packet: &mut [u8]) {
    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
    let ipv4_source = Ipv4Addr::new(10, 137, 2, 41);
    let ipv4_destination = Ipv4Addr::new(10, 137, 2, 41);
    ip_header.set_version(4);
    ip_header.set_header_length(5);
    ip_header.set_dscp(4);
    ip_header.set_ecn(1);
    ip_header.set_total_length(115);
    ip_header.set_identification(257);
    ip_header.set_flags(2);
    ip_header.set_fragment_offset(257);
    ip_header.set_ttl(64);
    ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    ip_header.set_source(ipv4_source);
    ip_header.set_destination(ipv4_destination);
    let imm_header = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(imm_header);
}

fn compose_ethernet_header(packet: &mut [u8]) {
    // ethernet
    let mut ethernet_header = MutableEthernetPacket::new(&mut packet[0..]).unwrap();
    let source = MacAddr(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
    let dest = MacAddr(0xde, 0xf0, 0x12, 0x34, 0x45, 0x67);
    ethernet_header.set_source(source);
    ethernet_header.set_destination(dest);
    ethernet_header.set_ethertype(EtherTypes::Ipv4);
}
