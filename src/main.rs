
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
use pnet::packet::Packet;
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, checksum};
use pnet::packet::tcp;
use pnet::packet::tcp::{MutableTcpPacket};
use pnet::transport::TransportProtocol::{Ipv4};
use pnet::transport::{TransportChannelType, transport_channel};
use pnet::transport::TransportChannelType::{Layer3};



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

    if matches.opt_present("rawsocket") {
        compose_on_linux_raw_socket();
    } else {
        compose_on_ethernet(matches.opt_str("ethernet").unwrap());
    }
}

fn compose_on_linux_raw_socket() {

    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 21;
    const TEST_DATA_LEN: usize = 4;
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);

    // XXX for the time being we ignore the read channel
    let (mut tx, _) = match transport_channel(IPV4_HEADER_LEN + TCP_HEADER_LEN + TEST_DATA_LEN, protocol) {
        Ok(tx) => tx,
        Err(e) => panic!("An error occurred when creating the transport channel: {}", e)
    };

    //                     ip +tcp +payload
    let mut packet = [0u8; 20 + 21 + 4];

    let ipv4_source = Ipv4Addr::new(10, 137, 2, 41);
    let ipv4_destination = Ipv4Addr::new(10, 137, 2, 41);

    {
        /* this code
0000   ad 36 25 c2 4f ba bf ec 6d b4 ad 33 80 18 02 ab  .6%.O...m..3....
0010   19 8f 00 00 00 00 00 00 00                       .........
         */
        /* netcat
0000   ad 39 25 c2 ff 3f 6a 16 c9 e8 65 85 80 18 02 ab  .9%..?j...e.....
0010   19 8f 00 00 01 01 08 0a 03 53 94 ec 03 53 91 0e                                                  .........S...S..
         */
        let mut tcp_header = MutableTcpPacket::new(&mut packet[IPV4_HEADER_LEN..]).unwrap();
        tcp_header.set_source(44342);
        tcp_header.set_destination(9666);
        tcp_header.set_sequence(1337638892);
        tcp_header.set_acknowledgement(1840557363);
        tcp_header.set_data_offset_reserved(0x80);
        tcp_header.set_control_bits(0x18);
        tcp_header.set_window(0x02ab);
        tcp_header.set_checksum(0x198f);
        tcp_header.set_urgent_pointer(0x0000);
    }

    {
        /* this test code
0000   45 11 00 73 01 01 41 01 40 06 1f 0f 0a 89 02 29  E..s..A.@......)
0010   0a 89 02 29                                      ...)
         */
        /* netcat on qubes "eth0"
0000   45 00 00 39 fb 1d 40 00 40 06 26 3e 0a 89 02 29  E..9..@.@.&>...)
0010   0a 89 02 29                                      ...)
         */
        let mut ip_header = MutableIpv4Packet::new(&mut packet[0..]).unwrap();
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

        let immutable_ip_header = ip_header.to_immutable();
        match tx.send_to(immutable_ip_header, IpAddr::V4(ipv4_destination)) {
            Ok(_) => println!("packet sent!"),
            Err(e) => panic!("oh no panic {}", e)
        }
    }
}

fn compose_on_ethernet(interface_name: String) {
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;

    // Find the network interface with the provided name
    let interfaces = get_network_interfaces();
    let interface = interfaces.into_iter()
                              .filter(interface_names_match)
                              .next()
                              .unwrap();

    // Create a new channel, dealing with layer 2 packets
    // XXX for now we ignore the receive channel...
    let (mut tx, _) = match datalink_channel(&interface, 4096, 4096, Layer2) {
        Ok(tx) => tx,
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e)
    };

    //                     eth +ip +tcp +payload
    let mut packet = [0u8; 14 + 20 + 21 + 4];

    let ipv4_source = Ipv4Addr::new(10, 137, 2, 41);
    let ipv4_destination = Ipv4Addr::new(10, 137, 2, 41);

    {
        /* this test code
0000   45 11 00 73 01 01 41 01 40 06 1f 0f 0a 89 02 29  E..s..A.@......)
0010   0a 89 02 29                                      ...)
         */
        /* netcat on qubes "eth0" with slightly different ip headers
0000   45 00 00 39 fb 1d 40 00 40 06 26 3e 0a 89 02 29  E..9..@.@.&>...)
0010   0a 89 02 29                                      ...)
         */
        let mut ip_header = MutableIpv4Packet::new(&mut packet[14..]).unwrap();
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

    {
        /* this code
0000   ad 36 25 c2 4f ba bf ec 6d b4 ad 33 80 18 02 ab  .6%.O...m..3....
0010   19 8f 00 00 00 00 00 00 00                       .........
         */
        /* netcat with different tcp attributes...
0000   ad 39 25 c2 ff 3f 6a 16 c9 e8 65 85 80 18 02 ab  .9%..?j...e.....
0010   19 8f 00 00 01 01 08 0a 03 53 94 ec 03 53 91 0e                                                  .........S...S..
         */
        let mut tcp_header = MutableTcpPacket::new(&mut packet[14+20..]).unwrap();
        tcp_header.set_source(44342);
        tcp_header.set_destination(9666);
        tcp_header.set_sequence(1337638892);
        tcp_header.set_acknowledgement(1840557363);
        tcp_header.set_data_offset_reserved(0x80);
        tcp_header.set_control_bits(0x18);
        tcp_header.set_window(0x02ab);
        tcp_header.set_checksum(0x198f);
        tcp_header.set_urgent_pointer(0x0000);
    }

    {
        // ethernet
        /*
0000   de f0 12 34 45 67 12 34 56 78 9a bc 08 00        ...4Eg.4Vx....
         */
        let mut ethernet_header = MutableEthernetPacket::new(&mut packet[0..]).unwrap();
        let source = MacAddr(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
        let dest = MacAddr(0xde, 0xf0, 0x12, 0x34, 0x45, 0x67);
        ethernet_header.set_source(source);
        ethernet_header.set_destination(dest);
        ethernet_header.set_ethertype(EtherTypes::Ipv4);

        let eth_immut = ethernet_header.to_immutable();
        match tx.send_to(&eth_immut, None) {
            Some(n) => match n {
                Ok(_) => println!("packet sent!"),
                Err(e) => panic!("oh no panic {}", e)
            },
            None => panic!("failed to send packet: fufu")
        }
    }
}
