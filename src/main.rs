extern crate pnet;

use std::env;
use std::net::Ipv4Addr;

use pnet::util::{NetworkInterface, MacAddr, get_network_interfaces};
use pnet::datalink::{datalink_channel};
use pnet::datalink::DataLinkChannelType::{Layer2};
use pnet::packet::{Packet};
use pnet::packet::ethernet::{Ethernet, EthernetPacket, EtherTypes, MutableEthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum};
use pnet::transport::TransportProtocol::{Ipv4};
use pnet::transport::TransportChannelType::{Layer4};


// Invoke as sprayTrace <interface name>
fn main() {
    let interface_name = env::args().nth(1).unwrap();
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


    // build ip packet header
    let mut packet = [0u8; 20];
    let mut ip_header = MutableIpv4Packet::new(&mut packet[..]).unwrap();
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
    ip_header.set_source(Ipv4Addr::new(192, 168, 0, 1));
    ip_header.set_destination(Ipv4Addr::new(192, 168, 0, 199));
    let imm_header = checksum(&ip_header.to_immutable());
    ip_header.set_checksum(imm_header);

    // build ethernet frame
    let mut ethernet_raw = [0u8; 14];
    let mut ethernet_header = MutableEthernetPacket::new(&mut ethernet_raw[..]).unwrap();
    let source = MacAddr(0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc);
    let dest = MacAddr(0xde, 0xf0, 0x12, 0x34, 0x45, 0x67);
    ethernet_header.set_source(source);
    ethernet_header.set_destination(dest);
    ethernet_header.set_ethertype(EtherTypes::Ipv4);

    let mut vec = Vec::new();
    vec.push_all(ip_header.to_immutable().packet);
    ethernet_header.set_payload(vec);

    let mut eth_vec = Vec::new();
    eth_vec.push_all(ethernet_header.to_immutable().packet);
    let eth_sz = eth_vec.len();
    let eth_immut = ethernet_header.to_immutable();
    
    match tx.send_to(&eth_immut, None) {
        Ok(n) => assert_eq!(n, eth_sz),
        Err(e) => panic!("failed to send packet: {}", e)
    }
}
