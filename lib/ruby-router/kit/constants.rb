module Constants
  module EtherTypes
    # @note net/ethernet.h
    PUP = 0x0200.freeze # Xerox PUP
    IP = 0x0800.freeze # IPv4
    ARP = 0x0806.freeze # Address resolution
    REVARP = 0x8035.freeze # Reverse ARP
    IPv6 = 0x86dd.freeze # IPv6

    STR_HASH = {
      PUP => "Xerox PUP",
      IP => "IPv4",
      ARP => "Address resolution",
      REVARP => "Reverse ARP",
      IPv6 => "IPv6",
  }.freeze
  end

  module Arp
    HRD = [
      "From KA9Q: NET/ROM pseudo.",
      "Ethernet 10/100Mbps.",
      "Experimental Ethernet.",
      "AX.25 Level 2.",
      "PROnet token ring.",
      "Chaosnet.",
      "IEEE 802. Ethernet/TR/TB.",
      "ARCnet.",
      "APPLEtalk",
      nil,
      nil,
      nil,
      nil,
      nil,
      nil,
      "Frame Relay DLCI.",
      nil,
      nil,
      nil,
      "ATM.",
      nil,
      nil,
      nil,
      "Metricom STRIP (new IANA id)."
    ].freeze

    OP = [
      nil,
      "ARP request.",
      "ARP reply.",
      "RARP request.",
      "RARP reply.",
      nil,
      nil,
      nil,
      "InARP request.",
      "InARP reply.",
      "(ATM)ARP NAK."
    ].freeze
  end

  module Ip
    PROTO = [
      nil,
      "ICMP",
      "IGMP",
      nil,
      "IPIP",
      nil,
      "TCP",
      nil,
      "EGP",
      nil,
      nil,
      nil,
      "PUP",
      nil,
      nil,
      nil,
      nil,
      "UDP"
    ].freeze

    ICMP = 1.freeze
    TCP = 6.freeze
    UDP = 17.freeze
  end

  module Icmp
    TYPE = [
      "Echo Reply",
      nil,
      nil,
      "Destination Unreachable",
      "Source Quench",
      "Redirect",
      nil,
      nil,
      "Echo Request",
      "Router Adverisement",
      "Router Selection",
      "Time Exceeded for Datagram",
      "Parameter Problem for Datagram",
      "Timestamp Request",
      "Timestamp Reply",
      "Information Request",
      "Information Reply",
      "Address Mask Request",
      "Address Mask Reply"
    ].freeze
  end

  module Tcp
    FLAGS = [
      "FIN",
      "SYN",
      "RST",
      "PSH",
      "ACK",
      "URG"
    ].freeze
  end

  module Io
    ETH_P_ALL = 768.freeze # htons(ETH_P_ALL) netinet/if_ethre.h Every packet
    SIOCGIFINDEX = 0x8933.freeze # bits/ioctls.h
  end

  module Udp
    BLE_PORT = 4096.freeze
  end
end