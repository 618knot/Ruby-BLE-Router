# frozen_string_literal: true

module Protocol

  ETHER = Struct.new(
    "Ether",
    :dhost, # Destination MAC address
    :shost, # Source MAC address
    :type,  # Protocol type
    )

  IP = Struct.new(
    "Ip",
    :version,  # IPv4 version
    :ihl,      # Header length
    :tos,      # Type of Service
    :tot_len,  # Total Length
    :id,       # Identifier
    :frag_off, # Fragment Offset
    :ttl,      # Time to Live
    :protocol, # Protocol
    :check,    # Checksum
    :saddr,    # Source Address
    :daddr,    # Destination Address
    :option,
  ) do

    def copy_from_analyzed(ip)
      self.members.each do |attr|
        self.send("#{attr}=", ip.send(attr))
      end
    end

    def bytes_str
      [
        pack_c((version << 4) | ihl),
        pack_c(tos),
        pack_c(tot_len),
        pack_c(id),
        pack_c(frag_off),
        pack_c(ttl),
        pack_c(protocol),
        pack_c(check),
        pack_c(saddr),
        pack_c(daddr),
        pack_c(option),
      ].reject(&:empty?).join
    end
  end

  ICMP = Struct.new(
    "Icmp",
    :type, # ICMP Type
    :code, # ICMP Code
    :check, # Checksum
    :void,
  ) do
    
    def bytes_str
      [
        pack_c(type),
        pack_c(code),
        two_bytes(check),
        four_bytes(void),
      ].join
    end
  end

  ARP = Struct.new(
    "Arp",
    :hrd, # Hardware Type
    :pro, # Protocol Type
    :hln, # Hardware Size
    :pln, # Protocol Size
    :op,  # Opcode
    :sha, # Sender MAC address
    :spa, # Sender IP address
    :tha, # Target MAC address
    :tpa, # Target IP address
  )

  UDP = Struct.new(
    "Udp",
    :source, # Source Port
    :dest,   # Destination Port
    :len,    # Data Length
    :check,  # Checksum
    :body,
  )

  BLE_DATA = Struct.new(
    :src_mac, # Source MAC Address:      6Byte
    :dst_mac, # Destination MAC Address: 6Byte
    :length,  # Length:                  2Byte
    :data,    # Data
  ) do
    def map_from_array(arr)
      self.src_mac = arr.slice(0..5)
      self.dst_mac = arr.slice(6..11)
      self.length = arr.slice(12..13)
      self.data = arr.slice(14..)
    end

    def bytes_str
      [
        pack_c(src_mac),
        pack_c(dst_mac),
        pack_c(length),
        pack_c(data),
      ].join
    end
  end
end
