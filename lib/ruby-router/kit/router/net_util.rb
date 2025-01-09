require_relative "../constants"
require_relative "./struct/protocol"
require_relative "../packet_analyzer/packet_analyzer"
require "socket"

module NetUtil
  include Protocol
  include SocketUtils

  def send_arp_request(socket, t_ip, t_mac, s_ip, s_mac)
    raise StandardError if t_ip.class != Array
    raise StandardError if s_ip.class != Array
    raise StandardError if t_mac.class != Array
    raise StandardError if s_mac.class != Array

    s_mac_packed = s_mac.pack("C*")
    t_mac_packed = t_mac.pack("C*")
    s_ip_packed = s_ip.pack("C*")
    t_ip_packed = t_ip.pack("C*")

    ether_header = ETHER.new(
      dhost: t_mac_packed,
      shost: s_mac_packed,
      type: [0x0806].pack("S>"),
    ).bytes_str

    packed_arp_header = [0x0001, 0x0800, 6, 4, 0x0001].pack("S>S>CCS>")

    arp = ARP.new(
      hrd: packed_arp_header.slice(0..1),
      pro: packed_arp_header.slice(2..3),
      hln: packed_arp_header[4],
      pln: packed_arp_header[5],
      op: packed_arp_header.slice(6..),
      sha: s_mac_packed,
      spa: s_ip_packed,
      tha: ([0x00] * 6).pack("C*"),
      tpa: t_ip_packed,
    ).bytes_str

    packet = ether_header + arp

    socket.write(packet)
  end

  #
  # checksumを計算する
  #
  # @param [Array] data header
  #
  # @return [Array] bytes
  #
  def checksum(data)
    sum = 0

    data.each_slice(2) do |b|
      sum += (b.first << 8) + b.last
    end

    while sum > 0xffff
      sum = (sum & 0xffff) + (sum >> 16)
    end

    ~sum & 0xffff
  end

  def ip_checksum_for_sending(ip)
    ip.check = [0, 0]
    ip_arr = ip.bytes_str.bytes

    ip.check = [checksum(ip_arr)].pack("S>").bytes
  end

  def valid_checksum?(c)
    c == 0 || c == 0xffff
  end

  def ip_addr_to_arr(ip)
    ip.split(".").map(&:to_i)
  end

  def mac_addr_to_arr(mac)
    mac.split(":").map(&:to_i)
  end

  #
  # Int Arrayを16進数値(10進数)に直す
  #
  # @param [Array] array
  #
  # @return [Integer]
  #
  def to_hex_int(array)
    str = ""
    array.map{ |e| str << e.to_s(16).rjust(2, "0") }
    str.to_i(16)
  end

  private

  def calculate_subnet(ip_address, netmask)
    ip = IPAddr.new(ip_address.join("."))
    mask = IPAddr.new(netmask.join(".")).to_i.to_s(2).delete("0").length
  
    subnet = ip.mask(mask)
  
    subnet.to_s.split(".").map(&:to_i)
  end
end