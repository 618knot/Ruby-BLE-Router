# frozen_string_literal: true

require_relative "../socket_utils"
require_relative "net_util"
require_relative "../packet_analyzer/packet_analyzer"
require_relative "router_base"
require_relative "../constants"
require_relative "send_req_data_manager"
require_relative "ble_handler"
require "ipaddr"

module Router
  class Router < RouterBase
    include SocketUtils
    include NetUtil

    #
    # @param [String] interface1 インターフェイス1の名前
    # @param [String] interface2 インターフェイス2の名前
    # @param [String] nextIp 送信先(ルータ)IP
    # @param [String] ble_if BLEインターフェイスの名前
    # @param [Array] ble_addresses BLEデバイスのアドレス
    #
    def initialize(interface1, interface2, next_ip, ble_if, ble_addresses)
      super(interface1, interface2, next_ip)

      @ble_addresses = ble_addresses.map(&:upcase)
      @ble_handler = BleHandler.new(ble_if, @ble_addresses)
    end

    def run
      @ble_handler.start_notify(@devices, @next_ip)
      Thread.new { @ble_handler.main_loop }
      Thread.new { SendReqDataManager.instance.buffer_send }

      router
    end

    private

    def router
      buf_size = 2048

      disable_ip_forward

      @logger.info("Router is running...")
      @logger.debug("\n#{@devices.join("\n")}")

      until @end_flag
        begin
          readable, _, _ = IO.select(self.devices.map { |d| d.socket }, nil, nil, 0.1)

          next unless readable

          readable.each do |socket|
            begin
              data = socket.read_nonblock(buf_size)
              if data.nil? || data.empty?
                @logger.debug("Connection closed or no data")
              else
                d_idx = search_device_idx(socket)
                analyze_packet(d_idx, data)
              end
            rescue IO::WaitReadable
              next
            rescue StandardError => e
              @logger.warn("Error reading socket: #{e.message}")
              @logger.debug(e.backtrace)
            end
          end
        rescue
          enable_ip_forward
          SendReqDataManager.instance.stop
          self.end_flag = true
          @logger.info("end")
        end
      end
    end

    def send_icmp_time_exceeded(device_no, ether_header, ip_header, data)
      device = self.devices[device_no]

      r_ether_header = ETHER.new(
        dhost: ether_header.src_mac_address.pack("C*"),
        shost: device.hwaddr.pack("C*"),
        type: [Constants::EtherTypes::IP].pack("S>"),
      )

      r_iphdr = IP.new(
        version: 4,
        ihl: 20 / 4,
        tos: 0,
        tot_len: [0, 8 + 64],
        id: [0, 0],
        frag_off: [0, 0],
        ttl: 64,
        protocol: 1,
        check: [0, 0],
        saddr: device.addr,
        daddr: ip_header.saddr,
        option: []
      )

      r_iphdr.check = [checksum(r_iphdr.bytes_str.bytes)].pack("S>").bytes

      icmp = ICMP.new(
        type: 11, # ICMP_TIME_EXCEEDED
        code: 0,  # ICMP_TIMXCEED_INTRANS
        check: 0,
        void: 0,
      )

      icmp.check = checksum(icmp.bytes_str.bytes)

      packet = r_ether_header.bytes_str + r_iphdr.bytes_str + icmp.bytes_str + data.slice(14..(14 + 64))

      socket = @devices[device_no].socket
      socket.write(packet)
    end

    def analyze_packet(device_no, data)
      @analyzed_data = PacketAnalyzer.new(data.bytes, disable_log: true).analyze

      if @analyzed_data.nil?
        # @logger.debug("#{@devices[device_no].if_name}: Analyzed data is nil")
        return
      end

      ether = @analyzed_data[:ether]

      if ether.nil?
        @logger.debug("#{@devices[device_no].if_name}: Ethernet header not found")
        return
      end

      device_hwaddr = @devices[device_no].hwaddr
      bcast = Array.new(6, 0xff)

      if ether.dst_mac_address != device_hwaddr && ether.dst_mac_address != bcast
        # @logger.debug("#{@devices[device_no].if_name}: Destination MAC does not match => #{ether.dst_mac_address.map { |m| m.to_s(16) }.join(":")}")
        return
      end

      case ether.int_hex_type
      when Constants::EtherTypes::ARP
        analyze_arp(device_no, @analyzed_data[:arp])
      when Constants::EtherTypes::IP
        analyze_ip(device_no, @analyzed_data[:ip], ether, data)
      end
    end

    def disable_ip_forward
      File.open("/proc/sys/net/ipv4/ip_forward", "w") do |f|
        f.puts "0"
      end
    end

    def enable_ip_forward
      File.open("/proc/sys/net/ipv4/ip_forward", "w") do |f|
        f.puts "1"
      end
    end

    def search_device_idx(socket)
      @devices.each_with_index do |d, i|
        return i if d.socket == socket
      end
    end

    def analyze_arp(device_no, arp)
      arp_op = to_hex_int(arp.arp_op)

      @logger.debug("#{@devices[device_no].if_name}: Receive ARP REQUEST") if arp_op == 1 # ARPOP_REQUEST
      @logger.debug("#{@devices[device_no].if_name}: Receive ARP REPLY") if arp_op == 2 # ARPOP_REPLY

      Ip2MacManager.instance.ip_to_mac(device_no, arp.arp_spa, arp.arp_sha, @devices)
    end

    def analyze_ip(device_no, ip, ether, data)
      ip_cpy = IP.new
      ip_cpy.copy_from_analyzed(ip)

      ip_checksum = checksum(ip_cpy.bytes_str.bytes)

      unless valid_checksum?(ip_checksum)
        @logger.debug("#{@devices[device_no].if_name}: Bad IP checksum")
        return
      end

      if ip_cpy.ttl <= 1
        @logger.debug("#{@devices[device_no].if_name}: TTL expired")
        send_icmp_time_exceeded(device_no, ether, ip_cpy, data)
        return
      end

      dev_ipaddr = @devices.map(&:addr)
      if dev_ipaddr.include?(ip_cpy.daddr)
        @logger.debug("#{@devices[device_no].if_name}: Received for this device")

        analyze_udp if ip_cpy.protocol == Constants::Ip::UDP

        return
      end

      sender_devices = @devices.clone
      sender_devices[device_no] = nil

      sender_devices.each_with_index do |device,idx|
        next if device.nil?
        next if device.netmask.nil? || device.subnet.nil?
        if (IPAddr.new(ip_cpy.daddr.join(".")).to_i & IPAddr.new(device.netmask.join(".")).to_i) == IPAddr.new(device.subnet.join(".")).to_i
          handle_segment(device_no, idx, ip_cpy, data)
        else
          handle_next(idx, ip_cpy, data)
        end
      end
    end

    def handle_segment(device_no, tno, ip, data)
      ip2mac = Ip2MacManager.instance.ip_to_mac(tno, ip.daddr, nil, @devices)
      if ip2mac.flag == :ng || !ip2mac.send_data.queue.empty?
        ip2mac.send_data.append_send_data(ip.daddr, data, data.size)
      else
        forward_packet(ip2mac.hwaddr, tno, ip, data)
      end
    end

    def analyze_udp
      udp = @analyzed_data[:udp]

      return unless udp.dest.pack("C*") == [Constants::Udp::BLE_PORT].pack("S>")

      ble_data = BLE_DATA.new
      ble_data.map_from_array(udp.body)

      return if ble_data.dst_mac == [0] * 6

      dst_ble = ble_data.dst_mac == [0xff] * 6 ? @ble_addresses : [ble_data.dst_mac]
      dst_ble.each do |mac|
        @ble_handler.write(mac, ble_data.data)
      end
    end

    def handle_next(tno, ip, data)
      ip2mac = Ip2MacManager.instance.ip_to_mac(tno, @next_ip, nil, @devices)
      if ip2mac.flag == :ng || !ip2mac.send_data.queue.empty?
        ip2mac.send_data.append_send_data(@next_ip, data, data.size)
      else
        forward_packet(ip2mac.hwaddr, tno, ip, data)
      end
    end

    def forward_packet(dest_mac, tno, ip, data)
      ip.ttl -= 1
      ip_checksum_for_sending(ip)

      analyzed_eth = @analyzed_data[:ether]

      ether_bin = ETHER.new(
        dest_mac.pack("C*"),
        analyzed_eth.dst_mac_address.pack("C*"),
        analyzed_eth.type.pack("C*"),
      ).bytes_str

      ip_bin = ip.bytes_str

      packet = ether_bin + ip_bin + data[ether_bin.length + ip_bin.length..]

      @devices[tno].socket.write(packet)
    end
  end
end
