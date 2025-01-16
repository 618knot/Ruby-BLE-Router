require_relative "../ble/ble"
require_relative "ip2mac"
require_relative "../custon_logger"
require_relative "../constants"
require_relative "net_util"
require_relative "struct/protocol"
require "ipaddr"

class BleHandler
  include BLE
  include Protocol
  include NetUtil

  DATA_TRANSFER_SERVICE_UUID = "c8edc62d-8604-40c6-a4b4-8878d228ec1c".freeze
  UPLOAD_DATA_CHARACTERISTIC_UUID = "124a03e2-46c2-4ddd-8cf2-b643a1e91071".freeze
  UPLOAD_DESTINATION_CHARACTERISTIC_UUID = "d7299075-a344-48a7-82bb-2baa19838b2d".freeze
  UPLOAD_BLE_MAC_CHARACTERISTIC_UUID = "99afe545-946e-437f-905e-06206b8d0f15".freeze
  DOWNLOAD_DATA_CHARACTERISTIC_UUID = "b4bf78a1-b41a-4412-b3a9-97740d7003e0".freeze

  #
  # @param [String] interface Bluetooth interface
  # @param [Array] device_addresses Device Mac Addresses
  #
  def initialize(interface, device_addresses)
    @ble = BLE.new(interface)
    @logger = CustomLogger.new
    @devices = device_addresses.map do |addr|
      device = @ble.device(addr)

      [
        addr,
        {
          :device => device,
          :chr_paths => get_characteristic_paths(device)
        }
      ]
    end.to_h
  end

  def start_notify(ne_devices, next_ip)
    @devices.each do |mac, v|
      device = v[:device]
      path = v[:chr_paths][:upload_data]

      return if path.nil?

      device.start_notify(path)

      chr = device.bluez.object(path)
      chr.introspect
      chr["org.freedesktop.DBus.Properties"].on_signal("PropertiesChanged") do |i, value|
        watch_notify(value["Value"], mac.split(":"), ne_devices, next_ip)
      end
    end
  end

  def main_loop
    @ble.main_loop
  end

  def read_addr(address)
    device_info = @devices[address.join(":")]

    hs = {}
    hs[:destination] = device_info[:device].read(device_info[:chr_paths][:upload_destination]).flatten
    hs[:ble_mac] = device_info[:device].read(device_info[:chr_paths][:upload_ble_mac]).flatten

    hs
  end

  def write(address, value)
    device_info = @devices[address.map { |o| o.to_s(16) }.join(":").upcase]

    device_info[:device].write_without_response(device_info[:chr_paths][:download_data], value)
  end

  private

  def get_characteristic_paths(device)
    chr = device.characteristics(DATA_TRANSFER_SERVICE_UUID)

    paths = {}
    chr.each do |c|
      case c[:uuid]
      when UPLOAD_DATA_CHARACTERISTIC_UUID
        paths[:upload_data] = c[:path]
      when UPLOAD_DESTINATION_CHARACTERISTIC_UUID
        paths[:upload_destination] = c[:path]
      when UPLOAD_BLE_MAC_CHARACTERISTIC_UUID
        paths[:upload_ble_mac] = c[:path]
      when DOWNLOAD_DATA_CHARACTERISTIC_UUID
        paths[:download_data] = c[:path]
      end
    end

    paths
  end

  def watch_notify(data, src_mac, devices, next_ip)
    read_value = self.read_addr(src_mac)
    ipaddr = read_value[:destination]
    src_mac = src_mac.map { |o| o.to_i(16) }
    dst_mac = read_value[:ble_mac]

    dst_mac_str = dst_mac.map { |o| o.to_s(16) }.join(":")
    if @devices.keys.include?(dst_mac_str)
      self.write(dst_mac_str, data)

      return
    end

    ble_data = BLE_DATA.new(
      src_mac:,
      dst_mac:,
      length: [12 + data.length].pack("S>").bytes,
      data:,
    )

    @logger.info("BLE DATA: #{ble_data}")

    devices.each_with_index do |device, idx|
      next if device.netmask.nil? || device.subnet.nil?

      is_segment = (IPAddr.new(ipaddr.join(".")).to_i & IPAddr.new(device.netmask.join(".")).to_i) == IPAddr.new(device.subnet.join(".")).to_i

      if ipaddr == device.addr
        @logger.debug("#{device.if_name}: Received for this device")

        break
      end

      target_ip = is_segment ? ipaddr : next_ip

      ip2mac = Ip2MacManager.instance.ip_to_mac(idx, target_ip, nil, devices)
      packet = build_packet(ble_data, ipaddr, device, ip2mac.hwaddr)

      if ip2mac.flag == :ng || !ip2mac.send_data.queue.empty?
        ip2mac.send_data.append_send_data(
          target_ip,
          packet,
          packet.size
        )
      else
        device.socket.write(packet)

        break
      end
    end
  end

  def build_packet(ble_data, ipaddr, device, hwaddr)
    dhost = hwaddr.nil? ? [0] * 6 : hwaddr
    dhost = dhost.pack("C*")

    eth = ETHER.new(
      dhost:,
      shost: device.hwaddr.pack("C*"),
      type: [Constants::EtherTypes::IP].pack("S>")
    )

    @logger.info("#{eth}")

    ble_data_arr = ble_data.to_a.flatten

    ip = IP.new(
      version: 4,
      ihl: 20 / 4,
      tos: 0,
      tot_len: [20 + 8 + ble_data_arr.length].pack("S>").bytes,
      id: [0, 0],
      frag_off: [0, 0],
      ttl: 64,
      protocol: Constants::Ip::UDP,
      check: [0, 0],
      saddr: device.addr,
      daddr: ipaddr,
      option: [],
    )

    ip.check = [checksum(ip.bytes_str.bytes)].pack("S>").bytes

    @logger.info("#{ip}")

    port = [Constants::Udp::BLE_PORT].pack("S>")
    udp = UDP.new(
      source: port,
      dest: port,
      len: [8 + ble_data_arr.length].pack("S>"),
      check: [0].pack("S>"),
      body: ble_data_arr.pack("C*"),
    )

    @logger.info("#{udp}")

    eth.bytes_str + ip.bytes_str + udp.bytes_str
  end
end
