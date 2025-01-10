require_relative "../ble/ble"
require_relative "ip2mac"
require_relative "../custon_logger"
require_relative "../constants"
require_relative "net_util"
require "ipaddr"

class BleHandler
  include BLE

  DATA_TRANSFER_SERVICE_UUID = "c8edc62d-8604-40c6-a4b4-8878d228ec1c".freeze
  UPLOAD_DATA_CHARACTERISTIC_UUID = "124a03e2-46c2-4ddd-8cf2-b643a1e91071".freeze
  UPLOAD_DESTINATION_CHARACTERISTIC_UUID = "d7299075-a344-48a7-82bb-2baa19838b2d".freeze
  DOWNLOAD_DATA_CHARACTERISTIC_UUID = "b4bf78a1-b41a-4412-b3a9-97740d7003e0".freeze

  #
  # @param [String] interface Bluetooth interface
  # @param [Array] device_addresses Device Mac Addresses
  #
  def initialize(interface, device_addresses)
    @ble = BLE::BLE.new(interface)
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

  def start_notify
    @devices.each do |_, v|
      device = v[:device]

      device.start_notify(v[:chr_paths][:upload_data])
    end
  end

  def watch_notify(devices, next_ip)
    @ble.properties.on_signal("PropertiesChanged") do |_, v, _|
      data = v["Value"]
      ipaddr = self.read(nil)
      src_mac = self.read(nil)
      dst_mac = self.read(nil)

      ble_data = BLE_DATA.new(
        src_mac:,
        dst_mac:,
        length: [12 + value.length].pack("S>"),
        data:,
      )

      devices.each_with_index do |device, idx|
        is_segment = IPAddr.new(ipaddr.join(":").to_i & IPAddr.new(device.netmask.join(".")).to_i) == IPAddr.new(device.subnet.join(".")).to_i

        if ipaddr == device.addr
          @logger.debug("#{ipaddr.if_name}: Received for this device")

          break
        end

        ip2mac = Ip2MacManager.instance.ip_to_mac(idx, ipaddr, devices)
        data = build_packet(ble_data, ipaddr, device, ip2mac.hwaddr)
        if ip2mac.flag == :ng || !ip2mac.send_data.queue.empty?
          ip2mac.send_data.append_send_data(
            is_segment ? ipaddr : next_ip,
            data,
            data.size
          )
        else
          device.socket.write(data)

          break
        end
      end
    end
  end

  def read(address)
    device_info = @devices[address.join(":")]

    device_info[:device].read(device_info[:chr_paths][:upload_destination]).flatten
  end

  def write(address, value)
    device_info = @devices[address.join(":")]

    device_info[:device].write_without_response(device_info[:chr_paths][:download_data], value.bytes_str)
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
      when DOWNLOAD_DATA_CHARACTERISTIC_UUID
        paths[:download_data] = c[:path]
      end
    end

    paths
  end

  private

  def build_packet(ble_data, ipaddr, device, hwaddr)
    dhost = hwaddr.nil? ? [0] * 6 : hwaddr
    dhost = dhost.pack("C*")

    eth = ETHER.new(
      dhost:,
      shost: device.hwaddr.pack("C*"),
      type: [Constants::EtherTypes::IP].pack("S>")
    )

    ip = IP.new(
      version: 4,
      ihl: 20 / 4,
      tos: 0,
      tot_len: [20 + 6 + ble_data.length].pack("S>"),
      id: [0, 0],
      frag_off: [0, 0],
      ttl: 64,
      protocol: Constants::Ip::UDP,
      check: nil,
      saddr: device.addr,
      daddr: ipaddr,
      option: [],
    )

    ip.check = [checksum(ip.bytes_str.bytes)].pack("S>").bytes

    port = [Constants::Udp::BLE_PORT].pack("S>")
    udp = UDP.new(
      source: port,
      dest: port,
      len: [14 + ble_data.bytes_str.length].pack("S>"),
      check: [0, 0],
      body: ble_data,
    )

    eth.bytes_str + ip.bytes_str + udp.bytes_str
  end
end
