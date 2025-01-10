require_relative "../ble/ble"

class BleHandler
  include BLE

  attr_accessor :queue

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
    @queue = Queue.new
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

  def watch_notify
    @ble.properties.on_signal("PropertiesChanged") do |_, value, _|
      v = value["Value"]
      @queue.push(
        {
          :value => v,
          :ip => self.read(v.slice(0..5))
        }
      )
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
end
