require "dbus"

module BLE
  class BLE
    def initialize(interface)
      @interface = interface
  
      @bluez = DBus.system_bus.service("org.bluez")
  
      @adapther = "/org/bluez/" + @interface
      device = @bluez.object(@adapther)
      @device_if = device["org.bluez.Adapter1"]
  
      manager = @bluez.object("/")
      manager.introspect
      @obj_manager = manager["org.freedesktop.DBus.ObjectManager"]
    end

    def main_loop
      main = DBus::Main.new
      main << DBus.system_bus
      main.run
    end

    def start_discovery
      @device_if.StartDiscovery
    end
  
    def stop_discovery
      @device_if.StopDiscovery
    end
  
    def get_infomations
      objects = @obj_manager.GetManagedObjects.first
  
      keys = objects.keys.filter do |k|
        k.start_with?("/org/bluez/#{@interface}/dev_")
      end
  
      keys.map do |key|
        objects[key]["org.bluez.Device1"]
      end
    end
  
    def device(dev_mac)
      Device.new(dev_mac, @adapther)
    end
  end
  
  private class Device
    attr_accessor :bluez
  
    @instances = {}
  
    class << self
      attr_reader :instances
  
      def new(*args)
        key = args.hash
  
        return @instances[key] if @instances.key?(key)
  
        instance = super(*args)
        @instances[key] = instance
        instance
      end
    end
  
    def initialize(dev_mac, adapter)
      @device_path = "#{adapter}/dev_#{dev_mac.upcase.gsub(":", "_")}"
  
      @bluez = DBus.system_bus.service("org.bluez")
  
      device = @bluez.object(@device_path)
      device.introspect
      @device_if = device["org.bluez.Device1"]
  
      manager = @bluez.object("/")
      manager.introspect
      obj_manager = manager["org.freedesktop.DBus.ObjectManager"]
      @objects = obj_manager.GetManagedObjects.first
    end
  
    def connect
      @device_if.Connect
    rescue DBus::Error => e
      puts "Connection failed: #{e.message}"
    end
  
    def disconnect
      @device_if.Disconnect
    end
  
    def services
      srv = @objects.select do |key, value|
        key.start_with?(@device_path)
      end
  
      pp srv
  
      srv = @objects.select do |key, value|
        key.start_with?(@device_path) && value.key?("org.bluez.GattService1")
      end
  
      uuids = []
      srv.each do |key, value|
        uuids << value["org.bluez.GattService1"]["UUID"]
      end
  
      uuids
    end
  
    def characteristics(srv_uuid)
      chr = @objects.select do |key, value|
        key.start_with?(@device_path) && value.key?("org.bluez.GattCharacteristic1")
      end
  
      if srv_uuid
        chr = chr.select do |key, value|
          arr = key.split("/")
          arr.delete_at(-1)
  
          service_path = arr.join('/')
  
          @objects.dig(service_path, "org.bluez.GattService1", "UUID") == srv_uuid
        end
      end
  
      chr.map do |key, value|
        {
          uuid: value["org.bluez.GattCharacteristic1"]["UUID"],
          path: key,
          flags: value["org.bluez.GattCharacteristic1"]["Flags"]
        }
      end
    end
  
    def read(path)
      get_chr_if(path).ReadValue({})
  
    rescue DBus::Error => e
      puts "Failed to read characteristic: #{e.message}"
      nil
    end
  
    def write_without_response(path, value)
      get_chr_if(path).WriteValue(value, {"type" => "command"})
  
    rescue DBus::Error => e
      puts "Failed to write characteristic: #{e.message}"
      nil
    end
  
    def start_notify(path)
      chr_if = get_chr_if(path)
      
      chr_if.StartNotify
  
      chr = @bluez.object(path)
      chr.introspect
  
      chr["org.freedesktop.DBus.Properties"].on_signal("PropertiesChanged") do |_, value, _|
        pp value["Value"]
      end
    rescue DBus::Error => e
      puts "Failed to notify characteristic: #{e.message}"
      nil
    end
  
    def stop_notify(path)
      get_chr_if(path).StopNotify
  
    rescue DBus::Error => e
      puts "Failed to notify characteristic: #{e.message}"
      nil
    end
  
    private def get_chr_if(path)
      chr = @bluez.object(path)
      chr.introspect
      chr["org.bluez.GattCharacteristic1"]
    end
  end
end
