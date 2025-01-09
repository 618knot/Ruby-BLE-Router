# frozen_string_literal: true

require "singleton"
require "thread"
require_relative "struct/base"
require_relative "struct/protocol"
require_relative "../packet_analyzer/packet_analyzer"
require_relative "net_util"
require_relative "ip2mac"
require_relative "../custon_logger"

class SendReqDataManager
  include Singleton

  include NetUtil

  def initialize
    @queue = Queue.new
    @set = Set.new
    @mutex = Mutex.new
    @cond = ConditionVariable.new
    @end_flag = false
    @logger ||= CustomLogger.new
  end

  def append_send_req_data(device_no, ip2mac_no, devices)

    @devices ||= devices
    arr = [device_no, ip2mac_no]

    @mutex.synchronize do
      return unless @set.add?(arr)

      @queue.push(arr)
    end

    @logger.debug("#{@devices[device_no].if_name}: Append Send Req Data")
  end

  def get_send_req_data
    return if @queue.empty?

    req_data = nil

    @mutex.synchronize do
      req_data = @queue.pop
      @set.delete(req_data)
    end

    @logger.debug("Get Send Req Data")

    req_data
  end

  def buffer_send
    until @end_flag
      @mutex.synchronize do
        begin
          @cond.wait(@mutex, 1)
        rescue
        end
      end

      loop do
        req_data = get_send_req_data

        break if req_data.nil?

        buffer_send_one(*req_data)
      end
    end
  end

  def buffer_send_one(device_no, ip2mac_no)
    loop do
      ip2mac = Ip2MacManager.instance.ip2macs[device_no].data[ip2mac_no]
      send_data = ip2mac.send_data.get_send_data

      break if send_data.nil?

      src_packet = send_data.data

      analyzed_data = PacketAnalyzer.new(src_packet.bytes, disable_log: true).analyze
      analyzed_ether = analyzed_data[:ether]

      ether_bin = ETHER.new(
        dhost: ip2mac.hwaddr.pack("C*"),
        shost: analyzed_ether.src_mac_address.pack("C*"),
        type: analyzed_ether.type.pack("C*"),
      ).bytes_str

      ip_header = IP.new
      ip_header.copy_from_analyzed(analyzed_data[:ip])
      ip_header.ttl -= 1

      ip_checksum_for_sending(ip_header)
      ip_bin = ip_header.bytes_str

      packet = ether_bin + ip_bin + src_packet.slice(ether_bin.length + ip_bin.length..)

      socket = @devices[device_no].socket
      socket.write(packet)

      @logger.debug("#{@devices[device_no].if_name}: Buffer Send One")
      @logger.debug(packet.bytes)
    end
  end

  def stop
    @end_flag = true
  end
end
