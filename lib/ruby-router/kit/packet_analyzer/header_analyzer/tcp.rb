# frozen_string_literal: true

module HeaderAnalyzer
  class Tcp < Header
    attr_reader(
      :source,
      :dest,
      :seq,
      :ack_seq,
      :doff,
      :flags,
      :window,
      :check,
      :urg_ptr
    )

    def initialize(msg_bytes, ip)
      super(msg_bytes)
      @ip = ip
    end

    def analyze
      @source = @msg_bytes.slice(0..1)    # Source Port:       2Byte
      @dest = @msg_bytes.slice(2..3)      # Destination Port:  2Byte
      @seq = @msg_bytes.slice(4..7)       # Sequence Number:   4Byte
      @ack_seq = @msg_bytes.slice(8..11)  # ACK Number:        4Byte
      @doff = @msg_bytes.slice(12)[4..7]  # Data Offset:       4bit
      @flags = @msg_bytes.slice(13)[0..5] # Flags:             6bit
      @window = @msg_bytes.slice(14..15)  # Window Size:       2Byte
      @check = @msg_bytes.slice(16..17)   # Checksum:         2Byte
      @urg_ptr = @msg_bytes.slice(18..19) # Emergency Pointer: 2Byte

      # print_tcp
    end

    private

    def flags_to_array(flags)
      arr = []
      for i in 0..5
        arr << Constants::Tcp::FLAGS[i] if flags[i] == 1
      end
      arr
    end

    def print_tcp
      @logger.info("■■■■■ TCP Header ■■■■■")

      msg = [
        "Source Port => #{self.to_hex_int(@source)}",
        "Destination Port => #{self.to_hex_int(@dest)}",
        "Sequence Number => #{self.to_hex_string(@seq, is_formated: true)}",
        "ACK Number => #{self.to_hex_string(@ack_seq, is_formated: true)}",
        "Data Offset => #{@doff} (#{@doff * 4} Byte)",
        "Flags => #{flags_to_array(@flags).join(", ")}",
        "WIndow Size => #{self.to_hex_int(@window)} Byte",
        "Checksum => #{self.to_hex_string(@check, is_formated: true)}",
        "Emergency Pointer => #{self.to_hex_int(@urg_ptr)}",
        "Valid Checksum ? => #{tcp_checksum}"
      ]

      out_msg_array(msg)
    end

    def tcp_checksum
      tcp_len = [@msg_bytes.length].pack("n").unpack("C*")

      pesudo_ip = pseudo_hddr(tcp_len)
      
      c = checksum(pesudo_ip + @msg_bytes)
      valid_checksum?(c)
    end
  end
end