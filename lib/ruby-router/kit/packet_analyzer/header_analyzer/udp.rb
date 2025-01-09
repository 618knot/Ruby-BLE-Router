# frozen_string_literal: true

module HeaderAnalyzer
  class Udp < Header
    attr_reader(
      :source,
      :dest,
      :len,
      :check,
      :body
    )

    def initialize(msg_bytes, ip)
      super(msg_bytes)
      @ip = ip
    end

    def analyze
      @source = @msg_bytes.slice(0..1) # Source Port:      2Byte
      @dest = @msg_bytes.slice(2..3)   # Destination Port: 2Byte
      @len = @msg_bytes.slice(4..5)    # Data Length:      2Byte
      @check = @msg_bytes.slice(5..7)  # Checksum:        2Byte
      @body = @msg_bytes.slice(8..)

      print_udp
    end

    private

    def print_udp
      @logger.info("■■■■■ UDP Header ■■■■■")

      msg = [
        "Source Port => #{self.to_hex_int(@source)}",
        "Destination Port => #{self.to_hex_int(@dest)}",
        "Data Length => #{self.to_hex_int(@len)}",
        "Checksum => #{self.to_hex_string(@check, is_formated: true)}",
        "Valid Checksum ? => #{udp_checksum}"
      ]

      out_msg_array(msg)
    end

    def udp_checksum
      udp_len = [@msg_bytes.length].pack("n").unpack("C*")
      
      pseudo_ip = pseudo_hddr(udp_len)

      c = checksum(pseudo_ip)
      valid_checksum?(c)
    end
  end
end