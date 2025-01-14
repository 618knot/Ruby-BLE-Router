# frozen_string_literal: true

module HeaderAnalyzer
  class Icmp < Header
    attr_reader(:type, :code, :check, :id, :seq)

    def analyze
      @type = @msg_bytes.slice(0)     # ICMP Type:       1Byte
      @code = @msg_bytes.slice(1)     # ICMP Code:       1Byte
      @check = @msg_bytes.slice(2..3) # Checksum:        2Byte
      @id = nil                       # Identifier:      2Byte
      @seq = nil                      # Sequence Number: 2Byte

      @type = Constants::Icmp::TYPE[@msg_bytes.slice(0)]
      @check = self.to_hex_string(@check, is_formated: true)

      if echo?
        id = @msg_bytes.slice(4..5)  # Identifier:      2Byte
        seq = @msg_bytes.slice(6..7) # Sequence Number: 2Byte

        @id = self.to_hex_string(id, is_formated: true)
        @seq = self.to_hex_string(seq, is_formated: true)
      end

      # print_icmp
    end

    #
    # @return [Boolean] Is Type Echo Request or Echo Reply?
    #
    def echo?
      @type == "Echo Reply" || @type == "Echo Request"
    end

    private

    def print_icmp
      @logger.info("■■■■■ ICMP Header ■■■■■")
      msg = [
        "Type => #{@type}",
        "Code => #{@code}",
        "Checksum => #{@check}",
        "Identifier => #{@id}",
        "Sequence => #{@seq}"
      ]

      out_msg_array(msg)
    end
  end
end