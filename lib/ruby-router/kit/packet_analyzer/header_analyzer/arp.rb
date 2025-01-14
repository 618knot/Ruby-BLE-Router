# frozen_string_literal: true

module HeaderAnalyzer
  class Arp < Header
    attr_reader(
      :arp_hrd,
      :arp_pro,
      :arp_hln,
      :arp_pln,
      :arp_op,
      :arp_sha,
      :arp_spa,
      :arp_tha,
      :arp_tpa
      )

    def analyze
      @arp_hrd = @msg_bytes.slice(0..1)    # Hardware Type:      2Byte
      @arp_pro = @msg_bytes.slice(2..3)    # Protocol Type:      2Byte
      @arp_hln = @msg_bytes.slice(4)       # Hardware Size:      1Byte
      @arp_pln = @msg_bytes.slice(5)       # Protocol Size:      1Byte
      @arp_op = @msg_bytes.slice(6..7)     # Opcode:             2Byte
      @arp_sha = @msg_bytes.slice(8..13)   # Sender MAC address: 6Byte
      @arp_spa = @msg_bytes.slice(14..17)  # Sender IP address:  4Byte
      @arp_tha = @msg_bytes.slice(18..23)  # Target MAC address: 6Byte
      @arp_tpa = @msg_bytes.slice(24..27)  # Target IP address:  4Byte

      # print_arp
    end

    private

    def print_arp
      @logger.info("■■■■■ ARP ■■■■■")

      arp_hrd = Constants::Arp::HRD[self.to_hex_int(@arp_hrd)]
      arp_pro = Constants::EtherTypes::STR_HASH[self.to_hex_int(@arp_pro)]
      arp_op = Constants::Arp::OP[self.to_hex_int(@arp_op)]
      arp_sha = macaddr_to_s(@arp_sha)
      arp_spa = @arp_spa.join(".")
      arp_tha = macaddr_to_s(@arp_tha)
      arp_tpa = @arp_tpa.join(".")

      msg = [
        "Hardware Type => #{arp_hrd}",
        "Protocol Type => #{arp_pro}",
        "Hardware Size => #{@arp_hln} Byte",
        "Protocol Size => #{@arp_pln} Byte",
        "Opcode => #{arp_op}",
        "Sender MAC address => #{arp_sha}",
        "Sender IP address => #{arp_spa}",
        "Target MAC address => #{arp_tha}",
        "Target IP address => #{arp_tpa}"
      ]

      out_msg_array(msg)
    end
  end
end
