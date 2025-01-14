# frozen_string_literal: true

# @note ref: https://github.com/kuredev/simple_capture/blob/main/lib/simple_capture/header/ehter_header.rb
#       ref: https://en.wikipedia.org/wiki/Ethernet_frame
#       ref: https://shinmeisha.co.jp/newsroom/2020/06/09/%E3%82%A4%E3%83%BC%E3%82%B5%E3%83%8D%E3%83%83%E3%83%88%E3%83%98%E3%83%83%E3%83%80%E3%81%AE%E3%83%95%E3%82%A9%E3%83%BC%E3%83%9E%E3%83%83%E3%83%88%E3%81%A8%E3%82%B5%E3%82%A4%E3%82%BA%E3%81%AE%E5%9F%BA/

require_relative "../../constants"
require_relative "header"

module HeaderAnalyzer
  class Ether < Header
    attr_reader :dst_mac_address, :src_mac_address, :type, :int_hex_type
  
    #
    # ヘッダー情報を出力する
    #
    def analyze
      to_headers(@msg_bytes)
      # @logger.info("■■■■■ Ether Header ■■■■■")
      # @logger.debug("dst_mac_address=> #{macaddr_to_s(dst_mac_address)}")
      # @logger.debug("src_mac_address=> #{macaddr_to_s(src_mac_address)}")
      # @logger.debug("type=> #{type_to_s}")
    end
  
    private
  
    #
    # Ether Headerから必要な情報を取り出す
    # 
    # @param [Array] msg_bytes
    # 
    # @note variables
    #         @dst_mac_address 送信先MACアドレス
    #         @src_mac_address 送信元MACアドレス
    #         @type タイプ/長さ
    #
    def to_headers(msg_bytes)
      @dst_mac_address = msg_bytes.slice(0..5)
      @src_mac_address = msg_bytes.slice(6..11)
      @type = msg_bytes.slice(12..13)
      @int_hex_type = hex_type(@type)
    end
  
    #
    # hexのEthertype値
    #
    # @param [Array] type typeのbyte array
    #
    # @return [Integer] Ethertypeのhex値
    #
    def hex_type(type)
      hex_type = type.map { |byte| byte.to_s(16).rjust(2, "0") }
      hex_type.join.to_i(16)
    end
  
    #
    # ETHERTYPE文字列にする
    #
    # @return [String or nil] ETHERTYPE文字列(該当するものがないときはnil)
    #
    def type_to_s
      Constants::EtherTypes::STR_HASH[self.int_hex_type]
    end
  end
end
