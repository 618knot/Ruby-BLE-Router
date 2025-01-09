# frozen_string_literal: true

class Struct
  def bytes_str
    self.to_a.flatten.join
  end

  def two_bytes(v)
    [v].flatten.pack("S>")
  end

  def four_bytes(v)
    [v].flatten.pack("L>")
  end

  def pack_c(v)
    [v].flatten.pack("C*")
  end
end
