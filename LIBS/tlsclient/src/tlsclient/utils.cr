module Utils
  def self.int16_to_big(value)
    [
      ((value & 0xFF00) >> 8).to_u8,
      (value & 0x00ff).to_u8,
    ]
  end

  def self.length_of(calclength, *attributes) : Array(UInt8)
    all = Array(UInt8).new(0)
    attributes.each do |one_attr|
      if one_attr.is_a?(UInt8)
        all << one_attr
      elsif one_attr.is_a?(Nil)
        # NOTHING
      else
        one_attr.each { |item| all << item }
      end
    end
    all.flatten
    v = all.size
    # ---------------------
    case calclength
    when "1"
      [v.to_u8, all].flatten
    when "2"
      [
        ((v & 0xff00) >> 8).to_u8,
        (v & 0x00ff).to_u8,
        all,
      ].flatten
    when "3"
      [
        ((v & 0x00FF0000) >> 16).to_u8,
        ((v & 0x0000FF00) >> 8).to_u8,
        (v & 0x000000FF).to_u8,
        all,
      ].flatten
    when "4"
      [
        ((v & 0x00FF000000) >> 24).to_u8,
        ((v & 0x0000FF0000) >> 16).to_u8,
        ((v & 0x000000FF00) >> 8).to_u8,
        (v & 0x00000000FF).to_u8,
        all,
      ].flatten
    else
      raise "calclength '#{calclength}' is not known in 'length_of"
    end
  end
end
