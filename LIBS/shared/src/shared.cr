# TODO: Write documentation for `Shared`

require "./shared/*"

module Shared
  VERSION = "0.1.0"

  def self.to_bytes(arr)
    Bytes.new(arr.size) { |i| arr[i].to_u8 }
  end

  def self.to_array_to_bytes(str)
    tmp = self.to_bytes(str.split(' '))
  end
end
