class Unmarshaller < IO
  property in_message : Bytes
  setter remaining : Int32 = 0

  def initialize(@in_message : Bytes)
    @remaining = @in_message.size
  end

  def read(slice : Bytes)
    # return 0 unless @remaining > 0
    slice.size.times { |i| slice[i] = @in_message[i] }
    @in_message += slice.size
    slice.size
  end

  def write(slice : Bytes) : Nil
    slice.size.times { |i| @in_message[i] = slice[i] }
    @in_message += slice.size
  end

  def remaining
    @remaining
  end

  def read_byte!
    @remaining -= 1
    read_byte || raise "Unexpected EOF"
  end

  def read_fixed_int(n)
    int = 0
    n.times do |i|
      int += (read_byte!.to_i << (i * 8))
    end
    int
  end

  def read_slice(length)
    Bytes.new(length) { |i| read_byte! }
  end

  def read_string
    String.build do |buffer|
      while (b = read_byte) != 0 && b
        @remaining -= 1
        buffer.write_byte b if b
      end
    end
  end

  def read_int
    read_byte!.to_i + (read_byte!.to_i << 8) + (read_byte!.to_i << 16) + (read_byte!.to_i << 24)
  end

  def read_lenenc_string
    length = read_lenenc_int
    read_string(length)
  end

  def discard
  end

  def read_lenenc_int(h = read_byte!)
    res = if h < 251
            h.to_i
          elsif h == 0xfc
            read_byte!.to_i + (read_byte!.to_i << 8)
          elsif h == 0xfd
            read_byte!.to_i + (read_byte!.to_i << 8) + (read_byte!.to_i << 16)
          elsif h == 0xfe
            read_bytes(UInt64, IO::ByteFormat::LittleEndian)
          else
            raise "Unexpected int length"
          end

    res.to_u64
  end

  def read_blob
    ary = read_byte_array(read_lenenc_int.to_i32)
    Bytes.new(ary.to_unsafe, ary.size)
  end

  def read_byte_array(length)
    Array(UInt8).new(length) { |i| read_byte! }
  end

  def error_message_unmarshall
    errornumber = read_fixed_int(1).to_u32! + 256 * read_fixed_int(1).to_u32!
    read_byte! # the hashmark
    errorname = String.new(read_slice(5))
    erro_explain = String.new(read_slice(remaining - 0))
    raise "Error(a) #{errornumber} (#{errorname}): #{erro_explain}"
  end
end
