class Marshaller < IO
#   getter slice : Bytes

#   def initialize(@slice)
  def initialize(@io : IO)
  end

  def read(slice : Bytes)
    raise "not implemented"
    # slice.size.times { |i| slice[i] = @slice[i] }
    # @slice += slice.size
    # slice.size
  end

#   def write(slice : Bytes) : Nil
#     slice.size.times { |i| @slice[i] = slice[i] }
#     @slice += slice.size
#   end

  def write(slice) : Nil
    @io.write(slice)
  rescue e : IO::EOFError
    # raise DB::ConnectionLost.new(@connection, cause: e)
    raise "Marshaller::write cause=#{e}"
  end

  def write_string(s : String)
    # x = s.to_slice
    # x.size.times { |i| @slice[i] = x[i] }
        @io << s
      rescue e : IO::EOFError
            raise "Marshaller::write_string cause=#{e}"
  end

  def write_lenenc_int(v)
    if v < 251
      write_bytes(v.to_u8, IO::ByteFormat::LittleEndian)
    elsif v < 65_536
      write_bytes(0xfc_u8, IO::ByteFormat::LittleEndian)
      write_bytes(v.to_u16, IO::ByteFormat::LittleEndian)
    elsif v < 16_777_216
      write_bytes(0xfd_u8, IO::ByteFormat::LittleEndian)
      write_bytes((v & 0x000000FF).to_u8)
      write_bytes(((v & 0x0000FF00) >> 8).to_u8)
      write_bytes(((v & 0x00FF0000) >> 16).to_u8)
    else
      write_bytes(0xfe_u8, IO::ByteFormat::LittleEndian)
      write_bytes(v.to_u64, IO::ByteFormat::LittleEndian)
    end
  end
end
