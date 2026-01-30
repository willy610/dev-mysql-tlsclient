alias DERIVED_SECRET = HKDF_EXPAND_LABEL
alias HKDF_EXPAND_LABEL = Bytes

class HKDF
  property expander : HMAC
  property size : Int32 = 0

  property info : Bytes
  property counter : Int8 = 0

  property prev : Bytes # : Array(UInt8)

  property buf : Array(UInt8)

  def initialize(@expander, @size, @info, @counter)
    @buf = Array(UInt8).new
    @prev = uninitialized Bytes # Array(UInt8)
  end

  def read(length : Int32) : Bytes
    # 1. we shall produce 'lenght' bytes as result
    p = Slice.new(length, 0x00.to_u8)
    need = p.size
    # 2. There might be left '@buf' over from previous calls ()
    p_off = 0
    @buf.each_with_index { |c, i| p[i] = c }
    p_off = @buf.size
    @buf.clear
    # 3. Now produce sum(s) and append to result
    while p_off < p.size
      if @counter > 1
        @expander.reset
      end
      @expander.write_hmac(Slice.new(@prev.size) { |i| @prev[i] }) 
      @expander.write_hmac(@info)
      @expander.write_hmac(Slice.new(1, @counter.to_u8))
      @prev = @expander.sum_hmac(Slice.new(0, @counter.to_u8)).map { |c| c }
      @counter += 1

      inx_from_buf = 0
      while inx_from_buf < @prev.size
        if p_off < p.size
          p[p_off] = @prev[inx_from_buf]
          p_off += 1
        else
          @buf << @prev[inx_from_buf]
        end
        inx_from_buf += 1
      end
    end
    p
  end

  def self.hkdfExpandLabel(secret : Bytes, label, context, length) : HKDF_EXPAND_LABEL
    hkdfLabel_raw = [
      Utils.int16_to_big(length),
      Utils.length_of("1",
        ["tls13 ".bytes, label].flatten
      ),
      Utils.length_of("1",
        context
      ),
    ].flatten.map { |c| c.to_u8 }
    hkdfLabel = Bytes.new(hkdfLabel_raw.size) { |i| hkdfLabel_raw[i].to_u8 }
    reader_obj : HKDF = HKDF.expand(secret, hkdfLabel)
    buf = reader_obj.read(length)
    buf
  end

  def self.extract(secret : Bytes | Nil, salt : Bytes) : Bytes
    extractor = HMAC.new(salt)
    extractor.write_hmac(secret)
    extractor.sum_hmac(Slice.new(0, 0x00.to_u8))
  end

  def self.expand(pseudorandomKey, info : Bytes) : HKDF
    the_hmac_expander = HMAC.new(pseudorandomKey)
    the_hkdf_obj = HKDF.new(the_hmac_expander, the_hmac_expander.outer.checksum_size, info, 1.to_i8)
    the_hkdf_obj
  end
end
