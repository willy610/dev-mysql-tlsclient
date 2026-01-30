{% if flag?(:trcshared) %}
{% else %}
{% end %}

class HMAC
  property inner : Shared::Sha256
  property outer : Shared::Sha256
  property opad : Bytes # Bytes # = Bytes(UInt8).new
  property ipad : Bytes # Bytes # (UInt8) = Array(UInt8).new
  property marshaled : Bool = false

  def initialize(key : Bytes)
    @outer = Shared::Sha256.new
    @inner = Shared::Sha256.new
    blocksize = @inner.block_size

    marshaled_size = 8*4 + Shared::Sha256::BIGmagic256.size + Shared::Sha256::ChunkSize256 + 8
    @opad = Bytes.new(marshaled_size, 0x00)
    @ipad = Bytes.new(marshaled_size, 0x00)
    fixed_key = Bytes.new(blocksize, 0_u8)

    if key.size > blocksize
      # // If key is too big, hash it.
      @outer.bigwrite(p_as_slice: fixed_key)
      key = @outer.bigsum
    else
    end
    fixed_key = key + Bytes.new(blocksize - key.size, 0.to_u8)
    @ipad = fixed_key
    @opad = fixed_key.clone

    @ipad.each_with_index { |c, i| @ipad[i] = @ipad[i] ^ 0x36 }
    @opad.each_with_index { |c, i| @opad[i] = @opad[i] ^ 0x5C }

    @inner.bigwrite(p_as_slice: @ipad)

    self
  end

  def to_s(io : IO)
    io << "\n(HMAC:: outer=#{@outer}\n inner=#{@inner}\n opad=#{@opad.dmp_content}\n ipad=#{@ipad.dmp_content})\n"
  end

  def write_hmac(to_write : Bytes) : Nil
    @inner.bigwrite(p_as_slice: to_write)
  end

  def sum_hmac(in_data : Bytes) : Bytes
    orig_len = in_data.size
    hash = @inner.bigsum
    in_data += hash
    @outer.bigwrite(p_as_slice: @opad)
    @outer.bigwrite(p_as_slice: in_data)
    how = @outer.bigsum
    return how
  end

  def reset : Nil
    @inner.bigwrite(p_as_slice: @ipad)
    imarshal = @inner.bigmarshal_binary
    @outer.bigwrite(p_as_slice: @opad)
    omarshal = @outer.bigmarshal_binary
    @ipad = imarshal
    @opad = omarshal
  end
end
