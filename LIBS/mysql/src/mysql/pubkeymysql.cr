require "big"

class PubKeyMySql
  #
  # This is a rough compile of attributes in the PubKey from mysql
  # Attributes are just collected in order of appearance  and
  # finally  established as useful attributes.
  #
  # Verify Public Key at 'https://sandbox.swedenconnect.se/cap/asn1'
  #
  enum Asn1Type : UInt8
    Asn1Undef         = 0x00
    Asn1TypeInteger   = 0x02
    Asn1TypeBitString = 0x03
    Asn1TypeNull      = 0x05
    Asn1TypeObjectId  = 0x06
    Asn1TypeSequence  = 0x30
  end
  @bigInts : Array(BigInt)
  @bitcount_bigInts : Array(Int32)

  # @bigE : Int32
  getter bigN : BigInt
  getter bigE : Int64
  getter bitcount_bigN : Int32
  getter sign_rsaEncryption : String
  obj_ident_sign : Array(Int32)
  bitcount_bigE : Int32

  def initialize
    @bigInts = Array(BigInt).new
    @bitcount_bigInts = Array(Int32).new
    @bigN = BigInt.new(1)
    @bitcount_bigN = 0
    @bigE = 0
    @bitcount_bigE = 0
    @obj_ident_sign = Array(Int32).new
    @sign_rsaEncryption = ""
  end

  def calc_N_and_E
    @bigN = @bigInts[0]
    @bigE = @bigInts[1].to_i64
    @bitcount_bigN = @bitcount_bigInts[0]
    @bitcount_bigE = @bitcount_bigInts[1]
    @sign_rsaEncryption = @obj_ident_sign.map { |c| c.to_s }.join(',')
    # pp self
  end

  def from_bytes(pubkey)
    as_string : String = String.new
    pubkey.each do |an_Unit8|
      as_string += an_Unit8.chr
    end
    {% if flag?(:dbg) %}
      puts as_string
    {% end %}
    as_string = as_string.delete("\n")
    as_string = as_string.sub("-----BEGIN PUBLIC KEY-----", "")
    as_string = as_string.sub("-----END PUBLIC KEY-----", "")

    {% if flag?(:dbg) %}
      puts as_string
    {% end %}

    plain = Base64.decode(as_string)

    {% if flag?(:dbg) %}
      puts plain.hexdump
    {% end %}

    self.parse(plain, 0)
    self.calc_N_and_E
  end

  def parse(data : Bytes, pos : Int32) : Int32
    if data.size - pos < 2
      raise "parse_asn.1 input to short (1)"
    end
    #   pos = 0

    code = data[pos] & 0x3F
    # puts "--------\nofsset=#{pos} code=#{code.to_s(16)}x"
    pos += 1
    length = data[pos].to_i32
    pos += 1
    if (length > 127)
      count = length & 0x7F
      # if pos + count > remaining
      #   raise "parse_asn.1 input to short (3)"
      # end
      # puts "count=#{count}"
      length = 0
      while count > 0
        length = (length << 8) | (data[pos].to_i32)
        pos += 1
        count -= 1
      end
      # pos -=1
    end
    #   if pos + length > remaining
    #     raise "parse_asn.1 input to short (2)"
    #   end
    # @type = code
    # puts "code=#{code.to_s(16)}x length=#{length}"
    last_used_pos = pos - 1
    case code
    when Asn1Type::Asn1TypeInteger.value
      # @type = Asn1Type::Asn1TypeInteger
      # puts "Asn1TypeInteger"
      # bas256 = BigInt.new(1) # 256^0
      values = Array(Int32).new
      # puts "pos=#{pos} length=#{length} outer_len=#{data.size}"
      # yyy = [9, 4, 5, 6]
      # bra = yyy[1, 5]
      # puts bra
      # puts data[pos]
      # puts data[pos + 1]
      # puts data[pos + 2]
      bigN = BigInt.new(1) # 256^0
      bitcount_bigES = 0
      ddd = data[pos, length]
      terms = ddd.map_with_index { |c, index|
        this_val = ddd[length - index - 1] # [1,2,3] first is 3 - 0 - 1 ->2
        ret = this_val * bigN
        bigN = bigN * 256
        bitcount_bigES += 4 # base 256
        ret
      }
      # puts "terms=#{terms}"
      summit = terms.sum(BigInt.new(0))
      # puts "parts=#{summit}"
      # puts ddd
      # @bigInts << bigN
      @bigInts << summit
      # @bitcount_bigInts << bitcount_bigES
      # @bitcount_bigInts << bigN.bit_length
      @bitcount_bigInts << summit.bit_length
      last_used_pos = pos + length - 1
    when Asn1Type::Asn1TypeBitString.value
      @type = Asn1Type::Asn1TypeBitString
      # puts "Asn1TypeBitString"
      last_used_pos = pos
    when Asn1Type::Asn1TypeNull.value
      @type = Asn1Type::Asn1TypeNull
      # puts "Asn1TypeNull"
    when Asn1Type::Asn1TypeObjectId.value
      @type = Asn1Type::Asn1TypeObjectId
      # puts "Asn1TypeObjectId"
      values = Array(Int32).new

      # puts data[pos]
      values << data[pos] // 40
      values << data[pos] % 40
      outlen = 2
      init_value : Int32 = 0
      # length -= 1
      while length > 0
        v = data[pos]
        pos += 1
        init_value = (init_value << 7) | (v & 0x7F)
        if (v & 0x80) == 0
          values << init_value
          init_value = 0
          outlen += 1
        end
        length -= 1
        @obj_ident_sign = values
      end
      # puts init_value
      # pos -= 1
      last_used_pos = pos - 1
      # puts values
    when Asn1Type::Asn1TypeSequence.value
      @type = Asn1Type::Asn1TypeSequence
      # puts "Asn1TypeSequence"
      maxpos = pos + length
      while pos < maxpos
        #   x = data[pos..maxpos - pos]
        #   puts "#{x[0].to_s(16)}x"
        #   obj, read = self.parse(data + pos, maxpos - pos)
        #   obj, read = self.parse(x, maxpos - pos)
        last_used_pos = self.parse(data, pos)
        pos = last_used_pos + 1
        # puts "pos=#{pos}"
        #   pos += read
      end
    else
      raise "Unknonw type #{code}"
    end
    # puts "return last_used_pos=#{last_used_pos}"
    last_used_pos
  end
end
