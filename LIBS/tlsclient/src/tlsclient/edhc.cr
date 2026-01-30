"
willys4@Mac MYSQLMARS2025 % crystal tool hierarchy lib/mysql/src/mysql.cr -e Allt
- class Object (4 bytes)
  |
  +- class Reference (4 bytes)
     |
     +- class Allt::Curve (64 bytes)
     |      @name  : String         ( 8 bytes)
     |      @a     : BigInt         (16 bytes)
     |      @b     : BigInt         (16 bytes)
     |      @field : Allt::SubGroup ( 8 bytes)
     |      @g     : Allt::Point    ( 8 bytes)
     |
     +- class Allt::ECDHE (40 bytes)
     |      @priv_multi : BigInt                          (16 bytes)
     |      @pub_key    : (Allt::Inf | Allt::Point | Nil) ( 8 bytes)
     |      @curve      : Allt::Curve                     ( 8 bytes)
     |
     +- class Allt::Inf (48 bytes)
     |      @x     : BigInt      (16 bytes)
     |      @y     : BigInt      (16 bytes)
     |      @curve : Allt::Curve ( 8 bytes)
     |
     +- class Allt::KeyPair (40 bytes)
     |      @curve      : Allt::Curve                     ( 8 bytes)
     |      @priv_multi : BigInt                          (16 bytes)
     |      @pub_key    : (Allt::Inf | Allt::Point | Nil) ( 8 bytes)
     |
     +- class Allt::MyECDH (40 bytes)
     |      @curve      : Allt::Curve                     ( 8 bytes)
     |      @priv_multi : BigInt                          (16 bytes)
     |      @pub_key    : (Allt::Inf | Allt::Point | Nil) ( 8 bytes)
     |
     +- class Allt::Point (64 bytes)
     |      @x     : BigInt      (16 bytes)
     |      @y     : BigInt      (16 bytes)
     |      @curve : Allt::Curve ( 8 bytes)
     |      @p     : BigInt      (16 bytes)
     |
     +- class Allt::SubGroup (56 bytes)
            @p : BigInt        (16 bytes)
            @g : Array(BigInt) ( 8 bytes)
            @n : BigInt        (16 bytes)
            @h : Int32         ( 4 bytes)
"

# module Allt
# https://github.com/alexmgr/tinyec
class ECDH
  getter curve
  property priv_multi : BigInt = BigInt.new(0)
  property pub_key : Point? | Inf? | Nil?

  def initialize
    # Secp256r1 is p256
    # Secp256r1 prime256v1 1.2. 840.10045. 3.1. 7
    c_vals = {name: "p256",
              p:    BigInt.new("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
              a:    BigInt.new("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
              b:    BigInt.new("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
              g:    [
                BigInt.new("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
                BigInt.new("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
              ],
              n: BigInt.new("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
              h: 0x1,
    }
    sub_group = EllipticCurve::SubGroup.new(c_vals[:p], c_vals[:g], c_vals[:n], c_vals[:h])
    @curve = EllipticCurve::Curve.new(c_vals[:a], c_vals[:b], sub_group, c_vals[:name])
  end

  def calc_public_key_xy : Array(BigInt) # | Nil
    if curve_init_point = @curve.g
      if curve_init_point.is_a?(Point)
        pub_key = curve_init_point.mul(@priv_multi)
        #   if typeof(pub_key) == Point
        #   if pub_key.is_a?(Point)
        if pub_key.class == EllipticCurve::Point
          # puts pub_key.x
          @pub_key = pub_key
          return [pub_key.x, pub_key.y]
        end
        raise "calc_public_key_xy gives not a point"
      end
      #   else
      raise "curve.g does not hold an init point(2)"
    end
    raise "curve.g does not hold an init point(1)"
  end

  #   end

  def self.egcd(a, b)
    if a == 0
      return b, 0, 1
    else
      g, y, x = egcd(b % a, a)
      return g, x - (b // a) * y, y
    end
  end

  def self.mod_inv(a, p) : BigInt
    if a < 0
      return p - self.mod_inv(-a, p)
    end
    g, x, y = self.egcd(a, p)
    if g != 1
      raise "Modular inverse does not exist"
    else
      return x % p
    end
  end
end

#   def self.to_hex(val : BigInt)
#     "0x%dx" % val
#   end

class Curve
  property name : String
  property a : BigInt
  property b : BigInt
  getter field : SubGroup
  property g : Point

  def initialize(@a, @b, @field, @name)
    # alias XXX = {name: String, p: BigInt, a: BigInt, b: BigInt, g: Array(BigInt), n: BigInt, h: Int32}
    @g = uninitialized Point
    @g = Point.new(self, @field.g[0], @field.g[1])
  end

  def on_curve(x, y)
    return (y*y - x*x*x - @a * x - @b) % @field.p == 0
  end

  def to_s(io : IO)
    io << "#{@name} => y^2 = x^3 + #{@a} x + #{@b} (mod #{@field.p})"
  end
end

class SubGroup
  property p : BigInt
  property g : Array(BigInt)
  property n : BigInt
  property h : Int32

  def initialize(@p, @g, @n, @h)
  end
end

class Inf
  property x : BigInt = BigInt.new
  property y : BigInt = BigInt.new
  property curve : Curve

  def initialize(@curve, @x = BigInt.new, @y = BigInt.new)
  end

  def mul(other)
    self
  end

  def add(other)
    if other.class == Allt::Inf
      return other
    end
    if other.class == Allt::Point
      return other
    end
    raise "Inf:: add()Unsupported operand type(s)"
  end
end

class Point
  property x : BigInt
  property y : BigInt
  property curve : Curve
  on_curve : Bool = true

  def initialize(@curve : Curve, @x : BigInt, @y : BigInt)
    @p = @curve.field.p
    if @curve.on_curve(@x, @y) == false
      raise "Point new not on curve"
    end
  end

  def self.to_slice(x_in : BigInt, y_in : BigInt) : Array(Bytes)
    the_x_as_bytes : Slice(UInt8) = Slice.new(32, 0x00.to_u8)
    end_pos = 31
    cop_x = x_in
    while cop_x > 0
      cop_x, r = cop_x.divmod(256)
      the_x_as_bytes[end_pos] = r.to_u8
      end_pos -= 1
    end
    the_y_as_bytes : Slice(UInt8) = Slice.new(32, 0x00.to_u8)
    end_pos = 31
    cop_y = y_in
    while cop_y > 0
      cop_y, r = cop_y.divmod(256)
      the_y_as_bytes[end_pos] = r.to_u8
      end_pos -= 1
    end
    [the_x_as_bytes, the_y_as_bytes]
  end

  def self.from_bytes(x_in : Bytes, y_in : Bytes)
    x_as_string = x_in.map { |val| "%02X" % val }.join
    y_as_string = y_in.map { |val| "%02X" % val }.join
    x_ret = BigInt.new(x_as_string, base = 16)
    y_ret = BigInt.new(y_as_string, base = 16)
    {x_ret, y_ret}
  end

  def dom(p, q) : BigInt
    if p.x == q.x
      (3 * p.x*p.x + @curve.a) * Allt.mod_inv(2 * p.y, @p)
    else
      (p.y - q.y) * Allt.mod_inv(p.x - q.x, @p)
    end
  end

  def add(other : Point | Inf) : Point | Inf
    if @x == other.x && @y != other.y
      return Inf.new(@curve)
    end
    if @curve == other.curve
      m : BigInt = dom(self, other)
      x_r = (m * m - @x - other.x) % @p
      y_r = -(@y + m * (x_r - @x)) % @p
      Point.new(@curve, x_r, y_r)
    else
      raise "point: add not on same curve"
    end
  end

  def sub(other : Point | Inf) : Point | Inf
    if typeof(other) == Inf
      return self.add(other)
    elsif typeof(other) == Point
      return self.add(Point.new(@curve, other.x, -other.y % @p))
    else
      raise "Point:: sub() Unsupported operand type(s)"
    end
  end

  def mul(other)
    addend : Point | Inf = self
    if typeof(other) == Inf
      return Inf.new(@curve)
    elsif typeof(other) == BigInt || typeof(other) == Int32
      if other % @curve.field.n == 0
        return Inf.new(@curve)
      end
      if other < 0
        addend = Point.new(@curve, @x, -@y % @p)
      else
        addend = self
      end
      result = Inf.new(@curve)
      # Iterate over all bits starting by the LSB
      bit_cnt = other.bit_length
      (0..bit_cnt).each { |bitpos|
        if other.bit(bitpos) == 1
          result = result.add(addend)
        end
        addend = addend.add(addend)
      }
      result
      # for bit in reversed([int(i) for i in bin(abs(other))[2:]]):
      #     if bit == 1:
      #         result += addend
      #     addend += addend
      #     end
      # return result
    else
      raise "Point:: mul() Unsupported operand type(s)"
    end
  end

  def to_s(io : IO)
    io << "Point: x=#{@x}, y=#{@y}"
  end

  def to_x(io : IO)
    io << @x.to_s(base = 16, upcase = true)
  end
end

class KeyPair
  property curve : Curve
  # property can_sign : Bool
  # property can_encrypt : Bool
  property priv_multi : BigInt
  property pub_key : Point | Inf | Nil

  # property priv_key :
  def initialize(@curve, @priv_multi)
    if curve_init_point = @curve.g
      @pub_key = curve_init_point.mul(@priv_multi)
      return self
    end
    raise "KeyPair:: init() curve undefined"
  end
end

# class MyECDH
#   property curve : Curve
#   property priv_multi : BigInt
#   property pub_key : Point? | Inf? | Nil?

#   def initialize(@curve, @priv_multi)
#   end

#   def calc_public_key_xy : Array(BigInt) | Nil
#     if curve_init_point = @curve.g
#       if curve_init_point.is_a?(Point)
#         pub_key = curve_init_point.mul(@priv_multi)
#         #   if typeof(pub_key) == Point
#         if pub_key.is_a?(Point)
#           # puts pub_key.x
#           @pub_key = pub_key
#           return [pub_key.x, pub_key.y]
#         end
#         raise "calc_public_key_xy gives not a point"
#       end
#       #   else
#       raise "curve.g does not hold an init point"
#     end
#   end
# end
# end
