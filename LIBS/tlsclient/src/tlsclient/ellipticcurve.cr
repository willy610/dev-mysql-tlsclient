module EllipticCurve

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
      if other.class == EllipticCurve::Inf
        return other
      end
      if other.class == EllipticCurve::Point
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
        (3 * p.x*p.x + @curve.a) * ECDH.mod_inv(2 * p.y, @p)
      else
        (p.y - q.y) * ECDH.mod_inv(p.x - q.x, @p)
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
end
