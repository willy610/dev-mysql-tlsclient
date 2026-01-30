
class ECDHContainer
  property the_ECDH : ECDH
  property priv_key_int : BigInt
  @pub_client_key : EllipticCurve::Point | EllipticCurve::Inf

  def initialize
    @the_ECDH = ECDH.new
    @pub_client_key = uninitialized EllipticCurve::Point | EllipticCurve::Inf
    @priv_key_int = uninitialized BigInt
    # yyy = BigInt.new(Random.rand * BigFloat.new(@the_ECDH.curve.field.n))
    #
    # Compute a client public key
    #
    # set_private_key(yyy)
    # @pub_client_key = @the_ECDH.curve.g.mul(@priv_key_int)
    self
  end

  def set_private_key(xxx : BigInt)
    @priv_key_int = xxx
    # Compute a client public key
    @pub_client_key = @the_ECDH.curve.g.mul(@priv_key_int)
  end

  def calc_public_key_xy
    if @pub_client_key.class == EllipticCurve::Point
      # if typeof(@pub_client_key) == BigInt
      {@pub_client_key.x, @pub_client_key.y}
    else
      raise "ECDHContainer calc_public_key_xy() '@pub_client_key' is not a Point"
    end
  end
end
