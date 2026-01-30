class Certificate
  property from_server_certificaterequest : Bytes
  property from_server_certificate : Bytes
  property from_server_certificateverify : Bytes

  def initialize
    @from_server_certificaterequest = uninitialized Bytes
    @from_server_certificate = uninitialized Bytes
    @from_server_certificateverify = uninitialized Bytes
  end
end
