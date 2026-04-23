module TLSClient
  class ServerHelloMessage
    @raw_package : Unmarshaller
    property sharedkey_ECDH : Bytes

    def initialize(@raw_package : Unmarshaller, edch_container : ECDHContainer)
      #
      # Start consuming message
      #
      hello_type : UInt8 = @raw_package.read_byte!
      @sharedkey_ECDH = Bytes.new(0)
      length : UInt64 = ((@raw_package.read_byte! << 16) + (@raw_package.read_byte! << 8) + @raw_package.read_byte!).to_u64
      vers : UInt32 = ((@raw_package.read_byte! << 8) + @raw_package.read_byte!).to_u32
      random : Bytes = @raw_package.read_slice(32)
      l_sessionId = @raw_package.read_fixed_int(1)
      session = @raw_package.read_slice(l_sessionId)
      cipherSuite = @raw_package.read_fixed_int(2)
      compressionMethod = @raw_package.read_fixed_int(1)

      # 4.1.3.  Server Hello
      # For reasons of backward compatibility with middleboxes (see Appendix D.4),
      # the HelloRetryRequest message uses the same structure as the ServerHello,
      # but with Random set to the special value of the SHA-256 of "HelloRetryRequest":

      # CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
      # C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
      # HelloRetryRequest?
      #
      # Section 4.1.4
      # Look into
      #  -  supported_versions (see Section 4.2.1)

      #  -  cookie (see Section 4.2.2)

      #  -  key_share (see Section 4.2.8)
      #

      check_random = random.map { |c| c.to_s(base: 16, upcase: true) }.join(' ')
      # puts "random=#{random}"
      # puts "check_random in servehello=#{check_random}"
      if check_random == "CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91 C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C"
        raise "ServerHelloMessage::initialize() got 'HelloRetryRequest' (4.1.3) as reserved random value"
      end

      # 4.1.3.  Server Hello
      # "supported_versions"
      # Current ServerHello messages additionally contain
      # either the "pre_shared_key" extension or the "key_share"
      # extension, or both (when using a PSK with (EC)DHE key
      # establishment).
      extension_size = ((@raw_package.read_byte! << 8) + @raw_package.read_byte!).to_u32
      # Collect all extensions
      while extension_size > 0
        extension = ((@raw_package.read_byte! << 8) + @raw_package.read_byte!).to_i16
        extension_size -= 2
        {% if flag?(:trctls) %}
          puts "ServerHelloMessage::extension=#{extension}"
        {% end %}

        case extension
        when TLSDefinitions::ExtensionType::ExtensionSupportedVersions.value
          extension_length = ((@raw_package.read_byte! << 8) + @raw_package.read_byte!).to_i32
          extension_size -= extension_length
          extension_content_ExtensionSupportedVersions = @raw_package.read_slice(extension_length)
          {% if flag?(:trctls) %}
            puts "ServerHelloMessage::(ExtensionSupportedVersions) extension_content_ExtensionSupportedVersions=#{extension_content_ExtensionSupportedVersions}"
          {% end %}
          # extension_size -= extension_length
        when TLSDefinitions::ExtensionType::ExtensionKeyShare.value
          # This extension has different formats in SH and HRR, accept either
          # and let the handshake logic decide. See RFC 8446, Section 4.2.8.
          extension_length = ((@raw_package.read_byte! << 8) + @raw_package.read_byte!).to_i32
          extension_size -= extension_length
          if extension_length == 2
            selectedGroup = @raw_package.read_slice(extension_length)
            raise "ServerHelloMessage::initialize() length of 'ExtensionKeyShare' is just 2"
          else
            _ = ((@raw_package.read_byte! << 8) + @raw_package.read_byte!).to_i32
            len = ((@raw_package.read_byte! << 8) + @raw_package.read_byte!).to_i32
            extension_size -= 4
            extension_content = @raw_package.read_slice(len)
            x, y = EllipticCurve::Point.from_bytes(extension_content[1, 32], extension_content[33, 32])
            server_public_key = EllipticCurve::Point.new(edch_container.the_ECDH.curve, x, y)
            shared_point = server_public_key.mul(edch_container.priv_key_int)
            if shared_point.class == EllipticCurve::Point
              @sharedkey_ECDH, shared_y = EllipticCurve::Point.to_slice(shared_point.x, shared_point.y)
            else
              raise "ServerHelloMessage::initialize() Can't compute a shared key"
            end
          end
        when TLSDefinitions::ExtensionType::ExtensionPreSharedKey.value
          raise "ServerHelloMessage::initialize() can't handle 'ExtensionPreSharedKey'"
        else
          raise "ServerHelloMessage::initialize() unsupported extension '#{extension}' in servermessag "
        end
      end
      # Now we have all values to create the instance
    end
  end
end
