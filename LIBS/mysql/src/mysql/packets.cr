module MySql::Protocol
  enum ResponceOn_caching_sha2_password : UInt8
    CachingSha2PasswordRequestPublicKey          = 2
    CachingSha2PasswordFastAuthSuccess
    CachingSha2PasswordPerformFullAuthentication
  end
  enum HandshakeResponse : UInt32
    CLIENT_LONG_PASSWORD                  = 0x00000001
    CLIENT_FOUND_ROWS                     = 0x00000002
    CLIENT_LONG_FLAG                      = 0x00000004
    CLIENT_CONNECT_WITH_DB                = 0x00000008
    CLIENT_NO_SCHEMA                      = 0x00000010
    CLIENT_COMPRESS                       = 0x00000020
    CLIENT_ODBC                           = 0x00000040
    CLIENT_LOCAL_FILES                    = 0x00000080
    CLIENT_IGNORE_SPACE                   = 0x00000100
    CLIENT_PROTOCOL_41                    = 0x00000200
    CLIENT_INTERACTIVE                    = 0x00000400
    CLIENT_SSL                            = 0x00000800
    CLIENT_IGNORE_SIGPIPE                 = 0x00001000
    CLIENT_TRANSACTIONS                   = 0x00002000
    CLIENT_RESERVED                       = 0x00004000
    CLIENT_SECURE_CONNECTION              = 0x00008000
    CLIENT_MULTI_STATEMENTS               = 0x00010000
    CLIENT_MULTI_RESULTS                  = 0x00020000
    CLIENT_PS_MULTI_RESULTS               = 0x00040000
    CLIENT_PLUGIN_AUTH                    = 0x00080000
    CLIENT_CONNECT_ATTRS                  = 0x00100000
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
    CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS   = 0x00400000
    CLIENT_SESSION_TRACK                  = 0x00800000
    CLIENT_DEPRECATE_EOF                  = 0x01000000
  end

  #
  # InHandshakeV10
  # ============
  class InHandshakeV10
    property raw_message : Unmarshaller
    getter auth_plugin_data : Bytes
    getter charset : UInt8
    getter server_capabilities : Int32
    getter server_plugin_name : String

    def initialize(@raw_message) # @auth_plugin_data, @charset, @server_capabilities, @server_plugin_name
      @auth_plugin_data = uninitialized Bytes
      @charset = uninitialized UInt8
      @server_capabilities = uninitialized Int32
      @server_plugin_name = uninitialized String
      protocol_version = @raw_message.read_byte!
      if protocol_version == 255
        @raw_message.error_message_unmarshall

        errono = @raw_message.read_fixed_int(2).to_u16!
        errmsg = @raw_message.read_string
        raise "Error(4) #{errono}: #{errmsg}"
      end
      # https://dev.mysql.com/doc/dev/mysql-server/9.1.0/page_protocol_connection_phase_@raw_packages_protocol_handshake_v10.html
      # null terminated string
      version = @raw_message.read_string
      # connection id 4 bytes
      thread = @raw_message.read_int
      auth_data = Bytes.new(20)

      # first part of the password cipher [8 bytes]
      @raw_message.read_fully(auth_data[0, 8])
      # filler 0x00
      @raw_message.read_byte!
      cap1 = @raw_message.read_byte!
      cap2 = @raw_message.read_byte!
      @charset = @raw_message.read_byte!
      @raw_message.read_byte_array(2)
      cap3 = @raw_message.read_byte!
      cap4 = @raw_message.read_byte!
      @server_capabilities = cap1.to_i + (cap2.to_i << 8) + (cap3.to_i << 16) + (cap4.to_i << 24)
      # second part of the password cipher [minimum 13 bytes]
      auth_plugin_data_length = @raw_message.read_byte!
      # reserved 10 bytes
      @raw_message.read_byte_array(10)

      computed_maxlength_auth_plugin = {13, auth_plugin_data_length.to_i16 - 8}.max - 1

      @raw_message.read_fully(auth_data[8, {13, auth_plugin_data_length.to_i16 - 8}.max - 1])

      @raw_message.read_byte!
      @server_plugin_name = @raw_message.read_string
      @auth_plugin_data = auth_data
    end
  end

  #
  # OutHandshakeResponse41
  # ===================
  #
  class OutHandshakeResponse41
    getter a_marshaller : Marshaller

    def initialize(@a_marshaller,
                   @username : String?,
                   @password : String?,
                   @initial_catalog : String?,
                   @auth_plugin_data : Bytes,
                   @plugin_name : String,
                   @charset : UInt8,
                   @mysql_options : ::MySql::Connection::Options)
      case @plugin_name
      when "mysql_native_password"
        caps : UInt32 = HandshakeResponse::CLIENT_PROTOCOL_41.value | HandshakeResponse::CLIENT_SECURE_CONNECTION.value | HandshakeResponse::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA.value
        # caps |= CLIENT_SSL
        caps |= HandshakeResponse::CLIENT_PLUGIN_AUTH.value if @password
        caps |= HandshakeResponse::CLIENT_CONNECT_WITH_DB.value if @initial_catalog
      when "caching_sha2_password"
        caps = HandshakeResponse::CLIENT_PROTOCOL_41.value |
               HandshakeResponse::CLIENT_SECURE_CONNECTION.value |
               HandshakeResponse::CLIENT_LONG_PASSWORD.value |
               HandshakeResponse::CLIENT_TRANSACTIONS.value |
               HandshakeResponse::CLIENT_PLUGIN_AUTH.value |
               #  CLIENT_SSL |
               HandshakeResponse::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA.value
        #  CLIENT_LOCAL_FILES |
        #  CLIENT_MULTI_RESULTS |
        # CLIENT_CONNECT_ATTRS
        # CLIENT_FOUND_ROWS
        caps |= HandshakeResponse::CLIENT_CONNECT_WITH_DB.value if @initial_catalog
      else
        raise "can't responde to protocol #{@plugin_name}"
      end
      if @mysql_options.want_tls
        caps |= HandshakeResponse::CLIENT_SSL.value
      end
      @a_marshaller.write_bytes caps, IO::ByteFormat::LittleEndian
      @a_marshaller.write_bytes 0x00000000u32, IO::ByteFormat::LittleEndian
      @a_marshaller.write_byte @charset
      23.times { @a_marshaller.write_byte 0_u8 }
      #
      #
      @a_marshaller << @username
      @a_marshaller.write_byte 0_u8

      content = MySql::Protocol.which_plugin(@plugin_name, @password, @auth_plugin_data)
      if content.size == 0
        @a_marshaller.write_byte 0_u8
      else
        @a_marshaller.write_lenenc_int content.size
        @a_marshaller.write(content)
      end

      if initial_catalog = @initial_catalog
        @a_marshaller << initial_catalog
        @a_marshaller.write_byte 0_u8
      end

      case @plugin_name
      when "mysql_native_password", "caching_sha2_password"
        @a_marshaller << @plugin_name
        @a_marshaller.write_byte 0_u8
      else
        raise "Unsupported '#{@plugin_name}' plugin"
      end
      # NO encodedAttributes
      # https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_@a_marshallers_protocol_handshake_response.html

      @a_marshaller.write_byte 0_u8
    end
  end

  #
  # OutHandshakeResponse41TLS
  # ===================
  #
  class OutHandshakeResponse41TLS
    def initialize(
      @charset : UInt8,
      @marshaller : Marshaller
    )
      caps : UInt32 = HandshakeResponse::CLIENT_PROTOCOL_41.value | # YES
        HandshakeResponse::CLIENT_SECURE_CONNECTION.value |         # YES
        HandshakeResponse::CLIENT_LONG_PASSWORD.value |             # YES
        HandshakeResponse::CLIENT_TRANSACTIONS.value |              # YES
        HandshakeResponse::CLIENT_SSL.value |                       # YES
        HandshakeResponse::CLIENT_PLUGIN_AUTH.value |               # YES
      #         CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA |
        HandshakeResponse::CLIENT_CONNECT_WITH_DB.value | # YES
        HandshakeResponse::CLIENT_LONG_FLAG.value |       # YES
        HandshakeResponse::CLIENT_LOCAL_FILES.value |     # YES
        HandshakeResponse::CLIENT_MULTI_RESULTS.value     # |   # YES
      #  HandshakeResponse::CLIENT_CONNECT_ATTRS.value     # YES

      #  Capabilities Flags
      @marshaller.write_bytes caps, IO::ByteFormat::LittleEndian
      # maximum packet size
      @marshaller.write_bytes 0x00000000u32, IO::ByteFormat::LittleEndian
      # character_set
      @marshaller.write_byte @charset
      23.times { @marshaller.write_byte 0_u8 }
    end
  end

  #
  # OutRequestPublicKeyCommon
  # ==================
  #
  class OutRequestPublicKeyCommon
    def initialize(@marshaller : Marshaller)
      @marshaller.write_byte MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordRequestPublicKey.value
    end
  end

  #
  # OutPasswordEnCoded
  # ================
  #

  class OutPasswordEnCoded
    property marshaller : Marshaller

    def initialize(@len : UInt8, @coded_password : Bytes, @marshaller)
      if @len > 0
        # is this ok no length indicator
        # packet.write_lenenc_int @len
        @marshaller.write(@coded_password)
      else
        @marshaller.write_byte 0_u8
      end
    end
  end

  #
  # OutPasswordThroughTLS
  # ==================
  #

  class OutPasswordThroughTLS
    def initialize(marshaller : Marshaller, password : String?)
      if pw = password
        if pw.size == 0
          marshaller.write_byte 0_u8
        else
          marshaller.write_string(password)
          marshaller.write_byte 0_u8
        end
      else
        marshaller.write_byte 0_u8
      end
    end
  end

  #
  # OutRequestPublicKeyAfter_sha256_password
  # ==================
  #
  class OutRequestPublicKeyAfter_sha256_password
    property message : Bytes
    property marshaller : Marshaller

    def initialize(@marshaller)
      @message = Slice.new(1, 1.to_u8)
      @marshaller.write(Slice.new(1, 1.to_u8))
    end

    def marshall
    end
  end

  #
  # SendRSAOAEPencoded
  # ==================
  #

  class SendRSAOAEPencoded
    def initialize(@len : Int32, @coded_password : Bytes, @marshaller : Marshaller)
      if @len > 0
        marshaller.write(@coded_password)
      else
        marshaller.write_byte 0_u8
      end
    end
  end

  # ==============================================================================================

  class InStateB
    # getter status : UInt8
    getter auth_data : Bytes
    getter plugin : String

    def initialize(@an_unmarshaller : Unmarshaller)
      @auth_data = uninitialized Bytes
      @plugin = uninitialized String
      @auth_data, @plugin = MySql::Protocol.plg_auth(@an_unmarshaller)
    end
  end

  # ==============================================================================================

  class InStateC
    # getter status : UInt8
    getter auth_data : Bytes
    getter plugin : String

    def initialize(@an_unmarshaller : Unmarshaller)
      @auth_data = uninitialized Bytes
      @plugin = uninitialized String
      @auth_data, @plugin = MySql::Protocol.plg_auth(@an_unmarshaller)
    end
  end

  # ==============================================================================================

  class InStateD
    getter status : UInt8

    def initialize(@raw_message : Unmarshaller)
      @status = @raw_message.read_byte!
      if @status != 0
        @raw_message.error_message_unmarshall
        raise "Status from read OK message != 1 was #{@status} and msg = #{@raw_message.remaining - 1}"
      end
      self
    end
  end

  # ==============================================================================================

  class InStateE
    getter status : UInt8
    getter pub_key : Bytes

    def initialize(@an_unmarshaller : Unmarshaller)
      @status = uninitialized UInt8
      @pub_key = uninitialized Bytes
      @status = an_unmarshaller.read_byte.not_nil!
      if @status != 1
        an_unmarshaller.error_message_unmarshall
      end
      @pub_key = an_unmarshaller.read_slice(an_unmarshaller.remaining - 1).not_nil!.to_slice
    end
  end

  # ==============================================================================================

  def self.which_plugin(in_plugin_name : String, in_password : String?, in_auth_plugin_data : Bytes)
    case in_plugin_name
    when "mysql_native_password"
      # SHA1( password ) XOR SHA1( "20-bytes random data from server" <concat> SHA1( SHA1( password ) ) )
      # https://dev.mysql.com/doc/dev/mysql-server/8.4.6/page_protocol_connection_phase_authentication_methods_native_password_authentication.html
      if password = in_password
        puts "mysql_native_password NOT VERFIED"
        auth_response2 = Bytes.new(20, 0x00.to_u8)

        puts "self.which_plugin() new mysql_native_password"
        sh1 = Shared::Sha1.new
        sh1.bigwrite(p_as_slice: password.to_slice)
        sha1_password = sh1.bigsum

        sh2 = Shared::Sha1.new
        sh2.bigwrite(p_as_slice: sha1_password)
        sha1_sha1_password = sh2.bigsum

        concat_term = in_auth_plugin_data.to_slice + Bytes.new(20 - in_auth_plugin_data.size, 0x00.to_u8) + sha1_sha1_password

        sh3 = Shared::Sha1.new
        sh3.bigwrite(p_as_slice: concat_term)
        right_term = sh3.bigsum
        20.times { |i|
          auth_response2[i] = sha1_password[i] ^ right_term[i]
        }
        auth_response2
      else
        Bytes.new(0)
      end
    when "caching_sha2_password"
      # https://dev.mysql.com/blog-archive/mysql-8-0-4-new-default-authentication-plugin-caching_sha2_password/
      #
      # generate 	XOR(SHA256(password), SHA256(SHA256(SHA256(password)), auth_plugin_data))
      #
      if password = in_password
        # puts "self.which_plugin() new caching_sha2_password works"
        crypter = Shared::Sha256.new
        crypter.bigwrite(p_as_slice: password.to_slice)
        hash1 = crypter.bigsum

        crypter2 = Shared::Sha256.new
        crypter2.bigwrite(p_as_slice: hash1)
        hash2 = crypter2.bigsum

        crypter3 = Shared::Sha256.new
        crypter3.bigwrite(p_as_slice: hash2)
        crypter3.bigwrite(p_as_slice: (in_auth_plugin_data.to_slice + Bytes.new(20 - in_auth_plugin_data.size, 0x00.to_u8)))
        hash3 = crypter3.bigsum

        hash1.size.times { |i|
          hash1[i] ^= hash3[i]
        }
        hash1
      else
        Bytes.new(0)
      end
    when "sha256_password"
      Bytes.new(0)
    when "mysql_old_password"
      Bytes.new(0)
    when "mysql_clear_password"
      Bytes.new(0)
    else
      raise "Unsupported '#{in_plugin_name}' plugin"
    end
  end

  def self.plg_auth(in_msg : Unmarshaller) : {Bytes, String}
    new_plugin_from_server = ""
    new_auth_data : Bytes = Bytes.new(0)

    {% if flag?(:trcsql) %}
      puts in_msg.in_message
    {% end %}

    status = in_msg.read_byte!
    case status
    when 0
    when 1 # iAuthMoreData
      new_auth_data = in_msg.read_slice(in_msg.remaining)
    when 254 # iEOF
      if in_msg.remaining == 0
        new_plugin_from_server = "mysql_old_password"
      else
        new_plugin_from_server = in_msg.read_string
        {% if flag?(:trcsql) %}
          puts "new_plugin_from_server #{new_plugin_from_server.size}, #{new_plugin_from_server}"
        {% end %}

        new_auth_data = in_msg.read_slice(in_msg.remaining - 1)
        ett = new_plugin_from_server.to_slice
        allt = ett + new_auth_data
      end
    when 255 # error
      in_msg.error_message_unmarshall
    else
      rest = in_msg.read_slice(in_msg.remaining)
      puts "status, rest=#{status}, #{rest}#\n#{rest.hexdump}"
      raise "plg_auth not expecting #{status}"
    end
    {new_auth_data, new_plugin_from_server}
  end
end
