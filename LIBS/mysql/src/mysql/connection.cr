require "socket"
require "io/hexdump"
require "tlsclient"
require "db"

class MySql::Connection < DB::Connection
  struct Options
    getter host : String
    getter port : Int32
    getter username : String?
    getter password : String?
    getter initial_catalog : String?

    getter want_tls : Bool
    getter charset : String

    def initialize(
      @host : String, @port : Int32, @username : String?, @password : String?,
      @initial_catalog : String?,
      @charset : String,
      @want_tls : Bool,
    )
    end

    def self.from_uri(uri : URI) : Options
      host = uri.hostname || raise "no host provided"
      port = uri.port || 3306
      username = uri.user
      password = uri.password
      params = uri.query_params
      charset = uri.query_params.fetch "encoding", Collations.default_collation
      path = uri.path
      if path && path.size > 1
        initial_catalog = path[1..-1]
      else
        initial_catalog = nil
      end
      # Do we have a tls param as param like 'mysql://test:PASSWORD@192.168.0.25/chrisdate?tls=skip-verify'
      # pp uri.query_params
      if uri.query_params.has_key?("tls")
        want_tls = true
      else
        want_tls = false
      end
      Options.new(
        host: host, port: port, username: username, password: password,
        initial_catalog: initial_catalog, charset: charset, want_tls: want_tls)
    end
  end

  property socket : TCPSocket
  property auth_data_to_use : Bytes
  property responce_reader : SQLResponceReader
  property anBRIDGE : MySql::BRIDGE::BRIDGEPlain | MySql::BRIDGE::BRIDGETls
  property seq_RW : UInt8

  def initialize(options : ::DB::Connection::Options,
                 @mysql_options : ::MySql::Connection::Options)
    super(options)
    @socket = uninitialized TCPSocket
    @auth_data_to_use = uninitialized Bytes
    @responce_reader = uninitialized SQLResponceReader
    @anBRIDGE = uninitialized MySql::BRIDGE::BRIDGEPlain | MySql::BRIDGE::BRIDGETls
    @seq_RW = 1
  end

  def go
    @responce_reader = SQLResponceReader.new(self)
    header_4_mysql = uninitialized UInt8[4]
    state = "1"
    @seq_RW = 1
    begin
      charset_id = Collations.id_for_collation(@mysql_options.charset).to_u8
      @socket = TCPSocket.new(@mysql_options.host, @mysql_options.port)
      @socket.recv_buffer_size = 17000
      plugin_1 = ""
      auth_data_1 : Bytes = Bytes.new(0)
      plugin_B = ""
      auth_data_B : Bytes = Bytes.new(0)
      reader_1_obj = uninitialized Protocol::InHandshakeV10
      while state != "END"
        {% if flag?(:trcsql) %}
          puts "===================================================>state=#{state}"
        {% end %}
        case state
        when "1"
          # THIS IS A STATE "1" read and write using '@socket' is ok
          # later on use '@anBRIDGE' for read and write
          # READ
          @socket.read_fully(header_4_mysql.to_slice)
          if header_4_mysql[0] == 255
            errornumber = header_4_mysql[1].to_u32! + 256 * header_4_mysql[2].to_u32!
            errorname = Bytes.new(5)
            @socket.read(errorname)
            errortext = @socket.gets
            raise "Error(2) #{errornumber} (#{errorname}): #{errortext}"
          end
          message_mysql_size = header_4_mysql[0].to_i + (header_4_mysql[1].to_i << 8) + (header_4_mysql[2].to_i << 16)
          @seq_RW = header_4_mysql[3].to_u8 + 1
          message_in = Bytes.new(message_mysql_size)
          @socket.read(message_in)
          {% if flag?(:trcsql) %}
            puts "<---#{4 + message_in.size}-----[sql]InHandshakeV10 ,#{header_4_mysql},#{message_in} "
          {% end %}

          an_unmarshaller = Unmarshaller.new(message_in)
          reader_1_obj = Protocol::InHandshakeV10.new(an_unmarshaller)
          plugin_1 = reader_1_obj.server_plugin_name
          auth_data_1 = reader_1_obj.auth_plugin_data
          {% if flag?(:trcsql) %}
            puts "plugin_1=#{plugin_1}"
            puts "auth_data_1=#{auth_data_1}"
          {% end %}

          # ==========================
          if @mysql_options.want_tls
            # STARTTLS is used when switching from plain to TLS
            # https://en.wikipedia.org/wiki/Opportunistic_TLS
            m = IO::Memory.new
            a_marshaller = Marshaller.new(m)
            Protocol::OutHandshakeResponse41TLS.new(charset_id, a_marshaller)
            mess = m.to_slice
            msg_size = mess.size
            header_4_mysql[2] = ((msg_size & 0x00FF0000) >> 16).to_u8
            header_4_mysql[1] = ((msg_size & 0x0000FF00) >> 8).to_u8
            header_4_mysql[0] = (msg_size & 0x000000FF).to_u8
            header_4_mysql[3] = @seq_RW
            @seq_RW += 1
            {% if flag?(:trcsql) %}
              puts "---#{4 + msg_size}-----[sql]>#{header_4_mysql},OutHandshakeResponse41TLS"
            {% end %}

            @socket.write(header_4_mysql.to_slice + mess)
            @socket.flush
            #
            @responce_reader.using_tls = true
            state = "P_tls"
            # ==========================
          else
            # Use a bridge with no tls
            @anBRIDGE = MySql::BRIDGE::BRIDGEPlain.new(@socket)
            @anBRIDGE.seq_out = @seq_RW
            @responce_reader.use_bridge(@anBRIDGE)
            state = "A"
          end
        when "A"
          # NO READ
          # WRITE
          if plugin_1 == "sha256_password"
            @auth_data_to_use = auth_data_1
            m = IO::Memory.new
            a_marshaller = Marshaller.new(m)
            Protocol::OutRequestPublicKeyAfter_sha256_password.new(a_marshaller)
            to_write = m.to_slice
            @anBRIDGE.write_message(to_write, "OutRequestPublicKeyAfter_sha256_password")
            state = "E"
          else
            m = IO::Memory.new
            a_marshaller = Marshaller.new(m)
            Protocol::OutHandshakeResponse41.new(a_marshaller, @mysql_options.username,
              @mysql_options.password,
              @mysql_options.initial_catalog,
              reader_1_obj.auth_plugin_data,
              reader_1_obj.server_plugin_name,
              charset_id,
              @mysql_options)
            to_write = m.to_slice
            {% if flag?(:trcsql) %}
              puts "OutHandshakeResponse41=\n#{to_write.hexdump}"
            {% end %}
            @anBRIDGE.write_message(to_write, "OutHandshakeResponse41")
            state = "B"
          end
        when "B"
          # READ
          for_us, hdr_4sql, message_in = @anBRIDGE.read_packet
          if for_us
            an_unmarshaller = Unmarshaller.new(message_in)
            reader_B_obj = Protocol::InStateB.new(an_unmarshaller)
            auth_data_B = reader_B_obj.auth_data
            plugin_B = reader_B_obj.plugin
            {% if flag?(:trcsql) %}
              puts "plugin_B=#{plugin_B}"
              puts "auth_data_B=#{auth_data_B}"
            {% end %}

            # WRITE
            if plugin_B != ""
              # Got a new plugin. We need to take another turn to the server
              plugin_content = MySql::Protocol.which_plugin(plugin_B, @mysql_options.password, auth_data_1)
              len = plugin_content.size
              if len == 0 && plugin_B == "sha256_password"
                # cond_1
                @auth_data_to_use = auth_data_B
                m = IO::Memory.new
                a_marshaller = Marshaller.new(m)
                Protocol::OutRequestPublicKeyAfter_sha256_password.new(a_marshaller)
                to_write = m.to_slice
                @anBRIDGE.write_message(to_write, "OutRequestPublicKeyAfter_sha256_password")
                state = "E"
                # end
              else
                # cond_2
                @auth_data_to_use = auth_data_B
                m = IO::Memory.new
                a_marshaller = Marshaller.new(m)
                answer_a_new_password_package = Protocol::OutPasswordEnCoded.new(len.to_u8, plugin_content, a_marshaller)
                to_write = m.to_slice
                @anBRIDGE.write_message(to_write, "OutPasswordEnCoded")
                state = "C"
              end
            else
              # that is plugin_B == ""
              case plugin_1
              when "caching_sha2_password"
                case auth_data_B.size
                when 1
                  case auth_data_B[0]
                  when MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordFastAuthSuccess.value
                    # puts "(0)MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordFastAuthSuccess read ok result'"
                    # cond_3
                    state = "D"
                  when MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordPerformFullAuthentication.value
                    puts "(1)MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordPerformFullAuthentication"
                    # cond_4
                    # if @anBRIDGE.is_tls
                    #   send_password(@mysql_options.password)
                    #   state = "D"
                    # else
                    # puts "funkar  med @auth_data_to_use = auth_data_1"
                    @auth_data_to_use = auth_data_1
                    # @auth_data_to_use = auth_data_B# IDAG ????????????
                    m = IO::Memory.new
                    a_marshaller = Marshaller.new(m)
                    Protocol::OutRequestPublicKeyCommon.new(a_marshaller)
                    to_write = m.to_slice
                    @anBRIDGE.write_message(to_write, "OutRequestPublicKeyCommon")
                    state = "E"
                    # end
                  else
                    raise "When 'caching_sha2_password' got odd auth_data_B[0] (1)= #{auth_data_B[0]}"
                  end
                else
                  state = "END" # OK
                end
              when "sha256_password"
                state = "END"
              else
                state = "END" # succes
              end
            end
          else
            # re-read and keep stat
          end
        when "C"
          # READ
          for_us, hdr_4sql, message_in = @anBRIDGE.read_packet
          if for_us
            an_unmarshaller = Unmarshaller.new(message_in)
            reader_C_obj = Protocol::InStateC.new(an_unmarshaller)
            auth_data_C = reader_C_obj.auth_data
            plugin_C = reader_C_obj.plugin

            if plugin_C != ""
              raise "Do not allow to change the auth plugin more than once"
            end
            case plugin_B
            when "caching_sha2_password"
              case auth_data_C.size
              when 1
                case auth_data_C[0]
                when MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordFastAuthSuccess.value
                  # cond_1
                  puts "(2)MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordFastAuthSuccess read ok result'"
                  state = "D"
                when MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordPerformFullAuthentication.value
                  # cond_2
                  puts "(3)MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordPerformFullAuthentication"

                  @auth_data_to_use = auth_data_B
                  m = IO::Memory.new
                  a_marshaller = Marshaller.new(m)
                  Protocol::OutRequestPublicKeyCommon.new(a_marshaller)
                  to_write = m.to_slice

                  @anBRIDGE.write_message(to_write, "OutRequestPublicKeyCommon")
                  state = "E"
                else
                  raise "When 'caching_sha2_password' got odd auth_data_B[0] (2)= #{auth_data_B[0]}"
                end
              else
                # cond_3
                state = "END" # OK
              end
            when "sha256_password"
              # cond_4
              state = "END"
            else
              # cond_5
              state = "END"
            end
          else
            # redo with the same state
          end
        when "D"
          # Just read an ok? or error message
          # READ
          for_us, hdr_4sql, message_in = @anBRIDGE.read_packet
          if for_us
            an_unmarshaller = Unmarshaller.new(message_in)
            reader_D_obj = Protocol::InStateD.new(an_unmarshaller)
            state = "END"
          else
          end
        when "E"
          # fail here
          for_us, hdr_4sql, message_in = @anBRIDGE.read_packet
          if for_us
            an_unmarshaller = Unmarshaller.new(message_in)
            reader_E_obj = Protocol::InStateE.new(an_unmarshaller)

            if use_auth_data = @auth_data_to_use
              encoded_password, _ = MySql::RSAOAEP.go(@mysql_options.password, reader_E_obj.pub_key, use_auth_data)
              m = IO::Memory.new
              a_marshaller = Marshaller.new(m)
              send_RSAOAP = Protocol::SendRSAOAEPencoded.new(encoded_password.size, encoded_password, a_marshaller)
              to_write = m.to_slice
              @anBRIDGE.write_message(to_write, "SendRSAOAEPencoded")
              state = "D"
            else
              raise "Internal @auth_data_to_use has no value in state 'E' "
            end
          else
          end
        when "P_tls"
          # STARTTLS
          # https://en.wikipedia.org/wiki/Opportunistic_TLS
          # https://crystal-lang.org/api/1.15.1/OpenSSL/SSL/Socket/Client.html
          # https://dev.mysql.com/blog-archive/mysql-8-0-4-new-default-authentication-plugin-caching_sha2_password/
          {% if flag?(:trcsql) %}
            puts "TLS request package"
          {% end %}
          tlsconn = TLSClient::Client.new(@socket, client_send_empty_certificate: true) # ALWAYS false for WEB. BUT true for MYSQL)

          @anBRIDGE = MySql::BRIDGE::BRIDGETls.new(@socket, tlsconn)

          @anBRIDGE.seq_out = @seq_RW
          @anBRIDGE.set_halfconnections(tlsconn.s_ap_traffic, tlsconn.c_ap_traffic)
          @anBRIDGE.set_tls_record_type_applicationdata(tlsconn.get_value_RecordTypeApplicationData)
          @responce_reader.use_bridge(@anBRIDGE)
          {% if flag?(:trcsql) %}
            puts "from TLSCONNECT DONE"
          {% end %}

          state = "Q_tls"
        when "Q_tls"
          {% if flag?(:trcsql) %}
            puts "plugin_1=#{plugin_1}"
          {% end %}

          if plugin_1 == "sha256_password"
            puts "Connection::go() state=='Q_tls' and plugin_1 == 'sha256_password' is NOT verified yet"
            state = "END"
          else
            m = IO::Memory.new
            a_marshaller = Marshaller.new(m)
            Protocol::OutHandshakeResponse41.new(a_marshaller, @mysql_options.username,
              @mysql_options.password,
              @mysql_options.initial_catalog,
              reader_1_obj.auth_plugin_data,
              reader_1_obj.server_plugin_name,
              charset_id,
              @mysql_options)
            to_write = m.to_slice

            @anBRIDGE.write_message(to_write, "OutHandshakeResponse41")
            state = "R_tls"
          end
        when "R_tls"
          # READ
          for_us, hdr_4sql, message_in = @anBRIDGE.read_packet
          if for_us
            an_unmarshaller = Unmarshaller.new(message_in)
            reader_B_obj = Protocol::InStateB.new(an_unmarshaller)
            auth_data_B = reader_B_obj.auth_data
            plugin_B = reader_B_obj.plugin
            {% if flag?(:trcsql) %}
              puts "plugin_B=#{plugin_B}"
              puts "auth_data_B=#{auth_data_B}"
            {% end %}

            # WRITE
            if plugin_B != ""
              # Got a new plugin. We need to take another turn to the server
              plugin_content = MySql::Protocol.which_plugin(plugin_B, @mysql_options.password, auth_data_1)
              len = plugin_content.size
              if len == 0 && plugin_B == "sha256_password"
                # cond_1
                send_password(@mysql_options.password)
                # Just read an ok? or error message
                state = "D"
              else
                #  cond_2
                @auth_data_to_use = auth_data_B
                m = IO::Memory.new
                a_marshaller = Marshaller.new(m)
                answer_a_new_password_package = Protocol::OutPasswordEnCoded.new(len.to_u8, plugin_content, a_marshaller)
                to_write = m.to_slice
                @anBRIDGE.write_message(to_write, "OutPasswordEnCoded")
                puts "Connection::go() state=='R_tls' and plugin_B != '' and more is  NOT verified yet"
                state = "END"
              end
            else
              # that is plugin_B == ""
              case plugin_1
              when "caching_sha2_password"
                case auth_data_B.size
                when 1
                  # cond_3
                  case auth_data_B[0]
                  when MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordFastAuthSuccess.value
                    state = "D"
                  when MySql::Protocol::ResponceOn_caching_sha2_password::CachingSha2PasswordPerformFullAuthentication.value
                    # cond_4
                    send_password(@mysql_options.password) # this works as of 2026-01-08
                    state = "D"
                  else
                    raise "When 'caching_sha2_password' got odd auth_data_B[0] (1)= #{auth_data_B[0]}"
                  end
                else
                  # cond_5
                  state = "END" # OK
                end
              when "sha256_password"
                # cond_6
                raise "UNPROVEN"
                state = "END"
              else
                # cond_7
                state = "END" # succes
              end
            end
          else
            # re-read and keep stat
          end
        else
          raise "Unknown state=#{state}"
        end
      end
      @anBRIDGE.multi_message_packet = true
      @anBRIDGE.seq_out = 0
      self
    rescue ex
      puts "MySql::Connection failed=#{ex.message}"
      raise DB::ConnectionRefused.new
    end
  end

  def send_password(password)
    m = IO::Memory.new
    a_marshaller = Marshaller.new(m)

    Protocol::OutPasswordThroughTLS.new(a_marshaller, password)
    to_write = m.to_slice
    @anBRIDGE.write_message(to_write, "OutPasswordThroughTLS")
  end

  # --------------------------
  # --------------------------
  def do_close
    super
    begin
      # ???? write_packet(the_conn: self, calling_obj: nil, name: "Quit",
      #   tls_handshake_type: TLSRecordType::RecordTypeApplicationData.value) do |packet|
      #   Protocol::Quit.new.write(packet)
      # end
      @socket.close
    rescue
    end
  end

  # --------------------------
  # SQL :
  # --------------------------

  def read_column_definitions(target : Array(ColumnSpec), column_count : Int, responce_reader = nil)
    # Parse column definitions
    # http://dev.mysql.com/doc/internals/en/com-query-response.html#packet-Protocol::ColumnDefinition
    if reader = responce_reader
      column_count.times do
        reader.next("Connection::read_column_definitions() column_count.times")
        reader.read_message() do |packet|
          catalog = packet.read_lenenc_string
          schema = packet.read_lenenc_string
          table = packet.read_lenenc_string
          org_table = packet.read_lenenc_string
          name = packet.read_lenenc_string
          org_name = packet.read_lenenc_string
          next_length = packet.read_lenenc_int # length of fixed-length fields, always 0x0c
          raise "Unexpected next_length value: #{next_length}." unless next_length == 0x0c
          character_set = packet.read_fixed_int(2).to_u16!
          column_length = packet.read_fixed_int(4).to_u32!
          column_type = packet.read_fixed_int(1).to_u8!
          flags = packet.read_fixed_int(2).to_u16!
          decimal = packet.read_fixed_int(1).to_u8!
          filler = packet.read_fixed_int(2).to_u16! # filler [00] [00]
          raise "Unexpected filler value #{filler}" unless filler == 0x0000

          target << ColumnSpec.new(catalog, schema, table, org_table, name, org_name, character_set, column_length, column_type, flags, decimal)
        end
      end

      if column_count > 0
        reader.next("Connection::read_column_definitions() column_count > 0")
        reader.read_message() do |eof_packet|
          goteof = eof_packet.read_byte # TODO assert EOF Packet
          if goteof == 0xfe
            # No drain required
            return 0xfe
          else
            raise "expected enf of file but got #{goteof}"
          end
        end
      end
    else
      raise "read_column_definitions missing parameter 'responce_reader"
    end
    nil
  end

  def build_prepared_statement(query) : MySql::Statement
    MySql::Statement.new(self, query)
  end

  def build_unprepared_statement(query) : MySql::UnpreparedStatement
    MySql::UnpreparedStatement.new(self, query)
  end
end
