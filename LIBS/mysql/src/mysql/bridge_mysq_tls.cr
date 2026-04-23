# alias LLLMMM = {StaticArray(UInt8, 4), Slice(UInt8)}
module MySql::BRIDGE
  abstract class BRIDGE
    property socket : TCPSocket
    property multi_message_packet : Bool
    property seq_out : UInt8

    def initialize(@socket)
      @multi_message_packet = false
      @seq_out = 0
    end

    abstract def read_packet : {Bool, StaticArray(UInt8, 4), Slice(UInt8)}

    abstract def read_message_set : Slice(UInt8)

    abstract def write_message(mess : Bytes, mess_name = "NO_MESS_NAME_NAME")

    abstract def set_halfconnections(s_ap_traffic, c_ap_traffic)
    abstract def is_tls
  end
end

module MySql::BRIDGE
  class BRIDGEPlain < BRIDGE
    def initialize(@socket)
      @multi_message_packet = false
      @seq_out = 0
    end

    def is_tls
      false
    end

    def read_packet : {Bool, StaticArray(UInt8, 4), Slice(UInt8)}
      header_4_mysql = uninitialized UInt8[4]
      @socket.read_fully(header_4_mysql.to_slice)
      if header_4_mysql[0] == 255
        # error_hdr_4_socket(@socket)
        # THIS IS NOT CORRECT ????
        errornumber = header_4_mysql[1].to_u32! + 256 * header_4_mysql[2].to_u32!
        errorname = Bytes.new(5)
        @socket.read_fully(errorname)
        errortext = @socket.gets
        raise "Error(1) #{errornumber} (#{errorname}): #{errortext}"
      end
      message_mysql_size = header_4_mysql[0].to_i + (header_4_mysql[1].to_i << 8) + (header_4_mysql[2].to_i << 16)
      @seq_out = header_4_mysql[3]
      @seq_out = @seq_out &+ 1.to_u8
      message_in = Bytes.new(message_mysql_size)
      @socket.read_fully(message_in)
      {% if flag?(:trc) %}
        puts "<---#{4 + message_in.size}-----[sql] BridgePlain ,#{header_4_mysql}\n#{message_in.hexdump}"
      {% end %}

      {true, header_4_mysql, message_in}
    end

    def set_halfconnections(s_ap_traffic, c_ap_traffic)
      raise "BRIDGEPlain::set_halfconnections() is useless"
    end

    def set_tls_record_type_applicationdata(tls_record_type)
      raise "BRIDGEPlain::set_tls_record_type_applicationdata() is useless"
    end

    def set_tls_record_type_alert(tls_record_type_alert)
      raise "BRIDGEPlain::set_tls_record_type_alert() is useless"
    end

    def read_message_set : Slice(UInt8)
      for_us, hdr_4, mess = read_packet
      while !for_us
        for_us, hdr_4, mess = read_packet
      end
      hdr_4.to_slice + mess
    end

    def write_message(mess : Bytes, mess_name = "NO_MESS_NAME_NAME")
      header_4_mysql = uninitialized UInt8[4]
      msg_size = mess.size
      header_4_mysql[2] = ((msg_size & 0x00FF0000) >> 16).to_u8
      header_4_mysql[1] = ((msg_size & 0x0000FF00) >> 8).to_u8
      header_4_mysql[0] = (msg_size & 0x000000FF).to_u8
      header_4_mysql[3] = @seq_out
      @seq_out = @seq_out &+ 1
      {% if flag?(:trc) %}
        puts "---#{4 + msg_size}-----[sql]>#{header_4_mysql},#{mess_name}"
      {% end %}

      @socket.write(header_4_mysql.to_slice + mess)
      @socket.flush
    end
  end

  class BRIDGETls < BRIDGE
    property c_ap_traffic : HalfConnection
    property s_ap_traffic : HalfConnection
    property tls_record_type_applicationdata : UInt8
    property tls_record_type_alert : UInt8

    property tlsconn : TLSClient::Client

    def initialize(@socket, @tlsconn)
      @c_ap_traffic = uninitialized HalfConnection
      @s_ap_traffic = uninitialized HalfConnection
      @tls_record_type_applicationdata = uninitialized UInt8
      @tls_record_type_alert = uninitialized UInt8
      @multi_message_packet = false
      @seq_out = 0
      # @tls_record_type = uninitialized UInt8
    end

    def is_tls
      true
    end

    def set_halfconnections(s_ap_traffic, c_ap_traffic)
      @s_ap_traffic = s_ap_traffic
      @c_ap_traffic = c_ap_traffic
    end

    def set_tls_record_type_applicationdata(tls_record_type_applicationdata)
      @tls_record_type_applicationdata = tls_record_type_applicationdata
    end

    def set_tls_record_type_alert(tls_record_type_alert)
      @tls_record_type_alert = tls_record_type_alert
    end

    def read_packet : {Bool, StaticArray(UInt8, 4), Slice(UInt8)}
      header_5_tls = uninitialized UInt8[5]
      @socket.read_fully(header_5_tls.to_slice)
      tls_record_type = header_5_tls[0].to_u8
      version = ((header_5_tls[1].to_u16 << 8) + header_5_tls[2].to_u8).to_u16
      local_payload_size = (header_5_tls[3].to_i16 << 8) + header_5_tls[4].to_i16
      if header_5_tls[4] == 0xFF
        raise "SQLResponceReader::next(). eof in packet=#{header_5_tls}"
      end
      local_payload = Bytes.new(local_payload_size)
      @socket.read_fully(local_payload)

      {% if flag?(:trc) %}
        puts "<---#{0 + 5 + local_payload.size}-----[read_packet] #{header_5_tls}"
      {% end %}

      encrypted_message = local_payload[0..local_payload_size - 16 - 1]
      tag_received = local_payload[local_payload_size - 16..local_payload_size - 1]
      msg_decrypted = Xcrypt.decrypt(
        header: header_5_tls.to_slice,
        encrypted_message: encrypted_message,
        tag_received: tag_received,
        half_conn: @s_ap_traffic)
      record_type = msg_decrypted.last
      is_application_data = tlsconn.filter_tls_internals(record_type, msg_decrypted) # {header_4_mysql, Bytes.new(1)}
      if is_application_data
        header_4_mysql = StaticArray(UInt8, 4).new { |i| msg_decrypted[i] }
        @seq_out = header_4_mysql[3]
        @seq_out = @seq_out &+ 1.to_u8

        {true, header_4_mysql, msg_decrypted[4..-2]} # drop last byte
      else
        # "dismiss this"
        {false, StaticArray(UInt8, 4).new(0), Bytes.new(0, 0x00)}
      end
    end

    def read_packet_result_set : {Bool, Slice(UInt8)}
      header_5_tls = uninitialized UInt8[5]
      @socket.read_fully(header_5_tls.to_slice)
      tls_record_type = header_5_tls[0].to_u8
      version = ((header_5_tls[1].to_u16 << 8) + header_5_tls[2].to_u8).to_u16
      local_payload_size = (header_5_tls[3].to_i << 8) + header_5_tls[4].to_i
      if header_5_tls[4] == 0xFF
        raise "SQLResponceReader::next(). eof in packet=#{header_5_tls}"
      end
      local_payload = Bytes.new(local_payload_size)

      @socket.read_fully(local_payload)

      {% if flag?(:trc) %}
        puts "<---#{0 + 5 + local_payload.size}-----[read_packet_result_set] #{header_5_tls}"
      {% end %}

      encrypted_message = local_payload[0..local_payload_size - 16 - 1]
      {% if flag?(:trc) %}
        puts " encrypted_message=#{encrypted_message},\n#{encrypted_message.hexdump}"
      {% end %}

      tag_received = local_payload[local_payload_size - 16..local_payload_size - 1]
      msg_decrypted = Xcrypt.decrypt(
        header: header_5_tls.to_slice,
        encrypted_message: encrypted_message,
        tag_received: tag_received,
        half_conn: @s_ap_traffic)
      record_type = msg_decrypted.last
      {% if flag?(:trc) %}
        puts " msg_decrypted=#{msg_decrypted}"
        puts " record_type=#{record_type}"
      {% end %}

      is_application_data = tlsconn.filter_tls_internals(record_type, msg_decrypted) # {header_4_mysql, Bytes.new(1)}
      if is_application_data
        {% if flag?(:trc) %}
          puts "msg_decrypted[0..-2]=#{msg_decrypted[0..-2]}"
        {% end %}
        {true, msg_decrypted[0..-2]} # drop last byte
      else
        # "dismiss this"
        {false, Bytes.new(0, 0x00)}
      end
    end

    def read_message_set : Slice(UInt8)
      for_us, messages = read_packet_result_set
      while !for_us
        for_us, messages = read_packet_result_set
      end
      messages
    end

    def write_message(mess : Bytes, mess_name = "NO_MESS_NAME_NAME")
      header_4_mysql = Bytes.new(4, 0x00)
      applic_msg_size = mess.size
      header_4_mysql[0] = (applic_msg_size & 0x000000FF).to_u8
      header_4_mysql[1] = ((applic_msg_size & 0x0000FF00) >> 8).to_u8
      header_4_mysql[2] = ((applic_msg_size & 0x00FF0000) >> 16).to_u8
      header_4_mysql[3] = @seq_out
      @seq_out = @seq_out &+ 1.to_u8
      header_5_tls : Bytes = Bytes.new(5, 0x00)
      version = @tlsconn.message_version
      #  SIC! ????
      tls_record_type = @tls_record_type_applicationdata
      tls_handshake_type = @tls_record_type_applicationdata
      header_5_tls[0] = tls_handshake_type
      header_5_tls[1] = (version >> 8).to_u8
      header_5_tls[2] = (version & 0x00FF).to_u8
      mess += Bytes.new(1, tls_record_type)
      packet_size = 4 + mess.size + 16 # tag
      header_5_tls[3] = (packet_size >> 8).to_u8
      header_5_tls[4] = (packet_size & 0x00FF).to_u8
      {% if flag?(:trc) %}
        puts "---#{5 + 4 + applic_msg_size}-----[sql]> #{header_5_tls},#{header_4_mysql},#{mess_name}"
      {% end %}

      msg_decrypted, tag = Xcrypt.encrypt(header: header_5_tls.to_slice,
        message: header_4_mysql + mess,
        half_conn: @c_ap_traffic)
      @socket.write(header_5_tls.to_slice + msg_decrypted + tag)
      @socket.flush
    end
  end
end
