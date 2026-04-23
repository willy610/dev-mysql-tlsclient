require "big"
require "socket"

module TLSClient
  class Client
    property socket : TCPSocket
    property c_hs_traffic : HalfConnection
    property s_hs_traffic : HalfConnection
    property c_ap_traffic : HalfConnection
    property s_ap_traffic : HalfConnection
    property the_ECDHD_container : ECDHContainer
    getter legacy_version : UInt16 = 0x0304
    getter message_version : UInt16 = 0x0303

    def initialize(@socket : TCPSocket, client_send_empty_certificate : Bool)
      # The following attributes is used after initialize
      @c_hs_traffic = uninitialized HalfConnection
      @s_hs_traffic = uninitialized HalfConnection
      @c_ap_traffic = uninitialized HalfConnection
      @s_ap_traffic = uninitialized HalfConnection
      @the_ECDHD_container = ECDHContainer.new
      #
      sup = SetUpTLSSession.new(self, @legacy_version, @message_version,
        client_send_empty_certificate: client_send_empty_certificate)
    end

    # **********************************************************************

    #
    # In application state
    #  we must detect 'RecordTypeAlert' and terminate when not warning
    #  we must detect 'RecordTypeHandshake::TypeHelloRequest' and terminate
    #  we must detect 'RecordTypeHandshake::TypeNewSessionTicket' and dismiss it
    #
    def filter_tls_internals(record_type, msg_decrypted) : Bool
      # {% if flag?(:trctls) %}
      #   puts "filter_tls_internals() #{record_type},#{msg_decrypted.size}"
      # {% end %}

      case record_type
      when TLSDefinitions::TLSRecordType::RecordTypeApplicationData.value
        return true # For application
      when TLSDefinitions::TLSRecordType::RecordTypeHandshake.value
        {% if flag?(:trctls) %}
          puts "filter_tls_internals() msg_decrypted[0]=#{msg_decrypted[0]}"
        {% end %}

        case msg_decrypted[0]
        when TLSDefinitions::TlSHandshakeType::TypeHelloRequest.value
          puts "filter_tls_internals() DO NOT process 'TypeHelloRequest'"
          raise "filter_tls_internals() DO NOT process 'TypeHelloRequest'"
          return false
        when TLSDefinitions::TlSHandshakeType::TypeNewSessionTicket.value
          # This message might arrive after session is establihed. After client has sent 'finish'
          # Take care of SessionTicket. (Not implemented)
          {% if flag?(:trctls) %}
            puts "filter_tls_internals() process 'TypeNewSessionTicket'"
          {% end %}
          # Not for application
          return false
        else
          raise "filter_tls_internals TLSRecordType::RecordTypeHandshake unknown 'TlSHandshakeType' = #{msg_decrypted[0]}"
          return false # For application
        end
      when TLSDefinitions::TLSRecordType::RecordTypeAlert.value
        # rfc 6. Alert Protocol
        the_alert_text_and_number = Client.alert_text_and_number.select! { |alert_text_and_number| alert_text_and_number[1] == msg_decrypted[1] }
        puts "the_alert_text_and_number=#{the_alert_text_and_number}"
        if msg_decrypted[0] == 1 # warning
          puts "warning encountered"
          return true
        else
          raise "filter_tls_internals() Alert fatal #{the_alert_text_and_number}"
          return false
        end
      else
        raise "filter_tls_internals() Unknown 'TLSRecordType' #{record_type}"
      end
    end

    # **********************************************************************

    def get_value_RecordTypeApplicationData
      TLSDefinitions::TLSRecordType::RecordTypeApplicationData.value
    end

    # **********************************************************************

    def private_write_init_plain(type, the_message)
      header_5_tls_init : Bytes = Bytes.new(5, 0x00)
      hdr_4 : Bytes = Bytes.new(4, 0x00)

      message_size = the_message.size
      payload_size = hdr_4.size + message_size
      hdr_4[0] = type
      hdr_4[1] = ((message_size & 0x00FF0000) >> 16).to_u8
      hdr_4[2] = ((message_size & 0x0000FF00) >> 8).to_u8
      hdr_4[3] = (message_size & 0x000000FF).to_u8

      header_5_tls_init[0] = TLSDefinitions::TLSRecordType::RecordTypeHandshake.value
      header_5_tls_init[1] = (@message_version >> 8).to_u8
      header_5_tls_init[2] = (@message_version & 0x00FF).to_u8

      header_5_tls_init[3] = (payload_size >> 8).to_u8
      header_5_tls_init[4] = (payload_size & 0x00FF).to_u8
      {% if flag?(:trchdrs) %}
        puts "---->(ClientHello)=#{header_5_tls_init}"
      {% end %}

      @socket.write(header_5_tls_init + hdr_4 + the_message)
      @socket.flush
      {hdr_4, the_message}
    end

    # **********************************************************************

    def private_write_ChangeCipherSpec
      the_message = Bytes.new(1, 0x00)
      payload_size = the_message.size
      header_5_tls_ccs : Bytes = Bytes.new(5, 0x00)
      header_5_tls_ccs[0] = TLSDefinitions::TLSRecordType::RecordTypeHandshake.value
      header_5_tls_ccs[1] = (@message_version >> 8).to_u8
      header_5_tls_ccs[2] = (@message_version & 0x00FF).to_u8
      header_5_tls_ccs[3] = (payload_size >> 8).to_u8
      header_5_tls_ccs[4] = (payload_size & 0x00FF).to_u8
      {% if flag?(:trchdrs) %}
        puts "---->(ChangeCipherSpec)=#{header_5_tls_ccs}"
      {% end %}

      @socket.write(header_5_tls_ccs + the_message)
      @socket.flush
      {header_5_tls_ccs, the_message}
    end

    # **********************************************************************

    # Read a full packet
    def private_read_init_plain
      header_5_tls_init = uninitialized UInt8[5]
      @socket.read_fully(header_5_tls_init.to_slice)
      {% if flag?(:trchdrs) %}
        puts "<----(private_read_init_plain)=#{header_5_tls_init}"
      {% end %}

      record_type = header_5_tls_init[0]
      local_payload_size = (header_5_tls_init[3].to_i << 8) + header_5_tls_init[4].to_i
      local_payload = Bytes.new(local_payload_size)
      @socket.read_fully(local_payload)
      an_unmarshaller = Unmarshaller.new(local_payload.to_slice)

      {record_type, header_5_tls_init, local_payload}
    end

    # **********************************************************************
    # Read a full encrypted package
    def private_read_init_encrypted(s_hs_traffic : HalfConnection)
      header_5_tls = uninitialized UInt8[5]
      @socket.read_fully(header_5_tls.to_slice)
      {% if flag?(:trctls) %}
        puts "private_read_init_encrypted() header_5_tls=#{header_5_tls}"
      {% end %}
      tls_record_type = header_5_tls[0].to_u8
      got_version = ((header_5_tls[1].to_u16 << 8) + header_5_tls[2].to_u8).to_u16
      local_payload_size = (header_5_tls[3].to_i << 8) + header_5_tls[4].to_i
      if header_5_tls[4] == 0xFF
        puts "eof in packet=?#{header_5_tls}" # ???????
      end

      local_payload = Bytes.new(local_payload_size)
      @socket.read_fully(local_payload)

      msg_encrypted = uninitialized Bytes
      encrypted_message = local_payload[0..local_payload_size - 16 - 1]
      tag_received = local_payload[local_payload_size - 16..local_payload_size - 1]
      msg_decrypted = Xcrypt.decrypt(
        header: header_5_tls.to_slice,
        encrypted_message: encrypted_message,
        tag_received: tag_received,
        half_conn: s_hs_traffic) # FUNKAR with NormalCrypt

      handshaketype = msg_decrypted.last
      header_4 = msg_decrypted[0..3]
      message = msg_decrypted[4, (msg_decrypted.size - 4 - 1)]
      {% if flag?(:trchdrs) %}
        puts "<---#{5 + 4 + 1 + local_payload.size}-----[private_read_init_encrypted]#{header_4.to_slice}"
      {% end %}

      {header_4.to_slice, handshaketype, message}
    end

    # **********************************************************************

    def self.alert_text_and_number
      [
        ["close_notify", 0],
        ["unexpected_message", 10],
        ["bad_record_mac", 20],
        ["record_overflow", 22],
        ["handshake_failure", 40],
        ["bad_certificate", 42],
        ["unsupported_certificate", 43],
        ["certificate_revoked", 44],
        ["certificate_expired", 45],
        ["certificate_unknown", 46],
        ["illegal_parameter", 47],
        ["unknown_ca", 48],
        ["access_denied", 49],
        ["decode_error", 50],
        ["decrypt_error", 51],
        ["protocol_version", 70],
        ["insufficient_security", 71],
        ["internal_error", 80],
        ["inappropriate_fallback", 86],
        ["user_canceled", 90],
        ["missing_extension", 109],
        ["unsupported_extension", 110],
        ["unrecognized_name", 112],
        ["bad_certificate_status_response", 113],
        ["unknown_psk_identity", 115],
        ["certificate_required", 116],
        ["no_application_protocol", 120],
        ["other error!", 255],
      ]
    end

    # **********************************************************************

    def self.resolve_alert_reason(msg)
      the_alert_text_and_number = self.alert_text_and_number.select! { |alert_text_and_number| alert_text_and_number[1] == msg[1] }
      puts the_alert_text_and_number.first
      the_alert_text_and_number.first
    end
  end

  #
  # Here we will read messages of size 'req_amount' by unbuffering decrypted buffers
  #
  # |<in_buff                           >|
  # |                                    |
  # |<in_buff_off>
  # |             req_amount             |
  # |             *---------------->     |
  # |             req_amount             |<in_buff                 >|
  # |             *------------------------------------------->     |          |
  # |             req_amount             |<in_buff                 >|<in_buff >|
  # |             *-------------------------------------------------|------>   |
  # |                                    |                          |          |

  # @in_buff holds a decrypted buffer with one or messages or fractions of a message
  # @in_buff_off tells what offset to start consuming meassage part out of the '@in_buff'

  # -The @in_buff_off might be none zero. That might happens when not all messages
  # are yet consumed but whole or partly in the buffer
  # -The @in_buff_off is set to zero when a new in_buff is read
  #
  # **********************************************************************
  private struct GetEncrytpedMessage
    # property history : Array(String)
    property in_buff : Bytes
    property in_buff_off : Int32

    def initialize(@the_client : Client)
      # @history = [""]
      @in_buff = uninitialized Bytes
      @in_buff_off = 0
    end

    # Usage for retriving a message
    # hdr4 = get_bytes(4)
    # messagesize is calculated on hdr4[1,3]
    # message = get_bytes(messagesize)
    #
    # **********************************************************************
    def get_bytes(req_amount)
      to_ret = Bytes.new(0x00, 0)
      # @history << "\n1: req_amount=#{"%05d" % req_amount}, @in_buff_off=#{"0x%04x" % @in_buff_off} @in_buff.size=(#{"%05d" % @in_buff.size})"

      while to_ret.size < req_amount
        # How much to copy?
        cnt_to_copy = Math.min(req_amount - to_ret.size, @in_buff.size - @in_buff_off)
        # Do the copy from buffer to result
        # hex_cnt_to_copy = "0x%04x" % cnt_to_copy
        # hex_read_off = "0x%04x" % @in_buff_off
        # hex_ret_size = "0x%04x" % to_ret.size
        # @history << "2: Copied cnt_to_copy=#{"%05d" % cnt_to_copy}, from @in_buff_off=#{"0x%04x" % @in_buff_off} (#{"%05d" % @in_buff_off})"

        to_ret += @in_buff[@in_buff_off, cnt_to_copy]
        # Advance offset to copy from
        @in_buff_off += cnt_to_copy # consumed
        # Are we done?
        if to_ret.size < req_amount
          first_header_4, handshaketype, message = @the_client.private_read_init_encrypted(@the_client.s_hs_traffic)
          @in_buff = first_header_4 + message
          @in_buff_off = 0
          # history_str = "3. (read in_buff) @in_buff.size=#{"0x%04x" % @in_buff.size} (#{"%05d" % @in_buff.size})"
          # @history << history_str
        end
      end
      # @history << "4: @in_buff.size=#{"0x%04x" % @in_buff.size} (#{"%05d" % @in_buff.size}) @in_buff_off=#{"0x%04x" % @in_buff_off} (#{"%05d" % @in_buff_off})"
      to_ret
    end

    # **********************************************************************
    def get_message
      hdr4 = get_bytes(4)
      mess_size = (hdr4[1].to_u32 << 16) + (hdr4[2].to_u32 << 8) + (hdr4[3].to_u32)
      if mess_size > 65536 # 2^16-1
        # Very wrong
        # @history.each { |row| puts row }
        raise "GetEncrytpedMessage::get_message() mess_size > 2^16-1, is #{mess_size}"
      end
      # get message
      message = get_bytes(mess_size)
      # TOD Take care of alert messages here
      {hdr4[0], mess_size, hdr4, message}
    end
  end

  # **********************************************************************
  private struct SetUpTLSSession
    property legacy_version : UInt16
    property message_version : UInt16

    def initialize(@the_client : Client, @legacy_version, @message_version, @client_send_empty_certificate : Bool)
      @the_transcriptor = Transcriptor.new
      @handshakeSecret = uninitialized DERIVED_SECRET
      @client_hello_msg_sent = uninitialized Bytes
      @server_hello_msg_received = uninitialized Bytes
      @client_verificate_package_sent = uninitialized Bytes
      @finished_packet_read = uninitialized Bytes
      @finished_hdr_4 = uninitialized Bytes
      @finished_message_read = uninitialized Bytes
      # As long as the clienthello and serverhelle is not evaluated according to send_empty_certificate
      # than stick too:
      # @client_send_empty_certificate = true  # MUST BE TRUE FOR MYSQL
      # @client_send_empty_certificate = false # MUST BE TRUE FOR WEB
      #
      @do_send_ChangeCipherSpec = false

      the_certificator = Certificate.new
      the_message_reader = GetEncrytpedMessage.new(@the_client)
      # RFC 8846
      # look into transcriptor.cr for more details around State Machine
      # A.1. Client State Machine
      state = "START"
      while state != "END"
        {% if flag?(:trctls) %}
          puts "\nSetUpTLSSession state=#{state}"
        {% end %}
        case state
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "START"
          # NO READ
          # WRITE
          client_hello_msg_obj = ClientHelloMessage.new(the_ECDHD_container: @the_client.the_ECDHD_container,
            legacy_version: @the_client.legacy_version)
          client_hello_msg_obj.build_client_hello_msg
          hdr_4, message = @the_client.private_write_init_plain(TLSDefinitions::TlSHandshakeType::TypeClientHello.value,
            client_hello_msg_obj.message)
          @the_transcriptor.add_bytes(to_add: hdr_4 + message, note: "write ClientHello")
          @client_hello_msg_sent = hdr_4 + message
          state = "WAIT_SH"
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "WAIT_SH"
          # READ
          event, hdr_5, paylod = @the_client.private_read_init_plain
          case event
          when TLSDefinitions::TLSRecordType::RecordTypeHandshake.value
            @the_transcriptor.add_bytes(to_add: paylod, note: "read ServerHello")
            @server_hello_msg_received = paylod
            an_unmarshaller = Unmarshaller.new(paylod)
            server_hello_msg_obj = ServerHelloMessage.new(an_unmarshaller, @the_client.the_ECDHD_container)
            establishHandshakeKeys_from_hello_messages(server_hello_msg_obj.sharedkey_ECDH)
            # NO WRITE
            state = "WAIT_ChangeCipherSpec"
          when TLSDefinitions::TLSRecordType::RecordTypeAlert.value
            raise "SetUpTLSSession:: State=#{state}, got 'Alert' paylod=#{paylod}, '#{Client.resolve_alert_reason(paylod)[0]}"
          else
            raise "SetUpTLSSession:: State=#{state}, event=#{event} unknown"
          end
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "WAIT_ChangeCipherSpec"
          # READ
          event, hdr_5, paylod = @the_client.private_read_init_plain
          case event
          when TLSDefinitions::TLSRecordType::RecordTypeChangeCipherSpec.value
            state = "WAIT_EE"
          else
            raise "SetUpTLSSession:: State=#{state}, event=#{event} unknown"
          end
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "WAIT_EE"
          # READ
          # At least one acccording to RFC
          event, size, hdr_4, message = the_message_reader.get_message
          message_type = TLSDefinitions::TlSHandshakeType.new(event)
          {% if flag?(:trctls) %}
            puts "(1) ", event, size, message_type, message[0, Math.min(5, size)]
            puts message_type
          {% end %}
          if message_type == TLSDefinitions::TlSHandshakeType::TypeEncryptedExtensions
            # Take care of extension TOD
            @the_transcriptor.add_bytes(to_add: hdr_4 + message, note: "read EncryptedExtensions")

            event, size, hdr_4, message = the_message_reader.get_message
            message_type = TLSDefinitions::TlSHandshakeType.new(event)
            {% if flag?(:trctls) %}
              puts "(2) ", event, size, message_type, message[0, Math.min(5, size)]
              puts message_type
            {% end %}
            case message_type
            when TLSDefinitions::TlSHandshakeType::TypeEncryptedExtensions
              # Take care of extension TOD
              @the_transcriptor.add_bytes(to_add: hdr_4 + message, note: "read TypeEncryptedExtensions")
              # Stay for more extension(s). No state change
            when TLSDefinitions::TlSHandshakeType::TypeCertificateRequest
              # Take care of TypeCertificateRequest
              @the_transcriptor.add_bytes(to_add: hdr_4 + message, note: "read TypeCertificateRequest")
              state = "WAIT_Certificate_CertificateVerify_Finished"
            when TLSDefinitions::TlSHandshakeType::TypeCertificate
              # Take care of TypeCertificate
              @the_transcriptor.add_bytes(to_add: hdr_4 + message, note: "read TypeCertificate")
              state = "WAIT_CertificateVerify_Finished"
            when TLSDefinitions::TlSHandshakeType::TypeCertificateVerify
              # Take care of CertificateVerify
              @the_transcriptor.add_bytes(to_add: hdr_4 + message, note: "read TypeCertificateVerify")
              state = "WAIT_Finished"
            when TLSDefinitions::TlSHandshakeType::TypeFinished
              # Take care of Finished
              @finished_hdr_4, @finished_message_read = {hdr_4, message}
              state = "GOT_Finished"
            else
              raise "SetUpTLSSession:: State=#{state}, message_type=#{message_type} but expected '1,2,3'"
            end
          else
            raise "SetUpTLSSession:: State=#{state}, message_type=#{message_type} but expected 'TypeEncryptedExtensions'"
          end
        when "WAIT_Certificate_CertificateVerify_Finished"
          # READ
          event, size, hdr_4, message = the_message_reader.get_message
          message_type = TLSDefinitions::TlSHandshakeType.new(event)
          {% if flag?(:trctls) %}
            puts "(3) ", event, size, message_type, message[0, Math.min(5, size)]
            puts message_type
          {% end %}
          case message_type
          when TLSDefinitions::TlSHandshakeType::TypeCertificate
            @the_transcriptor.add_bytes(to_add: hdr_4 + message, note: "read TypeCertificate")
            state = "WAIT_CertificateVerify_Finished"
          when TLSDefinitions::TlSHandshakeType::TypeCertificateVerify
            @the_transcriptor.add_bytes(to_add: hdr_4 + message, note: "read TypeCertificateVerify")
            state = "WAIT_Finished"
          when TLSDefinitions::TlSHandshakeType::TypeFinished
            @finished_hdr_4, @finished_message_read = {hdr_4, message}
            state = "GOT_Finished"
          else
            raise "SetUpTLSSession:: State=#{state}, message_type=#{message_type} but expected 'Certificate_CertificateVerify_Finished'"
          end
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "WAIT_CertificateVerify_Finished"
          # READ
          event, size, hdr_4, message = the_message_reader.get_message
          message_type = TLSDefinitions::TlSHandshakeType.new(event)
          {% if flag?(:trctls) %}
            puts "(4) ", event, size, message_type, message[0, Math.min(5, size)]
            puts message_type
          {% end %}
          case message_type
          when TLSDefinitions::TlSHandshakeType::TypeCertificateVerify
            @the_transcriptor.add_bytes(to_add: hdr_4 + message, note: "read TypeCertificateVerify")
            state = "WAIT_Finished"
          when TLSDefinitions::TlSHandshakeType::TypeFinished
            @finished_hdr_4, @finished_message_read = {hdr_4, message}
            state = "GOT_Finished"
          else
            raise "SetUpTLSSession:: State=#{state}, message_type=#{message_type} but expected 'CertificateVerify_Finished'"
          end
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "WAIT_Finished"
          # READ
          event, size, hdr_4, message = the_message_reader.get_message
          message_type = TLSDefinitions::TlSHandshakeType.new(event)
          {% if flag?(:trctls) %}
            puts "(5) ", event, size, message_type, message[0, Math.min(5, size)]
            puts message_type
          {% end %}
          case message_type
          when TLSDefinitions::TlSHandshakeType::TypeFinished
            @finished_hdr_4, @finished_message_read = {hdr_4, message}
            # the_message_reader.history.each { |row| puts row }
            state = "GOT_Finished"
          else
            raise "SetUpTLSSession:: State=#{state}, message_type=#{message_type} but expected 'Finished'"
          end
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "GOT_Finished"
          # @the_transcriptor.show_history
          # We have got a finnished message already
          res = verifyFinishFromServer(@finished_message_read)
          if !res
            raise "SetUpTLSSession:: Verification of 'Finished message' failed in state=#{state}"
          end
          {% if flag?(:trctls) %}
            puts "Verification of 'Finished message' OK"
          {% end %}
          @the_transcriptor.add_bytes(to_add: @finished_hdr_4 + @finished_message_read, note: "read Finished")

          generate_applic_keys

          # TOD
          # WHAT ABOUT SEND CertificateVerify?? like Certificate ?

          # {% if flag?(:trctls) %}
          #   @the_transcriptor.show_history
          # {% end %}

          if @do_send_ChangeCipherSpec
            header, the_message = @the_client.private_write_ChangeCipherSpec
            {% if flag?(:trctls) %}
              puts "do private_write_ChangeCipherSpec"
            {% end %}
            @the_transcriptor.add_bytes(to_add: header + the_message, note: "write ChangeCipherSpec")
          end
          state = "SEND_CERT_CETVERIFY_FINISH"
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "SEND_CERT_CETVERIFY_FINISH"
          # WRITE THINGS
          if @client_send_empty_certificate # sendemptyverificate
            @client_verificate_package_sent = send_certificate_message()
            @the_transcriptor.add_bytes(to_add: @client_verificate_package_sent, note: "write empty ClientCertificatePacket")
            @the_transcriptor.add_not(note: "END in 'SEND_CERT_CETVERIFY_FINISH'")
          end
          state = "SEND_CETVERIFY_FINISH"
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "SEND_CETVERIFY_FINISH"
          # WHAT ABOUT SEND CertificateVerify?? like Certificate ?
          # WRITE THINGS
          state = "SEND_FINISH"
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "SEND_FINISH"
          # WRITE THINGS
          build_finish_message_and_send()
          {% if flag?(:trctls) %}
            @the_transcriptor.show_history
          {% end %}
          state = "END"
          # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        when "END"
          # Done!
        else
          raise "SetUpTLSSession() unknown state=#{state}"
        end
      end
    end

    # **********************************************************************

    def establishHandshakeKeys_from_hello_messages(sharedkey_ECDH)
      #
      # Spec at
      # https://datatracker.ietf.org/doc/html/rfc8446#section-7.4
      #
      # Verify at
      # https://fotoventus.cz/tool/hkdf.html

      zeros = Bytes.new(Shared::Sha256.checksum_size, 0x00.to_u8)
      psk = Bytes.new(Shared::Sha256.checksum_size, 0x00.to_u8)
      earlySecret = HKDF.extract(psk, zeros)
      derived_secret : DERIVED_SECRET = derivesecret(earlySecret, "derived".bytes, Shared::Sha256.new)
      @handshakeSecret = HKDF.extract(sharedkey_ECDH, derived_secret)

      summit = @the_transcriptor.get_sum
      @the_client.c_hs_traffic = generate_content_4_crypt(@handshakeSecret, "c hs traffic".bytes, summit, Shared::Sha256.checksum_size)
      @the_client.s_hs_traffic = generate_content_4_crypt(@handshakeSecret, "s hs traffic".bytes, summit, Shared::Sha256.checksum_size)
    end

    # **********************************************************************

    def derivesecret(secret, label, hasher_obj) : DERIVED_SECRET
      summer = hasher_obj.bigsum
      HKDF.hkdfExpandLabel(secret, label, summer, hasher_obj.checksum_size)
    end

    # **********************************************************************

    def generate_content_4_crypt(secret, the_label, a_bigsum, a_bigsum_resultsize)
      the_label_secret = HKDF.hkdfExpandLabel(secret, the_label, a_bigsum, a_bigsum_resultsize)
      HalfConnection.new(the_label_secret,
        HKDF.hkdfExpandLabel(the_label_secret, "key".bytes, [] of UInt8, 32), # c.keyLen for SHA256
        HKDF.hkdfExpandLabel(the_label_secret, "iv".bytes, [] of UInt8, 12)
      )
    end

    # **********************************************************************

    def verifyFinishFromServer(payload : Bytes) : Bool
      basekey = @the_client.s_hs_traffic.trafficSecret
      @the_transcriptor.add_not(note: "verifyFinishFromServer")
      expectedMAC = generate_finished_key(basekey, @the_transcriptor)
      if !Xcrypt.constant_time_compare(expectedMAC, payload)
        puts "verifyFinishFromServer()"
        puts "\nexpectedMAC=#{expectedMAC.size} , #{expectedMAC}"
        puts "payload=    #{payload.size} , #{payload}\n\n"
        puts "verify of finished message is wrong"
        false
      else
        {% if flag?(:trctls) %}
          puts "\nServer Finished Message is understood (payload and expectedMAC are the same)\n\n"
        {% end %}

        true
      end
    end

    # **********************************************************************

    def generate_finished_key(basekey, the_transcript)
      # finishedHash generates the Finished verify_data or PskBinderEntry according
      #  to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
      #  selection.

      @the_transcriptor.add_not(note: "calc sum in 'generate_finished_key'")

      the_transcript_checksum_size = @the_transcriptor.checksum_size
      finishedKey = HKDF.hkdfExpandLabel(basekey, "finished".bytes, [] of UInt8, the_transcript_checksum_size)
      verifydata = HMAC.new(finishedKey)
      transbigsum = the_transcript.get_sum
      verifydata.write_hmac(transbigsum)

      summit = verifydata.sum_hmac(Slice.new(0, 0x00.to_u8))
      return summit
    end

    # **********************************************************************

    def generate_applic_keys
      zeros = Bytes.new(Shared::Sha256.checksum_size, 0x00.to_u8)
      derived_secret_X : DERIVED_SECRET = derivesecret(@handshakeSecret, "derived".bytes, Shared::Sha256.new)
      masterSecret_X = HKDF.extract(zeros, derived_secret_X)

      @the_transcriptor.add_not(note: "calc sum in 'gen_c_XX_traffic()' 'c ap traffic and 's ap traffic'")
      summit_X = @the_transcriptor.get_sum

      @the_client.c_ap_traffic = generate_content_4_crypt(masterSecret_X, "c ap traffic".bytes, summit_X, @the_transcriptor.checksum_size)
      @the_client.s_ap_traffic = generate_content_4_crypt(masterSecret_X, "s ap traffic".bytes, summit_X, @the_transcriptor.checksum_size)
    end

    # **********************************************************************

    def build_finish_message_and_send : Bytes
      basekey = @the_client.c_hs_traffic.trafficSecret
      verify_message_to_server = generate_finished_key(basekey, @the_transcriptor)
      @the_transcriptor.add_not(note: "send_finish_message")
      msg = send_finish_message(verify_message_to_server)
      return msg
    end

    # **********************************************************************

    def send_certificate_message : Bytes
      emtpy_certificate_message = Shared.to_bytes([0, 0, 0, 0])
      hdr_4 : Bytes = gen_hdr_4(TLSDefinitions::TlSHandshakeType::TypeCertificate, emtpy_certificate_message)
      hdr_5 : Bytes = gen_hdr_5(emtpy_certificate_message.size, TLSDefinitions::TLSRecordType::RecordTypeApplicationData.value, @the_client.message_version)
      header_5_tls, encrypted_msg, tag = gen_encrytpted_message(hdr_5,
        hdr_4,
        emtpy_certificate_message,
        TLSDefinitions::TLSRecordType::RecordTypeHandshake.value,
        @the_client.c_hs_traffic
      )
      {% if flag?(:trctls) %}
        puts "---->(Verificate)=#{header_5_tls}"
      {% end %}

      @the_client.socket.write(header_5_tls)
      @the_client.socket.write(encrypted_msg)
      @the_client.socket.write(tag)
      @the_client.socket.flush
      hdr_4 + emtpy_certificate_message # package
    end

    # **********************************************************************

    def send_finish_message(message : Bytes) : Bytes
      hdr_4 : Bytes = gen_hdr_4(TLSDefinitions::TlSHandshakeType::TypeFinished, message)
      hdr_5 : Bytes = gen_hdr_5(message.size, TLSDefinitions::TLSRecordType::RecordTypeApplicationData.value, @the_client.message_version)
      header_5_tls, encrypted_msg, tag = gen_encrytpted_message(hdr_5,
        hdr_4,
        message,
        TLSDefinitions::TLSRecordType::RecordTypeHandshake.value,
        @the_client.c_hs_traffic
      )
      {% if flag?(:trctls) %}
        puts "---->(Finish)=#{header_5_tls}"
      {% end %}

      @the_client.socket.write(header_5_tls)
      @the_client.socket.write(encrypted_msg)
      @the_client.socket.write(tag)
      @the_client.socket.flush
      # package
      hdr_4 + message
    end

    # **********************************************************************

    def gen_encrytpted_message(header_5_tls, header_4_tls, message, tlsrecordtype, a_HalfConnection) : {Bytes, Bytes, Bytes}
      {% if flag?(:trctls) %}
        puts "gen_encrytpted_message()"
        puts "  header_5_tls                    =#{header_5_tls}"
        puts "  header_4_tls                    =#{header_4_tls}"
        puts "  message                         =#{message.size},#{message}"
      {% end %}

      message += Bytes.new(1, tlsrecordtype.to_u8)
      new_packet_size = 4 + message.size + 16 # tag
      header_5_tls[3] = (new_packet_size >> 8).to_u8
      header_5_tls[4] = (new_packet_size & 0x00FF).to_u8
      plaintext_4_encrypt = header_4_tls + message
      {% if flag?(:trctls) %}
        puts "some trace"
        puts "  header_5_tls.to_slice           =#{header_5_tls.size},#{header_5_tls}"
        puts "  plaintext_4_encrypt             =#{plaintext_4_encrypt.size},#{plaintext_4_encrypt}"
      {% end %}

      msg_decrypted, tag = Xcrypt.encrypt(
        header: header_5_tls.to_slice,
        message: plaintext_4_encrypt,
        half_conn: a_HalfConnection)
      {header_5_tls, msg_decrypted, tag}
    end

    # **********************************************************************

    def gen_hdr_4(handshake_type : TLSDefinitions::TlSHandshakeType, message : Bytes)
      header_4_tls = Bytes.new(4, 0x00)
      header_4_tls[0] = handshake_type.value
      message_size = message.size
      header_4_tls[1] = ((message_size & 0xFF0000) >> 16).to_u8
      header_4_tls[2] = ((message_size & 0x00FF00) >> 8).to_u8
      header_4_tls[3] = (message_size & 0x0000FF).to_u8
      header_4_tls
    end

    # **********************************************************************

    def gen_hdr_5(message_size, tlsrecordtype, message_version)
      header_5_tls = Bytes.new(5, 0x00)
      header_5_tls[0] = tlsrecordtype
      header_5_tls[1] = (message_version >> 8).to_u8
      header_5_tls[2] = (message_version & 0x00FF).to_u8

      packet_size = message_size + 4 # hdr_4 size
      header_5_tls[3] = (packet_size >> 8).to_u8
      header_5_tls[4] = (packet_size & 0x00FF).to_u8
      header_5_tls
    end
  end
end
