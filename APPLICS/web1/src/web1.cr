# ports and servers https://support.apple.com/en-us/103229

require "socket"
require "io/hexdump"
require "TLSClient"
require "librfc8439"
require "shared"

#  crystal tool hierarchy  src/web1.cr -e TLSClient
#
# http on tls
# https://datatracker.ietf.org/doc/html/rfc2818
#

module Web1
  VERSION = "0.1.0"
  domain = "dn.se"

  domains = [
    # domain , short number, result (all HTTP/1.1 are considered ok here)
    {"www.deciweb.se", 0, "HTTP/1.1 200 OK"},
    {"www.svd.se", 1, "SetUpTLSSession:: State=WAIT_SH, got 'Alert' paylod=Bytes[2, 40], 'handshake_failure (Exception)"},
    {"www.expressen.se", 2, "HTTP/1.1 421 Misdirected Request. Requested host does not match any Subject Alternative Names (SANs) on TLS certificate [41a6990cf8fba374d17f275a7e15944e9b396c3d402ac9b098120382ab83ebe4] in use with this connection"},
    {"www.ms.se", 3, "Client:: got event 'Alert' in state 'WAIT_SH' paylod=Bytes[2, 112], 'unrecognized_name' (Exception)"},
    {"www.ms.com", 4, "SetUpTLSSession:: State=WAIT_SH, got 'Alert' paylod=Bytes[2, 70], 'protocol_version (Exception)"},
    {"www.flamman.se", 5, "SetUpTLSSession:: State=WAIT_SH, got 'Alert' paylod=Bytes[2, 40], 'handshake_failure (Exception)"},
    {"www.aftonbladet.se", 6, "SetUpTLSSession:: State=WAIT_SH, got 'Alert' paylod=Bytes[2, 40], 'handshake_failure (Exception)"},
    {"www.dn.se", 7, "HTTP/1.1 421 Misdirected Request. Requested host does not match any Subject Alternative Names (SANs) on TLS certificate [41a6990cf8fba374d17f275a7e15944e9b396c3d402ac9b098120382ab83ebe4] in use with this connection "},
    {"www.svd.se", 8, "SetUpTLSSession:: State=WAIT_SH, got 'Alert' paylod=Bytes[2, 40], 'handshake_failure (Exception)"},
    {"www.etc.se", 9, "SetUp state=WAIT_SH.End of file reached (IO::EOFError)"},
    {"www.apple.se", 10, "HTTP/1.1 301 Moved Permanently"},
    {"www.gp.se", 11, "SetUpTLSSession:: State=WAIT_SH, got 'Alert' paylod=Bytes[2, 40], 'handshake_failure (Exception)"},
    {"www.goteborg.goactivebooking.com", 12, "Hostname lookup for www.goteborg.goactivebooking.com failed: No address found (Socket::Addrinfo::Error)"},
    {"www.facebook.se", 13, "HTTP/1.1 302 Found"},
    {"www.tiktok.com", 14, "HTTP/1.1 302 Moved Temporarily"},
    {"www.nasa.com", 15, "SetUpTLSSession:: State=WAIT_SH, got 'Alert' paylod=Bytes[2, 80], 'internal_error (Exception)"},
    {"www.whitehouse.gov", 16, "SetUpTLSSession:: State=WAIT_SH, got 'Alert' paylod=Bytes[2, 40], 'handshake_failure (Exception)"},
    {"www.polisen.se", 17, "Unhandled exception: decrypt() received tag and computed tag are not the same. (FAILS IN READING APPLIC DATA (Responce Header))"},
    {"sv-se.facebook.com", 18, "GetEncrytpedMessage::get_message() mess_size > 2^16-1, is 14416341 (Exception)"},
    {"www.microsoft.com",19 , "HTTP/1.1 302 Moved Temporarily"}
  ]

  if ARGV.size == 1
    if argv_0 = ARGV[0].to_i?
      i = ARGV[0].to_i
      domain = domains[i][0] # ref to number above in 'domains'
    else
      domain = ARGV[0] # pick a name like www.site.com
    end
  else
    puts "empty"
    exit
  end
  puts domain

  the_request = [
    # "GET /index.html HTTP/1.1",
    "GET / HTTP/1.1", # no routing at th moment
    "Host: #{domain}",
    "#{self.gen_headers}",
  ].join("\r\n") + "\r\n" + "\r\n"
  puts the_request

  socket = TCPSocket.new(domain, 443)

  me = TLSClient::Client.new(socket, client_send_empty_certificate: false) # ALWAYS false for WEB. BUT true for MYSQL
  puts "sendHTTP"
  self.sendHTTP(me, the_request)
  #
  # The answer is RESPONCE_PARAMS + CRLFCRLF + [ HTMLCONTENT + [CRLFCRLF]]
  # Look for "Content-Length: " in RESPONCE_PARAMS as the HTMLCONTENT is not for sure terminated with CRLFCRLF !
  #
  puts "READ RESPONCE PARAMETRS"
  x = TLSInBuff.new(me)
  resp_params = read_responce_params_or_html_or_max(x)
  puts "resp_params=\n#{resp_params}"
  #
  # Find 'Content-Length: '
  #
  content_lenght : Int32 = -1 # no value
  index_content_length = resp_params.index("Content-Length: ")
  if the_index_content_length = index_content_length
    off = "Content-Length: ".size
    i = 0
    content_lenght = 0
    loop do
      got_byte = resp_params[index_content_length + off + i]
      digit = '0' <= got_byte <= '9'
      break if !digit
      content_lenght = 10*content_lenght + got_byte.to_i
      i += 1
    end
  end
  #
  # Limit given by "Content-Length: "
  if content_lenght == -1
    limit = 10000 # 'content_lenght' NOT present. Set limit of interest.
  else
    if content_lenght == 0
      limit = 0 # Limit given by "Content-Length: 0"
    else
      limit = content_lenght # Limit given by "Content-Length: 999"
    end
  end

  if limit > 0
    html = read_responce_params_or_html_or_max(x, limit: limit)
    puts "html=\n#{html}"
  else
    puts "NO html!"
  end

  # ================================================================================
  # puts "\r******receiveHTTP\r"
  # x = self.receiveHTTP(me)
  # puts String.new(x)

  # puts "\r******receiveHTTP\r"
  # x = self.receiveHTTP(me)
  # puts String.new(x)

  # x = self.receiveHTTP(me)
  # puts x.to_s
  # ----------------------------------------------------------
  def self.gen_headers
    ["Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    #  "Accept-Encoding: gzip, deflate, br",
     "Accept-Language: en-US,en;q=0.9",
     #  "Priority: u=0, i",
     #  "Sec-Fetch-Dest: document",
     #  "Sec-Fetch-Mode: navigate",
     #  "Sec-Fetch-Site: none",
     "Accept-Charset: ISO-8859-1,utf-8",
     "User-Agent: User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15",
     "Connection: keep-alive",
     "Keep-Alive: timeout=10",
    ].join("\r\n")
  end

  # ----------------------------------------------------------
  def self.sendHTTP(me, the_request)
    header_5_tls : Bytes = Bytes.new(5, 0x00)
    version = me.message_version
    #  SIC! ????
    tls_record_type = me.get_value_RecordTypeApplicationData
    tls_handshake_type = me.get_value_RecordTypeApplicationData
    header_5_tls[0] = tls_handshake_type
    header_5_tls[0] = tls_handshake_type
    header_5_tls[1] = (version >> 8).to_u8
    header_5_tls[2] = (version & 0x00FF).to_u8

    send_bytes = the_request.to_slice
    puts "(sendHTTP) REQUEST"
    # puts send_bytes.to_slice.hexdump

    send_bytes += Bytes.new(1, tls_record_type)
    # packet_size = 4 + send_bytes.size + 16 # tag
    packet_size = 0 + send_bytes.size + 16 # tag
    header_5_tls[3] = (packet_size >> 8).to_u8
    header_5_tls[4] = (packet_size & 0x00FF).to_u8
    msg_decrypted, tag = Xcrypt.encrypt(header: header_5_tls.to_slice,
      message: send_bytes,
      half_conn: me.c_ap_traffic)
    me.socket.write(header_5_tls.to_slice + msg_decrypted + tag)
    me.socket.flush
  end

  # ----------------------------------------------------------
  def self.read_responce_params_or_html_or_max(reader : TLSInBuff, limit : Int32 = 30000)
    # resp = Array.new(0, 0x00.to_u8)
    resp = String::Builder.new(0)
    state = "inline"
    read_so_far = 0
    while state != "eof"
      got_byte = reader.read_byte
      resp.write_byte(got_byte)
      case state
      when "inline"
        if got_byte == 0x0D
          state = "R"
        end
      when "R"
        if got_byte == 0x0A
          state = "RN"
        else
          state = "inline"
        end
      when "RN"
        if got_byte == 0x0D
          state = "RNR"
        else
          state = "inline"
        end
      when "RNR"
        if got_byte == 0x0A
          state = "eof"
        else
          state = "inline"
        end
      else
        state = "inline"
      end
      read_so_far += 1
      if read_so_far >= limit
        state = "eof"
      end
    end
    resp.to_s
  end

  # ----------------------------------------------------------
  def read_html_size(reader : TLSInBuff)
    size : Int32 = 0
    loop do
      got_byte = reader.read_byte
      digit = '0' <= got_byte <= '9'
      break if !digit
      size = 10*size + got_byte.to_i
    end

    # got_byte = reader.read_byte
    got_byte = reader.read_byte # \r 0x0D
    got_byte = reader.read_byte # \n 0x0A
    return size
  end

  # ----------------------------------------------------------
  class TLSInBuff
    property msg_decrypted : Bytes
    property read_index : Int32 = 0
    property msg_size : Int32 = 0

    def initialize(@me : TLSClient::Client)
      @state = "empty"
      @msg_decrypted = Bytes.new(0)
    end

    def read_byte
      if @state == "empty"
        is_application_data = false
        loop do
          header_5_tls : Bytes = Bytes.new(5, 0x00)
          @me.socket.read_fully(header_5_tls)
          # puts "header_5_tls       =#{header_5_tls}"
          tls_record_type = header_5_tls[0].to_u8
          version = ((header_5_tls[1].to_u16 << 8) + header_5_tls[2].to_u8).to_u16
          local_payload_size = (header_5_tls[3].to_i << 8) + header_5_tls[4].to_i
          # puts "tls_record_type    =#{tls_record_type}"
          # puts "version            =#{version}"
          # puts "local_payload_size =#{local_payload_size}"

          local_payload = Bytes.new(local_payload_size)
          @me.socket.read_fully(local_payload)

          encrypted_message = local_payload[0..local_payload_size - 16 - 1]
          tag_received = local_payload[local_payload_size - 16..local_payload_size - 1]

          @msg_decrypted = Xcrypt.decrypt(
            header: header_5_tls.to_slice,
            encrypted_message: encrypted_message,
            tag_received: tag_received,
            half_conn: @me.s_ap_traffic)

          record_type = msg_decrypted.last
          is_application_data = @me.filter_tls_internals(record_type, msg_decrypted)
          break if is_application_data
        end
        @msg_decrypted = @msg_decrypted[0..-2].to_slice
        @state = "not_empty"
        @read_index = 0
        @msg_size = @msg_decrypted.size
      end
      # Pick next char. Assume there is at least one in the tls packet!
      to_ret = @msg_decrypted[@read_index]
      @read_index += 1
      @msg_size -= 1
      if @msg_size == 0
        @state = "empty" # for next call
      end
      to_ret
    end
  end
end
