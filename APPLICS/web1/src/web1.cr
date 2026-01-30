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
    {"deciweb.se", 0, "WEB1 ended"},
    {"svd.se", 1, "WEB1 ended"},
    {"expressen.se", 2, "WAIT_CERT_CR"},
    {"ms.se", 3, "Client:: got event 'Alert' in state 'WAIT_SH' paylod=Bytes[2, 112], 'unrecognized_name' (Exception)"},
    {"ms.com", 4, "Client:: got event 'Alert' in state 'WAIT_SH' paylod=Bytes[2, 70], 'protocol_version' (Exception)"},
    {"flamman.se", 5, "WEB1 ended"},
    {"aftonbladet.se", 6, " Client:: got event 'Alert' in state 'WAIT_SH' paylod=Bytes[1, 0], 'close_notify' (Exception)"},
    {"dn.se", 7, "WAIT_CERT_CR"},
    {"svd.se", 8, "WEB1 ended"},
    {"etc.se", 9, "SetUp state=WAIT_SH.End of file reached (IO::EOFError)"},
    {"apple.se", 10, "SetUp state=SEND_2"},
    {"gp.se", 11, "???"},
    {"goteborg.goactivebooking.com", 12, "???"},
    {"facebook.se", 13, "fel i WAIT_CERT_CR"},
  ]

  if ARGV.size == 1
    if argv_0 = ARGV[0].to_i?
      i = ARGV[0].to_i
      domain = domains[i][0]
    else
      domain = ARGV[0]
    end
  end
  puts domain

  the_request = [
    "GET /index.html HTTP/1.1",
    "Host: #{domain}",
    "#{self.gen_headers}",
  ].join("\r\n") + "\r\n" + "\r\n"
  puts the_request
  # puts "+++++"
  # self.test(hostan: domain, rqst: the_request)
  # puts "-----"

  socket = TCPSocket.new(domain, 443)

  puts "WEB1 started"
  #
  me = TLSClient::Client.new(socket)
  # self.sendHTTP(me, the_request)
  self.receiveHTTP(me)
  puts "WEB1 ended"

  def self.gen_headers
    ["Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
     "Accept-Encoding: gzip, deflate, br",
     "Accept-Language: en-US,en;q=0.9",
     "Priority: u=0, i",
     "Sec-Fetch-Dest: document",
     "Sec-Fetch-Mode: navigate",
     "Accept-Charset: ISO-8859-1,utf-8",
     "User-Agent: User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15",
     "Connection: keep-alive",
     "Keep-Alive: 300",
    ].join("\r\n")
  end

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
    puts send_bytes.to_slice.hexdump

    send_bytes += Bytes.new(1, tls_record_type)
    packet_size = 4 + send_bytes.size + 16 # tag
    header_5_tls[3] = (packet_size >> 8).to_u8
    header_5_tls[4] = (packet_size & 0x00FF).to_u8
    # puts "(send) header_5_tls =#{header_5_tls}"
    # puts "(send) txt_to_bytes =#{send_bytes}\n#{send_bytes.hexdump}"
    msg_decrypted, tag = Xcrypt.encrypt(header: header_5_tls.to_slice,
      message: send_bytes,
      half_conn: me.c_ap_traffic)
    # puts "(send) tag          =#{tag}"
    me.socket.write(header_5_tls.to_slice + msg_decrypted + tag)
    me.socket.flush
  end

  def self.receiveHTTP(me)
    header_5_tls : Bytes = Bytes.new(5, 0x00)
    me.socket.read_fully(header_5_tls)
    puts "header_5_tls       =#{header_5_tls}"
    tls_record_type = header_5_tls[0].to_u8
    version = ((header_5_tls[1].to_u16 << 8) + header_5_tls[2].to_u8).to_u16
    local_payload_size = (header_5_tls[3].to_i << 8) + header_5_tls[4].to_i
    # puts "tls_record_type    =#{tls_record_type}"
    # puts "version            =#{version}"
    # puts "local_payload_size =#{local_payload_size}"

    local_payload = Bytes.new(local_payload_size)
    me.socket.read(local_payload)
    # puts "local_payload      =#{local_payload},\n\n#{local_payload.hexdump}"

    encrypted_message = local_payload[0..local_payload_size - 16 - 1]
    tag_received = local_payload[local_payload_size - 16..local_payload_size - 1]
    # puts "encrypted_message   =#{encrypted_message}"
    # puts "tag_received        =#{tag_received}"

    msg_decrypted = Xcrypt.decrypt(
      header: header_5_tls.to_slice,
      encrypted_message: encrypted_message,
      tag_received: tag_received,
      half_conn: me.s_ap_traffic)
    puts "msg_decrypted       =#{msg_decrypted}"
    record_type = msg_decrypted.last
    is_application_data = me.filter_tls_internals(record_type, msg_decrypted) # {header_4_mysql, Bytes.new(1)}
    if is_application_data
      {true, msg_decrypted[0 - 2]} # drop last byte
    else
      puts "dismiss this"
      {false, StaticArray(UInt8, 4).new(0), Bytes.new(0, 0x00)}
    end
  end

  def self.test(hostan : String, rqst : String)
    socket = TCPSocket.new(hostan, 80)
    puts "(test) REQUEST"
    puts rqst.to_slice.hexdump
    socket.write(rqst.to_slice)
    socket.flush
    state = "inline"
    resp = Array.new(0, 0x00.to_u8)
    while state != "eof"
      got = socket.read_byte
      if got_byte = got
        resp << got_byte.to_u8
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
      end
    end
    sl = Slice.new(resp.size) { |i| resp[i].to_u8 }
    puts "(test) RESPONCE"
    puts sl.hexdump
  end
end
