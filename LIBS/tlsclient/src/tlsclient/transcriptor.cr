#  RFC 8846
# 2. Protocol Overview
#
#      Client                                           Server

# Key  ^ ClientHello
# Exch | + key_share*
#      | + signature_algorithms*
#      | + psk_key_exchange_modes*
#      v + pre_shared_key*       -------->
#                                                   ServerHello  ^ Key
#                                                  + key_share*  | Exch
#                                             + pre_shared_key*  v
#                                         {EncryptedExtensions}  ^  Server
#                                         {CertificateRequest*}  v  Params
#                                                {Certificate*}  ^
#                                          {CertificateVerify*}  | Auth
#                                                    {Finished}  v
#                                <--------  [Application Data*]
#      ^ {Certificate*}
# Auth | {CertificateVerify*}
#      v {Finished}              -------->
#        [Application Data]      <------->  [Application Data]
# =======================================================================
# =======================================================================
# =======================================================================
# A.1. Client State Machine
#
#                           START <----+
#            Send ClientHello |        | Recv HelloRetryRequest
#       [K_send = early data] |        |
#                             v        |
#        /                 WAIT_SH ----+
#        |                    | Recv ServerHello
#        |                    | K_recv = handshake
#    Can |                    V
#   send |                 WAIT_EE
#  early |                    | Recv EncryptedExtensions
#   data |           +--------+--------+
#        |     Using |                 | Using certificate
#        |       PSK |                 v
#        |           |            WAIT_CERT_CR
#        |           |        Recv |       | Recv CertificateRequest
#        |           | Certificate |       v
#        |           |             |    WAIT_CERT
#        |           |             |       | Recv Certificate
#        |           |             v       v
#        |           |              WAIT_CV
#        |           |                 | Recv CertificateVerify
#        |           +> WAIT_FINISHED <+
#        |                  | Recv Finished
#        \                  | [Send EndOfEarlyData]
#                           | K_send = handshake
#                           | [Send Certificate [+ CertificateVerify]]
# Can send                  | Send Finished
# app data   -->            | K_send = K_recv = application
# after here                v
#                       CONNECTED
#
# =======================================================================
# =======================================================================
# =======================================================================
# A.2. Server State Machine
#                               START <-----+
#                Recv ClientHello |         | Send HelloRetryRequest
#                                 v         |
#                              RECVD_CH ----+
#                                 | Select parameters
#                                 v
#                              NEGOTIATED
#                                 | Send ServerHello
#                                 | K_send = handshake
#                                 | Send EncryptedExtensions
#                                 | [Send CertificateRequest]
#  Can send                       | [Send Certificate + CertificateVerify]
#  app data                       | Send Finished
#  after   -->                    | K_send = application
#  here                  +--------+--------+
#               No 0-RTT |                 | 0-RTT
#                        |                 |
#    K_recv = handshake  |                 | K_recv = early data
#  [Skip decrypt errors] |    +------> WAIT_EOED -+
#                        |    |       Recv |      | Recv EndOfEarlyData
#                        |    | early data |      | K_recv = handshake
#                        |    +------------+      |
#                        |                        |
#                        +> WAIT_FLIGHT2 <--------+
#                                 |
#                        +--------+--------+
#                No auth |                 | Client auth
#                        |                 |
#                        |                 v
#                        |             WAIT_CERT
#                        |        Recv |       | Recv Certificate
#                        |       empty |       v
#                        | Certificate |    WAIT_CV
#                        |             |       | Recv
#                        |             v       | CertificateVerify
#                        +-> WAIT_FINISHED <---+
#                                 | Recv Finished
#                                 | K_recv = application
#                                 v
#                             CONNECTED

class Transcriptor
  
  # State                      | Message                    | Action
  # START                      | write hellomsg             | add
  # WAIT_SH                    | read hellomsg              | add
  #                            |                            | compute derive "c hs traffic" and "s hs traffic"
  # WAIT_EE_ChangeCipherSpec   | read 'ChangeCipherSpec'    | nothing
  # WAIT_EE                    | read 'EncryptedExtensions' | add
  # WAIT_CERT_CR               | read 'CertificateRequest'  | add
  # WAIT_CERT                  | read 'Certificate'         | add
  # WAIT_CV                    | read 'CertificateVerify'   | add
  # WAIT_FINISHED              | read 'Finished'            | compute and verify 'Finished' from server
  #                            |                            | add 'ReadFinished'
  #                            |                            | generate_applic_keys() via compute derive 'c ap traffic' and 's ap traffic'
  #                            | write 'Certificate'        |
  #                            |                            | add 'WriteCertificate'
  #                            |                            | compute a 'Finished' content to server
  # SEND_FINISH                | write 'Finished'           | add
  #

  property the_total_transcript_hasher : Shared::Sha256
  property notes : Array(String)

  def initialize
    @the_total_transcript_hasher = Shared::Sha256.new
    Shared
    @notes = Array.new(0, "")
    self
  end

  def add_bytes(to_add : Bytes, note : String)
    @the_total_transcript_hasher.bigwrite(p_as_slice: to_add)
    add_not(note)
    self
  end

  def add_not(note : String)
    @notes << note
    self
  end

  def checksum_size
    @the_total_transcript_hasher.checksum_size
  end

  def show_history
    puts "\nTranscriptor history:\n#{@notes.join("\n ")}\n\n"
  end

  def get_sum
    @the_total_transcript_hasher.bigsum
  end
end
