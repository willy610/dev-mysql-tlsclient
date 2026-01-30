module TLSClient
  class ClientHelloMessage
    # @handshake_messag_type : UInt8 = 0x16
    @typeClientHelloMessage : UInt8 = 1

    @client_hello_protocol_version : UInt16 = 0x0304 # TLS v1.2 772
    # @client_hello_protocol_version : UInt16 = 0x0304 # TLS VersionTLS13 773
    @random : Bytes = Bytes.new(32)
    @sessionid : Bytes = Bytes.new(32)

    @cipher_suites = Array(UInt8).new
    @sign_algo = Array(UInt8).new
    @supported_curves = Array(NamedTuple(name: String, id: UInt16, pubkey: Slice(UInt8))).new

    getter message : Bytes

    def initialize(@the_ECDHD_container : ECDHContainer, @legacy_version : UInt16 )
      @message = uninitialized Bytes
      @cipher_suites = [{name: "TLS_CHACHA20_POLY1305_SHA256", id: 0x1303.to_u16}].map { |ciph|
        [((ciph[:id] & 0xff00) >> 8).to_u8, (ciph[:id] & 0x00ff).to_u8]
      }.flatten

      @sign_algo = [
        {name: "PSSWithSHA256", id: 0x804.to_u16},
        # {name: "ECDSAWithP256AndSHA256", id: 0x403.to_u16},
        # {name: "Ed25519", id: 0x807.to_u16},
        # {name: "PSSWithSHA384", id: 0x805.to_u16},
        # {name: "PSSWithSHA512", id: 0x806.to_u16},
        # {name: "PKCS1WithSHA256", id: 0x401.to_u16},
        # {name: "PKCS1WithSHA384", id: 0x501.to_u16},
        # {name: "PKCS1WithSHA512", id: 0x601.to_u16},
        # {name: "ECDSAWithP384AndSHA384", id: 0x503.to_u16},
        # {name: "ECDSAWithP521AndSHA512", id: 0x603.to_u16},
        # {name: "PKCS1WithSHA1", id: 0x201.to_u16},
        # {name: "ECDSAWithSHA1", id: 0x203.to_u16},
      ].map { |curv|
        [((curv[:id] & 0xff00) >> 8).to_u8, (curv[:id] & 0x00ff).to_u8]
      }.flatten
      # puts "@sign_algo=#{@sign_algo}"
      rand_big_int = BigInt.new(Random.rand * BigFloat.new(@the_ECDHD_container.the_ECDH.curve.field.n))
      # rand_big_int = BigInt.new("55127834379294770026244673887767786285380127299628066169304562401906461245440")
      @the_ECDHD_container.set_private_key(rand_big_int)
      client_priv_XY = @the_ECDHD_container.calc_public_key_xy

      the_xy_as_bytes = EllipticCurve::Point.to_slice(client_priv_XY[0], client_priv_XY[1])

      shared_key : Slice(UInt8) = Slice.new(1 + 32 + 32, 0.to_u8)
      shared_key[0] = 0x04 # No copression
      (0..31).each { |i| shared_key[1 + i] = the_xy_as_bytes[0][i] }
      (0..31).each { |i| shared_key[1 + 32 + i] = the_xy_as_bytes[1][i] }
      use_as_shared_key = shared_key
      @supported_curves = [
        {name: "CurveP256", id: 0x17.to_u16, pubkey: use_as_shared_key},
        #   {name: "CurveP384", id: 0x18.to_u16, pubkey: use_as_shared_key},
        # {name: "CurveP521", id: 0x19.to_u16, pubkey: Slice(UInt8).empty},
      ]
      self
    end

    def build_client_hello_msg
      # Mandatory
      pref : Int64 = Time.utc.to_unix
      (0..32 - 1).each { |i| @random[i] = Random::Secure.rand(255).to_u8 }
      (0..32 - 1).each { |i| @sessionid[i] = Random::Secure.rand(255).to_u8 }

      # ++++++++++++++++++++++
      # SUPPORTEDPOINTS RFC 4492, Section 5.1.2

      ext_supported_points = [
        Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionSupportedPoints.value),
        [0x0.to_u8, # Uncompressed
         0x2.to_u8, # ANSI X.962 compressed char2
         0x1.to_u8, # ANSI X.962 compressed prime
         0x0.to_u8],
      ].flatten

      #  RFC 5746, Section 3.2
      ext_renegotiation = [
        Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionRenegotiationInfo.value),
        Utils.length_of("2", 0x00.to_u8),
      ].flatten
      #
      #  RFC 7627, Section 4
      ext_extended_master_secret = [
        Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionExtendedMasterSecret.value),
        Utils.int16_to_big(0), # // empty ext_data
      ].flatten
      #
      #  RFC 6962, Section 3.3.1
      ext_sct = [
        Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionSCT.value),
        Utils.int16_to_big(0), # // empty ext_data
      ].flatten
      #
      #  RFC 4366, Section 3.6
      ext_status_request = [
        Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionStatusRequest.value),
        Utils.length_of("2",
          0x01.to_u8,            # status_type = ocsp
          Utils.int16_to_big(0), # empty responder_id_list
          Utils.int16_to_big(0)  # empty request_extensions
        ),
      ].flatten
      # supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7

      ext_supported_groups = [
        Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionSupportedGroups.value),
        Utils.length_of("2", # @supporetd_curves
          Utils.length_of("2",
          # JUST THE FIRST??????
          # mysql accepst both
          [@supported_curves[0]].map { |kurv| Utils.int16_to_big(kurv[:id]) }.flatten
        )
        ),
      ].flatten
      # ext_supported_curves = [
      #   Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionSupportedCurves.value),
      #   Utils.length_of("2", # @supporetd_curves
      #     Utils.length_of("2",
      #     # JUST THE FIRST?
      #     @supported_curves.map { |kurv| Utils.int16_to_big(kurv[:id]) }.flatten
      #   )
      #   ),
      # ].flatten

      # //  RFC 5246, Section 7.4.1.4.1
      ext_signatur_algorithm = [
        Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionSignatureAlgorithms.value),
        Utils.length_of("2",
          Utils.length_of("2",
            @sign_algo
          )),
      ].flatten
      # //  RFC 8446, Section 4.2.1
      ext_supported_versions = [
        Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionSupportedVersions.value),
        Utils.length_of("2",
          Utils.length_of("1",
            Utils.int16_to_big(0x304),
          )),
      ].flatten
      #
      # //  RFC 8446, Section 4.2.8
      ext_key_shares = [
        Utils.int16_to_big(TLSDefinitions::ExtensionType::ExtensionKeyShare.value),
        Utils.length_of("2",
          Utils.length_of("2",
            [@supported_curves[0]].map { |kurv|
              [Utils.int16_to_big(kurv[:id]),
               Utils.length_of("2",
                 kurv[:pubkey]
               ),
              ].flatten
            }.flatten
          )
        ),
      ].flatten

      tmp_ara =
        [
          @typeClientHelloMessage, # Handshake message type
          Utils.length_of("3",
            # Utils.int16_to_big(@client_hello_protocol_version), # client hello protocol version
            Utils.int16_to_big(@legacy_version), # client hello protocol version
            @random,                                            # random value
            Utils.length_of("1", @sessionid),                   # session
            Utils.length_of("2", @cipher_suites),
            # number of compression methods to follow. zero is no compression
            Utils.length_of("1", 0.to_u8),
            # LENGTH OF EXTENSIONS
            Utils.length_of("2",
              ext_supported_points,
              ext_renegotiation,
              ext_extended_master_secret,
              ext_sct,
              ext_status_request,
              ext_supported_groups,
              ext_signatur_algorithm,
              ext_supported_versions,
              ext_key_shares,
            ).flatten,
          ).flatten,
        ].flatten

      # Remove header
      @message = Bytes.new(tmp_ara.size - 4) { |i| tmp_ara[4 + i] }
    end
  end
end
