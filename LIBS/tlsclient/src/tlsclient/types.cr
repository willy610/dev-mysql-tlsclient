module TLSDefinitions
  # https://crystal-lang.org/reference/1.18/syntax_and_semantics/alias.html
  enum TLSRecordType : UInt8
    RecordTypeChangeCipherSpec =   20
    RecordTypeAlert            =   21
    RecordTypeHandshake        =   22
    RecordTypeApplicationData  =   23
    RecordTypeUndefined        =    0
    RecordTypeError            = 0xff # 255
  end

  #
  enum TlSHandshakeType : UInt8
    TypeHelloRequest        =   0
    TypeClientHello         =   1
    TypeServerHello         =   2
    TypeNewSessionTicket    =   4
    TypeEndOfEarlyData      =   5
    TypeEncryptedExtensions =   8
    TypeCertificate         =  11
    TypeServerKeyExchange   =  12
    TypeCertificateRequest  =  13
    TypeServerHelloDone     =  14
    TypeCertificateVerify   =  15
    TypeClientKeyExchange   =  16
    TypeFinished            =  20
    TypeCertificateStatus   =  22
    TypeKeyUpdate           =  24
    TypeUndefined           =  99
    TypeMessageHash         = 254 # synthetic message
  end

  # # RFC 8446  4.2 Extensions

  enum ExtensionType : UInt16
    # ExtensionServerName              uint16 = 0
    ExtensionStatusRequest       =  5
    # ExtensionSupportedCurves     = 10
    ExtensionSupportedGroups     = 10
    ExtensionSupportedPoints     = 11
    ExtensionSignatureAlgorithms = 13
    # ExtensionALPN                    uint16 = 16
    ExtensionSCT                  = 18
    ExtensionExtendedMasterSecret = 23
    # ExtensionSessionTicket           uint16 = 35
    # ExtensionPreSharedKey            uint16 = 41
    # ExtensionEarlyData               uint16 = 42
    ExtensionSupportedVersions = 43
    # ExtensionCookie                  uint16 = 44
    # ExtensionPSKModes                uint16 = 45
    # ExtensionCertificateAuthorities  uint16 = 47
    # ExtensionSignatureAlgorithmsCert uint16 = 50
    ExtensionKeyShare = 51
    # ExtensionQUICTransportParameters uint16 = 57
    ExtensionRenegotiationInfo = 0xff01
    # ExtensionECHOuterExtensions      uint16 = 0xfd00
    # ExtensionEncryptedClientHello    uint16 = 0xfe0d
  end
end
