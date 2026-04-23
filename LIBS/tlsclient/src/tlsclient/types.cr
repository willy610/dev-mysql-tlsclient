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
    ExtensionServerName               = 0
    ExtensionStatusRequest = 5
    # ExtensionSupportedCurves     = 10
    ExtensionSupportedGroups     = 10
    ExtensionSupportedPoints     = 11
    ExtensionSignatureAlgorithms = 13
    ExtensionALPN                     = 16
    ExtensionSCT                  = 18
    ExtensionExtendedMasterSecret = 23
    ExtensionSessionTicket            = 35
    ExtensionPreSharedKey = 41
    ExtensionEarlyData                = 42
    ExtensionSupportedVersions = 43
    ExtensionCookie                   = 44
    ExtensionPSKModes                 = 45
    ExtensionCertificateAuthorities   = 47
    ExtensionSignatureAlgorithmsCert  = 50
    ExtensionKeyShare = 51
    ExtensionQUICTransportParameters  = 57
    ExtensionRenegotiationInfo = 0xff01
    ExtensionECHOuterExtensions       = 0xfd00
    ExtensionEncryptedClientHello     = 0xfe0d
  end
end
