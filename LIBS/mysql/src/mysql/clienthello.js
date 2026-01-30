x = {
    "Handshake_message_type": 0x16,
    "Message version": 0x0301,
    "content length_1": calculated,
    "1":
    {
        "client hello message": 0x01,
        "client hello length_2": calculated,
        "2": {
            "client hello protocol version": 0x0303,
            "random value": [1, 2, 3, 4],
            "session id length_next": computed,
            "session id": [5, 4, 3, 2],
            "Cipher suites length_next": computed,
            "Cipher suites": [1000, 2000, 3000],
            "number of compression methods to follow": 1,
            "the compression method": 0,
            "length of extensions_next": computed,
            "extension" : "at_least 8 bytes"
        }
    }
}