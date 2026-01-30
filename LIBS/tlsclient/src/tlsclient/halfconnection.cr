  class HalfConnection
    #
    property trafficSecret : Bytes # current TLS 1.3 traffic secret
    property key : Bytes           # A 256-bit key
    property iv : Bytes            # 96 bits Inital Vector
    property seq : Array(UInt8)    # 64-bit sequence number

    def initialize(@trafficSecret, @key, @iv)
      # iv is nonce
      # nonce = @iv
      # @aead = Crypto::AeadChacha20Poly1305.new(key, nonce, ciphertext)
      @seq = Array.new(8, 0x00.to_u8)
      #  google ChaCha20-Poly1305 how to use key iv gives
      # https://www.google.com/search?q=ChaCha20-Poly1305+how+to+use+key+iv&sca_esv=0f3f3d91d2ee70a0&rlz=1C5CHFA_enSE1136SE1136&biw=1123&bih=1031&ei=rLN3aMCwMN-n1fIPuuOZkAg&ved=0ahUKEwjAtv2KyMGOAxXfU1UIHbpxBoIQ4dUDCBA&uact=5&oq=ChaCha20-Poly1305+how+to+use+key+iv&gs_lp=Egxnd3Mtd2l6LXNlcnAiI0NoYUNoYTIwLVBvbHkxMzA1IGhvdyB0byB1c2Uga2V5IGl2MggQABiABBiiBDIIEAAYgAQYogQyBRAAGO8FSLBCUJIKWPo_cAF4AZABAJgB6wGgAaELqgEGMTYuMS4xuAEDyAEA-AEBmAIToAKIDMICChAAGLADGNYEGEfCAg0QABiABBiwAxhDGIoFwgIHEAAYgAQYE8ICBhAAGBYYHsICBRAhGKABwgIIEAAYFhgKGB7CAgQQIRgVwgIHECEYoAEYCpgDAIgGAZAGCZIHBjE3LjEuMaAH0z6yBwYxNi4xLjG4B4IMwgcGMC40LjE1yAdB&sclient=gws-wiz-serp

      #  key = Crypto::Hex.bytes("00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f")
      # nonce = Crypto::Hex.bytes("00:00:00:09:00:00:00:4a:00:00:00:00")
      # ciphertext = IO::Memory.new
      # The inputs to AEAD_CHACHA20_POLY1305 are:
      # * key: A 256-bit key
      # * nonce: A 96-bit nonce -- different for each invocation with the same key
      # * io: the buffer to write the authenticated plain and ciphertext to

      # aead = Crypto::AeadChacha20Poly1305.new(key, nonce, ciphertext)
      # aead.aad("Header".to_slice)
      # aead.update("Hello World!".to_slice)
      # tag = aead.final

      # puts tag
      self
    end

    # https://forum.crystal-lang.org/t/correct-way-to-copy-objects/3398
    # clone
    # copy

    def_clone

    def iv_mix_in_or_out_seq
      (0..@seq.size - 1).each { |i|
        @iv[4 + i] ^= @seq[i]
      }
      @iv
    end

    def inc_sequence
      i = @seq.size - 1
      while i > 0
        @seq[i] &+= 1 # accept overflow. don't raise
        if @seq[i] != 0
          return
        end
        i -= 1
      end
      raise "HalfConnection::inc_sequence() sequence number wraparound"
    end

    def use_it(ciphertext)
      aead = Crypto::AeadChacha20Poly1305.new(@key, @nonce, ciphertext)
    end

    def to_s(io : IO)
      io << "\n(HalfConnection:: trafficSecret=#{@trafficSecret}\n key=#{@key}\n iv=#{iv}\n seq=#{@seq})\n"
    end
  end