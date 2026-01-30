module Shared
  class Sha256 < MyDigest
    # SizeChecksum256 = 32
    # BlockSize256    = 64
    # ChunkSize256    = 64
    Init0 = 0x6A09E667.to_u32
    Init1 = 0xBB67AE85.to_u32
    Init2 = 0x3C6EF372.to_u32
    Init3 = 0xA54FF53A.to_u32
    Init4 = 0x510E527F.to_u32
    Init5 = 0x9B05688C.to_u32
    Init6 = 0x1F83D9AB.to_u32
    Init7 = 0x5BE0CD19.to_u32

    BIGmagic256 = "sha\x03"

    K = [0x428a2f98,
         0x71374491,
         0xb5c0fbcf,
         0xe9b5dba5,
         0x3956c25b,
         0x59f111f1,
         0x923f82a4,
         0xab1c5ed5,
         0xd807aa98,
         0x12835b01,
         0x243185be,
         0x550c7dc3,
         0x72be5d74,
         0x80deb1fe,
         0x9bdc06a7,
         0xc19bf174,
         0xe49b69c1,
         0xefbe4786,
         0x0fc19dc6,
         0x240ca1cc,
         0x2de92c6f,
         0x4a7484aa,
         0x5cb0a9dc,
         0x76f988da,
         0x983e5152,
         0xa831c66d,
         0xb00327c8,
         0xbf597fc7,
         0xc6e00bf3,
         0xd5a79147,
         0x06ca6351,
         0x14292967,
         0x27b70a85,
         0x2e1b2138,
         0x4d2c6dfc,
         0x53380d13,
         0x650a7354,
         0x766a0abb,
         0x81c2c92e,
         0x92722c85,
         0xa2bfe8a1,
         0xa81a664b,
         0xc24b8b70,
         0xc76c51a3,
         0xd192e819,
         0xd6990624,
         0xf40e3585,
         0x106aa070,
         0x19a4c116,
         0x1e376c08,
         0x2748774c,
         0x34b0bcb5,
         0x391c0cb3,
         0x4ed8aa4a,
         0x5b9cca4f,
         0x682e6ff3,
         0x748f82ee,
         0x78a5636f,
         0x84c87814,
         0x8cc70208,
         0x90befffa,
         0xa4506ceb,
         0xbef9a3f7,
         0xc67178f2]

    def initialize
      super
      @h = Array.new(8, 0.to_u32)
      # The size of a SHA256 checksum in bytes.
      @checksum_size = SizeChecksum256.to_i32
      # // The blocksize of SHA256 and SHA224 in bytes.
      @block_size = BlockSize256
      @chunk_size = ChunkSize256
      @w_in_blockit = Slice.new(64, 0.to_u64)
      @h = [Init0, Init1, Init2, Init3, Init4, Init5, Init6, Init7]
      @nx = 0
    end

    def to_s(io : IO)
      io << "(ident=#{ident} \n h=#{@h}\n saved_msg_in_write=#{@saved_msg_in_write})\n"
    end

    def self.checksum_size
      SizeChecksum256.to_i32
    end

    def bigmarshal_binary : Bytes
      marshaledSize = BIGmagic256.size + 8*4 + ChunkSize256 + 8
      b = Bytes.new(marshaledSize, 0x00.to_u8)
      to_b = [BIGmagic256.bytes,
              @h.map { |src| [((src & 0xFF000000) >> 24).to_u8,
                              ((src & 0x00FF0000) >> 16).to_u8,
                              ((src & 0x0000FF00) >> 8).to_u8,
                              (src & 0x000000FF).to_u8] }.flatten,
              # (0..@saved_msg_in_write.length - 1).map_with_index { |_, i| @saved_msg_in_write[i] },
              (0..@saved_msg_in_write.size - 1).map_with_index { |_, i| @saved_msg_in_write[i] },
      ].flatten
      (0..to_b.size - 1).each { |i| b[i] = to_b[i] }
      len = @len_written
      len_as_bytes : Array(UInt8) = [(len >> 56).to_u8,
                                     (len >> 48).to_u8,
                                     (len >> 40).to_u8,
                                     (len >> 32).to_u8,
                                     (len >> 24).to_u8,
                                     (len >> 16).to_u8,
                                     (len >> 8).to_u8,
                                     (len.to_u8)]
      (0..8 - 1).each { |i|
        b[i + marshaledSize - 8] = len_as_bytes[i]
      }
      b
    end

    def blockit(msg : Bytes, consumed_p : Int32, end_index : Int32) : Nil
      v1 : UInt32 = 0.to_u32
      t1 : UInt32 = 0.to_u32
      t2 : UInt32 = 0.to_u32
      h0, h1, h2, h3, h4, h5, h6, h7 = @h.map { |v| v }
      (0..15).each { |i|
        j = i * 4
        @w_in_blockit[i] = msg[j].to_u32 << 24 | msg[j + 1].to_u32 << 16 | msg[j + 2].to_u32 << 8 | msg[j + 3].to_u32
      }
      i = 16
      while i < 64
        v1 = (@w_in_blockit[i - 2] & 0xFFFFFFFF).to_u32
        t1 = v1.rotate_left(-17) ^ v1.rotate_left(-19) ^ (v1 >> 10)
        v2 = (@w_in_blockit[i - 15] & 0xFFFFFFFF).to_u32
        t2 = v2.rotate_left(-7) ^ v2.rotate_left(-18) ^ (v2 >> 3)
        @w_in_blockit[i] = ((t1.to_u64 + @w_in_blockit[i - 7].to_u64 + t2.to_u64 + @w_in_blockit[i - 16].to_u64) & 0xFFFFFFFF).to_u32
        i += 1
      end
      a, b, c, d, e, f, g, h = {h0, h1, h2, h3, h4, h5, h6, h7}
      i = 0
      while i < 64
        t1 = ((h.to_u64 +
               (e.rotate_left(-6) ^ e.rotate_left(-11) ^ e.rotate_left(-25)).to_u64 +
               ((e & f) ^ (~e & g)).to_u64 + K[i].to_u64 + @w_in_blockit[i].to_u64) &
              0xFFFFFFFF).to_u32
        t2 = (
          (
            (a.rotate_left(-2).to_u64 ^ a.rotate_left(-13).to_u64 ^ a.rotate_left(-22).to_u64) +
            ((a & b) ^ (a & c) ^ (b & c)).to_u64
          ) & 0xFFFFFFFF
        ).to_u32
        h = g
        g = f
        f = e
        e = ((d.to_u64 + t1.to_u64) & 0xFFFFFFFF).to_u32
        d = c
        c = b
        b = a
        a = ((t1.to_u64 + t2.to_u64) & 0xFFFFFFFF).to_u32

        i += 1
      end
      h0 = ((h0.to_u64 + a.to_u64) & 0xFFFFFFFF).to_u32
      h1 = ((h1.to_u64 + b.to_u64) & 0xFFFFFFFF).to_u32
      h2 = ((h2.to_u64 + c.to_u64) & 0xFFFFFFFF).to_u32
      h3 = ((h3.to_u64 + d.to_u64) & 0xFFFFFFFF).to_u32
      h4 = ((h4.to_u64 + e.to_u64) & 0xFFFFFFFF).to_u32
      h5 = ((h5.to_u64 + f.to_u64) & 0xFFFFFFFF).to_u32
      h6 = ((h6.to_u64 + g.to_u64) & 0xFFFFFFFF).to_u32
      h7 = ((h7.to_u64 + h.to_u64) & 0xFFFFFFFF).to_u32
      [h0, h1, h2, h3, h4, h5, h6, h7].each_with_index { |v, i| @h[i] = v }
    end
  end
end
