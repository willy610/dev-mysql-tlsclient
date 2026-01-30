module Shared
  class Sha1 < MyDigest
    Init0 = 0x67452301.to_u32
    Init1 = 0xEFCDAB89.to_u32
    Init2 = 0x98BADCFE.to_u32
    Init3 = 0x10325476.to_u32
    Init4 = 0xC3D2E1F0.to_u32

    getter checksum_size : Int32
    getter block_size : Int32
    getter chunk_size : Int32

    def initialize
      super
      @h = Array.new(5, 0.to_u32)
      @h = [Init0, Init1, Init2, Init3, Init4]
      @checksum_size = SizeChecksum1.to_i32
      @block_size = BlockSize1
      @chunk_size = ChunkSize1
      @w_in_blockit = Slice.new(16, 0.to_u64)
      @state = State::Initialized
    end

    K0 = 0x5A827999
    K1 = 0x6ED9EBA1
    K2 = 0x8F1BBCDC
    K3 = 0xCA62C1D6

    alias TYPEHS = UInt64
    alias TYPE_a_f = UInt64

    def blockit(msg : Bytes, consumed_p : Int32, end_index : Int32) : Nil # puts "msg= #{msg}"
      start_index = 0
      h0 : TYPEHS
      h1 : TYPEHS
      h2 : TYPEHS
      h3 : TYPEHS
      h4 : TYPEHS
      #
      a : TYPE_a_f
      b : TYPE_a_f
      c : TYPE_a_f
      d : TYPE_a_f
      e : TYPE_a_f
      f : TYPE_a_f
      tmp : TYPE_a_f
      t : TYPE_a_f

      h0, h1, h2, h3, h4 = {@h[0].to_u64, @h[1].to_u64, @h[2].to_u64, @h[3].to_u64, @h[4].to_u64}
      while start_index < end_index - consumed_p
        (0..15).each { |i|
          j = consumed_p + start_index + i * 4
          @w_in_blockit[i] = msg[j].to_u32 << 24 | msg[j + 1].to_u32 << 16 | msg[j + 2].to_u32 << 8 | msg[j + 3].to_u32
        }
        a, b, c, d, e = {h0, h1, h2, h3, h4}
        i = 0
        while i < 16
          f = b & c | ~b & d
          t = (a.to_u32.rotate_left(5).to_u64 + f + e + @w_in_blockit[i & 0xf] + K0) & 0xFFFFFFFF
          a, b, c, d, e = {t, a, b.to_u32.rotate_left(30).to_u64, c, d}

          i = i + 1
        end
        while i < 20
          tmp = (@w_in_blockit[(i - 3) & 0xf] ^ @w_in_blockit[(i - 8) & 0xf] ^ @w_in_blockit[(i - 14) & 0xf] ^ @w_in_blockit[(i) & 0xf]) & 0xFFFFFFFF
          @w_in_blockit[i & 0xf] = tmp.to_u32.rotate_left(1).to_u64
          f = b & c | ~b & d
          t = (a.to_u32.rotate_left(5).to_u64 + f + e + @w_in_blockit[i & 0xf] + K0) & 0xFFFFFFFF
          a, b, c, d, e = {t, a, b.to_u32.rotate_left(30).to_u64, c, d}
          i = i + 1
        end
        while i < 40
          tmp = (@w_in_blockit[(i - 3) & 0xf] ^ @w_in_blockit[(i - 8) & 0xf] ^ @w_in_blockit[(i - 14) & 0xf] ^ @w_in_blockit[(i) & 0xf]) & 0xFFFFFFFF
          @w_in_blockit[i & 0xf] = tmp.to_u32.rotate_left(1).to_u64
          f = b ^ c ^ d
          t = (a.to_u32.rotate_left(5).to_u64 + f + e + @w_in_blockit[i & 0xf] + K1) & 0xFFFFFFFF
          a, b, c, d, e = {t, a, b.to_u32.rotate_left(30).to_u64, c, d}
          i = i + 1
        end
        while i < 60
          tmp = (@w_in_blockit[(i - 3) & 0xf] ^ @w_in_blockit[(i - 8) & 0xf] ^ @w_in_blockit[(i - 14) & 0xf] ^ @w_in_blockit[(i) & 0xf]) & 0xFFFFFFFF
          @w_in_blockit[i & 0xf] = tmp.to_u32.rotate_left(1).to_u64
          f = ((b | c) & d) | (b & c)
          t = (a.to_u32.rotate_left(5).to_u64 + f + e + @w_in_blockit[i & 0xf] + K2) & 0xFFFFFFFF
          a, b, c, d, e = {t, a, b.to_u32.rotate_left(30).to_u64, c, d}
          i = i + 1
        end
        while i < 80
          tmp = (@w_in_blockit[(i - 3) & 0xf] ^ @w_in_blockit[(i - 8) & 0xf] ^ @w_in_blockit[(i - 14) & 0xf] ^ @w_in_blockit[(i) & 0xf]) & 0xFFFFFFFF
          @w_in_blockit[i & 0xf] = (tmp.to_u32.rotate_left(1).to_u64) & 0xFFFFFFFF
          f = b ^ c ^ d
          t = (a.to_u32.rotate_left(5).to_u64 + f + e + @w_in_blockit[i & 0xf] + K3) & 0xFFFFFFFF
          a, b, c, d, e = {t, a, b.to_u32.rotate_left(30).to_u64, c, d}

          i = i + 1
        end
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        start_index = start_index + ChunkSize1
      end
      #   done
      @h[0], @h[1], @h[2], @h[3], @h[4] = {h0.to_u32, h1.to_u32, h2.to_u32, h3.to_u32, h4.to_u32}
    end

    def to_s(io : IO) : Nil
      io << "Sha1::\n"
      io << " saved_msg_in_write="
      io << @saved_msg_in_write
      io << "\n h="
      io << @h.to_s
      io << "\n padlen_2_write="
      io << @padlen_2_write.to_s

    end
  end
end
