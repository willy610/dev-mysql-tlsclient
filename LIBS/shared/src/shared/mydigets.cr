module Shared
  enum State : UInt32
    Initialized = 1
    Written
    Summed
    CheckSummed
  end

  def self.endian_UInt32(dst : Bytes, off, src : UInt32)
    dst[off + 0] = ((src & 0xFF000000) >> 24).to_u8
    dst[off + 1] = ((src & 0x00FF0000) >> 16).to_u8
    dst[off + 2] = ((src & 0x0000FF00) >> 8).to_u8
    dst[off + 3] = (src & 0x000000FF).to_u8
  end

  abstract class MyDigest
    SizeChecksum1   = 20
    BlockSize1      = 64
    ChunkSize1      = 64
    SizeChecksum256 = 32
    BlockSize256    = 64
    ChunkSize256    = 64

    @@ident = 0
    property ident : Int32
    property checksum_size : Int32
    property block_size : Int32
    property chunk_size : Int32
    getter w_in_blockit : Slice(UInt64)
    getter h : Array(UInt32)
    len_written : UInt64 = 0
    # property saved_msg_in_write : FixedSizedMessage
    property saved_msg_in_write : Bytes
    getter padlen_2_write : Bytes
    getter digs_from_checksum : Bytes
    getter state : State

    property save_h : Array(UInt32)
    property save_len_written : UInt64
    property save_saved_msg_in_write : Bytes
    abstract def blockit(msg : Bytes, consumed_p : Int32, end_index : Int32) : Nil

    def initialize
      @checksum_size = uninitialized Int32
      @block_size = uninitialized Int32
      @chunk_size = uninitialized Int32
      @h = uninitialized Array(UInt32)
      @w_in_blockit = uninitialized Slice(UInt64)
      #   used for copy and restore
      @len_written = uninitialized UInt64
      @saved_msg_in_write = uninitialized Bytes
      @padlen_2_write = uninitialized Bytes
      @digs_from_checksum = uninitialized Bytes # .new(0) # resize deeper

      @save_h = uninitialized Array(UInt32)
      @save_len_written = uninitialized UInt64
      @save_saved_msg_in_write = Bytes.new(ChunkSize256) # !!!!!! correct this

      @state = State::Initialized
      @@ident += 1
      @ident = @@ident
      #
    end

    def bigsum : Bytes
      if @state == State::Initialized || @state == State::Written
      else
        raise "MyDigest wrong method 'bigsum' in state '#{@state}'"
      end
      push_some_attributes

      hash = bigchecksum

      pop_some_attributes
      @state = State::Written
      hash
    end

    private def push_some_attributes
      # save values that can be changed
      @save_h = @h.map { |v| v }
      @save_len_written = @len_written
      @save_saved_msg_in_write = @saved_msg_in_write
    end

    private def pop_some_attributes
      @h = @save_h.map { |v| v }
      @len_written = @save_len_written
      @saved_msg_in_write = @save_saved_msg_in_write
    end

    def bigwrite(p_as_slice : Bytes) : Nil
      if @state == State::Initialized || @state == State::Written
        @state = State::Written
      else
        raise "MyDigest wrong method 'bigwrite' in state '#{@state}'"
      end
      # p_as_slice holds: case (1)      111
      #
      # p_as_slice holds: case (2)      111222 222333 333444
      #                                       |      |      | chunksize == 6
      # saved_msg_in_write holds:       00
      # total to hash                   001112 222223 333334 44
      #                                       |      |      |
      @len_written += p_as_slice.size.to_u64
      begin
        if p_as_slice.size + @saved_msg_in_write.size < @chunk_size
          # Case (1)
          # Old (00) and new (111) fits in 6 bytes. Save and return
          @saved_msg_in_write += p_as_slice
        else
          from_offset = 0
          to_offset = @saved_msg_in_write.size
          copy_len = @chunk_size - @saved_msg_in_write.size
          # Case(2)
          # append a slice like 1112 to 00 giving 6 bytes 001112
          loop do
            a_slice_from_in = p_as_slice[from_offset, copy_len]

            # consume from 'p_as_slice'
            @saved_msg_in_write += a_slice_from_in
            blockit(@saved_msg_in_write, 0, @chunk_size)
            @saved_msg_in_write = Bytes.new(0) # empty
            to_offset = 0
            # jump along 'p_as_slice'
            from_offset += copy_len
            copy_len = @chunk_size
            # last part smaller than a chunk? than exit and save
            # we might have wrtitten 222223 or 333334
            break if from_offset + @chunk_size > p_as_slice.size
          end
          # Save the traling part of 'p_as_slice'
          # last it is 44
          copy_len = p_as_slice.size - from_offset
          a_slice_from_in = p_as_slice[from_offset, copy_len]
          @saved_msg_in_write += a_slice_from_in
        end
      rescue ex
        raise "bigwrite failde=#{ex.message}"
      end
    end

    def bigchecksum : Bytes
      if @state == State::Written || @state == State::Initialized
      else
        raise "MyDigest wrong method 'bigchecksum' in state '#{@state}'"
      end

      len = @len_written.to_u32 # sofar not negative
      t : Int64 = 0x00
      if len % 64 < 56
        t = (56.to_i64 - len) % 64.to_i64
      else
        t = (64.to_i64 + 56.to_i64 - len) % 64.to_i64
      end
      # // Length in bits.
      len = len << 3

      @padlen_2_write = Bytes.new(t.to_i32 + 8)
      @padlen_2_write[0] = 0x80
      Shared.endian_UInt32(@padlen_2_write, t + 4, len)

      bigwrite(p_as_slice: @padlen_2_write.to_slice)
      if @saved_msg_in_write.size != 0
        raise "MyDigest :: bigchecksum() saved_msg_in_write.size != 0"
      end
      @digs_from_checksum = Bytes.new(@checksum_size)
      (0..@h.size - 1).each { |i| Shared.endian_UInt32(@digs_from_checksum, i * 4, @h[i]) }
      @state = State::CheckSummed

      @digs_from_checksum
    end
  end
end
