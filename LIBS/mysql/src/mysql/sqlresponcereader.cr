class MySql::SQLResponceReader
  property message : Bytes
  property connection : MySql::Connection
  property using_tls : Bool
  property header_4_mysql : UInt8[4]
  property the_message_as_io : Unmarshaller
  property do_read_and_deblock_tlspackage : Bool = true
  property msg_decrypted : Bytes
  property tls_payload_size : Int32
  property anBRIDGE : MySql::BRIDGE::BRIDGEPlain | MySql::BRIDGE::BRIDGETls

  property in_empty : Bool = true
  property index_next_sql_message : Int32
  property array_of_messages : Bytes
  property nr_messages_in_array : Int32 = 0
  property from_previous_packet : Bytes

  def initialize(@connection)
    @message = uninitialized Bytes
    @msg_decrypted = uninitialized Bytes
    @header_4_mysql = uninitialized UInt8[4]
    @anBRIDGE = uninitialized (MySql::BRIDGE::BRIDGEPlain | MySql::BRIDGE::BRIDGETls)
    #
    # Will be set to true if we will use tls after the connection phase
    #
    @using_tls = false
    #
    @the_message_as_io = Unmarshaller.new(Slice.new(1, 0x00.to_u8))
    @index_next_sql_message = 0
    @tls_payload_size = 0
    @array_of_messages = Bytes.new(0x00, 0)
    @from_previous_packet = Bytes.new(0x00, 0)
  end

  def use_bridge(anBRIDGE : MySql::BRIDGE::BRIDGEPlain | MySql::BRIDGE::BRIDGETls)
    @anBRIDGE = anBRIDGE
  end

  def read_message
    begin
      yield @the_message_as_io
    ensure
      # NO meaning with packet.discard
    end
  end

  def next(tag)
    if tag == "Connection::read_column_definitions() column_count > 0"
    end
    self.next
    {% if flag?(:trcsql) %}
      puts "<<---#{@message.size}--#{tag}"
    {% end %}
  end

  def next
    # advance to the next message
    # we come here because we must deliver a row in the rowset
    # we must deliver
    if @in_empty == true
      # we might have an incomplete message from previous packet
      # puts "@from_previous_packet.size=#{@from_previous_packet.size}"
      if @from_previous_packet.size > 0
        @array_of_messages = @from_previous_packet + @anBRIDGE.read_message_set
        @from_previous_packet = Bytes.new(0x00, 0)
      else
        @array_of_messages = @anBRIDGE.read_message_set
      end
      {% if flag?(:trcsql) %}
        puts "@array_of_messages=#{@array_of_messages}"
      {% end %}
      @index_next_sql_message = 0
      # puts " @array_of_messages.size=#{@array_of_messages.size}"
    end
    header_4_mysql = @array_of_messages[@index_next_sql_message + 0, 4]
    message_size = header_4_mysql[0].to_i + (header_4_mysql[1].to_i << 8) + (header_4_mysql[2].to_i << 16)
    mess = @array_of_messages[@index_next_sql_message + 4, message_size]
    if mess[0] == 0xFF
      errornumber = mess[1].to_u32! + 256 * mess[2].to_u32!
      errorname = mess[3, 6]
      errortext = mess[9..-1]
      raise "Error(6) #{errornumber} (#{String.new(errorname)}): #{String.new(errortext)}"
    end
    # We have something to deliver
    @the_message_as_io = Unmarshaller.new(mess)
    # Prepare for next message
    @index_next_sql_message += message_size + 4

    remain_in_packet = @array_of_messages.size - @index_next_sql_message
    # puts "remain_in_packet=#{remain_in_packet}"

    if remain_in_packet == 0
      # This was the last message in the message_set OR message_set ends exacktly at end of packet
      @from_previous_packet = Bytes.new(0x00, 0)
      @in_empty = true
    else
      # Do we have compltete hdr_4
      if remain_in_packet >= 4
        # peek if complete
        header_4_mysql = @array_of_messages[@index_next_sql_message + 0, 4]
        message_size = header_4_mysql[0].to_i + (header_4_mysql[1].to_i << 8) + (header_4_mysql[2].to_i << 16)

        if 4 + message_size <= remain_in_packet
          @in_empty = false
        else
          @from_previous_packet = @array_of_messages[@index_next_sql_message..-1]
          @in_empty = true
        end
      else
        # save firsta bytes of hdr_4
        @from_previous_packet = @array_of_messages[@index_next_sql_message..-1]
        @in_empty = true
      end
    end
  end
end
