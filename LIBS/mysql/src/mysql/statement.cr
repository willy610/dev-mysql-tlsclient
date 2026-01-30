class MySql::Statement < DB::Statement
  @statement_id : Int32

  def initialize(connection, command : String)
    super(connection, command)
    @statement_id = 0
    #
    # Create an iterator for reading messages from server.
    # The messages can be seen as
    # an [] of Messages when using an unecrypted connction
    # or as [] of [] of Messages when using an en encryped connction
    #
    # the 'read_responec_message' is reponsible of reading from server and ev. deblock.
    #
    params = @params = [] of ColumnSpec
    columns = @columns = [] of ColumnSpec

    conn = self.conn

    # http://dev.mysql.com/doc/internals/en/com-stmt-prepare.html#packet-COM_STMT_PREPARE

    m = IO::Memory.new
    a_marshaller = Marshaller.new(m)
    MessageComStamtPrepare.new(a_marshaller, command)
    to_write = m.to_slice
    conn.anBRIDGE.seq_out = 0
    {% if flag?(:trcsql) %}
      puts "MessageComStamtPrepare to_write=\n#{to_write.hexdump}"
    {% end %}

    conn.anBRIDGE.write_message(to_write, "MessageComStamtPrepare")

    # http://dev.mysql.com/doc/internals/en/com-stmt-prepare-response.html
    @connection.responce_reader.next("MySql::Statement initialize()")
    @connection.responce_reader.read_message() do |message|
      # conn.raise_if_err_packet packet
      # ??????
      # message.raise_if_err_packet
      status = message.read_byte!
      if status != 0
        message.error_message_unmarshall
      end
      @statement_id = message.read_int
      num_columns = message.read_fixed_int(2)
      num_params = message.read_fixed_int(2)
      message.read_byte! # reserved_1
      warning_count = message.read_fixed_int(2)
      conn.read_column_definitions(params, num_params, responce_reader: @connection.responce_reader)
      conn.read_column_definitions(columns, num_columns, responce_reader: @connection.responce_reader)
    end
  end

  protected def perform_query(args : Enumerable) : MySql::ResultSet
    perform_exec_or_query(args).as(DB::ResultSet)
  end

  protected def perform_exec(args : Enumerable) : DB::ExecResult
    perform_exec_or_query(args).as(DB::ExecResult)
  end

  private def perform_exec_or_query(args : Enumerable)
    conn = self.conn
    m = IO::Memory.new
    a_marshaller = Marshaller.new(m)
    MessagePerformExecOrQuery.new(a_marshaller, @statement_id, @params, args)
    to_write = m.to_slice
    conn.anBRIDGE.seq_out = 0
    {% if flag?(:trcsql) %}
      puts "MessagePerformExecOrQuery to_write=\n#{to_write.hexdump}"
    {% end %}

    conn.anBRIDGE.write_message(to_write, "MessagePerformExecOrQuery")

    @connection.responce_reader.next("MySql::Statement perform_exec_or_query()")
    @connection.responce_reader.read_message() do |message|
      {% if flag?(:trcsql) %}
        puts message.in_message
      {% end %}

      case header = message.read_byte!
      when 255 # err message
        # conn.handle_err_packet(packet)
        message.error_message_unmarshall
      when 0 # ok message
        affected_rows = message.read_lenenc_int.to_i64
        last_insert_id = message.read_lenenc_int.to_i64
        DB::ExecResult.new affected_rows, last_insert_id
      else
        MySql::ResultSet.new(self, message.read_lenenc_int(header))
      end
    end
  end

  protected def conn
    @connection.as(Connection)
  end
end
