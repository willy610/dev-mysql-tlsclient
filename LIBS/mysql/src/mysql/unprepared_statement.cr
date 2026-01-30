class MySql::UnpreparedStatement < DB::Statement
  def initialize(connection, command : String)
    super(connection, command)
  end

  protected def conn
    @connection.as(Connection)
  end

  protected def perform_query(args : Enumerable) : DB::ResultSet
    perform_exec_or_query(args).as(DB::ResultSet)
  end

  protected def perform_exec(args : Enumerable) : DB::ExecResult
    perform_exec_or_query(args).as(DB::ExecResult)
  end

  private def perform_exec_or_query(args : Enumerable)
    raise "exec/query with args is not supported" if args.size > 0

    conn = self.conn
    m = IO::Memory.new
    a_marshaller = Marshaller.new(m)

    MessagePerformExecOrQueryUnPrep.new(a_marshaller, command)
    to_write = m.to_slice
    conn.anBRIDGE.seq_out = 0
    conn.anBRIDGE.write_message(to_write, "MessagePerformExecOrQueryUnPrep")

    @connection.responce_reader.next("MySql::Statement perform_exec_or_query_unprep()")
    @connection.responce_reader.read_message() do |packet|
      case header = packet.read_byte!
      when 255 # err packet
        packet.error_message_unmarshall
        # packet.handle_err_packet
      when 0 # ok packet
        affected_rows = packet.read_lenenc_int.to_i64
        last_insert_id = packet.read_lenenc_int.to_i64
        DB::ExecResult.new affected_rows, last_insert_id
      else
        MySql::TextResultSet.new(self, packet.read_lenenc_int(header))
      end
    end
  end
end
