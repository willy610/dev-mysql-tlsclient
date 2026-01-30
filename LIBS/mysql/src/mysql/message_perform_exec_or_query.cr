class MySql::MessagePerformExecOrQuery
  # FUNKAR
  def initialize(@a_marshaller : Marshaller, @statement_id : Int32, @params : Array(MySql::ColumnSpec),args : Enumerable)
    @a_marshaller.write_byte 0x17u8
    @a_marshaller.write_bytes @statement_id.not_nil!, IO::ByteFormat::LittleEndian
    @a_marshaller.write_byte 0x00u8 # flags: CURSOR_TYPE_NO_CURSOR
    @a_marshaller.write_bytes 1i32, IO::ByteFormat::LittleEndian

    params = @params.not_nil!
    if params.size > 0
      null_bitmap = BitArray.new(params.size)
      args.each_with_index do |arg, index|
        next unless arg.nil?
        null_bitmap[index] = true
      end
      null_bitmap_slice = null_bitmap.to_slice
      @a_marshaller.write null_bitmap_slice

      @a_marshaller.write_byte 0x01u8

      # TODO raise if args.size and params.size does not match
      # params types
      args.each do |arg|
        arg = MySql::Type.to_mysql(arg)
        t = MySql::Type.type_for(arg.class)
        @a_marshaller.write_byte t.hex_value
        @a_marshaller.write_byte 0x00u8
      end

      # params values
      args.each do |arg|
        next if arg.nil?
        arg = MySql::Type.to_mysql(arg)
        t = MySql::Type.type_for(arg.class)
        t.write(@a_marshaller, arg)
      end
    end
  end
end
