class MySql::MessagePerformExecOrQueryUnPrep
  def initialize(@a_marshaller : Marshaller, @command : String)
    @a_marshaller.write_byte 0x03u8
    @a_marshaller.write_string @command
  end
end
