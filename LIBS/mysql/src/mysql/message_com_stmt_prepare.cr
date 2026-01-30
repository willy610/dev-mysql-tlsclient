class MySql::MessageComStamtPrepare
  def initialize(@a_marshaller : Marshaller, @command : String)
    @a_marshaller.write_byte 0x16u8
    @a_marshaller.write_string(@command)
  end
end
