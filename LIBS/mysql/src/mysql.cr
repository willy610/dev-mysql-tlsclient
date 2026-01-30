require "db"
require "shared"
require "./mysql/*"

module MySql
  record ColumnSpec, catalog : String, schema : String, table : String, org_table : String, name : String, org_name : String, character_set : UInt16, column_length : UInt32, column_type_code : UInt8, flags : UInt16, decimal : UInt8

  struct ColumnSpec
    def column_type
      MySql::Type.types_by_code[column_type_code]
    end
  end

  alias Any = DB::Any | Int16 | Int8 | Time::Span | UUID

  # :nodoc:
  TIME_ZONE = Time::Location::UTC

  def self.to_bytes(arr)
    Bytes.new(arr.size) { |i| arr[i].to_u8 }
  end

  def self.to_array_to_bytes(str)
    tmp = self.to_bytes(str.split(' '))
  end
end
