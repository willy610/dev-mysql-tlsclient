module Xcrypt
  def self.decrypt(header : Bytes, encrypted_message : Bytes, tag_received : Bytes, half_conn : HalfConnection)
    # puts "\ndecrypt called\n"
    # WORKS DON'T TUCH
    result_tag_calc = IO::Memory.new
    key = half_conn.key
    iv_x = half_conn.iv_mix_in_or_out_seq
    # Calculate the tag for 'encrypted_message'
    for_tag_calc = Crypto::AeadChacha20Poly1305.new(key, iv_x, result_tag_calc)
    tag_calc = for_tag_calc.calc_tag(key, iv_x, header, encrypted_message)
    # Compare calculated tag with provide from recived on wire
    if !constant_time_compare(tag_calc.to_slice, tag_received.to_slice)
      # puts "encrypted_message=#{encrypted_message + tag_received}"
      puts "encrypted_message=\n#{(encrypted_message + tag_received).hexdump}"
      puts "tag_calc=          #{tag_calc}"
      puts "tag_received=      #{tag_received}"
      raise "decrypt() received tag and computed tag are not the same"
    end
    # Now decrypt 'encrypted_message' to plain text
    result_decrypt_plain = IO::Memory.new
    for_decrypt = Crypto::AeadChacha20Poly1305.new(key, iv_x, result_decrypt_plain)
    for_decrypt.on_the_spot(encrypted_message)
    encrypted = result_decrypt_plain.to_slice
    _ = half_conn.iv_mix_in_or_out_seq
    half_conn.inc_sequence
    encrypted
  end

  def self.encrypt(header : Bytes, message : Bytes, half_conn : HalfConnection)
    # First recrypt the messsage
    # Then calculate tag
    #
    # recrypt

    key = half_conn.key
    iv_x = half_conn.iv_mix_in_or_out_seq
    #
    result_encrypt_plain = IO::Memory.new
    for_encrypt = Crypto::AeadChacha20Poly1305.new(key, iv_x, result_encrypt_plain)
    for_encrypt.on_the_spot(message)
    encrypted = result_encrypt_plain.to_slice


    # calc tag
    #
    result_tag_calc = IO::Memory.new
    for_tag_calc = Crypto::AeadChacha20Poly1305.new(key, iv_x, result_tag_calc)
    tag_calc = for_tag_calc.calc_tag(key, iv_x, header, encrypted)

    _ = half_conn.iv_mix_in_or_out_seq
    half_conn.inc_sequence

    {encrypted, tag_calc}
  end

  def self.constant_time_compare(left : Bytes, right : Bytes) : Bool
    if left.size != right.size
      return false
    end
    v : UInt8 = 0x00
    (0..left.size - 1).each { |i|
      v |= left[i] ^ right[i]
    }
    return v == 0
  end
end
