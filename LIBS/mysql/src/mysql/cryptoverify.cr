module Crypto
  # For verification
  def self.run_server(useprod : Bool,
                      halfconn : Diverse::HalfConnection,
                      plaintext : Bytes) : {Bytes, Bytes, Bytes}
    header_5_tls : Bytes = Bytes.new(5, 0x00)

    encrypted_msg_in_server : Bytes = Bytes.new(0, 0x00)
    tag_in_server : Bytes = Bytes.new(0, 0x00)
    if useprod
      encrypted_msg_in_server, tag_in_server = encrypt(header_5_tls,
        plaintext, halfconn)
      {header_5_tls, encrypted_msg_in_server, tag_in_server}
    else
      key = halfconn.key
      iv = halfconn.iv_mix_in_or_out_seq
      #
      result_encrypt_plain = IO::Memory.new
      for_encrypt = Crypto::AeadChacha20Poly1305.new(key, iv, result_encrypt_plain)
      for_encrypt.on_the_spot(plaintext)
      encrypted_msg_in_server = result_encrypt_plain.to_slice
      #   calc tag
      result_tag_calc = IO::Memory.new
      for_tag_calc = Crypto::AeadChacha20Poly1305.new(key, iv, result_tag_calc)
      tag_in_server = for_tag_calc.calc_tag(key, iv, header_5_tls, encrypted_msg_in_server)
      _ = halfconn.iv_mix_in_or_out_seq
      halfconn.inc_sequence
      {header_5_tls, encrypted_msg_in_server, tag_in_server.to_slice}
    end
  end

  # For verification
  def self.run_client(useprod : Bool,
                      halfconn : Diverse::HalfConnection,
                      hdr_from_wire : Bytes,
                      message_from_wire : Bytes,
                      tag_from_wire : Bytes) : {Bytes, Bytes, Bytes}
    if useprod
      #   encrypted_msg_in_client, tag_in_client = decrypt(header: hdr_from_wire,
      encrypted_msg_in_client = decrypt(header: hdr_from_wire,
        encrypted_message: message_from_wire,
        tag_received: tag_from_wire,
        half_conn: halfconn)
      {hdr_from_wire, tag_from_wire, encrypted_msg_in_client}
    else
      result_tag_calc = IO::Memory.new
      key = halfconn.key
      iv = halfconn.iv
      for_tag_calc = Crypto::AeadChacha20Poly1305.new(key, iv, result_tag_calc)
      tag_calc_in_client = for_tag_calc.calc_tag(key, iv, hdr_from_wire, message_from_wire)
      puts "tag_calc_in_client=#{tag_calc_in_client}"
      puts "tag_from_wire=#{tag_from_wire}"
      if !constant_time_compare(tag_calc_in_client, tag_from_wire)
        puts "tags NOT equal"
      else
        puts "tags ARE equal"
      end
      result_decrypt_plain = IO::Memory.new
      for_decrypt = Crypto::AeadChacha20Poly1305.new(key, iv, result_decrypt_plain)
      for_decrypt.on_the_spot(message_from_wire)
      #   puts "decrypted_messag_in_client=#{result_decrypt_plain}"
      {hdr_from_wire, tag_calc_in_client.to_slice, result_decrypt_plain.to_slice}
    end
  end
end
