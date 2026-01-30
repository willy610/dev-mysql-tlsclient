# class Crypto::AeadChacha20Poly1305
#   def on_the_spot(plaintext)
#     @io.write(@cipher.encrypt(plaintext))
#   end

#   def calc_tag(key : Bytes, nonce : Bytes, ad : Bytes, encrypted_message : Bytes) : Bytes
#     aad(ad)
#     write(encrypted_message)
#     @plaintext_size += encrypted_message.size
#     calculated_tag = final
#     calculated_tag
#   end
# end