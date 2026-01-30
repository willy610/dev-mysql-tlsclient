module MySql::RSAOAEP
  def self.go(given_password : String?, pubkey : Bytes, use_auth_data : Bytes) : {Bytes, Bytes}
    #   def self.go(given_password : String?, pubkey : Bytes, use_auth_data : Bytes, given_seed : Bytes) : {Bytes, Bytes}
    # 1. Interpret the public key
    # 2. Salt given_password with use_auth_data from server
    # 3. Encode the message accordning to RSA OAEP and PKCS#1 RFC 2437
    # 4. Use result to produce Compute Modular Exponentiation using primary key
    # 5. Return result

    pub_key : PubKeyMySql = PubKeyMySql.new
    pub_key.from_bytes(pubkey)
    if password = given_password
    else
      password = ""
    end

    # include a terminating zero the C way
    password_as_bytes : Bytes = (password + '\0').to_slice
    plain : Bytes = password_as_bytes.map_with_index { |ch, i| ch ^ use_auth_data[i % use_auth_data.size] }
    the_RSAEncoder : RSAOAEPencode = RSAOAEPencode.new(pub_key, plain, "")
    #
    #  1. Now produce an message of input plain
    #
    # em_encoded_message, seed = the_RSAEncoder.go(given_seed)
    em_encoded_message, seed = the_RSAEncoder.go
    #
    #  2. Convert encoded messsage to a bigint!
    #  3. Compute Modular Exponentiation
    #      modulus_result = my_bigint  ^ PublicKey.exp mod PublicKey.value
    #  4. Convert the (bigint) modulus_result to an array of u16
    #
    my_bigint_as_base : BigInt = the_RSAEncoder.bigint_from_message(pub_key, em_encoded_message)

    modulus_result : BigInt = the_RSAEncoder.modular_pow(my_bigint_as_base,
      pub_key.bigE.to_u32,
      pub_key.bigN)
    k = (pub_key.bitcount_bigN + 7) // 8
    to_send : Bytes = the_RSAEncoder.bigint_to_message(modulus_result, k)

    {to_send, seed}
  end

  class RSAOAEPencode
    getter digmachine_obj : Shared::Sha1
    getter label : String

    def initialize(@pub_key : PubKeyMySql, @message : Bytes, @label : String)
      @digmachine_obj = Shared::Sha1.new
    end

    def go : {Bytes, Bytes}
      k = (@pub_key.bitcount_bigN + 7) // 8
      @digmachine_obj = Shared::Sha1.new
      max_message_length = k - 2 * @digmachine_obj.checksum_size - 2

      @digmachine_obj.bigwrite(p_as_slice: @label.to_slice)
      lHash = @digmachine_obj.bigchecksum # size is 20
      @digmachine_obj = Shared::Sha1.new

      padding_size = k - @message.size - 2 * lHash.size - 2

      ps_padding_bytes = Bytes.new(padding_size)
      ps_padding_bytes.each_with_index { |c, i| ps_padding_bytes[i] = 0x00 }
      #
      # Create the db
      #
      # ----------------
      # const DB = lHash.getBytes() + ps_padding_bytes + '\x01' + message;
      # ----------------

      db_size = lHash.size + ps_padding_bytes.size + 1 + @message.size

      db : Slice(UInt8) = Slice.new(db_size, 0.to_u8)

      lHash.each_with_index { |c, i| db[i] = lHash[i] }

      @digmachine_obj = Shared::Sha1.new

      seed = Bytes.new(@digmachine_obj.checksum_size) # seed is 20

      (0..seed.size - 1).each { |i| seed[i] = Random::Secure.rand(255).to_u8 }

      off_set = lHash.size
      ps_padding_bytes.each_with_index { |c, i| db[off_set + i] = ps_padding_bytes[i] }

      off_set = off_set + ps_padding_bytes.size

      db[off_set] = 0x01
      off_set = off_set + 1
      @message.each_with_index { |c, i| db[off_set + i] = @message[i] }

      from_db_one = db
      from_seed_two = seed

      #   puts "first mgf1XOR------------------------------NYASTE"

      @digmachine_obj = Shared::Sha1.new

      #   puts "from_db_one(1)=\n#{from_db_one.hexdump}"
      #   puts "from_seed_two=\n#{from_seed_two.hexdump}"

      mgf1XOR(from_db_one, @digmachine_obj, from_seed_two)

      #   puts "from_db_one(2)=\n#{from_db_one.hexdump}"
      #   puts "from_seed_two=\n#{from_seed_two.hexdump}"

      # puts "second mgf1XOR------------------------------"

      @digmachine_obj = Shared::Sha1.new

      mgf1XOR(from_seed_two, @digmachine_obj, from_db_one)

      #   puts "from_db_one(3)=\n#{from_db_one.hexdump}"
      #   puts "from_seed_two=\n#{from_seed_two.hexdump}"

      em_encoded_message = Slice.new(1, 0x00.to_u8) + from_seed_two + from_db_one
      {em_encoded_message, seed}
    end

    def mgf1XOR(result, hash_obj, seed) : Nil
      #
      # https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
      # https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
      # https://en.wikipedia.org/wiki/Modular_exponentiation
      # https://en.wikipedia.org/wiki/Mask_generation_function#MGF1
      # https://github.com/rgl/go-pkcs11-rsa-oaep
      #
      counter : Slice(UInt8) = Slice.new(4, 0.to_u8)

      done = 0

      while done < result.size
        hash_obj.bigwrite(p_as_slice: seed)
        hash_obj.bigwrite(p_as_slice: counter)
        was_digest = hash_obj.bigchecksum

        hash_obj = Shared::Sha1.new
        i = 0
        while i < was_digest.size && done < result.size
          result[done] = result[done] ^ was_digest[i]
          done = done + 1
          i = i + 1
        end
        #  increments a four byte, big-endian counter.
        counter[3] = counter[3] + 1
        if counter[3] == 0
          counter[2] = counter[2] + 1
          if counter[2] == 0
            counter[1] = counter[1] + 1
            if counter[1] == 0
              counter[0] = counter[0] + 1
            end
          end
        end
      end
    end

    def bigint_from_message(pub_key, em : Bytes) : BigInt
      big_n = BigInt.new(1) # 256^0
      em_terms = em.map_with_index { |_, i|
        this_val = em[em.size - i - 1]
        ret = this_val * big_n
        big_n = big_n * 256
        ret
      }
      em_bigint = em_terms.sum(BigInt.new(0))
    end

    def modular_pow(base : BigInt, exponent : UInt32, modulus : BigInt) : BigInt
      if modulus == 0
        return BigInt.new(0)
      end
      result = BigInt.new(1)
      base = base.modulo(modulus)
      while exponent > 0
        if exponent % 2 == 1
          result = (result * base).modulo(modulus)
        end
        base = base.modulo(modulus)
        exponent = exponent >> (1)
        base = (base * base).modulo(modulus)
      end
      result
    end

    def bigint_to_message(from_mod_pow : BigInt, k) : Bytes
      k = (@pub_key.bitcount_bigN + 7) // 8
      from_mod_pow_as_hex : String = from_mod_pow.to_s(16, upcase: true)
      u8a : Bytes = Slice.new(k, 0.to_u8)
      zeros = k - (from_mod_pow_as_hex.size // 2)
      prependedLength = zeros
      while zeros > 0
        u8a[prependedLength - zeros] = 0
        zeros = zeros - 1
      end
      i = 0
      if (from_mod_pow_as_hex.size & 1) == 1
        # // odd number of characters, convert first character alone
        i = 1
        u8a[prependedLength] = from_mod_pow_as_hex[0].to_u8(16)
        x = "as"[0].to_i8(16)
      end
      # // convert 2 characters (1 byte) at a time
      while i < from_mod_pow_as_hex.size
        dig_high = from_mod_pow_as_hex[i].to_u8(16)
        dig_low = from_mod_pow_as_hex[i + 1].to_u8(16)
        u8a[(prependedLength + i)//2] = dig_high * 16 + dig_low
        i = i + 2
      end
      u8a
    end
  end
end
