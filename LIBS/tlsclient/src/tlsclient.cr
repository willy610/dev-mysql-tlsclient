#
# sudo tcpdump host deciweb.se and 192.168.50.201 -nnvvv -X
# crystal tool hierarchy  src/web1.cr -e TLSClient
#
#
# TODO: Write documentation for `TLSClient`
# RANDOM SALT
# https://ochagavia.nl/blog/implementing-the-mysql-server-protocol-for-fun-and-profit/
# https://github.com/mysql/mysql-server/blob/3290a66c89eb1625a7058e0ef732432b6952b435/mysys/crypt_genhash_impl.cc#L421

#   Generate a random string using ASCII characters but avoid separator character.
#   Stdlib rand and srand are used to produce pseudo random numbers between
#   with about 7 bit worth of entropty between 1-127.
# */
# void generate_user_salt(char *buffer, int buffer_len) {
#   char *end = buffer + buffer_len - 1;
#   RAND_bytes((unsigned char *)buffer, buffer_len);

#   /* Sequence must be a legal UTF8 string */
#   for (; buffer < end; buffer++) {
#     *buffer &= 0x7f;
#     if (*buffer == '\0' || *buffer == '$') *buffer = *buffer + 1;
#   }
#   /* Make sure the buffer is terminated properly */
#   *end = '\0';
# }

require "./tlsclient/*"
require "shared"

# https://www.thesslstore.com/blog/explaining-ssl-handshake/#the-tls-13-handshake-step-by-step
module TLSClient
  VERSION = "0.1.0"
end
