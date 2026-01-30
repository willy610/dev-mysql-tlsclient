#
# sudo tcpdump host deciweb.se and 192.168.50.201 -nnvvv -X
# crystal tool hierarchy  src/web1.cr -e TLSClient
#
#
# TODO: Write documentation for `TLSClient`
require "./tlsclient/*"
require "shared"

# https://www.thesslstore.com/blog/explaining-ssl-handshake/#the-tls-13-handshake-step-by-step
module TLSClient
  VERSION = "0.1.0"
end
