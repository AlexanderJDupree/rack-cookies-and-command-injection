require 'uri'
require 'openssl'

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
            puts('find-secret: Brute force failed')
        else
            puts('Secret found: ' + secret)
        end
    end
    return 0

end

main
