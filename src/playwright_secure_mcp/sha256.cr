{% if flag?(:darwin) %}
  module PlaywrightSecureMcp
    # SHA-256 hex digests via Apple's CommonCrypto (part of libSystem), so the
    # macOS build has no libcrypto dependency. Produces the same hex output as
    # `Digest::SHA256.hexdigest`.
    module Sha256
      DIGEST_SIZE = 32 # CC_SHA256_DIGEST_LENGTH

      # CommonCrypto lives in libSystem, so no @[Link] annotation is needed.
      lib LibCommonCrypto
        fun CC_SHA256(data : UInt8*, len : UInt32, md : UInt8*) : UInt8*
      end

      def self.hexdigest(input : String) : String
        digest = Bytes.new(DIGEST_SIZE)
        LibCommonCrypto.CC_SHA256(input.to_unsafe, UInt32.new(input.bytesize), digest.to_unsafe)
        digest.hexstring
      end
    end
  end
{% else %}
  require "digest/sha256"

  module PlaywrightSecureMcp
    # SHA-256 hex digests via Crystal's libcrypto-backed Digest on Linux.
    module Sha256
      def self.hexdigest(input : String) : String
        Digest::SHA256.hexdigest(input)
      end
    end
  end
{% end %}
