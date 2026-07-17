require "log"
require "./secret_cipher"
require "./in_memory_cipher"
require "./secure_enclave_cipher"
require "./tpm_cipher"
require "./keyring_cipher"

module PlaywrightSecureMcp
  # A candidate cipher tier. `build` attempts to initialize the tier and raises
  # if it is unavailable on this host.
  record CipherCandidate,
    name : String,
    hardware : Bool,
    build : Proc(SecretCipher)

  # Chooses the best available cipher tier, warning on each downgrade, and fails
  # closed when hardware-backed protection is required but unavailable.
  class CipherSelector
    Log = ::Log.for(self)

    class Error < Exception
    end

    def initialize(@candidates : Array(CipherCandidate), *, @log : ::Log = Log)
    end

    def select(*, require_hardware : Bool) : SecretCipher
      @candidates.each do |candidate|
        next if require_hardware && !candidate.hardware
        cipher = try_build(candidate)
        next if cipher.nil?
        warn_if_downgraded(candidate)
        return cipher
      end
      raise Error.new("no hardware-backed key protection available") if require_hardware
      raise Error.new("no cipher tier available")
    end

    private def try_build(candidate : CipherCandidate) : SecretCipher?
      candidate.build.call
    rescue error
      @log.warn { "cache key tier #{candidate.name} unavailable: #{error.message}" }
      nil
    end

    private def warn_if_downgraded(candidate : CipherCandidate) : Nil
      return if candidate.hardware
      @log.warn do
        "cache key protection using #{candidate.name}; " \
        "hardware-backed protection unavailable"
      end
    end

    # Platform candidate list, best tier first.
    def self.for_host(*, log : ::Log = Log) : CipherSelector
      candidates = [] of CipherCandidate
      {% if flag?(:darwin) %}
        candidates << CipherCandidate.new(
          name: "Secure Enclave", hardware: true, build: -> { SecureEnclaveCipher.new.as(SecretCipher) })
      {% end %}
      {% if flag?(:linux) %}
        candidates << CipherCandidate.new(
          name: "TPM 2.0", hardware: true, build: -> { TpmCipher.new.as(SecretCipher) })
        candidates << CipherCandidate.new(
          name: "kernel keyring", hardware: false, build: -> { KeyringCipher.new.as(SecretCipher) })
      {% end %}
      candidates << CipherCandidate.new(
        name: "in-memory", hardware: false, build: -> { InMemoryCipher.new.as(SecretCipher) })
      new(candidates, log: log)
    end
  end
end
