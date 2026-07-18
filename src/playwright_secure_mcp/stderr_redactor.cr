require "log"
require "./redactor"

module PlaywrightSecureMcp
  # Drains an upstream child's stderr through the redactor and re-emits it via
  # Log, so a secret the upstream prints does not reach host logs verbatim.
  #
  # Reads are bounded per read (MAX_LINE). A logical line longer than MAX_LINE
  # is reassembled across reads before its head is emitted: otherwise a secret
  # straddling a read boundary would be split so that neither half matches the
  # redactor. When an over-long line forces a flush, the last
  # `redactor.max_secret_length` characters of the already-redacted text are
  # carried into the next read, so any secret spanning the boundary is matched
  # whole before its head is emitted. Memory stays bounded by MAX_LINE + the
  # overlap.
  class StderrRedactor
    Log = ::Log.for(self)

    MAX_LINE = 8192

    def initialize(@io : IO, @redactor : Redactor, *, @log : ::Log = Log)
    end

    def start : Nil
      spawn do
        carry = ""
        while chunk = @io.gets(MAX_LINE, chomp: false)
          if chunk.ends_with?('\n')
            emit(carry + chunk.chomp)
            carry = ""
          else
            carry = flush_overlong(carry + chunk)
          end
        end
        emit(carry)
      rescue IO::Error
        # Pipe closed on upstream exit; nothing more to read.
      end
    end

    # Redacts a completed logical line and logs it, skipping blank lines. Any
    # already-redacted carry prefix re-redacts to itself (the token never
    # matches a secret), so re-redaction is safe.
    private def emit(line : String) : Nil
      return if line.empty?
      log_redacted(@redactor.redact(line))
    end

    private def log_redacted(text : String) : Nil
      return if text.empty?
      @log.warn { "upstream: #{text}" }
    end

    # Redacts an unterminated over-long buffer, emits all but an overlap tail,
    # and returns that redacted tail to prepend to the next read. Keeping the
    # last max_secret_length chars guarantees a secret straddling the flush
    # boundary is re-joined and matched before its head is emitted. With no
    # cached secrets there is nothing to protect, so the whole buffer flushes.
    private def flush_overlong(buffer : String) : String
      redacted = @redactor.redact(buffer)
      overlap = @redactor.max_secret_length
      if overlap.zero?
        log_redacted(redacted)
        return ""
      end
      return redacted if redacted.size <= overlap
      log_redacted(redacted[0, redacted.size - overlap])
      redacted[redacted.size - overlap, overlap]
    end
  end
end
