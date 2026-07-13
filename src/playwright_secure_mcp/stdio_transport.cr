require "json"

module PlaywrightSecureMcp
  class StdioTransport
    def initialize(*, @input : IO, @output : IO)
      @write_mutex = Mutex.new
    end

    def read : JSON::Any?
      message = nil.as(JSON::Any?)
      while line = @input.gets
        stripped = line.strip
        next if stripped.empty?
        message = JSON.parse(stripped)
        break
      end
      message
    end

    def write(message : JSON::Any) : Nil
      write_raw(message.to_json)
    end

    def write_raw(line : String) : Nil
      @write_mutex.synchronize do
        @output.print(line)
        @output.print('\n')
        @output.flush
      end
    end
  end
end
