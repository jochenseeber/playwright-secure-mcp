require "./stdio_transport"

module PlaywrightSecureMcp
  class Upstream
    class Error < Exception
    end

    def initialize(@tokens : Array(String))
      @process = nil.as(Process?)
    end

    def start : StdioTransport
      raise Error.new("upstream command is empty") if @tokens.empty?
      process = Process.new(
        @tokens.first,
        @tokens[1..],
        # Scrub verbose-logging vars so the child does not print typed values.
        env: {"DEBUG" => nil, "PWDEBUG" => nil},
        input: Process::Redirect::Pipe,
        output: Process::Redirect::Pipe,
        error: Process::Redirect::Pipe,
      )
      @process = process
      StdioTransport.new(input: process.output, output: process.input)
    end

    # The upstream child's stderr pipe (only after start). Callers MUST drain it
    # or the child blocks once its stderr buffer fills.
    def stderr : IO?
      @process.try(&.error)
    end

    def stop : Nil
      process = @process
      return if process.nil?
      process.terminate unless process.terminated?
    rescue
      # process already gone; nothing to clean up
    end
  end
end
