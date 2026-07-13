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
        input: Process::Redirect::Pipe,
        output: Process::Redirect::Pipe,
        error: Process::Redirect::Inherit,
      )
      @process = process
      StdioTransport.new(input: process.output, output: process.input)
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
