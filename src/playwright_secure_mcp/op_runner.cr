module PlaywrightSecureMcp
  # Runs a subprocess with a hard wall-clock timeout, so a hung `op` — e.g. a
  # locked 1Password vault blocking on an interactive unlock that never comes —
  # cannot stall the proxy forever. On timeout the process is force-killed and
  # a TimeoutError is raised (never a silent nil). Otherwise it behaves like
  # Process.run, returning the exit status; callers still check success?.
  module OpRunner
    class TimeoutError < Exception
    end

    DEFAULT_TIMEOUT = 60.seconds

    def self.run(
      command : String,
      args : Array(String),
      *,
      env : Process::Env = nil,
      input : Process::Stdio = Process::Redirect::Close,
      output : Process::Stdio = Process::Redirect::Close,
      timeout : Time::Span = DEFAULT_TIMEOUT,
    ) : Process::Status
      process = Process.new(
        command, args,
        env: env, input: input, output: output, error: Process::Redirect::Close,
      )
      completed = Channel(Process::Status).new(1)
      spawn { completed.send(process.wait) }

      select
      when status = completed.receive
        status
      when timeout(timeout)
        process.terminate(graceful: false)
        raise TimeoutError.new(
          "`#{command} #{args.first?}` did not complete within #{timeout.total_seconds.to_i}s")
      end
    end
  end
end
