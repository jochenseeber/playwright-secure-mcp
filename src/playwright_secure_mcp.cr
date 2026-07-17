require "./playwright_secure_mcp/application"

module PlaywrightSecureMcp
  def self.run(arguments : Array(String)) : Nil
    Application.new(arguments).run
  end
end
