module PlaywrightSecureMcp
  # Resolves the 1Password account to use from the CLI options. Precedence
  # (highest to lowest): --account-from-git > --account-email > --account.
  class AccountResolver
    class Error < Exception
    end

    def resolve(*, account : String?, account_email : String?, account_from_git : String?) : String?
      return git_email(account_from_git) if account_from_git

      account_email || account
    end

    private def git_email(directory : String) : String
      path = File.join(directory, ".git", "config")
      raise Error.new("git config not found: #{path}") unless File.exists?(path)

      section = ""
      File.each_line(path) do |line|
        stripped = line.strip
        if stripped.starts_with?('[') && stripped.ends_with?(']')
          section = stripped[1..-2].strip.downcase
          next
        end
        next unless section == "user"
        match = stripped.match(/\A(?i:email)\s*=\s*(.*)\z/)
        next unless match
        return match[1].strip.strip('"')
      end

      raise Error.new("no user.email in #{path}")
    end
  end
end
