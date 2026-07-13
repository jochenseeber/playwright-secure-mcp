# frozen_string_literal: true

require_relative "support"

# Generic macOS code-signing helpers (no-op off macOS), usable by any project.
# The identity is taken from the CODESIGN_IDENTITY env var (the one supported
# override, so CI can inject a keychain-imported secret), otherwise resolved by
# convention from a 1Password item tagged codesign/<git user.email>/<release|
# debug> (credential field). Defines no task.

# The configured git user email, used to key the 1Password lookup.
def git_user_email
  email = capture("git", "config", "user.email").to_s.strip
  email.empty? ? nil : email
end

# The 1Password account UUID whose email matches +email+ (op --account matches a
# UUID/shorthand/sign-in address, never an email). Returns nil to fall back to
# op's default account.
def op_account_for(email)
  listed = capture("op", "account", "list", "--format=json")
  return nil if listed.nil? || listed.empty?
  match = JSON.parse(listed).find { |account| account["email"] == email }
  match && match["account_uuid"]
end

# Resolve the codesign identity from the `credential` field of the 1Password
# item tagged codesign/<git user.email>/<release|debug>. Returns nil when the
# item, field, or git user email is unavailable.
def onepassword_codesign_identity(release:)
  email = git_user_email
  return nil if email.nil? || email.empty?

  account = op_account_for(email)
  account_args = account ? ["--account", account] : []
  tag = "codesign/#{email}/#{release ? "release" : "debug"}"

  listed = capture("op", "item", "list", "--tags", tag, "--format=json", *account_args)
  return nil if listed.nil? || listed.empty?
  items = JSON.parse(listed)
  return nil if items.empty?

  fetched = capture("op", "item", "get", items.first["id"], "--fields", "label=credential", "--reveal", "--format=json", *account_args)
  return nil if fetched.nil? || fetched.empty?
  fields = JSON.parse(fetched)
  field = fields.is_a?(Array) ? fields.find { |candidate| candidate["label"] == "credential" || candidate["id"] == "credential" } : fields
  value = field && field["value"]
  value.nil? || value.empty? ? nil : value
end

# Resolve the signing identity: CODESIGN_IDENTITY overrides; only when it is
# unset does the 1Password lookup run. Release builds abort without one (the
# Secure Enclave rejects ad-hoc signatures); debug builds fall back to ad-hoc.
def codesign_identity(release:)
  identity = ENV["CODESIGN_IDENTITY"]
  identity = onepassword_codesign_identity(release: release) if identity.nil? || identity.empty?
  if identity.nil? || identity.empty?
    if release
      abort "release signing needs an Apple Developer identity: set CODESIGN_IDENTITY, " \
            "or add a 1Password item tagged codesign/#{git_user_email || "<git-user-email>"}/release " \
            "with a `credential` field holding the cert SHA-1 (the Secure Enclave rejects ad-hoc signatures)"
    end
    return "-"
  end
  identity
end

# Code-sign a freshly built binary on macOS (no-op elsewhere).
def codesign_binary(path:, release:)
  return unless Platform.detect.ostype == "darwin"

  identity = codesign_identity(release: release)
  warn "WARNING: ad-hoc signing; the Secure Enclave will not engage (falls back to in-memory)" if identity == "-"

  sh("codesign", "--sign", identity, "--force", "--timestamp=none", path)
end
