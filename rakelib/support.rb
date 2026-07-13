# frozen_string_literal: true

# Generic, language-agnostic primitives shared by the rakelib libraries: command
# capture, host detection, and a semantic-version value type. Nothing here knows
# about Crystal or defines any task.

require "rbconfig"
require "yaml"
require "json"
require "digest"
require "rake/clean"

# The build platform as an OS/arch pair. libc/link detection lives with the
# project that consumes it (see Crystal::Project).
Platform = Data.define(:ostype, :arch) do
  def self.detect
    host_os = RbConfig::CONFIG["host_os"]
    ostype =
      case host_os
      when %r{darwin} then "darwin"
      when %r{linux}  then "linux"
      else raise "unsupported host OS: #{host_os.inspect}"
      end
    host_cpu = RbConfig::CONFIG["host_cpu"]
    arch =
      case host_cpu
      when "x86_64", "amd64"  then "amd64"
      when "aarch64", "arm64" then "arm64"
      else raise "unsupported host architecture: #{host_cpu.inspect}"
      end
    new(ostype: ostype, arch: arch)
  end
end

# The build host: its platform (OS type + arch) plus the specific OS
# distribution. Host.detect classifies the current machine and raises when it
# cannot be positively determined, so an unknown host fails loudly.
Host = Data.define(:osname, :platform) do
  def self.detect
    platform = Platform.detect
    new(platform: platform, osname: detect_osname(platform))
  end

  # The specific OS: :macosx, :alpine, or :debian.
  def self.detect_osname(platform)
    return :macosx if platform.ostype == "darwin"
    return :alpine if alpine?
    return :debian if debian?

    raise "cannot determine OS (ostype=#{platform.ostype}, /etc/os-release ID=#{os_release_id.inspect})"
  end

  def self.alpine?
    os_release_id == "alpine"
  end

  def self.debian?
    os_release_id == "debian"
  end

  def self.os_release_id
    return nil unless File.exist?("/etc/os-release")

    contents = File.read("/etc/os-release")
    value = contents[%r{^ID_LIKE=(.*)$}, 1] || contents[%r{^ID=(.*)$}, 1]
    value&.delete('"')
  end
end

# A parsed semantic version. Comparison ignores the prerelease tag (major.minor.
# patch only), matching how release ordering treats X.Y.Z-dev and X.Y.Z.
Version = Data.define(:major, :minor, :patch, :prerelease) do
  def self.parse(text)
    match = %r{\A(\d+)\.(\d+)\.(\d+)(?:-(.+))?\z}.match(text.to_s)
    raise "Invalid version: #{text}" unless match

    new(major: match[1].to_i, minor: match[2].to_i, patch: match[3].to_i, prerelease: match[4])
  end

  def to_s
    base = "#{major}.#{minor}.#{patch}"
    prerelease ? "#{base}-#{prerelease}" : base
  end

  def <=>(other)
    [major, minor, patch] <=> [other.major, other.minor, other.patch]
  end
end

# Run a command with array args (no shell, so no injection) and return its
# stdout, or nil if it fails.
def capture(*args)
  output = IO.popen(args, err: File::NULL, &:read)
  $?.success? ? output : nil
end
