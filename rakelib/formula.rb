# frozen_string_literal: true

require_relative "support"

# Generic Homebrew formula updater, usable by any project. Sets the formula's
# version and the SHA256 of each release binary; an asset's basename must match
# the filename in a formula `url` line so its checksum lands in the right
# on_os/on_arch block. Defines no task itself; call define_formula_task.

def write_formula(formula_path:, version:, asset_paths:)
  abort "formula not found: #{formula_path}" unless File.exist?(formula_path)

  contents = File.read(formula_path)
  with_version = contents.sub(/^(\s*)version\s+"[^"]*"$/, "\\1version \"#{version}\"")
  abort "could not find version line in #{formula_path}" if with_version == contents
  contents = with_version

  asset_paths.each do |path|
    asset = File.basename(path)
    digest = Digest::SHA256.file(path).hexdigest
    pattern = /(url "[^"]*#{Regexp.escape(asset)}"\s*\n\s*sha256 )"[^"]*"/
    updated = contents.sub(pattern) { "#{Regexp.last_match(1)}\"#{digest}\"" }
    abort "could not find url/sha256 for asset #{asset} in #{formula_path}" if updated == contents
    contents = updated
  end

  File.write(formula_path, contents)
  puts "Updated #{formula_path} to #{version} for #{asset_paths.size} asset(s)"
end

# Create a task named +name+ that updates +formula_path+. Release binaries are
# found under an assets directory (task arg, default +default_assets_dir+),
# matched by "#{binary_prefix}-*" so non-binary files are ignored.
def define_formula_task(name:, formula_path:, binary_prefix:, default_assets_dir: "dist")
  desc "Update the Homebrew formula version/checksums from release binaries " \
       "(args: version[, assets dir; default #{default_assets_dir}])"
  task name, [:version, :assets_dir] do |_task, args|
    version = args[:version]
    abort "usage: rake '#{name}[VERSION]' or rake '#{name}[VERSION,ASSETS_DIR]'" if version.nil? || version.empty?
    dir = args[:assets_dir].to_s.empty? ? default_assets_dir : args[:assets_dir]
    assets = Dir.glob(File.join(dir, "**", "#{binary_prefix}-*")).select { |path| File.file?(path) }
    abort "no release binaries matched '#{binary_prefix}-*' under '#{dir}'" if assets.empty?
    write_formula(formula_path: formula_path, version: version, asset_paths: assets)
  end
end
