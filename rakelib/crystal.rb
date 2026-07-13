# frozen_string_literal: true

require_relative "support"
require_relative "codesign"
require_relative "release"
require_relative "formula"

# Crystal-specific project configuration and tasks. Crystal::Project holds all
# the data (project name, components, directories, current-host profiles) and knows how to define
# its tasks: the Crystal build/test tasks directly, and release/formula by
# calling the generic factories. The main Rakefile builds one via
# Crystal::Project.create and calls #define_tasks on it.
module Crystal
  # The shards manifest — the single source of truth for the version.
  SHARD_PATH = "shard.yml"

  # A build target: a shards target name plus the component name (target with the
  # project prefix stripped), which also names its spec/test directories.
  Component = Data.define(:name, :target) do
    def spec_dir = "spec/#{name}"
    def test_dir = "test/#{name}"
  end

  # A build profile: the platform plus the libc/linkage that identify a build
  # variant. Its dir names the bin/ subdirectory (<ostype>-<arch>-<libc>-<linkage>);
  # Project appends the build mode when building.
  Profile = Data.define(:platform, :libc, :linkage) do
    # Parse a profile dir string (<ostype>-<arch>-<libc>-<linkage>) back into a Profile.
    def self.parse(dir)
      ostype, arch, libc, linkage = dir.split("-")
      new(platform: Platform.new(ostype: ostype, arch: arch), libc: libc, linkage: linkage)
    end

    def dir = "#{platform.ostype}-#{platform.arch}-#{libc}-#{linkage}"

    # On macOS, Crystal auto-adds -fuse-ld=mold, which Apple's clang rejects.
    # Supplying our own -fuse-ld= disables that and forces Apple's ld; no-op elsewhere.
    def link_flags
      platform.ostype == "darwin" ? " --link-flags=-fuse-ld=/usr/bin/ld" : ""
    end
  end

  # All Crystal-specific project data, with derived build paths and task
  # definitions. Includes Rake::DSL so its methods (and the task action blocks,
  # which run with the instance as self) can call task/desc/namespace/sh/etc.
  # +profiles+ holds only the build profiles valid on the current host (selected
  # from shard.yml's `profiles:` mapping by Project.create).
  Project = Data.define(
    :name, :components, :bin_dir, :dist_dir, :coverage_dir, :src_dir, :profiles
  ) do
    include Rake::DSL

    # The preferred build profile for the current host, or nil if none apply.
    # Prefers dynamic over static, and musl over glibc.
    def default_profile
      profiles.min_by { |profile| [profile.linkage == "dynamic" ? 0 : 1, profile.libc == "musl" ? 0 : 1] }
    end

    # The profile whose dir string matches +name+; aborts if none does.
    def profile_named(name)
      profiles.find { |profile| profile.dir == name } || abort("unknown profile: #{name.inspect}")
    end

    # The bin/ subdirectory for a build profile in the given mode (mode appended last).
    def bin_dir_for(profile:, mode:)
      File.join(bin_dir, "#{profile.dir}-#{mode}")
    end

    def formula_path = "deploy/homebrew/#{name}.rb"

    # Define all tasks for this project: the aggregates and per-component
    # namespaces directly, and release/formula via the generic factories.
    def define_tasks
      CLEAN.include("#{bin_dir}/*", "#{dist_dir}/*", coverage_dir)
      CLOBBER.include(bin_dir, "lib", ".shards")

      component_names = components.map(&:name)

      desc "Build the application (args: mode [debug|release, default debug], profile string)"
      task "build", [:mode, :profile] do |_task, args|
        components.each { |component| Rake::Task["#{component.name}:build"].invoke(args[:mode], args[:profile]) }
      end

      desc "Run unit tests"
      task "spec" => component_names.map { |component| "#{component}:spec" }

      desc "Run integration tests"
      task "test" => component_names.map { |component| "#{component}:test" }

      desc "Run unit tests with coverage"
      task "cover" => component_names.map { |component| "#{component}:cover" }

      desc "Run Ameba linter"
      task "lint", [:no_color] do |_task, args|
        cmd = "lib/ameba/bin/ameba"
        cmd += " --no-color" if args[:no_color]
        sh cmd
      end

      desc "Install Crystal dependencies"
      task "deps" do
        sh "shards install"
      end

      desc "Set up the project (install dependencies)"
      task "setup" => "deps"

      desc "List the build profiles supported on this host"
      task "profiles" do
        profiles.each { |profile| puts profile.dir }
      end

      components.each { |component| define_component_tasks(component: component) }

      # Release: version lives in shard.yml (the single source of truth).
      define_release_task(
        name: "release",
        read_version: -> { File.read(SHARD_PATH)[%r{^version:\s*(\S+)}, 1] },
        write_version: lambda do |version|
          raw = File.read(SHARD_PATH)
          abort "Could not find version field in #{SHARD_PATH}" unless raw.match?(%r{^version:.*$})
          File.write(SHARD_PATH, raw.sub(%r{^version:.*$}, "version: #{version}"))
        end,
        version_files: [SHARD_PATH]
      )

      # Homebrew formula update from release binaries.
      define_formula_task(
        name: "update_formula",
        formula_path: formula_path,
        binary_prefix: name
      )
    end

    # Define the per-component namespace (build/spec/test/cover/run).
    def define_component_tasks(component:)
      target = component.target

      namespace component.name do
        desc "Build #{target} (args: mode [debug|release, default debug], profile string; default: preferred)"
        task "build", [:mode, :profile] do |_task, args|
          mode = args[:mode] || "debug"
          abort "unknown mode: #{mode.inspect} (expected debug or release)" unless %w[debug release].include?(mode)
          profile = args[:profile] ? profile_named(args[:profile]) : default_profile
          abort "no build profile configured for this host in #{SHARD_PATH}" unless profile
          # Fail fast on a missing Developer ID before a slow release build.
          codesign_identity(release: true) if mode == "release" && profile.platform.ostype == "darwin"
          bin = bin_dir_for(profile: profile, mode: mode)
          mkdir_p bin
          cmd = "shards build #{target} --output=#{bin}/#{target} --#{mode}"
          cmd += " --static" if profile.linkage == "static"
          cmd += profile.link_flags
          sh cmd
          codesign_binary(path: "#{bin}/#{target}", release: mode == "release")
          ln_sf File.join(File.basename(bin), target), File.join(bin_dir, target)
        end

        desc "Run unit tests for #{target}"
        task "spec" do
          sh "crystal spec #{component.spec_dir}#{default_profile.link_flags}"
        end

        desc "Run integration tests for #{target} (optional argument: test pattern)"
        task "test", [:pattern] do |_, args|
          cmd = "bundle exec rspec --format documentation --require=./test/spec_helper.rb"
          cmd += " --example '#{args[:pattern]}'" if args[:pattern]
          cmd += " #{component.test_dir}"
          sh cmd
        end

        desc "Run unit tests with coverage for #{target}"
        task "cover" do
          bin = bin_dir_for(profile: default_profile, mode: "debug")
          mkdir_p bin
          mkdir_p ".work"

          runner = ".work/run_#{component.name}_specs.cr"
          File.write(runner, %(require "../#{component.spec_dir}/**"\n))

          spec_binary = File.join(bin, "#{target}-specs")
          sh "crystal build #{runner} --output #{spec_binary} --debug#{default_profile.link_flags}"

          coverage_output = File.join(coverage_dir, component.name)
          mkdir_p coverage_output
          sh "kcov --clean --include-path=./#{src_dir} #{coverage_output} #{spec_binary}"
        end

        desc "Run the application in debug mode"
        task "run" do
          bin = bin_dir_for(profile: default_profile, mode: "debug")
          sh "shards run #{target} --output=#{bin}/#{target} --debug#{default_profile.link_flags}"
        end
      end
    end

    # Build a Project by inspecting shard.yml and detecting the host.
    def self.create
      shard = YAML.load_file(SHARD_PATH)
      name = shard.fetch("name")
      components = shard.fetch("targets").map do |target, _|
        Component.new(name: target.delete_prefix("#{name}-"), target: target)
      end

      host = ::Host.detect

      # Only the profiles valid on the current host, from shard.yml's `profiles:` mapping.
      profiles = shard.fetch("profiles").fetch(host.osname.to_s, []).map do |p|
        Profile.parse(p)
      end.filter do |p|
        p.platform == host.platform
      end

      new(
        name: name,
        components: components,
        bin_dir: "bin",
        dist_dir: "dist",
        coverage_dir: "coverage",
        src_dir: "src",
        profiles: profiles
      )
    end
  end
end
