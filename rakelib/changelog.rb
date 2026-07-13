# frozen_string_literal: true

require_relative "support"

# Generic conventional-commits changelog generator: a Ruby port of the myborg
# TypeScript changelog script (conventional-changelog, conventionalcommits
# preset). Regenerates the section for the current version from the commits
# since the last tag and prepends it under a single "# Changelog" title.
# Idempotent: an existing section for the version is left untouched. Language-
# agnostic and defines no task.

CHANGELOG_TITLE = "# Changelog"

# conventionalcommits preset: the commit types that get a section, in order,
# with their headings. Other types (docs, chore, style, refactor, …) are hidden.
CHANGELOG_SECTIONS = {
  "feat" => "Features",
  "fix" => "Bug Fixes",
  "perf" => "Performance Improvements",
  "revert" => "Reverts"
}.freeze

# A parsed conventional commit: type, optional scope, subject, short hash, and
# whether it declares a breaking change.
CommitEntry = Data.define(:type, :scope, :subject, :hash, :breaking)

# The GitHub "owner/repo" slug from the origin remote, or nil when it is not a
# GitHub remote (links are then omitted).
def changelog_repo_slug
  url = capture("git", "remote", "get-url", "origin").to_s.strip
  return nil if url.empty?

  match = url.match(%r{github\.com[:/]([^/]+/[^/]+?)(?:\.git)?\z})
  match && match[1]
end

# The highest existing tag matching +tag_re+, or nil (defines the commit range
# and the compare link's left side).
def changelog_previous_tag(tag_re:)
  tags = capture("git", "tag", "-l").to_s.split("\n").reject(&:empty?)
  matching = tags.select { |tag| tag_re.match?(tag) }
  matching.max_by do |tag|
    match = tag_re.match(tag)
    Version.new(major: match[1].to_i, minor: match[2].to_i, patch: match[3].to_i, prerelease: nil)
  end
end

# Parse a commit subject/body into a CommitEntry, or nil when the subject is not
# a conventional commit.
def parse_commit(hash:, subject:, body:)
  match = subject.match(%r{\A(\w+)(?:\(([^)]+)\))?(!)?:\s*(.+)\z})
  return nil unless match

  breaking = !match[3].nil? || body.include?("BREAKING CHANGE")
  CommitEntry.new(type: match[1], scope: match[2], subject: match[4].strip, hash: hash, breaking: breaking)
end

# The conventional commits in +range+ (e.g. "v1.1.0..HEAD" or "HEAD"), newest
# first, non-conventional subjects dropped.
def changelog_commits(range:)
  log = capture("git", "log", range, "--no-merges", "--pretty=format:%h%x1f%s%x1f%b%x1e").to_s
  log.split("\x1e").map(&:strip).reject(&:empty?).filter_map do |record|
    short, subject, body = record.split("\x1f")
    parse_commit(hash: short.to_s.strip, subject: subject.to_s.strip, body: body.to_s.strip)
  end
end

# A single "* …" changelog line for a commit (bold scope, linked hash if GitHub).
def changelog_entry_line(entry:, slug:)
  scope = entry.scope ? "**#{entry.scope}:** " : ""
  ref = slug ? "([#{entry.hash}](https://github.com/#{slug}/commit/#{entry.hash}))" : "(#{entry.hash})"
  "* #{scope}#{entry.subject} #{ref}"
end

# The "## <version> (date)" heading, linked to a GitHub compare when possible.
def changelog_header(version:, date:, tag_prefix:, previous_tag:, slug:)
  tag = "#{tag_prefix}#{version}"
  if slug && previous_tag
    "## [#{version}](https://github.com/#{slug}/compare/#{previous_tag}...#{tag}) (#{date})"
  else
    "## #{version} (#{date})"
  end
end

# The full markdown section for +version+: header plus a subsection per commit
# type that has entries (breaking changes first).
def changelog_section(version:, tag_prefix:, tag_re:, date:)
  slug = changelog_repo_slug
  previous_tag = changelog_previous_tag(tag_re: tag_re)
  range = previous_tag ? "#{previous_tag}..HEAD" : "HEAD"
  commits = changelog_commits(range: range)

  parts = [changelog_header(version: version, date: date, tag_prefix: tag_prefix, previous_tag: previous_tag, slug: slug)]

  breaking = commits.select(&:breaking)
  unless breaking.empty?
    parts.push("", "### ⚠ BREAKING CHANGES", "")
    breaking.each { |entry| parts << changelog_entry_line(entry: entry, slug: slug) }
  end

  CHANGELOG_SECTIONS.each do |type, heading|
    entries = commits.select { |commit| commit.type == type }
    next if entries.empty?

    parts.push("", "### #{heading}", "")
    entries.each { |entry| parts << changelog_entry_line(entry: entry, slug: slug) }
  end

  parts.join("\n")
end

# The changelog body with the leading "# Changelog" title (and blank lines)
# removed, so a new section can be prepended above it.
def strip_changelog_title(content)
  lines = content.split("\n")
  index = 0
  if lines[0].to_s.strip == CHANGELOG_TITLE
    index = 1
    index += 1 while index < lines.length && lines[index].to_s.strip.empty?
  end
  lines[index..].to_a.join("\n").strip
end

# Whether +body+ already has a section for +version+ (idempotency guard).
def changelog_has_version?(body:, version:)
  %r{^##\s+\[?#{Regexp.escape(version.to_s)}[\]\s(]}.match?(body)
end

# Prepend the section for +version+ to the changelog at +path+ (created if
# missing), under a single "# Changelog" title. A no-op if the version already
# has a section.
def regenerate_changelog(version:, tag_prefix:, tag_re:, date:, path: "CHANGELOG.md")
  existing = File.exist?(path) ? File.read(path) : ""
  body = strip_changelog_title(existing)
  return if changelog_has_version?(body: body, version: version)

  section = changelog_section(version: version, tag_prefix: tag_prefix, tag_re: tag_re, date: date)
  combined = body.empty? ? section : "#{section}\n\n#{body}"
  File.write(path, "#{CHANGELOG_TITLE}\n\n#{combined.strip}\n")
end
