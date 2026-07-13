module PlaywrightSecureMcp
  # Read the version from shard.yml at compile time (single source of truth).
  VERSION = {{ read_file("#{__DIR__}/../../shard.yml").split("version:")[1].split("\n")[0].strip }}
end
