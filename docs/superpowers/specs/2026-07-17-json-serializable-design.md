# Adopt JSON::Serializable for owned JSON — design

Date: 2026-07-17

## Goal

Replace hand-written `JSON::Any` parsing and building with Crystal
`JSON::Serializable` structs for the JSON the project **owns**: everything it
deserializes from the `op` CLI and everything it serializes for MCP output.
Keep `JSON::Any` only where the data is genuinely opaque — the messages the
proxy relays without understanding, and the arbitrary structures the redactor
and guard walk.

## Principle: type what we own, keep JSON::Any at the opaque seams

- **Deserialize with typed DTOs**: `op` command output (items, accounts, token
  lookups) and MCP tool-call arguments we consume.
- **Serialize with typed DTOs**: discovery/result payloads and the JSON-RPC
  results the proxy fully constructs.
- **Keep `JSON::Any`** (unchanged): `StdioTransport` (opaque line I/O), `Proxy`
  routing + `augment_initialize`/`augment_tools_list` (they mutate a forwarded
  upstream response), `PageUrl` (reads an opaque upstream result), `Redactor`,
  and `SecretGuard` (walk arbitrary structures).
- **Domain records stay plain** (`Item`/`Field`/`Section`/`ItemKey`): DTOs map
  to/from them; the domain is not coupled to any wire schema.
- **Tool-definition heredocs stay as-is** (static JSON constants).

## Inbound: op wire DTOs (new files)

`JSON::Serializable` structs mirroring `op`'s `--format=json` schema. They hold
the wire shape only; the mapping to domain records applies encryption,
credential-filtering, and hash-keying.

```crystal
struct OpVault      # {"id": "..."}
  include JSON::Serializable
  getter id : String
end

struct OpUrl        # {"href": "...", ...}
  include JSON::Serializable
  getter href : String?
end

struct OpFieldSection
  include JSON::Serializable
  getter id : String?
end

struct OpField      # item field
  include JSON::Serializable
  getter id : String?
  getter label : String?
  getter type : String?
  getter purpose : String?
  getter value : String?
  getter section : OpFieldSection?
end

struct OpSection
  include JSON::Serializable
  getter id : String?
  getter label : String?
end

struct OpItem
  include JSON::Serializable
  getter id : String
  getter title : String?
  getter category : String?
  getter vault : OpVault
  getter urls : Array(OpUrl) = [] of OpUrl
  getter tags : Array(String) = [] of String
  getter fields : Array(OpField) = [] of OpField
  getter sections : Array(OpSection) = [] of OpSection
end

struct OpAccount    # `op account list`
  include JSON::Serializable
  getter email : String?
  getter account_uuid : String
end
```

- All optional/absent-tolerant fields use `String?` or a `= default` array so a
  missing key never raises (matching today's tolerant `try` parsing). Only
  truly always-present keys (`OpItem#id`, `OpVault#id`,
  `OpAccount#account_uuid`) are required.
- **Malformed op output**: parsing (`OpItem.from_json` /
  `Array(OpItem).from_json`) rescues `JSON::ParseException` and
  `JSON::SerializableError` and re-raises the locator's existing `Error` ("op
  returned a malformed item…"), so callers see the same error type as today.
- **Mapping** (in `ItemLocator`, not the DTO): `OpItem` → domain `Item` —
  `ItemKey(vault.id, id)`, `urls` from `urls.compact_map(&.href)`, `fields`
  hash keyed by field id (value encrypted **only** for credential fields:
  `CONCEALED` type or `USERNAME`/`PASSWORD` purpose — unchanged rule),
  `sections` hash keyed by id.
- **Summary vs full**: `list_*` still maps only identity/urls/tags (empty
  fields/sections); `reveal` maps the full item and drops non-`LOGIN`.
- **Concatenated stream**: `op item get -` returns concatenated top-level
  objects for several items (see prior fix). Keep the structural splitter, but
  parse each segment with `OpItem.from_json`; a single top-level array parses
  with `Array(OpItem).from_json`. The splitter yields raw JSON string segments
  now, not `JSON::Any`.

## Arguments: DTOs parsed from the call (new)

```crystal
struct SecretTypeArguments
  include JSON::Serializable
  getter element : String
  getter ref : String
  getter vault : String
  getter item : String
  getter field : String
  getter submit : Bool?
  getter slowly : Bool?
end
```

- Parsed via `SecretTypeArguments.from_json(arguments.to_json)`. A missing
  required field raises `JSON::SerializableError`; `SecretTypeTool` rescues it
  and raises its existing `MissingArgumentError` so the proxy's error handling
  is unchanged.
- `SecretTypeTool#key`/`field_name` read the struct;
  `build_browser_type_arguments` builds the upstream `browser_type` arguments
  from a small serializable struct (`element`, `target`, `text`, optional
  `submit`/`slowly`) rendered to `JSON::Any` for embedding in the injected
  call.
- Finder arguments get small structs (`item`/`vault?`, `tag`/`vault?`); the
  `browser_list_items` no-arg tool needs only an optional `vault`.

## Outbound: MCP payload DTOs (new)

```crystal
struct FieldMeta   # declaration order matches today's output: id,label,type,purpose?,section?
  include JSON::Serializable
  getter id : String
  getter label : String
  getter type : String
  @[JSON::Field(emit_null: false)]
  getter purpose : String?
  @[JSON::Field(emit_null: false)]
  getter section : String?
end

struct SectionMeta
  include JSON::Serializable
  getter id : String
  getter label : String
end

struct ItemIdentity
  include JSON::Serializable
  getter vault : String
  getter item : String
  getter title : String
  getter urls : Array(String)
  getter tags : Array(String)
  getter fields : Array(FieldMeta)
  getter sections : Array(SectionMeta)
end
```

- `ItemResult#build` maps `Array(Item)` → `Array(ItemIdentity)`, serializes
  with `to_json`, and embeds that string as the `text` content of the tool
  result. **No field value is ever included** — `ItemIdentity` has no value
  field.
- The JSON-RPC results the proxy fully constructs — the error result and the
  discovery result body — become `JSON::Serializable` structs, with a
  `JSON::Any` field for the opaque `id`:

```crystal
struct ToolContent
  include JSON::Serializable
  getter type : String = "text"
  getter text : String

  def initialize(@text : String)
  end
end

struct ToolTextResult   # {"content":[{"type":"text","text":...}],"isError":bool}
  include JSON::Serializable
  getter content : Array(ToolContent)
  @[JSON::Field(key: "isError")]
  getter? is_error : Bool

  def initialize(text : String, *, @is_error : Bool)
    @content = [ToolContent.new(text)]
  end
end

struct JsonRpcToolResult
  include JSON::Serializable
  getter jsonrpc : String = "2.0"
  getter id : JSON::Any
  getter result : ToolTextResult

  def initialize(@id : JSON::Any, @result : ToolTextResult)
  end
end
```

- The proxy builds these directly: `error_result(id, text)` →
  `JsonRpcToolResult.new(id, ToolTextResult.new(text, is_error: true))`; the
  discovery body → `ToolTextResult.new(item_result_json, is_error: false)`
  where the text is the serialized `Array(ItemIdentity)`.
- **Redaction gate is preserved**: `send_to_client` still redacts. A struct is
  converted to `JSON::Any` (`JSON.parse(struct.to_json)`) before
  `send_to_client`, so it passes through the same string-leaf redactor as every
  other client-bound message (titles containing a cached email, error text,
  etc. are still masked).
- `augment_initialize` / `augment_tools_list` stay `JSON::Any`: they dup a
  forwarded upstream response and add fields, so they operate on an opaque
  message we do not own.

## Files

- New: `op_item.cr` (OpVault/OpUrl/OpFieldSection/OpField/OpSection/OpItem),
  `op_account.cr` (OpAccount), `secret_type_arguments.cr`, finder arg struct(s)
  (in `item_finders.cr` or a small `finder_arguments.cr`), `item_identity.cr`
  (FieldMeta/SectionMeta/ItemIdentity), and result structs (in a `json_rpc.cr`
  or alongside `item_result.cr`).
- Modify: `item_locator.cr` (DTO parse + mapping), `account_locator.cr`,
  `token_fetcher.cr`, `secret_type_tool.cr`, `item_finders.cr`,
  `item_result.cr`, `proxy.cr` (error/result construction only).
- Each modified/new file requires its own direct dependencies (per the existing
  convention); no reintroduction of the include-all aggregator.

## Behavior invariants (must not change)

- Same MCP wire output: `tools/list` additions, discovery result JSON shape,
  error results, and the redaction/guard behavior are byte-for-byte equivalent
  (verified by the existing specs, which stay green).
- LOGIN-only, current-URL scoping, URL-bound typing, credential-only caching,
  and structural redaction are untouched.
- Absent/optional op keys never raise (DTOs are absent-tolerant).

## Testing

- Unit round-trip specs per DTO: parse representative `op` fixtures into DTOs
  and assert the mapped domain records; serialize `ItemIdentity`/results and
  assert the JSON shape matches today's output.
- `SecretTypeArguments`: missing-required raises → surfaces as
  `MissingArgumentError`.
- All existing specs (`item_locator`, `item_finders`, `item_result`, `proxy`,
  `secret_type_tool`, `account_locator`, `token_fetcher`, `redactor`,
  `secret_guard`) stay green unchanged — the observable behavior is identical.
- `rake spec`, `rake lint`, `rake build` all green.

## Rollout

Crystal compiles the whole program (every spec requires the library), and this
touches the shared item-mapping area plus many consumers, so it lands as
**compile-safe milestones**, each keeping the tree compiling and specs green:

1. Inbound op DTOs + `ItemLocator`/`AccountLocator`/`TokenFetcher` mapping.
2. Argument DTOs (`SecretTypeArguments`, finder args) +
   `SecretTypeTool`/finders.
3. Outbound DTOs (`ItemIdentity`, result structs) + `ItemResult`/`Proxy`
   construction.

Subagent-driven, review per milestone.

## Out of scope

- Typing the MCP JSON-RPC envelope for the pass-through/routing path.
- Converting tool-definition heredocs.
- Any behavior change to redaction, URL binding, or caching.
