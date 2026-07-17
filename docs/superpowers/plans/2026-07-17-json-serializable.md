# JSON::Serializable adoption — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hand-written `JSON::Any` parsing/building with
`JSON::Serializable` DTOs for the JSON the project owns (op output in, MCP
payloads out), keeping `JSON::Any` only at the opaque pass-through seams.

**Architecture:** Typed wire DTOs mirror op's `--format=json` schema and the
MCP payloads we emit; plain domain records (`Item`/`Field`/`Section`) stay the
internal model, with mapping functions between DTO and domain that carry the
existing encryption / credential-filtering / hash-keying. Behavior and wire
output are byte-for-byte unchanged.

**Tech Stack:** Crystal ≥ 1.20, `JSON::Serializable`, Spectator specs, the `op`
CLI (faked in specs).

## Global Constraints

- Crystal `>= 1.20`; object-oriented style; edit with Write/Edit (never Serena
  symbol editing — corrupts Crystal).
- **Behavior/wire output must not change**: `tools/list` additions, discovery
  result JSON (key order: item `vault,item,title,urls,tags,fields,sections`;
  field `id,label,type,purpose?,section?`), error results, redaction, guard,
  LOGIN-only, URL binding, credential-only caching — all identical. The
  existing specs are the guard; they must stay green unmodified except where a
  test asserts an internal type that changed.
- DTOs are absent-tolerant: optional fields `String?`, arrays `= [] of T`; only
  always-present keys required. Parsing rescues `JSON::ParseException` /
  `JSON::SerializableError` into the caller's existing `Error`.
- Each new/modified file requires its own direct dependencies; no include-all.
- `op` invoked only via `OpRunner.run`; no secret on a command line.
- Run `rake spec`, `rake lint`, `rake build` before each commit; all green.
- Commits: Conventional Commits, `refactor:` (no behavior change), body as an
  unordered bullet list ≤72 cols, NO AI/Claude/Copilot references. Commit per
  milestone (compile-safe unit); do not commit a red/non-compiling tree.
- Crystal linker on this host needs `--link-flags=-fuse-ld=/usr/bin/ld` for
  ad-hoc `crystal run`/`crystal spec` (rake handles it).

## Milestones (compile-safe; each keeps the tree green)

- **M1** — inbound op DTOs + `ItemLocator`/`AccountLocator`/`TokenFetcher`.
- **M2** — argument DTOs + `SecretTypeTool`/finders (internal only).
- **M3** — outbound DTOs + `ItemResult`/`Proxy` result construction.

Public method signatures stay stable within M1 and M2 (so consumers compile
unchanged); M3 changes `ItemResult#build`'s return type and updates `Proxy`
together in the same milestone.

---

## Milestone 1 — inbound op DTOs

### Task 1.1: op item DTOs

**Files:**

- Create: `src/playwright_secure_mcp/op_item.cr`
- Test: `spec/op_item_spec.cr`

**Interfaces produced:** `OpVault`, `OpUrl`, `OpFieldSection`, `OpField`,
`OpSection`, `OpItem` (all `JSON::Serializable` structs).

- [ ] **Step 1: Write the failing test**

```crystal
# spec/op_item_spec.cr
require "./spec_helper"
require "../src/playwright_secure_mcp/op_item"

Spectator.describe PlaywrightSecureMcp::OpItem do
  it "parses a full revealed item" do
    json = %({"id":"i1","title":"Example","category":"LOGIN","vault":{"id":"v1"},
      "urls":[{"href":"https://example.com/login"}],"tags":["work"],
      "sections":[{"id":"sec1","label":"More"}],
      "fields":[{"id":"password","type":"CONCEALED","purpose":"PASSWORD","label":"password","value":"pw","section":{"id":"sec1"}}]})
    item = PlaywrightSecureMcp::OpItem.from_json(json)
    expect(item.id).to eq("i1")
    expect(item.vault.id).to eq("v1")
    expect(item.category).to eq("LOGIN")
    expect(item.urls.first.href).to eq("https://example.com/login")
    expect(item.fields.first.value).to eq("pw")
    expect(item.fields.first.section.try(&.id)).to eq("sec1")
  end

  it "tolerates a summary item with no fields/urls" do
    item = PlaywrightSecureMcp::OpItem.from_json(%({"id":"i2","vault":{"id":"v1"}}))
    expect(item.urls.empty?).to be_true
    expect(item.fields.empty?).to be_true
    expect(item.title).to be_nil
  end

  it "parses a concatenated stream and an array uniformly is out of scope here" do
    # array form
    items = Array(PlaywrightSecureMcp::OpItem).from_json(%([{"id":"a","vault":{"id":"v"}},{"id":"b","vault":{"id":"v"}}]))
    expect(items.map(&.id)).to eq(["a", "b"])
  end
end
```

- [ ] **Step 2: Run to verify it fails**

Run: `crystal spec spec/op_item_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: FAIL (`OpItem` undefined).

- [ ] **Step 3: Create `src/playwright_secure_mcp/op_item.cr`**

```crystal
require "json"

module PlaywrightSecureMcp
  # DTOs mirroring `op ... --format=json` item output. Wire shape only; mapping
  # to the domain `Item` (encryption, credential-filtering, hash-keying) lives
  # in ItemLocator.
  struct OpVault
    include JSON::Serializable
    getter id : String
  end

  struct OpUrl
    include JSON::Serializable
    getter href : String?
  end

  struct OpFieldSection
    include JSON::Serializable
    getter id : String?
  end

  struct OpField
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
end
```

- [ ] **Step 4: Run to verify it passes**

Run: `crystal spec spec/op_item_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS.

- [ ] **Step 5: Commit** — fold into the M1 commit (do not commit yet; M1 is
      one compile-safe unit). Proceed to Task 1.2.

### Task 1.2: op account DTO

**Files:** Create `src/playwright_secure_mcp/op_account.cr`; test in
`spec/op_account_spec.cr`.

- [ ] **Step 1: Failing test**

```crystal
# spec/op_account_spec.cr
require "./spec_helper"
require "../src/playwright_secure_mcp/op_account"

Spectator.describe PlaywrightSecureMcp::OpAccount do
  it "parses account list entries, tolerating extra keys" do
    accounts = Array(PlaywrightSecureMcp::OpAccount).from_json(
      %([{"email":"a@b.com","account_uuid":"U1","url":"x.1password.com"}]))
    expect(accounts.first.email).to eq("a@b.com")
    expect(accounts.first.account_uuid).to eq("U1")
  end
end
```

- [ ] **Step 2: Run — FAIL (undefined).**
- [ ] **Step 3: Create the file**

```crystal
require "json"

module PlaywrightSecureMcp
  struct OpAccount
    include JSON::Serializable
    getter email : String?
    getter account_uuid : String
  end
end
```

- [ ] **Step 4: Run — PASS.**
- [ ] **Step 5: Fold into M1 commit.**

### Task 1.3: ItemLocator uses OpItem DTOs

**Files:**

- Modify: `src/playwright_secure_mcp/item_locator.cr`
- Test: `spec/item_locator_spec.cr` stays green unchanged.

**Interfaces:** public `list_logins`/`list_by_tag`/`reveal` signatures
unchanged (`Array(Item)`). Internally replace
`parse`/`summary_from`/`full_from`/
`fields_of`/`sections_of`/`key_of`/`urls_of`/`tags_of` with OpItem parsing +
mapping. Keep `run`, `cache_value`, and the
`CONCEALED_TYPE`/`CREDENTIAL_PURPOSES` constants and `split_json_values` (now
yielding String segments).

- [ ] **Step 1: Confirm the guard test exists and passes today**

Run: `crystal spec spec/item_locator_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS (baseline). These assertions (`list_logins` ids/urls/tags/empty
fields; `reveal` fields.size/value encrypted/credential-only/sections) must
still pass after the refactor.

- [ ] **Step 2: Rewrite the parsing internals**

Replace `require`s to add `./op_item`. Replace the parse/mapping section:

```crystal
    def list_logins(vault : String?) : Array(Item)
      output = run(["item", "list", "--categories", "Login", "--format=json"], vault: vault)
      op_items(output).map { |op| summary(op) }
    end

    def list_by_tag(tag : String, vault : String?) : Array(Item)
      output = run(["item", "list", "--categories", "Login", "--tags", tag, "--format=json"], vault: vault)
      op_items(output).map { |op| summary(op) }
    end

    def reveal(keys : Array(ItemKey)) : Array(Item)
      return [] of Item if keys.empty?
      specifiers = keys.map { |k| {"id" => k.item_id, "vault" => {"id" => k.vault_id}} }.to_json
      output = run(["item", "get", "-", "--reveal", "--format=json"], vault: nil, input: specifiers)
      op_items(output).select { |op| op.category == LOGIN_CATEGORY }.map { |op| full(op) }
    end

    # Parse op's output: a single JSON array, or a stream of concatenated
    # top-level objects (op item get - for several items). Splits into raw JSON
    # segments and parses each with the DTO.
    private def op_items(output : String) : Array(OpItem)
      trimmed = output.strip
      return [] of OpItem if trimmed.empty?
      if trimmed.starts_with?('[')
        Array(OpItem).from_json(trimmed)
      else
        split_json_segments(trimmed).map { |segment| OpItem.from_json(segment) }
      end
    rescue error : JSON::ParseException | JSON::SerializableError
      raise Error.new("op returned malformed item JSON: #{error.message}")
    end

    private def summary(op : OpItem) : Item
      Item.new(
        key: ItemKey.new(vault_id: op.vault.id, item_id: op.id),
        title: op.title || "",
        urls: op.urls.compact_map(&.href),
        tags: op.tags,
        fields: {} of String => Field,
        sections: {} of String => Section)
    end

    private def full(op : OpItem) : Item
      sections = {} of String => Section
      op.sections.each do |section|
        id = section.id
        next if id.nil?
        sections[id] = Section.new(id: id, label: section.label || "")
      end

      fields = {} of String => Field
      op.fields.each do |field|
        id = field.id
        next if id.nil?
        type = field.type || ""
        purpose = field.purpose
        fields[id] = Field.new(
          id: id,
          section_id: field.section.try(&.id),
          type: type,
          purpose: purpose,
          label: field.label || "",
          value: cache_value(type: type, purpose: purpose, value: field.value))
      end

      Item.new(
        key: ItemKey.new(vault_id: op.vault.id, item_id: op.id),
        title: op.title || "",
        urls: op.urls.compact_map(&.href),
        tags: op.tags,
        fields: fields,
        sections: sections)
    end
```

Rename `split_json_values` → `split_json_segments`, returning `Array(String)`
(the substring per top-level value) instead of parsing each to `JSON::Any`:

```crystal
private def split_json_segments(output : String) : Array(String)
  segments = [] of String
  depth = 0
  in_string = false
  escape = false
  start = -1
  output.each_char_with_index do |char, index|
    if start < 0
      next if char.whitespace?
      start = index
    end
    if in_string
      in_string, escape = scan_string_char(char, escape)
    else
      case char
      when '"'      then in_string = true
      when '{', '[' then depth += 1
      when '}', ']'
        depth -= 1
        if depth == 0
          segments << output[start..index]
          start = -1
        end
      end
    end
  end
  segments
end
```

Delete the now-unused `parse`, `parse_full`, `summaries`, `summary_from`,
`full_from`, `fields_of`, `sections_of`, `key_of`, `urls_of`, `tags_of`. Keep
`scan_string_char`, `cache_value`, `run`, and the constants.

- [ ] **Step 3: Run the guard test — PASS**

Run: `crystal spec spec/item_locator_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
Expected: PASS (unchanged assertions), confirming identical behavior.

- [ ] **Step 4: Fold into M1 commit.**

### Task 1.4: AccountLocator + TokenFetcher use DTOs

**Files:** Modify `account_locator.cr`, `token_fetcher.cr`; their specs stay
green unchanged.

- [ ] **Step 1: Baseline** — run
      `crystal spec spec/account_locator_spec.cr spec/token_fetcher_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
      (PASS).

- [ ] **Step 2: AccountLocator** — `require "./op_account"`; replace the
      JSON::Any find:

```crystal
    def locate(account : String?) : String?
      return account unless account
      return account unless account.includes?('@')

      accounts = Array(OpAccount).from_json(run)
      match = accounts.find { |candidate| candidate.email == account }
      raise Error.new("no 1Password account for email #{account}") unless match

      match.account_uuid
    rescue error : JSON::ParseException | JSON::SerializableError
      raise Error.new("op account list returned malformed JSON: #{error.message}")
    end
```

- [ ] **Step 3: TokenFetcher** — `require "./op_item"`; parse the item-list id
      and the credential field via DTOs:

```crystal
    private def item_id(tag : String) : String
      items = Array(OpItem).from_json(run(["item", "list", "--tags", tag, "--format=json"]))
      raise Error.new("no 1Password item tagged #{tag}") if items.empty?
      items[0].id
    rescue error : JSON::ParseException | JSON::SerializableError
      raise Error.new("op item list returned malformed JSON: #{error.message}")
    end

    private def credential(id : String) : String
      fields = Array(OpField).from_json(run(["item", "get", id, "--fields", "label=credential", "--reveal", "--format=json"]))
      field = fields.find { |candidate| candidate.label == "credential" || candidate.id == "credential" }
      raise Error.new("no credential field on 1Password item #{id}") unless field
      value = field.value
      raise Error.new("credential field on 1Password item #{id} has no value") if value.nil?
      value
    rescue error : JSON::ParseException | JSON::SerializableError
      raise Error.new("op item get returned malformed JSON: #{error.message}")
    end
```

(`op item list` returns full item objects; `OpItem` parses them and we read
only `id`. `op item get --fields` returns an array of field objects; `OpField`
parses them.)

- [ ] **Step 4: Run those specs — PASS.**

- [ ] **Step 5: Milestone gate + commit**

Run: `rake spec && rake lint && rake build` Expected: all green.

```bash
git add src/playwright_secure_mcp/op_item.cr src/playwright_secure_mcp/op_account.cr \
        src/playwright_secure_mcp/item_locator.cr src/playwright_secure_mcp/account_locator.cr \
        src/playwright_secure_mcp/token_fetcher.cr spec/op_item_spec.cr spec/op_account_spec.cr
git commit -m "refactor: parse op output with JSON::Serializable DTOs"  # bullet body per constraints
```

---

## Milestone 2 — argument DTOs

### Task 2.1: SecretTypeArguments + SecretTypeTool

**Files:** Create `src/playwright_secure_mcp/secret_type_arguments.cr`; modify
`secret_type_tool.cr`; `spec/secret_type_tool_spec.cr` stays green.

**Interface stability:** keep `SecretTypeTool#key(JSON::Any) : ItemKey`,
`#field_name(JSON::Any) : String`,
`#build_browser_type_arguments(*, arguments,
secret) : JSON::Any`, and
`MissingArgumentError` — proxy unchanged.

- [ ] **Step 1: Failing test** for the DTO:

```crystal
# spec/secret_type_arguments_spec.cr
require "./spec_helper"
require "../src/playwright_secure_mcp/secret_type_arguments"

Spectator.describe PlaywrightSecureMcp::SecretTypeArguments do
  it "parses required and optional fields" do
    args = PlaywrightSecureMcp::SecretTypeArguments.from_json(
      %({"element":"E","ref":"e1","vault":"v","item":"i","field":"password","submit":true}))
    expect(args.item).to eq("i")
    expect(args.submit).to be_true
    expect(args.slowly).to be_nil
  end

  it "raises on a missing required field" do
    expect { PlaywrightSecureMcp::SecretTypeArguments.from_json(%({"element":"E"})) }
      .to raise_error(JSON::SerializableError)
  end
end
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Create the DTO**

```crystal
require "json"

module PlaywrightSecureMcp
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
end
```

- [ ] **Step 4: Rewrite `secret_type_tool.cr`** to parse once and read the
      struct. Add `require "./secret_type_arguments"` and `require "./item"`.
      Replace `key`/`field_name`/`build_browser_type_arguments` internals:

```crystal
    def key(arguments : JSON::Any) : ItemKey
      parsed = parse(arguments)
      ItemKey.new(vault_id: parsed.vault, item_id: parsed.item)
    end

    def field_name(arguments : JSON::Any) : String
      parse(arguments).field
    end

    def build_browser_type_arguments(*, arguments : JSON::Any, secret : String) : JSON::Any
      parsed = parse(arguments)
      built = {
        "element" => JSON::Any.new(parsed.element),
        "target"  => JSON::Any.new(parsed.ref),
        "text"    => JSON::Any.new(secret),
      } of String => JSON::Any
      submit = parsed.submit
      built["submit"] = JSON::Any.new(submit) unless submit.nil?
      slowly = parsed.slowly
      built["slowly"] = JSON::Any.new(slowly) unless slowly.nil?
      JSON::Any.new(built)
    end

    private def parse(arguments : JSON::Any) : SecretTypeArguments
      SecretTypeArguments.from_json(arguments.to_json)
    rescue error : JSON::ParseException | JSON::SerializableError
      raise MissingArgumentError.new("invalid browser_type_secret arguments: #{error.message}")
    end
```

Delete `required_string`/`fetch_string`/`copy_optional`. Keep
`DEFINITION_JSON`, `NAME`, `UPSTREAM_TOOL`, `definition`.

- [ ] **Step 5: Run**
      `crystal spec spec/secret_type_arguments_spec.cr spec/secret_type_tool_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
      — PASS.

Note: the existing `secret_type_tool_spec` builds arguments as JSON and expects
`MissingArgumentError` on a missing field — still satisfied (parse rescues into
it). If a test asserted the _specific_ message, update it to match.

### Task 2.2: finder argument structs

**Files:** modify `item_finders.cr` (add small arg parsing);
`spec/item_finders_spec.cr` stays green.

- [ ] **Step 1:** Replace `required_string`/`optional_string` usage in
      `NameItemsFinder`/`TagItemsFinder`/`ListItemsFinder#find` with typed
      parsing. Define private structs at top of the file:

```crystal
  private struct NameArgs
    include JSON::Serializable
    getter item : String
    getter vault : String?
  end

  private struct TagArgs
    include JSON::Serializable
    getter tag : String
    getter vault : String?
  end

  private struct ScopeArgs
    include JSON::Serializable
    getter vault : String?
  end
```

Then in each finder, parse via `NameArgs.from_json(arguments.to_json)` etc.,
rescuing `JSON::SerializableError`/`JSON::ParseException` into
`ItemFinder::MissingArgumentError`. Preserve behavior: `NameItemsFinder`
matches `item` case-sensitively against `item_id` and case-insensitively
against title; `ListItemsFinder` uses only optional `vault`.

- [ ] **Step 2: Run**
      `crystal spec spec/item_finders_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
      — PASS.

- [ ] **Step 3: Milestone gate + commit**

Run `rake spec && rake lint && rake build` (green), then commit M2:

```bash
git add src/playwright_secure_mcp/secret_type_arguments.cr src/playwright_secure_mcp/secret_type_tool.cr \
        src/playwright_secure_mcp/item_finders.cr spec/secret_type_arguments_spec.cr
git commit   # refactor: parse tool-call arguments with JSON::Serializable DTOs  (+bullet body)
```

---

## Milestone 3 — outbound DTOs

### Task 3.1: ItemIdentity + result structs

**Files:** Create `src/playwright_secure_mcp/item_identity.cr`
(`FieldMeta`/`SectionMeta`/`ItemIdentity`) and
`src/playwright_secure_mcp/tool_result.cr` (`ToolContent`/`ToolTextResult`/
`JsonRpcToolResult`). Tests in `spec/item_identity_spec.cr`.

- [ ] **Step 1: Failing test** — assert the serialized shape matches today's
      output exactly (key order and omitted nils):

```crystal
# spec/item_identity_spec.cr
require "./spec_helper"
require "../src/playwright_secure_mcp/item_identity"

Spectator.describe PlaywrightSecureMcp::ItemIdentity do
  it "serializes field metadata with id,label,type and omits absent purpose/section" do
    field = PlaywrightSecureMcp::FieldMeta.new(
      id: "password", label: "password", type: "CONCEALED", purpose: "PASSWORD", section: nil)
    json = field.to_json
    expect(json).to eq(%({"id":"password","label":"password","type":"CONCEALED","purpose":"PASSWORD"}))
  end
end
```

- [ ] **Step 2: Run — FAIL.**
- [ ] **Step 3: Create the DTOs** (with `initialize` for construction):

```crystal
# item_identity.cr
require "json"

module PlaywrightSecureMcp
  struct FieldMeta
    include JSON::Serializable
    getter id : String
    getter label : String
    getter type : String
    @[JSON::Field(emit_null: false)]
    getter purpose : String?
    @[JSON::Field(emit_null: false)]
    getter section : String?

    def initialize(*, @id, @label, @type, @purpose, @section)
    end
  end

  struct SectionMeta
    include JSON::Serializable
    getter id : String
    getter label : String

    def initialize(@id, @label)
    end
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

    def initialize(*, @vault, @item, @title, @urls, @tags, @fields, @sections)
    end
  end
end
```

```crystal
# tool_result.cr
require "json"

module PlaywrightSecureMcp
  struct ToolContent
    include JSON::Serializable
    getter type : String = "text"
    getter text : String

    def initialize(@text : String)
    end
  end

  struct ToolTextResult
    include JSON::Serializable
    getter content : Array(ToolContent)
    @[JSON::Field(key: "isError")]
    getter? is_error : Bool

    def initialize(text : String, *, is_error : Bool)
      @content = [ToolContent.new(text)]
      @is_error = is_error
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
end
```

- [ ] **Step 4: Run — PASS.**

### Task 3.2: ItemResult + Proxy use the outbound DTOs

**Files:** modify `item_result.cr`, `proxy.cr`; `spec/item_result_spec.cr` and
`spec/proxy_spec.cr` stay green (adjust only if they assert an internal type).

- [ ] **Step 1: Baseline** —
      `crystal spec spec/item_result_spec.cr spec/proxy_spec.cr --link-flags=-fuse-ld=/usr/bin/ld`
      PASS.

- [ ] **Step 2: `ItemResult#build` returns a `ToolTextResult`** built from
      `Array(ItemIdentity)`:

```crystal
require "json"
require "./item"
require "./item_identity"
require "./tool_result"

module PlaywrightSecureMcp
  class ItemResult
    def build(items : Array(Item)) : ToolTextResult
      identities = items.map { |item| identity(item) }
      ToolTextResult.new(identities.to_json, is_error: false)
    end

    private def identity(item : Item) : ItemIdentity
      ItemIdentity.new(
        vault: item.vault_id, item: item.item_id, title: item.title,
        urls: item.urls, tags: item.tags,
        fields: item.fields.values.map { |f| field_meta(f) },
        sections: item.sections.values.map { |s| SectionMeta.new(s.id, s.label) })
    end

    private def field_meta(field : Field) : FieldMeta
      FieldMeta.new(id: field.id, label: field.label, type: field.type,
        purpose: field.purpose, section: field.section_id)
    end
  end
end
```

- [ ] **Step 3: Proxy** — build error and discovery results with the structs
      and convert to `JSON::Any` for the redaction gate. Replace `error_result`
      and the `handle_find` body construction, and add a struct→client helper:

```crystal
    private def error_result(id : JSON::Any, text : String) : JSON::Any
      to_any(JsonRpcToolResult.new(id, ToolTextResult.new(text, is_error: true)))
    end

    # in handle_find, replace the body construction:
    #   result = @item_result.build(items)                       # ToolTextResult
    #   send_to_client(to_any(JsonRpcToolResult.new(original_id, result)))

    private def to_any(value) : JSON::Any
      JSON.parse(value.to_json)
    end
```

`send_to_client` is unchanged (`redact(JSON::Any).to_json`), so the constructed
results still pass through the string-leaf redactor. `handle_secret_call`'s
`with_id`/`call_upstream` path (forwarded upstream response) stays `JSON::Any`.
`augment_initialize`/`augment_tools_list` stay `JSON::Any`.

- [ ] **Step 4: Update `spec/item_result_spec.cr`** — it currently calls
      `ItemResult.new.build([item])` and reads `result["content"]...`. Since
      `build` now returns a `ToolTextResult`, assert on the struct (or on
      `JSON.parse(result.to_json)`). Keep the invariant checks:
      `content.first.text` parses to the identity array, ciphertext absent,
      `is_error?` false. Update `spec/proxy_spec.cr` only if a line depended on
      `build` returning `JSON::Any`; the wire assertions
      (`response["result"]["content"]...`) are unchanged because the client
      still receives the same JSON.

- [ ] **Step 5: Run** `rake spec` — PASS. Confirm the discovery wire output is
      byte-identical by an added assertion in `item_result_spec` comparing
      `JSON.parse(build(...).to_json)` to the previously-expected structure.

- [ ] **Step 6: Milestone gate + commit**

Run `rake spec && rake lint && rake build` (green), then commit M3:

```bash
git add src/playwright_secure_mcp/item_identity.cr src/playwright_secure_mcp/tool_result.cr \
        src/playwright_secure_mcp/item_result.cr src/playwright_secure_mcp/proxy.cr \
        spec/item_identity_spec.cr spec/item_result_spec.cr spec/proxy_spec.cr
git commit   # refactor: build MCP result payloads with JSON::Serializable DTOs  (+bullet body)
```

---

## Self-review notes

- **Spec coverage:** inbound op DTOs + mapping (M1), account/token DTOs (M1),
  argument DTOs (M2), outbound ItemIdentity + result structs (M3), JSON::Any
  retained at transport/proxy-routing/augment/page_url/redactor/guard
  (untouched in all milestones). Tool-def heredocs untouched. All covered.
- **Behavior invariance:** every existing spec stays green unmodified except
  `item_result_spec`/`proxy_spec` where an internal return type changed;
  discovery wire output verified byte-identical.
- **Type consistency:** `OpItem`/`OpField`/`OpAccount` field names match op's
  keys; `ItemLocator#full`/`summary` return `Item`; `ItemResult#build` returns
  `ToolTextResult`; `Proxy#to_any` bridges structs → `JSON::Any` for redaction.
- **Compile safety:** M1/M2 keep public signatures; M3 changes `build`'s return
  type and updates its only caller (`Proxy`) in the same commit.
