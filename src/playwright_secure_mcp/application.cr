require "log"
require "./account_resolver"
require "./account_locator"
require "./token_fetcher"
require "./configuration"
require "./command_line_parser"
require "./upstream_command"
require "./upstream"
require "./stdio_transport"
require "./item_cache"
require "./cipher_selector"
require "./redactor"
require "./secret_type_tool"
require "./item_locator"
require "./website_matcher"
require "./field_selector"
require "./page_url"
require "./item_finders"
require "./item_result"
require "./secret_guard"
require "./proxy"

module PlaywrightSecureMcp
  class Application
    Log = ::Log.for(self)

    def initialize(@arguments : Array(String))
    end

    def run : Nil
      # Logs go to STDERR; STDOUT carries the MCP JSON-RPC stream to the client.
      ::Log.setup_from_env(backend: ::Log::IOBackend.new(STDERR))
      configuration = CommandLineParser.new.parse(@arguments)
      account = AccountResolver.new.resolve(
        account: configuration.account,
        account_email: configuration.account_email,
        account_from_git: configuration.account_from_git,
      )
      account = AccountLocator.new(op_command: configuration.op_command).locate(account)
      cipher = CipherSelector.for_host.select(require_hardware: configuration.require_hardware_key)
      Log.info { "cache key protection: #{cipher.description}" }
      cache = ItemCache.new(cipher)
      token = fetch_token(configuration, account)
      cache.store_service_token(token) if token
      item_locator = ItemLocator.new(
        op_command: configuration.op_command,
        account: account,
        encryptor: cache,
      )
      tokens = UpstreamCommand.new(configuration).tokens
      upstream_process = Upstream.new(tokens)
      upstream_transport = upstream_process.start
      begin
        build_proxy(upstream_transport, cache: cache, item_locator: item_locator).run
      ensure
        upstream_process.stop
      end
    end

    private def fetch_token(configuration : Configuration, account : String?) : String?
      tag = configuration.token_tag
      return nil unless tag

      token = TokenFetcher.new(op_command: configuration.op_command, account: account).fetch(tag)
      return nil if token.empty?

      token
    end

    private def build_proxy(upstream_transport : StdioTransport, *, cache : ItemCache, item_locator : ItemLocator) : Proxy
      finders = [
        ListItemsFinder.new(cache: cache, item_locator: item_locator, website_matcher: WebsiteMatcher.new),
        NameItemsFinder.new(cache: cache, item_locator: item_locator, website_matcher: WebsiteMatcher.new),
        TagItemsFinder.new(cache: cache, item_locator: item_locator, website_matcher: WebsiteMatcher.new),
      ] of ItemFinder
      proxy = Proxy.new(
        client: StdioTransport.new(input: STDIN, output: STDOUT),
        upstream: upstream_transport,
        item_cache: cache,
        item_locator: item_locator,
        field_selector: FieldSelector.new,
        page_url: PageUrl.new,
        website_matcher: WebsiteMatcher.new,
        redactor: Redactor.new(cache),
        secret_guard: SecretGuard.new(cache),
        secret_type_tool: SecretTypeTool.new,
        finders: finders,
        item_result: ItemResult.new,
      )
      proxy
    end
  end
end
