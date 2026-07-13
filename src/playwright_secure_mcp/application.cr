require "log"
require "./account_resolver"
require "./account_locator"
require "./token_fetcher"
require "./command_line_parser"
require "./upstream_command"
require "./upstream"
require "./stdio_transport"
require "./secret_resolver"
require "./secret_vault"
require "./cipher_selector"
require "./redactor"
require "./secret_type_tool"
require "./item_locator"
require "./website_matcher"
require "./secret_finders"
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
      vault = SecretVault.new(cipher: cipher)
      token = fetch_token(configuration, account, vault)
      secret_resolver = SecretResolver.new(
        op_command: configuration.op_command,
        account: token ? nil : account,
        service_account_token: token,
      )
      item_locator = ItemLocator.new(
        op_command: configuration.op_command,
        account: token ? nil : account,
        service_account_token: token,
      )
      tokens = UpstreamCommand.new(configuration).tokens
      upstream_process = Upstream.new(tokens)
      upstream_transport = upstream_process.start
      begin
        build_proxy(upstream_transport, vault: vault, secret_resolver: secret_resolver, item_locator: item_locator).run
      ensure
        upstream_process.stop
      end
    end

    private def fetch_token(configuration : Configuration, account : String?, vault : SecretVault) : String?
      tag = configuration.token_tag
      return nil unless tag

      token = TokenFetcher.new(op_command: configuration.op_command, account: account).fetch(tag)
      return nil if token.empty?

      # Store the token in the vault so the redactor and guard cover it.
      vault.store("service-account-token", token)
      token
    end

    private def build_proxy(upstream_transport : StdioTransport, *, vault : SecretVault, secret_resolver : SecretResolver, item_locator : ItemLocator) : Proxy
      finders = [
        UrlSecretFinder.new(
          item_locator: item_locator,
          website_matcher: WebsiteMatcher.new,
        ),
        NameSecretFinder.new(item_locator),
        TagSecretFinder.new(item_locator),
      ] of SecretFinder
      proxy = Proxy.new(
        client: StdioTransport.new(input: STDIN, output: STDOUT),
        upstream: upstream_transport,
        secret_resolver: secret_resolver,
        secret_vault: vault,
        redactor: Redactor.new(vault),
        secret_type_tool: SecretTypeTool.new,
        secret_guard: SecretGuard.new(vault),
        finders: finders,
        item_result: ItemResult.new,
      )
      proxy
    end
  end
end
