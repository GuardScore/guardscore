# Publishing checklist (needs your accounts)

1. **Name.** Pick the product name. Then set `name` in package.json (an unscoped npm name, or `@yourorg/<name>`) and the MCP server name in src/mcp.js.
2. **npm.** Run `npm login`, then `npm publish --access public`. After that, `npx <name> check .` works anywhere with Node 20+.
3. **GitHub.** Push to a public repository, then tag it: `git tag v0.5.0 && git push --tags`. The Action is then usable as `your-org/<repo>@v0.5.0`. To list it in the Actions Marketplace, edit the release on GitHub and tick "Publish this Action to the GitHub Marketplace".
4. **MCP registries.** Add the server with the command `npx -y -p <name> verified-changes-mcp` to the MCP registries your users' agents read from. Claude Code users can run `claude mcp add verified-changes -- npx -y -p <name> verified-changes-mcp`.
5. **API.** Deploy `node src/cli.js serve` behind HTTPS with `VC_API_KEYS` set, on any Node host. It keeps no data.
6. **Keep private:** the review cases, benchmark tasks held out for scoring, and the runs.
