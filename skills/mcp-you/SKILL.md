---
name: mcp-you
description: Skills for web search via the You.com MCP server. Used when users need online searching with fresh results and source URLs; the free endpoint requires no API key.
---

# You.com Search
The You.com MCP server provides web search that returns ranked results with URLs, snippets and query-relevant passages.

**MCP Server URL**: https://api.you.com/mcp?profile=free (keyless, no API key required)

## Web search
- `npx -y mcporter call --http-url "https://api.you.com/mcp?profile=free" you-search query="{keyword}"`
- `npx -y mcporter call --http-url "https://api.you.com/mcp?profile=free" you-search query="{keyword}" count=10 freshness=month`

## Agent resource discovery
Search You.com's agent catalog for MCP servers, SDKs, skills and plugins.
- `npx -y mcporter call --http-url "https://api.you.com/mcp?profile=free" you-discover query="{keyword}"`

## Get tool list
- `npx -y mcporter list --http-url "https://api.you.com/mcp?profile=free" --schema --all-parameters`
