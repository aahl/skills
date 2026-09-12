---
name: edgeone
description: Deploy HTML content to EdgeOne Pages, return the public URL.
---

# EdgeOne
Deploy HTML content to EdgeOne Pages, return the public URL. No login required, no API key required.

## Deploy HTML
HTML or text content to deploy. Provide complete HTML or text content you want to publish, and the system will return a public URL where your content can be accessed.
```bash
npx -y mcporter call mcp-on-edge.edgeone.app/mcp-server.deploy-html value="<html>Content</html>"
npx -y mcporter call mcp-on-edge.edgeone.app/mcp-server.deploy-html value="$(cat index.html)"
```

## Deploy Website
Deploy your project to EdgeOne Makers.
```bash
npx -y edgeone makers deploy --help
npx -y edgeone makers deploy --anonymous [directoryOrZip]
```
