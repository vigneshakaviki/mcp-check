# Packaging

This project is ready to publish as a Python package. Publishing still requires maintainer-owned PyPI and Homebrew credentials.

## PyPI

Recommended release flow:

```bash
uv build
uv publish
```

For GitHub Actions, configure PyPI Trusted Publishing for this repository and use the release workflow below:

```yaml
name: Publish

on:
  release:
    types: [published]

jobs:
  pypi:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v5
      - run: uv build
      - run: uv publish
```

## Homebrew

After publishing to PyPI, create a Homebrew tap and update the formula URL and SHA256:

```ruby
class McpCheck < Formula
  include Language::Python::Virtualenv

  desc "Offline security scanner for MCP server configurations"
  homepage "https://github.com/vigneshakaviki/mcp-check"
  url "https://files.pythonhosted.org/packages/source/m/mcp-check/mcp_check-0.5.0.tar.gz"
  sha256 "UPDATE_WITH_RELEASE_SHA256"
  license "MIT"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "mcp-check", shell_output("#{bin}/mcp-check --help")
  end
end
```
