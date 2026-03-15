class PrismScanner < Formula
  include Language::Python::Virtualenv

  desc "Security scanner for AI Agent skills, plugins, and MCP servers"
  homepage "https://github.com/prismlab/prism-scanner"
  url "https://github.com/prismlab/prism-scanner/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256"
  license "Apache-2.0"

  depends_on "python@3.12"

  resource "pyyaml" do
    url "https://files.pythonhosted.org/packages/64/c2/b80047c7ac2478f9501676c988a5411ed5572f35d1beff9cae07d321512c/PyYAML-6.0.2.tar.gz"
    sha256 "d584d9ec91ad65861cc08d42e834324ef890a082e591037abe114850ff7bbc3e"
  end

  resource "rich" do
    url "https://files.pythonhosted.org/packages/a1/53/830aa4c3066a8ab0ae9a9955976fb770f9c6d1bf3c3c0c7b1b10aa2c2bac/rich-13.9.4.tar.gz"
    sha256 "439594978a49a09530cff7ebc4b5c7103ef57c74c583bf82bb1ea2da1d21b43c"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "Prism Scanner", shell_output("#{bin}/prism --version")
  end
end
