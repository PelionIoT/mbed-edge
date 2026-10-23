# Self-hosted GitHub Actions runners

All workflow jobs use self-hosted runners. There is no GitHub-hosted fallback.

| Jobs | Required labels | Prerequisites |
| --- | --- | --- |
| Linux builds, unit tests and spelling checks | `self-hosted`, `client` | Linux x64, Docker access, Git, Bash and Python 3.10 support |
| Windows Core build and signing | `self-hosted`, `Windows`, `X64`, `edge-windows-build` | Visual Studio 2022 C++ tools and Windows SDK, CMake/CTest, Git, Perl, GitHub CLI, Azure CLI and Windows PowerShell 5.1 |

The Windows workflow remains manually triggered. Its signing job continues to
use the `windows-signing` environment and Azure OIDC credentials. Missing runners
leave jobs queued; they do not cause a switch to hosted capacity.

Windows runners must be accessible to `PelionIoT/mbed-edge`. The separate
installer repository needs matching build runners and a disposable Windows test
pool; see its [runner requirements](https://github.com/IzumaNetworks/mbed-edge-windows-installer/blob/main/.github/SELF_HOSTED_RUNNERS.md).

Register build runners under a dedicated CI account. Keep signing/build machines
separate from the disposable MSI qualification pool. The qualification tests
remove shared Visual C++ runtimes and install services.

The repository REST runner list only lists repository registrations. Check the
repository's Settings > Actions > Runners page for organization runners shared
with it as well. Organization-wide REST inventory requires organization runner
read permissions (or `admin:org` for classic tokens).
