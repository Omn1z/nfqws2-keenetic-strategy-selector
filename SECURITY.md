# Dependency security checks

Release CI checks all Go and npm dependencies. Production npm dependencies must
have zero audit findings. The emitted browser module graph also rejects
`picomatch`, `fdir` and `tinyglobby`; the router ships the embedded browser UI,
not the Vite development server or Node build dependencies.

## Temporary build-only exception

Until **2026-11-25 00:00:00 UTC**, one exception covers
[GHSA-fc5q-39xc-vjpf](https://github.com/advisories/GHSA-fc5q-39xc-vjpf), the
single-branch repeated-extglob ReDoS in `picomatch <=4.0.7`. The current lockfile
contains `picomatch 4.0.4` only as a development dependency through Vite,
tinyglobby and fdir. Release builds use reviewed repository source and fixed
build patterns; router-provided settings are not build inputs. This exception
does not cover processing untrusted glob patterns or deploying a public Vite
development server.

`npm run audit:security` runs the complete audit and a separate production-only
audit. It rejects every other advisory, affected runtime dependency, unknown
report format, failed audit, changed affected range or lockfile version, and
the expiry boundary. It checks the official npm registry online and refuses
the exception if its currently published `picomatch` version changes from
4.0.7. No package version is relabeled and no advisory is removed from npm's
report. CI logs the accepted build-only finding explicitly.

When upstream publishes a fix, stop the exception, review the upstream patch,
update the lockfile to the verified fixed release, and rerun all frontend
tests, bundle graph checks and both audits. Remove the exception policy and
its documentation once the full audit is clean. Do not use `npm audit fix
--force` to downgrade Vite or disable the remaining security gates. The
[official registry metadata](https://registry.npmjs.org/picomatch/latest)
currently reports 4.0.7; the guard rechecks it for each affected build.
