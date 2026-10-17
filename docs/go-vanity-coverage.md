# Go module → GitHub repository coverage

`blindspot` can only check a dependency's maintainer-published security
advisories if it knows which GitHub repository that dependency comes from. For
packages on PyPI and npm it reads the repository link from the registry. For Go
modules there is no registry call: the GitHub repository is worked out from the
module path alone, by the rules below.

Every mapping here was verified from the project's own `go.mod` `module` line on
2026-10-17. `blindspot` never guesses a repository it has not verified: a Go
module on any host not listed below is reported as *unmapped* (add it with
`--map NAME=OWNER/REPO`), rather than silently skipped or mapped to a wrong repo.

This file documents `blindspot` as of advisory-import-census **0.9.9**.

## 1. Direct GitHub modules

`github.com/OWNER/REPO` → `OWNER/REPO`. A trailing `/vN` major-version element
and any deeper sub-package path do not change the repository
(`github.com/foo/bar/v2/baz` → `foo/bar`).

## 2. gopkg.in redirect rule

`gopkg.in` follows [its own documented redirect rule](https://gopkg.in):

| Module path | Repository |
|---|---|
| `gopkg.in/pkg.vN` | `go-pkg/pkg` |
| `gopkg.in/user/pkg.vN` | `user/pkg` |

A deeper sub-package path (`gopkg.in/DataDog/dd-trace-go.v1/ddtrace`) keeps the
repository. A `gopkg.in` path with no `.vN` selector is left unmapped.

## 3. Owner-prefix hosts

The repository is the **first path element after the prefix**; a `/vN` major
version or a deeper import path does not change it
(`k8s.io/klog/v2` → `kubernetes/klog`, `golang.org/x/net/http2` → `golang/net`).

| Prefix | GitHub owner | Example |
|---|---|---|
| `k8s.io` | `kubernetes` | `k8s.io/client-go` → `kubernetes/client-go` |
| `sigs.k8s.io` | `kubernetes-sigs` | `sigs.k8s.io/yaml` → `kubernetes-sigs/yaml` |
| `golang.org/x` | `golang` | `golang.org/x/crypto` → `golang/crypto` |

Only the `golang.org/x` namespace is a prefix; other `golang.org` paths
(`golang.org/dl`) stay unmapped.

## 4. Monorepo-prefix hosts

A whole vanity subtree lives in **one** GitHub monorepo: the module path equals
the prefix or begins with `<prefix>/`, and every sub-module maps to the same
repository, whatever follows (`cloud.google.com/go/storage` and
`cloud.google.com/go/compute/metadata` both → `googleapis/google-cloud-go`). The
longest matching prefix wins.

| Prefix | Repository | Since |
|---|---|---|
| `cloud.google.com/go` | `googleapis/google-cloud-go` | 0.9.7 |
| `go.etcd.io/etcd` | `etcd-io/etcd` | 0.9.7 |
| `go.opentelemetry.io/contrib` | `open-telemetry/opentelemetry-go-contrib` | 0.9.8 |
| `go.opentelemetry.io/otel` | `open-telemetry/opentelemetry-go` | 0.9.9 |
| `go.opentelemetry.io/collector` | `open-telemetry/opentelemetry-collector` | 0.9.9 |
| `go.opentelemetry.io/proto` | `open-telemetry/opentelemetry-proto-go` | 0.9.9 |
| `go.opentelemetry.io/auto` | `open-telemetry/opentelemetry-go-instrumentation` | 0.9.9 |
| `go.opentelemetry.io/ebpf-profiler` | `open-telemetry/opentelemetry-ebpf-profiler` | 0.9.9 |

**OpenTelemetry.** OpenTelemetry's own vanity-URL configuration
([`opentelemetry-go-vanityurls`](https://github.com/open-telemetry/opentelemetry-go-vanityurls),
`go.opentelemetry.io/vanity.yaml`) maps each top-level `go.opentelemetry.io`
path to one repository and no deeper path to any other, so each subtree is a
monorepo. Before 0.9.9 only `otel`, `otel/{trace,metric,sdk}` and the bare
`collector` had exact entries, so widely used modules such as
`go.opentelemetry.io/otel/sdk/metric`, the OTLP exporters
(`otel/exporters/otlp/...`) and `go.opentelemetry.io/collector/pdata` were
reported as unmapped and their advisories were never checked. Verified sub-modules:
`otel/{sdk/metric,log,exporters/prometheus,exporters/otlp/otlptrace/otlptracegrpc}`,
`collector/{pdata,component,confmap}`, `proto/otlp`, `auto`, `ebpf-profiler`.

The Collector's contrib repository declares `github.com/open-telemetry/
opentelemetry-collector-contrib/...` module paths, so it maps by rule 1 and is
not under `go.opentelemetry.io/collector`. Matching is path-boundary anchored:
`go.opentelemetry.io/otelc` (a different repository) is not under `.../otel`.
`go.etcd.io/bbolt` → `etcd-io/bbolt` is outside `go.etcd.io/etcd` and keeps its
exact entry below.

## 5. Exact vanity entries

Well-known vanity modules that are neither a prefix host nor a clean monorepo
(their siblings live under different owners, so a prefix rule would be wrong). A
trailing `/vN` is stripped before the lookup.

| Module path | Repository |
|---|---|
| `code.gitea.io/gitea`, `gitea.dev` | `go-gitea/gitea` |
| `gorm.io/gorm` | `go-gorm/gorm` |
| `gorm.io/driver/{mysql,postgres,sqlite,sqlserver}` | `go-gorm/{mysql,…}` |
| `gorm.io/datatypes` | `go-gorm/datatypes` |
| `gocloud.dev` | `google/go-cloud` |
| `google.golang.org/grpc` | `grpc/grpc-go` |
| `google.golang.org/protobuf` | `protocolbuffers/protobuf-go` |
| `google.golang.org/api` | `googleapis/google-api-go-client` |
| `google.golang.org/genproto` (+ `.../googleapis/{api,rpc}`) | `googleapis/go-genproto` |
| `google.golang.org/appengine` | `golang/appengine` |
| `go.uber.org/{zap,multierr,atomic}` | `uber-go/{zap,…}` |
| `go.uber.org/yarpc` | `yarpc/yarpc-go` |
| `go.mongodb.org/mongo-driver` | `mongodb/mongo-go-driver` |
| `go.etcd.io/bbolt` | `etcd-io/bbolt` |

`google.golang.org` is **not** a prefix host (grpc, protobuf, api and genproto
live in four different repositories), so each of its modules is an exact entry.

## Anything else

Any other Go module host — other `golang.org` paths, a private host, an
unverified vanity path — is reported as unmapped. Map it yourself with
`--map example.com/thing=owner/repo`; if it is a widely-used module worth adding
to `blindspot` by default, please open an issue with its `go.mod` `module` line.

---
Part of [advisory-import-census](https://github.com/munimtechnologies/advisory-import-census)
(Apache-2.0). Made with AI agents working for MV2 of Munim, Inc.
