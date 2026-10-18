# Go module → GitHub repository coverage

`blindspot` can only check a dependency's maintainer-published security
advisories if it knows which GitHub repository that dependency comes from. For
packages on PyPI and npm it reads the repository link from the registry. For Go
modules there is no registry call: the GitHub repository is worked out from the
module path alone, by the rules below.

Every mapping here was verified from the project's own `go.mod` `module` line on
2026-10-17 (those added in 0.9.11 to 0.9.21 on 2026-10-18). `blindspot`
never guesses a repository it has not verified: a Go
module on any host not listed below is reported as *unmapped* (add it with
`--map NAME=OWNER/REPO`), rather than silently skipped or mapped to a wrong repo.

This file documents `blindspot` as of advisory-import-census **0.9.21**.

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
| `istio.io` | `istio` | `istio.io/client-go` → `istio/client-go` |

Only the `golang.org/x` namespace is a prefix; other `golang.org` paths
(`golang.org/dl`) stay unmapped.

**Istio** (since 0.9.11). `istio/istio`, `istio/api`, `istio/client-go` and
`istio/pkg` each declare `module istio.io/<repo>`, and `istio.io/istio` requires
`istio.io/api` and `istio.io/client-go` as separate modules, so the element after
`istio.io` names a repository (an owner prefix, not a monorepo).

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
| `tailscale.com` | `tailscale/tailscale` | 0.9.10 |
| `go.elastic.co/apm` | `elastic/apm-agent-go` | 0.9.16 |

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

**Tailscale.** Tailscale ships as a single Go module whose path is the bare host
`tailscale.com` (verified `module tailscale.com`), so every import path under it
(`tailscale.com/cmd/tailscale`, `tailscale.com/ipn`, `tailscale.com/tsnet`, …) is
one package in the one repository `tailscale/tailscale`.

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
| `go.etcd.io/raft` | `etcd-io/raft` |
| `helm.sh/helm` | `helm/helm` |
| `cuelang.org/go` | `cue-lang/cue` |
| `oras.land/oras-go` | `oras-project/oras-go` |
| `connectrpc.com/connect` | `connectrpc/connect-go` |
| `connectrpc.com/otelconnect` | `connectrpc/otelconnect-go` |
| `connectrpc.com/grpcreflect` | `connectrpc/grpcreflect-go` |
| `dario.cat/mergo` | `darccio/mergo` |
| `filippo.io/age` | `FiloSottile/age` |
| `filippo.io/edwards25519` | `FiloSottile/edwards25519` |
| `honnef.co/go/tools` | `dominikh/go-tools` |
| `gotest.tools` (`/v3`) | `gotestyourself/gotest.tools` |
| `go.starlark.net` | `google/starlark-go` |
| `mvdan.cc/sh` (`/v3`) | `mvdan/sh` |
| `entgo.io/ent` | `ent/ent` |
| `go.temporal.io/sdk` | `temporalio/sdk-go` |
| `go.temporal.io/api` | `temporalio/api-go` |
| `gvisor.dev/gvisor` | `google/gvisor` |
| `buf.build/go/protovalidate` | `bufbuild/protovalidate-go` |
| `go.yaml.in/yaml` (`/v3`, `/v4`) | `yaml/go-yaml` |
| `go.uber.org/{mock,goleak,automaxprocs,dig,fx}` | `uber-go/{mock,…}` |
| `go.opencensus.io` | `census-instrumentation/opencensus-go` |
| `cel.dev/expr` | `google/cel-spec` |
| `go.uber.org/{ratelimit,nilaway,config}` | `uber-go/{ratelimit,…}` |
| `buf.build/go/protoyaml` | `bufbuild/protoyaml-go` |
| `buf.build/go/bufplugin` | `bufbuild/bufplugin-go` |
| `go.step.sm/crypto` | `smallstep/crypto` |
| `lukechampine.com/{blake3,frand,uint128}` | `lukechampine/{blake3,frand,uint128}` |
| `knative.dev/{serving,pkg,eventing,func}` | `knative/{serving,…}` |
| `kubevirt.io/{kubevirt,client-go,api}` | `kubevirt/{kubevirt,…}` |
| `kubevirt.io/{containerized-data-importer,csi-driver}` | `kubevirt/{containerized-data-importer,csi-driver}` |
| `go.elastic.co/ecszap` | `elastic/ecs-logging-go-zap` |
| `go.elastic.co/fastjson` | `elastic/go-fastjson` |
| `inet.af/netaddr` | `inetaf/netaddr` |
| `go4.org` | `go4org/go4` |
| `go4.org/netipx` | `go4org/netipx` |
| `fyne.io/fyne` (`/v2`) | `fyne-io/fyne` |
| `software.sslmate.com/src/go-pkcs12` | `SSLMate/go-pkcs12` |
| `go.uber.org/zap/exp` | `uber-go/zap` |
| `howett.net/plist` | `DHowett/go-plist` |
| `rsc.io/binaryregexp` | `rsc/binaryregexp` |
| `gonum.org/v1/gonum` | `gonum/gonum` |
| `gonum.org/v1/plot` | `gonum/plot` |
| `mvdan.cc/gofumpt` | `mvdan/gofumpt` |
| `mvdan.cc/xurls` (`/v2`) | `mvdan/xurls` |
| `mvdan.cc/editorconfig` | `mvdan/editorconfig` |
| `pgregory.net/rapid` | `flyingmutant/rapid` |
| `gocv.io/x/gocv` | `hybridgroup/gocv` |
| `zombiezen.com/go/sqlite` | `zombiezen/go-sqlite` |
| `maunium.net/go/mautrix` | `mautrix/go` |
| `gorm.io/gen` | `go-gorm/gen` |
| `gorm.io/driver/clickhouse` | `go-gorm/clickhouse` |
| `gorm.io/plugin/dbresolver` | `go-gorm/dbresolver` |
| `gorm.io/plugin/opentelemetry` | `go-gorm/opentelemetry` |
| `go.bug.st/serial` | `bugst/go-serial` |

`google.golang.org` is **not** a prefix host (grpc, protobuf, api and genproto
live in four different repositories), so each of its modules is an exact entry.
Neither is `connectrpc.com`: its repositories carry a `-go` suffix the import
path lacks, so only the three verified paths are mapped. ORAS's v2 line declares
`module oras.land/oras-go/v2`; its main branch has since moved to
`github.com/oras-project/oras-go/v3`, which rule 1 maps to the same repository.

The 0.9.12 entries (`dario.cat/mergo`, `filippo.io/age`,
`filippo.io/edwards25519`, `honnef.co/go/tools`, `gotest.tools`,
`go.starlark.net`, `mvdan.cc/sh`) are all common transitive dependencies.
`filippo.io` is **not** a prefix host — only the two verified paths are mapped,
so an unlisted `filippo.io` module stays unmapped rather than guessed.
`gotest.tools` and `mvdan.cc/sh` ship as `/v3` modules; the `/vN` is stripped
before the lookup, so the base path is the map key.

The 0.9.13 entries (`entgo.io/ent`, `go.temporal.io/{sdk,api}`,
`gvisor.dev/gvisor`, `buf.build/go/protovalidate`, `go.yaml.in/yaml`) are all
widely-used dependencies. `go.temporal.io` and `buf.build/go` are **not** prefix
hosts: their repository names carry a `-go` suffix the import path lacks
(`go.temporal.io/sdk` → `temporalio/sdk-go`, `go.temporal.io/api` →
`temporalio/api-go`), so only the verified paths are mapped. `go.yaml.in/yaml` is
the canonical go-yaml module's new vanity host — its `v3` branch declares
`module go.yaml.in/yaml/v3` and `main` declares `.../v4`, both in `yaml/go-yaml`;
the older `gopkg.in/yaml.vN` path still maps to `go-yaml/yaml` by the gopkg.in
rule (section 2).

The 0.9.14 entries are very common direct or transitive dependencies: five more
`go.uber.org` libraries (`mock`, the maintained gomock fork; `goleak`;
`automaxprocs`; `dig`; `fx`), `go.opencensus.io` (still pulled in by many Google
Cloud and gRPC clients) and `cel.dev/expr` (the CEL protobuf types, required by
grpc-go; it lives at the root of `google/cel-spec`). `go.uber.org` stays an
exact-entry host because `go.uber.org/yarpc` has a different owner, and `cel.dev`
is not a prefix host. The old `github.com/golang/mock` path is a different,
archived repository and still maps there by rule 1.

The 0.9.15 entries are three more `go.uber.org` libraries (`ratelimit`;
`nilaway`, Uber's static nil-panic analyzer; `config`), two more `buf.build/go`
modules (`protoyaml` and `bufplugin`) and two cryptography libraries
(`go.step.sm/crypto`, the smallstep crypto toolkit, and `lukechampine.com/blake3`,
a widely-used BLAKE3 implementation). `buf.build/go` stays an exact-entry host for
the same reason as in 0.9.13: its repository names carry a `-go` suffix the import
path lacks (`buf.build/go/protoyaml` → `bufbuild/protoyaml-go`). `go.step.sm` and
`lukechampine.com` are not prefix hosts, so only the verified paths are mapped.

The 0.9.16 entries add two Kubernetes-ecosystem vanity hosts, `knative.dev` and
`kubevirt.io`, as **exact entries rather than owner prefixes**. The import-path
host does not identify the GitHub owner here: Knative's core repositories are under
the `knative` org (`knative/serving`, `knative/pkg`, `knative/eventing`,
`knative/func` each declare `module knative.dev/<repo>`), but its extensions are
under a *different* org — `knative.dev/eventing-kafka-broker` declares
`module knative.dev/eventing-kafka-broker` yet is hosted at
`knative-extensions/eventing-kafka-broker`, not `knative/…`. A `knative.dev` owner
prefix would map every extension to the wrong owner, so only the four verified core
modules are mapped and any other `knative.dev` path stays unmapped. `kubevirt.io`
(`kubevirt/kubevirt`, `kubevirt/client-go`, `kubevirt/api`) is mapped the same
cautious way. These hosts are a worked example of the rule in rule 3's caption: a
vanity host is only treated as an owner prefix when the host reliably names the
owner for *every* module, which Knative's org split shows is not the case here.

The 0.9.16 monorepo entry `go.elastic.co/apm` → `elastic/apm-agent-go` covers the
Elastic APM Go agent: one repository holding the root module
(`module go.elastic.co/apm/v2`) and every instrumentation sub-module
(`module go.elastic.co/apm/module/<name>/v2`, verified `.../apmhttp/v2`). The
prefix is `go.elastic.co/apm`, **not** the bare host `go.elastic.co`: other
`go.elastic.co` modules such as `ecszap` and `fastjson` live in differently-named
repositories, so they are mapped individually (0.9.17 below) rather than by a host
prefix.

The 0.9.17 entries add six more exact paths, each verified from its own `go.mod`
`module` line (2026-10-18). Two more KubeVirt-org repositories join the three core
modules from 0.9.16: `kubevirt.io/containerized-data-importer` (the Containerized
Data Importer) and `kubevirt.io/csi-driver` (the KubeVirt CSI driver). The two
`go.elastic.co` siblings that 0.9.16 left unmapped are now mapped by their verified
exact paths: `go.elastic.co/ecszap` → `elastic/ecs-logging-go-zap` and
`go.elastic.co/fastjson` → `elastic/go-fastjson`; `go.elastic.co` is still not a
prefix host. `inet.af/netaddr` → `inetaf/netaddr` is the IP-address library still
pulled in transitively by many Go networking projects (its vanity host moved
owner, so only the current `inet.af` path is mapped). `go4.org` → `go4org/go4` is a
widely-vendored utility module; `go4.org` is **not** an owner prefix, because the
bare host is one repository while siblings such as `go4.org/netipx` are separate
repositories, so each verified `go4.org` path is mapped individually.

The 0.9.18 entries add six more exact paths, each verified from its own `go.mod`
`module` line (2026-10-18). `go4.org/netipx` → `go4org/netipx` is the IP-set and
prefix library (a common Tailscale/networking transitive dependency) that was
split out of `go4.org` into its **own** repository, a sibling of `go4org/go4`
rather than a sub-package, so it needs this exact entry (0.9.17 had left it
unmapped). `fyne.io/fyne` → `fyne-io/fyne` is the Fyne cross-platform GUI toolkit;
master declares `module fyne.io/fyne/v2`, so the `/vN` is stripped and the base
path `fyne.io/fyne` is the key, covering both the v1 and v2 modules. `fyne.io` is
**not** an owner prefix — the GitHub owner is `fyne-io`, not `fyne`.
`software.sslmate.com/src/go-pkcs12` → `SSLMate/go-pkcs12` is a common PKCS#12/TLS
dependency. `go.uber.org/zap/exp` → `uber-go/zap` is the experimental submodule
that lives **inside** the `uber-go/zap` repository as its own Go module; because
the exact lookup is on the full module path, it needs its own entry and is not
covered by the `go.uber.org/zap` entry. `howett.net/plist` → `DHowett/go-plist` is
the Apple property-list library (owner `DHowett`, repo `go-plist`).
`rsc.io/binaryregexp` → `rsc/binaryregexp` is a binary-data regexp replacement
pulled in transitively by some Google Cloud clients. `software.sslmate.com`,
`howett.net` and `rsc.io` are all kept as exact-entry hosts rather than owner
prefixes, so an unverified path on any of them stays unmapped rather than guessed.

The 0.9.19 entries add six more exact paths, each verified from its own `go.mod`
`module` line (2026-10-18). `gonum.org/v1/gonum` → `gonum/gonum` and
`gonum.org/v1/plot` → `gonum/plot` are the Gonum scientific-computing libraries
(numerical/linear-algebra and plotting), both very common in Go data and ML code;
each declares `module gonum.org/v1/<repo>`. `gonum.org/v1` is **not** an owner
prefix — only the two verified paths are mapped. Three `mvdan.cc` tooling modules
join `mvdan.cc/sh` (0.9.12): `mvdan.cc/gofumpt` → `mvdan/gofumpt` (the stricter
gofmt widely used in Go CI), `mvdan.cc/xurls` → `mvdan/xurls` (a URL-extraction
library; master declares `module mvdan.cc/xurls/v2`, so the `/vN` is stripped and
the base path is the key) and `mvdan.cc/editorconfig` → `mvdan/editorconfig`.
`mvdan.cc` stays an exact-entry host rather than an owner prefix. Finally
`pgregory.net/rapid` → `flyingmutant/rapid` is the Rapid property-based testing
library (a common test dependency); `pgregory.net` is **not** a prefix host (the
owner is `flyingmutant`, not `pgregory`), so only the verified path is mapped.

The 0.9.20 entries add five more exact paths, each verified from its own `go.mod`
`module` line (2026-10-18). `gocv.io/x/gocv` → `hybridgroup/gocv` is the GoCV
computer-vision bindings for OpenCV; `gocv.io` is **not** a prefix host (the owner
is `hybridgroup`). `zombiezen.com/go/sqlite` → `zombiezen/go-sqlite` is a widely
used cgo-free SQLite driver; `zombiezen.com` is **not** a prefix host (siblings
such as `zombiezen.com/go/log` are separate repositories). `maunium.net/go/mautrix`
→ `mautrix/go` is the mautrix Go Matrix framework (owner `mautrix`, repo `go`), so
again not a prefix host. Two more `gorm.io` repositories join the drivers above:
`gorm.io/gen` → `go-gorm/gen` (the GORM code generator) and
`gorm.io/driver/clickhouse` → `go-gorm/clickhouse` (the GORM ClickHouse driver, a
sibling of the mysql/postgres/sqlite/sqlserver drivers); `gorm.io` stays an
exact-entry host, so an unverified `gorm.io` driver is still left unmapped rather
than guessed.

The 0.9.21 entries add five more exact paths, each verified from its own `go.mod`
`module` line (2026-10-18). Two more `gorm.io` repositories join the drivers and
generator above, both under the `gorm.io/plugin/` namespace:
`gorm.io/plugin/dbresolver` → `go-gorm/dbresolver` (the read/write-splitting
plugin) and `gorm.io/plugin/opentelemetry` → `go-gorm/opentelemetry` (the
OpenTelemetry tracing/metrics plugin); `gorm.io` stays an exact-entry host, so an
unverified `gorm.io` plugin or driver is still left unmapped. Two more
`lukechampine.com` libraries join `blake3` (0.9.15): `lukechampine.com/uint128` →
`lukechampine/uint128` (a 128-bit unsigned-integer type, a common storage/crypto
transitive dependency) and `lukechampine.com/frand` → `lukechampine/frand` (a fast
cryptographic-quality RNG); `lukechampine.com` stays an exact-entry host, not an
owner prefix. Finally `go.bug.st/serial` → `bugst/go-serial` is the common
cross-platform serial-port library used by Go hardware/embedded tooling;
`go.bug.st` is **not** a prefix host (the owner is `bugst` and the repository is
`go-serial`), so only the verified path is mapped.

## Anything else

Any other Go module host — other `golang.org` paths, a private host, an
unverified vanity path — is reported as unmapped. Map it yourself with
`--map example.com/thing=owner/repo`; if it is a widely-used module worth adding
to `blindspot` by default, please open an issue with its `go.mod` `module` line.

---
Part of [advisory-import-census](https://github.com/munimtechnologies/advisory-import-census)
(Apache-2.0). Made with AI agents working for MV2 of Munim, Inc.
