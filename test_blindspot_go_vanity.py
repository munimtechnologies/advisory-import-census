"""Tests for Go vanity-host module mapping in blindspot.py (v0.9.6).

Before 0.9.2, a Go module whose path was not github.com/OWNER/REPO was always
reported "unmapped", so its maintainer's GitHub repository security advisories
were never checked -- even for gopkg.in packages (in almost every Go project)
and well-known vanity hosts such as Gitea. 0.9.2 added gopkg.in and a small
map of vanity hosts. 0.9.3 adds the whole Kubernetes ecosystem by prefix and a
few more exact vanity entries. 0.9.4 adds exact entries for gRPC, Protobuf, the
go.uber.org libraries and the MongoDB Go driver. 0.9.5 adds the Google
API/genproto and Cloud client modules, OpenTelemetry and etcd. 0.9.6 adds the
golang.org/x sub-repositories by (two-element) prefix, and exact entries for
App Engine, the OpenTelemetry Collector and the net/http contrib module. 0.9.7
adds a monorepo-prefix rule and moves cloud.google.com/go and go.etcd.io/etcd
to it, so every sub-module of those two monorepos now maps to the one repo. 0.9.8
adds go.opentelemetry.io/contrib as a monorepo prefix (the whole OpenTelemetry Go
contrib repo -- every instrumentation, exporter and detector module), replacing
the single exact net/http otelhttp entry from 0.9.6. 0.9.9 makes the other
go.opentelemetry.io subtrees (otel, collector, proto, auto, ebpf-profiler)
monorepo prefixes too, replacing the exact otel{,/trace,/metric,/sdk} and
collector entries. 0.9.10 adds Tailscale (tailscale.com) as a monorepo prefix
and exact entries for Helm (helm.sh/helm) and the etcd raft library
(go.etcd.io/raft). 0.9.11 adds Istio (istio.io) as an owner prefix and exact
entries for CUE (cuelang.org/go), ORAS (oras.land/oras-go) and Connect
(connectrpc.com/{connect,otelconnect,grpcreflect}). These tests pin the
behaviour:

  - gopkg.in follows its own documented redirect rule
    (gopkg.in/pkg.vN -> github.com/go-pkg/pkg; gopkg.in/user/pkg.vN ->
    github.com/user/pkg), verified at https://gopkg.in (2026-10-17);
  - the Kubernetes vanity hosts map by prefix: k8s.io/<repo> ->
    github.com/kubernetes/<repo> and sigs.k8s.io/<repo> ->
    github.com/kubernetes-sigs/<repo>, with a /vN major version or a deeper
    sub-package path leaving the repo unchanged (new in 0.9.3);
  - the Go project's own sub-repositories map by a two-element prefix:
    golang.org/x/<repo> -> github.com/golang/<repo> (new in 0.9.6);
  - a small map of exact vanity paths verified from each project's go.mod
    `module` line (2026-10-17): code.gitea.io/gitea and gitea.dev ->
    go-gitea/gitea; gorm.io/gorm -> go-gorm/gorm; gorm.io/driver/{mysql,
    postgres,sqlite,sqlserver} -> go-gorm/{...}; gorm.io/datatypes ->
    go-gorm/datatypes; gocloud.dev -> google/go-cloud; google.golang.org/grpc
    -> grpc/grpc-go; google.golang.org/protobuf -> protocolbuffers/protobuf-go;
    go.uber.org/{zap,multierr,atomic} -> uber-go/{...}; go.uber.org/yarpc ->
    yarpc/yarpc-go; go.mongodb.org/mongo-driver -> mongodb/mongo-go-driver;
    google.golang.org/api -> googleapis/google-api-go-client;
    google.golang.org/genproto (+ .../googleapis/{api,rpc}) ->
    googleapis/go-genproto; cloud.google.com/go -> googleapis/google-cloud-go;
    go.opentelemetry.io/otel (+ /{trace,metric,sdk}; the whole subtree from
    0.9.9) -> open-telemetry/opentelemetry-go; go.etcd.io/etcd (+ /{api,client,server,
    pkg}) -> etcd-io/etcd; go.etcd.io/bbolt -> etcd-io/bbolt;
    google.golang.org/appengine -> golang/appengine;
    go.opentelemetry.io/collector (the whole subtree from 0.9.9) ->
    open-telemetry/opentelemetry-collector;
    go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp ->
    open-telemetry/opentelemetry-go-contrib;
  - everything else (other golang.org paths, private hosts) stays unmapped, so
    the tool never guesses a repo.

Offline only: no network, no tokens.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import blindspot as bs  # noqa: E402


class TestGopkgInRule(unittest.TestCase):
    def test_short_form(self):
        # gopkg.in/pkg.vN -> github.com/go-pkg/pkg
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/yaml.v3"), "go-yaml/yaml")
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/yaml.v2"), "go-yaml/yaml")
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/ini.v1"), "go-ini/ini")
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/check.v1"), "go-check/check")

    def test_user_form(self):
        # gopkg.in/user/pkg.vN -> github.com/user/pkg
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/natefinch/lumberjack.v2"),
                         "natefinch/lumberjack")
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/square/go-jose.v2"),
                         "square/go-jose")

    def test_nested_subpackage_does_not_change_repo(self):
        self.assertEqual(bs.gopkg_in_repo("gopkg.in/DataDog/dd-trace-go.v1/ddtrace"),
                         "DataDog/dd-trace-go")

    def test_not_gopkg_or_no_version(self):
        self.assertIsNone(bs.gopkg_in_repo("github.com/foo/bar"))
        self.assertIsNone(bs.gopkg_in_repo("gopkg.in/yaml"))   # no .vN selector
        self.assertIsNone(bs.gopkg_in_repo("gopkg.in"))
        self.assertIsNone(bs.gopkg_in_repo(""))
        self.assertIsNone(bs.gopkg_in_repo(None))


class TestGoVanityRepos(unittest.TestCase):
    def test_gitea_release_and_current_module_paths(self):
        # go.mod module line: v1.22.x releases say code.gitea.io/gitea,
        # current main says gitea.dev; both are the same project.
        self.assertEqual(bs.go_module_repo("code.gitea.io/gitea"), "go-gitea/gitea")
        self.assertEqual(bs.go_module_repo("gitea.dev"), "go-gitea/gitea")

    def test_gorm(self):
        self.assertEqual(bs.go_module_repo("gorm.io/gorm"), "go-gorm/gorm")

    def test_major_version_suffix_tolerated(self):
        # A /vN major-version element on a mapped vanity path still resolves.
        self.assertEqual(bs.go_module_repo("code.gitea.io/gitea/v2"), "go-gitea/gitea")

    def test_gopkg_in_routed_through_go_module_repo(self):
        self.assertEqual(bs.go_module_repo("gopkg.in/yaml.v3"), "go-yaml/yaml")
        self.assertEqual(bs.go_module_repo("gopkg.in/natefinch/lumberjack.v2"),
                         "natefinch/lumberjack")

    def test_github_and_unmapped_unchanged(self):
        # Existing behaviour must not regress.
        self.assertEqual(bs.go_module_repo("github.com/gin-gonic/gin"), "gin-gonic/gin")
        self.assertEqual(bs.go_module_repo("github.com/foo/bar/v2"), "foo/bar")
        # Only golang.org/x is a prefix; other golang.org paths stay unmapped.
        self.assertIsNone(bs.go_module_repo("golang.org/dl"))
        self.assertIsNone(bs.go_module_repo("example.com/private/thing"))
        self.assertIsNone(bs.go_module_repo(""))


class TestKubernetesPrefixRule(unittest.TestCase):
    """k8s.io/<repo> -> kubernetes/<repo>, sigs.k8s.io/<repo> ->
    kubernetes-sigs/<repo>. Each module path below was verified from its repo's
    go.mod `module` line on 2026-10-17."""

    def test_k8s_io_modules(self):
        self.assertEqual(bs.go_module_repo("k8s.io/api"), "kubernetes/api")
        self.assertEqual(bs.go_module_repo("k8s.io/apimachinery"),
                         "kubernetes/apimachinery")
        self.assertEqual(bs.go_module_repo("k8s.io/client-go"), "kubernetes/client-go")
        self.assertEqual(bs.go_module_repo("k8s.io/apiserver"), "kubernetes/apiserver")
        self.assertEqual(bs.go_module_repo("k8s.io/kubernetes"), "kubernetes/kubernetes")

    def test_k8s_io_major_version_keeps_repo(self):
        # k8s.io/klog/v2 lives at github.com/kubernetes/klog; the /v2 is the
        # major version, not the repo.
        self.assertEqual(bs.go_module_repo("k8s.io/klog/v2"), "kubernetes/klog")

    def test_k8s_io_subpackage_keeps_repo(self):
        # The repo is the first element after the host; a deeper import path
        # does not change it (go.mod lists the module, but be safe anyway).
        self.assertEqual(bs.go_module_repo("k8s.io/client-go/kubernetes/typed/core/v1"),
                         "kubernetes/client-go")

    def test_sigs_k8s_io_modules(self):
        self.assertEqual(bs.go_module_repo("sigs.k8s.io/yaml"), "kubernetes-sigs/yaml")
        self.assertEqual(bs.go_module_repo("sigs.k8s.io/controller-runtime"),
                         "kubernetes-sigs/controller-runtime")
        self.assertEqual(bs.go_module_repo("sigs.k8s.io/json"), "kubernetes-sigs/json")

    def test_sigs_k8s_io_major_version_keeps_repo(self):
        self.assertEqual(bs.go_module_repo("sigs.k8s.io/structured-merge-diff/v7"),
                         "kubernetes-sigs/structured-merge-diff")

    def test_helper_directly(self):
        self.assertEqual(bs.go_vanity_prefix_repo("k8s.io/api"), "kubernetes/api")
        self.assertEqual(bs.go_vanity_prefix_repo("sigs.k8s.io/yaml"),
                         "kubernetes-sigs/yaml")
        # Not a prefix host, bare host, or empty -> None.
        self.assertIsNone(bs.go_vanity_prefix_repo("github.com/foo/bar"))
        self.assertIsNone(bs.go_vanity_prefix_repo("k8s.io"))
        self.assertIsNone(bs.go_vanity_prefix_repo("k8s.io.evil/foo"))
        self.assertIsNone(bs.go_vanity_prefix_repo(""))
        self.assertIsNone(bs.go_vanity_prefix_repo(None))


class TestGolangOrgXPrefixRule(unittest.TestCase):
    """golang.org/x/<repo> -> github.com/golang/<repo> (new in 0.9.6). Unlike
    the Kubernetes hosts this is a TWO-element prefix (golang.org/x), so the
    repo is the element after it. Verified from the go.mod `module` line of
    golang/{net,crypto,sys,text,oauth2} on 2026-10-17: each reads `module
    golang.org/x/<repo>`."""

    def test_common_x_modules(self):
        self.assertEqual(bs.go_module_repo("golang.org/x/net"), "golang/net")
        self.assertEqual(bs.go_module_repo("golang.org/x/crypto"), "golang/crypto")
        self.assertEqual(bs.go_module_repo("golang.org/x/sys"), "golang/sys")
        self.assertEqual(bs.go_module_repo("golang.org/x/text"), "golang/text")
        self.assertEqual(bs.go_module_repo("golang.org/x/oauth2"), "golang/oauth2")

    def test_subpackage_keeps_repo(self):
        # A deeper import path (golang.org/x/net/http2) is still the net repo.
        self.assertEqual(bs.go_module_repo("golang.org/x/net/http2"), "golang/net")
        self.assertEqual(bs.go_module_repo("golang.org/x/crypto/ssh"), "golang/crypto")

    def test_helper_directly_and_edges(self):
        self.assertEqual(bs.go_vanity_prefix_repo("golang.org/x/net"), "golang/net")
        # golang.org/x with no repo element, or a non-x golang.org path -> None.
        self.assertIsNone(bs.go_vanity_prefix_repo("golang.org/x"))
        self.assertIsNone(bs.go_vanity_prefix_repo("golang.org/dl"))
        # A bare /vN after the prefix is a version, not a repo -> None.
        self.assertIsNone(bs.go_vanity_prefix_repo("golang.org/x/v2"))

    def test_x_blind_spot_end_to_end(self):
        # A golang.org/x/crypto dependency now maps to golang/crypto, so a
        # maintainer advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "golang/crypto": [{
                "ghsa_id": "GHSA-xxxx-0000-0000",
                "cve_id": "CVE-2026-44444",
                "severity": "high",
                "summary": "example golang.org/x/crypto advisory",
                "html_url": "https://github.com/golang/crypto/security/advisories/GHSA-xxxx-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "golang.org/x/crypto"},
                    "vulnerable_version_range": "< 0.31.0",
                    "patched_versions": "0.31.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "golang.org/x/crypto", "v0.30.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "golang/crypto")
        self.assertEqual(f["ghsa_id"], "GHSA-xxxx-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestGormAndGoCloudVanity(unittest.TestCase):
    """Exact vanity entries added in 0.9.3, each verified from the project's
    go.mod `module` line on 2026-10-17."""

    def test_gorm_drivers(self):
        self.assertEqual(bs.go_module_repo("gorm.io/driver/mysql"), "go-gorm/mysql")
        self.assertEqual(bs.go_module_repo("gorm.io/driver/postgres"), "go-gorm/postgres")
        self.assertEqual(bs.go_module_repo("gorm.io/driver/sqlite"), "go-gorm/sqlite")
        self.assertEqual(bs.go_module_repo("gorm.io/driver/sqlserver"),
                         "go-gorm/sqlserver")

    def test_gorm_datatypes(self):
        self.assertEqual(bs.go_module_repo("gorm.io/datatypes"), "go-gorm/datatypes")

    def test_gocloud(self):
        self.assertEqual(bs.go_module_repo("gocloud.dev"), "google/go-cloud")

    def test_unmapped_gorm_path_not_guessed(self):
        # A gorm.io path we did not verify is left unmapped rather than guessed.
        self.assertIsNone(bs.go_module_repo("gorm.io/driver/bogus"))


class TestGrpcProtobufUberMongoVanity(unittest.TestCase):
    """Exact vanity entries added in 0.9.4, each verified from the project's
    go.mod `module` line on 2026-10-17:
      google.golang.org/grpc     -> grpc/grpc-go
      google.golang.org/protobuf -> protocolbuffers/protobuf-go
      go.uber.org/zap            -> uber-go/zap
      go.uber.org/multierr       -> uber-go/multierr
      go.uber.org/atomic         -> uber-go/atomic
      go.uber.org/yarpc          -> yarpc/yarpc-go  (different owner than uber-go)
      go.mongodb.org/mongo-driver -> mongodb/mongo-go-driver
    """

    def test_grpc_and_protobuf(self):
        self.assertEqual(bs.go_module_repo("google.golang.org/grpc"), "grpc/grpc-go")
        self.assertEqual(bs.go_module_repo("google.golang.org/protobuf"),
                         "protocolbuffers/protobuf-go")

    def test_uber_libraries(self):
        self.assertEqual(bs.go_module_repo("go.uber.org/zap"), "uber-go/zap")
        self.assertEqual(bs.go_module_repo("go.uber.org/multierr"), "uber-go/multierr")
        self.assertEqual(bs.go_module_repo("go.uber.org/atomic"), "uber-go/atomic")

    def test_uber_yarpc_is_a_different_owner(self):
        # go.uber.org is NOT a clean prefix host: yarpc lives at yarpc/yarpc-go,
        # not uber-go/yarpc, so this must come from the exact map.
        self.assertEqual(bs.go_module_repo("go.uber.org/yarpc"), "yarpc/yarpc-go")

    def test_uber_unverified_path_not_guessed(self):
        # A go.uber.org package we did not verify is left unmapped, never
        # guessed as uber-go/<name> (which would be wrong for yarpc).
        self.assertIsNone(bs.go_module_repo("go.uber.org/somethingelse"))

    def test_mongo_driver_v1_and_v2(self):
        # v1 module path is go.mongodb.org/mongo-driver; master is v2
        # (go.mongodb.org/mongo-driver/v2). Both live in mongodb/mongo-go-driver;
        # the trailing /vN is stripped before the exact lookup.
        self.assertEqual(bs.go_module_repo("go.mongodb.org/mongo-driver"),
                         "mongodb/mongo-go-driver")
        self.assertEqual(bs.go_module_repo("go.mongodb.org/mongo-driver/v2"),
                         "mongodb/mongo-go-driver")

    def test_grpc_blind_spot_end_to_end(self):
        # A google.golang.org/grpc dependency now maps to grpc/grpc-go, so a
        # maintainer advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "grpc/grpc-go": [{
                "ghsa_id": "GHSA-gggg-0000-0000",
                "cve_id": "CVE-2026-22222",
                "severity": "high",
                "summary": "example google.golang.org/grpc advisory",
                "html_url": "https://github.com/grpc/grpc-go/security/advisories/GHSA-gggg-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "google.golang.org/grpc"},
                    "vulnerable_version_range": "< 1.64.1",
                    "patched_versions": "1.64.1",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "google.golang.org/grpc", "v1.64.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "grpc/grpc-go")
        self.assertEqual(f["ghsa_id"], "GHSA-gggg-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestGoogleOtelEtcdVanity(unittest.TestCase):
    """Exact vanity entries added in 0.9.5, each verified from the project's
    go.mod `module` line on 2026-10-17:
      google.golang.org/api                       -> googleapis/google-api-go-client
      google.golang.org/genproto                  -> googleapis/go-genproto
      google.golang.org/genproto/googleapis/api   -> googleapis/go-genproto
      google.golang.org/genproto/googleapis/rpc   -> googleapis/go-genproto
      cloud.google.com/go                         -> googleapis/google-cloud-go
      go.opentelemetry.io/otel{,/trace,/metric,/sdk} -> open-telemetry/opentelemetry-go
      go.etcd.io/etcd{,/api,/client,/server,/pkg} -> etcd-io/etcd
      go.etcd.io/bbolt                            -> etcd-io/bbolt

    cloud.google.com/go and go.etcd.io/etcd became monorepo prefixes in 0.9.7
    (see TestGoVanityMonorepoPrefix); the assertions here still hold and guard
    against regressing the root and sub-module mappings.
    """

    def test_google_api_and_genproto(self):
        self.assertEqual(bs.go_module_repo("google.golang.org/api"),
                         "googleapis/google-api-go-client")
        self.assertEqual(bs.go_module_repo("google.golang.org/genproto"),
                         "googleapis/go-genproto")
        self.assertEqual(bs.go_module_repo("google.golang.org/genproto/googleapis/api"),
                         "googleapis/go-genproto")
        self.assertEqual(bs.go_module_repo("google.golang.org/genproto/googleapis/rpc"),
                         "googleapis/go-genproto")

    def test_google_golang_org_is_not_a_prefix(self):
        # grpc, protobuf, api and genproto all live in DIFFERENT repos, so the
        # host must never be treated as a prefix; an unverified path stays None.
        self.assertEqual(bs.go_module_repo("google.golang.org/grpc"), "grpc/grpc-go")
        self.assertEqual(bs.go_module_repo("google.golang.org/api"),
                         "googleapis/google-api-go-client")
        self.assertIsNone(bs.go_module_repo("google.golang.org/somethingelse"))

    def test_cloud_google_com_go(self):
        self.assertEqual(bs.go_module_repo("cloud.google.com/go"),
                         "googleapis/google-cloud-go")
        # From 0.9.7 the whole cloud.google.com/go subtree is a verified
        # monorepo prefix (see TestGoVanityMonorepoPrefix), so sub-modules map
        # too; this is no longer a "stays unmapped" case.
        self.assertEqual(bs.go_module_repo("cloud.google.com/go/storage"),
                         "googleapis/google-cloud-go")

    def test_opentelemetry(self):
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/otel"),
                         "open-telemetry/opentelemetry-go")
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/otel/trace"),
                         "open-telemetry/opentelemetry-go")
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/otel/metric"),
                         "open-telemetry/opentelemetry-go")
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/otel/sdk"),
                         "open-telemetry/opentelemetry-go")

    def test_opentelemetry_host_is_not_a_prefix(self):
        # go.opentelemetry.io itself is not one repo: only its verified subtrees
        # map (contrib from 0.9.8, otel/collector/proto/auto/ebpf-profiler from
        # 0.9.9; see TestGoVanityMonorepoPrefix and TestOtelSubtreeMonorepos), so
        # any OTHER, unverified go.opentelemetry.io path is left unmapped, never
        # guessed.
        self.assertIsNone(bs.go_module_repo("go.opentelemetry.io/somethingelse"))
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/contrib"),
                         "open-telemetry/opentelemetry-go-contrib")

    def test_etcd_root_and_submodules_with_major_version(self):
        # Every etcd module is a /vN module (go.etcd.io/etcd/v3,
        # go.etcd.io/etcd/client/v3, ...); the trailing /vN is stripped before
        # the exact lookup, so the base path must be the map key.
        self.assertEqual(bs.go_module_repo("go.etcd.io/etcd/v3"), "etcd-io/etcd")
        self.assertEqual(bs.go_module_repo("go.etcd.io/etcd/api/v3"), "etcd-io/etcd")
        self.assertEqual(bs.go_module_repo("go.etcd.io/etcd/client/v3"), "etcd-io/etcd")
        self.assertEqual(bs.go_module_repo("go.etcd.io/etcd/client/v2"), "etcd-io/etcd")
        self.assertEqual(bs.go_module_repo("go.etcd.io/etcd/server/v3"), "etcd-io/etcd")
        self.assertEqual(bs.go_module_repo("go.etcd.io/etcd/pkg/v3"), "etcd-io/etcd")

    def test_etcd_bbolt_is_a_different_repo(self):
        # go.etcd.io is NOT a prefix host: bbolt lives at etcd-io/bbolt, not
        # etcd-io/etcd, so it must come from its own exact entry.
        self.assertEqual(bs.go_module_repo("go.etcd.io/bbolt"), "etcd-io/bbolt")

    def test_etcd_unverified_path_not_guessed(self):
        self.assertIsNone(bs.go_module_repo("go.etcd.io/somethingelse"))

    def test_otel_blind_spot_end_to_end(self):
        # A go.opentelemetry.io/otel dependency now maps to
        # open-telemetry/opentelemetry-go, so a maintainer advisory OSV does not
        # report is surfaced (fully offline).
        advisories = {
            "open-telemetry/opentelemetry-go": [{
                "ghsa_id": "GHSA-oooo-0000-0000",
                "cve_id": "CVE-2026-33333",
                "severity": "high",
                "summary": "example go.opentelemetry.io/otel advisory",
                "html_url": "https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-oooo-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "go.opentelemetry.io/otel"},
                    "vulnerable_version_range": "< 1.28.0",
                    "patched_versions": "1.28.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "go.opentelemetry.io/otel", "v1.27.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "open-telemetry/opentelemetry-go")
        self.assertEqual(f["ghsa_id"], "GHSA-oooo-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestAppengineCollectorContribVanity(unittest.TestCase):
    """Exact vanity entries added in 0.9.6, each verified from the project's
    go.mod `module` line on 2026-10-17:
      google.golang.org/appengine                 -> golang/appengine
      go.opentelemetry.io/collector               -> open-telemetry/opentelemetry-collector

    The net/http otelhttp module had its own exact entry in 0.9.6; 0.9.8 replaced
    it with the go.opentelemetry.io/contrib monorepo prefix, which now covers the
    whole contrib subtree (see TestGoVanityMonorepoPrefix). otelhttp still
    resolves; the assertion below is kept as a regression guard.
    """

    def test_appengine_v1_and_v2(self):
        self.assertEqual(bs.go_module_repo("google.golang.org/appengine"),
                         "golang/appengine")
        # v2 module path is google.golang.org/appengine/v2; /vN stripped before
        # the exact lookup.
        self.assertEqual(bs.go_module_repo("google.golang.org/appengine/v2"),
                         "golang/appengine")

    def test_otel_collector(self):
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/collector"),
                         "open-telemetry/opentelemetry-collector")

    def test_otelhttp_contrib_module_still_resolves(self):
        # Still maps to the contrib repo, now via the monorepo prefix (0.9.8)
        # rather than the exact entry it had in 0.9.6.
        self.assertEqual(
            bs.go_module_repo("go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"),
            "open-telemetry/opentelemetry-go-contrib")

    def test_collector_is_outside_the_contrib_prefix(self):
        # The collector shares the go.opentelemetry.io host but is NOT under the
        # contrib/ prefix, so it keeps its own (different) repo.
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/collector"),
                         "open-telemetry/opentelemetry-collector")
        self.assertNotEqual(bs.go_module_repo("go.opentelemetry.io/collector"),
                            "open-telemetry/opentelemetry-go-contrib")


class TestVanityBlindSpotEndToEnd(unittest.TestCase):
    """A gopkg.in dependency now maps to a repo, so a maintainer advisory OSV
    does not report is surfaced as a blind spot (fully offline)."""

    def test_gopkg_in_dependency_blind_spot(self):
        advisories = {
            "go-yaml/yaml": [{
                "ghsa_id": "GHSA-yyyy-0000-0000",
                "cve_id": "CVE-2026-00000",
                "severity": "high",
                "summary": "example gopkg.in/yaml.v3 advisory",
                "html_url": "https://github.com/go-yaml/yaml/security/advisories/GHSA-yyyy-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "gopkg.in/yaml.v3"},
                    "vulnerable_version_range": "< 3.0.2",
                    "patched_versions": "3.0.2",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "gopkg.in/yaml.v3", "v3.0.1")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "go-yaml/yaml")
        self.assertEqual(f["ghsa_id"], "GHSA-yyyy-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertTrue(f["package_named"])
        self.assertFalse(f["scanner_visible"])

    def test_k8s_dependency_blind_spot(self):
        # A k8s.io module now maps to kubernetes/<repo>, so a maintainer
        # advisory OSV does not report for that package is a blind spot.
        advisories = {
            "kubernetes/apimachinery": [{
                "ghsa_id": "GHSA-kkkk-0000-0000",
                "cve_id": "CVE-2026-11111",
                "severity": "high",
                "summary": "example k8s.io/apimachinery advisory",
                "html_url": "https://github.com/kubernetes/apimachinery/security/advisories/GHSA-kkkk-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "k8s.io/apimachinery"},
                    "vulnerable_version_range": "< 0.29.1",
                    "patched_versions": "0.29.1",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "k8s.io/apimachinery", "v0.29.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "kubernetes/apimachinery")
        self.assertEqual(f["ghsa_id"], "GHSA-kkkk-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestGoVanityMonorepoPrefix(unittest.TestCase):
    """New in 0.9.7: a monorepo-prefix rule. A module whose path is the prefix
    itself or begins with "<prefix>/" maps to ONE fixed repo, whatever follows
    (unlike the owner-prefix rule, where the repo is the element after the
    prefix). Verified from the go.mod `module` line of the root and several
    sub-modules on 2026-10-17:
      cloud.google.com/go{,/storage,/pubsub,/bigquery,/compute/metadata}
                                                  -> googleapis/google-cloud-go
      go.etcd.io/etcd{,/api,/client,/server,/pkg,/etcdctl,/etcdutl} -> etcd-io/etcd
      go.opentelemetry.io/contrib{,/instrumentation/net/http/otelhttp,
        /instrumentation/google.golang.org/grpc/otelgrpc,/exporters/autoexport,
        /detectors/gcp}                           -> open-telemetry/opentelemetry-go-contrib
                                                     (new in 0.9.8)
    """

    def test_cloud_google_root_and_submodules(self):
        self.assertEqual(bs.go_module_repo("cloud.google.com/go"),
                         "googleapis/google-cloud-go")
        for sub in ("storage", "pubsub", "bigquery", "firestore", "spanner"):
            self.assertEqual(bs.go_module_repo("cloud.google.com/go/" + sub),
                             "googleapis/google-cloud-go")

    def test_cloud_google_deep_path_and_major_version(self):
        # A deeper import path (compute/metadata, verified) and a /vN major
        # version both stay in the one monorepo.
        self.assertEqual(bs.go_module_repo("cloud.google.com/go/compute/metadata"),
                         "googleapis/google-cloud-go")
        self.assertEqual(bs.go_module_repo("cloud.google.com/go/pubsub/v2"),
                         "googleapis/google-cloud-go")

    def test_etcd_submodules_including_new_ones(self):
        # The five sub-modules mapped before plus etcdctl/etcdutl (verified in
        # 0.9.7) now all come from the one monorepo prefix; each is a /vN module.
        for path in ("go.etcd.io/etcd/v3", "go.etcd.io/etcd/api/v3",
                     "go.etcd.io/etcd/client/v3", "go.etcd.io/etcd/server/v3",
                     "go.etcd.io/etcd/pkg/v3", "go.etcd.io/etcd/etcdctl/v3",
                     "go.etcd.io/etcd/etcdutl/v3", "go.etcd.io/etcd/tests/v3"):
            self.assertEqual(bs.go_module_repo(path), "etcd-io/etcd")

    def test_etcd_sibling_repos_not_caught_by_prefix(self):
        # bbolt and raft are different repos outside the go.etcd.io/etcd/ prefix;
        # the monorepo helper must not claim them. Both still resolve via their
        # own exact entries (bbolt since 0.9.5, raft since 0.9.10).
        self.assertIsNone(bs.go_vanity_monorepo_repo("go.etcd.io/bbolt"))
        self.assertIsNone(bs.go_vanity_monorepo_repo("go.etcd.io/raft"))
        self.assertEqual(bs.go_module_repo("go.etcd.io/bbolt"), "etcd-io/bbolt")
        self.assertEqual(bs.go_module_repo("go.etcd.io/raft"), "etcd-io/raft")

    def test_otel_contrib_root_and_submodules(self):
        # Root plus the four sub-modules verified from their go.mod `module`
        # line (2026-10-17), spanning instrumentation, exporters and detectors.
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/contrib"),
                         "open-telemetry/opentelemetry-go-contrib")
        for sub in ("instrumentation/net/http/otelhttp",
                    "instrumentation/google.golang.org/grpc/otelgrpc",
                    "exporters/autoexport", "detectors/gcp"):
            self.assertEqual(bs.go_module_repo("go.opentelemetry.io/contrib/" + sub),
                             "open-telemetry/opentelemetry-go-contrib")

    def test_otel_contrib_siblings_outside_prefix(self):
        # The otel core and the collector share the go.opentelemetry.io host but
        # are NOT under the contrib/ prefix, so they never resolve to the contrib
        # repo; since 0.9.9 each is its own monorepo prefix with its own repo.
        self.assertEqual(bs.go_vanity_monorepo_repo("go.opentelemetry.io/otel"),
                         "open-telemetry/opentelemetry-go")
        self.assertEqual(bs.go_vanity_monorepo_repo("go.opentelemetry.io/collector"),
                         "open-telemetry/opentelemetry-collector")
        self.assertIsNone(bs.go_vanity_monorepo_repo("go.opentelemetry.io/contribfoo"))
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/otel"),
                         "open-telemetry/opentelemetry-go")
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/collector"),
                         "open-telemetry/opentelemetry-collector")

    def test_helper_directly_and_edges(self):
        self.assertEqual(bs.go_vanity_monorepo_repo("cloud.google.com/go/storage"),
                         "googleapis/google-cloud-go")
        self.assertEqual(bs.go_vanity_monorepo_repo("go.etcd.io/etcd/api/v3"),
                         "etcd-io/etcd")
        self.assertEqual(
            bs.go_vanity_monorepo_repo("go.opentelemetry.io/contrib/detectors/gcp"),
            "open-telemetry/opentelemetry-go-contrib")
        # A host that merely shares a prefix string but not a path boundary must
        # not match (startswith is anchored on "<prefix>/" or the exact prefix).
        self.assertIsNone(bs.go_vanity_monorepo_repo("cloud.google.com/godzilla"))
        self.assertIsNone(bs.go_vanity_monorepo_repo("go.etcd.io/etcdfoo"))
        self.assertIsNone(bs.go_vanity_monorepo_repo("github.com/foo/bar"))
        self.assertIsNone(bs.go_vanity_monorepo_repo(""))
        self.assertIsNone(bs.go_vanity_monorepo_repo(None))

    def test_cloud_storage_blind_spot_end_to_end(self):
        # A cloud.google.com/go/storage dependency now maps to the monorepo, so a
        # maintainer advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "googleapis/google-cloud-go": [{
                "ghsa_id": "GHSA-cccc-0000-0000",
                "cve_id": "CVE-2026-55555",
                "severity": "high",
                "summary": "example cloud.google.com/go/storage advisory",
                "html_url": "https://github.com/googleapis/google-cloud-go/security/advisories/GHSA-cccc-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "cloud.google.com/go/storage"},
                    "vulnerable_version_range": "< 1.40.0",
                    "patched_versions": "1.40.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "cloud.google.com/go/storage", "v1.39.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "googleapis/google-cloud-go")
        self.assertEqual(f["ghsa_id"], "GHSA-cccc-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])

    def test_otel_contrib_blind_spot_end_to_end(self):
        # A go.opentelemetry.io/contrib instrumentation module now maps to the
        # contrib monorepo, so a maintainer advisory OSV does not report is
        # surfaced (fully offline).
        advisories = {
            "open-telemetry/opentelemetry-go-contrib": [{
                "ghsa_id": "GHSA-tttt-0000-0000",
                "cve_id": "CVE-2026-66666",
                "severity": "high",
                "summary": "example go.opentelemetry.io/contrib advisory",
                "html_url": "https://github.com/open-telemetry/opentelemetry-go-contrib/security/advisories/GHSA-tttt-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go",
                                "name": "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"},
                    "vulnerable_version_range": "< 0.44.0",
                    "patched_versions": "0.44.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp",
              "v0.43.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "open-telemetry/opentelemetry-go-contrib")
        self.assertEqual(f["ghsa_id"], "GHSA-tttt-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestOtelSubtreeMonorepos(unittest.TestCase):
    """New in 0.9.9: every go.opentelemetry.io subtree is a monorepo prefix.
    OpenTelemetry's own vanity-URL config (open-telemetry/
    opentelemetry-go-vanityurls, go.opentelemetry.io/vanity.yaml, read
    2026-10-17) maps each top-level path to one repo and no deeper path to any
    other repo. Verified from each go.mod `module` line on 2026-10-17:
      go.opentelemetry.io/otel{,/sdk/metric,/log,/exporters/prometheus,
        /exporters/otlp/otlptrace/otlptracegrpc} -> open-telemetry/opentelemetry-go
      go.opentelemetry.io/collector{,/pdata,/component,/confmap}
                                    -> open-telemetry/opentelemetry-collector
      go.opentelemetry.io/proto/otlp -> open-telemetry/opentelemetry-proto-go
      go.opentelemetry.io/auto       -> open-telemetry/opentelemetry-go-instrumentation
      go.opentelemetry.io/ebpf-profiler -> open-telemetry/opentelemetry-ebpf-profiler
    Before 0.9.9 only otel{,/trace,/metric,/sdk} and the bare collector had
    exact entries, so e.g. otel/sdk/metric and collector/pdata were unmapped.
    """

    def test_otel_core_submodules(self):
        for sub in ("", "/trace", "/metric", "/sdk", "/sdk/metric", "/log",
                    "/exporters/prometheus",
                    "/exporters/otlp/otlptrace/otlptracegrpc"):
            self.assertEqual(bs.go_module_repo("go.opentelemetry.io/otel" + sub),
                             "open-telemetry/opentelemetry-go")

    def test_collector_submodules(self):
        for sub in ("", "/pdata", "/component", "/confmap"):
            self.assertEqual(bs.go_module_repo("go.opentelemetry.io/collector" + sub),
                             "open-telemetry/opentelemetry-collector")

    def test_proto_auto_ebpf_profiler(self):
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/proto/otlp"),
                         "open-telemetry/opentelemetry-proto-go")
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/auto"),
                         "open-telemetry/opentelemetry-go-instrumentation")
        self.assertEqual(bs.go_module_repo("go.opentelemetry.io/ebpf-profiler"),
                         "open-telemetry/opentelemetry-ebpf-profiler")

    def test_subtrees_do_not_bleed_into_each_other(self):
        # Path-boundary anchored: otelc (a different repo) is not under otel/,
        # and collector-contrib is not under collector/; neither is mapped here.
        self.assertIsNone(bs.go_vanity_monorepo_repo("go.opentelemetry.io/otelc"))
        self.assertIsNone(bs.go_module_repo("go.opentelemetry.io/otelc"))
        self.assertIsNone(
            bs.go_vanity_monorepo_repo("go.opentelemetry.io/collector-contrib"))
        # Longest prefix: contrib stays contrib, not otel.
        self.assertEqual(
            bs.go_module_repo("go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"),
            "open-telemetry/opentelemetry-go-contrib")

    def test_collector_contrib_maps_as_a_direct_github_module(self):
        # Its go.mod module paths are github.com/... (root and
        # receiver/prometheusreceiver checked), so it maps by the GitHub rule.
        self.assertEqual(
            bs.go_module_repo("github.com/open-telemetry/opentelemetry-collector-contrib"
                              "/receiver/prometheusreceiver"),
            "open-telemetry/opentelemetry-collector-contrib")

    def test_otel_sdk_metric_blind_spot_end_to_end(self):
        # go.opentelemetry.io/otel/sdk/metric was unmapped before 0.9.9; it now
        # maps to the core repo, so a maintainer advisory OSV does not report is
        # surfaced (fully offline).
        advisories = {
            "open-telemetry/opentelemetry-go": [{
                "ghsa_id": "GHSA-mmmm-0000-0000",
                "cve_id": "CVE-2026-77777",
                "severity": "high",
                "summary": "example go.opentelemetry.io/otel/sdk/metric advisory",
                "html_url": "https://github.com/open-telemetry/opentelemetry-go/security/advisories/GHSA-mmmm-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go",
                                "name": "go.opentelemetry.io/otel/sdk/metric"},
                    "vulnerable_version_range": "< 1.30.0",
                    "patched_versions": "1.30.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "go.opentelemetry.io/otel/sdk/metric", "v1.29.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "open-telemetry/opentelemetry-go")
        self.assertEqual(f["ghsa_id"], "GHSA-mmmm-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestHelmTailscaleRaftVanity(unittest.TestCase):
    """New in 0.9.10, each verified from the project's go.mod `module` line
    (2026-10-17):
      helm.sh/helm      -> helm/helm        (exact; main reads
                           `module helm.sh/helm/v4`, dev-v3 reads
                           `module helm.sh/helm/v3`; both in helm/helm)
      tailscale.com     -> tailscale/tailscale  (monorepo prefix; one module
                           whose path is the bare host, every sub-package inside)
      go.etcd.io/raft   -> etcd-io/raft     (exact; `module go.etcd.io/raft/v3`,
                           outside the go.etcd.io/etcd/ monorepo prefix)
    """

    def test_helm_major_versions(self):
        # Helm's module path carries a major-version element; the trailing /vN is
        # stripped before the exact lookup, so v3 and v4 both resolve to helm/helm.
        self.assertEqual(bs.go_module_repo("helm.sh/helm/v3"), "helm/helm")
        self.assertEqual(bs.go_module_repo("helm.sh/helm/v4"), "helm/helm")
        self.assertEqual(bs.go_module_repo("helm.sh/helm"), "helm/helm")

    def test_helm_unverified_path_not_guessed(self):
        # Only helm.sh/helm is mapped; another helm.sh path is left unmapped.
        self.assertIsNone(bs.go_module_repo("helm.sh/somethingelse"))

    def test_tailscale_monorepo(self):
        self.assertEqual(bs.go_module_repo("tailscale.com"), "tailscale/tailscale")
        for sub in ("cmd/tailscale", "ipn", "tsnet", "client/tailscale"):
            self.assertEqual(bs.go_module_repo("tailscale.com/" + sub),
                             "tailscale/tailscale")

    def test_tailscale_helper_and_path_boundary(self):
        self.assertEqual(bs.go_vanity_monorepo_repo("tailscale.com/tsnet"),
                         "tailscale/tailscale")
        # A host that merely shares the prefix string but not a path boundary
        # must not match.
        self.assertIsNone(bs.go_vanity_monorepo_repo("tailscale.com.evil/foo"))
        self.assertIsNone(bs.go_module_repo("tailscale.community/foo"))

    def test_etcd_raft_major_version(self):
        self.assertEqual(bs.go_module_repo("go.etcd.io/raft"), "etcd-io/raft")
        self.assertEqual(bs.go_module_repo("go.etcd.io/raft/v3"), "etcd-io/raft")
        # raft is an exact entry, NOT caught by the go.etcd.io/etcd monorepo
        # prefix (so it never resolves to etcd-io/etcd by accident).
        self.assertIsNone(bs.go_vanity_monorepo_repo("go.etcd.io/raft/v3"))

    def test_helm_blind_spot_end_to_end(self):
        # A helm.sh/helm/v3 dependency now maps to helm/helm, so a maintainer
        # advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "helm/helm": [{
                "ghsa_id": "GHSA-hhhh-0000-0000",
                "cve_id": "CVE-2026-88888",
                "severity": "high",
                "summary": "example helm.sh/helm advisory",
                "html_url": "https://github.com/helm/helm/security/advisories/GHSA-hhhh-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "helm.sh/helm/v3"},
                    "vulnerable_version_range": "< 3.16.0",
                    "patched_versions": "3.16.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "helm.sh/helm/v3", "v3.15.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "helm/helm")
        self.assertEqual(f["ghsa_id"], "GHSA-hhhh-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestIstioCueOrasConnectVanity(unittest.TestCase):
    """New in 0.9.11, each verified from the project's go.mod `module` line
    (2026-10-18):
      istio.io/<repo>   -> istio/<repo>     (owner prefix; istio/{istio,api,
                           client-go,pkg} each read `module istio.io/<repo>`)
      cuelang.org/go    -> cue-lang/cue     (exact; `module cuelang.org/go`)
      oras.land/oras-go -> oras-project/oras-go  (exact; v2.6.0 reads
                           `module oras.land/oras-go/v2`)
      connectrpc.com/{connect,otelconnect,grpcreflect}
                        -> connectrpc/{connect-go,otelconnect-go,grpcreflect-go}
                           (exact; repo names carry a -go suffix)
    """

    def test_istio_owner_prefix(self):
        for repo in ("istio", "api", "client-go", "pkg"):
            self.assertEqual(bs.go_module_repo("istio.io/" + repo),
                             "istio/" + repo)

    def test_istio_subpackage_keeps_repo(self):
        self.assertEqual(bs.go_module_repo("istio.io/istio/pkg/config"),
                         "istio/istio")
        self.assertEqual(bs.go_module_repo("istio.io/api/networking/v1"),
                         "istio/api")
        self.assertEqual(bs.go_vanity_prefix_repo("istio.io/client-go"),
                         "istio/client-go")

    def test_istio_edges(self):
        # The bare host and a bare major version name no repo; a host that only
        # shares the prefix string is a different host.
        self.assertIsNone(bs.go_vanity_prefix_repo("istio.io"))
        self.assertIsNone(bs.go_vanity_prefix_repo("istio.io/v2"))
        self.assertIsNone(bs.go_module_repo("istio.io.evil/istio"))
        self.assertIsNone(bs.go_vanity_monorepo_repo("istio.io/istio"))

    def test_cue(self):
        self.assertEqual(bs.go_module_repo("cuelang.org/go"), "cue-lang/cue")
        # Only the verified module is mapped; another cuelang.org path is not.
        self.assertIsNone(bs.go_module_repo("cuelang.org/other"))

    def test_oras_v1_v2_and_current_github_path(self):
        self.assertEqual(bs.go_module_repo("oras.land/oras-go"),
                         "oras-project/oras-go")
        self.assertEqual(bs.go_module_repo("oras.land/oras-go/v2"),
                         "oras-project/oras-go")
        # main's current module path is a github.com path, already mapped.
        self.assertEqual(bs.go_module_repo("github.com/oras-project/oras-go/v3"),
                         "oras-project/oras-go")
        self.assertIsNone(bs.go_module_repo("oras.land/oras"))

    def test_connect_modules_and_major_versions(self):
        self.assertEqual(bs.go_module_repo("connectrpc.com/connect"),
                         "connectrpc/connect-go")
        self.assertEqual(bs.go_module_repo("connectrpc.com/connect/v2"),
                         "connectrpc/connect-go")
        self.assertEqual(bs.go_module_repo("connectrpc.com/otelconnect"),
                         "connectrpc/otelconnect-go")
        self.assertEqual(bs.go_module_repo("connectrpc.com/grpcreflect/v2"),
                         "connectrpc/grpcreflect-go")

    def test_connect_host_is_not_a_prefix(self):
        # connectrpc.com/<x> does not map to connectrpc/<x>, so an unverified
        # path is left unmapped rather than guessed.
        self.assertIsNone(bs.go_module_repo("connectrpc.com/vanguard"))
        self.assertIsNone(bs.go_vanity_prefix_repo("connectrpc.com/connect"))

    def test_istio_blind_spot_end_to_end(self):
        # An istio.io/istio dependency now maps to istio/istio, so a maintainer
        # advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "istio/istio": [{
                "ghsa_id": "GHSA-iiii-0000-0000",
                "cve_id": "CVE-2026-77777",
                "severity": "high",
                "summary": "example istio.io/istio advisory",
                "html_url": "https://github.com/istio/istio/security/advisories/GHSA-iiii-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "istio.io/istio"},
                    "vulnerable_version_range": "< 1.27.0",
                    "patched_versions": "1.27.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "istio.io/istio", "v1.26.2")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "istio/istio")
        self.assertEqual(f["ghsa_id"], "GHSA-iiii-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestMergoAgeStaticcheckVanity(unittest.TestCase):
    """New in 0.9.12, each verified from the project's go.mod `module` line
    (2026-10-18). All are widely-used transitive dependencies on vanity hosts
    that are neither prefix hosts nor monorepos, so each is an exact entry; a
    trailing /vN is stripped before the lookup:
      dario.cat/mergo          -> darccio/mergo
      filippo.io/age           -> FiloSottile/age
      filippo.io/edwards25519  -> FiloSottile/edwards25519
      honnef.co/go/tools       -> dominikh/go-tools
      gotest.tools (/v3)       -> gotestyourself/gotest.tools
      go.starlark.net          -> google/starlark-go
      mvdan.cc/sh (/v3)        -> mvdan/sh
    """

    def test_mergo(self):
        self.assertEqual(bs.go_module_repo("dario.cat/mergo"), "darccio/mergo")

    def test_filippo_modules(self):
        self.assertEqual(bs.go_module_repo("filippo.io/age"), "FiloSottile/age")
        self.assertEqual(bs.go_module_repo("filippo.io/edwards25519"),
                         "FiloSottile/edwards25519")

    def test_filippo_is_not_a_prefix(self):
        # filippo.io is NOT an owner prefix: only the two verified paths are
        # mapped, an unverified filippo.io path is left unmapped, not guessed.
        self.assertIsNone(bs.go_module_repo("filippo.io/somethingelse"))
        self.assertIsNone(bs.go_vanity_prefix_repo("filippo.io/age"))

    def test_staticcheck_tools(self):
        self.assertEqual(bs.go_module_repo("honnef.co/go/tools"),
                         "dominikh/go-tools")
        self.assertIsNone(bs.go_module_repo("honnef.co/go/somethingelse"))

    def test_gotest_tools_bare_and_v3(self):
        # The current module path is gotest.tools/v3 (the /v3 is stripped before
        # the exact lookup); the v1/v2 line was the bare gotest.tools. Both map.
        self.assertEqual(bs.go_module_repo("gotest.tools"),
                         "gotestyourself/gotest.tools")
        self.assertEqual(bs.go_module_repo("gotest.tools/v3"),
                         "gotestyourself/gotest.tools")

    def test_starlark(self):
        self.assertEqual(bs.go_module_repo("go.starlark.net"), "google/starlark-go")
        # A deeper import path still resolves (it is a single-module repo); the
        # exact key is the bare host, and go.starlark.net/syntax is an import
        # inside it, not a separate module, so only the bare host is asserted.
        self.assertIsNone(bs.go_module_repo("go.starlark.example/net"))

    def test_mvdan_sh_bare_and_v3(self):
        # The current module path is mvdan.cc/sh/v3 (the /v3 is stripped before
        # the lookup); the repo is mvdan/sh (the import path lacks the owner).
        self.assertEqual(bs.go_module_repo("mvdan.cc/sh"), "mvdan/sh")
        self.assertEqual(bs.go_module_repo("mvdan.cc/sh/v3"), "mvdan/sh")
        # mvdan.cc is not a prefix host; an unverified mvdan.cc path is not guessed.
        # (gofumpt/xurls/editorconfig became exact entries in 0.9.19 and are tested
        # in TestGonumMvdanRapidVanity below, so an unverified path is used here.)
        self.assertIsNone(bs.go_module_repo("mvdan.cc/unverified"))

    def test_mergo_blind_spot_end_to_end(self):
        # A dario.cat/mergo dependency now maps to darccio/mergo, so a maintainer
        # advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "darccio/mergo": [{
                "ghsa_id": "GHSA-dddd-0000-0000",
                "cve_id": "CVE-2026-99999",
                "severity": "high",
                "summary": "example dario.cat/mergo advisory",
                "html_url": "https://github.com/darccio/mergo/security/advisories/GHSA-dddd-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "dario.cat/mergo"},
                    "vulnerable_version_range": "< 1.0.1",
                    "patched_versions": "1.0.1",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "dario.cat/mergo", "v1.0.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "darccio/mergo")
        self.assertEqual(f["ghsa_id"], "GHSA-dddd-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestEntTemporalGvisorBufYamlVanity(unittest.TestCase):
    """New in 0.9.13, each verified from the project's go.mod `module` line
    (2026-10-18). All are widely-used dependencies on vanity hosts that are
    neither prefix hosts nor monorepos, so each is an exact entry; a trailing
    /vN is stripped before the lookup:
      entgo.io/ent               -> ent/ent
      go.temporal.io/sdk         -> temporalio/sdk-go
      go.temporal.io/api         -> temporalio/api-go
      gvisor.dev/gvisor          -> google/gvisor
      buf.build/go/protovalidate -> bufbuild/protovalidate-go
      go.yaml.in/yaml (/v3,/v4)  -> yaml/go-yaml
    """

    def test_ent(self):
        self.assertEqual(bs.go_module_repo("entgo.io/ent"), "ent/ent")
        # entgo.io is not a prefix host; an unverified path is left unmapped.
        self.assertIsNone(bs.go_module_repo("entgo.io/contrib"))

    def test_temporal_modules(self):
        self.assertEqual(bs.go_module_repo("go.temporal.io/sdk"), "temporalio/sdk-go")
        self.assertEqual(bs.go_module_repo("go.temporal.io/api"), "temporalio/api-go")

    def test_temporal_is_not_a_prefix(self):
        # The repo names carry a -go suffix the import path lacks (sdk -> sdk-go,
        # api -> api-go), so go.temporal.io is NOT an owner prefix: only the two
        # verified paths map, and an unverified one is left unmapped, not guessed.
        self.assertIsNone(bs.go_module_repo("go.temporal.io/somethingelse"))
        self.assertIsNone(bs.go_vanity_prefix_repo("go.temporal.io/sdk"))

    def test_gvisor(self):
        self.assertEqual(bs.go_module_repo("gvisor.dev/gvisor"), "google/gvisor")
        self.assertIsNone(bs.go_module_repo("gvisor.example/gvisor"))

    def test_buf_protovalidate(self):
        self.assertEqual(bs.go_module_repo("buf.build/go/protovalidate"),
                         "bufbuild/protovalidate-go")
        # buf.build/go is not a prefix host; an unverified path is left unmapped.
        self.assertIsNone(bs.go_module_repo("buf.build/go/somethingelse"))

    def test_go_yaml_in_v3_and_v4(self):
        # The go-yaml module moved to go.yaml.in/yaml: v3 reads
        # `module go.yaml.in/yaml/v3`, main reads `.../v4`; both live in
        # yaml/go-yaml and the /vN is stripped before the exact lookup.
        self.assertEqual(bs.go_module_repo("go.yaml.in/yaml"), "yaml/go-yaml")
        self.assertEqual(bs.go_module_repo("go.yaml.in/yaml/v3"), "yaml/go-yaml")
        self.assertEqual(bs.go_module_repo("go.yaml.in/yaml/v4"), "yaml/go-yaml")
        # The older gopkg.in/yaml.vN path still resolves (to go-yaml/yaml) via
        # the gopkg.in rule, unchanged by this addition.
        self.assertEqual(bs.go_module_repo("gopkg.in/yaml.v3"), "go-yaml/yaml")

    def test_ent_blind_spot_end_to_end(self):
        # An entgo.io/ent dependency now maps to ent/ent, so a maintainer
        # advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "ent/ent": [{
                "ghsa_id": "GHSA-eeee-0000-0000",
                "cve_id": "CVE-2026-12121",
                "severity": "high",
                "summary": "example entgo.io/ent advisory",
                "html_url": "https://github.com/ent/ent/security/advisories/GHSA-eeee-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "entgo.io/ent"},
                    "vulnerable_version_range": "< 0.14.0",
                    "patched_versions": "0.14.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "entgo.io/ent", "v0.13.1")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "ent/ent")
        self.assertEqual(f["ghsa_id"], "GHSA-eeee-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestUberOpenCensusCelVanity(unittest.TestCase):
    """New in 0.9.14, each verified from the project's go.mod `module` line
    (2026-10-18). All exact entries:
      go.uber.org/mock         -> uber-go/mock
      go.uber.org/goleak       -> uber-go/goleak
      go.uber.org/automaxprocs -> uber-go/automaxprocs
      go.uber.org/dig          -> uber-go/dig
      go.uber.org/fx           -> uber-go/fx
      go.opencensus.io         -> census-instrumentation/opencensus-go
      cel.dev/expr             -> google/cel-spec
    """

    def test_uber_libraries(self):
        for name in ("mock", "goleak", "automaxprocs", "dig", "fx"):
            self.assertEqual(bs.go_module_repo("go.uber.org/" + name),
                             "uber-go/" + name)

    def test_uber_still_not_a_prefix(self):
        # go.uber.org stays exact-entry only (yarpc has a different owner), so an
        # unverified path is still left unmapped and yarpc is unchanged.
        self.assertIsNone(bs.go_module_repo("go.uber.org/somethingelse"))
        self.assertIsNone(bs.go_vanity_prefix_repo("go.uber.org/fx"))
        self.assertEqual(bs.go_module_repo("go.uber.org/yarpc"), "yarpc/yarpc-go")

    def test_old_golang_mock_path_unchanged(self):
        # The archived original keeps mapping to its own repo by the github.com rule.
        self.assertEqual(bs.go_module_repo("github.com/golang/mock"), "golang/mock")

    def test_opencensus(self):
        self.assertEqual(bs.go_module_repo("go.opencensus.io"),
                         "census-instrumentation/opencensus-go")

    def test_cel_expr(self):
        self.assertEqual(bs.go_module_repo("cel.dev/expr"), "google/cel-spec")
        # cel.dev is not a prefix host; an unverified path is left unmapped.
        self.assertIsNone(bs.go_module_repo("cel.dev/somethingelse"))

    def test_goleak_blind_spot_end_to_end(self):
        # A go.uber.org/goleak dependency now maps to uber-go/goleak, so a
        # maintainer advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "uber-go/goleak": [{
                "ghsa_id": "GHSA-ffff-0000-0000",
                "cve_id": "CVE-2026-12122",
                "severity": "moderate",
                "summary": "example go.uber.org/goleak advisory",
                "html_url": "https://github.com/uber-go/goleak/security/advisories/GHSA-ffff-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "go.uber.org/goleak"},
                    "vulnerable_version_range": "< 1.4.0",
                    "patched_versions": "1.4.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "go.uber.org/goleak", "v1.3.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "uber-go/goleak")
        self.assertEqual(f["ghsa_id"], "GHSA-ffff-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestUberBufStepBlakeVanity(unittest.TestCase):
    """New in 0.9.15, each verified from the project's go.mod `module` line
    (2026-10-18). All exact entries (a trailing /vN is stripped before the
    lookup):
      go.uber.org/ratelimit    -> uber-go/ratelimit
      go.uber.org/nilaway      -> uber-go/nilaway
      go.uber.org/config       -> uber-go/config
      buf.build/go/protoyaml   -> bufbuild/protoyaml-go
      buf.build/go/bufplugin   -> bufbuild/bufplugin-go
      go.step.sm/crypto        -> smallstep/crypto
      lukechampine.com/blake3  -> lukechampine/blake3
    """

    def test_more_uber_libraries(self):
        for name in ("ratelimit", "nilaway", "config"):
            self.assertEqual(bs.go_module_repo("go.uber.org/" + name),
                             "uber-go/" + name)

    def test_uber_still_not_a_prefix(self):
        # go.uber.org remains exact-entry only (yarpc has a different owner), so
        # an unverified path is still left unmapped and yarpc is unchanged.
        self.assertIsNone(bs.go_module_repo("go.uber.org/stillunverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("go.uber.org/config"))
        self.assertEqual(bs.go_module_repo("go.uber.org/yarpc"), "yarpc/yarpc-go")

    def test_buf_build_go_modules(self):
        # The repo names carry a -go suffix the import path lacks, so buf.build/go
        # is NOT a prefix host: only the verified paths map.
        self.assertEqual(bs.go_module_repo("buf.build/go/protoyaml"),
                         "bufbuild/protoyaml-go")
        self.assertEqual(bs.go_module_repo("buf.build/go/bufplugin"),
                         "bufbuild/bufplugin-go")
        # protovalidate (added in 0.9.13) still resolves; an unverified buf.build
        # path is left unmapped.
        self.assertEqual(bs.go_module_repo("buf.build/go/protovalidate"),
                         "bufbuild/protovalidate-go")
        self.assertIsNone(bs.go_module_repo("buf.build/go/stillunverified"))

    def test_step_crypto(self):
        self.assertEqual(bs.go_module_repo("go.step.sm/crypto"), "smallstep/crypto")
        # go.step.sm is not a prefix host; an unverified path is left unmapped.
        self.assertIsNone(bs.go_module_repo("go.step.sm/cli"))

    def test_blake3(self):
        self.assertEqual(bs.go_module_repo("lukechampine.com/blake3"),
                         "lukechampine/blake3")
        # frand and uint128 are mapped from 0.9.21 (see
        # TestGormPluginLukechampineBugstVanity); lukechampine.com stays an
        # exact-entry host, so a path we have not verified is still unmapped.
        self.assertIsNone(bs.go_module_repo("lukechampine.com/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("lukechampine.com/blake3"))

    def test_ratelimit_blind_spot_end_to_end(self):
        # A go.uber.org/ratelimit dependency now maps to uber-go/ratelimit, so a
        # maintainer advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "uber-go/ratelimit": [{
                "ghsa_id": "GHSA-rrrr-0000-0000",
                "cve_id": "CVE-2026-13131",
                "severity": "moderate",
                "summary": "example go.uber.org/ratelimit advisory",
                "html_url": "https://github.com/uber-go/ratelimit/security/advisories/GHSA-rrrr-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "go.uber.org/ratelimit"},
                    "vulnerable_version_range": "< 0.3.1",
                    "patched_versions": "0.3.1",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "go.uber.org/ratelimit", "v0.3.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "uber-go/ratelimit")
        self.assertEqual(f["ghsa_id"], "GHSA-rrrr-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestKnativeKubevirtElasticVanity(unittest.TestCase):
    """New in 0.9.16, each verified from the project's go.mod `module` line
    (2026-10-18):
      knative.dev/{serving,pkg,eventing,func} -> knative/{...}  (EXACT entries)
      kubevirt.io/{kubevirt,client-go,api}    -> kubevirt/{...} (EXACT entries)
      go.elastic.co/apm                       -> elastic/apm-agent-go (monorepo)

    knative.dev and kubevirt.io are deliberately NOT owner prefixes: the import
    host does not identify the GitHub owner. knative.dev/eventing-kafka-broker
    reads `module knative.dev/eventing-kafka-broker` but lives at
    knative-extensions/eventing-kafka-broker, not knative/..., so a knative.dev
    owner prefix would map every extension to the wrong owner. Only verified
    core modules are mapped as exact entries; everything else stays unmapped.
    """

    def test_knative_core_exact_entries(self):
        for repo in ("serving", "pkg", "eventing", "func"):
            self.assertEqual(bs.go_module_repo("knative.dev/" + repo),
                             "knative/" + repo)

    def test_knative_is_not_an_owner_prefix(self):
        # An extension module lives under knative-extensions, not knative, so the
        # host must NOT be a prefix: an unverified knative.dev path is left
        # unmapped rather than guessed as knative/<name>.
        self.assertIsNone(bs.go_vanity_prefix_repo("knative.dev/serving"))
        self.assertIsNone(bs.go_module_repo("knative.dev/eventing-kafka-broker"))
        self.assertIsNone(bs.go_module_repo("knative.dev/somethingelse"))

    def test_knative_subpackage_keeps_repo(self):
        # A /vN major version or deeper import path is stripped to the base path
        # before the exact lookup, so it still resolves.
        self.assertEqual(bs.go_module_repo("knative.dev/pkg/v2"), "knative/pkg")

    def test_kubevirt_exact_entries(self):
        self.assertEqual(bs.go_module_repo("kubevirt.io/kubevirt"),
                         "kubevirt/kubevirt")
        self.assertEqual(bs.go_module_repo("kubevirt.io/client-go"),
                         "kubevirt/client-go")
        self.assertEqual(bs.go_module_repo("kubevirt.io/api"), "kubevirt/api")

    def test_kubevirt_is_not_an_owner_prefix(self):
        self.assertIsNone(bs.go_vanity_prefix_repo("kubevirt.io/kubevirt"))
        self.assertIsNone(bs.go_module_repo("kubevirt.io/somethingelse"))

    def test_elastic_apm_monorepo(self):
        # Root (go.elastic.co/apm/v2) and every instrumentation sub-module
        # (go.elastic.co/apm/module/<name>/v2) live in elastic/apm-agent-go.
        self.assertEqual(bs.go_module_repo("go.elastic.co/apm"),
                         "elastic/apm-agent-go")
        self.assertEqual(bs.go_module_repo("go.elastic.co/apm/v2"),
                         "elastic/apm-agent-go")
        self.assertEqual(
            bs.go_module_repo("go.elastic.co/apm/module/apmhttp/v2"),
            "elastic/apm-agent-go")

    def test_elastic_apm_prefix_is_path_boundary_anchored(self):
        # Only the /apm subtree is a monorepo; the bare host is not. ecszap and
        # fastjson are mapped as EXACT entries (added in 0.9.17), not by the
        # monorepo prefix, so the monorepo helper still returns None for them, and
        # a host that merely shares the prefix string does not match.
        self.assertEqual(bs.go_vanity_monorepo_repo("go.elastic.co/apm/module/apmsql/v2"),
                         "elastic/apm-agent-go")
        self.assertIsNone(bs.go_vanity_monorepo_repo("go.elastic.co/ecszap"))
        self.assertIsNone(bs.go_vanity_monorepo_repo("go.elastic.co/apmtest"))
        # An unverified, unmapped go.elastic.co path is still left alone.
        self.assertIsNone(bs.go_module_repo("go.elastic.co/apmtest"))

    def test_knative_blind_spot_end_to_end(self):
        # A knative.dev/serving dependency now maps to knative/serving, so a
        # maintainer advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "knative/serving": [{
                "ghsa_id": "GHSA-knkn-0000-0000",
                "cve_id": "CVE-2026-14141",
                "severity": "high",
                "summary": "example knative.dev/serving advisory",
                "html_url": "https://github.com/knative/serving/security/advisories/GHSA-knkn-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "knative.dev/serving"},
                    "vulnerable_version_range": "< 0.44.0",
                    "patched_versions": "0.44.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "knative.dev/serving", "v0.43.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "knative/serving")
        self.assertEqual(f["ghsa_id"], "GHSA-knkn-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])

    def test_elastic_apm_blind_spot_end_to_end(self):
        # A go.elastic.co/apm/module/apmhttp dependency now maps to the monorepo,
        # so a maintainer advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "elastic/apm-agent-go": [{
                "ghsa_id": "GHSA-elel-0000-0000",
                "cve_id": "CVE-2026-15151",
                "severity": "moderate",
                "summary": "example go.elastic.co/apm advisory",
                "html_url": "https://github.com/elastic/apm-agent-go/security/advisories/GHSA-elel-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go",
                                "name": "go.elastic.co/apm/module/apmhttp/v2"},
                    "vulnerable_version_range": "< 2.6.0",
                    "patched_versions": "2.6.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "go.elastic.co/apm/module/apmhttp/v2", "v2.5.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "elastic/apm-agent-go")
        self.assertEqual(f["ghsa_id"], "GHSA-elel-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestKubevirtElasticNetaddrGo4Vanity(unittest.TestCase):
    """New in 0.9.17, each verified from the project's go.mod `module` line
    (2026-10-18). All exact entries (none of their hosts names the GitHub owner
    for every module, so none is an owner prefix):
      kubevirt.io/containerized-data-importer -> kubevirt/containerized-data-importer
      kubevirt.io/csi-driver                  -> kubevirt/csi-driver
      go.elastic.co/ecszap                    -> elastic/ecs-logging-go-zap
      go.elastic.co/fastjson                  -> elastic/go-fastjson
      inet.af/netaddr                         -> inetaf/netaddr
      go4.org                                 -> go4org/go4
    """

    def test_more_kubevirt_repos(self):
        self.assertEqual(bs.go_module_repo("kubevirt.io/containerized-data-importer"),
                         "kubevirt/containerized-data-importer")
        self.assertEqual(bs.go_module_repo("kubevirt.io/csi-driver"),
                         "kubevirt/csi-driver")
        # The three core kubevirt modules from 0.9.16 still resolve.
        self.assertEqual(bs.go_module_repo("kubevirt.io/kubevirt"), "kubevirt/kubevirt")

    def test_kubevirt_still_not_a_prefix(self):
        # kubevirt.io stays exact-entry only; an unverified path is not guessed.
        self.assertIsNone(bs.go_vanity_prefix_repo("kubevirt.io/csi-driver"))
        self.assertIsNone(bs.go_module_repo("kubevirt.io/stillunverified"))

    def test_elastic_siblings_mapped_as_exact_entries(self):
        # 0.9.16 mapped only the go.elastic.co/apm monorepo subtree and left the
        # bare host unmapped; these two siblings now resolve by exact path.
        self.assertEqual(bs.go_module_repo("go.elastic.co/ecszap"),
                         "elastic/ecs-logging-go-zap")
        self.assertEqual(bs.go_module_repo("go.elastic.co/fastjson"),
                         "elastic/go-fastjson")
        # The /apm monorepo prefix from 0.9.16 is unchanged.
        self.assertEqual(bs.go_module_repo("go.elastic.co/apm/v2"),
                         "elastic/apm-agent-go")
        # go.elastic.co is still NOT a prefix host, and an unverified path stays
        # unmapped; the exact entries are not caught by the monorepo helper.
        self.assertIsNone(bs.go_module_repo("go.elastic.co/stillunverified"))
        self.assertIsNone(bs.go_vanity_monorepo_repo("go.elastic.co/ecszap"))

    def test_netaddr(self):
        self.assertEqual(bs.go_module_repo("inet.af/netaddr"), "inetaf/netaddr")
        # inet.af is not a prefix host; an unverified path is left unmapped.
        self.assertIsNone(bs.go_module_repo("inet.af/somethingelse"))

    def test_go4org(self):
        self.assertEqual(bs.go_module_repo("go4.org"), "go4org/go4")
        # go4.org is NOT an owner prefix: the bare host and its sibling repos are
        # each mapped by their own exact entry, never by a prefix rule. netipx
        # gained its exact entry in 0.9.18 (see TestGo4orgFyneSslmateUberHowettRsc).
        self.assertEqual(bs.go_module_repo("go4.org/netipx"), "go4org/netipx")
        self.assertIsNone(bs.go_vanity_prefix_repo("go4.org/netipx"))
        # A go4.org sibling we have NOT verified is still left unmapped.
        self.assertIsNone(bs.go_module_repo("go4.org/unverified"))

    def test_cdi_blind_spot_end_to_end(self):
        # A kubevirt.io/containerized-data-importer dependency now maps to its
        # repo, so a maintainer advisory OSV does not report is surfaced (offline).
        advisories = {
            "kubevirt/containerized-data-importer": [{
                "ghsa_id": "GHSA-cdcd-0000-0000",
                "cve_id": "CVE-2026-16161",
                "severity": "high",
                "summary": "example kubevirt.io/containerized-data-importer advisory",
                "html_url": "https://github.com/kubevirt/containerized-data-importer/security/advisories/GHSA-cdcd-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go",
                                "name": "kubevirt.io/containerized-data-importer"},
                    "vulnerable_version_range": "< 1.60.0",
                    "patched_versions": "1.60.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "kubevirt.io/containerized-data-importer", "v1.59.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "kubevirt/containerized-data-importer")
        self.assertEqual(f["ghsa_id"], "GHSA-cdcd-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])

    def test_netaddr_blind_spot_end_to_end(self):
        # An inet.af/netaddr dependency now maps to inetaf/netaddr, so a
        # maintainer advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "inetaf/netaddr": [{
                "ghsa_id": "GHSA-nana-0000-0000",
                "cve_id": "CVE-2026-17171",
                "severity": "moderate",
                "summary": "example inet.af/netaddr advisory",
                "html_url": "https://github.com/inetaf/netaddr/security/advisories/GHSA-nana-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "inet.af/netaddr"},
                    "vulnerable_version_range": "<= 0.0.0",
                    "patched_versions": "",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "inet.af/netaddr", None)],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "inetaf/netaddr")
        self.assertEqual(f["ghsa_id"], "GHSA-nana-0000-0000")
        self.assertFalse(f["scanner_visible"])


class TestGo4orgFyneSslmateUberHowettRsc(unittest.TestCase):
    """New in 0.9.18, each verified from the project's go.mod `module` line
    (2026-10-18). All are exact entries; none of their hosts names the GitHub
    owner for every module, so none is an owner prefix:
      go4.org/netipx                     -> go4org/netipx   (sibling of go4org/go4)
      fyne.io/fyne (/v2)                  -> fyne-io/fyne
      software.sslmate.com/src/go-pkcs12 -> SSLMate/go-pkcs12
      go.uber.org/zap/exp                -> uber-go/zap      (submodule in that repo)
      howett.net/plist                   -> DHowett/go-plist
      rsc.io/binaryregexp                -> rsc/binaryregexp
    """

    def test_go4org_netipx_is_its_own_repo(self):
        # netipx is a SEPARATE repo from go4org/go4, not under it. go4.org is
        # not an owner prefix, so this must come from the exact map.
        self.assertEqual(bs.go_module_repo("go4.org/netipx"), "go4org/netipx")
        self.assertEqual(bs.go_module_repo("go4.org"), "go4org/go4")
        self.assertIsNone(bs.go_vanity_prefix_repo("go4.org/netipx"))

    def test_fyne_v1_and_v2(self):
        # Current master is module fyne.io/fyne/v2; the /vN is stripped before the
        # lookup, so the base path fyne.io/fyne is the key and covers both the v1
        # module and the current v2 module. The owner is fyne-io, not fyne.
        self.assertEqual(bs.go_module_repo("fyne.io/fyne/v2"), "fyne-io/fyne")
        self.assertEqual(bs.go_module_repo("fyne.io/fyne"), "fyne-io/fyne")
        # fyne.io is NOT a prefix host (owner fyne-io != host element fyne); an
        # unverified fyne.io path stays unmapped rather than guessed.
        self.assertIsNone(bs.go_module_repo("fyne.io/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("fyne.io/fyne"))

    def test_sslmate_pkcs12(self):
        self.assertEqual(bs.go_module_repo("software.sslmate.com/src/go-pkcs12"),
                         "SSLMate/go-pkcs12")
        self.assertIsNone(bs.go_module_repo("software.sslmate.com/src/unverified"))

    def test_uber_zap_exp_submodule(self):
        # zap/exp is its own Go module living inside the uber-go/zap repo; the
        # exact lookup is on the full module path, so it needs its own entry and
        # is not covered by the go.uber.org/zap entry.
        self.assertEqual(bs.go_module_repo("go.uber.org/zap/exp"), "uber-go/zap")
        self.assertEqual(bs.go_module_repo("go.uber.org/zap"), "uber-go/zap")
        # go.uber.org stays an exact-entry host (yarpc has a different owner), so
        # an unverified go.uber.org path is still not guessed.
        self.assertIsNone(bs.go_module_repo("go.uber.org/stillunverified"))

    def test_howett_plist(self):
        self.assertEqual(bs.go_module_repo("howett.net/plist"), "DHowett/go-plist")
        self.assertIsNone(bs.go_module_repo("howett.net/unverified"))

    def test_rsc_binaryregexp(self):
        self.assertEqual(bs.go_module_repo("rsc.io/binaryregexp"), "rsc/binaryregexp")
        # rsc.io is kept an exact-entry host, not an owner prefix, so an
        # unverified rsc.io path is left unmapped.
        self.assertIsNone(bs.go_module_repo("rsc.io/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("rsc.io/binaryregexp"))

    def test_fyne_blind_spot_end_to_end(self):
        # A fyne.io/fyne/v2 dependency now maps to fyne-io/fyne, so a maintainer
        # advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "fyne-io/fyne": [{
                "ghsa_id": "GHSA-fyfy-0000-0000",
                "cve_id": "CVE-2026-18181",
                "severity": "moderate",
                "summary": "example fyne.io/fyne advisory",
                "html_url": "https://github.com/fyne-io/fyne/security/advisories/GHSA-fyfy-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "fyne.io/fyne/v2"},
                    "vulnerable_version_range": "< 2.5.0",
                    "patched_versions": "2.5.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "fyne.io/fyne/v2", "v2.4.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "fyne-io/fyne")
        self.assertEqual(f["ghsa_id"], "GHSA-fyfy-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestGonumMvdanRapidVanity(unittest.TestCase):
    """New in 0.9.19, each verified from the project's go.mod `module` line
    (2026-10-18). All are exact entries (none of their hosts names the GitHub
    owner for every module, so none is an owner prefix); a trailing /vN is
    stripped before the lookup:
      gonum.org/v1/gonum     -> gonum/gonum
      gonum.org/v1/plot      -> gonum/plot
      mvdan.cc/gofumpt       -> mvdan/gofumpt
      mvdan.cc/xurls (/v2)   -> mvdan/xurls
      mvdan.cc/editorconfig  -> mvdan/editorconfig
      pgregory.net/rapid     -> flyingmutant/rapid
    """

    def test_gonum_libraries(self):
        self.assertEqual(bs.go_module_repo("gonum.org/v1/gonum"), "gonum/gonum")
        self.assertEqual(bs.go_module_repo("gonum.org/v1/plot"), "gonum/plot")
        # A deeper import path keeps the repo (exact entry on the module path,
        # with /vN stripping; a sub-package is not a /vN so it is not mapped here).
        self.assertEqual(bs.go_module_repo("gonum.org/v1/gonum/mat"), None)
        # gonum.org/v1 is NOT an owner prefix; an unverified path stays unmapped.
        self.assertIsNone(bs.go_module_repo("gonum.org/v1/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("gonum.org/v1/gonum"))

    def test_mvdan_modules(self):
        self.assertEqual(bs.go_module_repo("mvdan.cc/gofumpt"), "mvdan/gofumpt")
        self.assertEqual(bs.go_module_repo("mvdan.cc/editorconfig"),
                         "mvdan/editorconfig")
        # xurls ships as a /v2 module; the /vN is stripped before the lookup, so
        # both the base path and the versioned path resolve.
        self.assertEqual(bs.go_module_repo("mvdan.cc/xurls"), "mvdan/xurls")
        self.assertEqual(bs.go_module_repo("mvdan.cc/xurls/v2"), "mvdan/xurls")
        # mvdan.cc is an exact-entry host, not a prefix; sh stays mapped (0.9.12).
        self.assertEqual(bs.go_module_repo("mvdan.cc/sh"), "mvdan/sh")
        self.assertIsNone(bs.go_module_repo("mvdan.cc/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("mvdan.cc/gofumpt"))

    def test_rapid(self):
        self.assertEqual(bs.go_module_repo("pgregory.net/rapid"),
                         "flyingmutant/rapid")
        # pgregory.net is NOT a prefix host (owner is flyingmutant, not pgregory).
        self.assertIsNone(bs.go_module_repo("pgregory.net/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("pgregory.net/rapid"))

    def test_gonum_blind_spot_end_to_end(self):
        # A gonum.org/v1/gonum dependency now maps to gonum/gonum, so a maintainer
        # advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "gonum/gonum": [{
                "ghsa_id": "GHSA-gnum-0000-0000",
                "cve_id": "CVE-2026-19191",
                "severity": "moderate",
                "summary": "example gonum.org/v1/gonum advisory",
                "html_url": "https://github.com/gonum/gonum/security/advisories/GHSA-gnum-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "gonum.org/v1/gonum"},
                    "vulnerable_version_range": "< 0.15.0",
                    "patched_versions": "0.15.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "gonum.org/v1/gonum", "v0.14.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "gonum/gonum")
        self.assertEqual(f["ghsa_id"], "GHSA-gnum-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestGocvZombiezenMautrixGormVanity(unittest.TestCase):
    """0.9.20 additions, each verified from the project's go.mod `module` line
    (2026-10-18):

      gocv.io/x/gocv             -> hybridgroup/gocv
      zombiezen.com/go/sqlite    -> zombiezen/go-sqlite
      maunium.net/go/mautrix     -> mautrix/go
      gorm.io/gen                -> go-gorm/gen
      gorm.io/driver/clickhouse  -> go-gorm/clickhouse
    """

    def test_gocv(self):
        self.assertEqual(bs.go_module_repo("gocv.io/x/gocv"), "hybridgroup/gocv")
        # gocv.io is NOT a prefix host (owner is hybridgroup, not gocv).
        self.assertIsNone(bs.go_module_repo("gocv.io/x/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("gocv.io/x/gocv"))

    def test_zombiezen_sqlite(self):
        self.assertEqual(bs.go_module_repo("zombiezen.com/go/sqlite"),
                         "zombiezen/go-sqlite")
        # zombiezen.com is NOT a prefix host; a sibling path we have not verified
        # (e.g. zombiezen.com/go/log) stays unmapped rather than guessed.
        self.assertIsNone(bs.go_module_repo("zombiezen.com/go/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("zombiezen.com/go/sqlite"))

    def test_mautrix(self):
        self.assertEqual(bs.go_module_repo("maunium.net/go/mautrix"), "mautrix/go")
        # maunium.net is NOT a prefix host (owner is mautrix, repo is go).
        self.assertIsNone(bs.go_module_repo("maunium.net/go/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("maunium.net/go/mautrix"))

    def test_gorm_gen_and_clickhouse_driver(self):
        self.assertEqual(bs.go_module_repo("gorm.io/gen"), "go-gorm/gen")
        self.assertEqual(bs.go_module_repo("gorm.io/driver/clickhouse"),
                         "go-gorm/clickhouse")
        # Existing guard still holds: an unverified gorm.io driver is not guessed.
        self.assertIsNone(bs.go_module_repo("gorm.io/driver/bogus"))
        self.assertIsNone(bs.go_vanity_prefix_repo("gorm.io/gen"))

    def test_gocv_blind_spot_end_to_end(self):
        # A gocv.io/x/gocv dependency now maps to hybridgroup/gocv, so a maintainer
        # advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "hybridgroup/gocv": [{
                "ghsa_id": "GHSA-gocv-0000-0000",
                "cve_id": "CVE-2026-20202",
                "severity": "high",
                "summary": "example gocv.io/x/gocv advisory",
                "html_url": "https://github.com/hybridgroup/gocv/security/advisories/GHSA-gocv-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "gocv.io/x/gocv"},
                    "vulnerable_version_range": "< 0.36.0",
                    "patched_versions": "0.36.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "gocv.io/x/gocv", "v0.35.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "hybridgroup/gocv")
        self.assertEqual(f["ghsa_id"], "GHSA-gocv-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestGormPluginLukechampineBugstVanity(unittest.TestCase):
    """0.9.21 additions, each verified from the project's go.mod `module` line
    (2026-10-18):

      gorm.io/plugin/dbresolver    -> go-gorm/dbresolver
      gorm.io/plugin/opentelemetry -> go-gorm/opentelemetry
      lukechampine.com/uint128     -> lukechampine/uint128
      lukechampine.com/frand       -> lukechampine/frand
      go.bug.st/serial             -> bugst/go-serial
    """

    def test_gorm_plugins(self):
        self.assertEqual(bs.go_module_repo("gorm.io/plugin/dbresolver"),
                         "go-gorm/dbresolver")
        self.assertEqual(bs.go_module_repo("gorm.io/plugin/opentelemetry"),
                         "go-gorm/opentelemetry")
        # gorm.io stays an exact-entry host: an unverified plugin path and an
        # unverified driver path are both left unmapped, never guessed.
        self.assertIsNone(bs.go_module_repo("gorm.io/plugin/unverified"))
        self.assertIsNone(bs.go_module_repo("gorm.io/driver/bogus"))
        self.assertIsNone(bs.go_vanity_prefix_repo("gorm.io/plugin/dbresolver"))

    def test_lukechampine_frand_and_uint128(self):
        self.assertEqual(bs.go_module_repo("lukechampine.com/uint128"),
                         "lukechampine/uint128")
        self.assertEqual(bs.go_module_repo("lukechampine.com/frand"),
                         "lukechampine/frand")
        # blake3 (0.9.15) still resolves; lukechampine.com is NOT a prefix host.
        self.assertEqual(bs.go_module_repo("lukechampine.com/blake3"),
                         "lukechampine/blake3")
        self.assertIsNone(bs.go_module_repo("lukechampine.com/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("lukechampine.com/uint128"))

    def test_bugst_serial(self):
        self.assertEqual(bs.go_module_repo("go.bug.st/serial"), "bugst/go-serial")
        # go.bug.st is NOT a prefix host (owner bugst, repo go-serial); an
        # unverified path is left unmapped.
        self.assertIsNone(bs.go_module_repo("go.bug.st/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("go.bug.st/serial"))

    def test_dbresolver_blind_spot_end_to_end(self):
        # A gorm.io/plugin/dbresolver dependency now maps to go-gorm/dbresolver,
        # so a maintainer advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "go-gorm/dbresolver": [{
                "ghsa_id": "GHSA-dbrs-0000-0000",
                "cve_id": "CVE-2026-21212",
                "severity": "high",
                "summary": "example gorm.io/plugin/dbresolver advisory",
                "html_url": "https://github.com/go-gorm/dbresolver/security/advisories/GHSA-dbrs-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "gorm.io/plugin/dbresolver"},
                    "vulnerable_version_range": "< 1.5.0",
                    "patched_versions": "1.5.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "gorm.io/plugin/dbresolver", "v1.4.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "go-gorm/dbresolver")
        self.assertEqual(f["ghsa_id"], "GHSA-dbrs-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


class TestK6WhatsmeowWoodpeckerFliptBazilVanity(unittest.TestCase):
    """0.9.22 additions, each verified from the project's go.mod `module` line
    (2026-10-18):

      go.k6.io/k6                     -> grafana/k6
      go.mau.fi/whatsmeow             -> tulir/whatsmeow
      go.woodpecker-ci.org/woodpecker -> woodpecker-ci/woodpecker
      go.flipt.io/flipt               -> flipt-io/flipt
      bazil.org/fuse                  -> bazil/fuse
    """

    def test_k6_with_and_without_major_version(self):
        self.assertEqual(bs.go_module_repo("go.k6.io/k6"), "grafana/k6")
        # main reads `module go.k6.io/k6/v2`; the /v2 is stripped.
        self.assertEqual(bs.go_module_repo("go.k6.io/k6/v2"), "grafana/k6")
        self.assertIsNone(bs.go_module_repo("go.k6.io/unverified"))
        self.assertIsNone(bs.go_vanity_prefix_repo("go.k6.io/k6"))

    def test_whatsmeow(self):
        self.assertEqual(bs.go_module_repo("go.mau.fi/whatsmeow"),
                         "tulir/whatsmeow")
        # go.mau.fi is NOT a prefix host (owners differ); unverified paths stay
        # unmapped. maunium.net/go/mautrix (0.9.20) is unaffected.
        self.assertIsNone(bs.go_module_repo("go.mau.fi/unverified"))
        self.assertEqual(bs.go_module_repo("maunium.net/go/mautrix"), "mautrix/go")

    def test_woodpecker(self):
        self.assertEqual(bs.go_module_repo("go.woodpecker-ci.org/woodpecker/v3"),
                         "woodpecker-ci/woodpecker")
        self.assertEqual(bs.go_module_repo("go.woodpecker-ci.org/woodpecker"),
                         "woodpecker-ci/woodpecker")
        self.assertIsNone(bs.go_module_repo("go.woodpecker-ci.org/unverified"))

    def test_flipt_and_bazil_fuse(self):
        self.assertEqual(bs.go_module_repo("go.flipt.io/flipt"), "flipt-io/flipt")
        self.assertEqual(bs.go_module_repo("bazil.org/fuse"), "bazil/fuse")
        self.assertIsNone(bs.go_module_repo("go.flipt.io/unverified"))
        self.assertIsNone(bs.go_module_repo("bazil.org/unverified"))

    def test_linkedca_is_github_canonical(self):
        # go.step.sm/linkedca was checked and NOT added: its go.mod declares
        # github.com/smallstep/linkedca, which the github.com rule maps.
        self.assertIsNone(bs.go_module_repo("go.step.sm/linkedca"))
        self.assertEqual(bs.go_module_repo("github.com/smallstep/linkedca"),
                         "smallstep/linkedca")

    def test_k6_blind_spot_end_to_end(self):
        # A go.k6.io/k6/v2 dependency now maps to grafana/k6, so a maintainer
        # advisory OSV does not report is surfaced (fully offline).
        advisories = {
            "grafana/k6": [{
                "ghsa_id": "GHSA-k6k6-0000-0000",
                "cve_id": "CVE-2026-22222",
                "severity": "high",
                "summary": "example go.k6.io/k6 advisory",
                "html_url": "https://github.com/grafana/k6/security/advisories/GHSA-k6k6-0000-0000",
                "vulnerabilities": [{
                    "package": {"ecosystem": "go", "name": "go.k6.io/k6/v2"},
                    "vulnerable_version_range": "< 2.1.0",
                    "patched_versions": "2.1.0",
                }],
            }],
        }
        resolve = lambda eco, name: bs.go_module_repo(name)
        report = bs.check(
            [("go", "go.k6.io/k6/v2", "v2.0.0")],
            resolve,
            lambda repo: advisories.get(repo, []),
            lambda eco, name, version: set(),   # OSV reports nothing
            lambda vuln_id: set(),
        )
        self.assertEqual(report["mapped_to_repo"], 1)
        self.assertEqual(report["unmapped"], [])
        self.assertEqual(report["blind_spots"], 1)
        f = report["findings"][0]
        self.assertEqual(f["repo"], "grafana/k6")
        self.assertEqual(f["ghsa_id"], "GHSA-k6k6-0000-0000")
        self.assertEqual(f["affects_your_version"], "yes")
        self.assertFalse(f["scanner_visible"])


if __name__ == "__main__":
    unittest.main()
