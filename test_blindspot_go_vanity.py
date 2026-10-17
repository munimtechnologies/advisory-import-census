"""Tests for Go vanity-host module mapping in blindspot.py (v0.9.4).

Before 0.9.2, a Go module whose path was not github.com/OWNER/REPO was always
reported "unmapped", so its maintainer's GitHub repository security advisories
were never checked -- even for gopkg.in packages (in almost every Go project)
and well-known vanity hosts such as Gitea. 0.9.2 added gopkg.in and a small
map of vanity hosts. 0.9.3 adds the whole Kubernetes ecosystem by prefix and a
few more exact vanity entries. 0.9.4 adds exact entries for gRPC, Protobuf, the
go.uber.org libraries and the MongoDB Go driver. These tests pin the behaviour:

  - gopkg.in follows its own documented redirect rule
    (gopkg.in/pkg.vN -> github.com/go-pkg/pkg; gopkg.in/user/pkg.vN ->
    github.com/user/pkg), verified at https://gopkg.in (2026-10-17);
  - the Kubernetes vanity hosts map by prefix: k8s.io/<repo> ->
    github.com/kubernetes/<repo> and sigs.k8s.io/<repo> ->
    github.com/kubernetes-sigs/<repo>, with a /vN major version or a deeper
    sub-package path leaving the repo unchanged (new in 0.9.3);
  - a small map of exact vanity paths verified from each project's go.mod
    `module` line (2026-10-17): code.gitea.io/gitea and gitea.dev ->
    go-gitea/gitea; gorm.io/gorm -> go-gorm/gorm; gorm.io/driver/{mysql,
    postgres,sqlite,sqlserver} -> go-gorm/{...}; gorm.io/datatypes ->
    go-gorm/datatypes; gocloud.dev -> google/go-cloud; google.golang.org/grpc
    -> grpc/grpc-go; google.golang.org/protobuf -> protocolbuffers/protobuf-go;
    go.uber.org/{zap,multierr,atomic} -> uber-go/{...}; go.uber.org/yarpc ->
    yarpc/yarpc-go; go.mongodb.org/mongo-driver -> mongodb/mongo-go-driver;
  - everything else (golang.org/x/..., private hosts) stays unmapped, so the
    tool never guesses a repo.

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
        self.assertIsNone(bs.go_module_repo("golang.org/x/text"))
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


if __name__ == "__main__":
    unittest.main()
