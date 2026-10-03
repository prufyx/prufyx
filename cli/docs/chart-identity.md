# Chart identity tables

Prufyx reads Helm chart references in GitOps repositories (a `HelmRelease`, an Argo CD
`Application`, a `helmCharts` entry). A chart reference tells you a repository URL, a chart name and
a chart version. It does not tell you which software the chart installs, or which version of that
software the chart version contains. Two embedded tables bridge that gap. Both ship empty in the
source tree until reviewed entries are published.

## A chart version is not an application version

A chart is packaging. Chart `4.11.2` may install application `1.9.4`, and the next chart release may
change only a template while the application stays the same. Treating the chart version as the
application version would select rules for the wrong release, so Prufyx never does. When no record
exists for a chart version, the chart version is shown as a label and is not used for any verdict.

## Chart-source table (reviewed)

`cli/internal/chartidentity/data/chart-sources.json` maps `(repoURL, chart)` to a catalog project and
the component name that project's rules use. A record is reviewed knowledge: someone checked the
project's own documentation, cited it (pinned commit, content digest, line span), and gave the record
an expiry. A record can be withdrawn. `project` must be a catalog project whose component equals the
record's `component`; charts of software that is not in the catalog cannot have a record yet.

Lookups use a normalised repository URL (`chartidentity.NormalizeRepoURL`): scheme `https` or `oci`,
lower-case host, no trailing `/`, no `.git`, no query, fragment or user information.

## App-version table (mechanical)

`cli/internal/chartidentity/data/chart-app-versions.json` maps `(component, chart, chartVersion)` to
`appVersion`. Nothing in it is typed by hand: each record is derived from the chart's own
`Chart.yaml` at the release tag's commit, and cites that file (commit, whole-file sha256, the lines
holding `version:` and `appVersion:`) together with the derivation code's digest.

Rules of the derivation:

- Only strict `X.Y.Z` is accepted for both versions, after removing one leading `v`. Pre-releases,
  build metadata, ranges, `latest` and two-part versions are not guessed at: the tag is withheld and
  the reason is printed.
- `Chart.yaml` must name the mapped chart, and its `version` must equal the version in the tag.
- Two tags naming the same chart version are both withheld.
- The derivation reads only the offline factory mirror. A blob the mirror does not hold is an error,
  not a withheld tag.

## Freshness

Every record has a `validUntil`. Lookups take the current time and treat an expired (or withdrawn)
record as not found; a missing record means the chart label is shown but not used.

## Maintainer commands

```
prufyx-maintainer chart-versions derive --mirror DIR --mapping FILE --out FILE \
    [--derived-at 2030-01-02T03:04:05Z] [--valid-days 90] [--report FILE]
prufyx-maintainer chart-versions verify --mirror DIR --mapping FILE --out FILE
```

`derive` writes the table. `verify` re-derives it from the same mirror with the times recorded in the
table and fails (exit 1) unless the bytes are identical. The mapping file is JSON, reviewed like
code:

```json
{
  "schema": "prufyx.io/chart-mapping/v1alpha1",
  "entries": [
    {
      "component": "pkg:github/acme/widget",
      "chart": "widget",
      "repo": "github.com/acme/widget",
      "chartPath": "charts/widget",
      "tagPattern": "v{version}"
    }
  ]
}
```

`tagPattern` is literal text around one `{version}`. Entries are sorted by component and chart.
`--report` writes the withheld tags as JSON; the same lines are printed to standard output.
