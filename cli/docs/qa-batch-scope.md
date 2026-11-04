# Batch QA scope

The batch QA harness freezes its required scope from fetched Git objects before
building or executing the candidate. An onboarding run requires exactly one
added `prufyx.io/knowledge-onboarding-batch/v2` envelope. It supports `new`
projects in the `cncf` and `community` catalogs with their exact CRD target
artifact. Unsupported or missing scope blocks the run.

The frozen scope includes the independently selected full or changed-project
scope, every envelope project, and every exact proof pair. A proof pair binds
both tag names and both commit IDs. The oracle resolves each proof tag once,
checks its commit, reads the CRD sources by commit ID, and executes the exact
pair even when normal release-line sampling would select different patches.
An empty source served set cannot satisfy a required proof pair.

The trusted parent keeps its expected contract digest and Git objects outside
the candidate's mounted directory. Before accepting the result it rederives
the contract and checks the original scope declarations and suite case files.
Missing projects, pairs, cases, suites, omitted input, changed bindings, and
failed cases cannot be removed to manufacture zero errors.

The original-declaration and exact project/pair case comparisons apply to runs
that add a v2 envelope. Non-onboarding data runs retain their existing suite
and internally declared inventory checks; they do not gain those additional
envelope comparisons. Temporary parent Git checkouts are removed on exit,
while the frozen contract and original suite artifacts remain as evidence.

The fast batch receipt explicitly records kind and database checks as
`not_executed`. Its green result covers only its declared suites. Separate
required checks on the same candidate, signature verification, data review,
and client compatibility remain necessary for publication. This harness does
not sign or publish an approval.
