# Synthetic observation input

The importer tests construct this fixture shape in a temporary directory with
four public component identities and deliberately non-customer versions. No
cluster snapshot, kubeconfig, namespace, object name, endpoint, or customer
timestamp is copied into this testdata. The test helper writes both SHA-256
manifest layers before each import.
