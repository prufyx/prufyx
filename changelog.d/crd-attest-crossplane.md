### Changed

- The Crossplane CRD extractor target now enables line attestation. In a dry run of the derive loop, two of its five pairs are attestable (2.2 to 2.3 and 2.3 to 2.4); the three older pairs (1.20 to 2.0, 2.0 to 2.1, 2.1 to 2.2) stay unattested because the scan of the older tags still finds the reviewed package-metadata exclusion void. The change only turns the switch on; attested pairs appear only after the factory re-derives them and the resulting data change passes the QA gate and data review.
