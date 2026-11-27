### Security

- The QA batch gate refuses a change to either upstream repository of a CRD version target, including its remote repository, and requires a new target to use repositories trusted in the same role, listed by the operator or covered by a signed batch.
- Target files are read strictly, so the gate scripts and the extractor cannot read different targets from the same bytes.
- The CRD oracle and the kind probe use a cached clone only when its origin is the target's repository, and the oracle refuses a batch binding that differs from the target file.
- Gate mode refuses a blank sandbox prefix before anything runs, and an existing run directory is refused.
