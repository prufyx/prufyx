### Security

- The QA batch gate refuses a change that removes, renames or retypes a CRD version target present at its base, and no longer treats an unreadable changed target as a deletion.
- The QA batch gate accepts only the main tip as its base, verified as the single merge base from a full fetch; a head behind main must be rebased, and a recorded green result turns stale when main moves.
- The nightly change listing no longer follows renames, so a file moved into an ignored path still lists its removal.
