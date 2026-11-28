### Removed

- The Harbor rules about the installer `--with-chartmuseum` option for 2.10.3 to 2.15.2 and 2.11.2 to 2.15.2 are withdrawn. The upstream 2.15 upgrade guide covers migration from 2.12.0 and later only, so the scoped PASS these rules gave was wrong. Those transitions now report UNKNOWN, including the case they used to report as blocked.
