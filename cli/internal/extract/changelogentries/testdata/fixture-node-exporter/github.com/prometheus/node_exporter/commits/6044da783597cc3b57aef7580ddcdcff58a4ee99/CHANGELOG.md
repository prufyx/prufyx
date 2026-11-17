## master / unreleased

## 1.12.1 / 2026-07-14

* [BUGFIX] perf: Fix perf profiler flag handling #3731
* [BUGFIX] edac: Fix optional csrow ue_count collection #3734

## 1.12.0 / 2026-07-10

* [FEATURE] mountstats: Add NFS mountpoint info metric #3554
* [FEATURE] nvmesubsystem: Add new collector #3579
* [FEATURE] dmmultipath: Add new collector #3581
* [FEATURE] infiniband: Add device filtering option #3694
* [ENHANCEMENT] hwmon: disambiguate colliding chip labels #3646
* [ENHANCEMENT] cpufreq: Add support for cpuinfo_avg_freq #3712
* [ENHANCEMENT] filesystem: Support ext4 super block emergency_ro flag #3717
* [ENHANCEMENT] edac: Add per-channel error metrics with DIMM labels #3720
* [BUGFIX] diskstats: Only enforce mutual exclusivity for non-empty values #3617
* [BUGFIX] thermal_zone: Handle EINVAL errors gracefully #3657
* [BUGFIX] filesystem: Add comma separator in mount options #3659
* [BUGFIX] diskstats: Fix rotational queue stats scrape regression #3686
* [BUGFIX] filesystem: Prevent panic on mount points with non-UTF-8 names #3687

## 1.11.1 / 2026-04-07

* [BUGFIX] Fix kernel_hung for no data #3613

