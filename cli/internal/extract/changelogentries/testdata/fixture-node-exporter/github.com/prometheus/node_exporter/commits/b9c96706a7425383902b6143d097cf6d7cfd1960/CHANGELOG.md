## master / unreleased

* [CHANGE]
* [FEATURE]
* [ENHANCEMENT]
* [BUGFIX]

## 1.0.0 / 2020-05-25

### **Breaking changes**

* The netdev collector CLI argument `--collector.netdev.ignored-devices` was renamed to `--collector.netdev.device-blacklist` in order to conform with the systemd collector. #1279
* The label named `state` on `node_systemd_service_restart_total` metrics was changed to `name` to better describe the metric. #1393
* Refactoring of the mdadm collector changes several metrics
    - `node_md_disks_active` is removed
    - `node_md_disks` now has a `state` label for "fail", "spare", "active" disks.
    - `node_md_is_active` is replaced by `node_md_state` with a state set of "active", "inactive", "recovering", "resync".
* Additional label `mountaddr` added to NFS device metrics to distinguish mounts from the same URL, but different IP addresses. #1417
* Metrics node_cpu_scaling_frequency_min_hrts and node_cpu_scaling_frequency_max_hrts of the cpufreq collector were renamed to node_cpu_scaling_frequency_min_hertz and node_cpu_scaling_frequency_max_hertz. #1510
* Collectors that are enabled, but are unable to find data to collect, now return 0 for `node_scrape_collector_success`.

### Changes

* [CHANGE] Add `--collector.netdev.device-whitelist`. #1279
* [CHANGE] Ignore iso9600 filesystem on Linux #1355
* [CHANGE] Refactor mdadm collector #1403
* [CHANGE] Add `mountaddr` label to NFS metrics. #1417
* [CHANGE] Don't count empty collectors as success. #1613
* [FEATURE] New flag to disable default collectors #1276
* [FEATURE] Add experimental TLS support #1277, #1687, #1695
* [FEATURE] Add collector for Power Supply Class #1280
* [FEATURE] Add new schedstat collector #1389
* [FEATURE] Add FreeBSD zfs support #1394
* [FEATURE] Add uname support for Darwin and OpenBSD #1433
* [FEATURE] Add new metric node_cpu_info #1489
* [FEATURE] Add new thermal_zone collector #1425
* [FEATURE] Add new cooling_device metrics to thermal zone collector #1445
* [FEATURE] Add swap usage on darwin #1508
* [FEATURE] Add Btrfs collector #1512
* [FEATURE] Add RAPL collector #1523
* [FEATURE] Add new softnet collector #1576
* [FEATURE] Add new udp_queues collector #1503
* [FEATURE] Add basic authentication #1673
* [ENHANCEMENT] Log pid when there is a problem reading the process stats #1341
* [ENHANCEMENT] Collect InfiniBand port state and physical state #1357
* [ENHANCEMENT] Include additional XFS runtime statistics. #1423
* [ENHANCEMENT] Report non-fatal collection errors in the exporter metric. #1439
* [ENHANCEMENT] Expose IPVS firewall mark as a label #1455
* [ENHANCEMENT] Add check for systemd version before attempting to query certain metrics. #1413
* [ENHANCEMENT] Add a flag to adjust mount timeout #1486
* [ENHANCEMENT] Add new counters for flush requests in Linux 5.5 #1548
* [ENHANCEMENT] Add metrics and tests for UDP receive and send buffer errors #1534
* [ENHANCEMENT] The sockstat collector now exposes IPv6 statistics in addition to the existing IPv4 support. #1552
* [ENHANCEMENT] Add infiniband info metric #1563
* [ENHANCEMENT] Add unix socket support for supervisord collector #1592
* [ENHANCEMENT] Implement loadavg on all BSDs without cgo #1584
* [ENHANCEMENT] Add model_name and stepping to node_cpu_info metric #1617
* [ENHANCEMENT] Add `--collector.perf.cpus` to allow setting the CPU list for perf stats. #1561
* [ENHANCEMENT] Add metrics for IO errors and retires on Darwin. #1636
* [ENHANCEMENT] Add perf tracepoint collection flag #1664
* [ENHANCEMENT] ZFS: read contents of objset file #1632
* [ENHANCEMENT] Linux CPU: Cache CPU metrics to make them monotonically increasing #1711
* [BUGFIX] Read /proc/net files with a single read syscall #1380
* [BUGFIX] Renamed label `state` to `name` on `node_systemd_service_restart_total`. #1393
* [BUGFIX] Fix netdev nil reference on Darwin #1414
* [BUGFIX] Strip path.rootfs from mountpoint labels #1421
* [BUGFIX] Fix seconds reported by schedstat #1426
* [BUGFIX] Fix empty string in path.rootfs #1464
* [BUGFIX] Fix typo in cpufreq metric names #1510
* [BUGFIX] Read /proc/stat in one syscall #1538
* [BUGFIX] Fix OpenBSD cache memory information #1542
* [BUGFIX] Refactor textfile collector to avoid looping defer #1549
* [BUGFIX] Fix network speed math #1580
* [BUGFIX] collector/systemd: use regexp to extract systemd version #1647
* [BUGFIX] Fix initialization in perf collector when using multiple CPUs #1665
* [BUGFIX] Fix accidentally empty lines in meminfo_linux #1671

## 0.18.1 / 2019-06-04

### Changes
* [BUGFIX] Fix incorrect sysctl call in BSD meminfo collector, resulting in broken swap metrics on FreeBSD #1345
* [BUGFIX] Fix rollover bug in mountstats collector #1364

## 0.18.0 / 2019-05-09

### **Breaking changes**

* Renamed `interface` label to `device` in netclass collector for consistency with
  other network metrics #1224
* The cpufreq metrics now separate the `cpufreq` and `scaling` data based on what the driver provides. #1248
* The labels for the network_up metric have changed, see issue #1236
* Bonding collector now uses `mii_status` instead of `operstatus` #1124
* Several systemd metrics have been turned off by default to improve performance #1254
  These include unit_tasks_current, unit_tasks_max, service_restart_total, and unit_start_time_seconds
* The systemd collector blacklist now includes automount, device, mount, and slice units by default. #1255

### Changes

* [CHANGE] Bonding state uses mii_status #1124
* [CHANGE] Add a limit to the number of in-flight requests #1166
* [CHANGE] Renamed `interface` label to `device` in netclass collector #1224
* [CHANGE] Add separate cpufreq and scaling metrics #1248
* [CHANGE] Several systemd metrics have been turned off by default to improve performance #1254
* [CHANGE] Expand systemd collector blacklist #1255
* [CHANGE] Split cpufreq metrics into a separate collector #1253
* [FEATURE] Add a flag to disable exporter metrics #1148
* [FEATURE] Add kstat-based Solaris metrics for boottime, cpu and zfs collectors #1197
* [FEATURE] Add uname collector for FreeBSD #1239
* [FEATURE] Add diskstats collector for OpenBSD #1250
* [FEATURE] Add pressure collector exposing pressure stall information for Linux #1174
* [FEATURE] Add perf exporter for Linux #1274
* [ENHANCEMENT] Add Infiniband counters #1120
* [ENHANCEMENT] Add TCPSynRetrans to netstat default filter #1143
* [ENHANCEMENT] Move network_up labels into new metric network_info #1236
* [ENHANCEMENT] Use 64-bit counters for Darwin netstat
* [BUGFIX] Add fallback for missing /proc/1/mounts #1172
* [BUGFIX] Fix node_textfile_mtime_seconds to work properly on symlinks #1326

