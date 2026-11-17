## master / unreleased

* [CHANGE]
* [FEATURE]
* [ENHANCEMENT]
* [BUGFIX]

## 1.5.0 / 2022-11-29

NOTE: This changes the Go runtime "GOMAXPROCS" to 1. This is done to limit the
  concurrency of the exporter to 1 CPU thread at a time in order to avoid a
  race condition problem in the Linux kernel (#2500) and parallel IO issues
  on nodes with high numbers of CPUs/CPU threads (#1880).

* [CHANGE] Default GOMAXPROCS to 1 #2530
* [FEATURE] Add multiple listeners and systemd socket listener activation #2393
* [ENHANCEMENT] Add RTNL version of netclass collector #2492, #2528
* [BUGFIX] Fix diskstats exclude flags #2487
* [BUGFIX] Bump go/x/crypt and go/x/net #2488
* [BUGFIX] Fix hwmon label sanitizer #2504
* [BUGFIX] Use native endianness when encoding InetDiagMsg #2508
* [BUGFIX] Fix btrfs device stats always being zero #2516
* [BUGFIX] Security: Update exporter-toolkit (CVE-2022-46146) #2531

## 1.4.1 / 2022-11-29

* [BUGFIX] Fix diskstats exclude flags #2487
* [BUGFIX] Security: Update go/x/crypto and go/x/net (CVE-2022-27191 CVE-2022-27664) #2488
* [BUGFIX] Security: Update exporter-toolkit (CVE-2022-46146) #2531

## 1.4.0 / 2022-09-24

* [CHANGE] Merge metrics descriptions in textfile collector #2475
* [FEATURE] [node-mixin] Add darwin dashboard to mixin #2351
* [FEATURE] Add "isolated" metric on cpu collector on linux #2251
* [FEATURE] Add cgroup summary collector #2408
* [FEATURE] Add selinux collector #2205
* [FEATURE] Add slab info collector #2376
* [FEATURE] Add sysctl collector #2425
* [FEATURE] Also track the CPU Spin time for OpenBSD systems #1971
* [FEATURE] Add support for MacOS version #2471
* [ENHANCEMENT] [node-mixin] Add missing selectors #2426
* [ENHANCEMENT] [node-mixin] Change current datasource to grafana's default #2281
* [ENHANCEMENT] [node-mixin] Change disk graph to disk table #2364
* [ENHANCEMENT] [node-mixin] Change io time units to %util #2375
* [ENHANCEMENT] Ad user_wired_bytes and laundry_bytes on *bsd #2266
* [ENHANCEMENT] Add additional vm_stat memory metrics for darwin #2240
* [ENHANCEMENT] Add device filter flags to arp collector #2254
* [ENHANCEMENT] Add diskstats include and exclude device flags #2417
* [ENHANCEMENT] Add node_softirqs_total metric #2221
* [ENHANCEMENT] Add rapl zone name label option #2401
* [ENHANCEMENT] Add slabinfo collector #1799
* [ENHANCEMENT] Allow user to select port on NTP server to query #2270
* [ENHANCEMENT] collector/diskstats: Add labels and metrics from udev #2404
* [ENHANCEMENT] Enable builds against older macOS SDK #2327
* [ENHANCEMENT] qdisk-linux: Add exclude and include flags for interface name #2432
* [ENHANCEMENT] systemd: Expose systemd minor version #2282
* [ENHANCEMENT] Use netlink for tcpstat collector #2322
* [ENHANCEMENT] Use netlink to get netdev stats #2074
* [ENHANCEMENT] Add additional perf counters for stalled frontend/backend cycles #2191
* [ENHANCEMENT] Add btrfs device error stats #2193
* [BUGFIX] [node-mixin] Fix fsSpaceAvailableCriticalThreshold and fsSpaceAvailableWarning #2352
* [BUGFIX] Fix concurrency issue in ethtool collector #2289
* [BUGFIX] Fix concurrency issue in netdev collector #2267
* [BUGFIX] Fix diskstat reads and write metrics for disks with different sector sizes #2311
* [BUGFIX] Fix iostat on macos broken by deprecation warning #2292
* [BUGFIX] Fix NodeFileDescriptorLimit alerts #2340
* [BUGFIX] Sanitize rapl zone names #2299
* [BUGFIX] Add file descriptor close safely in test #2447
* [BUGFIX] Fix race condition in os_release.go #2454
* [BUGFIX] Skip ZFS IO metrics if their paths are missing #2451

