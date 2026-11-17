## master / unreleased

* [CHANGE]
* [FEATURE]
* [ENHANCEMENT]
* [BUGFIX]

## 1.8.2 / 2024-06-19

* [BUGFIX] Fix CPU pressure metric collection #3054

## 1.8.1 / 2024-05-16

* [BUGFIX] Fix CPU seconds on Solaris #2963
* [BUGFIX] Sign Darwin/MacOS binaries #3008
* [BUGFIX] Fix pressure collector nil reference #3016

## 1.8.0 / 2024-04-24

* [CHANGE] exec_bsd: Fix labels for `vm.stats.sys.v_syscall` sysctl #2895
* [CHANGE] diskstats: Ignore zram devices on linux systems #2898
* [CHANGE] textfile: Avoid inconsistent help-texts  #2962
* [CHANGE] os: Removed caching of modtime/filename of os-release file #2987
* [FEATURE] xfrm: Add new collector #2866
* [FEATURE] watchdog: Add new collector #2880
* [ENHANCEMENT] cpu_vulnerabilities: Add mitigation information label #2806
* [ENHANCEMENT] nfsd: Handle new `wdeleg_getattr` attribute #2810
* [ENHANCEMENT] netstat: Add TCPOFOQueue to default netstat metrics #2867
* [ENHANCEMENT] filesystem: surface device errors #2923
* [ENHANCEMENT] os: Add support end parsing #2982
* [ENHANCEMENT] zfs: Log mib when sysctl read fails on FreeBSD #2975
* [ENHANCEMENT] fibre_channel: update procfs to take into account optional attributes #2933
* [BUGFIX] cpu: Fix debug log in cpu collector #2857
* [BUGFIX] hwmon: Fix hwmon nil ptr #2873
* [BUGFIX] hwmon: Fix hwmon error capture #2915
* [BUGFIX] zfs: Revert "Add ZFS freebsd per dataset stats #2925
* [BUGFIX] ethtool: Sanitize ethtool metric name keys #2940
* [BUGFIX] fix: data race of NetClassCollector metrics initialization #2995

