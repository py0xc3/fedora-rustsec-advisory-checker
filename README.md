# fedora-rustsec-advisory-checker/

This script is a simple tool to (partially-)automate the identification and reporting of RustSec advisories that affect Fedora packages.

This tool is currently experimental. Any output should be reviewed before processing!

The tool should be used within its git repository: it checks for updates and pulls them automatically before checking for advisories. If updates had to be applied, the tool exits after the updates and needs to be manually re-started: there will be **no** check for advisories before exiting if updates are applied.

# Issues & considerations

The tool depends on [RustSec.org/feed.xml](https://rustsec.org/feed.xml) and [bodhi.fedoraproject.org/releases/?rows_per_page=1000](https://bodhi.fedoraproject.org/releases/?rows_per_page=1000), which is both not optimal for automatic processing. Also, there is no documentation or standardization against which the outputs of [RustSec.org/feed.xml](https://rustsec.org/feed.xml) have to comply to: outputs might change without "official" notice.

While the output seems to be consistent and thus to some extent reliable, this risk cannot be fully mitigated: the script contains many tests that aim to identify if the output of [RustSec.org/feed.xml](https://rustsec.org/feed.xml) has changed (or could have changed) in order to make aware of that fact rather than providing output: tests are designed to be rather false positive than false negative, in order to raise awareness for the user to take over for investigating. The same for the output of [bodhi.fedoraproject.org/releases/?rows_per_page=1000](https://bodhi.fedoraproject.org/releases/?rows_per_page=1000), although bodhi is likely to be more reliable as long as names and structures in its `json` do not change (but it is much less likely that changes in bodhi are both relevant and yet do not cause errors).

However, both pages' output cannot be explicitly proven to be applicable and unchanged, and therefore, the output should be human-reviewed: the script output should be compared to the summaries of [RustSec.org/feed.xml](https://rustsec.org/feed.xml) or [RustSec.org/advisories](https://rustsec.org/advisories/): **important is comparing that all crate names make sense (e.g., no spaces contained) and none is lost in the output** (the output also lists advisories that are not found within Fedora: the output Fedora and non-Fedora advisories should be in sum equal to the "vulnerability" list of [RustSec.org/feed.xml](https://rustsec.org/feed.xml)) (excluding "unmaintained" and "unsound" advisories).

The later check for Fedora packages or bundles can be considered reliable if it passes without an error report and if each Fedora advisory contains at least one branch. 

# How to use this tool

As simple as `python3 fedora-rustsec-advisory-checker.py YYYYMMDD` -> e.g., `python3 fedora-rustsec-advisory-checker.py 20261023`

The tool will then provide the output: crate names and links to the advisory entries, along with branches in which the crate has been found in, so that the user can create the respective tickets in Fedora.

This tool is to be embedded in a process that will be partially automated (1), partially human-reviewed (2) and partially done by a human at all (3): so far this is an experiment, and it s not yet clear what will be (1), (2) and what will be (3).

Feel free to file tickets or open PR. 
