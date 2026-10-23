# fedora-rustsec-advisory-checker/

This script is a simple tool to (partially-)automate the identification and reporting of RustSec advisories that affect Fedora packages.

This tool is currently experimental. Any output should be reviewed before processing!

The tool should be used within its git repository: it checks for updates and pulls them automatically before checking for advisories. If updates had to be applied, the tool exits after the updates and needs to be manually re-started: there will be **no** check for advisories before exiting if updates are applied.

# Issues & considerations

The tool depends on [RustSec.org/feed.xml](https://rustsec.org/feed.xml) , which is not optimal for automatic processing. Also, there is no documentation or standardization against which the outputs of [RustSec.org/feed.xml](https://rustsec.org/feed.xml) have to comply to: outputs might change without "official" notice.

While the output seems to be consistent and thus to some extent reliable, this risk cannot be fully mitigated: the script contains many tests that aim to identify if the output of [RustSec.org/feed.xml](https://rustsec.org/feed.xml) has changed in order to make aware of that fact rather than providing output. 

However, this cannot be explicitly proven, and therefore, the output should be human-reviewed: the script output should be compared to the summaries of [RustSec.org/feed.xml](https://rustsec.org/feed.xml) or [RustSec.org/advisories](https://rustsec.org/advisories/): important is comparing that all crate names are correct and none is lost. 

The check for Fedora packages can be considered reliable if it passes without an error report, but this tool does **not** yet check if a crate is bundled somewhere. So the "Non-Fedora advisory entries" output is not yet reliable.

# How to use this tool

As simple as `python3 fedora-rustsec-advisory-checker.py YYYYMMDD` -> e.g., `python3 fedora-rustsec-advisory-checker.py 20261023`

The tool will then provide the output: crate names and links to the advisory entries, so that the user can create the respective tickets in Fedora.

This tool is to be embedded in a process that will be partially automated (1), partially human-reviewed (2) and partially done by a human at all (3): so far this is an experiment, and it s not yet clear what will be (1), (2) and what will be (3).

Feel free to file tickets or open PR. 
