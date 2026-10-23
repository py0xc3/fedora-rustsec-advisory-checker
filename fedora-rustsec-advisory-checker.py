#!/usr/bin/python3

# Before running this, read the README.md and the below comments
# This tool is experimental and makes several presumptions
# that are not checked before or during runtime.

from os import listdir
from git import Repo
from git.exc import NoSuchPathError
from datetime import date
from getpass import getuser
from requests import get
from argparse import ArgumentParser
from xml.etree import ElementTree
from datetime import datetime
from sys import exit


# get the date that is to be checked for advisories
parseddate = ArgumentParser(
                 prog='fedora-rustsec-advisory-checker',
                 description='(partially-)automate the identification and reporting of RustSec advisories that affect Fedora packages',
                 epilog='Provide the date in this format: YYYYMMDD')
parseddate.add_argument("date")
dateinput = parseddate.parse_args().date

# verify the correct input format
try:
    dateraw = datetime(int(dateinput[0:4]),
                       int(dateinput[4:6]),
                       int(dateinput[6:8]))
except ValueError:
    print("Wrong date format. Provide the date in this format: YYYYMMDD")
    exit(2)
except TypeError:
    print("Wrong date format. Provide the date in this format: YYYYMMDD")
    exit(2)

date = str(dateraw.year)+"-"+str(dateraw.month)+"-"+str(dateraw.day)


# check if the script is up to date and update if applicable
# NOTE: the update assumes that there are no changes in the working directory!
try:
    repodist = Repo()
except NoSuchPathError:
        print("Run this script only within its git repository so that the"
              "tool can verify and update itself")
        exit(1)

# identify if updates were necessary by comparing head before and after pull
oldcommits = repodist.head.commit
gitpull = repodist.remotes.origin.pull()
newcommits = repodist.head.commit
if oldcommits != newcommits:
    print("The script had to be updated: it did NOT run!"
          "Please start it again!")
    exit(1)

# At the moment, this tool is not reliably resilient against changes of
# https://rustsec.org/feed.xml structures. The structures of
# https://rustsec.org/feed.xml are not documented/standardized:
# they might change without notice
#
# The script introduces several tests that shall identify such changes and
# make aware, but this cannot be explicitly proven: human review of the actual
# RustSec advisories and the output advisories of this script is suggested
#
# The script should output a list of relevant and non-relevant advisories,
# which together should contain all advisories of the RustSec advisories,
# whereas the file names might be compared by the reviewer too.
#
# The goal of the script is to save some time through "review instead of doing"
# and through saving the time for checking each advisory's relevance for Fedora

feed = get("https://rustsec.org/feed.xml")
if feed.status_code == 200:
    content = ElementTree.fromstring(feed.content)
else:
    print("Something went wrong! feed.status_code: ",
          feed.status_code)
    exit(1)

# pagemaybechanged verifies that at least one entry followed the assumed
# structure. NOTE: this can also mean that there are no advisories for
# the given day! So this can be intended, but it should be verified by
# checking https://rustsec.org/feed.xml for the very day!
pagemaybechanged = 1
# entryorder is to verify that each <entry> contains first <title>
# and any time later <link> and then any time later <published>
# if this does not fit, anything has changed and the output is not to be trusted
entryorder = 0
advisories = []
newcandidate = 0
# the first title entry is to be skipped for the tests
firsttitleentry = "RustSec Advisories"
# links shall be ignored until the actual entries begin
initlinks = 0

for entry in content.iter():
    if "{http://www.w3.org/2005/Atom}title" == entry.tag:
        if entryorder > 0:
            print("The order of entries does not fit! "
                "https://rustsec.org/feed.xml might have changed!")
            print(entryorder)
            exit(1)
        if entry.text[19:32] == "Vulnerability":
            advisorycandidate = entry.text[36:] # selects the crate
            newcandidate = 1
            entryorder = 1
            if " " in entry.text[36:]:
                print("there is a space in the crate name: something in "
                      "https://rustsec.org/feed.xml seems to have changed!")
                exit(1)
            if "RUSTSEC-2" != entry.text[0:9]:
                print("A title does not begin with \"RUSTSEC-2\":"
                      "https://rustsec.org/feed.xml seems to have changed!")
                exit(1)
        elif entry.text[-12:] == "unmaintained":
            entryorder = 1
            if "RUSTSEC-2" != entry.text[0:9]:
                print("A title does not begin with \"RUSTSEC-2\":"
                      "https://rustsec.org/feed.xml seems to have changed!")
                exit(1)
        elif entry.text[19:30] == "Unsoundness":
            entryorder = 1
            if "RUSTSEC-2" != entry.text[0:9]:
                print("A title does not begin with \"RUSTSEC-2\":"
                      "https://rustsec.org/feed.xml seems to have changed!")
                exit(1)
        else:
            if entry.text != firsttitleentry:
                print("\"Vulnerability\", \"unmaintained\" & \"Unsoundness\" "
                    "form no trichotomy of <title> entries: "
                    "something in https://rustsec.org/feed.xml seems to have "
                    "changed! A changed structure of the titles' sentences "
                    "can be the cause of the problem too. Verify! Error A")
                exit(1)
            # this entry should exist only once;
            # otherwise something has changed
            if entry.text == firsttitleentry:
                firsttitleentry == ""
            if firsttitleentry == "":
                print("\"Vulnerability\", \"unmaintained\" & \"Unsoundness\" "
                    "form no trichotomy of <title> entries: "
                    "something in https://rustsec.org/feed.xml seems to have "
                    "changed! A changed structure of the titles' sentences "
                    "can be the cause of the problem too. Verify! Error B")
                exit(1)
    if "{http://www.w3.org/2005/Atom}entry" == entry.tag:
        # from now on, links shall be considered
        initlinks = 1
    if "{http://www.w3.org/2005/Atom}link" == entry.tag:
        if initlinks == 1:
            if entryorder != 1:
                print("The order of entries does not fit! "
                    "https://rustsec.org/feed.xml might have changed!")
                exit(1)
            entryorder = 2
            if newcandidate == 1:
                advisorycandidate = [advisorycandidate, entry.attrib["href"]]
                newcandidate = 2
    if "{http://www.w3.org/2005/Atom}published" == entry.tag:
        if entryorder != 2:
            print("The order of entries does not fit! "
                "https://rustsec.org/feed.xml might have changed!")
            exit(1)
        if entry.text[0:10] == date:
            entryorder = 0
            if newcandidate == 2:
                advisories.append(advisorycandidate)
                newcandidate = 0
                pagemaybechanged = 0
        if entry.text[0:10] != date:
            entryorder = 0

if pagemaybechanged == 1:
    print(pagemaybechanged)
    print("The lack of outputs might be caused by "
          "https://rustsec.org/feed.xml having changed! "
          "But it also can be that today there was no advisory! "
          "Verify by checking https://rustsec.org/feed.xml")

fedoraadvisories = []
nonfedoraadvisories = []

for x in range(0,len(advisories),1):
    cratelink = ("https://src.fedoraproject.org/rpms/rust-"
                 + advisories[x][0])
    fedoracrate = get(cratelink)
    if fedoracrate.status_code == 200:
        fedoraadvisories.append(advisories[x])
    elif fedoracrate.status_code == 404:
        # NOTE: HERE, A CHECK FOR BUNDLES SHOULD BE ADDED
        nonfedoraadvisories.append(advisories[x])
    else:
        print("Something went wrong when checking distgit! "
            "fedoracrate.status_code: ", feed.status_code)
        exit(1)

print("Please compare all advisory entries of the very day "
      "with the following two lists. The number of entries on "
      "https://rustsec.org/feed.xml of the very day must be equal to "
      "the sum of fedora and non-fedora advisories output by this tool!")
print()
print("Fedora advisory entries:")
for x in range(0,len(fedoraadvisories),1):
    print(fedoraadvisories[x])
print()
print("Non-Fedora advisory entries:")
for x in range(0,len(nonfedoraadvisories),1):
    print(nonfedoraadvisories[x])
print()
print("IMPORTANT: this script does not yet check if a crate "
      "is bundled somewhere!")
