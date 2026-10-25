#!/usr/bin/python3

# Before running this, read the README.md and the below comments
# This tool is experimental and makes several presumptions
# that are not checked before or during runtime.

from git import Repo
from git.exc import NoSuchPathError
from datetime import date
from requests import get
from argparse import ArgumentParser
from xml.etree import ElementTree
from datetime import datetime
from sys import exit
from json import loads
from subprocess import getoutput


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
    print("pagemaybechanged output:", pagemaybechanged)
    print("The lack of outputs might be caused by "
          "https://rustsec.org/feed.xml having changed! "
          "But it also can be that today there was no advisory! "
          "Verify by checking https://rustsec.org/feed.xml")

# get the current fedora branches

fedorareleases = get("https://bodhi.fedoraproject.org/releases/"
                     "?rows_per_page=1000")
if fedorareleases.status_code == 200:
    jsondata = loads(fedorareleases.content.decode("UTF-8"))
else:
    print("Something went wrong! fedorareleases.status_code: ",
          feed.status_code)
    exit(1)

currentbranches = []
archivedbranchesfound = 0
currentbranchesfound = 0

for x in range(0,len(jsondata["releases"]),1):
    if jsondata["releases"][x]["state"] == "current":
        currentbranches.append(jsondata["releases"][x]["branch"])
        currentbranchesfound = 1
    elif jsondata["releases"][x]["state"] == "archived":
        archivedbranchesfound = 1
    elif jsondata["releases"][x]["state"] == "pending":
        if jsondata["releases"][x]["branch"] == "rawhide":
            currentbranches.append(jsondata["releases"][x]["branch"])
    elif jsondata["releases"][x]["state"] == "frozen":
        currentbranches.append(jsondata["releases"][x]["branch"])
    else:
        print("Something went wrong! the \"state\" of jsondata "
              "seems to contain more than \"current\", \"frozen\" "
              "and \"archived\"")
        print(jsondata["releases"][x]["state"])
        exit(1)

# remove duplicates
currentbranches = list(set(currentbranches))

# some tests to verify currentbranches make sense
if "rawhide" not in currentbranches:
    print("Something must have changed! "
          "rawhide did not end up in \"currentbranches\"!")
    exit(1)
# There should always 2 or 3 F** branches
fbranches = 0
for x in range(0,len(currentbranches),1):
    if "f" == currentbranches[x][0]:
        if len(currentbranches[x]) == 3:
            fbranches = fbranches + 1
if fbranches != 2:
    if fbranches != 3:
        print("Something went wrong! There should be always only 2 or 3 "
              "f** branches, but \"fbranches\" counts: ", fbranches)
        exit(1)
# There should always epel branches
epelbranches = 0
for x in range(0,len(currentbranches),1):
    if "epel" == currentbranches[x][0:4]:
        if len(currentbranches[x]) > 4:
            epelbranches = epelbranches + 1
if epelbranches < 2:
        print("Something went wrong! There should be always 2+ epel branches, "
              "with any version number, but "
              "\"epelbranches\" counts: ", epelbranches)
        exit(1)

# there should be always supported and archived branches
if currentbranchesfound == 0:
    print("Something went wrong! It seems no currently supported "
          "branches have been found!")
    exit(1)
if archivedbranchesfound == 0:
    print("Something went wrong! It seems no archived "
          "branches have been found!")
    exit(1)

# do the fedrq commands to check out what crates exist in
# fedora, as package or bundled. This is designed to rather add a
# false output that will raise awareness of an issue later (e.g.,
# when a ticket is raised for something not packaged/bundled) rather
# than giving no output: yet, this output should still be taken with care

fedoraadvisories = []
nonfedoraadvisories = []

for xa in range(0,len(advisories),1):
    for xc in range(0,len(currentbranches),1):
        fedpack = ("fedrq pkgs -P -b " + currentbranches[xc]
                   + " \"crate(" + advisories[xa][0] + ")\"")
        fedbundle = ("fedrq pkgs -P -b " + currentbranches[xc]
                     + " \"bundled(crate(" + advisories[xa][0] + "))\"")
        fedpackres =  getoutput(fedpack)
        fedbundleres = getoutput(fedbundle)
        if advisories[xa][0] in fedpackres:
            advisories[xa].append(currentbranches[xc])
        elif advisories[xa][0] not in fedpackres:
            if advisories[xa][0] in fedbundleres:
                advisories[xa].append(currentbranches[xc])
    # if any branch has been confirmed, len() will be more than 2
    if len(advisories[xa]) > 2:
        fedoraadvisories.append(advisories[xa])
    if len(advisories[xa]) <= 2:
        nonfedoraadvisories.append(advisories[xa])

# Output results for the user
print("Fedora Advisories and confirmed branches:")
for x in range(0,len(fedoraadvisories),1):
    print(fedoraadvisories[x])
print("---")
print("Non-Fedora Advisories:")
for x in range(0,len(nonfedoraadvisories),1):
    print(nonfedoraadvisories[x])
