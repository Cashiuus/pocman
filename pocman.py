#!/usr/bin/env python
# ==============================================================================
# File:         pocman.py
# Author:       Cashiuus
# Created:      15-May-2023     -     Revised:
#
# ==============================================================================
__version__ = "0.0.1"
__author__ = "Cashiuus"
__license__ = "MIT"
__copyright__ = "Copyright (C) 2023 Cashiuus"
## =======[ IMPORTS ]======= ##
import argparse
import json
import logging
import os
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import sleep

import requests


## =======[ Constants & Settings ]======= ##
DEBUG = False
TDATE = f"{datetime.now():%Y-%m-%d}"      # "2022-02-15"
APP_BASE = Path(__file__).resolve(strict=True).parent

log = logging.getLogger(__name__)


## ======================[ BEGIN APPLICATION ]====================== ##

@dataclass
class Repository():
    name: str
    full_name: str
    url: str
    description: str
    # related_cve: str
    stars: str
    # discovered_on: str
    # pushed_on: str



def prettify_elapsed_time(seconds):
    """
    Convert the specified seconds value into days|hours|minutes|seconds.
    Will start with largest type, days, and continue drilling down.
        - Credit: # https://gist.github.com/thatalextaylor/7408395

    Example returns     1d 4h37m13s

    """
    sign_string = "-" if seconds < 0 else ""
    seconds = abs(int(seconds))
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    time_delta = sign_string

    if days > 0:
        time_delta += f"{days}d "
    if hours > 0:
        time_delta += f"{hours}h"
    if minutes > 0:
        time_delta += f"{minutes}m"
    if seconds > 0:
        time_delta += f"{seconds}s"

    return time_delta



class Pocman():
    """
    POC Monitoring tool coined as Pacman

    Usage:
    bot = Pocman(cve=CVE-2023-2019, sleep_interval=1200)
    bot.run_bot()
    """
    def __init__(self, cve=None, sleep_interval=None):
        self.cves = set()
        self.sleep_interval = sleep_interval if sleep_interval else 1200
        self.db_file = APP_BASE / 'pocman.db'

        if isinstance(cve, str):
            self.cves.add(cve)
        elif isinstance(cve, (list, set)):
            self.cves = set(cve)


    def run_bot(self, cve=None):
        """ Run periodic checks for the provided CVE at every interval. """
        cves_scope_for_bot = set()
        if cve:
            cves_scope_for_bot.add(cve)
        else:
            cves_scope_for_bot = self.cves

        if not cves_scope_for_bot:
            print("[ERR] Your CVEs scope for monitoring is empty, try again by providing one or more CVEs to search")
            sys.exit(1)

        while True:
            for cve in cves_scope_for_bot:
                try:
                    pocs = self.search_github(cve)
                    if pocs:
                        print(f"[*] Found {len(pocs):,d} POC results for {cve} on GitHub")
                        print(f"{'Stars':<8} {'Language':<12} {'Name':<40} {'URL':<40}")
                        print("=" * 90)
                        for item in pocs:
                            repo = Repository(
                                name = item['name'],
                                full_name = item['full_name'],
                                url = item['html_url'],
                                description = item.get('description', ""),
                                stars = item.get('stargazers_count', 0),
                            )
                            # print(f"[DBG] {item=}")
                            if not item.get('description'):
                                item['description'] = ""
                            if not item.get('language'):
                                item['language'] = ''
                            print(f"{item['stargazers_count']:<8}{item.get('language', ''):<12}{item['name']:<40}{item['html_url']:<40}")
                        print()

                    self.save_to_db(cve, pocs)
                    print(f"[*] Sleeping for {prettify_elapsed_time(self.sleep_interval)}...")
                    sleep(self.sleep_interval)
                except KeyboardInterrupt:
                    print("[*] Shutting down")
                    sys.exit(0)

                print()
            # -=- End of Loop -=-


    def search_github(self, cve):
        """ Run a specific CVE search at GitHub and return json data to do things with.

        NOTE: Some field values could be None, so be sure to account for that condition
        TODO: Could add additional code to check if match is a fork, and skip forks

        -- GitHub API's Full Response dict contains these keys: --
        id, node_id, name, full_name, private: (bool), owner: (dict),
        html_url, description, fork: (bool), url, forks_url, keys_url,
        collaborators_url, teams_url, hooks_url, issue_events_url,
        events_url, assignees_url, branches_url, tags_url, blobs_url,
        git_tags_url, git_refs_url, trees_url, status_url, languages_url,
        stargazers_url, contributors_url, subscribers_url, subscription_url,
        commits_url, git_commits_url, comments_url, issue_comment_url,
        contents_url, compare_url, merges_url, archive_url, downloads_url,
        issues_url, pulls_url, milestones_url, notifications_url, labels_url,
        releases_url, deployments_url, mirror_url,
        created_at (format: 2023-10-17T07:35:50Z), updated_at, pushed_at,
        git_url, clone_url, svn_url, homepage (can be None), size: (4 -- number of files/dirs?),
        stargazers_count (int), watchers_count (int), watchers: (int),
        language: (e.g. Python), default_branch: (str, e.g. "main"),
        score: (float, e.g. 1.0),
        forks_count: (int), forks: (int),
        open_issues_count: (int), open_issues: (int),
        has_issues: (bool), has_projects: (bool), has_downloads: (bool), has_wiki: (bool),
        has_pages: (bool), has_discussions: (bool), archived: (bool), disabled: (bool),
        license: (can be None), allow_forking: (bool),
        is_template: (bool), web_commit_signoff_required: (bool), topics: (list),
        visibility: (str, e.g. "public"),

        """
        url = f"https://api.github.com/search/repositories?q={cve}"

        response = requests.get(url)

        if response.status_code != 200:
            print(f"[ERR] Response not 200, failed search for CVE: {cve}")
            return

        data = json.loads(response.text)
        log.debug(f"Response data keys: {data.keys()}")
        return data['items']


    def save_to_db(self, cve, poc_results):

        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS cves(id integer PRIMARY KEY, cve_id text UNIQUE, description text)""")
        # "discovered_on" is for a datetime, sqlite stores these in a text datatype
        c.execute("""
            CREATE TABLE IF NOT EXISTS pocs(
                id integer PRIMARY KEY AUTOINCREMENT, full_name text unique, name text, cve,
                stars integer, language text,
                description text, discovered_on text, url text,
                FOREIGN KEY (cve) REFERENCES cves(cve_id))
        """)

        for poc in poc_results:
            # if poc.get('description'):
            #     poc['description'] = ''
            try:
                c.execute("INSERT INTO cves (cve_id) VALUES (?)", (cve,))
            except sqlite3.IntegrityError:
                # Don't need to update record, CVE is already there, nothing to update
                pass

            try:
                c.execute(
                    "INSERT INTO pocs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (None, poc['full_name'], poc['name'], cve, poc['stargazers_count'], poc.get('language'), poc['description'], datetime.now(), poc['html_url'])
                )
                log.debug("Inserted new record into db")
            except sqlite3.IntegrityError as e:
                c.execute(
                    "UPDATE pocs set stars = ? where full_name = ?", (poc['stargazers_count'], poc['full_name'])
                )
                log.debug("Updated existing record with current stars count")
        conn.commit()
        conn.close()
        return True

# -=- End of Class -=-




def main():
    """
    Main function of script when run directly, executing the primary purpose of this file.
    """
    # -- Logging --
    # ch = logging.StreamHandler()
    # if DEBUG:
    #     ch.setLevel(logging.DEBUG)
    # else:
    #     ch.setLevel(logging.INFO)
    # datefmt = '%Y%m%d %I:%M:%S%p'
    # formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s:%(funcName)s: %(message)s', datefmt=datefmt)
    # ch.setFormatter(formatter)
    # log.addHandler(ch)
    # log.debug('Logger initialized')

    # -- Args --
    parser = argparse.ArgumentParser(description='Find GitHub PoCs for a specific CVE ID.')
    parser.add_argument('cve', type=str, help='CVE ID to search for (ex: CVE-2023-44487)')
    # parser.add_argument('target', help='IP/CIDR/URL of target') # positional arg
    # parser.add_argument('-i', "--input_file", help="an input file")
    # parser.add_argument("-i", "--input-file", dest='input', nargs='*',
    #                     help="Specify one or more files, (process as a list)")
    parser.add_argument(
        '-s', '--sleep_time',
        type=int, default=3900,
        help='The sleep time between checks, in seconds (default is 1 hour, 5 min)',
    )
    # parser.add_argument("--debug", action="store_true",
    #                     help="Show debug messages for troubleshooting or verbosity")

    args = parser.parse_args()

    if not args.cve:
        parser.print_usage()
        sys.exit(1)

    # -- Main App Flow --
    # NOTE: Seconds <-> Hours Reference
    # 12 hours = 43200
    # 1 hour = 3600

    bot = Pocman(args.cve, args.sleep_time)
    bot.run_bot()

    return


if __name__ == '__main__':
    main()
