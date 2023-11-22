#!/usr/bin/env python
# ==============================================================================
# File:         pocman.py
# Author:       Cashiuus
# Created:      15-May-2023     -     Revised: 21-Nov-2023
#
# ==============================================================================
__version__ = "0.0.2"
__author__ = "Cashiuus"
__license__ = "MIT"
__copyright__ = "Copyright (C) 2023 Cashiuus"
## =======[ IMPORTS ]======= ##
import argparse
import json
import logging
import operator
import os
import shutil
import sqlite3
import sys
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from time import sleep

import requests

from email_handler import EmailSender
from helpers import prettify_elapsed_time, convert_string_to_datetime


## =======[ Constants & Settings ]======= ##
DEBUG = False
TDATE = f"{datetime.now():%Y-%m-%d}"      # "2022-02-15"
APP_BASE = Path(__file__).resolve(strict=True).parent
CVES_FILE = APP_BASE / "tracking_cves.txt"

log = logging.getLogger(__name__)


## ======================[ BEGIN APPLICATION ]====================== ##

@dataclass
class Repository():
    name: str
    full_name: str
    url: str
    language: str
    description: str
    # related_cve: str
    stars: str
    # discovered_on: str
    last_pushed: str



def first_run():
    """ Do first-run stuff. """
    if not os.path.exists(APP_BASE / "settings.py"):
        shutil.copy(APP_BASE / "settings_example.py", APP_BASE / "settings.py")
        print("[+] settings.py file has been created. Please add your settings before continuing!")
        sys.exit(0)
    return


def load_targets_from_file(input_file):
    """
    From input file, load up the CVE's that will be tracked.
    """
    items = set()
    with open(input_file, 'r') as f:
        for line in f:
            if line.startswith('#'): continue
            items.add(line.strip())
    print(f"[*] Loaded {len(items):,d} CVE's to tracking list")
    return items


# --
# The main part of this script
# --

class Pocman():
    """
    POC Monitoring tool, coined as "Pocman" (like "Pacman")

    Usage:
    bot = Pocman(cve=CVE-2023-2019, sleep_interval=1200)
    bot.run_bot()
    """
    def __init__(self, cve=None, sleep_interval=None, enable_emails=False):
        self.cves = set()
        self.sleep_interval = sleep_interval if sleep_interval else 1200
        self.db_file = APP_BASE / 'pocman.db'

        # self.run_start_date = f"{datetime.now():%Y-%m-%d}"
        self.run_start_date = datetime.today().date()
        self.run_daily_completed = False

        if isinstance(cve, str):
            self.cves.add(cve)
        elif isinstance(cve, (list, set)):
            self.cves = set(cve)


    def is_daily_pending(self):
        """
        Check/set a daily flag that tracks sending or doing something once per day.

        return True if the action is not yet completed and is pending
        """
        if self.run_daily_completed:
            # True, we already did it; check if it's a new day since start
            if self.run_start_date != datetime.today().date():
                # print(f"New Day -- Start Date: {self.run_start_date} -- Today: {datetime.today().date()}")
                print("[*] Daily email is pending now that it is a new day")
                return True
            else:
                print("[*] Daily email already run for today, not needed")
                return False
        else:
            # Else, not yet completed, do it
            print("[*] Daily email is pending")
            return True


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
            full_dataset = []
            for cve in cves_scope_for_bot:
                pocs = self.search_github(cve)
                single_cve_dataset = []
                if pocs:
                    for item in pocs:
                        # print(f"[DBG] {item=}")
                        if not item.get('description'):
                            item['description'] = ""
                        if not item.get('language'):
                            item['language'] = ''

                        formatted_pushed = convert_string_to_datetime(item.get('pushed_at'))
                        repo_record = Repository(
                            name = item['name'],
                            full_name = item['full_name'],
                            url = item['html_url'],
                            language = item['language'],
                            # description = item.get('description', ""),
                            description = item['description'],
                            stars = item.get('stargazers_count', 0),
                            last_pushed = formatted_pushed
                        )
                        single_cve_dataset.append(repo_record)

                        # print(f"{repo_record.stars:<8}{repo_record.language:<12}{repo_record.full_name:<45}")
                    # -=- End of Single CVE Loop -=-

                    # self.save_to_db(cve, pocs)
                    self.save_to_db(cve, single_cve_dataset)

                    # Sorting by most stars
                    sorted_dataset = sorted(single_cve_dataset, key=operator.attrgetter('stars'), reverse=True)
                    # print(f"[*] Sorted print of {cve} most stars first:")
                    print(f"[*] Found {len(pocs):,d} POC results for {cve} on GitHub\n")
                    print(f"{'Stars':<10}{'Language':<14}{'Name':<45}{'Last Pushed':<20}")
                    print("-" * 90)
                    for item in sorted_dataset:
                        # print(f"{item['stargazers_count']:<8}{item.get('language', ''):<12}{item['name']:<40}{item['html_url']:<40}")
                        formatted = f"{item.last_pushed:%Y-%m-%d}"
                        print(f"{item.stars:<10}{item.language:<14}{item.full_name:<45}{formatted:<20}")
                    print("-" * 90)
                    print("\n\n")
                    sleep(2)

                    # TODO: Change this to the sorted dataset once working
                    # list of cve dicts -> list of repo's for each CVE
                    full_dataset.append({cve: sorted_dataset})
            # -=- End of CVE List Loop -=-

            if self.is_daily_pending():
                self.send_daily_tracker_email(full_dataset)

            print(f"[*] Sleeping for {prettify_elapsed_time(self.sleep_interval)}...\n")
            sleep(self.sleep_interval)


    def send_daily_tracker_email(self, tracker_data):
        """
        Format the tracker data into email message format and send.

        Help on Email Templating: https://mailtrap.io/blog/python-send-email-gmail/

        """
        if not tracker_data:
            print("[ERR] Tracker data is empty, nothing to send.")
            return

        subject = "CVE Tracker Daily POC Watchlist"

        full_message = f"Hello,\nThis is your CVE daily POC exploit automated watchlist.\n"
        full_message += f"  - Currently tracking {len(self.cves):,d} CVE's\n"
        full_message += f"  - {len(tracker_data):,d} CVE's have one or more relevant GitHub repo's\n"
        full_message += "\nThose with relevant POC repositories are outlined in more detail below.\n"

        for cve_results in tracker_data:
            # cve_results is a dict of {cve: [Repository dataclasses, ...]}
            # NOTE: According to timeit, next() is more speed efficient than list() for this
            # cve = list(item.keys())[0]
            cve = next(iter(cve_results))
            full_message += f"\n\n\n{cve}:\n"

            table_data = f"\n{'Stars':<10}{'Language':<14}{'Last Pushed':<20}{'Name':<45}\n"
            table_data += "-" * 90 + '\n'

            print(f"Processing CVE: {cve}")
            for parent in cve_results.values():
                for repo in parent:
                    # print(f"{repo=}")
                    formatted = f"{repo.last_pushed:%Y-%m-%d}"
                    table_data += f"{repo.stars:<10}{repo.language:<14}{formatted:<20}{repo.full_name:<45}\n"
            table_data += "-" * 90 + '\n'
            full_message += table_data

        full_message += "\n\n\nThank you for using Pocman!\n- Read more: https://www.github.com/Cashiuus/pocman"

        mailer = EmailSender()
        mailer.send_email(subject, full_message)
        self.run_daily_completed = True
        return


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
        """
        Save CVE POC results to database.
        """
        conn = sqlite3.connect(self.db_file)
        c = conn.cursor()

        c.execute("""CREATE TABLE IF NOT EXISTS cves(id integer PRIMARY KEY, cve_id text UNIQUE, description text)""")
        # "discovered_on" is for a datetime, sqlite stores these in a text datatype
        c.execute("""
            CREATE TABLE IF NOT EXISTS pocs(
                id integer PRIMARY KEY AUTOINCREMENT,
                  full_name text unique,
                  name text, cve,
                  stars integer,
                  language text,
                  description text,
                  discovered_on text,
                  url text,
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
                # This is the original method that used dictionary input data
                # c.execute(
                #     "INSERT INTO pocs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                #     (
                #         None,
                #         poc['full_name'],
                #         poc['name'],
                #         cve,
                #         poc['stargazers_count'],
                #         poc.get('language'),
                #         poc['description'],
                #         datetime.now(),
                #         poc['html_url']),
                # )
                # This execute method uses data that is input as the Repository dataclass
                c.execute(
                    "INSERT INTO pocs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        None,
                        poc.full_name,
                        poc.name,
                        cve,
                        poc.stars,
                        poc.language,
                        poc.description,
                        datetime.now(),
                        poc.url,
                ))
                log.debug("Inserted new record into db")
            except sqlite3.IntegrityError as e:
                c.execute(
                    # "UPDATE pocs set stars = ? where full_name = ?", (poc['stargazers_count'], poc['full_name'])
                    "UPDATE pocs set stars = ? where full_name = ?", (poc.stars, poc.full_name)
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
    parser = argparse.ArgumentParser(description='Find GitHub potential exploit PoCs for a specific CVE ID')
    parser.add_argument('--cve',
                        type=str,
                        help='CVE ID to search for (ex: CVE-2023-44487)')
    # parser.add_argument('target', help='IP/CIDR/URL of target') # positional arg
    # parser.add_argument('-i', "--input_file", help="an input file")
    # parser.add_argument("-i", "--input-file", dest='input', nargs='*',
    #                     help="Specify one or more files, (process as a list)")
    parser.add_argument(
        '-s', '--sleep_time',
        type=int, default=3900,
        help='The sleep time between checks, in seconds (default is 1 hour, 5 min)',
    )
    parser.add_argument(
        '--enable-emails',
        action='store_true',
        help='Enable sending a daily update email with the results of all tracked CVEs',
    )
    # parser.add_argument("--debug", action="store_true",
    #                     help="Show debug messages for troubleshooting or verbosity")

    args = parser.parse_args()
    targets = None
    if args.cve:
        targets = args.cve
    else:
        if os.path.isfile(CVES_FILE):
            targets = load_targets_from_file(CVES_FILE)
        else:
            print(f"[!] {CVES_FILE.name} does not yet exist, creating file now. Add CVEs to it to (one per line) use this capability!")
            with open(CVES_FILE, 'w') as f:
                pass
            # Empty file is now created
            sys.exit(1)

    if not targets:
        print("[!] targets is empty, check and try again!")
        sys.exit(1)

    if args.enable_emails:
        toggle_email_sending = True
    else:
        toggle_email_sending = False

    # -- Main App Flow --
    # NOTE: Seconds <-> Hours Reference
    # 12 hours = 43200
    # 1 hour = 3600
    bot = Pocman(targets, args.sleep_time, enable_emails=toggle_email_sending)
    bot.run_bot()

    return


if __name__ == '__main__':
    main()
