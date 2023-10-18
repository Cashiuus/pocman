PoC Man
========


Monitoring platform to identify and catalog Proof of Concept (POC) tools, scanners, or exploitation scripts for various CVE's.





## Usage

```
# Search for CVE and run it every 600 seconds (10 minutes)
python pocman.py CVE-2023-20198 -s 600
```


## TODO

[] Expand code to support GitHub Actions workflow bot that runs on schedule, sends messages of new repo's identified since last run (using list of CVE's to search on), and tracks last run data using `pocman_latest.json` file

[] Publish as a PyPi package for easy use in other projects




Similar Projects
=================
Thank you to similar projects that may have similar or in some cases more robust functionality:

- (Python) https://github.com/dorkerdevil/poc-mon
- (Python): https://github.com/sari3l/Poc-Monitor
- (Go): https://github.com/sari3l/Poc-Monitor
