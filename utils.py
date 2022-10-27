import subprocess
import json
import logging
from datetime import datetime, timedelta
import glob
import os

import requests

import csv
import re
from logger_config import logger_conf
import shutil
import sys

# Logger instance
logger_conf()
logger = logging.getLogger("S3 scanner")

cwd = os.getcwd()


def print_banner():
    print("""
   __________                __                                          
  / ___/__  /_____________  / /_   ______________ _____  ____  ___  _____
  \__ \ /_ </ ___/ ___/ _ \/ __/  / ___/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
 ___/ /__/ / /__/ /  /  __/ /_   (__  ) /__/ /_/ / / / / / / /  __/ /    
/____/____/\___/_/   \___/\__/  /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                                         v1.0 """)


class Colors:
    LIGHTRED = '\033[1;31m'
    LIGHTGREEN = '\033[1;32m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def normalize_filename(public_file) -> str:
    if "/" in public_file:
        download_name = public_file.replace("/", "//")
    else:
        download_name = public_file
    return download_name


def read_csv() -> dict:
    """ Parse the accounts CSV file

        Returns:
            The account name, as a key, with the corresponding account id
            i.e - {'account_name': 'account_id'}
    """
    accounts_dict = dict()
    try:
        # Validate that accounts.csv is in csv folder
        file = os.path.isfile('csv/accounts.csv')
        if not file:
            logger.info(f"No accounts.csv file found in {cwd}/csv folder")
            sys.exit()
        with open(f'{cwd}/csv/accounts.csv', 'r') as file:
            reader = csv.reader(file)
            for row in reader:
                try:
                    assert re.match(r'^\d+$', row[1])
                    accounts_dict[row[0]] = row[1]
                except AssertionError:
                    pass
                except Exception as e:
                    logger.debug(e)
        logger.info(f'[+] Successfully loaded CSV file - {cwd}/csv/accounts.csv')
        logger.info(f'[+] {len(accounts_dict)} accounts were loaded')
        return accounts_dict
    except Exception as e:
        logger.debug(e)
        sys.exit()


def get_modified_date(time_delta: int) -> any:
    """ Calculate the time from the specified interval
    Args:
        time_delta: the number of days to scan since the file was last modified

    Return:
        the datetime object in %Y-%m-%d 00:00:00+00:00 format
    """
    dt_string = datetime.strftime(datetime.now() - timedelta(time_delta), "%Y-%m-%d 00:00:00+00:00")
    return dt_string


def create_downloads_folder():
    try:
        files = glob.glob(f'{cwd}/*')
        for file in files:
            if file.endswith('downloads'):
                return True
        os.mkdir(f'{cwd}/downloads')
        logger.info("Successfully created downloads directory in the CWD")
    except Exception as e:
        logger.error(f"create_downloads_folder exception raised -> {e}")
        sys.exit()


def delete_files():
    try:
        files = glob.glob(f'{cwd}/downloads/*')
        for file in files:
            os.remove(file)
            logger.info("[*] Successfully deleted {}".format(file))
    except Exception as e:
        logger.error(f"delete_files exception raised -> {e}")


def write_findings(file_name, findings):
    try:
        with open(file_name, "a") as file:
            file.write(json.dumps(findings)+"\n")
    except Exception as e:
        logger.error(f"write_findings error raised -> {e}")


def run_trufflehog(bucket, file):
    try:
        all_findings = list()
        command = ["trufflehog3", "downloads", "--format", "json", "-r", "rules.yml"]
        t = subprocess.Popen(command, stdout=subprocess.PIPE)
        output = t.stdout.read().decode("UTF-8")
        json_data = json.loads(output)
        for i in range(len(json_data)):
            rule = json_data[i]['rule'].get('message', None)
            file = json_data[i].get('path', None)
            line = json_data[i].get('line', None)
            secret = json_data[i].get('secret', None)
            findings = {
                "bucket": bucket,
                "rule": rule,
                "file": file,
                "line": line,
                "result": secret
            }

            all_findings.append(findings)
        if all_findings:
            return all_findings[0]['rule'], all_findings[0]
        else:
            logger.info("[-] No results found in {}".format(file))
            return None, None
    except IndexError:
        logger.info("No results found in {}".format(file))
        return None, None
    except Exception as e:
        logger.error(f"run_trufflehog exception raised -> {e}")
        return None, None


def prerequisite_checks(*args):
    try:
        missing_files = []
        for arg in args:
            try:
                check = shutil.which(arg)
                assert check, arg
            except AssertionError as ae:
                missing_files.append("".join(ae.args))
        if missing_files:
            logger.error(f'The following files could not be found - {missing_files}')
            sys.exit()
        else:
            logger.info("[+] Prerequisite checks passed")
    except Exception as e:
        logger.error(e)


def download_content(bucket_name, file_name, download_name):
    try:
        r = requests.get(
            f'https://{bucket_name}.s3.amazonaws.com/{file_name}')
        text_file = json.dumps(r.json())
        with open(f'{os.getcwd()}/downloads/{download_name}', 'w') as f:
            f.write(text_file)
    except Exception as e:
        logger.error(f'download_content exception raised -> {e}')
