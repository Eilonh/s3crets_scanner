import utils
import logging
from logger_config import logger_conf
import argparse
import scripts

# Logger configurations
logger_conf()
logger = logging.getLogger("S3 scanner")

# Parser arguments
parser = argparse.ArgumentParser(description='S3 scanner')
parser.add_argument('--method', '-m', type=str, help='the scan type', required=True)
parser.add_argument('--aws_profile', '-p', type=str, help='the aws IAM User name corresponding with your locally stored access keys', required=True)
parser.add_argument('--scanner_role', '-r', type=str, help='the aws scanner\'s role name', required=True)
parser.add_argument('--last_modified', '-l', type=int, default=1,
                    help='the number of days to scan since the file was last modified (scan files this many days old)')

args = parser.parse_args()

if __name__ == "__main__":
    colors = utils.Colors()
    utils.print_banner()
    utils.check_for_local_aws_credentials()
    utils.create_downloads_folder()
    utils.prerequisite_checks('trufflehog3','aws')
    

    if args.method.lower() == 'internal':
        print(colors.WARNING)
        logger.info(f"[+] Scanning for files which last modified since {utils.get_modified_date(args.last_modified)}")
        print(colors.ENDC, end="")
        scripts.scan_internal_accounts(args.aws_profile, args.scanner_role, args.last_modified)
    else:
        print(colors.LIGHTRED,'[!] Not a valid action - please choose the method \"internal\"', colors.ENDC)