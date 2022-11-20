import utils
import logging
import aws
from logger_config import logger_conf

# Logger instance
logger_conf()
logger = logging.getLogger("S3 scanner")

colors = utils.Colors()

def scan_internal_accounts(aws_profile: str, scanner_role: str, time_delta: int):
    """ Main function to scan internal accounts

    Args:
        aws_profile: the aws profile in ~/.aws/credentials
        scanner_role: the role name without ARN prefix
        time_delta: the number of days in the past to scan since the file was last modified
    """
    total_public_files = dict()
    accounts = utils.read_csv()
    for account_name, account_id in accounts.items():#
        sts_token = aws.get_sts_token(account_id,
                                      profile_name=aws_profile,
                                      scanner_role_name=scanner_role)
        bucket_list = aws.get_all_buckets(sts_token, account_name) #############
        public_buckets = [] #array to contain a list of public buckets
        try:
            if bucket_list:
                for bucket in bucket_list:
                    # Check bucket exposure
                    is_public = aws.get_public_access_block(sts_token, bucket)

                    if is_public:
                        public_buckets.append(bucket) #populate the array of public buckets with the intention to process them all at once
                        #print(f"public_buckets is {public_buckets}")

                for public_bucket in public_buckets:
                    ##start async here?
                    logger.info(f"{colors.WARNING}\n[*] Analyzing public bucket - {public_bucket} in"
                                f" {account_name} account{colors.ENDC}")
                    textual_files = aws.list_bucket_content(sts_token, public_bucket, time_delta) 
                    if textual_files:
                        for file in textual_files:
                            # Check file exposure
                            public_file = aws.get_object_acl(public_bucket, file_path=file, session=sts_token)
                            if public_file:
                                logger.info(f"[+] Recently changed public file - {public_file} "
                                            f"found in {public_bucket} bucket")
                                file_extension = public_file.split(".")[-1]
                                total_public_files.setdefault(file_extension, []).append(public_file)
                                # Normalize file names
                                download_name = utils.normalize_filename(public_file)
                                aws.download_content(sts_token, public_bucket, public_file, download_name)
                                if public_file.endswith((".p12", ".pgp", ".docx", ".dotx", ".xslx")):
                                    logger.info(f"{colors.OKCYAN}[!] Encrypted file type found -> {public_file} {colors.ENDC}")
                                    utils.write_findings(file_name='findings.json',
                                                        findings=[{
                                                            "bucket": public_bucket,
                                                            "rule": "Suspicious file type detected",
                                                            "file": file}]
                                                        )
                                rule, findings = utils.run_trufflehog(public_bucket, file)
                                if findings:
                                    print(colors.OKCYAN, colors.UNDERLINE)
                                    logger.warning(f'[!] Scan finding -> {findings}')
                                    print(colors.ENDC)
                                    utils.write_findings(file_name='findings.json', findings=findings)
                                utils.delete_files()
                print(colors.PURPLE,"=== Scan completed ===", colors.ENDC)
        except TypeError as te:
            logger.debug(te)
