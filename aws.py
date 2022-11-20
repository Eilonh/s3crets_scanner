import logging
import sys

import boto3
import botocore
from botocore.client import Config
from botocore import UNSIGNED
import os
import utils
from logger_config import logger_conf
import botocore.exceptions

# Logger
logger_conf()
logger = logging.getLogger("S3 scanner")

# Exponential backoff
config = Config(
    retries=dict(
        max_attempts=10
    )
)

colors = utils.Colors()

def get_sts_token(account_id: any, profile_name: str, scanner_role_name: str) -> dict or None:
    """Assumes the IAM role you must set up for s3cret scanner in the accounts specified in accounts.csv

    Args:
        account_id: the number representation of the account
        profile_name: the IAM user name that corresponds with the KEYID and KEY stored in the local aws profile in ~./aws/credentials
        scanner_role_name: the role name without ARN


    Returns:
        Temporary AWS role credentials (by default - valid for 12H)
    """
    try:
        try:
            session = boto3.Session(profile_name=profile_name)
        except Exception:
            session = boto3.session.Session()
        sts_client = session.client('sts', config=config)
        scanner_arn_role = f"arn:aws:iam::{account_id}:role/{scanner_role_name}"
        assumed_role_object = sts_client.assume_role(
            RoleArn=scanner_arn_role,
            RoleSessionName="AssumeRoleSession1",
        )
        credentials = assumed_role_object['Credentials']
        # Session init
        session = boto3.Session(
            aws_access_key_id=credentials['AccessKeyId'],
            aws_secret_access_key=credentials['SecretAccessKey'],
            aws_session_token=credentials['SessionToken'],
        )
        return session

    except Exception as e:
        print(colors.FAIL)
        logger.debug(f"[-] get_sts_token exception raise -> {e}")
        logger.debug(f"[?] Did you forget to edit the CSV file found here: {utils.cwd}/csv/accounts.csv ?")
        logger.debug(f"[?] Did you remember to run 'aws configure'? https://docs.aws.amazon.com/cli/latest/userguide/getting-started-quickstart.html ")
        sys.exit()


def get_all_buckets(session, account_name) -> list or None:
    """List all buckets in the supplied account

    Args:
        session: the active session key
        account_name: the name of the account

    Returns:
        A list of buckets
    """
    try:
        s3 = session.resource("s3")
        bucket_list = list()
        for bucket in s3.buckets.all():
            bucket_list.append(bucket.name)
        return bucket_list
    except Exception as e:
        logger.debug(f"{colors.FAIL}[-] get_all_buckets exception raised on {account_name} -> {e}{colors.ENDC}")
        return None


def get_all_objects_anonymous(bucket_name) -> list or None:
    """List all buckets in the account

    Args:
        None

    Returns:
        A list of buckets
    """
    try:
        resource = boto3.resource('s3', config=Config(signature_version=UNSIGNED))
        objects_list = list()
        bucket = resource.Bucket(bucket_name)
        for item in bucket.objects.all():
            objects_list.append(item.key)
        return objects_list
    except Exception as e:
        logger.debug(f"{colors.FAIL}[-] get_all_buckets exception raised -> {e}{colors.ENDC}")
        return None


def list_bucket_content(session: str, bucket_name: str, time_delta: int) -> list or None:
    """Iterating on the bucket's content, search for textual objects

    Args:
        session: the active session key
        bucket_name: the name of the specific bucket
        time_delta: scan files this many days old

    Returns:
        textual_files: all the textual files name found in the bucket
        total_download_size: sum of all textual files size
    """
    try:
        textual_files = list()
        s3 = session.client("s3")
        paginator = s3.get_paginator('list_objects')
        operation_parameters = {'Bucket': f'{bucket_name}'}
        page_iterator = paginator.paginate(**operation_parameters)
        dt_string = utils.get_modified_date(time_delta)
        jmespath_query = f"Contents[?to_string(LastModified)>'\"{dt_string}\"'][]"
        filtered_iterator = page_iterator.search(jmespath_query)
        for result in filtered_iterator:
            if result:
                file_name = result['Key']
                if file_name.endswith((".txt", "log", ".htm", ".xml", ".json", ".js", ".accdb", ".bat", ".c", ".c#",
                                       ".cer", ".cpp", ".cxx", ".dbf", ".doc", ".docx", ".dot", ".dotx",
                                       ".eml", ".gpg", ".iwa", ".jar", ".java", ".msg", ".p12", ".pgp", ".py",
                                       ".sql", ".tsv", ".xls", ".xlsx", ".log", ".creds")):
                    textual_files.append(file_name)
                ##if file_name contains 'credentials' or results of 'file' command is a text file add to textual_files.append(file_name)
        return textual_files
    except Exception as e:
        logger.debug(f'{colors.FAIL}list_bucket_content exception raised -> {e}{colors.ENDC}')


def get_object_acl(bucket_name: str, file_path: str, session: str) -> str or None:
    """Checks the textual object's ACL

    Args:
        bucket_name: the name of the specific bucket
        file_path: full path of the resource
        session: the active session key

    Returns:
        file path of the resources, if the file is public
    """
    try:
        s3 = session.client("s3")
        response = s3.get_object_acl(Bucket=bucket_name, Key=file_path)
        for i in range(len(response['Grants'])):
            entity = response['Grants'][i]['Grantee'].get('URI')
            if entity:
                if "allusers" or 'authenticatedusers' in entity.lower():
                    return file_path
        return None
    except Exception as e:
        logger.info(f"{colors.WARNING}Blocked by Bucket ACL - {file_path} -> {e}{colors.ENDC}")


def download_content(session: str, bucket_name: str, file_name: str, download_name: str):
    """Iterating on the bucket's content, search for textual objects

    Args:
        session: the active session key
        bucket_name: the name of the specific bucket
        file_name: the full S3 path of the file
        download_name: the normalized file path
    """
    try:
        s3 = session.client("s3")
        downloaded_file = f'{os.getcwd()}/downloads/{download_name}'
        s3.download_file(bucket_name, file_name, downloaded_file)
    except Exception as e:
        logger.debug(f'{colors.FAIL}download_content exception raised -> {e}{colors.ENDC}')

def download_public_content(bucket_name: str, file_name: str, download_name: str):
    """Download the file to the ${cwd}/downloads folder, using Boto3

    Args:
        bucket_name: the name of the specific bucket:
        file_name: the name of the file located in the bucket
        download_name: the name of the file which will be saved in ${pwd}/downloads folder

    Return:
        None
    """
    try:
        cwd = os.getcwd()
        client = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        downloaded_file = f'{cwd}/downloads/{download_name}'
        client.download_file(bucket_name, file_name, downloaded_file)
    except Exception as e:
        logger.debug(f"{colors.FAIL}[-] download_content exception raised -> {e}{colors.FAIL}")

def get_public_access_block(session: str, bucket_name: str) -> bool or None:
    """
    Args:
        bucket_name: the name of the specific bucket
        session: the active session key

    Return:
        bool - False (restricted), True (public/objects can be public)

    """
    try:
        s3 = session.client('s3')
        response = s3.get_public_access_block(Bucket=bucket_name)
        block_public_acls = response['PublicAccessBlockConfiguration'].get('BlockPublicAcls')
        block_public_policy = response['PublicAccessBlockConfiguration'].get('BlockPublicPolicy')
        if block_public_acls and block_public_policy:
            # Bucket is restricted
            return False
        else:
            # Bucket is public
            return True
    except botocore.exceptions.ClientError as ce:
        if ce.response['Error'].get('Code') == 'NoSuchPublicAccessBlockConfiguration':
            return True
    except Exception as e:
        logger.debug(f"{colors.FAIL}[-] get_public_access_block exception raised -> {e}{colors.ENDC}")
        return None