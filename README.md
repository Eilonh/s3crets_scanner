# S3cret Scanner: Hunting For Secrets Uploaded To Public S3 Buckets

![](DOCS/logo.png)

* `S3cret Scanner` tool designed to provide a complementary layer for the [Amazon S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html) by proactively hunting secrets in public S3 buckets.
* Can be executed as `scheduled task` or `On-Demand`

-----
## Automation workflow
The automation will perform the following actions:
1. List the public buckets in the account (Set with ACL of `Public` or `objects can be public`)
2. List the textual or sensitive files (i.e. `.p12`, `.pgp` and more)
3. Download, scan (using truffleHog3) and delete the files from disk, once done evaluating, one by one.
4. The logs will be created in `logger.log` file.
-----
## Prerequisites
1. Python 3.6 or above
2. TruffleHog3 installed in $PATH
3. An AWS role with the following permissions. Make sure you allow the role to be assumed by editing the SID "AllowRoleToBeAssumed" with your    account's ARN for the role:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": [
                "s3:GetLifecycleConfiguration",
                "s3:GetBucketTagging",
                "s3:ListBucket",
                "s3:GetAccelerateConfiguration",
                "s3:GetBucketPolicy",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketPolicyStatus",
                "s3:GetBucketAcl",
                "s3:GetBucketLocation"
            ],
            "Resource": "arn:aws:s3:::*"
        },
        {
            "Sid": "VisualEditor1",
            "Effect": "Allow",
            "Action": "s3:ListAllMyBuckets",
            "Resource": "*"
        },
        {
            "Sid": "AllowRoleToBeAssumed",
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole"
            ],
            "Resource": [
                "arn:aws:iam::123456789012:role/desired-role"
            ]
        }
    ]
}
```

4. Make sure to edit the file `accounts.csv` in the `csv` directory to add the AWS account(s) you want to scan using the following format:
```csv
Account name,Account id
prod,123456789
ci,321654987
dev,148739578
```
-----

## Getting started

Use [pip](https://pip.pypa.io/en/stable/) to install the needed requirements.

```bash
# Clone the repo
git clone <repo>

# Install requirements
pip3 install -r requirements.txt

# Install trufflehog3
pip3 install trufflehog3
```
-----
## Usage

| Argument | Values | Description| Required|
| :---: | :---: | :---: | :---: |
| -p, --aws_profile |  | The aws profile name for the access keys | &check;
| -r, --scanner_role |  | The aws scanner\'s role name | &check;
| -m, --method | internal |the scan type | &check;
| -l, --last_modified |  1-365 | Number of days to scan since the file was last modified; _Default - 1_| &cross;


### Usage Examples
`python3 main.py -p secTeam -r secteam-inspect-s3-buckets -l 1`
-----
## Demo

![](DOCS/scanner_gif.gif)

-----
## Troubleshooting
Commomn errors and how to fix them:

* "The following files could not be found - \['trufflehog3']"
  
  trufflehog3 is missing. Install it with pip3 install trufflehog3

* "The following files could not be found - \['aws']
  
  AWS CLI is missing. Download and install it from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

* "check_for_local_aws_credentials error raised -> AWS Credentials not found!"
  
  Make sure you have installed AWS CLI found here: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
  Next, create an IAM User with programmatic access to obtain a KEYID and KEY (unless you have one already).
  See Programmatic Access here: https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html and here https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html
  Lastly, use 'aws configure' to set your AWS Credentials. See New Configuration quick setup here:  https://docs.aws.amazon.com/cli/latest/userguide/getting-started-quickstart.html

* "[-] get_sts_token exception raise -> An error occurred (AccessDenied) when calling the AssumeRole operation: User: arn:aws:iam::0123456789012:user/example_user is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::123456789012:role/example_role"
  
  Make sure you have created an IAM Role that can be assumed by your chosen IAM User. If you have a role already, then ensure that it can be assumed by your chosen IAM User. See item number 3 in the prerequisites section above.

  Creating an IAM User: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_create.html
  Creating an IAM Role for an IAM Role: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html

* "[-] get_sts_token exception raise -> Provided region_name 'seemingly-random-string-RegionCode' doesn't match a supported format."
  
  It is likely that you have pasted the IAM Key with a line break. Re-run "aws configure" and be sure that the KEY ID and KEY are pasted as one continuous string with no breaks.

* "download_content exception raised -> [Errno 2] No such file or directory: '/Users/example_user/Documents/s3crets_scanner/downloads/abc123.xyz'"

  The downloads folder is missing. Check to make the user account you are using to run S3cret Scanner has permissions to create folders.


-----
## References
 [![Medium](https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white)](https://medium.com/@hareleilon/hunting-after-secrets-accidentally-uploaded-to-public-s3-buckets-7e5bbbb80097)


-----
## Contributing
Pull requests and forks are welcome. For major changes, please open an issue first to discuss what you would like to change.

------
## License
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
