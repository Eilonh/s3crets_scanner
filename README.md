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
3. An AWS role with the following permissions:

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
    ]
}
```
4. If you're using a CSV file - make sure to place the file `accounts.csv` in the `csv` directory, in the following format:
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
| -l, --last_modified |  1-365 | Number of days to scan since the file was last modified; _Default - 1_| &cross;


### Usage Examples
`python3 main.py -p secTeam -r secteam-inspect-s3-buckets -l 1`
-----
## Demo

![](DOCS/scanner_gif.gif)

-----
## References
 [![Medium](https://img.shields.io/badge/Medium-12100E?style=for-the-badge&logo=medium&logoColor=white)](https://medium.com/@hareleilon/hunting-after-secrets-accidentally-uploaded-to-public-s3-buckets-7e5bbbb80097)


-----
## Contributing
Pull requests and forks are welcome. For major changes, please open an issue first to discuss what you would like to change.

------
## License
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
