## Disclaimer

Automated account ripper, to terminate and delete orphaned AWS resources automatically across multiple accounts, regions and services.

## Usecase

If you ever tried to cleanup temporary AWS testing accounts, you might understand the pain of logging in to multiple AWS accounts, deleting various cloud resources hidden within various services and regions.

## Overview

This AWS account ripper is a tool to automate the task of deleting resources within an AWS account. By enabling the "removeStuff" flag various supported AWS resources will not only be indexes but also DELETED. This script goes through all AWS accounts specified below by assuming the role  "OrganizationAccountAccessRole" and shows an inventory of all resources such as

- cloudformation stacks
- ec2 instances
- s3 buckets
- lambda functions
- iam users, groups and roles
- codestar projects
- cognito user pools
- dynamodb tables

Built on top of boto3.

## Setup

```sh
cd ./aws-account-ripper
python3 -m venv ./py3/
source ./py3/bin/activate
pip3 install -r requirements.txt
```

## Usage

```sh
python3 aws-account-ripper.py
deactivate
```

## AWS CLI commands for inventory

```sh
aws organizations list-accounts
aws cloudformation describe-stacks
aws ec2 describe-instances
aws ec2 describe-security-groups
aws ec2 describe-key-pairs
aws codestar list-projects
aws lambda list-functions
aws cognito-identity list-identity-pools --max-results 10
aws dynamodb list-tables
aws s3 ls
aws iam list-groups
aws iam list-roles
aws iam list-users
aws iam update-login-profile --user-name userXX --password "newpassword"
```

## External references

- [Assume role](https://gist.github.com/gene1wood/938ff578fbe57cf894a105b4107702de)
- [Randall Hunt](http://ranman.com/cleaning-up-aws-with-boto3/)

## TODO

- Add deletion of non empty S3 buckets
- Add deletion of IAM users/groups/roles with login-profiles & policies attached
