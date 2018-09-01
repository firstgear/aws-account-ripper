import boto3
import accountlist

awsAccounts = accountlist.awsAccounts

# Commented out non-used regions to speedup inventory
awsRegions = {
  "us-east-1": "US East (N. Virginia)",
  "us-east-2": "US East (Ohio)",
  "us-west-1": "US West (N. California)",
  "us-west-2": "US West (Oregon)",
  "ca-central-1": "Canada (Central)",
  "eu-central-1": "EU (Frankfurt)",
  "eu-west-1": "EU (Ireland)",
  "eu-west-2": "EU (London)",
  "eu-west-3": "EU (Paris)",
#  "ap-northeast-1": "Asia Pacific (Tokyo)",
#  "ap-northeast-2": "Asia Pacific (Seoul)",
#  "ap-northeast-3": "Asia Pacific (Osaka-Local)",
#  "ap-southeast-1": "Asia Pacific (Singapore)",
#  "ap-southeast-2": "Asia Pacific (Sydney)",
#  "ap-south-1": "Asia Pacific (Mumbai)",
#  "sa-east-1": "South America (Sao Paulo)"
}

awsServices = {
  "cloudformation": False,
  "ec2": False,
  "s3": False,
  "lambda": True,
  "iam": False,
  "codestar": False,
  "cognito": False,
  "dynamodb": False,
}

awsRoleName = "OrganizationAccountAccessRole"

removeStuff = False

def role_arn_to_session(**args):
    """
    Usage :
        session = role_arn_to_session(
            RoleArn='arn:aws:iam::012345678901:role/example-role',
            RoleSessionName='ExampleSessionName')
        client = session.client('sqs')
    """
    client = boto3.client('sts')
    response = client.assume_role(**args)
    return boto3.Session(
        aws_access_key_id=response['Credentials']['AccessKeyId'],
        aws_secret_access_key=response['Credentials']['SecretAccessKey'],
        aws_session_token=response['Credentials']['SessionToken'])

for i in awsAccounts:
    awsAccount = awsAccounts[i]
    session = role_arn_to_session(
        RoleArn="arn:aws:iam::" + str(awsAccount) + ":role/OrganizationAccountAccessRole",
        RoleSessionName='awsAccount')
    print("> " + str(i) + " = " + str(awsAccount))

# Global Services
# S3 delete not working for non empty buckets

    if awsServices["s3"]:
        s3 = session.resource('s3')
        for bucket in s3.buckets.all():
            print(">> S3 " + bucket.name)
            if removeStuff:
                print("Deleting S3 bucket")
                empty_s3_bucket(bucket.name)

    if awsServices["iam"]:
        iam = session.client('iam')
        for grouplist in iam.list_groups()['Groups']:
            groupName = grouplist['GroupName']
            print(">> IAM group " + groupName)
            #if removeStuff:
            #    print("Deleting IAM Group")
            #    response = iam.delete_group(GroupName=groupName)
            #    print(response)
        for userlist in iam.list_users()['Users']:
            userName = userlist['UserName']
            if str(userName) != str(i):
                print(">> IAM user " + userName)
                if removeStuff:
                    print("Deleting IAM User")
                    try:
                        response = iam.get_login_profile(UserName=userName)
                        response = iam.delete_login_profile(UserName=userName)
                    except Exception as e:
                        if e.response['ResponseMetadata']['HTTPStatusCode'] == 404:
                            print('User {} has no login profile'.format(userName))
                    try:
                        response = iam.delete_user(UserName=userName)
                    except Exception as e:
                        if e.response['ResponseMetadata']['HTTPStatusCode'] == 409:
                            print('User {} limit exceeded'.format(userName))
                    #response = iam.list_user_policies(UserName=userName)
                    #response = iam.list_policies()
        for rolelist in iam.list_roles()['Roles']:
            print(">> IAM role " + rolelist['RoleName'])

#Regional Services
    if awsServices["cloudformation"]:
        for region in awsRegions:
            cloudformation = session.resource('cloudformation', region_name=region)
            cloudformationclient = session.client('cloudformation', region_name=region)
            for stack in cloudformation.stacks.all():
                print(">> CF " + region + " "+ stack.name)
                if removeStuff:
                    print("Deleting stack")
                    cloudformationclient.delete_stack(
                        StackName=stack.name,
                        RoleARN="arn:aws:iam::" + str(awsAccount) + ":role/OrganizationAccountAccessRole"
                    )

    if awsServices["ec2"]:
        for region in awsRegions:
            ec2 = session.resource('ec2', region_name=region)
            ec2client = session.client('ec2', region_name=region)
            for instance in ec2.instances.all():
                print(">> EC2 " + region + " "+ instance.instance_id + " "+ instance.instance_type)
                if removeStuff:
                    print("Terminating EC2 instance")
                    response = ec2client.terminate_instances(InstanceIds=[instance.instance_id])
                    print(response)

    if awsServices["lambda"]:
        for region in awsRegions:
            client = session.client('lambda', region_name=region)
            functions = client.list_functions()
            if functions["Functions"]:
                for functionName in functions["Functions"]:
                    print(">> Lambda " + region + " "+ functionName["FunctionName"])
                    if removeStuff:
                        print("Deleting Lambda")
                        response = client.delete_function( FunctionName=functionName["FunctionName"] )
                        print(response)

    if awsServices["codestar"]:
        codestarNotInRegion = ["eu-west-3"]
        for region in awsRegions:
            if region not in codestarNotInRegion:
                projects = session.client('codestar', region_name=region).list_projects()
                if projects["projects"]:
                    for projectName in projects["projects"]:
                        print(">> Codestar " + region + " "+ projectName["projectId"])
                        if removeStuff:
                                print("Deleting Codestar project")
                                response = session.client.delete_project(
                                    id=projectName["projectId"],
                                    deleteStack=True
                                    )
                                print(response)

    if awsServices["cognito"]:
        cognitoNotInRegion = ["us-west-1","ca-central-1","sa-east-1","eu-west-3"]
        for region in awsRegions:
            if region not in cognitoNotInRegion:
                cognito = session.client('cognito-idp', region_name=region)
                pools = cognito.list_user_pools(MaxResults=60)
                if pools["UserPools"]:
                    for pool in pools["UserPools"]:
                        print(">> Cognito " + region + " "+ pool["Name"])
                        if removeStuff:
                            response = cognito.delete_user_pool( UserPoolId=pool["Id"] )
                            print(response)

    if awsServices["dynamodb"]:
        for region in awsRegions:
            dynamo = session.client('dynamodb', region_name=region)
            tables = dynamo.list_tables()
            if tables["TableNames"]:
                for table in tables["TableNames"]:
                    print(">> DDB " + region + " "+ table)
                    if removeStuff:
                        response = dynamo.delete_table(TableName=table)
                        print(response)
