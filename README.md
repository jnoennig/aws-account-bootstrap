# Account Bootstrap

A Lambda function that is triggered by the Control Tower CloudWatch Event `CreateManagedAccount`. It automates configuration items that are not included in Control Tower. It uses boto3 to configure some resources and adds stacks to existing StackSets. It runs from the Control Tower root account.

## Trigger

CloudWatch Event rule that looks for a new account that has been created by Control Tower.

AWS Documentation: [Control Tower lifecycle events](https://docs.aws.amazon.com/controltower/latest/userguide/lifecycle-events.html#create-managed-account)

## Actions

* Set IAM password policy
* Set AWS account alias
* Enable S3 "block public access" at account level
* Create S3 logging bucket
* Enables GuardDuty on the new account and sets up master member relationship
  * If GuardDuty auto-enable is on for the Organization the GuardDuty pie
* Add Stacks to StackSets

## Variables

These variables control the regions which resources are configured in, the IAM role it assumes to configure the new accounts, which CloudFormation StackSets it will add Stacks to, how to construct the account email address, and the S3 bucket the Lambda code is stored in.

| Variable        | Format                        | Example                                      | Notes |
|-----------------|-------------------------------|----------------------------------------------|---------|
| AssumedRoleName | `role_name`                   | `AWSControlTowerExecution`                     | The role assumed by the script in the new member account. |
| CodeBucketName  | `s3_bucket_name`              | `my-automation-bucket-us-west-2`               | The S3 bucket name that has the Python code. |
| CodePath        | `folder/file`                 | `account-bootstrap/account-bootstrap_v1_0.zip` | The path to Python code zip file. |
| EnabledRegions  | `region1,region2`             | `us-west-2,us-east-1`                          | Regions you want resources created in. Used by GuardDuty and CloudFormation.
| StackSetNames   | `StackSetName1,StackSetName2` | `myconfig-rules,splunk-trumpet`                | StackSet Names |
| StackSetNamesOneRegion | `StackSetName1,StackSetName2` | `cis-cloudwatch-alarms` | StackSetNames that only need to be deployed in one region | 

## CloudFormation Template

[account-bootstrap-lambda.yaml](account-bootstrap-lambda.yaml) creates the resources for [accountBootstrap.py](accountBootstrap.py])

### Resources Created

| Type                     | Name                      | Notes                                     |
|--------------------------|---------------------------|-------------------------------------------|
| IAM Role                 | account-bootstrap         |                                           |
| IAM Policy               | account-bootstrap         | Inline policy for account-bootstrap role  |
| KMS Customer Managed CMK | account-bootstrap         |                                           |
| CloudWatch Event Rule    | account-bootstrap-trigger |                                           |
| Lambda Function          | account-bootstrap         | Python 3.8                                |

## Copyright

The Amazon copyright covers the GuardDuty functions taken from:
https://github.com/aws-samples/amazon-guardduty-multiaccount-scripts
