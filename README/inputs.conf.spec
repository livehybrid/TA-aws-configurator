[aws_configurator_description://<name>]
aws_description_role_name = This is the *name* of the role that will be assumed in each child account by the Splunk instance when configuring AWS Description data collection

[aws_configurator_cloudtrail://<name>]
aws_cloudtrail_role_arn = This is the *arn* of the role that will be assumed in the audit account when configuring AWS Cloudtrail data collection
aws_cloudtrail_sqs_url = This is the *arn* of the SQS queue that contains the S3 notifications for cloudtrail
aws_cloudtrail_sqs_region = This is the *region* of the SQS queue that contains the S3 notifications for cloudtrail

[aws_configurator_config://<name>]
aws_config_role_arn = This is the *arn* of the role that will be assumed in the audit account when configuring AWS Config data collection
aws_config_sqs_url = This is the *arn* of the SQS queue that contains the S3 notifications for config
aws_config_sqs_region = This is the *region* of the SQS queue that contains the S3 notifications for config
