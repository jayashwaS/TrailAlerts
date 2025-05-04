############################
# TRAILALERTS CLOUDTRAIL ANALYZER LAMBDA
############################
# Package up the main Lambda code:
data "archive_file" "trailalerts_cloudtrail_analyzer_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/TrailAlertsCloudTrailAnalyzer"
  output_path = "${path.module}/TrailAlertsCloudTrailAnalyzer.zip"
}

# Create Lambda role
resource "aws_iam_role" "trailalerts_cloudtrail_analyzer_role" {
  name = "trailalerts-cloudtrail-analyzer-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Principal = { Service = "lambda.amazonaws.com" }
        Effect    = "Allow"
        Sid       = ""
      }
    ]
  })

}

# Attach inline policy to Lambda role
resource "aws_iam_role_policy" "trailalerts_cloudtrail_analyzer_policy" {
  name = "trailalerts-cloudtrail-analyzer-policy"
  role = aws_iam_role.trailalerts_cloudtrail_analyzer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${local.cloudtrail_bucket_arn}/*"
      },
      {
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.trailalerts_rules_bucket.arn,
          "${aws_s3_bucket.trailalerts_rules_bucket.arn}/*"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.trailalerts_alerts_queue.arn
      }
    ]
  })
}

resource "aws_lambda_function" "trailalerts_cloudtrail_analyzer" {
  function_name = "trailalerts-cloudtrail-analyzer"
  runtime       = "python3.13"
  handler       = "lambda_function.lambda_handler"
  role          = aws_iam_role.trailalerts_cloudtrail_analyzer_role.arn
  layers        = [aws_lambda_layer_version.trailalerts_detection_layer.arn]
  timeout       = 30
  memory_size   = 256

  filename         = data.archive_file.trailalerts_cloudtrail_analyzer_zip.output_path
  source_code_hash = data.archive_file.trailalerts_cloudtrail_analyzer_zip.output_base64sha256

  environment {
    variables = {
      SQS_QUEUE_URL      = aws_sqs_queue.trailalerts_alerts_queue.url
      TRAILALERTS_BUCKET = aws_s3_bucket.trailalerts_rules_bucket.bucket
      ENVIRONMENT        = var.environment
    }
  }

  depends_on = [
    aws_s3_bucket.trailalerts_rules_bucket,
    aws_cloudwatch_log_group.trailalerts_cloudtrail_analyzer_log_group
  ]

}

############################
# S3 EVENT NOTIFICATION
############################
# Trigger Lambda when new logs appear in the CloudTrail bucket
resource "aws_s3_bucket_notification" "cloudtrail_logs_notification" {
  bucket = local.cloudtrail_bucket_id

  lambda_function {
    lambda_function_arn = aws_lambda_function.trailalerts_cloudtrail_analyzer.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [
    aws_s3_bucket.cloudtrail_logs,
    aws_lambda_function.trailalerts_cloudtrail_analyzer,
    aws_lambda_permission.allow_s3
  ]
}

############################
# LAMBDA PERMISSIONS
############################
resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.trailalerts_cloudtrail_analyzer.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = local.cloudtrail_bucket_arn
}

resource "aws_cloudwatch_log_group" "trailalerts_cloudtrail_analyzer_log_group" {
  name              = "/aws/lambda/trailalerts-cloudtrail-analyzer"
  retention_in_days = var.cloudwatch_logs_retention_days
}