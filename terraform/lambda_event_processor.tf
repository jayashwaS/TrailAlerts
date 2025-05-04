############################
# TRAILALERTS EVENT PROCESSOR LAMBDA
############################
data "archive_file" "trailalerts_event_processor_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../lambdas/TrailAlertsEventProcessor"
  output_path = "${path.module}/TrailAlertsEventProcessor.zip"
}

resource "aws_lambda_function" "trailalerts_event_processor" {
  function_name = "trailalerts-event-processor"
  runtime       = "python3.13"
  handler       = "lambda_function.lambda_handler"
  layers        = [aws_lambda_layer_version.trailalerts_detection_layer.arn]
  role          = aws_iam_role.trailalerts_event_processor_role.arn
  timeout       = 120
  memory_size   = 512

  filename         = data.archive_file.trailalerts_event_processor_zip.output_path
  source_code_hash = data.archive_file.trailalerts_event_processor_zip.output_base64sha256

  environment {
    variables = {
      DYNAMODB_TABLE_NAME           = var.correlation_enabled ? aws_dynamodb_table.security_events[0].name : ""
      SNS_TOPIC_ARN                 = var.enable_sns ? aws_sns_topic.trailalerts_alerts_topic[0].arn : ""
      EMAIL_RECIPIENT               = var.email_endpoint
      SOURCE_EMAIL                  = var.source_email
      VPNAPI_KEY                    = var.vpnapi_key
      CORRELATION_ENABLED           = tostring(var.correlation_enabled)
      CORRELATION_RULES_BUCKET      = aws_s3_bucket.trailalerts_rules_bucket.bucket
      NOTIFICATION_COOLDOWN_MINUTES = tostring(var.notification_cooldown_minutes)
      MIN_NOTIFICATION_SEVERITY     = var.min_notification_severity
    }
  }

}

resource "aws_iam_role" "trailalerts_event_processor_role" {
  name = "trailalerts-event-processor-role"

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

  tags = {
    Name        = "TrailAlerts Event Processor Lambda Role"
    Environment = var.environment
    Service     = "CloudTrail-Monitoring"
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy" "trailalerts_event_processor_policy" {
  name = "trailalerts-event-processor-policy"
  role = aws_iam_role.trailalerts_event_processor_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
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
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.trailalerts_alerts_queue.arn
      },
      {
        Effect   = "Allow"
        Action   = ["ses:SendEmail", "ses:SendRawEmail"]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = ["s3:ListBucket", "s3:GetObject"]
        Resource = [
          aws_s3_bucket.trailalerts_rules_bucket.arn,
          "${aws_s3_bucket.trailalerts_rules_bucket.arn}/*"
        ]
      }
      ],
      var.correlation_enabled ? [{
        Effect = "Allow"
        Action = ["dynamodb:PutItem", "dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan"]
        Resource = [
          aws_dynamodb_table.security_events[0].arn,
          "${aws_dynamodb_table.security_events[0].arn}/index/*"
        ]
    }] : [])
  })
}

resource "aws_lambda_event_source_mapping" "sqs_to_event_processor" {
  event_source_arn                   = aws_sqs_queue.trailalerts_alerts_queue.arn
  function_name                      = aws_lambda_function.trailalerts_event_processor.arn
  batch_size                         = 10
  maximum_batching_window_in_seconds = 60
}

resource "aws_cloudwatch_log_group" "trailalerts_event_processor_log_group" {
  name              = "/aws/lambda/${aws_lambda_function.trailalerts_event_processor.function_name}"
  retention_in_days = var.cloudwatch_logs_retention_days
}