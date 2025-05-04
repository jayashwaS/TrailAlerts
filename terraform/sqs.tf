############################
# SQS QUEUE FOR SECURITY ALERTS
############################

# Queue for security alerts - buffers detected security events before processing
resource "aws_sqs_queue" "trailalerts_alerts_queue" {
  name                       = "trailalerts-alerts-queue"
  message_retention_seconds  = 86400
  visibility_timeout_seconds = 180
  delay_seconds              = 0

}

# Policy allowing the CloudTrail Analyzer Lambda to publish security events to SQS
resource "aws_iam_role_policy" "trailalerts_cloudtrail_analyzer_sqs_policy" {
  name = "trailalerts-cloudtrail-analyzer-sqs-policy"
  role = aws_iam_role.trailalerts_cloudtrail_analyzer_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.trailalerts_alerts_queue.arn
      }
    ]
  })
}

# Policy allowing the Event Processor Lambda to consume and process security events from SQS
resource "aws_iam_role_policy" "trailalerts_event_processor_sqs_policy" {
  name = "trailalerts-event-processor-sqs-policy"
  role = aws_iam_role.trailalerts_event_processor_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = aws_sqs_queue.trailalerts_alerts_queue.arn
      }
    ]
  })
}