############################
# SNS TOPIC FOR SECURITY NOTIFICATIONS
############################
resource "aws_sns_topic" "trailalerts_alerts_topic" {
  count = var.enable_sns ? 1 : 0

  name = "trailalerts-cloudtrail-alerts"

}

# Email subscription for security notifications
resource "aws_sns_topic_subscription" "email_subscription" {
  count = var.enable_sns ? 1 : 0

  topic_arn = aws_sns_topic.trailalerts_alerts_topic[0].arn
  protocol  = "email"
  endpoint  = var.email_endpoint
}

# Security policy restricting publishing permissions to the SNS topic
data "aws_iam_policy_document" "sns_topic_policy" {
  count = var.enable_sns ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["SNS:Publish"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
    resources = [aws_sns_topic.trailalerts_alerts_topic[0].arn]
  }
}

# IAM policy document for Lambda roles to publish to SNS
data "aws_iam_policy_document" "sns_topic_policy_role" {
  count = var.enable_sns ? 1 : 0

  statement {
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.trailalerts_alerts_topic[0].arn]
  }
}

# Attach the security policy to the SNS topic
resource "aws_sns_topic_policy" "trailalerts_alerts_policy" {
  count = var.enable_sns ? 1 : 0

  arn    = aws_sns_topic.trailalerts_alerts_topic[0].arn
  policy = data.aws_iam_policy_document.sns_topic_policy[0].json
}

# Attach the publishing permissions to the event processor role
resource "aws_iam_role_policy" "sns_topic_policy" {
  count = var.enable_sns ? 1 : 0

  name = "sns_topic_policy"
  role = aws_iam_role.trailalerts_event_processor_role.id

  policy = data.aws_iam_policy_document.sns_topic_policy_role[0].json
}