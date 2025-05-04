############################
# S3 BUCKETS FOR TRAILALERTS
############################

# CloudTrail audit logs bucket - stores all AWS API activity for security analysis
resource "aws_s3_bucket" "cloudtrail_logs" {
  count  = var.create_cloudtrail ? 1 : 0
  bucket = "trailalert-cloudtrail-logs-${data.aws_caller_identity.current.account_id}"

}

# Bucket for storing Sigma detection rules and correlation configurations
resource "aws_s3_bucket" "trailalerts_rules_bucket" {
  bucket = "trailalerts-rules-${data.aws_caller_identity.current.account_id}"

}

############################
# CLOUDTRAIL BUCKET SECURITY POLICY
############################
resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  count  = var.create_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail_logs[count.index].bucket

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs[count.index].arn
      },
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs[count.index].arn}/*"
      }
    ]
  })
}