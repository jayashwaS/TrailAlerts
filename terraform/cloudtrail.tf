############################
# CLOUDTRAIL CONFIGURATION
############################
resource "aws_cloudtrail" "security_trail" {
  count                         = var.create_cloudtrail ? 1 : 0
  name                          = "trailalerts-monitoring-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs[count.index].bucket
  include_global_service_events = true
  is_multi_region_trail         = true

}