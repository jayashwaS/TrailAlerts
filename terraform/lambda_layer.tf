############################
# LAMBDA LAYER BUILD
############################
resource "null_resource" "build_trailalerts_lambda_layer" {
  # If the requirements.txt changes, re-run build.sh
  triggers = {
    requirements_sha1 = filesha1(local.requirements_path)
  }

  provisioner "local-exec" {
    command = "../lambdas/layer/build.sh"
  }
}

resource "aws_lambda_layer_version" "trailalerts_detection_layer" {
  depends_on          = [null_resource.build_trailalerts_lambda_layer]
  layer_name          = local.layer_name
  compatible_runtimes = ["python3.13"]
  skip_destroy        = true
  filename            = local.layer_zip_path
  source_code_hash    = filebase64sha256(local.layer_zip_path)

  description = "Layer containing TrailAlerts detection dependencies"
}