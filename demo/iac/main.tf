terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

# VULNERABILITY: Access key hardcoded in provider block
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAY2K7MNQ4RST6UVWX"
  secret_key = "xK8mPn3R7vZ2qL5wJ9hE4yF1cB+tA0sD/NG6pQr"
}

# VULNERABILITY: Password hardcoded in resource
resource "aws_db_instance" "prod" {
  identifier         = "prod-database"
  engine             = "postgres"
  instance_class     = "db.t3.medium"
  allocated_storage  = 20
  username           = "dbadmin"
  password           = "TerraformHardcoded_P@ss!"
  skip_final_snapshot = true
}

# VULNERABILITY: API token in variable default
variable "github_token" {
  description = "GitHub API token"
  default     = "ghp_Ry7mKx2pQn4vZ8wBfCgHjLnMt9RsTuVwXy3"
}

# SAFE: This one correctly uses a variable reference
resource "aws_secretsmanager_secret_version" "db_creds" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = jsonencode({
    password = var.db_password   # This is fine — references a variable
  })
}
