// Synthetic fixture: hardcoded credentials in Terraform.

provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAQ4R7MNZ2PVTW6XYL"
  secret_key = "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"
}

resource "aws_db_instance" "primary" {
  identifier          = "prod-primary"
  engine              = "postgres"
  username            = "dbadmin"
  password            = "Pr0dDb_Pass_X7y2Kp9Q"
  skip_final_snapshot = true
}

# Decoy: a variable reference, not a literal (true negative)
resource "aws_secretsmanager_secret_version" "db" {
  secret_id     = aws_secretsmanager_secret.db.id
  secret_string = var.db_password
}
