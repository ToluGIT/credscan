provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

resource "aws_db_instance" "main" {
  password = "SuperSecret123!"
}

variable "api_token" {
  default = "ghp_SAFE_NOT_THIS"
}
