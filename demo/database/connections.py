import os

# Database connection strings — all hardcoded
POSTGRES_URL = "postgresql://admin:S3cur3Passw0rd!@prod-db.example.com:5432/appdb"
MYSQL_URL    = "mysql://root:MySQLPr0d_P@ss@10.0.1.5:3306/users"
MONGO_URL    = "mongodb://mongouser:MongoS3cret!@cluster0.mongodb.net:27017/analytics"
REDIS_URL    = "redis://redisuser:Redis_P@ssw0rd@cache.example.com:6379/0"

# Individual config dict
DB_CONFIG = {
    "host": "prod-db.example.com",
    "port": 5432,
    "database": "appdb",
    "username": "dbadmin",
    "password": "Ultra$ecretDBPass_2024!",
}

# Environment variable name shadows — these are real values, not references
DB_PASSWORD = "Pr0d_DB_P@ssw0rd_2024!"
database_password = "Leaked_DB_P@ss_Xyz789$"
db_pass = "L3akd_99!
