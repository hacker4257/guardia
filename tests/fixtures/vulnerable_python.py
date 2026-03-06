# This file contains intentional security issues for testing guardia
# All values are FAKE and for testing only

import os
import boto3

# SEC001: AWS Access Key ID
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# SEC002: AWS Secret Access Key
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# SEC010: Generic API Key
api_key = "sk_test_FAKE00guardia00test00value00abcdefgh"

# SEC011: Generic Password
database_password = "SuperSecretP@ssw0rd123!"

# SEC020: GitHub Token
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"

# SEC040: Database Connection String
DATABASE_URL = "postgres://admin:secretpass123@db.example.com:5432/myapp"

# SEC060: Stripe Key (fake test key)
STRIPE_KEY = "sk_test_FAKE00guardia00testvalue00only"

# SEC080: JWT Token
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

def connect_to_db():
    return boto3.client(
        's3',
        aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
        aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
    )
