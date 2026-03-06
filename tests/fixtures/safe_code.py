# This file should NOT trigger any findings

import os

# Using environment variables - safe
API_KEY = os.environ.get("API_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")

# Placeholder values - should be filtered
api_key = "your_api_key_here"
password = "changeme"
token = "example_token_placeholder"
secret = "TODO_replace_this"

# Normal code
def calculate_sum(a, b):
    return a + b

class Config:
    DEBUG = True
    PORT = 8080
    HOST = "0.0.0.0"
