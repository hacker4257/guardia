// This file contains intentional security issues for testing guardia
// All values are FAKE and for testing only

// SEC010: API Key in config
const API_KEY = "abcdef1234567890abcdef1234567890";

// SEC011: Hardcoded password
const password = "MyS3cretP@ssword!2024";

// SEC012: Bearer Token
const headers = {
  Authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
};

// SEC020: GitHub Token
const GITHUB_TOKEN = "ghp_1234567890abcdefghijABCDEFGHIJ123456";

// SEC030: Slack Token (pattern only, not a real token)
// guardia should detect: xoxb-NNNNNNNNNN-NNNNNNNNNNNNN-XXXXXXXXXXXXXXXXXXXXXXXX
const SLACK_TOKEN_PATTERN = "slack_token_goes_here";

// SEC031: Slack Webhook (pattern described in docs, not included here to avoid push protection)
const SLACK_WEBHOOK_PATTERN = "slack_webhook_url_goes_here";

// SEC032: Discord Webhook
const DISCORD_WEBHOOK = "https://discord.com/api/webhooks/0000000000/FAKE-guardia-test-webhook-value-FAKE";

// SEC040: MongoDB Connection String
const MONGO_URI = "mongodb://admin:password123@mongo.example.com:27017/mydb";

// SEC060: Stripe Key (fake test key)
const stripe = require('stripe')('sk_test_FAKE00guardia00testvalue00');

function getConfig() {
  return {
    api_secret: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
    token: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
  };
}
