#!/bin/bash
set -e
AWSSES_ACCESS_KEY_ID=$1
AWSSES_SECRET_ACCESS_KEY=$2

if [ -f ~/.aws/credentials] then
    rm ~/.aws/credentials
fi

echo "[default]" >> ~/.aws/credentials
echo "aws_access_key_id = $AWSSES_ACCESS_KEY_ID" >> ~/.aws/credentials
echo "aws_secret_access_key = $AWSSES_SECRET_ACCESS_KEY" >> ~/.aws/credentials

