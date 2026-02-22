import json
import mimetypes
import os

import boto3

s3 = boto3.client("s3")
UI_BUCKET = os.getenv("UI_BUCKET", "")

CONTENT_TYPES = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".svg": "image/svg+xml"
}


def _content_type(path):
    ext = os.path.splitext(path)[1]
    if ext in CONTENT_TYPES:
        return CONTENT_TYPES[ext]
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


def lambda_handler(event, context):
    path = event.get("rawPath", "/")
    key = path.lstrip("/") or "index.html"

    try:
        response = s3.get_object(Bucket=UI_BUCKET, Key=key)
        body = response["Body"].read().decode("utf-8")
        return {
            "statusCode": 200,
            "headers": {"Content-Type": _content_type(key)},
            "body": body
        }
    except s3.exceptions.NoSuchKey:
        return {
            "statusCode": 404,
            "headers": {"Content-Type": "text/plain"},
            "body": "Not Found"
        }
    except Exception as exc:
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "text/plain"},
            "body": f"Error: {str(exc)}"
        }
