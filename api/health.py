def handler(request):
    return {
        "statusCode": 200,
        "body": '{"status": "ok"}',
        "headers": {
            "Content-Type": "application/json"
        }
    }
