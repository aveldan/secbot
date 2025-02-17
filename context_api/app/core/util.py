import json
import requests
import os
from fastapi import UploadFile

async def json_to_dict(file: UploadFile) -> dict:
    content = await file.read()
    json_content = content.decode("utf-8")
    data_dict = json.loads(json_content)

    return data_dict

async def find_vulnerabilities(pkg: dict) -> dict:
    url = os.getenv("OSV_URL", "https://api.osv.dev/v1/query")

    response = requests.post(url, json=pkg)
    return response.json()