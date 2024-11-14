import json
import requests
import os
from dotenv import load_dotenv


def req_body(filename: str) -> list[dict]:
    sbom = json_to_dict(filename)
    body_params = []
    
    refrence = {
        "pypi": "PyPI",
        "npm": "npm"
    }

    packages = sbom["packages"]
    for package in packages:
        bdy = {}
        if "versionInfo" in package:
            bdy["version"] = package["versionInfo"]
        
        bdy["package"] = {"name": package["name"]}
        lst = package["externalRefs"]
        for ref in lst:
            if ref["referenceType"] == "purl":
                ecosystem = ""
                for i in range(4, len(ref["referenceLocator"])):
                    if ref["referenceLocator"][i] == '/':
                        break
                    ecosystem += ref["referenceLocator"][i]
                if ecosystem.lower() in refrence:
                    bdy["package"]["ecosystem"] = refrence[ecosystem.lower()]

        body_params.append(bdy)

    return body_params

def params(filename: str):
    sbom = json_to_dict(filename)
    body_params = {}
    
    refrence = {
        "pypi": "PyPI",
        "npm": "npm"
    }

    packages = sbom["packages"]
    for package in packages:
        bdy = {}
        if "versionInfo" in package:
            bdy["version"] = package["versionInfo"]
        
        bdy["package"] = {"name": package["name"]}
        lst = package["externalRefs"]
        for ref in lst:
            if ref["referenceType"] == "purl":
                ecosystem = ""
                for i in range(4, len(ref["referenceLocator"])):
                    if ref["referenceLocator"][i] == '/':
                        break
                    ecosystem += ref["referenceLocator"][i]
                if ecosystem.lower() in refrence:
                    bdy["package"]["ecosystem"] = refrence[ecosystem.lower()]

        body_params[package["name"]] = bdy

    return body_params

def json_to_dict(filename: str) -> dict:
    data_dict = {}
    with open(filename, 'r') as file:
        data_dict = json.load(file)

    return data_dict

def find_vulnerabilities(pkg: dict) -> dict:
    load_dotenv()
    url = os.getenv("OSV_URL")

    response = requests.post(url, json=pkg)
    return response.json()