from fastapi import APIRouter, File, UploadFile
import json

from app.core import spdx_analysis
from app.core.util import json_to_dict

router = APIRouter()

@router.post("/spdx")
async def getContextSPDX(spdx: UploadFile = File(...)):
    """
        Given an spdx file, get context for that file.
    """
    sbom = await json_to_dict(spdx)
    
    return spdx_analysis.retrive_osv_context(sbom=sbom)

@router.get("/spdx/{file}")
async def getContextSPDX(file: str):
    file_paths = {
        "accelerate": "./app/files/accelerate.spdx.json",
        "it_depends": "./app/files/it_depends.spdx.json",
        "bloombot": "./app/files/bloombot.spdx.json",
        "graphtage": "./app/files/graphtage.spdx.json",
        "ansible": "./app/files/ansible.spdx.json",
        "camel": "./app/files/ansible.spdx.json",
    }

    data_dict = {}
    with open(file_paths[file], 'r') as file:
        data_dict = json.load(file)
    
    context_list = await spdx_analysis.retrive_osv_context(sbom=data_dict)

    return context_list

@router.post("/spdx/pkg")
async def getContextPackageSPDX(pkg: dict):
    context = await spdx_analysis.retrive_package_context(pkg=pkg)

    return context