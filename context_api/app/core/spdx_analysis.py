from app.core.util import find_vulnerabilities
from app.model.context import Context

refrence = {
    "pypi": "PyPI",
    "npm": "npm"
}

def params(sbom: dict):
    body_params = {}

    packages = sbom["packages"]
    for package in packages:
        bdy = {}
        if package["versionInfo"] != None:
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

async def package_vulns(package: dict):

    bdy = {}
    if package["versionInfo"] != None:
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
    
    vuls = await find_vulnerabilities(bdy)
    
    return (vuls, bdy)

def get_vulnarability_readable_format(vuls: dict):
    
    if "vulns" not in vuls:
        return "No known vulnerabilities"
    else:
        vuls = vuls["vulns"]
        package_vulnerabilities = []
        for v in vuls:
            reqVals = {}
            if "id" in v:
                reqVals["id"] = v["id"]
            if "summary" in v:
                reqVals["summary"] = v["summary"]
            if "details" in v:
                reqVals["details"] = v["details"]
            if "affected" in v:
                reqVals["affected"] = v["affected"]
            if "severity" in v:
                reqVals["severity"] = v["severity"]
            if "aliases" in v:
                reqVals["aliases"] = v["aliases"]
            package_vulnerabilities.append(reqVals)
        
        return package_vulnerabilities

def create_context(pkg: dict, params: dict, vuls: dict):

    context = Context(
        package_name = pkg["name"],
        package_version = params["version"],
        package_ecosystem = "unknown" if "ecosystem" not in params["package"] else params["package"]["ecosystem"],
        package_vulnerabilities = get_vulnarability_readable_format(vuls=vuls)
    )

    return context

async def retrive_package_context(pkg: dict):

    (vuls, params) = await package_vulns(pkg)
    context = create_context(pkg=pkg, params=params, vuls=vuls)

    return context

async def retrive_osv_context(sbom: dict):
    
    pkgs_context = []

    for pkg in sbom["packages"]:

        (vuls, params) = await package_vulns(pkg)
        context = create_context(pkg=pkg, params=params, vuls=vuls)
        pkgs_context.append(context)

    return pkgs_context