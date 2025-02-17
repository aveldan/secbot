from fastapi import APIRouter

router = APIRouter()

@router.get("/privacy-policy")
async def getPrivacyPolicy():
    return """
        Effective Date: 02/12/2025
    This app values your privacy. 
    We do not collect, store, or share any personal data. 
    No information is linked to your account or identity. 
    All interactions within the app remain private and are not tracked or recorded.
    """