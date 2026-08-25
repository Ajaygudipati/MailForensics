import re
from fastapi import HTTPException, UploadFile

MAX_UPLOAD_BYTES = 10 * 1024 * 1024

async def validate_eml_upload(file: UploadFile) -> bytes:
    name = file.filename or "sample.eml"
    if not name.lower().endswith(".eml"):
        raise HTTPException(415, "Only .eml email samples are accepted.")
    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Sample exceeds the 10 MB analysis limit.")
    if not content.strip():
        raise HTTPException(422, "The uploaded sample is empty.")
    return content

def clean_text(value: str, limit: int = 5000) -> str:
    return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value or "")[:limit]
