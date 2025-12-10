from pydantic import BaseModel
from typing import List


class MetaInfo(BaseModel):
    version: str
    build_time: str
    feature_flags: List[str] = []
