from pydantic import BaseModel, Field
from typing import Optional, List

# Collections:
# - userprofile
# - challenge
# - submission

class UserProfile(BaseModel):
    username: str = Field(..., min_length=2, max_length=30, description="Unique handle")
    solved: List[str] = Field(default_factory=list, description="Challenge slugs solved")
    unlocked_sections: List[str] = Field(default_factory=list, description="Unlocked portfolio sections")

class Challenge(BaseModel):
    slug: str = Field(..., min_length=3, max_length=50, description="Unique identifier, e.g., enum-01")
    title: str = Field(..., description="Display title")
    concept: str = Field(..., description="Category like Enumeration/OSINT/SQLi")
    section: str = Field(..., description="Portfolio section unlocked: about/skills/projects/certifications")
    difficulty: str = Field(default="easy", description="easy | medium | hard")
    flag_hash: str = Field(..., description="SHA256 of the flag (ctf{...})")
    is_active: bool = Field(default=True)

class Submission(BaseModel):
    username: str = Field(...)
    challenge_slug: str = Field(...)
    correct: bool = Field(default=False)
    provided_hash: Optional[str] = None
