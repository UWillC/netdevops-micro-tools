import json
from typing import Dict, Any, List
from models.profile_model import DeviceProfile


class ProfileService:
    """
    Handles reading, listing and saving device profiles.
    Future: custom user profiles per auth.
    """

    def __init__(self, profiles_dir: str = "profiles"):
        self.dir = profiles_dir

    def list_profiles(self) -> List[str]:
        """Return list of available profile files."""
        return []

    def load_profile(self, name: str) -> Dict[str, Any]:
        """Load a profile as dict."""
        return {}

    def save_profile(self, name: str, data: Dict[str, Any]) -> None:
        """Save a new or updated profile."""
        pass
