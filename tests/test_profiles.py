from services.profile_service import ProfileService


def test_profile_service_list():
    svc = ProfileService()
    profiles = svc.list_profiles()
    assert isinstance(profiles, list)
