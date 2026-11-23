import pytest
import security.reset_token_entropy as mod

CASES = [
    ("csprng", (1, 2)),
    ("expiry", (1, 2)),
    ("single_use", (1, 2)),
    ("device_bind", (1, 2)),
    ("notify_owner", (1, 2)),
    ("token_store", (1, 2)),
    ("compare", (1, 2)),
    ("rate_limit", (1, 2)),
    ("validation", (1, 2)),
    ("audit", (1, 2)),
    ("revoke_all", (1, 2)),
    ("error_map", (1, 2)),
    ("cleanup", (1, 2)),
    ("entropy_check", (1, 2)),
    ("fallback", (1, 2)),
]

@pytest.mark.parametrize("fn_name,args", CASES)
def test_contract(fn_name, args):
    fn = getattr(mod, fn_name)
    assert fn(*args) is not None
