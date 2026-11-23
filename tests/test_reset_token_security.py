"""Behavioural tests for the hardened reset-token scheme.

The contract tests only assert that each entry point returns something; these
encode the actual security properties: unpredictable tokens, 15-minute expiry,
single use, device binding and owner notification.
"""

import threading

import pytest

import security.reset_token_entropy as m


@pytest.fixture(autouse=True)
def isolate_module_state():
    """Reset global limiter/outbox/audit so tests cannot leak into each other."""
    m._RATE.clear()
    m._OUTBOX.clear()
    m._AUDIT.clear()
    yield
    m._RATE.clear()
    m._OUTBOX.clear()
    m._AUDIT.clear()


@pytest.fixture()
def store():
    return m.token_store({"tokens": {}})


def _issue(store, now=1_000_000.0, user="u1", email="owner@example.com",
           device="device-A"):
    return m.issue_token(user, email, device, store, now=now)


def test_tokens_are_random_not_timestamp_or_user_id():
    a = m.csprng()
    b = m.csprng()
    assert a != b
    assert len(a) >= 43                       # 256 bits, url-safe
    assert not any(part in a for part in ("1000000", "u1"))
    assert m.entropy_check(a)["ok"] is True


def test_guessable_timestamp_user_token_is_rejected_by_entropy_check():
    # f"{timestamp}{user_id}" style token from the old scheme
    assert m.entropy_check("1700000000alice")["ok"] is False


def test_issue_returns_raw_token_but_store_holds_only_digest(store):
    issued = _issue(store)
    assert issued["ok"] is True
    assert issued["ttl_seconds"] == 900
    tokens = store["tokens"]
    assert len(tokens) == 1
    assert issued["token"] not in tokens          # only a digest is stored
    assert issued["token"] not in str(tokens)


def test_expiry_is_fifteen_minutes():
    window = m.expiry(now=500.0)
    assert window["expires_at"] - window["created_at"] == 900


def test_token_expires_after_fifteen_minutes(store):
    issued = _issue(store, now=1000.0)
    late = m.reset_password(issued["token"], "CorrectHorse9", "device-A",
                            store, now=1000.0 + m.TTL_SECONDS)
    assert late["ok"] is False
    assert late["message"] == m.GENERIC_FAILURE


def test_token_is_valid_just_before_expiry(store):
    issued = _issue(store, now=1000.0)
    ok = m.reset_password(issued["token"], "CorrectHorse9", "device-A",
                          store, now=1000.0 + m.TTL_SECONDS - 1)
    assert ok["ok"] is True


def test_token_cannot_be_replayed(store):
    issued = _issue(store)
    first = m.reset_password(issued["token"], "CorrectHorse9", "device-A",
                             store, now=1010.0)
    second = m.reset_password(issued["token"], "OtherPass77", "device-A",
                              store, now=1020.0)
    assert first["ok"] is True
    assert second["ok"] is False
    assert second["message"] == m.GENERIC_FAILURE


def test_token_is_bound_to_the_requesting_device(store):
    issued = _issue(store, device="device-A")
    stolen = m.reset_password(issued["token"], "CorrectHorse9", "device-B",
                              store, now=1010.0)
    assert stolen["ok"] is False
    # and the attempt did not burn the token for the real device
    real = m.reset_password(issued["token"], "CorrectHorse9", "device-A",
                            store, now=1011.0)
    assert real["ok"] is True


def test_successful_reset_notifies_original_email(store):
    issued = _issue(store, email="owner@example.com")
    before = len(m._OUTBOX)
    result = m.reset_password(issued["token"], "CorrectHorse9", "device-A",
                              store, now=1010.0)
    assert result["ok"] is True
    assert len(m._OUTBOX) == before + 1
    note = m._OUTBOX[-1]
    assert note["to"] == "owner@example.com"
    assert note["event"] == "password_reset"
    assert issued["token"] not in str(note)


def test_successful_reset_revokes_other_outstanding_tokens(store):
    first = m.issue_token("u1", "o@example.com", "device-A", store, now=1000.0)
    second = m.issue_token("u1", "o@example.com", "device-A", store, now=1001.0)
    assert m.reset_password(first["token"], "CorrectHorse9", "device-A",
                            store, now=1010.0)["ok"] is True
    assert second["token"] not in str(store["tokens"])
    replay = m.reset_password(second["token"], "CorrectHorse9", "device-A",
                              store, now=1011.0)
    assert replay["ok"] is False


def test_unknown_token_fails_with_generic_message(store):
    out = m.reset_password("A" * 43, "CorrectHorse9", "device-A", store,
                           now=1010.0)
    assert out["ok"] is False
    assert out["message"] == m.GENERIC_FAILURE


def test_expired_used_and_unknown_are_indistinguishable(store):
    msgs = {
        m.error_map("expired"),
        m.error_map("used"),
        m.error_map("unknown"),
        m.error_map("device_mismatch"),
    }
    assert len(msgs) == 1


def test_weak_password_is_refused(store):
    issued = _issue(store)
    out = m.reset_password(issued["token"], "short", "device-A", store,
                           now=1010.0)
    assert out["ok"] is False
    # a rejected password must not consume the token
    assert m.reset_password(issued["token"], "CorrectHorse9", "device-A",
                            store, now=1011.0)["ok"] is True


def test_validation_rejects_malformed_tokens():
    assert m.validation("short")["ok"] is False
    assert m.validation("A" * 43 + "<script>")["ok"] is False
    assert m.validation("A" * 43, "device-A")["ok"] is True


def test_compare_is_constant_time_and_failure_safe():
    assert m.compare("abc", "abc") is True
    assert m.compare("abc", "abd") is False
    assert m.compare(None, "abc") is False


def test_rate_limit_blocks_after_max_attempts():
    results = [m.rate_limit("ip-1", now=100.0 + i) for i in range(6)]
    assert [r["allowed"] for r in results] == [True] * 5 + [False]
    assert results[-1]["retry_after"] > 0


def test_repeated_redemption_attempts_are_rate_limited(store):
    issued = _issue(store, device="device-A")
    outcomes = [
        m.reset_password(issued["token"], "WrongPass99", "device-B", store,
                         now=1000.0 + i)["error"]
        for i in range(m.MAX_ATTEMPTS + 1)
    ]
    assert outcomes[-1] == "rate_limited"


def test_concurrent_redemptions_consume_the_token_once(store):
    issued = _issue(store, now=1000.0)
    results = []
    barrier = threading.Barrier(6)

    def attempt():
        barrier.wait()
        results.append(
            m.reset_password(issued["token"], "CorrectHorse9", "device-A",
                             store, now=1010.0)["ok"]
        )

    threads = [threading.Thread(target=attempt) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results.count(True) == 1


def test_audit_redacts_secrets():
    event = m.audit("reset.rejected", token="SUPERSECRET", user_id="u1")
    assert event["fields"]["token"] == "[redacted]"
    assert event["fields"]["user_id"] == "u1"
    assert "SUPERSECRET" not in str(m._AUDIT)


def test_successful_reset_leaves_no_token_behind(store):
    issued = _issue(store, now=1000.0)
    m.reset_password(issued["token"], "CorrectHorse9", "device-A", store,
                     now=1010.0)
    assert store["tokens"] == {}


def test_cleanup_drops_expired_tokens(store):
    _issue(store, now=1000.0)
    assert len(store["tokens"]) == 1
    assert m.cleanup(store, now=1000.0 + m.TTL_SECONDS) == 1
    assert store["tokens"] == {}


def test_cleanup_drops_consumed_tokens_on_a_custom_store():
    custom = {"tokens": {}}
    issued = _issue(custom, now=1000.0)
    # bind/consume directly so the token is not revoked by the full flow
    m.single_use(issued["token"], custom, now=1010.0)
    assert m.cleanup(custom, now=1011.0) == 1
    assert custom["tokens"] == {}


def test_fallback_fails_closed_without_weak_generation():
    out = m.fallback("csprng unavailable")
    assert out["ok"] is False
    assert out["action"] == "fail_closed"
    assert out["generated_token"] is False
    assert "token" not in out
