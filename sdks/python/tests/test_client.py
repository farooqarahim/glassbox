"""Client round-trip tests against a real running glassbox-server."""

from __future__ import annotations

import pytest

from glassbox import Client, ClientError


def test_healthz(server):
    with Client(server["base_url"], server["secret"], server["stream_id"]) as c:
        assert c.healthz() is True


def test_list_streams(server):
    with Client(server["base_url"], server["secret"], server["stream_id"]) as c:
        assert c.list_streams() == ["acme/credit"]


def test_iter_records_returns_genesis(server):
    with Client(server["base_url"], server["secret"], server["stream_id"]) as c:
        rs = c.iter_records()
        assert len(rs) == 1
        assert rs[0]["record"]["sequence"] == 0


def test_inclusion_proof_for_genesis(server):
    with Client(server["base_url"], server["secret"], server["stream_id"]) as c:
        proof = c.inclusion_proof(0)
        assert len(proof["leaf_hex"]) == 64
        assert len(proof["root_hex"]) == 64
        assert proof["steps"] == []


def test_verify_returns_ok(server):
    with Client(server["base_url"], server["secret"], server["stream_id"]) as c:
        report = c.verify()
        assert report["ok"] is True
        assert report["records_walked"] == 1


def test_wrong_token_is_rejected(server):
    with Client(server["base_url"], "wrong-secret", server["stream_id"]) as c:
        with pytest.raises(ClientError) as excinfo:
            c.list_streams()
        assert excinfo.value.status in (401, 403)


def test_get_missing_sequence(server):
    with Client(server["base_url"], server["secret"], server["stream_id"]) as c:
        assert c.get(9999) is None
