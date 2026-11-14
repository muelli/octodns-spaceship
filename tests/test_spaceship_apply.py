"""Offline test of SpaceshipProvider._apply against a fake Spaceship API.

Run:  PYTHONPATH=octodns-config .venv/bin/python -m pytest -q tests/test_spaceship_apply.py
(or run the file directly).

The fake behaves like the real API did in the failure this guards against:
- DELETE only removes an item that matches a live record exactly, and answers 200
  either way;
- PUT (create) refuses a CNAME whose host exists ("CNAME with host ... already exists").
"""
import copy
from types import SimpleNamespace

from octodns.provider.plan import Plan
from octodns.record import Record, Update
from octodns.zone import Zone

import spaceship_octodns as mod


class FakeApi:
    def __init__(self, live):
        self.live = copy.deepcopy(live)
        self.deletes = []
        self.puts = []

    def _resp(self, status=200, body=''):
        return SimpleNamespace(
            ok=status < 400, status_code=status, text=body, json=lambda: {},
            raise_for_status=lambda: None if status < 400 else (_ for _ in ()).throw(
                mod.requests.exceptions.HTTPError(response=SimpleNamespace(text=body))))

    def get(self, url, params=None, headers=None):
        items = self.live[params['skip']:params['skip'] + params['take']]
        return SimpleNamespace(
            raise_for_status=lambda: None,
            json=lambda: {'items': items, 'total': len(self.live)})

    def delete(self, url, json=None, headers=None):
        self.deletes.append(json)
        for item in json:
            if item in self.live:  # an exact match only; otherwise silently nothing
                self.live.remove(item)
        return self._resp(200)

    def put(self, url, json=None, headers=None):
        self.puts.append(json)
        for item in json['items']:
            if item['type'] == 'CNAME' and any(
                    r['type'] == 'CNAME' and r['name'] == item['name'] for r in self.live):
                return self._resp(400, '{"detail":"Request validation error.","data":[{"details":'
                                       '"CNAME with host %s already exists"}]}' % item['name'])
            self.live.append(item)
        return self._resp(200)


def run(live, existing_ttl, new_ttl, live_cname, new_value):
    api = FakeApi(live)
    zone = Zone('example.com.', [])
    old = Record.new(zone, 'k._domainkey', {'type': 'CNAME', 'ttl': existing_ttl, 'value': live_cname}, lenient=True)
    new = Record.new(zone, 'k._domainkey', {'type': 'CNAME', 'ttl': new_ttl, 'value': new_value}, lenient=True)
    provider = mod.SpaceshipProvider('t', 'key', 'secret')
    plan = Plan(zone, zone, [Update(old, new)], True)
    real = mod.requests
    mod.requests = SimpleNamespace(get=api.get, delete=api.delete, put=api.put,
                                   exceptions=real.exceptions)
    try:
        provider._apply(plan)
    finally:
        mod.requests = real
    return api


def test_update_of_a_cname_whose_live_ttl_is_out_of_range():
    live = [{'type': 'CNAME', 'name': 'k._domainkey', 'cname': 'k.dkim.example.net', 'ttl': 7200}]
    api = run(live, 7200, 3600, 'k.dkim.example.net.', 'k.dkim.example.net.')
    assert api.live == [{'type': 'CNAME', 'name': 'k._domainkey', 'cname': 'k.dkim.example.net', 'ttl': 3600}]
    # the delete carried the TTL Spaceship really has, not a clamped one
    assert api.deletes[0][0]['ttl'] == 7200


def test_a_leftover_live_cname_is_removed_before_the_create():
    # the live value differs in case, so a delete built from octoDNS' record would not match
    live = [{'type': 'CNAME', 'name': 'k._domainkey', 'cname': 'K.DKIM.example.net', 'ttl': 1800}]
    api = run(live, 1800, 3600, 'k.dkim.example.net.', 'k.dkim.example.net.')
    assert api.live == [{'type': 'CNAME', 'name': 'k._domainkey', 'cname': 'k.dkim.example.net', 'ttl': 3600}]


def test_an_identical_live_cname_is_left_alone():
    live = [{'type': 'CNAME', 'name': 'k._domainkey', 'cname': 'k.dkim.example.net', 'ttl': 3600}]
    api = run(live, 1800, 3600, 'k.dkim.example.net.', 'k.dkim.example.net.')
    assert api.puts == [] and api.live == live


if __name__ == '__main__':
    for name, fn in sorted(globals().items()):
        if name.startswith('test_'):
            fn()
            print('ok', name)
