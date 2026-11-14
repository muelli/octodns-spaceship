"""Offline test of SpaceshipProvider._apply against a fake Spaceship API.

Run:  PYTHONPATH=octodns-config .venv/bin/python tests/test_spaceship_apply.py
(or with pytest).

The fake behaves like the real API did in the failures this guards against:
- DELETE only removes an item that matches a live record exactly, and answers 200
  either way (Spaceship stores CNAME values with a trailing dot, and records can
  carry extra fields such as `group`);
- PUT (create) refuses a CNAME whose host exists ("CNAME with host ... already exists").
"""
import copy
from types import SimpleNamespace

from octodns.provider.plan import Plan
from octodns.record import Delete, Record, Update
from octodns.zone import Zone

import octodns_spaceship as mod


class FakeApi:
    def __init__(self, live, skip_deletes=0):
        self.live = copy.deepcopy(live)
        self.skip_deletes = skip_deletes  # the first N DELETE calls answer 200 and remove nothing
        self.deletes = []
        self.puts = []

    def _resp(self, status=200, body=''):
        def raise_for_status():
            if status >= 400:
                raise mod.requests.exceptions.HTTPError(response=SimpleNamespace(text=body))
        return SimpleNamespace(ok=status < 400, status_code=status, text=body,
                               json=lambda: {}, raise_for_status=raise_for_status)

    def get(self, url, params=None, headers=None):
        items = self.live[params['skip']:params['skip'] + params['take']]
        return SimpleNamespace(raise_for_status=lambda: None,
                               json=lambda: {'items': items, 'total': len(self.live)})

    def delete(self, url, json=None, headers=None):
        silent = len(self.deletes) < self.skip_deletes
        self.deletes.append(json)
        if not silent:
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


def apply(api, make_changes):
    zone = Zone('example.com.', [])
    provider = mod.SpaceshipProvider('t', 'key', 'secret')
    plan = Plan(zone, zone, make_changes(zone), True)
    real = mod.requests
    mod.requests = SimpleNamespace(get=api.get, delete=api.delete, put=api.put,
                                   exceptions=real.exceptions)
    try:
        provider._apply(plan)
    finally:
        mod.requests = real
    return api


def update_cname(api, existing_ttl, new_ttl, live_value, new_value):
    def changes(zone):
        old = Record.new(zone, 'k._domainkey', {'type': 'CNAME', 'ttl': existing_ttl, 'value': live_value}, lenient=True)
        new = Record.new(zone, 'k._domainkey', {'type': 'CNAME', 'ttl': new_ttl, 'value': new_value}, lenient=True)
        return [Update(old, new)]
    return apply(api, changes)


CNAME = {'type': 'CNAME', 'name': 'k._domainkey', 'cname': 'k.dkim.example.net.', 'ttl': 1800,
         'group': {'type': 'custom'}}
NEW_CNAME = {'type': 'CNAME', 'name': 'k._domainkey', 'cname': 'k.dkim.example.net', 'ttl': 3600}


def test_update_of_a_cname_stored_with_a_trailing_dot_and_extra_fields():
    api = update_cname(FakeApi([CNAME]), 1800, 3600, 'k.dkim.example.net.', 'k.dkim.example.net.')
    assert api.live == [NEW_CNAME]
    # the delete sent the record exactly as Spaceship returned it
    assert api.deletes[0] == [CNAME]


def test_update_of_a_cname_whose_live_ttl_is_out_of_range():
    live = [{'type': 'CNAME', 'name': 'k._domainkey', 'cname': 'k.dkim.example.net', 'ttl': 7200}]
    api = update_cname(FakeApi(live), 7200, 3600, 'k.dkim.example.net.', 'k.dkim.example.net.')
    assert api.live == [NEW_CNAME]
    assert api.deletes[0][0]['ttl'] == 7200


def test_a_delete_that_still_matches_nothing_is_caught_before_the_create():
    # safety net: whatever the reason the delete did nothing, the create must not collide
    api = update_cname(FakeApi([CNAME], skip_deletes=1), 1800, 3600,
                       'k.dkim.example.net.', 'k.dkim.example.net.')
    assert api.live == [NEW_CNAME]
    assert len(api.deletes) == 2  # the first did nothing, the re-check removed the leftover


def test_an_identical_live_cname_is_left_alone():
    live = [{'type': 'CNAME', 'name': 'k._domainkey', 'cname': 'k.dkim.example.net', 'ttl': 3600}]
    api = update_cname(FakeApi(live, skip_deletes=1), 1800, 3600,
                       'k.dkim.example.net.', 'k.dkim.example.net.')
    assert api.puts == [] and api.live == live


def test_delete_of_a_cname_stored_with_a_trailing_dot():
    live = [{'type': 'CNAME', 'name': '_autoconfig', 'cname': 'www.example.net.', 'ttl': 1800}]

    def changes(zone):
        return [Delete(Record.new(zone, '_autoconfig', {'type': 'CNAME', 'ttl': 1800, 'value': 'www.example.net.'}, lenient=True))]
    api = apply(FakeApi(live), changes)
    assert api.live == []


def test_update_removes_every_duplicate_live_value():
    mx = {'type': 'MX', 'name': '@', 'preference': 0, 'exchange': 'mail.example.net.', 'ttl': 1800}
    live = [dict(mx), dict(mx)]  # Spaceship held the same MX twice

    def changes(zone):
        old = Record.new(zone, '', {'type': 'MX', 'ttl': 1800, 'values': [
            {'preference': 0, 'exchange': 'mail.example.net.'}]}, lenient=True)
        new = Record.new(zone, '', {'type': 'MX', 'ttl': 300, 'value': {
            'preference': 0, 'exchange': 'mail.example.net.'}}, lenient=True)
        return [Update(old, new)]
    api = apply(FakeApi(live), changes)
    assert len(api.live) == 1 and api.live[0]['ttl'] == 300


if __name__ == '__main__':
    for name, fn in sorted(globals().items()):
        if name.startswith('test_'):
            fn()
            print('ok', name)
