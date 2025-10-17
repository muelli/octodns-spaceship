"""
OctoDNS provider for Spaceship DNS API
https://spaceship.dev/api/docs
"""

import logging
import requests
from collections import defaultdict

from octodns.provider.base import BaseProvider
from octodns.record import Record


class SpaceshipProvider(BaseProvider):
    """
    Spaceship DNS provider for OctoDNS
    
    Usage in config.yaml:
    
    providers:
      spaceship:
        class: octodns_spaceship.SpaceshipProvider
        api_key: env/SPACESHIP_API_KEY
        api_secret: env/SPACESHIP_API_SECRET
        # Optional pagination settings
        page_size: 100
    """
    
    SUPPORTS_GEO = False
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV', 'CAA'))
    
    def __init__(self, id, api_key, api_secret, page_size=100, *args, **kwargs):
        self.log = logging.getLogger(f'SpaceshipProvider[{id}]')
        self.log.debug('__init__: id=%s, page_size=%d', id, page_size)
        super().__init__(id, *args, **kwargs)
        
        self.api_key = api_key
        self.api_secret = api_secret
        self.page_size = page_size
        self.base_url = "https://spaceship.dev/api/v1/dns/records"
    
    def _get_headers(self):
        """Generate request headers with API credentials"""
        return {
            "X-API-Key": self.api_key,
            "X-API-Secret": self.api_secret,
            "content-type": "application/json",
        }
    
    def list_zones(self):
        """List all domains/zones available in the Spaceship account"""
        all_domains = []
        skip = 0
        
        while True:
            url = "https://spaceship.dev/api/v1/domains"
            params = {
                "take": self.page_size,
                "skip": skip,
            }
            
            self.log.debug(f'list_zones: fetching domains skip={skip}')
            response = requests.get(url, params=params, headers=self._get_headers())
            response.raise_for_status()
            
            data = response.json()
            domains = data.get('items', [])
            
            if not domains:
                break
                
            all_domains.extend(domains)
            
            # Check if we've fetched all domains
            total = data.get('total', len(all_domains))
            if len(all_domains) >= total:
                break
                
            skip += self.page_size
        
        self.log.info(f'list_zones: fetched {len(all_domains)} domains')
        return [f"{domain['name']}." for domain in all_domains]
    
    def _fetch_records(self, domain):
        """Fetch all DNS records for a domain with pagination"""
        all_records = []
        skip = 0
        
        while True:
            url = f"{self.base_url}/{domain}"
            params = {
                "take": self.page_size,
                "skip": skip,
            }
            
            self.log.debug(f'_fetch_records: fetching records skip={skip}')
            response = requests.get(url, params=params, headers=self._get_headers())
            response.raise_for_status()
            
            data = response.json()
            records = data.get('items', [])
            
            if not records:
                break
                
            all_records.extend(records)
            
            # Check if we've fetched all records
            total = data.get('total', len(all_records))
            if len(all_records) >= total:
                break
                
            skip += self.page_size
        
        self.log.info(f'_fetch_records: fetched {len(all_records)} records for {domain}')
        return all_records
    
    def _normalize_fqdn_from_spaceship(self, value):
        """Add trailing dot to FQDN if not present (for reading from Spaceship)"""
        if value and not value.endswith('.'):
            return value + '.'
        return value
    
    def _normalize_fqdn_to_spaceship(self, value):
        """Remove trailing dot from FQDN (for writing to Spaceship)"""
        if value:
            return value.rstrip('.')
        return value
    
    def _clamp_ttl(self, ttl):
        """Clamp TTL to Spaceship's accepted range (60-3600)"""
        if ttl < 60:
            self.log.warning(f'TTL {ttl} is below minimum 60, clamping to 60')
            return 60
        elif ttl > 3600:
            self.log.warning(f'TTL {ttl} is above maximum 3600, clamping to 3600')
            return 3600
        return ttl
    
    def _parse_a_record(self, record):
        """Parse A record from Spaceship format to OctoDNS format"""
        return record['address']
    
    def _parse_aaaa_record(self, record):
        """Parse AAAA record from Spaceship format to OctoDNS format"""
        return record['address']
    
    def _parse_cname_record(self, record):
        """Parse CNAME record from Spaceship format to OctoDNS format"""
        cname_value = self._normalize_fqdn_from_spaceship(record['cname'])
        return {'type': 'CNAME', 'ttl': record.get('ttl', 3600), 'value': cname_value}
    
    def _parse_mx_record(self, record):
        """Parse MX record from Spaceship format to OctoDNS format"""
        exchange = self._normalize_fqdn_from_spaceship(record['exchange'])
        return {
            'preference': record.get('preference', 10),
            'exchange': exchange
        }
    
    def _parse_ns_record(self, record):
        """Parse NS record from Spaceship format to OctoDNS format"""
        nameserver = record.get('content', record.get('nameserver', ''))
        return self._normalize_fqdn_from_spaceship(nameserver)
    
    def _parse_txt_record(self, record):
        """Parse TXT record from Spaceship format to OctoDNS format"""
        return record['value']
    
    def _parse_srv_record(self, record):
        """Parse SRV record from Spaceship format to OctoDNS format"""
        target = record.get('target', record.get('content', ''))
        return {
            'priority': record.get('priority', 0),
            'weight': record.get('weight', 0),
            'port': record.get('port', 0),
            'target': self._normalize_fqdn_from_spaceship(target)
        }
    
    def _parse_caa_record(self, record):
        """Parse CAA record from Spaceship format to OctoDNS format"""
        return {
            'flags': record.get('flat', record.get('flags', 0)),
            'tag': record.get('tag', 'issue'),
            'value': record['value']
        }
    
    def _data_for_multiple(self, _type, records):
        """Convert multiple Spaceship records to OctoDNS data format"""
        # Map record types to their parser functions
        parsers = {
            'A': self._parse_a_record,
            'AAAA': self._parse_aaaa_record,
            'CNAME': self._parse_cname_record,
            'MX': self._parse_mx_record,
            'NS': self._parse_ns_record,
            'TXT': self._parse_txt_record,
            'SRV': self._parse_srv_record,
            'CAA': self._parse_caa_record,
        }
        
        parser = parsers.get(_type)
        if not parser:
            raise ValueError(f'Unsupported record type: {_type}')
        
        # CNAME is special - it returns a complete record dict
        if _type == 'CNAME':
            return parser(records[0])
        
        # For all other types, collect values
        values = [parser(record) for record in records]
        
        # Use the TTL from the first record
        ttl = records[0].get('ttl', 3600)
        
        return {
            'type': _type,
            'ttl': ttl,
            'values': values
        }
    
    def populate(self, zone, target=False, lenient=False):
        """Populate zone with records from Spaceship DNS"""
        self.log.debug('populate: zone=%s, target=%s, lenient=%s', 
                      zone.name, target, lenient)
        
        before = len(zone.records)
        
        # Remove trailing dot from zone name for API call
        domain = zone.name.rstrip('.')
        
        # Fetch all records
        records = self._fetch_records(domain)
        
        # Group records by name and type
        grouped = defaultdict(list)
        for record in records:
            name = record.get('name', '@')
            # Normalize empty name to @
            if name == '' or name == domain:
                name = '@'
            rtype = record['type']
            grouped[(name, rtype)].append(record)
        
        # Convert to OctoDNS records
        for (name, rtype), record_list in grouped.items():
            if rtype not in self.SUPPORTS:
                self.log.warning(f'populate: skipping unsupported record type {rtype}')
                continue
            
            data = self._data_for_multiple(rtype, record_list)
            
            # Convert @ to empty string for OctoDNS
            octodns_name = '' if name == '@' else name
            
            record = Record.new(zone, octodns_name, data, source=self, lenient=lenient)
            zone.add_record(record, lenient=lenient)
        
        self.log.info('populate: found %d records', len(zone.records) - before)
        return True
    
    def _format_a_record(self, name, value, ttl):
        """Format A record for Spaceship API"""
        return {
            'type': 'A',
            'name': name,
            'address': value,
            'ttl': ttl,
        }
    
    def _format_aaaa_record(self, name, value, ttl):
        """Format AAAA record for Spaceship API"""
        return {
            'type': 'AAAA',
            'name': name,
            'address': value,
            'ttl': ttl,
        }
    
    def _format_cname_record(self, name, value, ttl):
        """Format CNAME record for Spaceship API"""
        cname_value = self._normalize_fqdn_to_spaceship(value)
        self.log.debug(f'CNAME: {value!r} -> {cname_value!r}')
        return {
            'type': 'CNAME',
            'name': name,
            'cname': cname_value,
            'ttl': ttl,
        }
    
    def _format_mx_record(self, name, value, ttl):
        """Format MX record for Spaceship API"""
        exchange = self._normalize_fqdn_to_spaceship(value.exchange)
        self.log.debug(f'MX: {value.exchange!r} -> {exchange!r}')
        return {
            'type': 'MX',
            'name': name,
            'preference': value.preference,
            'exchange': exchange,
            'ttl': ttl,
        }
    
    def _format_txt_record(self, name, value, ttl):
        """Format TXT record for Spaceship API"""
        return {
            'type': 'TXT',
            'name': name,
            'value': value,
            'ttl': ttl,
        }
    
    def _format_ns_record(self, name, value, ttl):
        """Format NS record for Spaceship API"""
        nameserver = self._normalize_fqdn_to_spaceship(value)
        self.log.debug(f'NS: {value!r} -> {nameserver!r}')
        return {
            'type': 'NS',
            'name': name,
            'nameserver': nameserver,
            'ttl': ttl,
        }
    
    def _format_srv_record(self, name, value, ttl):
        """Format SRV record for Spaceship API"""
        target = self._normalize_fqdn_to_spaceship(value.target)
        self.log.debug(f'SRV: {value.target!r} -> {target!r}')
        return {
            'type': 'SRV',
            'name': name,
            'priority': value.priority,
            'weight': value.weight,
            'port': value.port,
            'target': target,
            'ttl': ttl,
        }
    
    def _format_caa_record(self, name, value, ttl):
        """Format CAA record for Spaceship API"""
        return {
            'type': 'CAA',
            'name': name,
            'flat': value.flags,
            'tag': value.tag,
            'value': value.value,
            'ttl': ttl,
        }
    
    def _record_to_spaceship_format(self, record):
        """Convert OctoDNS record to Spaceship API format"""
        items = []
        name = record.name if record.name else '@'
        ttl = self._clamp_ttl(record.ttl)
        
        # Map record types to their formatter functions
        formatters = {
            'A': self._format_a_record,
            'AAAA': self._format_aaaa_record,
            'CNAME': self._format_cname_record,
            'MX': self._format_mx_record,
            'TXT': self._format_txt_record,
            'NS': self._format_ns_record,
            'SRV': self._format_srv_record,
            'CAA': self._format_caa_record,
        }
        
        formatter = formatters.get(record._type)
        if not formatter:
            raise ValueError(f'Unsupported record type: {record._type}')
        
        # CNAME only has a single value
        if record._type == 'CNAME':
            items.append(formatter(name, record.value, ttl))
        else:
            # All other types can have multiple values
            for value in record.values:
                items.append(formatter(name, value, ttl))
        
        self.log.debug(f'_record_to_spaceship_format: {name}/{record._type} -> {items}')
        return items
    
    def _apply(self, plan):
        """Apply changes to Spaceship DNS"""
        desired = plan.desired
        changes = plan.changes
        
        domain = desired.name.rstrip('.')
        
        self.log.info('_apply: zone=%s, len(changes)=%d', domain, len(changes))
        
        # Group changes by type (create, update, delete)
        to_create = []
        to_delete = []
        
        for change in changes:
            # Check what type of change this is
            has_existing = hasattr(change, 'existing') and change.existing is not None
            has_new = hasattr(change, 'new') and change.new is not None
            
            if has_existing and has_new:
                # Update: delete old, create new
                self.log.debug('_apply: update %s', change)
                existing_items = self._record_to_spaceship_format(change.existing)
                new_items = self._record_to_spaceship_format(change.new)
                to_delete.extend(existing_items)
                to_create.extend(new_items)
            elif has_existing:
                # Delete
                self.log.debug('_apply: delete %s', change)
                items = self._record_to_spaceship_format(change.existing)
                to_delete.extend(items)
            elif has_new:
                # Create
                self.log.debug('_apply: create %s', change)
                items = self._record_to_spaceship_format(change.new)
                to_create.extend(items)
            else:
                self.log.warning('_apply: skipping change with no existing or new record: %s', change)
        
        # Apply deletions
        if to_delete:
            self._delete_records(domain, to_delete)
        
        # Apply creations
        if to_create:
            self._create_records(domain, to_create)
        
        self.log.info('_apply: zone=%s, complete', domain)
    
    def _delete_records(self, domain, items):
        """Delete records from Spaceship DNS"""
        url = f"{self.base_url}/{domain}"
        
        self.log.info(f'_delete_records: deleting {len(items)} records from {domain}')
        self.log.debug(f'_delete_records: items={items}')
        
        # Try to delete records one by one to identify problematic ones
        if len(items) > 1:
            self.log.info(f'_delete_records: attempting individual deletes to isolate errors')
            failed_items = []
            for item in items:
                try:
                    response = requests.delete(url, json=[item], headers=self._get_headers())
                    response.raise_for_status()
                    self.log.debug(f'_delete_records: successfully deleted {item}')
                except requests.exceptions.HTTPError as e:
                    self.log.error(f'_delete_records: failed to delete item: {item}')
                    self.log.error(f'_delete_records: error response: {e.response.text}')
                    failed_items.append(item)
            
            if failed_items:
                self.log.error(f'_delete_records: {len(failed_items)} items failed to delete')
                raise Exception(f'Failed to delete {len(failed_items)} records: {failed_items}')
        else:
            response = requests.delete(url, json=items, headers=self._get_headers())
            
            if not response.ok:
                self.log.error(f'_delete_records: failed with status {response.status_code}')
                self.log.error(f'_delete_records: response body={response.text}')
                self.log.error(f'_delete_records: items sent={items}')
            
            response.raise_for_status()
            self.log.debug(f'_delete_records: response={response.text}')
    
    def _create_records(self, domain, items):
        """Create records in Spaceship DNS"""
        url = f"{self.base_url}/{domain}"
        
        payload = {
            "force": False,
            "items": items,
        }
        
        self.log.info(f'_create_records: creating {len(items)} records for {domain}')
        self.log.debug(f'_create_records: payload={payload}')
        
        response = requests.put(url, json=payload, headers=self._get_headers())
        
        if not response.ok:
            self.log.error(f'_create_records: failed with status {response.status_code}')
            self.log.error(f'_create_records: response body={response.text}')
            self.log.error(f'_create_records: payload sent={payload}')
            
            # Try to identify which specific item is causing the issue
            if len(items) > 1:
                self.log.info(f'_create_records: attempting individual creates to isolate errors')
                for item in items:
                    try:
                        test_payload = {"force": False, "items": [item]}
                        test_response = requests.put(url, json=test_payload, headers=self._get_headers())
                        test_response.raise_for_status()
                        self.log.debug(f'_create_records: item OK: {item}')
                    except requests.exceptions.HTTPError as e:
                        self.log.error(f'_create_records: PROBLEMATIC ITEM: {item}')
                        self.log.error(f'_create_records: error: {e.response.text}')
        
        response.raise_for_status()
        self.log.debug(f'_create_records: response={response.text}')
