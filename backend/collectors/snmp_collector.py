"""
SNMP Collector ??polls all registered devices via pysnmp.
Supports SNMPv2c and SNMPv3.
"""
import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from config import settings
from pysnmp.hlapi.asyncio import (
    CommunityData, ContextData, ObjectIdentity, ObjectType,
    SnmpEngine, UdpTransportTarget, UsmUserData,
    getCmd, bulkCmd,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol,
    usmDESPrivProtocol, usmAesCfb128Protocol,
    usmNoAuthProtocol, usmNoPrivProtocol
)

logger = logging.getLogger('netguard.snmp')


class SNMPUnavailableError(RuntimeError):
    """Raised when a device does not answer the initial SNMP probe."""

# Standard OIDs
OID = {
    # System
    'sysDescr':   '1.3.6.1.2.1.1.1.0',
    'sysUpTime':  '1.3.6.1.2.1.1.3.0',
    'sysName':    '1.3.6.1.2.1.1.5.0',

    # Host Resources (servers)
    'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2',  # table
    'hrStorageDescr':  '1.3.6.1.2.1.25.2.3.1.3',
    'hrStorageSize':   '1.3.6.1.2.1.25.2.3.1.5',
    'hrStorageUsed':   '1.3.6.1.2.1.25.2.3.1.6',
    'hrStorageAllocationUnits': '1.3.6.1.2.1.25.2.3.1.4',
    'hrSWRunName':     '1.3.6.1.2.1.25.4.2.1.2',
    'hrSWRunPerfCPU':  '1.3.6.1.2.1.25.5.1.1.1',
    'hrSWRunPerfMem':  '1.3.6.1.2.1.25.5.1.1.2',

    # Memory (UCD-SNMP)
    'memTotalReal':  '1.3.6.1.4.1.2021.4.5.0',
    'memAvailReal':  '1.3.6.1.4.1.2021.4.6.0',
    'memTotalSwap':  '1.3.6.1.4.1.2021.4.3.0',
    'memAvailSwap':  '1.3.6.1.4.1.2021.4.4.0',
    'memBuffer':     '1.3.6.1.4.1.2021.4.14.0',
    'memCached':     '1.3.6.1.4.1.2021.4.15.0',

    # Interface (switches & servers)
    'ifDescr':       '1.3.6.1.2.1.2.2.1.2',
    'ifName':        '1.3.6.1.2.1.31.1.1.1.1',
    'ifAlias':       '1.3.6.1.2.1.31.1.1.1.18',
    'ifOperStatus':  '1.3.6.1.2.1.2.2.1.8',
    'ifSpeed':       '1.3.6.1.2.1.2.2.1.5',
    'ifInOctets':    '1.3.6.1.2.1.2.2.1.10',
    'ifOutOctets':   '1.3.6.1.2.1.2.2.1.16',
    'ifInErrors':    '1.3.6.1.2.1.2.2.1.14',
    'ifOutErrors':   '1.3.6.1.2.1.2.2.1.20',

    # UPS (RFC 1628)
    'upsEstimatedChargeRemaining': '1.3.6.1.2.1.33.1.2.4.0',
    'upsOutputLoad':               '1.3.6.1.2.1.33.1.4.4.1.5.1',
    'upsInputVoltage':             '1.3.6.1.2.1.33.1.3.3.1.3.1',
    'upsOutputVoltage':            '1.3.6.1.2.1.33.1.4.4.1.2.1',
    'upsBatteryTemperature':       '1.3.6.1.2.1.33.1.2.7.0',
    'upsEstimatedMinutesRemaining':'1.3.6.1.2.1.33.1.2.3.0',

    # Temperature/Humidity (generic sensor ??adjust per vendor)
    'temperature':  '1.3.6.1.4.1.9.9.13.1.3.1.3.1',   # Cisco example
    'humidity':     '1.3.6.1.4.1.9.9.13.1.3.1.4.1',

    # ENTITY-SENSOR-MIB generic sensors
    'entPhySensorType':       '1.3.6.1.2.1.99.1.1.1.1',
    'entPhySensorScale':      '1.3.6.1.2.1.99.1.1.1.2',
    'entPhySensorPrecision':  '1.3.6.1.2.1.99.1.1.1.3',
    'entPhySensorValue':      '1.3.6.1.2.1.99.1.1.1.4',
    'entPhySensorOperStatus': '1.3.6.1.2.1.99.1.1.1.5',

}

FLS_DDC400R_ENV_OIDS = {
    'humidity': '1.3.6.1.4.1.22210.2.1.53.0',
    'humidity_alt': '1.3.6.1.4.1.22210.2.1.58.0',
    'temperature': '1.3.6.1.4.1.22210.2.1.54.0',
    'model': '1.3.6.1.4.1.22210.2.1.300.0',
    'temperature_scale': 0.001,
    'humidity_scale': 1.0,
}

ENV_DEVICE_TYPES = ('env', 'rpi', 'environment', 'sensor')


def _make_auth(device: dict):
    if device.get('snmp_version') == 'v3':
        user = device.get('snmp_v3_user') or 'netguard'
        auth_key = device.get('snmp_v3_auth') or ''
        priv_key = device.get('snmp_v3_priv') or ''
        security_level = (device.get('snmp_v3_security_level') or '').lower()
        auth_name = (device.get('snmp_v3_auth_protocol') or 'sha').lower()
        priv_name = (device.get('snmp_v3_priv_protocol') or 'aes').lower()

        if not security_level:
            if priv_key:
                security_level = 'authpriv'
            elif auth_key:
                security_level = 'authnopriv'
            else:
                security_level = 'noauthnopriv'

        auth_protocols = {
            'md5': usmHMACMD5AuthProtocol,
            'sha': usmHMACSHAAuthProtocol,
            'sha1': usmHMACSHAAuthProtocol,
        }
        priv_protocols = {
            'des': usmDESPrivProtocol,
            'aes': usmAesCfb128Protocol,
            'aes128': usmAesCfb128Protocol,
        }

        auth_protocol = auth_protocols.get(auth_name, usmHMACSHAAuthProtocol)
        priv_protocol = priv_protocols.get(priv_name, usmAesCfb128Protocol)
        if security_level == 'noauthnopriv':
            auth_key = ''
            priv_key = ''
            auth_protocol = usmNoAuthProtocol
            priv_protocol = usmNoPrivProtocol
        elif security_level == 'authnopriv':
            priv_key = ''
            priv_protocol = usmNoPrivProtocol

        return UsmUserData(
            userName=user,
            authKey=auth_key,
            privKey=priv_key,
            authProtocol=auth_protocol,
            privProtocol=priv_protocol,
        )
    return CommunityData(device.get('community', 'public'), mpModel=1)



def safe_int(val, default=0):
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def safe_float(val, default=0.0):
    try:
        return float(val)
    except (ValueError, TypeError):
        return default

def is_snmp_null(val) -> bool:
    if val is None:
        return True
    text = str(val).strip().lower()
    return (
        text == ''
        or text == 'null'
        or text.startswith('no such')
        or text.startswith('no more')
    )

async def _get(engine, auth, transport, *oids) -> Dict[str, Any]:
    result = {}
    error_indication, error_status, _, var_binds = await getCmd(
        engine, auth, transport, ContextData(),
        *[ObjectType(ObjectIdentity(oid)) for oid in oids]
    )
    if error_indication or error_status:
        return result
    for var_bind in var_binds:
        oid_str, val = var_bind
        result[str(oid_str)] = val.prettyPrint()
    return result


async def _bulk(engine, auth, transport, oid, max_rows=64) -> List[tuple]:
    rows = []
    error_indication, error_status, _, var_binds_table = await bulkCmd(
        engine, auth, transport, ContextData(),
        0, max_rows,
        ObjectType(ObjectIdentity(oid))
    )
    if error_indication or error_status:
        return rows
    for var_binds in var_binds_table:
        for oid_str, val in var_binds:
            oid_str_s = str(oid_str)
            if not oid_str_s.startswith(oid):
                continue
            rows.append((oid_str_s, val.prettyPrint()))
    return rows


class SNMPCollector:
    def __init__(self):
        self.engine = SnmpEngine()
        self._devices: List[dict] = []

    def set_devices(self, devices: List[dict]):
        self._devices = devices

    async def collect_all(self) -> List[dict]:
        tasks = [self._collect_device(d) for d in self._devices]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out = []
        for d, r in zip(self._devices, results):
            if isinstance(r, Exception):
                logger.warning(f"Failed to poll {d['name']} ({d['ip_address']}): {r}")
                out.append({
                    'device': d['name'], 'ip': d['ip_address'],
                    'type': d['type'], 'status': 'offline',
                    'timestamp': datetime.now().isoformat(), 'metrics': {}
                })
            else:
                out.append(r)
        return out

    async def _collect_device(self, device: dict) -> dict:
        ip = str(device['ip_address'])
        dev_type = device.get('type', 'server')
        auth = _make_auth(device)
        transport = UdpTransportTarget(
            (ip, 161),
            timeout=settings.SNMP_TIMEOUT,
            retries=settings.SNMP_RETRIES,
        )

        probe = await _get(self.engine, auth, transport, OID['sysDescr'])
        sys_descr = probe.get(OID['sysDescr'])
        if not sys_descr:
            env_probe = await self._probe_env_device(auth, transport) if dev_type in ENV_DEVICE_TYPES else {}
            if not env_probe:
                raise SNMPUnavailableError(f"No SNMP response from {ip}")
            sys_descr = env_probe.get(FLS_DDC400R_ENV_OIDS['model']) or 'SNMP environment device'
        system_data = await _get(self.engine, auth, transport, OID['sysName'], OID['sysUpTime'])

        metrics = {}
        if dev_type == 'server':
            metrics = await self._collect_server(auth, transport)
        elif dev_type == 'switch':
            metrics = await self._collect_switch(auth, transport)
        elif dev_type == 'ups':
            metrics = await self._collect_ups(auth, transport)
        elif dev_type in ENV_DEVICE_TYPES:
            metrics = await self._collect_env(auth, transport)

        return {
            'device': device['name'],
            'ip': ip,
            'type': dev_type,
            'status': 'online',
            'timestamp': datetime.now().isoformat(),
            'system': {
                'sys_descr': sys_descr,
                'sys_name': system_data.get(OID['sysName']),
                'sys_uptime': system_data.get(OID['sysUpTime']),
            },
            'metrics': metrics
        }

    async def _probe_env_device(self, auth, transport) -> Dict[str, Any]:
        probe_oids = [
            FLS_DDC400R_ENV_OIDS['temperature'],
            FLS_DDC400R_ENV_OIDS['humidity'],
            FLS_DDC400R_ENV_OIDS['model'],
        ]
        for oid in (settings.ENV_TEMP_OID, settings.ENV_HUMIDITY_OID):
            if oid and oid not in probe_oids:
                probe_oids.append(oid)
        data = await _get(self.engine, auth, transport, *probe_oids)
        return {
            oid: value
            for oid, value in data.items()
            if not is_snmp_null(value)
        }

    async def _collect_server(self, auth, transport) -> dict:
        # CPU
        cpu_rows = await _bulk(self.engine, auth, transport, OID['hrProcessorLoad'])
        cpu_vals = [min(100.0, safe_float(v)) for _, v in cpu_rows if v.isdigit()]
        cpu_avg = sum(cpu_vals) / len(cpu_vals) if cpu_vals else 0.0

        # Memory
        sys_data = await _get(self.engine, auth, transport,
                               OID['memTotalReal'], OID['memAvailReal'],
                               OID['memBuffer'], OID['memCached'])
        total_mem = safe_int(sys_data.get(OID['memTotalReal'], 0))
        free_mem = safe_int(sys_data.get(OID['memAvailReal'], 0))
        buffer_mem = safe_int(sys_data.get(OID['memBuffer'], 0))
        cached_mem = safe_int(sys_data.get(OID['memCached'], 0))
        available_mem = min(total_mem, free_mem + buffer_mem + cached_mem)
        mem_pct = ((total_mem - available_mem) / total_mem * 100) if total_mem > 0 else 0.0

        # Disk (hrStorage)
        disk_info: Dict[str, dict] = {}
        for oid_suffix, oid_base in [
            ('descr', OID['hrStorageDescr']),
            ('size', OID['hrStorageSize']),
            ('used', OID['hrStorageUsed']),
            ('unit', OID['hrStorageAllocationUnits']),
        ]:
            rows = await _bulk(self.engine, auth, transport, oid_base)
            for oid_str, val in rows:
                idx = oid_str.split('.')[-1]
                disk_info.setdefault(idx, {})[oid_suffix] = val

        if total_mem <= 0:
            for d in disk_info.values():
                descr = d.get('descr', '').lower()
                is_physical_memory = (
                    'physical memory' in descr or
                    'real memory' in descr or
                    descr == 'memory'
                )
                if not is_physical_memory or 'virtual' in descr:
                    continue
                size_units = safe_int(d.get('size', 0) or 0)
                used_units = safe_int(d.get('used', 0) or 0)
                if size_units <= 0:
                    continue
                mem_pct = used_units / size_units * 100
                break

        disks = []
        # CD-ROM, 媛?곷뱶?쇱씠釉??쒖쇅 ??? hrStorageFixedDisk(4), hrStorageFlashMemory(14)
        EXCLUDE_TYPES = ['Compact Disc', 'Virtual Memory', 'Physical Memory', 'RAM', 'Removable', 'Memory']
        for idx, d in disk_info.items():
            descr = d.get('descr', '')
            if any(t.lower() in descr.lower() for t in EXCLUDE_TYPES):
                continue
            if 'size' in d and 'used' in d and safe_int(d.get('size', 0) or 0) > 0:
                size_bytes = safe_int(d['size']) * safe_int(d.get('unit', 4096))
                used_bytes = safe_int(d['used']) * safe_int(d.get('unit', 4096))
                pct = used_bytes / size_bytes * 100
                size_gb = round(size_bytes/1024**3, 1)
                if size_gb < 1.0:  # ?덈Т ?묒? ?쒕씪?대툕 ?쒖쇅 (1GB 誘몃쭔)
                    continue
                used_gb = round(used_bytes/1024**3, 1)
                free_gb = max(0.0, round((size_bytes - used_bytes)/1024**3, 1))
                disks.append({'path': d.get('descr', idx), 'used_pct': round(pct, 1),
                               'size_gb': size_gb, 'used_gb': used_gb,
                               'free_gb': free_gb})

        # Network interfaces
        interfaces = await self._collect_interfaces(auth, transport)
        processes = await self._collect_processes(auth, transport)

        return {
            'cpu_pct': round(cpu_avg, 1),
            'mem_pct': round(mem_pct, 1),
            'disks': disks,
            'processes': processes,
            'interfaces': interfaces
        }

    async def _collect_processes(self, auth, transport) -> list:
        proc_data: Dict[str, dict] = {}
        for field, oid in [
            ('name', OID['hrSWRunName']),
            ('cpu_centisec', OID['hrSWRunPerfCPU']),
            ('mem_kb', OID['hrSWRunPerfMem']),
        ]:
            rows = await _bulk(self.engine, auth, transport, oid, max_rows=256)
            for oid_str, val in rows:
                idx = oid_str.split('.')[-1]
                if not idx.isdigit():
                    continue
                proc_data.setdefault(idx, {})[field] = val

        processes = []
        for idx, data in proc_data.items():
            name = str(data.get('name', '')).strip()
            if not name:
                continue
            processes.append({
                'pid': safe_int(idx),
                'name': name,
                'cpu_centisec': safe_int(data.get('cpu_centisec', 0) or 0),
                'mem_kb': safe_int(data.get('mem_kb', 0) or 0),
            })

        processes.sort(key=lambda p: (p['mem_kb'], p['cpu_centisec']), reverse=True)
        return processes[:50]

    async def _collect_switch(self, auth, transport) -> dict:
        interfaces = await self._collect_interfaces(auth, transport)
        return {'interfaces': interfaces}

    async def _collect_ups(self, auth, transport) -> dict:
        data = await _get(self.engine, auth, transport,
                          OID['upsEstimatedChargeRemaining'],
                          OID['upsOutputLoad'],
                          OID['upsInputVoltage'],
                          OID['upsOutputVoltage'],
                          OID['upsBatteryTemperature'],
                          OID['upsEstimatedMinutesRemaining'])
        return {
            'battery_pct': safe_float(data.get(OID['upsEstimatedChargeRemaining'], 0) or 0),
            'load_pct':    safe_float(data.get(OID['upsOutputLoad'], 0) or 0),
            'input_v':     safe_float(data.get(OID['upsInputVoltage'], 0) or 0),
            'output_v':    safe_float(data.get(OID['upsOutputVoltage'], 0) or 0),
            'temp_c':      safe_float(data.get(OID['upsBatteryTemperature'], 0) or 0),
            'runtime_min': safe_float(data.get(OID['upsEstimatedMinutesRemaining'], 0) or 0),
        }

    async def _collect_env(self, auth, transport) -> dict:
        """Collect environment temperature/humidity via stable fallback order."""
        from config import settings

        if settings.ENV_TEMP_OID or settings.ENV_HUMIDITY_OID:
            custom_oids = [
                oid for oid in (settings.ENV_TEMP_OID, settings.ENV_HUMIDITY_OID)
                if oid
            ]
            custom = await _get(self.engine, auth, transport, *custom_oids)
            temp_c = None
            humidity_pct = None
            if settings.ENV_TEMP_OID:
                raw_temp = custom.get(settings.ENV_TEMP_OID)
                if not is_snmp_null(raw_temp):
                    temp_c = safe_float(raw_temp) * float(settings.ENV_TEMP_SCALE or 1.0)
            if settings.ENV_HUMIDITY_OID:
                raw_humidity = custom.get(settings.ENV_HUMIDITY_OID)
                if not is_snmp_null(raw_humidity):
                    humidity_pct = safe_float(raw_humidity) * float(settings.ENV_HUMIDITY_SCALE or 1.0)
            if (temp_c is not None and temp_c > 0) or (humidity_pct is not None and humidity_pct > 0):
                return {
                    'temp_c': round(temp_c, 1) if temp_c is not None and temp_c > 0 else None,
                    'humidity_pct': round(humidity_pct, 1) if humidity_pct is not None and humidity_pct > 0 else None,
                    'source': 'snmp_custom_oid',
                }

        data = await _get(self.engine, auth, transport,
                          OID['temperature'], OID['humidity'])
        temp_c = safe_float(data.get(OID['temperature'], 0) or 0) / 10
        humidity_pct = safe_float(data.get(OID['humidity'], 0) or 0)

        if temp_c <= 0 and humidity_pct <= 0:
            generic = await self._collect_entity_sensors(auth, transport)
            temp_c = generic.get('temp_c', temp_c)
            humidity_pct = generic.get('humidity_pct', humidity_pct)

        if temp_c <= 0 and humidity_pct <= 0:
            fls = await self._collect_fls_linknet_env(auth, transport)
            temp_c = fls.get('temp_c', temp_c)
            humidity_pct = fls.get('humidity_pct', humidity_pct)

        return {
            'temp_c': round(temp_c, 1) if temp_c > 0 else None,
            'humidity_pct': round(humidity_pct, 1) if humidity_pct > 0 else None,
            'source': 'snmp_env_fallback',
        }

    async def _collect_fls_linknet_env(self, auth, transport) -> dict:
        data = await _get(self.engine, auth, transport,
                          FLS_DDC400R_ENV_OIDS['temperature'],
                          FLS_DDC400R_ENV_OIDS['humidity'],
                          FLS_DDC400R_ENV_OIDS['humidity_alt'])
        raw_temp = safe_float(data.get(FLS_DDC400R_ENV_OIDS['temperature'], 0) or 0)
        raw_humidity = safe_float(data.get(FLS_DDC400R_ENV_OIDS['humidity'], 0) or 0)
        raw_humidity_alt = safe_float(data.get(FLS_DDC400R_ENV_OIDS['humidity_alt'], 0) or 0)

        result = {}
        if raw_temp > 0:
            result['temp_c'] = raw_temp / 1000 if raw_temp > 1000 else raw_temp
        humidity = raw_humidity if 0 < raw_humidity <= 100 else raw_humidity_alt
        if 0 < humidity <= 100:
            result['humidity_pct'] = humidity
        return result
    async def _collect_entity_sensors(self, auth, transport) -> dict:
        sensor_data: Dict[str, dict] = {}
        for field, oid in [
            ('type', OID['entPhySensorType']),
            ('scale', OID['entPhySensorScale']),
            ('precision', OID['entPhySensorPrecision']),
            ('value', OID['entPhySensorValue']),
            ('status', OID['entPhySensorOperStatus']),
        ]:
            rows = await _bulk(self.engine, auth, transport, oid, max_rows=512)
            for oid_str, val in rows:
                idx = oid_str.split('.')[-1]
                sensor_data.setdefault(idx, {})[field] = val

        result = {}
        for sensor in sensor_data.values():
            status = str(sensor.get('status', '')).lower()
            if status and status not in ('1', 'ok'):
                continue
            sensor_type = str(sensor.get('type', '')).lower()
            value = self._scaled_sensor_value(
                sensor.get('value', 0),
                sensor.get('scale', 9),
                sensor.get('precision', 0),
            )
            if value is None:
                continue
            if sensor_type in ('8', 'celsius') and 'temp_c' not in result:
                result['temp_c'] = value
            elif sensor_type in ('9', 'percentrh', 'percent rh', 'percent') and 'humidity_pct' not in result:
                result['humidity_pct'] = value
        return result

    @staticmethod
    def _scaled_sensor_value(raw_value, raw_scale, raw_precision) -> Optional[float]:
        try:
            value = float(raw_value)
            precision = int(raw_precision)
        except (TypeError, ValueError):
            return None

        scale_text = str(raw_scale).lower()
        scale_map = {
            '1': 1e-24, 'yocto': 1e-24,
            '2': 1e-21, 'zepto': 1e-21,
            '3': 1e-18, 'atto': 1e-18,
            '4': 1e-15, 'femto': 1e-15,
            '5': 1e-12, 'pico': 1e-12,
            '6': 1e-9, 'nano': 1e-9,
            '7': 1e-6, 'micro': 1e-6,
            '8': 1e-3, 'milli': 1e-3,
            '9': 1.0, 'units': 1.0,
            '10': 1e3, 'kilo': 1e3,
            '11': 1e6, 'mega': 1e6,
            '12': 1e9, 'giga': 1e9,
        }
        multiplier = scale_map.get(scale_text, 1.0)
        return value * multiplier / (10 ** precision)

    async def _collect_interfaces(self, auth, transport) -> list:
        ifdata: Dict[str, dict] = {}
        for field, oid in [('descr', OID['ifDescr']), ('if_name', OID['ifName']),
                            ('alias', OID['ifAlias']), ('status', OID['ifOperStatus']),
                            ('speed', OID['ifSpeed']), ('in_oct', OID['ifInOctets']),
                            ('out_oct', OID['ifOutOctets']), ('in_err', OID['ifInErrors']),
                            ('out_err', OID['ifOutErrors'])]:
            rows = await _bulk(self.engine, auth, transport, oid)
            for oid_str, val in rows:
                idx = oid_str.split('.')[-1]
                ifdata.setdefault(idx, {})[field] = val

        interfaces = []
        for idx, d in ifdata.items():
            status_map = {'1': 'up', '2': 'down', '3': 'testing'}
            if_name = str(d.get('if_name') or '').strip()
            descr = str(d.get('descr') or '').strip()
            name = if_name or descr or f'if{idx}'
            interfaces.append({
                'index':   int(idx),
                'name':    name,
                'descr':   descr or name,
                'if_name': if_name,
                'alias':   str(d.get('alias') or '').strip(),
                'status':  status_map.get(d.get('status', '2'), 'unknown'),
                'speed_mbps': safe_int(d.get('speed', 0) or 0) // 1_000_000,
                'in_octets':  safe_int(d.get('in_oct', 0) or 0),
                'out_octets': safe_int(d.get('out_oct', 0) or 0),
                'in_errors':  safe_int(d.get('in_err', 0) or 0),
                'out_errors': safe_int(d.get('out_err', 0) or 0),
            })
        return sorted(interfaces, key=lambda item: item['index'])

