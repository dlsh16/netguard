"""
Environmental sensor collector.
Supports:
 - Raspberry Pi HTTP REST sensor (DHT22 / BME280)
 - SNMP-based temperature/humidity sensors
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional

import aiohttp

logger = logging.getLogger('netguard.env')


class EnvCollector:
    def __init__(self):
        from config import settings
        self.rpi_enabled = settings.RPI_ENABLED
        self.rpi_ip = settings.RPI_IP
        self.rpi_port = settings.RPI_PORT
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            )
        return self._session

    async def collect(self) -> dict:
        if not self.rpi_enabled or not self.rpi_ip:
            return {'source': 'disabled', 'temp_c': None, 'humidity_pct': None}

        try:
            session = await self._get_session()
            url = f"http://{self.rpi_ip}:{self.rpi_port}/sensor"
            async with session.get(url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return {
                        'source': 'rpi',
                        'temp_c': data.get('temperature'),
                        'humidity_pct': data.get('humidity'),
                        'timestamp': datetime.now().isoformat()
                    }
        except Exception as e:
            logger.warning(f"RPI sensor read failed: {e}")

        return {
            'source': 'rpi',
            'temp_c': None,
            'humidity_pct': None,
            'error': 'connection_failed'
        }
