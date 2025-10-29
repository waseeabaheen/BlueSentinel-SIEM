import asyncio
from typing import Optional
from .pipeline import Pipeline

class SyslogUDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, pipeline: Pipeline):
        self.pipeline = pipeline

    def datagram_received(self, data: bytes, addr):
        line = data.decode(errors="ignore")
        self.pipeline.ingest_line("syslog", line)

async def run_syslog_server(pipeline: Pipeline, host: str = "0.0.0.0", port: int = 5514):
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SyslogUDPProtocol(pipeline),
        local_addr=(host, port),
    )
    try:
        await asyncio.Future()  # run forever
    finally:
        transport.close()
