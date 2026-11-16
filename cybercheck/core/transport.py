"""HTTPX transport with an assessment deadline and a 64 KiB header-read cap.

Uses the public httpcore backend API; every socket operation rechecks the shared
deadline, including fragmented/slow headers. Responses are closed without reading
their body streams, including for explicitly enabled GET fallback requests.
"""

import ssl

import httpcore
import httpx

from cybercheck.core.config import Budget
from cybercheck.core.validation import public_ip


class DeadlineStream(httpcore.NetworkStream):
    def __init__(self, stream: httpcore.NetworkStream, budget: Budget):
        self.stream = stream
        self.budget = budget
        self.received = 0

    def operation_timeout(self, requested: float | None) -> float:
        remaining = self.budget.remaining()
        return remaining if requested is None else min(requested, remaining)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        if self.received >= 65536:
            raise httpcore.RemoteProtocolError("Response header read limit exceeded")
        data = self.stream.read(
            min(max_bytes, 65536 - self.received), timeout=self.operation_timeout(timeout)
        )
        self.received += len(data)
        return data

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.stream.write(buffer, timeout=self.operation_timeout(timeout))

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        try:
            return DeadlineStream(
                self.stream.start_tls(
                    ssl_context,
                    server_hostname=server_hostname,
                    timeout=self.operation_timeout(timeout),
                ),
                self.budget,
            )
        except BaseException:
            # If the deadline expires before start_tls is called, httpcore has
            # not yet registered this connection. Close the connected raw stream.
            self.stream.close()
            raise

    def close(self) -> None:
        self.stream.close()

    def get_extra_info(self, info: str) -> object:
        return self.stream.get_extra_info(info)


class DeadlineBackend(httpcore.NetworkBackend):
    def __init__(self, budget: Budget):
        self.budget = budget
        self.backend = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: list[tuple] | None = None,
    ) -> httpcore.NetworkStream:
        # Defense in depth: transport cannot resolve a hostname or use other ports.
        public_ip(host.decode("ascii") if isinstance(host, bytes) else host)
        if port not in {80, 443}:
            raise ValueError("Only ports 80 and 443 are permitted")
        stream = self.backend.connect_tcp(
            host,
            port,
            timeout=min(timeout, self.budget.remaining()) if timeout is not None else self.budget.remaining(),
            local_address=local_address,
            socket_options=socket_options,
        )
        return DeadlineStream(stream, self.budget)


class PinnedTransport(httpx.BaseTransport):
    def __init__(self, budget: Budget, backend: httpcore.NetworkBackend | None = None):
        self.allow_get_fallback = budget.settings.allow_get_fallback
        self.pool = httpcore.ConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=1,
            max_keepalive_connections=0,
            retries=0,
            network_backend=backend or DeadlineBackend(budget),
            http1=True,
            http2=False,
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.method != "HEAD" and not (
            self.allow_get_fallback and request.method == "GET" and request.url.scheme == "https"
        ):
            raise ValueError("Only HEAD and explicitly enabled HTTPS GET requests are supported")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        response = None
        try:
            response = self.pool.handle_request(core_request)
            return httpx.Response(
                response.status, headers=response.headers, content=b"", extensions=response.extensions
            )
        except httpcore.TimeoutException as exc:
            raise httpx.TimeoutException(str(exc), request=request) from exc
        except (httpcore.NetworkError, httpcore.ProtocolError, httpcore.ConnectionNotAvailable) as exc:
            raise httpx.TransportError(str(exc), request=request) from exc
        finally:
            if response is not None:
                response.close()

    def close(self) -> None:
        self.pool.close()
