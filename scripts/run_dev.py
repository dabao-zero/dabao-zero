"""Start the dev server on the first free port at or above 8000 and print it."""

import socket

import uvicorn

from dabao.logging_config import configure_logging


def free_port(start: int = 8000) -> int:
    for port in range(start, start + 100):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("no free port found")


if __name__ == "__main__":
    configure_logging()
    port = free_port()
    print(f"dabao dev server: http://127.0.0.1:{port}")
    uvicorn.run("dabao.api:create_app", factory=True, host="127.0.0.1", port=port, reload=True)
