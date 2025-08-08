from app import create_app
import os
import socket

app = create_app()


def _is_port_free(port: int) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
        return True
    except OSError:
        return False


def _find_free_port(preferred: int) -> int:
    if _is_port_free(preferred):
        return preferred
    # Try the next few ports
    for p in range(preferred + 1, preferred + 11):
        if _is_port_free(p):
            return p
    # Fallback to an ephemeral port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


if __name__ == '__main__':
    preferred = int(os.environ.get('PORT', '5000'))
    port = _find_free_port(preferred)
    print(f"Starting Network Analyzer on http://localhost:{port}")
    app.run(host='0.0.0.0', port=port, debug=True)
