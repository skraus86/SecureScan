"""
Run the SecureScan Web UI server
"""

import argparse
from .app import create_app


def main():
    parser = argparse.ArgumentParser(description='SecureScan Web UI')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    app = create_app()
    
    print(f"""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║   🛡️  SecureScan Web UI                                   ║
    ║                                                           ║
    ║   Server running at: http://{args.host}:{args.port}              ║
    ║                                                           ║
    ║   SAST • SCA • Secrets Detection                          ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
