import sys
import os
import json
import time
import subprocess

sys.path.append('/home/joe/Project-Hellhound/Hellhound-Pentest')
from hellhound.modules.intel import BlobUnpacker, SourceAuditor

class MockEmit:
    def info(self, msg): print(f'[INFO] {msg}')
    def success(self, msg): print(f'[SUCCESS] {msg}')
    def warn(self, msg): print(f'[WARN] {msg}')
    def error(self, msg): print(f'[ERROR] {msg}')

def run_test():
    emit = MockEmit()
    target = 'http://localhost:9998'
    options = {
        'spider_intel': {
            'endpoints': [
                {'url': 'http://localhost:9998/mock.js'}
            ]
        }
    }

    print("--- 1. Running BlobUnpacker ---")
    blob_result = BlobUnpacker.run(target, emit, options)
    
    # Simulate console.py auto-feed
    options['blobunpacker_intel'] = blob_result['intel']

    print("\n--- 2. Running SourceAuditor ---")
    audit_result = SourceAuditor.run(target, emit, options)
    
    print('\n--- RESULTS ---')
    print(json.dumps(audit_result, indent=2))

    vulns = audit_result['intel']['vulnerabilities']
    
    # We expect:
    # 1. SA-001 (eval)
    # 2. SA-002 (dangerouslySetInnerHTML)
    # 3. SA-003 (isAdmin)
    # 4. SA-007 (SQLi)
    # 5. SA-008 (Cred)

    found_eval = any(v['id'] == 'SA-001' for v in vulns)
    found_xss = any(v['id'] == 'SA-002' for v in vulns)
    found_logic = any(v['id'] == 'SA-003' for v in vulns)
    found_sqli = any(v['id'] == 'SA-007' for v in vulns)
    found_cred = any(v['id'] == 'SA-008' for v in vulns)

    print('\nTests:')
    print(f'Dangerous eval() Found: {found_eval}')
    print(f'React XSS Point Found: {found_xss}')
    print(f'Hardcoded Admin Found: {found_logic}')
    print(f'SQL Injection Pattern Found: {found_sqli}')
    print(f'Hardcoded Credential Found: {found_cred}')

    if found_eval and found_xss and found_logic and found_sqli and found_cred:
        print('\nVERIFICATION SUCCESSFUL')
        return True
    else:
        print('\nVERIFICATION FAILED')
        return False

# Re-create mock_target.py since it was deleted
MOCK_TARGET_CONTENT = """
import http.server
import socketserver
import json

PORT = 9998

JS_MAP = {
    "version": 3,
    "file": "mock.js",
    "sources": ["src/app.tsx", "src/api/auth.ts"],
    "sourcesContent": [
        "export const App = () => { const DB_PASSWORD = 'SuperSecretPass123!'; const isAdmin = true; return <div dangerouslySetInnerHTML={{__html: '<h1>App</h1>'}} /> }",
        "export const query_db = (id) => { const q = 'SELECT * FROM users WHERE id = \\'' + id + '\\''; eval('console.log(\"Executing...\", q)'); return q; }"
    ],
    "names": ["App", "query_db", "DB_PASSWORD"],
    "mappings": "AAAA,OAAO,MAAM"
}

class MockHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/mock.js':
            self.send_response(200)
            self.send_header('Content-type', 'application/javascript')
            self.end_headers()
            self.wfile.write(b'console.log("Mock");\\n//# sourceMappingURL=mock.js.map')
        elif self.path == '/mock.js.map':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(JS_MAP).encode())
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), MockHandler) as httpd:
        httpd.serve_forever()
"""

if __name__ == '__main__':
    # Save mock target
    with open('/home/joe/Project-Hellhound/Hellhound-Pentest/tests/mock_target.py', 'w') as f:
        f.write(MOCK_TARGET_CONTENT)

    # Start mock server
    server_proc = subprocess.Popen(['python3', '/home/joe/Project-Hellhound/Hellhound-Pentest/tests/mock_target.py'])
    time.sleep(2)
    try:
        success = run_test()
        sys.exit(0 if success else 1)
    finally:
        server_proc.terminate()
        os.remove('/home/joe/Project-Hellhound/Hellhound-Pentest/tests/mock_target.py')
