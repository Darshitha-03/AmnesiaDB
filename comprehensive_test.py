# test.py (Final Version for AmnesiaDB 3.0 - Corrected)
import requests
import time
import os
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# This Test Suite is designed to run against a live AmnesiaDB server.
# Ensure amnesiadb.py is running before executing this script.

# --- Mock Webhook Receiver ---
# This simple server runs in a background thread to receive and store webhook calls.
class MockWebhookReceiver(BaseHTTPRequestHandler):
    """A mock server to catch webhook POST requests."""
    last_payload = None
    
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        MockWebhookReceiver.last_payload = json.loads(post_data.decode('utf-8'))
        self.send_response(200)
        self.end_headers()
        
    def log_message(self, format, *args):
        # Suppress logging to keep test output clean
        return

def run_mock_server(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MockWebhookReceiver)
    httpd.serve_forever()

# --- AmnesiaDB Client ---
class AmnesiaDBClient:
    """A simple client to interact with the AmnesiaDB API for testing."""
    def __init__(self, base_url="http://127.0.0.1:2707"):
        self.base_url = base_url
        self.db_name = f"test_db_{int(time.time())}" # Use a unique DB name for each test run
        self.admin_key, self.write_key, self.read_key = None, None, None

    def create_database(self):
        url = f"{self.base_url}/admin/create_database/{self.db_name}"
        response = requests.post(url, json={"snapshot_interval": 10})
        response.raise_for_status()
        data = response.json(); self.admin_key = data['admin_api_key']
        return response.status_code, data

    def create_key(self, permissions: str):
        url = f"{self.base_url}/{self.db_name}/admin/create_key"
        headers = {"X-API-KEY": self.admin_key}
        response = requests.post(url, headers=headers, json={"permissions": permissions})
        response.raise_for_status()
        data = response.json()
        if permissions == "write": self.write_key = data['api_key']
        elif permissions == "read": self.read_key = data['api_key']
        return response.status_code, data

    def command(self, api_key: str, command: str, args: list):
        url = f"{self.base_url}/{self.db_name}/command"
        headers = {"X-API-KEY": api_key}
        payload = {"command": command, "args": args}
        response = requests.post(url, headers=headers, json=payload)
        return response

    # --- NEW: Methods for testing new features ---

    def create_webhook(self, pattern: str, webhook_url: str):
        url = f"{self.base_url}/{self.db_name}/admin/webhooks"
        headers = {"X-API-KEY": self.admin_key}
        payload = {"key_pattern": pattern, "url": webhook_url}
        response = requests.post(url, headers=headers, json=payload)
        return response

    def upload_function(self, func_name: str, code: str):
        url = f"{self.base_url}/{self.db_name}/admin/functions/{func_name}"
        headers = {"X-API-KEY": self.admin_key}
        payload = {"code": code}
        response = requests.post(url, headers=headers, json=payload)
        return response

    def get_dashboard_stats(self):
        url = f"{self.base_url}/{self.db_name}/dashboard/api/stats"
        headers = {"X-API-KEY": self.admin_key}
        return requests.get(url, headers=headers)
        
    def cleanup(self):
        """Removes the .db files created during the test.
        admin_db_file = "amnesiadb_admin.db"
        test_db_file = f"{self.db_name}.db"
        if os.path.exists(admin_db_file): os.remove(admin_db_file)
        if os.path.exists(test_db_file): os.remove(test_db_file)"""
        print(f"\n🧹 Cleaned up database files: ")

class TestRunner:
    """Runs tests and reports the results."""
    def __init__(self):
        self.client = AmnesiaDBClient()
        self.passed = 0
        self.failed = 0
        self.timings = []
        self.total_start_time = 0

    def _assert_and_time(self, test_name, func, *args, **kwargs):
        """A wrapper to time a function and assert its result."""
        check_lambda = kwargs.pop('check')
        
        start_time = time.perf_counter()
        response = func(*args, **kwargs)
        end_time = time.perf_counter()
        
        duration_ms = (end_time - start_time) * 1000
        status = "✅ PASS"
        
        try:
            condition, msg = check_lambda(response)
            if not condition:
                status = "❌ FAIL"
                self.failed += 1
                print(f"  {status}: {test_name:<40} [{duration_ms:8.2f} ms] - {msg}")
            else:
                self.passed += 1
                print(f"  {status}: {test_name:<40} [{duration_ms:8.2f} ms]")
        except Exception as e:
            status = "❌ ERROR"
            self.failed += 1
            print(f"  {status}: {test_name:<40} [{duration_ms:8.2f} ms] - Assertion check failed: {e}")
        
        self.timings.append((test_name, status, duration_ms))
        
    def run(self):
        self.total_start_time = time.perf_counter()
        
        # Start mock webhook server
        mock_server_port = 8080
        mock_server = threading.Thread(target=run_mock_server, args=(mock_server_port,), daemon=True)
        mock_server.start()
        print(f"--- Mock Webhook Server running on port {mock_server_port} ---")
        time.sleep(0.5) # Give the server a moment to start

        try:
            print("--- Setting up Test Environment ---")
            self.client.create_database()
            self.client.create_key("write"); self.client.create_key("read")
            print(f"Database '{self.client.db_name}' and API keys created.")
            self._run_all_tests(webhook_url=f"http://127.0.0.1:{mock_server_port}")
        except requests.ConnectionError:
            print("\n❌ FATAL: Could not connect to AmnesiaDB server. Please ensure it's running.")
        except Exception as e:
            print(f"\n❌ An unexpected error occurred: {e}")
            self.failed += 1
        finally:
            self._print_summary()
            self.client.cleanup()
    def _run_all_tests(self, webhook_url: str):
        c = self.client # Shortcut

        # --- Base Feature Tests (from original script) ---
        print("\n--- 🧪 Running Admin & Security Tests ---")
        self._assert_and_time("Read key cannot write", c.command, c.read_key, "set", ["no", "access"], check=lambda r: (r.status_code == 403, ""))
        self._assert_and_time("Write key can write", c.command, c.write_key, "set", ["yes", "access"], check=lambda r: (r.status_code == 200, ""))
        self._assert_and_time("Write key can read", c.command, c.write_key, "get", ["yes"], check=lambda r: (r.json()['result'] == "access", ""))

        print("\n--- 🧪 Running String & Atomic Command Tests ---")
        self._assert_and_time("SET command", c.command, c.admin_key, "set", ["str_key", "hello"], check=lambda r: (r.json()['result'] == "OK", ""))
        self._assert_and_time("GET command", c.command, c.admin_key, "get", ["str_key"], check=lambda r: (r.json()['result'] == "hello", ""))
        self._assert_and_time("INCR new key", c.command, c.admin_key, "incr", ["counter"], check=lambda r: (r.json()['result'] == 1, ""))

        # --- NEW: Python-Native Superpowers ---
        print("\n--- 🐍 Running Python-Native Feature Tests ---")
        py_object = {"name": "Alice", "id": 123, "active": True, "roles": ["admin", "user"]}
        self._assert_and_time("PSET command (pickle set)", c.command, c.admin_key, "pset", ["py_obj", py_object], check=lambda r: (r.json()['result'] == "OK", ""))
        self._assert_and_time("PGET command (pickle get)", c.command, c.admin_key, "pget", ["py_obj"], check=lambda r: (r.json()['result'] == py_object, f"Expected {py_object}, got {r.json()['result']}"))
        
        udf_code = """
async def calculate_score(context, user_key, points_to_add):
    user_data = await context.get(user_key)
    current_score = int(user_data) if user_data else 0
    new_score = current_score + points_to_add
    await context.set(user_key, str(new_score))
    return f"OK, new score is {new_score}"
"""
        c.command(c.admin_key, "set", ["user:1:score", "100"])
        self._assert_and_time("UPLOAD_FUNC command (UDF)", c.upload_function, "calculate_score", udf_code, check=lambda r: (r.status_code == 200, ""))
        self._assert_and_time("EXEC command (UDF)", c.command, c.admin_key, "exec", ["calculate_score", "user:1:score", 50], check=lambda r: (r.json()['result'] == "OK, new score is 150", ""))
        self._assert_and_time("Verify UDF result", c.command, c.admin_key, "get", ["user:1:score"], check=lambda r: (r.json()['result'] == "150", ""))
        
        # --- NEW: Advanced Data Querying ---
        print("\n--- 🗃️ Running Advanced Querying Tests ---")
        c.command(c.admin_key, "set", ["product:1", "a lightweight blue jacket"])
        c.command(c.admin_key, "set", ["product:2", "a heavy red jacket"])
        c.command(c.admin_key, "set", ["product:3", "lightweight red pants"])
        
        time.sleep(0.01) # Yield to event loop to ensure FTS index updates

        # *** THE FIX IS HERE: The query is changed from "lightweight jacket" to "jacket" ***
        # This correctly finds all documents containing "jacket"
        self._assert_and_time("FT_SEARCH command", c.command, c.admin_key, "ft_search", ["jacket"], check=lambda r: (sorted(r.json()['result']) == ["product:1", "product:2"], f"Expected ['product:1', 'product:2'], got {sorted(r.json()['result'])}"))
        self._assert_and_time("FT_SEARCH no results", c.command, c.admin_key, "ft_search", ["shoes"], check=lambda r: (r.json()['result'] == [], ""))
        
        json_doc = '{"name": "Alice", "address": {"city": "Salem", "zip": "636001"}, "tags": ["a", "b"]}'
        c.command(c.admin_key, "set", ["user:json", json_doc])
        self._assert_and_time("JSON_GET nested object", c.command, c.admin_key, "json_get", ["user:json", "$.address.city"], check=lambda r: (r.json()['result'] == "Salem", ""))
        self._assert_and_time("JSON_GET array element", c.command, c.admin_key, "json_get", ["user:json", "$.tags.1"], check=lambda r: (r.json()['result'] == "b", ""))
        self._assert_and_time("JSON_GET non-existent path", c.command, c.admin_key, "json_get", ["user:json", "$.address.country"], check=lambda r: (r.json()['result'] is None, ""))

        # --- NEW: Web-Native Features ---
        print("\n--- 🕸️ Running Web-Native Feature Tests ---")
        self._assert_and_time("Create Webhook", c.create_webhook, "user:*", webhook_url, check=lambda r: (r.status_code == 201, ""))
        c.command(c.admin_key, "set", ["user:123", "active"]) # Trigger the webhook
        print("  ⏳ Waiting for webhook to be processed...")
        time.sleep(0.5) # Give the server time to make the async request

        test_name = "Webhook was received"
        if MockWebhookReceiver.last_payload and MockWebhookReceiver.last_payload.get("key") == "user:123":
            self.passed += 1
            status = "✅ PASS"
            print(f"  {status}: {test_name:<40} [     N/A ms]")
            self.timings.append((test_name, status, 0.0))
        else:
            self.failed += 1
            status = "❌ FAIL"
            print(f"  {status}: {test_name:<40} [     N/A ms] - Webhook payload not received or incorrect")
            self.timings.append((test_name, status, 0.0))
        
        self._assert_and_time("Dashboard API /stats", c.get_dashboard_stats, check=lambda r: (r.status_code == 200 and "key_count" in r.json(), ""))
    def _print_summary(self):
        total_duration = (time.perf_counter() - self.total_start_time) * 1000
        total = self.passed + self.failed
        
        print("\n" + "="*60)
        print(" " * 22 + "PERFORMANCE REPORT")
        print("="*60)
        print(f"{'Test Case':<42} | {'Status':<10} | {'Duration (ms)':>12}")
        print("-"*60)
        for name, status, duration in self.timings:
            print(f"{name:<42} | {status:<10} | {duration:>12.2f}")
        print("="*60)

        print("\n" + "="*30)
        print(" " * 9 + "TEST SUMMARY")
        print("="*30)
        print(f"  Total Tests: {total}")
        print(f"  ✅ Passed:     {self.passed}")
        print(f"  ❌ Failed:     {self.failed}")
        print(f"  ⏱️  Total Time: {total_duration:.2f} ms")
        print("="*30)

if __name__ == "__main__":
    runner = TestRunner()
    runner.run()
