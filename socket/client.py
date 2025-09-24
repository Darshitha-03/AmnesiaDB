# client.py (Final Corrected Version)
import websocket
import json

# Configuration - should match the server's configuration
DB_NAME = "realtime-app-cache"
PUBLISH_CHANNEL = "sensor_updates"

def on_message(ws, message):
    """Callback function when a message is received."""
    try:
        data = json.loads(message)
        value = data.get('value', 'N/A')
        sensor_id = data.get('sensor_id', 'Unknown')
        print(f"<- ✅ New update from Sensor '{sensor_id}': {value}")
    except json.JSONDecodeError:
        print(f"<- Received non-JSON message: {message}")

def on_error(ws, error):
    """Callback function when an error occurs."""
    # Don't print an error if it's just the normal connection close exception
    if not isinstance(error, websocket.WebSocketConnectionClosedException):
        print(f"--- ❌ WebSocket Error: {error} ---")

def on_close(ws, close_status_code, close_msg):
    """Callback function when the connection is closed."""
    print("--- 🔌 Connection closed ---")

def on_open(ws):
    """Callback function when the connection is opened."""
    print("--- 🔌 Connection opened ---")
    print(f"📡 Subscribed to channel '{PUBLISH_CHANNEL}'. Waiting for updates...")

if __name__ == "__main__":
    print("="*50)
    print("      AmnesiaDB Real-time Client")
    print("="*50)
    
    api_key = input("🔑 Please paste the 'Read Key' from the server output: ").strip()

    # --- THIS IS THE KEY CHANGE ---
    # The URL now includes the database name and the API key as a 'token' query parameter for authentication.
    websocket_url = f"ws://127.0.0.1:8000/{DB_NAME}/ws/subscribe/{PUBLISH_CHANNEL}?token={api_key}"
    
    print(f"Connecting to AmnesiaDB...")
    
    ws_app = websocket.WebSocketApp(
        websocket_url,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close
    )
    
    try:
        # run_forever() is a blocking call that keeps the client listening
        ws_app.run_forever()
    except KeyboardInterrupt:
        ws_app.close()
        print("\nClient stopped by user.")
