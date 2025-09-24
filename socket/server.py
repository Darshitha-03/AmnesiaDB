# server.py (Final Corrected Version)
import requests
import time
import random
import json

AMNESIADB_URL = "http://127.0.0.1:8000"
DB_NAME = "realtime-app-cache"
DATA_KEY = "sensor_readings"
PUBLISH_CHANNEL = "sensor_updates"

def create_database():
    """Creates a new database instance in AmnesiaDB."""
    print(f"Attempting to create database '{DB_NAME}'...")
    try:
        response = requests.post(
            f"{AMNESIADB_URL}/admin/create_database/{DB_NAME}",
            json={"snapshot_interval": 30}
        )
        if response.status_code == 201:
            data = response.json()
            print(f"✅ Database '{DB_NAME}' created successfully.")
            return data['admin_api_key']
        elif response.status_code == 409:
            print(f"⚠️ Database '{DB_NAME}' already exists. Please use an existing key or delete the corresponding .db file and restart.")
            return None
        else:
            print(f"❌ Error creating database: {response.status_code} {response.text}")
            return None
    except requests.ConnectionError:
        print("❌ Connection Error: Is the AmnesiaDB server running?")
        return None

def create_api_key(admin_key: str, permissions: str):
    """Creates a new API key with specified permissions."""
    print(f"Creating a '{permissions}' key...")
    headers = {"X-API-KEY": admin_key}
    response = requests.post(
        f"{AMNESIADB_URL}/{DB_NAME}/admin/create_key",
        headers=headers,
        json={"permissions": permissions}
    )
    if response.status_code == 200:
        data = response.json()
        print(f"✅ Successfully created '{permissions}' key.")
        return data['api_key']
    else:
        print(f"❌ Error creating key: {response.status_code} {response.text}")
        return None

def start_data_producer(admin_key: str):
    """Periodically pushes a random number to a list and publishes it."""
    print("\n🚀 Starting data producer. Pushing a new random number every 15 seconds...")
    print("Press Ctrl+C to stop.")
    
    headers = {"X-API-KEY": admin_key}

    while True:
        try:
            random_value = round(random.uniform(10.0, 50.0), 2)
            
            # 1. Push the value to a list for persistent storage
            lpush_payload = {
                "command": "lpush",
                "args": [DATA_KEY, str(random_value)]
            }
            response_lpush = requests.post(
                f"{AMNESIADB_URL}/{DB_NAME}/command",
                headers=headers,
                json=lpush_payload
            )
            response_lpush.raise_for_status()

            # 2. Publish the value to a WebSocket channel for real-time subscribers
            publish_payload = {"message": json.dumps({"sensor_id": "A-01", "value": random_value})}
            
            # THIS IS THE LINE THAT WAS FIXED
            publish_url = f"{AMNESIADB_URL}/{DB_NAME}/publish/{PUBLISH_CHANNEL}"
            
            response_pub = requests.post(
                publish_url,
                headers=headers, # Pass headers for authentication
                json=publish_payload
            )
            response_pub.raise_for_status()

            print(f"  -> Pushed and Published value: {random_value}")
            
            time.sleep(3)

        except requests.HTTPError as e:
            print(f"❌ HTTP Error during data push: {e.response.status_code} {e.response.text}")
            break
        except requests.ConnectionError:
            print("❌ Connection lost to AmnesiaDB server. Stopping producer.")
            break
        except KeyboardInterrupt:
            print("\n🛑 Producer stopped by user.")
            break


if __name__ == "__main__":
    admin_api_key = create_database()
    
    if admin_api_key:
        writer_api_key = create_api_key(admin_api_key, "write")
        reader_api_key = create_api_key(admin_api_key, "read")
        
        print("\n" + "="*50)
        print("🔑 API Keys Generated 🔑")
        print(f"Database Name: {DB_NAME}")
        print(f"  Admin Key: {admin_api_key}")
        print(f"  Write Key: {writer_api_key}")
        print(f"  Read Key (for client.py): {reader_api_key}")
        print("="*50 + "\n")

        # Start the producer using the admin or writer key
        start_data_producer(admin_api_key)
