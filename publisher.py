import jwt
import time
import json
import paho.mqtt.client as mqtt

# Secret key for signing the JWT (must be the same between publisher and subscriber)
JWT_SECRET = "your_jwt_secret_key"
JWT_ALGORITHM = "HS256"

# MQTT broker connection details
BROKER = "localhost"
PORT = 1883
USERNAME = "testuser"
PASSWORD = "testpass"
TOPIC = "demo/jwt"

def create_jwt(payload):
    """
    Creates a JSON Web Token using the provided payload.
    The token is signed with a secret key to ensure integrity.
    """
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Publisher Connected successfully")
    else:
        print("Publisher Connection failed with code", rc)

def publish_message():
    # Create the payload with any data you want to secure.
    payload_data = {
        "message": "Hello from MQTT with JWT!",
        "timestamp": int(time.time())
    }
    
    # Generate the JWT for the payload data.
    token = create_jwt(payload_data)
    
    # Prepare the complete payload. Here the JWT is embedded in a JSON structure.
    mqtt_payload = {
        "jwt": token,
        "info": "This message carries a JWT token for integrity verification."
    }
    
    client.publish(TOPIC, json.dumps(mqtt_payload))
    print("Published message with JWT token.")

# Create MQTT client instance
client = mqtt.Client("Publisher")
client.username_pw_set(USERNAME, PASSWORD)
client.on_connect = on_connect

client.connect(BROKER, PORT)
client.loop_start()

# Give the client a brief moment to connect
time.sleep(1)
publish_message()

# Allow some time for the message to be sent before ending the script.
time.sleep(2)
client.loop_stop()
client.disconnect()
