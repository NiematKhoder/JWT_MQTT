import jwt
import json
import paho.mqtt.client as mqtt

# Same secret key and algorithm for JWT verification
JWT_SECRET = "your_jwt_secret_key"
JWT_ALGORITHM = "HS256"

# MQTT broker connection details (same as publisher)
BROKER = "localhost"
PORT = 1883
USERNAME = "testuser"
PASSWORD = "testpass"
TOPIC = "demo/jwt"
# TOPIC = "demo/jwt_attacked" 

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Subscriber Connected successfully")
        # Subscribe to the topic once connected
        client.subscribe(TOPIC)
    else:
        print("Subscriber Connection failed with code", rc)

def on_message(client, userdata, msg):
    print("Message received on topic:", msg.topic)
    try:
        message = json.loads(msg.payload.decode())
        token = message.get("jwt", None)
        
        if token:
            # Decode and verify the JWT
            decoded_payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            print("JWT verified. Decoded payload:", decoded_payload)
        else:
            print("No JWT token found in the message.")
    except jwt.InvalidTokenError as e:
        print("JWT verification failed:", e)
    except Exception as e:
        print("Error processing the message:", e)

# Create an MQTT client instance
client = mqtt.Client("Subscriber")
client.username_pw_set(USERNAME, PASSWORD)
client.on_connect = on_connect
client.on_message = on_message

client.connect(BROKER, PORT)
client.loop_forever()
