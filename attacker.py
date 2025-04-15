import json
import paho.mqtt.client as mqtt

# MQTT broker parameters (adjust if needed)
BROKER = "localhost"
PORT = 1883
USERNAME = "testuser"
PASSWORD = "testpass"

# Topics: assuming the publisher sends to "demo/jwt" and
# the subscriber listens to "demo/jwt_attacked" (or you could reuse the same topic)
INPUT_TOPIC = "demo/jwt"          
OUTPUT_TOPIC = "demo/jwt_attacked"  

def tamper_jwt(token):
    """
    Simulate tampering by modifying the JWT token.
    Here, we simply change the last character of the token.
    (In a real attack, any change in the token will break the signature.)
    """
    if not token or len(token) < 1:
        return token
    # Change the last character (rotate between two arbitrary letters)
    new_last = 'X' if token[-1] != 'X' else 'Y'
    tampered_token = token[:-1] + new_last
    return tampered_token

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("MITM attacker connected to the broker!")
        client.subscribe(INPUT_TOPIC)
        print(f"Subscribed to {INPUT_TOPIC}. Waiting for messages...")
    else:
        print("Connection failed with code", rc)

def on_message(client, userdata, msg):
    print(f"\nReceived message on {msg.topic}:")
    try:
        # Parse the received JSON message
        data = json.loads(msg.payload.decode())
    except Exception as e:
        print("Error parsing message:", e)
        return
    
    original_token = data.get("jwt")
    if original_token:
        tampered_token = tamper_jwt(original_token)
        print("Original JWT token:", original_token)
        print("Tampered JWT token:", tampered_token)
        # Replace the token with the tampered version
        data["jwt"] = tampered_token
    else:
        print("No JWT found in the message. Nothing to tamper with.")

    # Optionally, you can also tamper other parts of the data here.
    # For this demo, we only change the JWT.
    
    new_payload = json.dumps(data)
    # Republish on the output topic so that the subscriber (believing it's from the broker)
    # receives the tampered message.
    client.publish(OUTPUT_TOPIC, new_payload)
    print(f"Republished tampered message to {OUTPUT_TOPIC}: {new_payload}")

# Set up the MQTT client
client = mqtt.Client("MITMAttacker", protocol=mqtt.MQTTv311)
client.username_pw_set(USERNAME, PASSWORD)
client.on_connect = on_connect
client.on_message = on_message

# Connect to the MQTT broker
client.connect(BROKER, PORT)
client.loop_forever()
