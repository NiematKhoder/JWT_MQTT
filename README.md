
# JWT with MQTT: Authentication, Data Integrity & MITM Simulation

## Table of Contents

- [Introduction](#introduction)
- [Purpose of This Tutorial](#purpose-of-this-tutorial)
- [Pre-requisites](#pre-requisites)
- [Project Structure](#project-structure)
- [Configuration & Setup](#configuration--setup)
  - [Mosquitto Broker Setup with Docker](#mosquitto-broker-setup-with-docker)
  - [Creating the Password File](#creating-the-password-file)
- [Phase 1: Normal Operation (Untampered Data)](#phase-1-normal-operation-untampered-data)
  - [Publisher Code: Creating and Sending JWT](#publisher-code-creating-and-sending-jwt)
  - [Subscriber Code: Verifying the JWT](#subscriber-code-verifying-the-jwt)
- [Phase 2: Man-in-the-Middle (MITM) Attack Simulation](#phase-2-man-in-the-middle-mitm-attack-simulation)
  - [Attacker Code: Tampering with the JWT](#attacker-code-tampering-with-the-jwt)
  - [How the Subscriber Detects Tampering](#how-the-subscriber-detects-tampering)
- [Additional Notes on JWT Expiration](#additional-notes-on-jwt-expiration)
- [Usage Instructions](#usage-instructions)
- [Conclusion](#conclusion)

---

## Introduction

**Authentication** is the process of verifying that someone is who they claim to be, while **authorization** ensures that an authenticated individual has permission to perform certain actions or access specific resources. In distributed systems and modern web applications, JSON Web Tokens (JWTs) are a common tool for implementing both authentication and authorization. 

JWTs work by encapsulating data in a token that is signed using a shared secret (or private/public key pair). This token contains three parts:
- **Header:** Identifies the token type (JWT) and the signing algorithm (e.g., HS256).
- **Payload:** Contains the claims (e.g., user data, permissions) in a Base64-encoded JSON format.
- **Signature:** A cryptographic signature computed over the header and payload using a secret key, which allows the recipient to verify the token's integrity.

When combined with MQTT—a lightweight messaging protocol for small sensors and mobile devices—JWT can secure and verify data exchanged between publishers and subscribers.

---

## Purpose of This Tutorial

This tutorial demonstrates how to integrate JWT with MQTT for secure and trusted data exchange. You will learn how:

- The **publisher** creates a JWT to secure a message.
- The **subscriber** verifies the JWT to ensure the message has not been tampered with.
- To simulate a man-in-the-middle (MITM) attack where an attacker intercepts, modifies, and repackages the message, and how the JWT verification process can detect such tampering.

The tutorial is divided into two phases:

1. **Phase 1:** Normal operation where the publisher sends a message, and the subscriber successfully verifies the JWT.
2. **Phase 2:** A simulated MITM attack where an attacker alters the JWT, and the subscriber detects the tampering.

---

## Pre-requisites

Before running the project, ensure you have the following installed on your Windows machine:

- **Python** (version 3.13 recommended)  
- **Docker Desktop** (for running the Mosquitto broker container)
- **pip** (for Python packages)
- **Required Python Libraries:**
  - `paho-mqtt` (install with a specific version constraint to avoid newer changes):
    - Open Command Prompt and run:
      ```cmd
      py -m pip install "paho-mqtt<2.0.0"
      ```
      (If you encounter "The system cannot find the file specified", ensure pip is on your PATH or use the py launcher.)
  - `PyJWT` (for handling JWT encoding and decoding):
    - Run:
      ```cmd
      py -m pip install PyJWT
      ```

---

## Project Structure

A suggested project structure for this tutorial is as follows:

```
Demo_JWT_MQTT/
│
├── docker-compose.yml            # Docker Compose file to run Mosquitto
├── mosquitto/
│   ├── config/
│   │   ├── mosquitto.conf        # Custom configuration file for Mosquitto
│   │   └── passwd                # Password file for user authentication
│   ├── data/                     # Mosquitto persistent data folder (empty initially)
│   └── log/                      # Mosquitto log folder (empty initially)
├── publisher.py                  # Python script to create and send the JWT secured message
├── subscriber.py                 # Python script to receive and verify the JWT
├── man_in_the_middle.py          # Python script to simulate the MITM attack
└── README.md                     # This file
```

---

## Configuration & Setup

### Mosquitto Broker Setup with Docker

We assume that the Mosquitto broker is running as a Docker container. Below is an example `docker-compose.yml` file:

```yaml
version: '3'
services:
  mosquitto:
    image: eclipse-mosquitto
    container_name: mosquitto_broker
    ports:
      - "1883:1883"   # MQTT port
      - "9001:9001"   # WebSockets port (if needed)
    volumes:
      - ./mosquitto/config:/mosquitto/config
      - ./mosquitto/data:/mosquitto/data
      - ./mosquitto/log:/mosquitto/log
```

This file mounts the entire `config` folder so that both `mosquitto.conf` and the `passwd` file are available to the container.

### Creating the Password File

Since Mosquitto is running in Docker, we can generate the password file using the container’s utilities. Follow these steps:

1. **Open a Command Prompt in your project directory.**
2. **Run the Following Docker Command:**

   ```cmd
   docker run --rm -v "%cd%/mosquitto/config":/mosquitto/config eclipse-mosquitto mosquitto_passwd -c /mosquitto/config/passwd testuser
   ```

   **Explanation:**
   - `docker run --rm`: Runs a temporary container that is removed once the command completes.
   - `-v "%cd%/mosquitto/config":/mosquitto/config`: Mounts your local `mosquitto/config` directory into the container.
   - `eclipse-mosquitto`: Uses the official Mosquitto image.
   - `mosquitto_passwd -c /mosquitto/config/passwd testuser`: Creates a new password file for the user `testuser`. You will be prompted to enter a password (e.g., **testpass**).

3. **Verify the Password File:**
   - Check in your local directory (e.g., `./mosquitto/config/passwd`) that the file is created.

---

## Phase 1: Normal Operation (Untampered Data)

In Phase 1, we demonstrate a scenario where the publisher creates a JWT-protected message and sends it to the subscriber via the Mosquitto broker. The subscriber verifies the JWT and processes the data if everything is correct.

### Publisher Code: Creating and Sending JWT

- The **publisher**:
  - Prepares a payload (e.g., including a message and a timestamp).
  - Uses the PyJWT library to generate a JWT by encoding the payload with a secret key.
  - Embeds the JWT in a JSON message and publishes it to a topic (e.g., `demo/jwt`).

**Example Snippet:**

```python
import time
import json
import jwt  # PyJWT library
import paho.mqtt.client as mqtt

JWT_SECRET = "your_very_secret_key"
JWT_ALGORITHM = "HS256"
BROKER = "localhost"
PORT = 1883
USERNAME = "testuser"
PASSWORD = "testpass"
TOPIC = "demo/jwt"

def create_jwt(payload):
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

payload_data = {
    "message": "Hello from MQTT with JWT!",
    "timestamp": int(time.time())
}

token = create_jwt(payload_data)
mqtt_payload = {
    "jwt": token,
    "additional_info": "This message is secured by JWT."
}

client = mqtt.Client(protocol=mqtt.MQTTv311)
client.username_pw_set(USERNAME, PASSWORD)
client.connect(BROKER, PORT)
client.publish(TOPIC, json.dumps(mqtt_payload))
print("Published message:", mqtt_payload)
client.disconnect()
```

### Subscriber Code: Verifying the JWT

- The **subscriber**:
  - Subscribes to the topic.
  - When a message is received, it extracts the JWT from the JSON message.
  - It calls `jwt.decode()` to verify the token using the shared secret.
  - If verification is successful, the message is accepted; if not, it is rejected.

**Example Snippet:**

```python
import json
import jwt  # PyJWT library
import paho.mqtt.client as mqtt

JWT_SECRET = "your_very_secret_key"
JWT_ALGORITHM = "HS256"
BROKER = "localhost"
PORT = 1883
USERNAME = "testuser"
PASSWORD = "testpass"
TOPIC = "demo/jwt"

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Subscriber connected!")
        client.subscribe(TOPIC)
    else:
        print("Connection failed, code:", rc)

def on_message(client, userdata, msg):
    try:
        message = json.loads(msg.payload.decode())
        token = message.get("jwt")
        if token:
            decoded_payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            print("JWT verified successfully. Data:", decoded_payload)
        else:
            print("No JWT in the message.")
    except jwt.InvalidTokenError as e:
        print("JWT verification failed:", e)

client = mqtt.Client(protocol=mqtt.MQTTv311)
client.username_pw_set(USERNAME, PASSWORD)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT)
client.loop_forever()
```

*When everything works correctly in Phase 1, the subscriber receives the message, verifies the JWT, and displays the data.*

---

## Phase 2: MITM Attack Simulation

In Phase 2, we simulate a man-in-the-middle (MITM) attack where an attacker intercepts the message, alters the JWT to create a new token (or remove it), and repackages the message. This scenario demonstrates that when the subscriber attempts to verify the tampered JWT, the verification fails, indicating that the data has been altered.

### Attacker Code: Tampering with the JWT

- The **attacker** script acts as an intermediary:
  - It subscribes to the original topic (`demo/jwt`).
  - On receiving a message, it extracts the JWT and modifies it (e.g., changing one character in the token).
  - It republishes the modified message to a different topic (`demo/jwt_attacked`).

**Example Snippet:**

```python
import json
import paho.mqtt.client as mqtt

BROKER = "localhost"
PORT = 1883
USERNAME = "testuser"
PASSWORD = "testpass"
INPUT_TOPIC = "demo/jwt"
OUTPUT_TOPIC = "demo/jwt_attacked"

def tamper_jwt(token):
    if not token or len(token) < 1:
        return token
    new_last = 'X' if token[-1] != 'X' else 'Y'
    return token[:-1] + new_last

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("MITM attacker connected!")
        client.subscribe(INPUT_TOPIC)
    else:
        print("Connection failed:", rc)

def on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())
    except Exception as e:
        print("Error parsing message:", e)
        return
    original_token = data.get("jwt")
    if original_token:
        tampered_token = tamper_jwt(original_token)
        print("Original JWT:", original_token)
        print("Tampered JWT:", tampered_token)
        data["jwt"] = tampered_token
    new_payload = json.dumps(data)
    client.publish(OUTPUT_TOPIC, new_payload)
    print("Republished tampered message to", OUTPUT_TOPIC)

client = mqtt.Client("MITMAttacker", protocol=mqtt.MQTTv311)
client.username_pw_set(USERNAME, PASSWORD)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, PORT)
client.loop_forever()
```

### How the Subscriber Detects Tampering

The subscriber (if modified to listen to the `demo/jwt_attacked` topic) will try to verify the JWT from the tampered message:

1. **Extraction:**  
   The subscriber extracts the JWT field from the received message.
2. **Recalculation:**  
   It uses the shared secret to recalculate the signature on the header and payload of the JWT.
3. **Verification Failure:**  
   Because the attacker altered the token (e.g., by changing the last character), the signature does not match.  
   This leads to a verification error, informing the subscriber that the message has been tampered with.

---

## Additional Notes on JWT Expiration

While this tutorial focuses on verifying data integrity through JWT, you may optionally include an expiration claim (`"exp"`) in your payload to limit the token’s lifetime. However, for transient MQTT messages that are processed immediately, adding an expiration time may be optional.

---

## Usage Instructions

1. **Set Up Mosquitto Broker:**
   - Ensure your Docker environment is running.
   - Execute `docker-compose up` in the project directory to start the Mosquitto container.
   - Generate the password file using the provided Docker command.

2. **Run Phase 1 (Normal Operation):**
   - Open one terminal and run the subscriber:
     ```cmd
     py subscriber.py
     ```
   - Open another terminal and run the publisher:
     ```cmd
     py publisher.py
     ```
   - Confirm that the subscriber verifies the JWT and displays the data.

3. **Run Phase 2 (MITM Attack Simulation):**
   - Open one terminal and start the attacker script:
     ```cmd
     py man_in_the_middle.py
     ```
   - Modify your subscriber to subscribe to the `demo/jwt_attacked` topic and run it.
   - Run the publisher as in Phase 1.
   - Observe that the attacker intercepts and modifies the JWT, and the subscriber’s JWT verification fails, indicating tampered data.

---

## Conclusion

This project demonstrates a practical approach to enhancing MQTT communications with JWT for data integrity and secure authorization. It covers:

- How JWTs are created and used by the publisher.
- How the subscriber verifies JWTs to ensure the data has not been altered.
- A simulated MITM attack showing that any modification—whether removing or creating a new JWT without the secret—results in verification failure.

By following this tutorial, you can deploy a secure MQTT system on GitHub that not only shows normal operation but also highlights the importance of protecting JWT signing secrets to prevent tampering.

Feel free to fork this project, modify it, or use it as a reference for your own secure messaging implementations!

---

*End of README*
```

---

Feel free to copy, modify, and expand upon this README as necessary for your GitHub repository. Let me know if you need additional details or further adjustments!
