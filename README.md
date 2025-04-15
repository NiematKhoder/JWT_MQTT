
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
  - [Publisher: Creating and Sending JWT](#publisher-creating-and-sending-jwt)
  - [Subscriber: Verifying the JWT](#subscriber-verifying-the-jwt)
- [Phase 2: MITM Attack Simulation](#phase-2-mitm-attack-simulation)
  - [Attacker: Tampering with the JWT](#attacker-tampering-with-the-jwt)
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
├── attacker.py          # Python script to simulate the MITM attack
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

**In the publisher, the JWT is created with the following function:**

```python
def create_jwt(payload):
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
```

**Explanation of Each Component:**

- **`payload`:**  
  This is a Python dictionary containing the data or claims you wish to transmit. For example, it might include a message, a timestamp, or other metadata relevant to the message.

- **`JWT_SECRET`:**  
  This is a secret key (a string) that both the publisher and the subscriber share. It is used to sign the JWT. The security of the JWT signature depends on the secrecy of this key. If an attacker doesn't have this key, they cannot create a valid signature.

- **`algorithm=JWT_ALGORITHM`:**  
  This parameter specifies the signing algorithm (e.g., `"HS256"` for HMAC using SHA-256). The algorithm determines how the header and payload are hashed and combined with the secret to generate the signature. Both the publisher and subscriber must use the same algorithm for the JWT verification to succeed.

- **`jwt.encode(...)`:**  
  This function takes the payload, the secret key, and the algorithm as inputs and outputs the JWT as a compact string in the format `header.payload.signature`, where each part is Base64 URL-safe encoded.

---

### Subscriber: Verifying the JWT
- The **subscriber**:
  - Subscribes to the topic.
  - When a message is received, it extracts the JWT from the JSON message.
  - It calls `jwt.decode()` to verify the token using the shared secret.
  - If verification is successful, the message is accepted; if not, it is rejected.

**In the subscriber, the verification and decoding of the JWT is done with this code snippet:**

```python
if token:
    decoded_payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    print("JWT verified successfully. Data:", decoded_payload)
```

**Explanation of Each Component:**

- **`if token:`**  
  This checks if the received message contains a JWT. If the token is present, the code proceeds with verification.

- **`jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])`:**  
  - **`token`:**  
    The JWT received in the message.
  - **`JWT_SECRET`:**  
    The same secret key used in the publisher. The subscriber uses this key to verify the token’s signature.
  - **`algorithms=[JWT_ALGORITHM]`:**  
    This parameter tells the `jwt.decode` function which algorithm(s) to expect. It verifies that the token's signature was generated using one of these algorithms. Both sides must use the same algorithm (for example, `"HS256"`) for successful verification.
  - **Result:**  
    If the signature matches, the function returns the decoded payload (the original claims/data). If the token was tampered with or invalid, a `jwt.InvalidTokenError` is raised, indicating verification failure.

---

### How to Run the Project

1. **Pull the Repository:**  
   Clone or pull the repository to your local machine so you have access to the source code.

2. **Navigate to the Project Directory:**

   ```cmd
   cd path\to\Demo_JWT_MQTT
   ```

3. **Run the Subscriber:**

   ```cmd
   py subscriber.py
   ```

4. **Run the Publisher:**

   In another terminal window (or after stopping the subscriber if needed), run:

   ```cmd
   py publisher.py
   ```

These steps will start the publisher and subscriber, demonstrating how a JWT is created, embedded in a message, and later verified by the subscriber to ensure the data has not been tampered with.

---

## Phase 2: MITM Attack Simulation

In Phase 2, we simulate a man-in-the-middle (MITM) attack where an attacker intercepts the message, alters the JWT to create a new token (or remove it), and repackages the message. This scenario demonstrates that when the subscriber attempts to verify the tampered JWT, the verification fails, indicating that the data has been altered.

### Attacker Code: Tampering with the JWT
In this phase, we simulate an attack scenario where an attacker intercepts the published message, modifies the JWT token, and repackages the message. When the subscriber, expecting a valid JWT, attempts to verify the tampered token, the verification fails—indicating that the data has been altered.  

- The **attacker** script acts as an intermediary:
  - It subscribes to the original topic (`demo/jwt`).
  - On receiving a message, it extracts the JWT and modifies it (e.g., changing one character in the token).
  - It republishes the modified message to a different topic (`demo/jwt_attacked`).

### Attacker Code: Tampering with the JWT

The attacker script acts as an intermediary. One of the key functions in this script is for tampering with the JWT. In our repository, we have the following function:

```python
def tamper_jwt(token):
    if not token or len(token) < 1:
        return token
    new_last = 'X' if token[-1] != 'X' else 'Y'
    return token[:-1] + new_last
```

**Explanation:**

- **Check for a Valid Token:**  
  The function starts by checking if the provided token is empty or too short. If it is, the function returns the token unchanged.

- **Modify the Token:**  
  The core tampering occurs by changing the last character of the token:
  - It determines a new character (`'X'` or `'Y'`) depending on what the original last character is.
  - By replacing the last character, it specifically alters the **signature** part of the JWT (since the token format is `header.payload.signature` and the signature is at the end).
  
- **Result:**  
  Even a small change like this means that when the subscriber recalculates the expected signature using the header and payload along with the shared secret, the resulting signature will no longer match the tampered token’s signature. As a result, JWT verification fails.

---

### How to Run the MITM Attack Simulation

Follow these steps to run this phase:

1. **Prepare the Subscriber:**  
   Open the `subscriber.py` script in your favorite editor.  
   **Modify the Topic:**
   - **Comment out line 14** where the subscriber is set to listen to the original topic:  
     ```python
     # TOPIC = "demo/jwt"
     ```
   - **Uncomment line 15** so the subscriber listens to the attacked topic:  
     ```python
     TOPIC = "demo/jwt_attacked"
     ```
   This configuration ensures that the subscriber will now receive messages republished by the attacker.

2. **Run the Subscriber:**
   Open a terminal, navigate to the project directory, and run:
   ```cmd
   py subscriber.py
   ```

3. **Run the Attacker:**
   In a new terminal, run the attacker script:
   ```cmd
   py attacker.py
   ```
   (Make sure that your repository contains the attacker script; it may be named something like `man_in_the_middle.py` or `attacker.py`.)

4. **Run the Publisher:**
   In another terminal, run the publisher script:
   ```cmd
   py publisher.py
   ```

---

### What Exactly Happens During the MITM Simulation

- **Publisher:**  
  The publisher creates a JWT-embedded JSON message (which includes the claims, the header, and the valid signature) and publishes it on the original topic `demo/jwt`.

- **Attacker:**  
  The attacker subscribes to `demo/jwt` (the original topic). Once a message is received:
  - The attacker extracts the JWT from the message.
  - The function `tamper_jwt()` is called, which slightly modifies the token by changing its last character.
  - The attacker then repackages the message—with the tampered JWT—and publishes it to the new topic `demo/jwt_attacked`.

- **Subscriber:**  
  The subscriber, now listening on `demo/jwt_attacked`, receives the tampered message. When it attempts to verify the JWT:
  - It decodes the token and re-calculates the expected signature using the header, payload, and the shared secret.
  - Because the attacker’s tampering altered the token’s signature (by modifying its last character), the recalculated signature does not match the tampered signature in the token.
  - Thus, the verification fails. The subscriber can then log or reject the message, which shows that the data has been altered in transit.

This simulation clearly demonstrates that even a minimal change to the JWT causes the signature verification to fail, ensuring that any tampering by an attacker is detected by the subscriber.

---

## Additional Notes on JWT Expiration

### 1. How the Subscriber Detects a Tampered Signature

- **No Memory of the Original Signature Needed:**  
  The subscriber doesn't store the "original signature" separately. Instead, it recalculates the signature on its own.

- **Recalculation Process:**  
  When the subscriber receives a JWT, it splits the token into its three parts: the header, the payload, and the signature.  
  Using the header and payload, along with the pre-shared secret key and the same cryptographic algorithm (for example, HS256), the subscriber recomputes what the signature should be.

- **Signature Comparison:**  
  The subscriber then compares the recomputed signature with the signature that came with the JWT.  
  - **If They Match:** This means the data (header and payload) has not been changed.  
  - **If They Don’t Match:** Any tampering—even a small change in the header or payload—will cause the recomputed signature to differ from the one attached to the token. This difference lets the subscriber know that the message has been altered in transit.

In summary, as long as both sides share the secret key and use the same algorithm, the subscriber can independently verify the integrity of the token without needing to store the original signature.

---

### 2. JWT: Not for Encryption, But for Integrity and (Often) Authorization

- **Not Primarily for Encryption:**  
  JWTs are **not** designed to encrypt the payload. They are usually encoded using Base64URL encoding—which means anyone who intercepts the token can decode it and view the contents.

- **Purpose of JWTs:**  
  - **Integrity and Authenticity:** The signature in a JWT ensures that the payload has not been tampered with since it was signed.  
  - **Authorization and Authentication:** JWTs are commonly used to prove that a client is authorized or authenticated, for example, as part of an OAuth flow.
  
- **Readable Payload:**  
  Because the payload is merely Base64 encoded and not encrypted, anyone who obtains the JWT can read the payload. If you need to hide the contents (for confidentiality), you must use encryption (for example, with JSON Web Encryption (JWE)), or use another layer such as TLS/SSL (HTTPS, secure MQTT connections) to secure the data in transit.

---

### 3.What Is the Expiration Time (exp Claim)?

- **Definition:**  
  The "exp" claim in a JWT specifies the time (as a Unix timestamp) after which the token should no longer be considered valid.

- **Purpose:**  
  - **Mitigates Replay Attacks:**  
    It limits the window in which an intercepted token can be reused by an attacker. Once expired, the token is rejected even if it hasn’t been tampered with.
  - **Improves Security:**  
    By enforcing token lifetimes, it helps ensure that if a token is compromised, its usability is limited to a short period.
  - **Session Management:**  
    In web applications, it ensures that sessions end after a given period, requiring a new token to be issued.

#### Is Expiration Necessary in Our MQTT Scenario?

In our current JWT-with-MQTT demo:

1. **Primary Focus – Integrity and Authorization:**  
   - We use JWTs mainly to verify that the data (payload) hasn’t been altered in transit.
   - The main goal is to detect tampering via signature verification rather than managing long-lived user sessions.

2. **Short-Lived Messages:**  
   - MQTT messages are typically transient; once they are published and delivered, they do not necessarily persist for long.
   - If the messages are processed immediately (or within a short time window), a token’s expiration might not be critical for integrity purposes.

3. **Additional Security – Replay Protection:**  
   - **Optional Usage:**  
     While the "exp" claim isn’t strictly needed for ensuring message integrity, adding an expiration time can prevent replay attacks. For example, if an attacker were to capture and resend a message later, an expired token would be recognized as invalid.
   - **Depends on the Use Case:**  
     - **If your MQTT system uses tokens for authentication/authorization that might be reused over a long period, then adding "exp" is a good idea.**
     - **If every published message is unique and processed immediately, it might be less critical.**

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

