# VIP Auth Hub – FIDO API Payload Reference

All calls require an `Authorization: Bearer <access_token>` header.
Calls after step 1 also require `X-Flow-State: <flowState>` (the token
returned by the previous step — it advances with each call).

---

## Step 0 – Obtain an access token

Every flow starts here. Use your privileged client credentials.

### Request
```
POST /oauth2/v1/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>

grant_type=client_credentials&scope=urn:iam:myscopes
```

### Response
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "urn:iam:myscopes"
}
```

---

## Step 1 – Initiate an authentication flow

Starts a stateful flow for the user. Returns the first `flowState` token.

### Request
```
POST /auth/v1/authenticate
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "channel": "web",
  "subject": "your-user-name",
  "action": "authenticate",
  "ipAddress": "192.168.1.50",
  "acrValues": []
}
```

### Response
```json
{
  "flowState": "FS_abc123...",
  "nextaction": "FACTOR_SELECTION",
  "availableFactors": ["FIDO", "PASSWORD", "TOTP"]
}
```

---

## Step 2 – Select FIDO as the factor

### Request
```
POST /auth/v1/SelectedFactor
Authorization: Bearer <access_token>
X-Flow-State: FS_abc123...
Content-Type: application/json

{
  "factor": "FIDO"
}
```

### Response A – user has NO existing FIDO credential (→ registration path)
```json
{
  "flowState": "FS_def456...",
  "nextaction": "PASSWORD_AUTH",
  "inline_registration": true,
  "message": "No FIDO credential found. Complete password auth to register."
}
```

### Response B – user HAS an existing FIDO credential (→ authentication path)
```json
{
  "flowState": "FS_def456...",
  "nextaction": "FIDO_AUTH_GENERATE_CHALLENGE"
}
```

---

# REGISTRATION FLOW
## (used when user has no FIDO credential yet)

---

## Reg Step 3 – Authenticate with password (only needed for first registration)

Required because the user has no FIDO key yet, so VIP Auth Hub needs another
proof of identity before it will issue a registration challenge.

### Request
```
POST /factor/v1/PasswordAuthenticator
Authorization: Bearer <access_token>
X-Flow-State: FS_def456...
Content-Type: application/json

{
  "password": "your_password"
}
```

### Response
```json
{
  "flowState": "FS_ghi789...",
  "nextaction": "FIDO_REGISTER_GENERATE_CHALLENGE"
}
```

---

## Reg Step 4 – Generate a registration challenge

Server returns the WebAuthn `PublicKeyCredentialCreationOptions`.

`documentDomain` must be a registrable domain suffix of the browser's origin.
Example: browser at `https://fido-test.demo-broadcom.com:3000`
→ valid domain: `demo-broadcom.com`

`deviceName` must be unique per user — use a timestamp suffix to avoid conflicts.

### Request
```
POST /factor/v1/FIDORegChallengeGenerator
Authorization: Bearer <access_token>
X-Flow-State: FS_ghi789...
Content-Type: application/json

{
  "documentDomain": "https://demo-broadcom.com",
  "userName": "your-user-name",
  "deviceName": "poc-1745123456"
}
```

### Response
The `data` field is passed directly to `navigator.credentials.create()` in the browser
(after converting `challenge` and `user.id` from base64url to ArrayBuffer).

```json
{
  "flowState": "FS_jkl012...",
  "nextaction": "FIDO_REGISTER_VERIFY_CHALLENGE",
  "data": {
    "challenge": "Y2hhbGxlbmdlX3JhbmRvbV9ieXRlcw",
    "rp": {
      "id": "demo-broadcom.com",
      "name": "VIP Auth Hub"
    },
    "user": {
      "id": "ODE0NTlkZmMtMDJkZS00NDNiLWIyZjAtN2RkZTYxZjdmYjky",
      "name": "your-user-name",
      "displayName": "your-user-name"
    },
    "pubKeyCredParams": [
      { "type": "public-key", "alg": -7  },
      { "type": "public-key", "alg": -257 }
    ],
    "timeout": 120000,
    "attestation": "none",
    "authenticatorSelection": {
      "authenticatorAttachment": "platform",
      "userVerification": "required",
      "residentKey": "preferred"
    },
    "excludeCredentials": []
  }
}
```

---

## Reg Step 5 – Browser creates the credential

This step happens entirely in the browser via the WebAuthn API.
The server is not called here.

```javascript
// challenge and user.id must be decoded from base64url → ArrayBuffer first
const credential = await navigator.credentials.create({ publicKey: createOptions });

// credential.response contains:
//   attestationObject  (ArrayBuffer) – the new public key + device attestation
//   clientDataJSON     (ArrayBuffer) – the challenge signed by the device
```

---

## Reg Step 6 – Verify the registration (send attestation to server)

The browser's response is encoded back to base64url and forwarded to VIP Auth Hub.

**Important:** `getTransports` must be sent as `{}` (empty object).
The browser API returns an array `["internal"]` — VIP Auth Hub rejects arrays here.

### Request
```
POST /factor/v1/FIDORegChallengeVerifier
Authorization: Bearer <access_token>
X-Flow-State: FS_jkl012...
Content-Type: application/json

{
  "id":    "AYqGnFy7kZ3...",
  "rawId": "AYqGnFy7kZ3...",
  "type":  "public-key",
  "response": {
    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10...",
    "clientDataJSON":    "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhb...",
    "getTransports": {}
  },
  "getClientExtensionResults": {}
}
```

### Response – success
```json
{
  "flowState": "FS_mno345...",
  "nextaction": "AUTH_ALLOWED",
  "data": {
    "credentialId": "AYqGnFy7kZ3...",
    "userId": "81359dfc-02de-443b-b2f0-7dde61f7fb92"
  }
}
```

### Response – failure
```json
{
  "flowState": "FS_mno345...",
  "nextaction": "FAILED",
  "data": {
    "errorCode": "3001036",
    "errorMessage": "Invalid request"
  }
}
```

---
---

# AUTHENTICATION FLOW  (Path A – direct)
## (used when user already has a FIDO credential registered under the matching domain)

---

## Auth Step 3 – Generate an authentication challenge

Picks up from Step 2 Response B (`nextaction: FIDO_AUTH_GENERATE_CHALLENGE`).

### Request
```
POST /factor/v1/FIDOAuthChallengeGenerator
Authorization: Bearer <access_token>
X-Flow-State: FS_def456...
Content-Type: application/json

{
  "documentDomain": "https://demo-broadcom.com",
  "userName": "your-user-name"
}
```

### Response
The `data` field is passed to `navigator.credentials.get()` in the browser.

```json
{
  "flowState": "FS_pqr678...",
  "nextaction": "FIDO_AUTH_VERIFY_CHALLENGE",
  "data": {
    "challenge": "cmFuZG9tX2F1dGhfY2hhbGxlbmdl",
    "rpId": "demo-broadcom.com",
    "timeout": 120000,
    "userVerification": "required",
    "allowCredentials": [
      {
        "type": "public-key",
        "id": "AYqGnFy7kZ3...",
        "transports": ["internal"]
      }
    ]
  }
}
```

---

## Auth Step 4 – Browser signs the challenge (assertion)

```javascript
const credential = await navigator.credentials.get({ publicKey: getOptions });

// credential.response contains:
//   authenticatorData  (ArrayBuffer) – device metadata + RP ID hash
//   clientDataJSON     (ArrayBuffer) – the challenge + origin
//   signature          (ArrayBuffer) – the private key signature over the above
//   userHandle         (ArrayBuffer or null) – the user ID if stored on device
```

---

## Auth Step 5 – Verify the assertion

### Request
```
POST /factor/v1/FIDOAuthChallengeVerifier
Authorization: Bearer <access_token>
X-Flow-State: FS_pqr678...
Content-Type: application/json

{
  "id":    "AYqGnFy7kZ3...",
  "rawId": "AYqGnFy7kZ3...",
  "type":  "public-key",
  "response": {
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAABA",
    "clientDataJSON":    "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiY21G...",
    "signature":         "MEYCIQDhMJqTGr7bXKFJvqSHHe8p...",
    "userHandle":        "ODE0NTlkZmMtMDJkZS00NDNiLWIyZjAtN2RkZTYxZjdmYjky"
  },
  "getClientExtensionResults": {}
}
```

### Response – success
```json
{
  "flowState": "FS_stu901...",
  "nextaction": "AUTH_ALLOWED",
  "data": {
    "userId": "81359dfc-02de-443b-b2f0-7dde61f7fb92",
    "subject": "your-user-name"
  }
}
```

---
---

# ADMIN ENDPOINTS

---

## List credentials for a user

```
GET /admin/v1/Creds/{userId}
Authorization: Bearer <access_token>
user-id: SYSTEM
```

### Response
```json
[
  {
    "credId": "cred-uuid-here",
    "credType": "fido",
    "domain": "demo-broadcom.com",
    "deviceName": "poc-1745123456",
    "createdDatetime": "2026-04-21T01:18:00Z",
    "userId": "81359dfc-02de-443b-b2f0-7dde61f7fb92"
  },
  {
    "credId": "cred-uuid-2",
    "credType": "password",
    ...
  }
]
```

---

## Delete a specific credential

```
DELETE /admin/v1/Creds/{userId}/{credId}
Authorization: Bearer <access_token>
user-id: SYSTEM
```

### Response
```
HTTP 204 No Content
```

---

# Key facts to remember when talking to customers

| Concept | Plain English |
|---|---|
| `flowState` | A session token — must be passed back with every call; it advances as the flow progresses |
| `documentDomain` | The domain the credential will be bound to; must be a suffix of the browser's URL (e.g. browser at `fido-test.demo-broadcom.com` → domain `demo-broadcom.com`) |
| `rpId` | Relying Party ID — the server derives this from `documentDomain`; the browser uses it to find matching credentials |
| `challenge` | A random nonce the server issues once; signing it proves the device is present right now (prevents replay attacks) |
| `attestationObject` | Proof that a real authenticator created the key pair (for registration) |
| `authenticatorData` | Proof the correct device was used (for authentication) |
| `getTransports: {}` | VIP Auth Hub quirk — must be an empty object, not the array the browser returns |
| `AUTH_ALLOWED` | The flow is complete — the user is authenticated |
