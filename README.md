# Auth Service

## Overview

This microservice handles authentication and authorization for the project.

### Key Concepts

- **Authentication:** The process of verifying the identity of a user. This can involve entering a username and password, receiving an SMS code, using a fingerprint, etc.
- **Authorization:** The process of granting or restricting access based on the user's identity. Different roles (e.g., admin, user) have different permissions. For example, only admins should have access to the admin panel, and a user may have access only to projects they are involved in.

### Implementation

Our service follows the OAuth 2.0 standard for authentication and authorization. Users are issued two JWT tokens upon login: an access token and a refresh token.

#### JWT Structure

A JWT token is a string consisting of three parts, separated by dots: `xxxxx.yyyyy.zzzzz`.

- `xxxxx`: Contains information about the token type and encryption algorithm.
- `yyyyy`: Contains the payload, such as username, user ID, role, permissions, and expiration date for the access token. The refresh token contains only the user ID and expiration date.
- `zzzzz`: A signature that ensures the token's integrity. If the payload is tampered with, the signature will no longer match, thus invalidating the token.

### Token Usage

- **Access Token:** Used for validating user permissions and access to resources. It has a short lifespan (minutes or tens of minutes) to minimize the impact if stolen.
- **Refresh Token:** Used to obtain a new access token when the current one expires. It has a longer lifespan and can be revoked to terminate sessions.

## API Endpoints

### `/create`
- **Description:** Create a new user account.
- **Request Body:**
  - `username` (string)
  - `email` (string)
  - `password` (string, repeated for confirmation)
- **Response:** User creation status.

### `/token`
- **Description:** Login with username and password.
- **Request Body:**
  - `username` (string)
  - `password` (string)
- **Response:** Pair of access token and refresh token.

### `/refresh`
- **Description:** Refresh the access token using the refresh token.
- **Request Body:**
  - `refresh_token` (string)
- **Response:** New access token.

### `/logout`
- **Description:** End the current session and revoke the refresh token.
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response:** Logout status.

### `/revoke`
- **Description:** Revoke a specific session by its ID.
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Request Body:**
  - `session_id` (string)
- **Response:** Session revocation status.

### `/my_sessions`
- **Description:** Get a list of active sessions.
- **Headers:**
  - `Authorization: Bearer <access_token>`
- **Response:** List of sessions.

## Session Management

Sessions are stored in the database, including the refresh token. Users can log in from multiple devices, creating multiple sessions.

## Documentation

API documentation can be found at `/docs` on the service's running instance. Example URL: `62.109.17.249:1337/docs`.

## Security

The service uses JWT tokens with RSA encryption. The private key signs the tokens, and the public key can be used to verify the token's authenticity.

## Setup

1. Clone the repository.
2. Create and activate a virtual environment.
3. Install dependencies.
4. Configure environment variables.
5. Run the service.

### Step-by-Step Setup

```sh
# Clone the repository
git clone <repository_url>
cd <repository_directory>

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows
venv\Scripts\activate

# On Unix or MacOS
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set environment variables

# Run the service
uvicorn main:app --reload