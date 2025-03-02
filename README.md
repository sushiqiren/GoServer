# GoServer

GoServer is a web application built with Go that provides various endpoints for managing users and chirps. It includes features such as user authentication, chirp creation, retrieval, and deletion, as well as handling webhooks from Polka.

## Table of Contents

- [Installation](#installation)
- [Configuration](#configuration)
- [Endpoints](#endpoints)
  - [Health Check](#health-check)
  - [Hits](#hits)
  - [Reset](#reset)
  - [Metrics](#metrics)
  - [Chirps](#chirps)
  - [Users](#users)
  - [Login](#login)
  - [Refresh](#refresh)
  - [Revoke](#revoke)
  - [Polka Webhooks](#polka-webhooks)
- [License](#license)

## Installation

1. Clone the repository:

   ```sh
   git clone https://github.com/yourusername/GoServer.git
   cd GoServer
   ```

2. Install dependencies:

    ```sh
    go mod tidy
    ```

3. Build application:

    ```sh
    go build -o GoServer
    ```

4. Run application

    ```sh
    ./GoServer
    ```

## Configuration

Create a .env file in the root directory with the following environment variables:

DB_URL=your_database_url
JWT_SECRET=your_jwt_secret
POLKA_KEY=your_polka_key
PLATFORM=dev

## Endpoints

### Health Check

```sh
GET /api/healthz
```
Returns a 200 status code if the server is running.

### Hits

```sh
GET /api/hits
```
Returns the number of times the file server has been accessed.

### Reset

```sh
POST /admin/reset
```
Deletes all users and resets the hits counter. Only available in the dev environment.

### Metrics

```sh
GET /admin/metrics
```
Returns an HTML page with the number of times the file server has been accessed.

### Chirps
```sh
POST /api/chirps
```
Creates a new chirp. Requires a valid JWT token.
Request body:
```json
{
  "body": "Your chirp message"
}
```

```sh
GET /api/chirps
```
Retrieves all chirps or chirps by a specific author. Supports optional query parameters author_id and sort.
Query parameters:
author_id: UUID of the author.
sort: Sorting order (asc or desc). Default is asc.

```sh
GET /api/chirps/{id}
```
Retrieves a chirp by its ID.

```sh
DELETE /api/chirps/{id}
```
Deletes a chirp by its ID. Requires a valid JWT token and the user must be the author of the chirp.

### Users

```sh
POST /api/users
```
Creates a new user.
Request body:
```json
{
  "email": "user@example.com",
  "password": "your_password"
}
```

```sh
PUT /api/users
```
Updates the user's email and password. Requires a valid JWT token.
Request body:
```json
{
  "email": "new_email@example.com",
  "password": "new_password"
}
```

### Login

```sh
POST /api/login
```
Authenticates a user and returns a JWT token and refresh token.
Request body:
```json
{
  "email": "user@example.com",
  "password": "your_password"
}
```

### Refresh

```sh
POST /api/refresh
```
Refreshes the JWT token using a valid refresh token.
Requires a valid refresh token in the Authorization header.

### Revoke

```sh
POST /api/revoke
```
Revokes the refresh token.
Requires a valid refresh token in the Authorization header.

### Polka Webhooks

```sh
POST /api/polka/webhooks
```
Handles webhooks from Polka. Validates the API key and processes the user.upgraded event.
Request body:
```json
{
  "event": "user.upgraded",
  "data": {
    "user_id": "user_uuid"
  }
}
```

## License
This project is licensed under the MIT License.
