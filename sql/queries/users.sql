-- name: CreateUserWithID :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1
)
RETURNING *;

-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password, is_chirpy_red)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2,
    FALSE
)
RETURNING id, created_at, updated_at, email, hashed_password, is_chirpy_red;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT id, created_at, updated_at, email, hashed_password, is_chirpy_red
FROM users
WHERE email = $1;

-- name: GetUserByID :one
SELECT id, created_at, updated_at, email, is_chirpy_red
FROM users
WHERE id = $1;

-- name: UpdateUser :exec
UPDATE users
SET email = $2, hashed_password = $3, updated_at = $4
WHERE id = $1;

-- name: UpgradeUserToChirpyRed :exec
UPDATE users
SET is_chirpy_red = TRUE,
    updated_at = NOW()
WHERE id = $1;