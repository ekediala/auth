# Go Auth Package (PostgreSQL Only)

This is a standalone Go authentication module using only the standard library and PostgreSQL. It includes:

- User registration and login using JWT
- Password reset functionality using database-backed reset tokens
- No third-party services or in-memory stores — everything is persisted in PostgreSQL

---

## PostgreSQL Schema

Create the required tables by running the following SQL:

```sql

-- Users Table
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Reset Tokens Table
CREATE TABLE IF NOT EXISTS reset_tokens (
    token TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);
