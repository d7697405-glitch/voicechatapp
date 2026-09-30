// Render deploy update
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { v4: uuidv4 } = require("uuid");

const app = express();

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      avatar_url TEXT,
      coins INTEGER NOT NULL DEFAULT 0,
      level INTEGER NOT NULL DEFAULT 1,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS rooms (
      id UUID PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      password_hash TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
  `);

  console.log("Database ready");
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  try {
    const token = header.substring(7);

    req.user = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    next();
  } catch (error) {
    return res.status(401).json({
      error: "Invalid token",
    });
  }
}

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    message: "Voice chat API is running",
  });
});

app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required",
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        error: "Username must be at least 3 characters",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters",
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (existing.rows.length > 0) {
      return res.status(409).json({
        error: "Username already exists",
      });
    }

    const id = uuidv4();

    const passwordHash = await bcrypt.hash(
      password,
      10
    );

    const result = await pool.query(
      `INSERT INTO users
      (id, username, password_hash)
      VALUES ($1, $2, $3)
      RETURNING id, username, coins, level, avatar_url`,
      [
        id,
        username,
        passwordHash,
      ]
    );

    const user = result.rows[0];

    res.status(201).json({
      user,
      token: createToken(user),
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Registration failed",
    });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    const result = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid username or password",
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid username or password",
      });
    }

    const safeUser = {
      id: user.id,
      username: user.username,
      coins: user.coins,
      level: user.level,
      avatar_url: user.avatar_url,
    };

    res.json({
      user: safeUser,
      token: createToken(safeUser),
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed",
    });
  }
});

app.get("/api/me", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, coins, level, avatar_url
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "User not found",
      });
    }

    res.json({
      user: result.rows[0],
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Failed to load profile",
    });
  }
});

app.get("/api/rooms", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        r.id,
        r.name,
        r.owner_id,
        u.username AS owner_username,
        r.created_at
      FROM rooms r
      JOIN users u ON u.id = r.owner_id
      ORDER BY r.created_at DESC
    `);

    res.json({
      rooms: result.rows,
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Failed to load rooms",
    });
  }
});

app.post("/api/rooms", authMiddleware, async (req, res) => {
  try {
    const { name, password } = req.body;

    if (!name) {
      return res.status(400).json({
        error: "Room name is required",
      });
    }

    const id = uuidv4();

    let passwordHash = null;

    if (password) {
      passwordHash = await bcrypt.hash(
        password,
        10
      );
    }

    const result = await pool.query(
      `INSERT INTO rooms
      (id, name, owner_id, password_hash)
      VALUES ($1, $2, $3, $4)
      RETURNING id, name, owner_id, created_at`,
      [
        id,
        name,
        req.user.id,
        passwordHash,
      ]
    );

    res.status(201).json({
      room: result.rows[0],
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Failed to create room",
    });
  }
});

app.post("/api/coins/demo", authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE users
       SET coins = coins + 100
       WHERE id = $1
       RETURNING id, username, coins, level, avatar_url`,
      [req.user.id]
    );

    res.json({
      user: result.rows[0],
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Failed to add coins",
    });
  }
});

app.get(
  "/api/rooms/:roomId/token",
  authMiddleware,
  async (req, res) => {
    res.status(501).json({
      error:
        "Live voice will be connected in the next step",
    });
  }
);

async function start() {
  try {
    await initDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Server running on port ${PORT}`
      );
    });
  } catch (error) {
    console.error(
      "Server startup failed:",
      error
    );

    process.exit(1);
  }
}

start();
