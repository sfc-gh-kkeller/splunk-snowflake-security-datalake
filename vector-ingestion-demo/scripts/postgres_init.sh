#!/bin/bash
# Initialize PostgreSQL for the demo
# This creates a local PostgreSQL instance with logging enabled

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$PROJECT_DIR/data/postgres"
LOG_DIR="$PROJECT_DIR/logs"

echo "🐘 Initializing PostgreSQL..."

# Create directories
mkdir -p "$DATA_DIR"
mkdir -p "$LOG_DIR"

# Check if already initialized
if [ -f "$DATA_DIR/PG_VERSION" ]; then
    echo "⚠️  PostgreSQL already initialized at $DATA_DIR"
    echo "   To reinitialize, run: rm -rf $DATA_DIR && pixi run pg-init"
    exit 0
fi

# Initialize the database cluster
echo "📦 Creating database cluster..."
initdb -D "$DATA_DIR" --auth=trust --no-locale --encoding=UTF8

# Configure PostgreSQL for detailed logging
echo "⚙️  Configuring logging..."
cat >> "$DATA_DIR/postgresql.conf" << 'EOF'

# ==========================================
# Logging Configuration for Security Demo
# ==========================================

# Enable CSV logging for Vector ingestion
log_destination = 'csvlog'
logging_collector = on
log_directory = '../../logs'
log_filename = 'postgresql-%Y-%m-%d.log'
log_file_mode = 0644

# Log everything for demo purposes
log_statement = 'all'
log_duration = on
log_min_duration_statement = 0
log_connections = on
log_disconnections = on
log_hostname = on

# Include additional info
log_line_prefix = '%t [%p]: user=%u,db=%d,app=%a,client=%h '
log_error_verbosity = verbose

# Log all queries (even successful ones)
log_min_messages = info
log_min_error_statement = info

# Checkpoint logging
log_checkpoints = on
log_lock_waits = on

# Listen on localhost only
listen_addresses = 'localhost'
port = 5432
EOF

# Start PostgreSQL temporarily to create database
echo "🚀 Starting PostgreSQL..."
pg_ctl -D "$DATA_DIR" -l "$LOG_DIR/postgres_init.log" start

# Wait for startup
sleep 2

# Create demo database and user
echo "📊 Creating demo database..."
createdb demo_app
psql -d demo_app << 'EOF'
-- Create tables for demo
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100),
    password_hash VARCHAR(255),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT true
);

CREATE TABLE sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    session_token VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER,
    action VARCHAR(50),
    table_name VARCHAR(50),
    record_id INTEGER,
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    description TEXT,
    price DECIMAL(10, 2),
    stock INTEGER,
    category VARCHAR(50)
);

CREATE TABLE orders (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    total_amount DECIMAL(10, 2),
    status VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE credit_cards (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    card_number_encrypted VARCHAR(255),
    expiry_month INTEGER,
    expiry_year INTEGER,
    last_four VARCHAR(4)
);

-- Insert sample data
INSERT INTO users (username, email, password_hash, role) VALUES
    ('admin', 'admin@example.com', '$2b$12$hash1', 'admin'),
    ('john_doe', 'john@example.com', '$2b$12$hash2', 'user'),
    ('jane_smith', 'jane@example.com', '$2b$12$hash3', 'user'),
    ('support', 'support@example.com', '$2b$12$hash4', 'support'),
    ('developer', 'dev@example.com', '$2b$12$hash5', 'developer');

INSERT INTO products (name, description, price, stock, category) VALUES
    ('Laptop Pro', 'High-end laptop', 1299.99, 50, 'electronics'),
    ('Wireless Mouse', 'Ergonomic mouse', 49.99, 200, 'accessories'),
    ('USB Hub', '7-port USB hub', 29.99, 150, 'accessories'),
    ('Monitor 27"', '4K display', 399.99, 75, 'electronics'),
    ('Keyboard', 'Mechanical keyboard', 129.99, 100, 'accessories');

INSERT INTO credit_cards (user_id, card_number_encrypted, expiry_month, expiry_year, last_four) VALUES
    (1, 'encrypted_data_1', 12, 2025, '4242'),
    (2, 'encrypted_data_2', 6, 2026, '1234'),
    (3, 'encrypted_data_3', 3, 2025, '5678');

-- Create an index for demo
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_products_category ON products(category);

GRANT ALL ON ALL TABLES IN SCHEMA public TO PUBLIC;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO PUBLIC;

\echo 'Demo database created successfully!'
EOF

echo "✅ PostgreSQL initialized!"
echo ""
echo "📍 Data directory: $DATA_DIR"
echo "📝 Log directory:  $LOG_DIR"
echo ""
echo "Commands:"
echo "  Start:   pixi run pg-start"
echo "  Stop:    pixi run pg-stop"
echo "  Status:  pixi run pg-status"
echo "  Attacks: pixi run pg-attacks"

