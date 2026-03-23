-- ============================================================
-- Snowflake Setup for Security Log Demo
-- ============================================================
-- 
-- This script creates:
--   1. Database and schema
--   2. Tables for Nginx and PostgreSQL logs
--   3. File formats for CSV uploads
--   4. Sample queries for analysis
--
-- Usage:
--   Run in Snowflake Web UI or via snow cli:
--   snow sql -f config/snowflake_setup.sql
-- ============================================================

-- Create database for security logs
CREATE DATABASE IF NOT EXISTS SECURITY_LOGS;
USE DATABASE SECURITY_LOGS;
CREATE SCHEMA IF NOT EXISTS PUBLIC;
USE SCHEMA PUBLIC;

-- ============================================================
-- TABLE: NGINX_LOGS (Critical - also goes to Splunk)
-- ============================================================
CREATE TABLE IF NOT EXISTS NGINX_LOGS (
    timestamp TIMESTAMP_NTZ,
    client_ip VARCHAR(50),
    request_method VARCHAR(10),
    request_path VARCHAR(4000),
    http_status INTEGER,
    response_size INTEGER,
    user_agent VARCHAR(2000),
    referer VARCHAR(2000),
    response_time_ms FLOAT,
    is_attack BOOLEAN,
    attack_type VARCHAR(100),
    severity VARCHAR(20),
    raw_log TEXT,
    source_system VARCHAR(50) DEFAULT 'nginx',
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ============================================================
-- TABLE: POSTGRES_LOGS (Not critical - Snowflake only)
-- ============================================================
CREATE TABLE IF NOT EXISTS POSTGRES_LOGS (
    log_time TIMESTAMP_NTZ,
    user_name VARCHAR(100),
    database_name VARCHAR(100),
    process_id INTEGER,
    connection_from VARCHAR(100),
    session_id VARCHAR(100),
    session_line_num INTEGER,
    command_tag VARCHAR(50),
    session_start_time TIMESTAMP_NTZ,
    virtual_transaction_id VARCHAR(50),
    transaction_id BIGINT,
    error_severity VARCHAR(20),
    sql_state_code VARCHAR(10),
    message TEXT,
    detail TEXT,
    hint TEXT,
    internal_query TEXT,
    internal_query_pos INTEGER,
    context TEXT,
    query TEXT,
    query_pos INTEGER,
    location TEXT,
    application_name VARCHAR(200),
    is_suspicious BOOLEAN,
    attack_pattern VARCHAR(100),
    source_system VARCHAR(50) DEFAULT 'postgresql',
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ============================================================
-- TABLE: SECURITY_EVENTS (Combined/Unified)
-- ============================================================
CREATE TABLE IF NOT EXISTS SECURITY_EVENTS (
    event_id VARCHAR(100) DEFAULT UUID_STRING(),
    event_time TIMESTAMP_NTZ,
    source_system VARCHAR(50),
    event_type VARCHAR(100),
    severity VARCHAR(20),
    source_ip VARCHAR(50),
    user_name VARCHAR(100),
    description TEXT,
    raw_data VARIANT,
    tags ARRAY,
    ingested_at TIMESTAMP_NTZ DEFAULT CURRENT_TIMESTAMP()
);

-- ============================================================
-- FILE FORMAT: CSV for direct uploads
-- ============================================================
CREATE OR REPLACE FILE FORMAT CSV_FORMAT
    TYPE = 'CSV'
    FIELD_DELIMITER = ','
    SKIP_HEADER = 1
    FIELD_OPTIONALLY_ENCLOSED_BY = '"'
    NULL_IF = ('', 'NULL', 'null', 'None')
    TRIM_SPACE = TRUE
    ERROR_ON_COLUMN_COUNT_MISMATCH = FALSE;

-- ============================================================
-- FILE FORMAT: JSON for Vector output
-- ============================================================
CREATE OR REPLACE FILE FORMAT JSON_FORMAT
    TYPE = 'JSON'
    STRIP_OUTER_ARRAY = TRUE;

-- ============================================================
-- INTERNAL STAGE: For file uploads
-- ============================================================
CREATE OR REPLACE STAGE UPLOAD_STAGE
    FILE_FORMAT = CSV_FORMAT;

-- ============================================================
-- SAMPLE ANALYSIS QUERIES
-- ============================================================

-- Query 1: Attack Summary by Type
-- SELECT 
--     attack_type,
--     COUNT(*) as attack_count,
--     COUNT(DISTINCT client_ip) as unique_ips
-- FROM NGINX_LOGS
-- WHERE is_attack = TRUE
-- GROUP BY attack_type
-- ORDER BY attack_count DESC;

-- Query 2: Top Attacking IPs
-- SELECT 
--     client_ip,
--     COUNT(*) as attack_count,
--     LISTAGG(DISTINCT attack_type, ', ') as attack_types
-- FROM NGINX_LOGS
-- WHERE is_attack = TRUE
-- GROUP BY client_ip
-- ORDER BY attack_count DESC
-- LIMIT 10;

-- Query 3: Suspicious PostgreSQL Queries
-- SELECT 
--     log_time,
--     user_name,
--     attack_pattern,
--     query
-- FROM POSTGRES_LOGS
-- WHERE is_suspicious = TRUE
-- ORDER BY log_time DESC
-- LIMIT 20;

-- Query 4: Cross-System Correlation
-- SELECT 
--     n.client_ip,
--     n.attack_type as nginx_attack,
--     p.attack_pattern as postgres_attack,
--     n.timestamp as nginx_time,
--     p.log_time as postgres_time
-- FROM NGINX_LOGS n
-- JOIN POSTGRES_LOGS p 
--     ON n.client_ip = p.connection_from
--     AND n.is_attack = TRUE 
--     AND p.is_suspicious = TRUE
--     AND ABS(TIMESTAMPDIFF(MINUTE, n.timestamp, p.log_time)) < 5
-- ORDER BY n.timestamp;

-- Query 5: Hourly Attack Trend
-- SELECT 
--     DATE_TRUNC('HOUR', timestamp) as hour,
--     source_system,
--     COUNT(*) as event_count
-- FROM (
--     SELECT timestamp, 'nginx' as source_system FROM NGINX_LOGS WHERE is_attack = TRUE
--     UNION ALL
--     SELECT log_time as timestamp, 'postgresql' as source_system FROM POSTGRES_LOGS WHERE is_suspicious = TRUE
-- )
-- GROUP BY 1, 2
-- ORDER BY 1, 2;

-- ============================================================
-- GRANTS (adjust as needed)
-- ============================================================
-- GRANT SELECT ON ALL TABLES IN SCHEMA PUBLIC TO ROLE PUBLIC;

SHOW TABLES;
