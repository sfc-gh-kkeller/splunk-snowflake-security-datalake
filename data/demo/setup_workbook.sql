-- ============================================================
-- Splunk + Snowflake Security Data Lake — Setup Workbook
-- ============================================================
--
-- This workbook creates the demo database, tables, and loads
-- the sample CSV data used by the Splunk federated query demos.
--
-- Prerequisites:
--   1. A Snowflake account with ACCOUNTADMIN or sufficient privileges
--   2. The CSV files from data/demo/ uploaded to a Snowflake stage
--
-- Usage:
--   Run each section in order via Snowflake Web UI or Snow CLI:
--     snow sql -f data/demo/setup_workbook.sql -c your_connection
--
-- ============================================================


-- ============================================================
-- STEP 1: Create Database and Schema
-- ============================================================

CREATE DATABASE IF NOT EXISTS CTF;
USE DATABASE CTF;
CREATE SCHEMA IF NOT EXISTS PUBLIC;
USE SCHEMA PUBLIC;

-- Use your warehouse (adjust name as needed)
USE WAREHOUSE COMPUTE_WH;


-- ============================================================
-- STEP 2: Create Tables
-- ============================================================

-- ACCESS_LOGS: Primary table for Splunk federated query demos
-- 100,000 rows of web access logs with realistic attack patterns
CREATE OR REPLACE TABLE ACCESS_LOGS (
    TIMESTAMP       TIMESTAMP_NTZ,
    IP_ADDRESS      VARCHAR(45),
    REQUEST_METHOD  VARCHAR(10),
    REQUEST_PATH    VARCHAR(2024),
    STATUS_CODE     NUMBER(38,0),
    BYTES_SENT      NUMBER(38,0),
    BACKEND_IP      VARCHAR(45)
);

-- ASSET_INVENTORY: Server/resource catalog
-- 844 rows with OS, hardware specs, location, owner, cloud provider
CREATE OR REPLACE TABLE ASSET_INVENTORY (
    ID              VARCHAR,
    OS              VARCHAR,
    MEMORY_GB       NUMBER(38,0),
    CPU_CORES       NUMBER(38,0),
    DISK_GB         NUMBER(38,0),
    LOCATION        VARCHAR,
    OWNER           VARCHAR,
    PROVIDER        VARCHAR,
    STATUS          VARCHAR,
    LAST_UPDATED    TIMESTAMP_NTZ,
    TAGS            VARIANT
);

-- VULNERABILITIES: Vulnerability scan results
-- 15,000 rows with CVEs, severity scores, resource details
CREATE OR REPLACE TABLE VULNERABILITIES (
    CREATED_AT           TIMESTAMP_NTZ,
    TITLE                VARCHAR,
    SEVERITY             NUMBER(38,0),
    STATUS               VARCHAR(10),
    RESOURCE_TYPE        VARCHAR(20),
    RESOURCE_EXTERNAL_ID VARCHAR(255),
    SUBSCRIPTION_ID      VARCHAR(255),
    PROJECT_IDS          VARCHAR(255),
    RESOLVED_TIME        TIMESTAMP_NTZ,
    CONTROL_ID           VARCHAR(255),
    RESOURCE_HOSTNAME    VARCHAR(255),
    RESOURCE_IP          VARCHAR(255),
    RESOURCE_REGION      VARCHAR(20),
    RESOURCE_STATUS      VARCHAR(20),
    RESOURCE_PLATFORM    VARCHAR(20),
    RESOURCE_OS          VARCHAR(50),
    ISSUE_ID             VARCHAR(255)
);

-- SECURITY_FINDINGS: Security findings with status tracking
-- 106 rows — findings derived from access log anomalies
CREATE OR REPLACE TABLE SECURITY_FINDINGS (
    FINDING_ID      NUMBER(38,0) NOT NULL,
    DETECTED_AT     TIMESTAMP_NTZ,
    FINDING_TYPE    VARCHAR(100),
    SEVERITY        VARCHAR(20),
    STATUS          VARCHAR(30),
    STATUS_COMMENT  VARCHAR(2000),
    TIMESTAMP       TIMESTAMP_NTZ,
    IP_ADDRESS      VARCHAR(45),
    REQUEST_PATH    VARCHAR(2048),
    REQUEST_METHOD  VARCHAR(10),
    STATUS_CODE     NUMBER(38,0),
    BYTES_SENT      NUMBER(38,0),
    BACKEND_IP      VARCHAR(45),
    DESCRIPTION     VARCHAR(2000),
    LAST_UPDATED_AT TIMESTAMP_NTZ,
    LAST_UPDATED_BY VARCHAR(256),
    EMAIL_SENT      BOOLEAN,
    EMAIL_SENT_AT   TIMESTAMP_NTZ
);


-- ============================================================
-- STEP 3: Create File Format and Stage
-- ============================================================

CREATE OR REPLACE FILE FORMAT CTF_CSV_FORMAT
    TYPE = 'CSV'
    FIELD_DELIMITER = ','
    SKIP_HEADER = 1
    FIELD_OPTIONALLY_ENCLOSED_BY = '"'
    NULL_IF = ('', 'NULL', 'null', 'None')
    TRIM_SPACE = TRUE
    ERROR_ON_COLUMN_COUNT_MISMATCH = FALSE;

CREATE OR REPLACE STAGE CTF_UPLOAD_STAGE
    FILE_FORMAT = CTF_CSV_FORMAT;


-- ============================================================
-- STEP 4: Upload CSV Files to Stage
-- ============================================================
-- Run these PUT commands from Snow CLI or SnowSQL:
--
--   PUT file:///path/to/data/demo/access_logs.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/access_logs AUTO_COMPRESS=FALSE;
--   PUT file:///path/to/data/demo/asset_inventory.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/asset_inventory AUTO_COMPRESS=FALSE;
--   PUT file:///path/to/data/demo/vulnerabilities.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/vulnerabilities AUTO_COMPRESS=FALSE;
--   PUT file:///path/to/data/demo/security_findings.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/security_findings AUTO_COMPRESS=FALSE;
--
-- Or use the Snowflake Web UI:
--   1. Go to Data → Databases → CTF → PUBLIC → Stages → CTF_UPLOAD_STAGE
--   2. Click "Upload Files" and select each CSV
--
-- Verify uploads:
-- LIST @CTF_UPLOAD_STAGE;


-- ============================================================
-- STEP 5: Load Data from Stage into Tables
-- ============================================================

COPY INTO ACCESS_LOGS
    FROM @CTF_UPLOAD_STAGE/access_logs
    FILE_FORMAT = CTF_CSV_FORMAT
    ON_ERROR = 'CONTINUE';

COPY INTO ASSET_INVENTORY (ID, OS, MEMORY_GB, CPU_CORES, DISK_GB, LOCATION, OWNER, PROVIDER, STATUS, LAST_UPDATED, TAGS)
    FROM (
        SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
               TRY_PARSE_JSON($11)
        FROM @CTF_UPLOAD_STAGE/asset_inventory
    )
    FILE_FORMAT = CTF_CSV_FORMAT
    ON_ERROR = 'CONTINUE';

COPY INTO VULNERABILITIES
    FROM @CTF_UPLOAD_STAGE/vulnerabilities
    FILE_FORMAT = CTF_CSV_FORMAT
    ON_ERROR = 'CONTINUE';

COPY INTO SECURITY_FINDINGS
    FROM @CTF_UPLOAD_STAGE/security_findings
    FILE_FORMAT = CTF_CSV_FORMAT
    ON_ERROR = 'CONTINUE';


-- ============================================================
-- STEP 6: Verify Data Loaded
-- ============================================================

SELECT 'ACCESS_LOGS' AS TABLE_NAME, COUNT(*) AS ROW_COUNT FROM ACCESS_LOGS
UNION ALL
SELECT 'ASSET_INVENTORY', COUNT(*) FROM ASSET_INVENTORY
UNION ALL
SELECT 'VULNERABILITIES', COUNT(*) FROM VULNERABILITIES
UNION ALL
SELECT 'SECURITY_FINDINGS', COUNT(*) FROM SECURITY_FINDINGS
ORDER BY TABLE_NAME;

-- Expected:
--   ACCESS_LOGS       100,000
--   ASSET_INVENTORY       844
--   SECURITY_FINDINGS     106
--   VULNERABILITIES    15,000


-- ============================================================
-- STEP 7: Sample Queries (verify data looks correct)
-- ============================================================

-- Quick stats on ACCESS_LOGS
SELECT
    COUNT(*) AS total_requests,
    COUNT(DISTINCT IP_ADDRESS) AS unique_ips,
    SUM(CASE WHEN STATUS_CODE = 401 THEN 1 ELSE 0 END) AS auth_failures,
    SUM(CASE WHEN STATUS_CODE >= 500 THEN 1 ELSE 0 END) AS server_errors,
    SUM(CASE WHEN REQUEST_METHOD = 'DELETE' THEN 1 ELSE 0 END) AS delete_ops
FROM ACCESS_LOGS;

-- Vulnerability severity distribution
SELECT SEVERITY, STATUS, COUNT(*) AS CNT
FROM VULNERABILITIES
GROUP BY SEVERITY, STATUS
ORDER BY SEVERITY DESC, CNT DESC;

-- Asset inventory by provider
SELECT PROVIDER, STATUS, COUNT(*) AS CNT
FROM ASSET_INVENTORY
GROUP BY PROVIDER, STATUS
ORDER BY CNT DESC;

-- Security findings by severity
SELECT SEVERITY, STATUS, COUNT(*) AS CNT
FROM SECURITY_FINDINGS
GROUP BY SEVERITY, STATUS
ORDER BY CNT DESC;


-- ============================================================
-- STEP 8: Cross-Table Analytics
-- ============================================================

-- Correlate findings with access logs for same IP
SELECT
    sf.FINDING_TYPE,
    sf.SEVERITY AS FINDING_SEVERITY,
    sf.IP_ADDRESS,
    COUNT(al.TIMESTAMP) AS RELATED_ACCESS_EVENTS,
    SUM(CASE WHEN al.STATUS_CODE = 401 THEN 1 ELSE 0 END) AS AUTH_FAILURES
FROM SECURITY_FINDINGS sf
LEFT JOIN ACCESS_LOGS al ON sf.IP_ADDRESS = al.IP_ADDRESS
GROUP BY sf.FINDING_TYPE, sf.SEVERITY, sf.IP_ADDRESS
ORDER BY AUTH_FAILURES DESC
LIMIT 20;

-- Find vulnerable hosts in asset inventory
SELECT
    ai.ID AS ASSET_ID,
    ai.OS,
    ai.PROVIDER,
    ai.STATUS AS ASSET_STATUS,
    COUNT(v.TITLE) AS OPEN_VULNS,
    MAX(v.SEVERITY) AS MAX_SEVERITY
FROM ASSET_INVENTORY ai
LEFT JOIN VULNERABILITIES v
    ON ai.RESOURCE_HOSTNAME = v.RESOURCE_HOSTNAME
    AND v.STATUS = 'OPEN'
GROUP BY ai.ID, ai.OS, ai.PROVIDER, ai.STATUS
HAVING COUNT(v.TITLE) > 0
ORDER BY MAX_SEVERITY DESC, OPEN_VULNS DESC
LIMIT 20;


-- ============================================================
-- OPTIONAL: Grant access for Splunk service account
-- ============================================================
-- CREATE ROLE IF NOT EXISTS SPLUNK_READER;
-- GRANT USAGE ON DATABASE CTF TO ROLE SPLUNK_READER;
-- GRANT USAGE ON SCHEMA CTF.PUBLIC TO ROLE SPLUNK_READER;
-- GRANT SELECT ON ALL TABLES IN SCHEMA CTF.PUBLIC TO ROLE SPLUNK_READER;
-- GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE SPLUNK_READER;
-- GRANT ROLE SPLUNK_READER TO USER your_splunk_service_account;


-- ============================================================
-- OPTIONAL: Cleanup stage after loading
-- ============================================================
-- DROP STAGE IF EXISTS CTF_UPLOAD_STAGE;
-- DROP FILE FORMAT IF EXISTS CTF_CSV_FORMAT;
