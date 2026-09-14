-- ==============================================================================
-- Snowflake Streamlit Deployment Script: AI Voice Authenticity Check
-- ==============================================================================

-- 1. Set your role and compute warehouse
USE ROLE SYSADMIN; -- or ACCOUNTADMIN / your designated role
CREATE WAREHOUSE IF NOT EXISTS COMPUTE_WH 
  WAREHOUSE_SIZE = 'XSMALL' 
  AUTO_SUSPEND = 120 
  AUTO_RESUME = TRUE;
USE WAREHOUSE COMPUTE_WH;

-- 2. Create database and schema
CREATE DATABASE IF NOT EXISTS VOICE_DETECTION_DB;
USE DATABASE VOICE_DETECTION_DB;

CREATE SCHEMA IF NOT EXISTS APP_SCHEMA;
USE SCHEMA APP_SCHEMA;

-- 3. Create an internal stage with directory enabled to hold app files
CREATE STAGE IF NOT EXISTS VOICE_APP_STAGE
  DIRECTORY = (ENABLE = TRUE)
  ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE');

-- 4. Upload app files to @VOICE_APP_STAGE:
-- OPTION A (Snowsight UI):
--   1. Go to Data > Databases > VOICE_DETECTION_DB > APP_SCHEMA > Stages > VOICE_APP_STAGE
--   2. Click "+ Files" and upload all unzipped files & folders (streamlit_app.py, environment.yml, model.joblib, src/, data/)
--
-- OPTION B (SnowSQL CLI):
--   snowsql -a <account_id> -u <user>
--   PUT file://<path_to_unzipped_folder>/* @VOICE_DETECTION_DB.APP_SCHEMA.VOICE_APP_STAGE/ AUTO_COMPRESS=FALSE OVERWRITE=TRUE;

-- 5. Create the Streamlit Application in Snowflake
CREATE OR REPLACE STREAMLIT VOICE_AUTHENTICITY_CHECK
  ROOT_LOCATION = '@VOICE_DETECTION_DB.APP_SCHEMA.VOICE_APP_STAGE'
  MAIN_FILE = '/streamlit_app.py'
  QUERY_WAREHOUSE = 'COMPUTE_WH'
  TITLE = 'Voice Authenticity Check';

-- 6. Verify and open
SHOW STREAMLITS;
