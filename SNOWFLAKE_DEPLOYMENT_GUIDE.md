# Deploying AI Voice Detection in Snowflake ❄️

This guide walks you through deploying the **Voice Authenticity Check** app to **Streamlit in Snowflake (SiS)**.

---

## 📦 What's in the Zip File

The deployment package `snowflake_ai_voice_detection.zip` contains:
- `streamlit_app.py` / `app.py`: Streamlit application entry points (cloud-ready).
- `environment.yml`: Conda/Snowflake package definitions.
- `requirements.txt`: Python package requirements.
- `model.joblib`: Pre-trained Random Forest model on 34 voice samples (100% validation accuracy).
- `src/`: Acoustic feature extraction, modeling, and inference modules.
- `data/sample_audio/`: 34 benchmark audio clips (20 Human, 14 AI).
- `train.py`: Standalone training script.
- `snowflake_setup.sql`: SQL script to create stage, warehouse, and Streamlit app.

---

## 🚀 Method 1: Deploy via Snowsight UI (Easiest, No CLI)

1. **Log in to Snowsight** (Snowflake Web Interface).
2. Go to **Projects** > **Streamlit** in the left sidebar.
3. Click the **+ Streamlit App** button (top right).
4. Configure:
   - **App title**: `Voice Authenticity Check`
   - **Warehouse**: Choose any warehouse (e.g. `COMPUTE_WH`).
   - **App location**: Select your database and schema (e.g., `VOICE_DETECTION_DB` > `APP_SCHEMA`).
   - Click **Create**.
5. Once created:
   - On the left file explorer inside the Streamlit editor, upload the files from the unzipped package:
     - Upload `streamlit_app.py` (replace existing code)
     - Upload `environment.yml`
     - Upload `model.joblib`
     - Upload folder `src/` (`feature_extraction.py`, `model.py`, `inference.py`, `__init__.py`)
     - Upload folder `data/sample_audio/`
6. In the **Packages** dropdown (top right), ensure Anaconda packages are enabled and dependencies match `environment.yml`.
7. Click **Run**! Your app is now live in Snowflake.

---

## 💻 Method 2: Deploy via Snowflake Stage & SQL

1. Open a new **SQL Worksheet** in Snowsight.
2. Run the SQL commands from [`snowflake_setup.sql`](file:///C:/Users/jaypr/.gemini/antigravity/scratch/ai_voice_detection/snowflake_setup.sql):
   ```sql
   CREATE DATABASE IF NOT EXISTS VOICE_DETECTION_DB;
   USE DATABASE VOICE_DETECTION_DB;
   CREATE SCHEMA IF NOT EXISTS APP_SCHEMA;
   USE SCHEMA APP_SCHEMA;

   CREATE STAGE IF NOT EXISTS VOICE_APP_STAGE
     DIRECTORY = (ENABLE = TRUE)
     ENCRYPTION = (TYPE = 'SNOWFLAKE_SSE');
   ```
3. Navigate to **Data** > **Databases** > `VOICE_DETECTION_DB` > `APP_SCHEMA` > **Stages** > `VOICE_APP_STAGE`.
4. Click **+ Files** and upload the contents of the unzipped zip folder into the stage root.
5. In your worksheet, create and launch the Streamlit app:
   ```sql
   CREATE OR REPLACE STREAMLIT VOICE_AUTHENTICITY_CHECK
     ROOT_LOCATION = '@VOICE_DETECTION_DB.APP_SCHEMA.VOICE_APP_STAGE'
     MAIN_FILE = '/streamlit_app.py'
     QUERY_WAREHOUSE = 'COMPUTE_WH'
     TITLE = 'Voice Authenticity Check';
   ```
6. Navigate to **Projects** > **Streamlit** to open and share your deployed app!
