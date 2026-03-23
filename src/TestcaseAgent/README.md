# Setup & Required Environment

Follow the steps below to prepare the environment and required folders for running the project.

## 1. Install required Python packages

Run this command in the project root to install dependencies:

```bash
pip install -r requirement.txt
```

## 2. Create a .env file (if it does not exist)

Create a file named `.env` in the project root and add the following content:

```bash
#.env
BASE_MODEL=4o-mini   # Model name
BASE_URL=            # URL or endpoint for the base model
API_KEY=             # API key for the model
```

Fill in `BASE_URL` and `API_KEY` according to your model provider or deployment.

## 3. Update configuration paths

Open `_config.py` and set the local paths used by the project:

```python
# _config.py
PROJECT_PATH =      # Path to the project you want to analyze
BIN_PATH =          # Path to the executable/script that can be run to trigger behavior in the project
```

Replace the comments with absolute or relative paths appropriate for your environment.

## 4. Create initial folders

To create the default folder structure for the first run, you can execute:

```bash
python3 TestcaseAgent.py
```

After that, create those folders manually if they were not created automatically.:

- ../src/TestcaseAgent/chat_history/TestcaseAgent/{your project name}
- ../src/TestcaseAgent/extra/{your project name}
