@echo off
setlocal
if "%ANTHROPIC_API_KEY%"=="" (
  echo Please set ANTHROPIC_API_KEY in your environment before running.
  echo Example: set ANTHROPIC_API_KEY=sk-...
  exit /b 1
)

echo Starting CorrelSOC dashboard on http://localhost:8501
streamlit run dashboard/app.py --server.port 8501 --server.address 0.0.0.0
