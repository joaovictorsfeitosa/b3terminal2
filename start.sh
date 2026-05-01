#!/bin/bash
echo "B3 Terminal - Iniciando..."
pip3 install flask flask-cors yfinance feedparser requests python-dateutil gunicorn -q
echo "Acesse: http://localhost:5000"
sleep 2
if [[ "$OSTYPE" == "darwin"* ]]; then open http://localhost:5000
else xdg-open http://localhost:5000 2>/dev/null & fi
python3 app.py
