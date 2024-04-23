#!/bin/bash
python3 Server.py &
sleep 5
python3 Client.py &
sleep 5
python3 GUI.py &
