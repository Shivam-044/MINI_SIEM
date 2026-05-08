import subprocess
import time
import sys
import os

def launch_siem():
    print("🚀 Starting Windows Mini-SIEM System...")

    # 1. Start the Collector
    print("[1/3] Launching Log Collector...")
    collector = subprocess.Popen([sys.executable, "collector.py"])

    # 2. Start the Correlation Engine
    print("[2/3] Launching Detection Engine...")
    engine = subprocess.Popen([sys.executable, "engine.py"])

    # 3. Start the Streamlit Dashboard
    print("[3/3] Launching Web Dashboard...")
    # We use 'shell=True' for streamlit because it's an executable in your PATH
    dashboard = subprocess.Popen(["streamlit", "run", "app.py"], shell=True)

    print("\n✅ SIEM is now fully operational!")
    print("Go to http://localhost:8501 to view your dashboard.")
    print("Press Ctrl+C to shut down all components safely.")

    try:
        # Keep the main script alive while children are running
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down SIEM components...")
        collector.terminate()
        engine.terminate()
        dashboard.terminate()
        print("👋 All processes closed. Goodbye!")

if __name__ == "__main__":
    launch_siem()