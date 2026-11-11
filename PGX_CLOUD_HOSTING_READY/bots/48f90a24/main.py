# PGX CLOUD - Default Bot
import time

print("=" * 40)
print("Bot is running on PGX CLOUD")
print("Server is ready!")
print("=" * 40)

counter = 0
while True:
    counter += 1
    print(f"[{time.strftime('%H:%M:%S')}] Heartbeat #{counter} | Server active")
    time.sleep(10)
