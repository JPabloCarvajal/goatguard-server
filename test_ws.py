"""Quick test for WebSocket connection."""
import sys
sys.path.insert(0, ".")

import asyncio
import json
import websockets

from src.api.auth import init_auth, create_token

async def test():
    # Create a valid token
    init_auth("goatguard-dev-secret-change-in-production")
    token = create_token(user_id=1, username="admin")

    uri = f"ws://localhost:8000/ws?token={token}"
    print(f"Connecting to {uri[:60]}...")

    async with websockets.connect(uri) as ws:
        print("Connected! Waiting for messages...\n")

        for i in range(5):
            message = await ws.recv()
            data = json.loads(message)
            print(f"Message {i+1}:")
            print(f"  Type: {data['type']}")
            if data.get("network"):
                net = data["network"]
                print(f"  ISP Latency: {net.get('isp_latency_avg')}ms")
                print(f"  Packet Loss: {net.get('packet_loss_pct')}%")
            print(f"  Devices: {len(data.get('devices', []))}")
            print(f"  Unseen Alerts: {data.get('unseen_alerts')}")
            print()

    print("Done!")

asyncio.run(test())