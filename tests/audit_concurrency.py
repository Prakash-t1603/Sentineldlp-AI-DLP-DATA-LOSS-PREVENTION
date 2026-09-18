import asyncio
import httpx
import uuid
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

BASE_URL = "http://localhost:8000/api/v1"

async def register_agent(client: httpx.AsyncClient, machine_id: str, hostname: str, ip_address: str, username: str):
    logging.info(f"Registering agent: {machine_id} ({username})")
    response = await client.post(f"{BASE_URL}/agent/register", json={
        "machine_id": machine_id,
        "hostname": hostname,
        "ip_address": ip_address,
        "username": username,
        "os_info": "Windows",
        "agent_version": "1.0.0"
    })
    
    if response.status_code == 200:
        data = response.json()
        logging.info(f"Registered {machine_id} successfully: {data}")
        return data.get("access_token")
    else:
        logging.error(f"Failed to register {machine_id}: {response.text}")
        return None

async def send_event(client: httpx.AsyncClient, token: str, machine_id: str, username: str, content: str):
    logging.info(f"[{machine_id}] Sending event for user {username}")
    event_id = str(uuid.uuid4())
    headers = {"Authorization": f"Bearer {token}"}
    
    event_data = {
        "event_id": event_id,
        "event_type": "clipboard",
        "timestamp": datetime.utcnow().isoformat(),
        "content": content,
        "process_name": "notepad.exe",
        "user_id": username
    }
    
    response = await client.post(f"{BASE_URL}/agent/events", json=[event_data], headers=headers)
    if response.status_code == 200:
        logging.info(f"[{machine_id}] Successfully sent event: {event_id}")
    else:
        logging.error(f"[{machine_id}] Failed to send event: {response.text}")
    
    return event_id

async def run_agent(machine_id: str, hostname: str, username: str, content: str):
    async with httpx.AsyncClient() as client:
        token = await register_agent(client, machine_id, hostname, f"192.168.1.{len(machine_id)}", username)
        if not token:
            return
        
        # Add a tiny delay to ensure both are registered before sending events
        await asyncio.sleep(1)
        
        event_id = await send_event(client, token, machine_id, username, content)
        logging.info(f"Finished {machine_id} -> {event_id}")

async def main():
    # EMP-001
    emp1_task = run_agent(
        machine_id="EMP-PC-DEVIL", 
        hostname="EMP-PC-DEVIL",
        username="EMP-001", 
        content="Confidential Data from EMP-001"
    )
    
    # EMP-002
    emp2_task = run_agent(
        machine_id="EMP-PC-WIN", 
        hostname="EMP-PC-WIN",
        username="EMP-002", 
        content="Confidential Data from EMP-002"
    )
    
    # Run concurrently
    await asyncio.gather(emp1_task, emp2_task)
    
    # Fetch latest events from the backend to verify the state
    async with httpx.AsyncClient() as client:
        # Assuming admin/admin for UI access (if we need to fetch via API)
        # We can also just read the DB directly via sqlalchemy in a synchronous script, but this tests the endpoint.
        pass

if __name__ == "__main__":
    asyncio.run(main())
