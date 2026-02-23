import os
import json
import base64
from datetime import datetime

NODES = {
    1: {"name": "AWS Cloud", "path": "storage/aws"},
    2: {"name": "Azure Cloud", "path": "storage/azure"},
    3: {"name": "Google Cloud", "path": "storage/gcp"},
    4: {"name": "On-Prem Server", "path": "storage/onprem"},
    5: {"name": "Legal Escrow", "path": "storage/escrow"}
}

def ensure_storage_dirs():
    for node in NODES.values():
        os.makedirs(node["path"], exist_ok=True)
    os.makedirs("database", exist_ok=True)

def store_share(node_id: int, share_data: dict, file_id: str):
    """Stores a share as a JSON file in the specific node directory."""
    node = NODES[node_id]
    filename = f"{file_id}_share_{node_id}.json"
    filepath = os.path.join(node["path"], filename)
    
    # Wrap share in metadata
    payload = {
        "share_id": node_id,
        "file_id": file_id,
        "timestamp": datetime.now().isoformat(),
        "data": share_data['data']
    }
    
    with open(filepath, 'w') as f:
        json.dump(payload, f, indent=2)
    
    return filepath

def get_all_shares(file_id: str):
    """Retrieves all available shares for a specific file ID from all nodes."""
    available_shares = []
    for node_id, node in NODES.items():
        filename = f"{file_id}_share_{node_id}.json"
        filepath = os.path.join(node["path"], filename)
        
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
                available_shares.append({
                    "node_id": node_id,
                    "node_name": node["name"],
                    "data": data['data']
                })
    return available_shares

def get_encrypted_file_metadata(file_id: str):
    """Retrieves the nonce and other metadata needed for decryption."""
    # In a real system, this metadata is public or stored separately from shares.
    # We will store it in a central 'metadata' file for simulation purposes.
    meta_path = f"database/{file_id}_meta.json"
    if os.path.exists(meta_path):
        with open(meta_path, 'r') as f:
            return json.load(f)
    return None

def save_encrypted_file_metadata(file_id: str, nonce: str):
    meta_path = f"database/{file_id}_meta.json"
    with open(meta_path, 'w') as f:
        json.dump({"file_id": file_id, "nonce": nonce}, f)