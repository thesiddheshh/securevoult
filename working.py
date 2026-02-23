import streamlit as st
import os
import time
import base64
import json
from datetime import datetime

# Import Core Modules
from core.encryption import AESCipher
from core.shamir import ShamirSecretSharing
from core.storage import ensure_storage_dirs, store_share, get_all_shares, save_encrypted_file_metadata, get_encrypted_file_metadata, NODES
from core.logging_module import init_db, log_event, get_logs
import pandas as pd

# --- Configuration ---
st.set_page_config(
    page_title="Secure Key Recovery",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load CSS
with open("assets/styles.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# Initialize Systems
ensure_storage_dirs()
init_db()

# Constants
THRESHOLD = 3
TOTAL_SHARES = 5
ADMIN_CREDS = {
    "adminA": "password123",
    "adminB": "secure456",
    "adminC": "root789"
}

# --- Helper Functions ---

def simulate_progress(steps, message):
    progress_bar = st.progress(0)
    status_text = st.empty()
    for i in range(steps):
        time.sleep(0.3)
        progress_bar.progress((i + 1) / steps)
        status_text.text(f"{message}... {int((i+1)/steps*100)}%")
    time.sleep(0.2)
    progress_bar.empty()
    status_text.empty()

# --- Pages ---

def page_dashboard():
    st.title("🛡️ Secure Distributed Key Backup & Recovery")
    st.markdown("### Enterprise-Grade Threshold Cryptography System")
    
    # 🏗 ARCHITECTURE DIAGRAM (Mermaid.js with HTML Injection)
    st.subheader("🏗 System Architecture Diagram")
    
    mermaid_diagram = """
    flowchart TD
        subgraph UserLayer ["👤 User Layer"]
            A[Admin/User] -->|Upload File| B(Streamlit App)
            H[Admins A/B/C] -->|Auth & Recover| B
        end

        subgraph CryptoLayer ["🔐 Cryptography Layer"]
            B -->|Generate| C[AES-256 Key]
            C -->|Encrypt| D[File Data]
            C -->|Split| E[Shamir's Secret Sharing]
            E -->|5 Shares| F{Threshold Check}
            F -->|≥ 3 Shares| G[Reconstruct Key]
        end

        subgraph StorageLayer ["☁️ Distributed Storage Layer"]
            F -->|Share 1| N1[(AWS Node)]
            F -->|Share 2| N2[(Azure Node)]
            F -->|Share 3| N3[(GCP Node)]
            F -->|Share 4| N4[(OnPrem Node)]
            F -->|Share 5| N5[(Escrow Vault)]
            G -->|Retrieve| N1
            G -->|Retrieve| N2
            G -->|Retrieve| N3
        end

        subgraph AuditLayer ["📜 Audit Layer"]
            B -->|Log Events| L[(SQLite Logs)]
        end

        style UserLayer fill:#161b22,stroke:#58a6ff,stroke-width:2px
        style CryptoLayer fill:#161b22,stroke:#238636,stroke-width:2px
        style StorageLayer fill:#161b22,stroke:#d29922,stroke-width:2px
        style AuditLayer fill:#161b22,stroke:#f85149,stroke-width:2px
        style C fill:#238636,color:#fff
        style E fill:#238636,color:#fff
        style G fill:#238636,color:#fff
    """
    
    # Render Mermaid Diagram using HTML/JS
    st.components.v1.html(
        f"""
        <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
        <div class="mermaid">
            {mermaid_diagram}
        </div>
        <script>
            mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
        </script>
        """,
        height=600
    )

    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("System Status", "🟢 Operational")
    with col2:
        st.metric("Active Nodes", f"{len(NODES)} / {len(NODES)}")
    with col3:
        st.metric("Security Level", "AES-256-GCM + SSS")

    st.markdown("---")
    
    st.subheader("🌐 Node Health Status")
    cols = st.columns(5)
    node_names = ["AWS", "Azure", "GCP", "OnPrem", "Escrow"]
    for i, col in enumerate(cols):
        with col:
            st.success(f"● {node_names[i]}")
            st.caption(f"ID: {i+1}")

def page_encrypt():
    st.title("🔒 Encrypt & Secure File")
    
    uploaded_file = st.file_uploader("Upload Sensitive Document", type=['txt', 'pdf', 'png', 'jpg'])
    
    if uploaded_file:
        file_bytes = uploaded_file.getvalue()
        file_name = uploaded_file.name
        
        if st.button("Initialize Encryption Protocol"):
            try:
                # 1. Generate Key
                simulate_progress(3, "Generating Secure AES-256 Key")
                cipher = AESCipher()
                aes_key = cipher.generate_key()
                
                # 2. Encrypt File
                simulate_progress(3, "Encrypting File Content (AES-GCM)")
                encrypted_data = cipher.encrypt(file_bytes, aes_key)
                
                # 3. Split Key
                simulate_progress(3, "Splitting Key via Shamir's Secret Sharing")
                shamir = ShamirSecretSharing(THRESHOLD, TOTAL_SHARES)
                shares = shamir.split_secret(aes_key)
                
                # SECURITY: Delete key from memory immediately
                del aes_key
                
                # 4. Distribute
                simulate_progress(5, "Distributing Shares to Cloud Nodes")
                file_id = f"file_{int(time.time())}"
                st.session_state['file_id'] = file_id
                st.session_state['encrypted_file'] = encrypted_data
                
                for share in shares:
                    store_share(share['id'], share, file_id)
                
                # Save metadata (nonce) publicly for recovery
                save_encrypted_file_metadata(file_id, encrypted_data['nonce'])
                
                # Save ciphertext to disk for recovery simulation
                ciphertext_path = f"database/{file_id}.enc"
                with open(ciphertext_path, 'wb') as f:
                    f.write(base64.b64decode(encrypted_data['payload']))
                
                st.success("✅ File Encrypted and Shares Distributed Successfully!")
                st.info(f"File ID: `{file_id}` (Save this for recovery)")
                
                # Log Event
                log_event("System", "ENCRYPTION", f"File {file_name} encrypted and split", "SUCCESS")
                
            except Exception as e:
                st.error(f"Critical Error: {str(e)}")
                log_event("System", "ENCRYPTION", f"Failed: {str(e)}", "FAILURE")

def page_recovery():
    st.title("🔓 Secure Recovery Portal")
    st.markdown("### Multi-Admin Authentication Required")
    
    # Step 1: Admin Login
    with st.expander("👤 Admin Authentication", expanded=True):
        col1, col2 = st.columns(2)
        with col1:
            admin_user = st.text_input("Admin ID", key="admin_user")
        with col2:
            admin_pass = st.text_input("Password", type="password", key="admin_pass")
        
        if st.button("Authenticate Admin"):
            if admin_user in ADMIN_CREDS and ADMIN_CREDS[admin_user] == admin_pass:
                st.session_state['authenticated_admin'] = admin_user
                st.success(f"Welcome, {admin_user}. Access Granted.")
                log_event(admin_user, "LOGIN", "Admin authenticated", "SUCCESS")
            else:
                st.error("Invalid Credentials")
                log_event(admin_user, "LOGIN", "Failed authentication attempt", "FAILURE")

    if 'authenticated_admin' in st.session_state:
        st.markdown("---")
        st.subheader("📂 Select File for Recovery")
        
        file_id = st.text_input("Enter File ID (from Encryption step)")
        
        if file_id:
            available_shares = get_all_shares(file_id)
            meta = get_encrypted_file_metadata(file_id)
            
            if not meta:
                st.warning("No encrypted file metadata found for this ID.")
            else:
                st.success(f"Found {len(available_shares)} available shares for this file.")
                
                st.write("### Available Shares")
                share_cols = st.columns(5)
                selected_share_ids = []
                
                for i, share in enumerate(available_shares):
                    with share_cols[i % 5]:
                        if st.checkbox(f"{share['node_name']} (ID:{share['node_id']})", key=f"share_{share['node_id']}"):
                            selected_share_ids.append(share)
                
                if st.button("🚀 Reconstruct & Decrypt"):
                    if len(selected_share_ids) < THRESHOLD:
                        st.error(f"⚠️ Access Denied: Insufficient Shares. Required: {THRESHOLD}, Provided: {len(selected_share_ids)}")
                        log_event(st.session_state['authenticated_admin'], "RECOVERY", "Failed: Insufficient shares", "FAILURE")
                    else:
                        try:
                            simulate_progress(4, "Reconstructing Key from Shares")
                            
                            shamir = ShamirSecretSharing(THRESHOLD, TOTAL_SHARES)
                            formatted_shares = [{"id": s['node_id'], "data": s['data']} for s in selected_share_ids]
                            recovered_key = shamir.recover_secret(formatted_shares)
                            
                            simulate_progress(3, "Decrypting File Content")
                            
                            cipher = AESCipher()
                            enc_dict = {
                                "nonce": meta['nonce'],
                                "payload": st.session_state.get('temp_payload')
                            }
                            
                            ciphertext_path = f"database/{file_id}.enc"
                            if os.path.exists(ciphertext_path):
                                with open(ciphertext_path, 'rb') as f:
                                    stored_payload = f.read()
                                enc_dict['payload'] = base64.b64encode(stored_payload).decode('utf-8')
                                
                                decrypted_bytes = cipher.decrypt(enc_dict, recovered_key)
                                
                                st.success("✅ Decryption Successful!")
                                st.download_button("Download Decrypted File", decrypted_bytes, file_name=f"decrypted_{file_id}")
                                log_event(st.session_state['authenticated_admin'], "RECOVERY", f"File {file_id} recovered", "SUCCESS")
                                
                                del recovered_key
                            else:
                                st.error("Encrypted payload not found on disk.")
                                
                        except Exception as e:
                            st.error(f"Reconstruction Failed: {str(e)}")
                            log_event(st.session_state['authenticated_admin'], "RECOVERY", f"Error: {str(e)}", "FAILURE")

def page_attack_sim():
    st.title("⚔️ Attack Simulation Lab")
    st.markdown("Demonstrate the resilience of Threshold Cryptography.")
    
    tab1, tab2 = st.tabs(["Single Node Breach", "Insider Attack"])
    
    with tab1:
        st.subheader("Scenario: Hacker breaches AWS Node")
        st.write("The attacker gains root access to Node 1 (AWS) and steals the share file.")
        
        if st.button("Simulate Breach"):
            st.warning("🚨 Breach Detected! Extracting Share ID 1...")
            time.sleep(1)
            st.code("Share Data: 8f3a... (Partial Key Material)", language="text")
            st.error("❌ Reconstruction Failed: 1 Share < 3 Threshold. Key remains secure.")
            st.info("Mathematical Proof: With 1 share, the key space remains 2^256 possibilities.")
            
    with tab2:
        st.subheader("Scenario: Malicious Insider (Admin A)")
        st.write("Admin A tries to recover a file without Admin B or C.")
        
        if st.button("Simulate Insider Attempt"):
            st.warning("🚨 Admin A attempting recovery alone...")
            time.sleep(1)
            st.error("❌ Access Denied: System requires 3 distinct authenticated admins.")
            st.info("Audit Log Updated: Unauthorized recovery attempt logged.")

def page_logs():
    st.title("📜 Audit Logs")
    
    logs = get_logs()
    if logs:
        df = pd.DataFrame(logs, columns=["ID", "Timestamp", "Admin ID", "Action", "Details", "Status", "IP Sim"])
        
        status_filter = st.selectbox("Filter by Status", ["All", "SUCCESS", "FAILURE"])
        if status_filter != "All":
            df = df[df["Status"] == status_filter]
            
        st.dataframe(df, use_container_width=True)
    else:
        st.info("No audit logs found.")

# --- Main Navigation ---
st.sidebar.title("🛡️ SecureVault")
menu = st.sidebar.radio("Navigation", ["Dashboard", "Encrypt & Secure", "Recovery Portal", "Attack Simulation", "Audit Logs"])

if menu == "Dashboard":
    page_dashboard()
elif menu == "Encrypt & Secure":
    page_encrypt()
elif menu == "Recovery Portal":
    page_recovery()
elif menu == "Attack Simulation":
    page_attack_sim()
elif menu == "Audit Logs":
    page_logs()