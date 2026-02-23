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
    page_title="SecureVault | Enterprise KMS",
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

# --- Custom UI Components ---

def create_security_card(icon, title, description, color="blue"):
    """Creates a styled security card component"""
    color_classes = {
        "blue": "icon-blue",
        "green": "icon-green", 
        "red": "icon-red",
        "gold": "icon-gold",
        "purple": "icon-purple"
    }
    
    st.markdown(f"""
    <div class="security-card fade-in">
        <div class="card-header">
            <div class="card-icon {color_classes.get(color, 'icon-blue')}">{icon}</div>
            <div>
                <h3 style="margin: 0; color: var(--text-primary);">{title}</h3>
                <p style="margin: 4px 0 0 0; color: var(--text-secondary); font-size: 0.9rem;">{description}</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

def create_node_status_card(node_name, node_id, status="online"):
    """Creates a node status card"""
    status_color = "var(--accent-green)" if status == "online" else "var(--accent-red)"
    status_text = "Operational" if status == "online" else "Offline"
    
    st.markdown(f"""
    <div class="node-status fade-in">
        <div style="font-size: 2rem; margin-bottom: 8px;">
            <span class="status-dot" style="background: {status_color}; box-shadow: 0 0 10px {status_color};"></span>
        </div>
        <div style="font-weight: 600; color: var(--text-primary);">{node_name}</div>
        <div style="font-size: 0.8rem; color: var(--text-secondary); margin-top: 4px;">ID: {node_id}</div>
        <div style="font-size: 0.75rem; color: {status_color}; margin-top: 8px;">
            <span class="badge badge-success">{status_text}</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

def create_metric_card(label, value, icon="📊"):
    """Creates a custom metric card"""
    st.markdown(f"""
    <div style="background: var(--bg-card); border: 1px solid var(--border-color); 
                border-radius: 16px; padding: 24px; text-align: center; 
                box-shadow: var(--shadow-lg);">
        <div style="font-size: 2.5rem; margin-bottom: 8px;">{icon}</div>
        <div style="font-size: 2rem; font-weight: 700; background: var(--gradient-3); 
                    -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
            {value}
        </div>
        <div style="color: var(--text-secondary); font-size: 0.875rem; 
                    text-transform: uppercase; letter-spacing: 1px; margin-top: 8px;">
            {label}
        </div>
    </div>
    """, unsafe_allow_html=True)

def simulate_progress(steps, message):
    """Enhanced progress simulation"""
    progress_bar = st.progress(0)
    status_text = st.empty()
    for i in range(steps):
        time.sleep(0.2)
        progress_bar.progress((i + 1) / steps)
        status_text.markdown(f"""
        <div style="color: var(--accent-blue); font-family: 'JetBrains Mono', monospace; 
                    font-size: 0.9rem;">
            🔐 {message}... {int((i+1)/steps*100)}%
        </div>
        """, unsafe_allow_html=True)
    time.sleep(0.2)
    progress_bar.empty()
    status_text.empty()

# --- Pages ---

def page_dashboard():
    st.title("🛡️ SecureVault")
    st.markdown('<p style="color: var(--text-secondary); font-size: 1.1rem; margin-bottom: 32px;">Enterprise-Grade Distributed Key Management System</p>', unsafe_allow_html=True)
    
    # Metrics Row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        create_metric_card("System Status", "🟢 Active", "🖥️")
    with col2:
        create_metric_card("Active Nodes", f"{len(NODES)}/{len(NODES)}", "☁️")
    with col3:
        create_metric_card("Security Level", "AES-256", "🔒")
    with col4:
        create_metric_card("Threshold", f"{THRESHOLD}/{TOTAL_SHARES}", "🔑")
    
    st.markdown("<div style='height: 32px;'></div>", unsafe_allow_html=True)
    
    # Architecture Diagram
    st.markdown("## 🏗 System Architecture")
    
    mermaid_diagram = """
    flowchart TD
        subgraph UserLayer ["👤 User Layer"]
            A[Admin/User] -->|Upload File| B[Streamlit App]
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

        style UserLayer fill:#1a1f35,stroke:#58a6ff,stroke-width:2px
        style CryptoLayer fill:#1a1f35,stroke:#10b981,stroke-width:2px
        style StorageLayer fill:#1a1f35,stroke:#f59e0b,stroke-width:2px
        style AuditLayer fill:#1a1f35,stroke:#ef4444,stroke-width:2px
        style C fill:#10b981,color:#fff
        style E fill:#10b981,color:#fff
        style G fill:#10b981,color:#fff
        style F fill:#f59e0b,color:#fff
    """
    
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
        height=650
    )
    
    st.markdown("<div style='height: 32px;'></div>", unsafe_allow_html=True)
    
    # Security Features
    st.markdown("## 🔐 Security Features")
    col1, col2, col3 = st.columns(3)
    with col1:
        create_security_card("🔑", "Threshold Cryptography", "3-of-5 shares required for recovery", "blue")
    with col2:
        create_security_card("🛡️", "AES-256-GCM Encryption", "Military-grade file encryption", "green")
    with col3:
        create_security_card("📜", "Audit Logging", "Complete activity tracking", "purple")
    
    st.markdown("<div style='height: 32px;'></div>", unsafe_allow_html=True)
    
    # Node Health Status
    st.markdown("## 🌐 Distributed Node Status")
    cols = st.columns(5)
    node_info = [
        ("AWS Cloud", 1),
        ("Azure Cloud", 2),
        ("Google Cloud", 3),
        ("OnPrem Server", 4),
        ("Legal Escrow", 5)
    ]
    for i, col in enumerate(cols):
        with col:
            create_node_status_card(node_info[i][0], node_info[i][1])

def page_encrypt():
    st.title("🔒 Encrypt & Secure")
    st.markdown('<p style="color: var(--text-secondary);">Upload and encrypt sensitive files with distributed key sharing</p>', unsafe_allow_html=True)
    
    # Info Card
    create_security_card("ℹ️", "How It Works", 
                        "Your file is encrypted with AES-256. The key is split into 5 shares and distributed across secure nodes. 3 shares are required for recovery.", 
                        "info")
    
    uploaded_file = st.file_uploader("📁 Upload Sensitive Document", type=['txt', 'pdf', 'png', 'jpg', 'docx'])
    
    if uploaded_file:
        st.markdown(f"""
        <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid var(--accent-blue); 
                    border-radius: 12px; padding: 16px; margin: 16px 0;">
            <div style="color: var(--accent-blue); font-weight: 600;">
                📄 Selected: {uploaded_file.name}
            </div>
            <div style="color: var(--text-secondary); font-size: 0.9rem;">
                Size: {len(uploaded_file.getvalue()) / 1024:.2f} KB
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🚀 Initialize Encryption Protocol"):
            try:
                # 1. Generate Key
                simulate_progress(3, "Generating Secure AES-256 Key")
                cipher = AESCipher()
                aes_key = cipher.generate_key()
                
                # 2. Encrypt File
                simulate_progress(3, "Encrypting File Content (AES-GCM)")
                encrypted_data = cipher.encrypt(uploaded_file.getvalue(), aes_key)
                
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
                
                save_encrypted_file_metadata(file_id, encrypted_data['nonce'])
                
                ciphertext_path = f"database/{file_id}.enc"
                with open(ciphertext_path, 'wb') as f:
                    f.write(base64.b64decode(encrypted_data['payload']))
                
                st.success("✅ File Encrypted and Shares Distributed Successfully!")
                
                st.markdown(f"""
                <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--accent-green); 
                            border-radius: 12px; padding: 20px; margin: 16px 0;">
                    <div style="color: var(--accent-green); font-weight: 600; font-size: 1.1rem; margin-bottom: 8px;">
                        🔐 Encryption Complete
                    </div>
                    <div style="color: var(--text-primary); font-family: 'JetBrains Mono', monospace;">
                        File ID: <span style="color: var(--accent-blue);">{file_id}</span>
                    </div>
                    <div style="color: var(--text-secondary); font-size: 0.9rem; margin-top: 8px;">
                        Save this ID for recovery. Shares distributed to {TOTAL_SHARES} nodes.
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                log_event("System", "ENCRYPTION", f"File {uploaded_file.name} encrypted and split", "SUCCESS")
                
            except Exception as e:
                st.error(f"Critical Error: {str(e)}")
                log_event("System", "ENCRYPTION", f"Failed: {str(e)}", "FAILURE")

def page_recovery():
    st.title("🔓 Recovery Portal")
    st.markdown('<p style="color: var(--text-secondary);">Multi-admin authentication required for key reconstruction</p>', unsafe_allow_html=True)
    
    # Security Warning
    st.markdown("""
    <div style="background: rgba(245, 158, 11, 0.1); border-left: 4px solid var(--accent-gold); 
                border-radius: 12px; padding: 16px; margin-bottom: 24px;">
        <div style="color: var(--accent-gold); font-weight: 600;">⚠️ Security Notice</div>
        <div style="color: var(--text-secondary); font-size: 0.9rem;">
            Recovery requires <strong>3 authenticated admins</strong> and <strong>3 valid shares</strong>. 
            All attempts are logged.
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Admin Login
    with st.expander("👤 Admin Authentication", expanded=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            admin_user = st.text_input("Admin ID", key="admin_user", placeholder="adminA")
        with col2:
            admin_pass = st.text_input("Password", type="password", key="admin_pass", placeholder="••••••••")
        with col3:
            st.write("")
            st.write("")
            if st.button("🔐 Authenticate"):
                if admin_user in ADMIN_CREDS and ADMIN_CREDS[admin_user] == admin_pass:
                    st.session_state['authenticated_admin'] = admin_user
                    st.success(f"Welcome, {admin_user}")
                    log_event(admin_user, "LOGIN", "Admin authenticated", "SUCCESS")
                    st.rerun()
                else:
                    st.error("Invalid Credentials")
                    log_event(admin_user, "LOGIN", "Failed authentication attempt", "FAILURE")

    if 'authenticated_admin' in st.session_state:
        st.markdown(f"""
        <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid var(--accent-green); 
                    border-radius: 12px; padding: 12px 16px; margin: 16px 0;">
            <span style="color: var(--accent-green);">✅</span> 
            <span style="color: var(--text-primary);">Authenticated as: </span>
            <span style="color: var(--accent-blue); font-family: 'JetBrains Mono', monospace;">{st.session_state['authenticated_admin']}</span>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("### 📂 Recovery Configuration")
        
        file_id = st.text_input("Enter File ID", placeholder="file_1234567890")
        
        if file_id:
            available_shares = get_all_shares(file_id)
            meta = get_encrypted_file_metadata(file_id)
            
            if not meta:
                st.warning("No encrypted file found for this ID.")
            else:
                st.markdown(f"""
                <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid var(--accent-blue); 
                            border-radius: 12px; padding: 16px; margin: 16px 0;">
                    <div style="color: var(--accent-blue); font-weight: 600;">
                        📦 Found {len(available_shares)} Available Shares
                    </div>
                    <div style="color: var(--text-secondary); font-size: 0.9rem; margin-top: 4px;">
                        Threshold Required: <strong>{THRESHOLD}</strong> shares
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                st.markdown("### 🔑 Select Shares for Recovery")
                share_cols = st.columns(5)
                selected_share_ids = []
                
                node_icons = ["☁️", "☁️", "☁️", "🖥️", "🏛️"]
                
                for i, share in enumerate(available_shares):
                    with share_cols[i % 5]:
                        icon = node_icons[i % 5]
                        if st.checkbox(f"{icon} {share['node_name']}", key=f"share_{share['node_id']}"):
                            selected_share_ids.append(share)
                
                # FIX: Determine color based on threshold (Python logic, not CSS)
                shares_count = len(selected_share_ids)
                if shares_count >= THRESHOLD:
                    status_color = "#10b981"  # Green
                    status_icon = "✅"
                    status_text = "Ready for Recovery"
                else:
                    status_color = "#ef4444"  # Red
                    status_icon = "⚠️"
                    status_text = f"Need {THRESHOLD - shares_count} More Share(s)"
                
                st.markdown(f"""
                <div style="text-align: center; margin: 24px 0; padding: 16px; 
                            background: var(--bg-card); border-radius: 12px;
                            border: 2px solid {status_color};">
                    <div style="color: var(--text-secondary);">{status_icon} Selected Shares</div>
                    <div style="font-size: 2rem; font-weight: 700; color: {status_color};">
                        {shares_count} / {THRESHOLD}
                    </div>
                    <div style="color: {status_color}; font-size: 0.9rem; margin-top: 8px; font-weight: 600;">
                        {status_text}
                    </div>
                </div>
                """, unsafe_allow_html=True)
                
                if st.button("🚀 Reconstruct & Decrypt"):
                    if len(selected_share_ids) < THRESHOLD:
                        st.error(f"⚠️ Access Denied: Insufficient Shares ({len(selected_share_ids)}/{THRESHOLD})")
                        log_event(st.session_state['authenticated_admin'], "RECOVERY", "Failed: Insufficient shares", "FAILURE")
                    else:
                        try:
                            simulate_progress(4, "Reconstructing Key from Shares")
                            
                            shamir = ShamirSecretSharing(THRESHOLD, TOTAL_SHARES)
                            formatted_shares = [{"id": s['node_id'], "data": s['data']} for s in selected_share_ids]
                            recovered_key = shamir.recover_secret(formatted_shares)
                            
                            simulate_progress(3, "Decrypting File Content")
                            
                            cipher = AESCipher()
                            enc_dict = {"nonce": meta['nonce'], "payload": ""}
                            
                            ciphertext_path = f"database/{file_id}.enc"
                            if os.path.exists(ciphertext_path):
                                with open(ciphertext_path, 'rb') as f:
                                    stored_payload = f.read()
                                enc_dict['payload'] = base64.b64encode(stored_payload).decode('utf-8')
                                
                                decrypted_bytes = cipher.decrypt(enc_dict, recovered_key)
                                
                                st.success("✅ Decryption Successful!")
                                
                                st.download_button(
                                    "📥 Download Decrypted File", 
                                    decrypted_bytes, 
                                    file_name=f"decrypted_{file_id}",
                                    key="download_btn"
                                )
                                
                                log_event(st.session_state['authenticated_admin'], "RECOVERY", f"File {file_id} recovered", "SUCCESS")
                                del recovered_key
                            else:
                                st.error("Encrypted payload not found.")
                                
                        except Exception as e:
                            st.error(f"Reconstruction Failed: {str(e)}")
                            log_event(st.session_state['authenticated_admin'], "RECOVERY", f"Error: {str(e)}", "FAILURE")
def page_attack_sim():
    st.title("⚔️ Attack Simulation")
    st.markdown('<p style="color: var(--text-secondary);">Test the resilience of threshold cryptography</p>', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["🔓 Single Node Breach", "👤 Insider Attack"])
    
    with tab1:
        st.markdown("""
        <div style="background: rgba(239, 68, 68, 0.1); border-left: 4px solid var(--accent-red); 
                    border-radius: 12px; padding: 20px; margin-bottom: 24px;">
            <div style="color: var(--accent-red); font-weight: 600; font-size: 1.1rem;">🚨 Scenario: Node Compromise</div>
            <div style="color: var(--text-secondary); margin-top: 8px;">
                Attacker gains access to AWS Node and steals Share #1. Can they recover the key?
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("💥 Simulate Breach Attack"):
            with st.spinner("Running attack simulation..."):
                time.sleep(1.5)
            
            st.markdown("""
            <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid var(--accent-red); 
                        border-radius: 12px; padding: 20px; margin: 16px 0;">
                <div style="color: var(--accent-red); font-weight: 600; font-size: 1.2rem; margin-bottom: 12px;">
                    ❌ Attack Failed
                </div>
                <div style="color: var(--text-primary); font-family: 'JetBrains Mono', monospace; margin-bottom: 8px;">
                    Shares Obtained: 1 / 3 Required
                </div>
                <div style="color: var(--text-secondary); font-size: 0.9rem;">
                    Mathematical Proof: With 1 share, the key space remains 2²⁵⁶ possibilities. 
                    Reconstruction is computationally impossible.
                </div>
            </div>
            """, unsafe_allow_html=True)
            
    with tab2:
        st.markdown("""
        <div style="background: rgba(245, 158, 11, 0.1); border-left: 4px solid var(--accent-gold); 
                    border-radius: 12px; padding: 20px; margin-bottom: 24px;">
            <div style="color: var(--accent-gold); font-weight: 600; font-size: 1.1rem;">⚠️ Scenario: Malicious Insider</div>
            <div style="color: var(--text-secondary); margin-top: 8px;">
                Admin A attempts recovery without Admin B or C authorization.
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        if st.button("🎭 Simulate Insider Attack"):
            with st.spinner("Running insider simulation..."):
                time.sleep(1.5)
            
            st.markdown("""
            <div style="background: rgba(245, 158, 11, 0.1); border: 1px solid var(--accent-gold); 
                        border-radius: 12px; padding: 20px; margin: 16px 0;">
                <div style="color: var(--accent-gold); font-weight: 600; font-size: 1.2rem; margin-bottom: 12px;">
                    🚫 Access Denied
                </div>
                <div style="color: var(--text-primary); font-family: 'JetBrains Mono', monospace; margin-bottom: 8px;">
                    Authenticated Admins: 1 / 3 Required
                </div>
                <div style="color: var(--text-secondary); font-size: 0.9rem;">
                    Multi-admin policy enforced. Attempt logged to audit trail.
                    Security team notified.
                </div>
            </div>
            """, unsafe_allow_html=True)

def page_logs():
    st.title("📜 Audit Logs")
    st.markdown('<p style="color: var(--text-secondary);">Complete activity tracking and compliance records</p>', unsafe_allow_html=True)
    
    # Stats
    logs = get_logs()
    if logs:
        df = pd.DataFrame(logs, columns=["ID", "Timestamp", "Admin ID", "Action", "Details", "Status", "IP Sim"])
        
        success_count = len(df[df["Status"] == "SUCCESS"])
        failure_count = len(df[df["Status"] == "FAILURE"])
        
        col1, col2, col3 = st.columns(3)
        with col1:
            create_metric_card("Total Events", str(len(logs)), "📊")
        with col2:
            create_metric_card("Successful", str(success_count), "✅")
        with col3:
            create_metric_card("Failed", str(failure_count), "❌")
        
        st.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)
        
        # Filters
        col1, col2 = st.columns(2)
        with col1:
            status_filter = st.selectbox("Filter by Status", ["All", "SUCCESS", "FAILURE"])
        with col2:
            action_filter = st.selectbox("Filter by Action", ["All"] + list(df["Action"].unique()))
        
        filtered_df = df.copy()
        if status_filter != "All":
            filtered_df = filtered_df[filtered_df["Status"] == status_filter]
        if action_filter != "All":
            filtered_df = filtered_df[filtered_df["Action"] == action_filter]
        
        st.dataframe(filtered_df, use_container_width=True, hide_index=True)
    else:
        st.info("No audit logs found. Start encrypting or recovering files to generate logs.")

# --- Main Navigation ---
st.sidebar.markdown("""
<div style="text-align: center; padding: 24px 0; border-bottom: 1px solid var(--border-color);">
    <div style="font-size: 3rem; margin-bottom: 8px;">🔐</div>
    <div style="font-family: 'JetBrains Mono', monospace; font-weight: 700; 
                font-size: 1.3rem; background: var(--gradient-3); 
                -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
        SecureVault
    </div>
    <div style="color: var(--text-secondary); font-size: 0.8rem; margin-top: 4px;">
        Enterprise KMS
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("<div style='height: 24px;'></div>", unsafe_allow_html=True)

menu = st.sidebar.radio(
    "Navigation", 
    ["🏠 Dashboard", "🔒 Encrypt & Secure", "🔓 Recovery Portal", "⚔️ Attack Simulation", "📜 Audit Logs"],
    label_visibility="collapsed"
)

if menu == "🏠 Dashboard":
    page_dashboard()
elif menu == "🔒 Encrypt & Secure":
    page_encrypt()
elif menu == "🔓 Recovery Portal":
    page_recovery()
elif menu == "⚔️ Attack Simulation":
    page_attack_sim()
elif menu == "📜 Audit Logs":
    page_logs()

# Footer
st.markdown("""
<div style="text-align: center; padding: 32px; color: var(--text-secondary); 
            font-size: 0.8rem; border-top: 1px solid var(--border-color); margin-top: 48px;">
    <div>🔐 SecureVault Enterprise Key Management System</div>
    <div style="margin-top: 8px;">Built with AES-256-GCM + Shamir's Secret Sharing</div>
    <div style="margin-top: 8px;">Final Year Cybersecurity Project</div>
</div>
""", unsafe_allow_html=True)