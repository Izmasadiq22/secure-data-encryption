import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64
import uuid

# 🌟 Initialize session states
if 'attempts' not in st.session_state:
    st.session_state.attempts = 0
if 'vault' not in st.session_state:
    st.session_state.vault = {}
if 'active_tab' not in st.session_state:
    st.session_state.active_tab = "Dashboard"
if 'last_try_time' not in st.session_state:
    st.session_state.last_try_time = 0

# 🔐 Utility functions
def encrypt_key(secret):
    return hashlib.sha256(secret.encode()).hexdigest()

def create_fernet_key(secret):
    key_digest = hashlib.sha256(secret.encode()).digest()
    return base64.urlsafe_b64encode(key_digest[:32])

def secure_encrypt(msg, secret):
    token = create_fernet_key(secret)
    cipher = Fernet(token)
    return cipher.encrypt(msg.encode()).decode()

def secure_decrypt(cipher_text, secret, record_id):
    try:
        hashed_key = encrypt_key(secret)
        if record_id in st.session_state.vault and st.session_state.vault[record_id]["key_hash"] == hashed_key:
            token = create_fernet_key(secret)
            f = Fernet(token)
            decrypted = f.decrypt(cipher_text.encode()).decode()
            st.session_state.attempts = 0
            return decrypted
        else:
            st.session_state.attempts += 1
            st.session_state.last_try_time = time.time()
            return None
    except:
        st.session_state.attempts += 1
        st.session_state.last_try_time = time.time()
        return None

def get_record_id():
    return str(uuid.uuid4())

def reset_attempts():
    st.session_state.attempts = 0

def navigate_to(tab):
    st.session_state.active_tab = tab

# UI Starts Here
st.title("🧊 Secure Data Encryption System")

# Sidebar Navigation
pages = ["Dashboard", "Add Entry", "View Entry", "Re-authenticate"]
selected = st.sidebar.selectbox("🔎 Navigate", pages, index=pages.index(st.session_state.active_tab))
st.session_state.active_tab = selected

# Auto-redirect on too many failures
if st.session_state.attempts >= 3:
    st.session_state.active_tab = "Re-authenticate"
    st.warning("⛔ Too many wrong tries. Please re-authorize.")

# 🏠 Dashboard
if st.session_state.active_tab == "Dashboard":
    st.header("✨ Welcome to My Data Encryption System")
    st.write("Store and retrieve your text securely using encryption and unique keys.")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("➕ Add New Entry", use_container_width=True):
            navigate_to("Add Entry")
    with col2:
        if st.button("🔓 View Stored Entry", use_container_width=True):
            navigate_to("View Entry")

    st.info(f"📁 You currently have {len(st.session_state.vault)} records stored.")

# 📂 Add Entry Page
elif st.session_state.active_tab == "Add Entry":
    st.header("🔐 Encrypt & Store Text")
    content = st.text_area("What do you want to save?")
    key1 = st.text_input("Set a Secret Key", type="password")
    key2 = st.text_input("Re-enter Secret Key", type="password")

    if st.button("🔒 Encrypt & Store"):
        if content and key1 and key2:
            if key1 != key2:
                st.error("🚫 Secret keys do not match!")
            else:
                record_id = get_record_id()
                encrypted = secure_encrypt(content, key1)
                hashed = encrypt_key(key1)

                st.session_state.vault[record_id] = {
                    "cipher_text": encrypted,
                    "key_hash": hashed
                }

                st.success("✅ Your data has been securely saved.")
                st.code(record_id, language="text")
                st.info("🧾 Keep this ID safe! You’ll need it to decrypt your data later.")
        else:
            st.error("⚠️ Please fill out all fields.")

# 🔍 View Entry Page
elif st.session_state.active_tab == "View Entry":
    st.header("📥 Retrieve & Decrypt Entry")
    remaining = 3 - st.session_state.attempts
    st.info(f"⏳ Remaining attempts: {remaining}")

    entry_id = st.text_input("Enter Your Entry ID")
    secret_key = st.text_input("Enter Secret Key", type="password")

    if st.button("🗝️ Decrypt Now"):
        if entry_id and secret_key:
            if entry_id in st.session_state.vault:
                encrypted_msg = st.session_state.vault[entry_id]["cipher_text"]
                result = secure_decrypt(encrypted_msg, secret_key, entry_id)

                if result:
                    st.success("🟢 Decryption Successful!")
                    st.markdown("**Here’s your message:**")
                    st.code(result, language="text")
                else:
                    st.error(f"❌ Incorrect key! Tries left: {3 - st.session_state.attempts}")
            else:
                st.error("🔍 Entry ID not found.")

            if st.session_state.attempts >= 3:
                st.warning("⚠️ Too many failed attempts. Going to Login page.")
                st.session_state.active_tab = "Re-authenticate"
                st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

# 🔑 Re-authenticate
elif st.session_state.active_tab == "Re-authenticate":
    st.header("🔐 Admin Login")

    if time.time() - st.session_state.last_try_time < 10:
        wait = int(10 - (time.time() - st.session_state.last_try_time))
        st.warning(f"⏳ Wait {wait} seconds to try again.")
    else:
        admin_key = st.text_input("Enter Admin Password", type="password")
        if st.button("✅ Authenticate"):
            if admin_key == "admin123":  # You can change this
                reset_attempts()
                st.success("🔓 Access granted!")
                st.session_state.active_tab = "Dashboard"
                st.rerun()
            else:
                st.error("❌ Invalid password!")

# 📌 Footer
st.markdown("---")
st.markdown("🔐 Secure Data Encryption System")
