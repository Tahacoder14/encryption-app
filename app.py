import streamlit as st
import base64
import hashlib
import requests
from cryptography.fernet import Fernet
import secrets
import string
from streamlit_lottie import st_lottie
from streamlit_extras.stylable_container import stylable_container

# --- 1. CORE FUNCTIONS ---

def derive_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt(data: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(data)

def decrypt(token: bytes, key: bytes) -> bytes | None:
    try:
        return Fernet(key).decrypt(token)
    except Exception:
        return None

def generate_secure_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def load_lottieurl(url: str):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

# --- NEW: CALLBACK FUNCTION TO FIX THE StreamlitAPIException ---
def generate_and_store_password():
    """Generates a password and stores it in session_state.
    This is the correct way to update widget state.
    """
    st.session_state.password_encrypt = generate_secure_password()


# --- 2. STREAMLIT PAGE CONFIGURATION & STYLING ---

st.set_page_config(
    page_title="Source Data Encryption Module",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="auto"
)

# (CSS remains the same, no changes needed here)
st.markdown("""
<style>
    /* General body styling */
    .main { background-color: #09101d; color: #ffffff; }
    /* Responsive padding */
    [data-testid="stAppViewContainer"] { padding: 2rem 5rem; }
    @media (max-width: 768px) { [data-testid="stAppViewContainer"] { padding: 1rem 1.5rem; } }
    /* Hide helper text */
    [data-testid="stTextArea"] .st-helper { display: none; }
    /* Tab Styling */
    .stTabs [data-baseweb="tab-list"] { gap: 24px; padding-bottom: 2px; }
    .stTabs [data-baseweb="tab"] { height: 50px; white-space: pre-wrap; background-color: transparent; border-radius: 8px 8px 0px 0px; gap: 1px; padding: 10px 20px; border-bottom: 2px solid transparent; transition: all 0.2s ease-in-out; }
    .stTabs [aria-selected="true"] { background-color: #1d2637; font-weight: bold; border-bottom: 2px solid #89f7fe; }
    .stTabs [data-baseweb="tab"]:hover { background-color: #1d2637; }
    /* Button Styling */
    .stButton>button { background-color: #89f7fe; color: #09101d; border-radius: 25px; border: 2px solid #89f7fe; font-weight: bold; transition: all 0.3s ease-in-out; padding: 8px 20px; }
    .stButton>button:hover { background-color: transparent; color: #89f7fe; transform: scale(1.05); }
    .stButton>button:active { transform: scale(0.95); }
    /* Footer Styling */
    .footer { width: 100%; background-color: transparent; color: #8892b0; text-align: center; padding: 20px 0; margin-top: 40px; font-size: 14px; border-top: 1px solid #1d2637; }
</style>""", unsafe_allow_html=True)


# --- 3. STREAMLIT UI LAYOUT ---

# Header with Lottie Animation
lottie_url = "https://assets10.lottiefiles.com/packages/lf20_gjmecwoc.json"
lottie_json = load_lottieurl(lottie_url)
col1_title, col2_title = st.columns([1, 4])
with col1_title:
    if lottie_json:
        st_lottie(lottie_json, speed=1, height=100, key="initial")
with col2_title:
    st.title("Source Data Encryption Module")
    st.write("A secure, modern, and user-friendly tool to encrypt your sensitive data and files.")
st.markdown("---")

# Tabs
tab_text, tab_file, tab_about = st.tabs(["🔒 Text", "📁 File", "💡 About"])

# Text Encryption/Decryption Tab
with tab_text:
    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.subheader("Encrypt Text")
        with stylable_container("encrypt_box", css_styles="{border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 10px; padding: 20px;}"):
            plaintext = st.text_area("Enter text to encrypt:", height=150, key="plaintext_input", placeholder="Your secret message goes here...")
            # The password_encrypt key is now correctly managed by the callback
            password_encrypt = st.text_input("Enter a strong password:", type="password", key="password_encrypt")

            # --- FIX #1: Using on_click callback for the button ---
            st.button(
                "Generate Secure Password",
                on_click=generate_and_store_password, # Call the function here
                key="gen_pass_encrypt"
            )

            if st.button("Encrypt Text", key="encrypt_button", use_container_width=True):
                if plaintext and password_encrypt:
                    derived_key = derive_key(password_encrypt)
                    encrypted_text = encrypt(plaintext.encode(), derived_key)
                    st.session_state.encrypted_text = encrypted_text.decode()
                    st.success("✅ Encryption Successful!")
                else:
                    st.warning("⚠️ Please provide both text and a password.")

        if "encrypted_text" in st.session_state and st.session_state.encrypted_text:
            st.text_area("Encrypted Text (copy this):", value=st.session_state.encrypted_text, height=150, key="encrypted_output")
            
            # --- FIX #2: Using robust Javascript for copy-to-clipboard ---
            if st.button("📋 Copy to Clipboard", key="copy_encrypt"):
                st.toast("Copied to clipboard!", icon='✅')
                # Using backticks (`) in Javascript handles all special characters safely
                st.components.v1.html(f"<script>navigator.clipboard.writeText(`{st.session_state.encrypted_text}`);</script>", height=0)

    # (The Decrypt column has no changes)
    with col2:
        st.subheader("Decrypt Text")
        with stylable_container("decrypt_box", css_styles="{border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 10px; padding: 20px;}"):
            ciphertext = st.text_area("Paste encrypted text here:", height=150, key="ciphertext_input")
            password_decrypt = st.text_input("Enter the decryption password:", type="password", key="password_decrypt")

            if st.button("Decrypt Text", key="decrypt_button", use_container_width=True):
                if ciphertext and password_decrypt:
                    try:
                        derived_key = derive_key(password_decrypt)
                        decrypted_bytes = decrypt(ciphertext.encode(), derived_key)
                        st.session_state.decrypted_text = decrypted_bytes.decode() if decrypted_bytes else ""
                        if decrypted_bytes: st.success("✅ Decryption Successful!")
                        else: st.error("❌ Decryption Failed. Check password or data.")
                    except Exception:
                        st.error("❌ Invalid data format.")
                        st.session_state.decrypted_text = ""
                else:
                    st.warning("⚠️ Please provide encrypted text and a password.")

        if "decrypted_text" in st.session_state and st.session_state.decrypted_text:
            st.text_area("Decrypted Text:", value=st.session_state.decrypted_text, height=150, key="decrypted_output", disabled=True)

# (The File and About tabs have no changes)
with tab_file:
    st.subheader("Encrypt or Decrypt Files")
    file_col1, file_col2 = st.columns(2, gap="large")
    with file_col1:
        st.markdown("#### Encrypt a File")
        uploaded_file = st.file_uploader("Choose a file to encrypt", key="file_uploader")
        file_password_encrypt = st.text_input("Enter a password for the file:", type="password", key="file_password_encrypt")
        if st.button("Encrypt File", key="encrypt_file_button", use_container_width=True):
            if uploaded_file and file_password_encrypt:
                file_bytes = uploaded_file.getvalue()
                derived_key = derive_key(file_password_encrypt)
                encrypted_file_bytes = encrypt(file_bytes, derived_key)
                st.success("File encrypted successfully!")
                st.download_button("Download Encrypted File", encrypted_file_bytes, f"encrypted_{uploaded_file.name}", "application/octet-stream", use_container_width=True)
            else:
                st.warning("⚠️ Please upload a file and enter a password.")
    with file_col2:
        st.markdown("#### Decrypt a File")
        encrypted_file = st.file_uploader("Choose an encrypted file to decrypt", key="encrypted_file_uploader")
        file_password_decrypt = st.text_input("Enter the file's password:", type="password", key="file_password_decrypt")
        if st.button("Decrypt File", key="decrypt_file_button", use_container_width=True):
            if encrypted_file and file_password_decrypt:
                encrypted_bytes = encrypted_file.getvalue()
                derived_key = derive_key(file_password_decrypt)
                decrypted_file_bytes = decrypt(encrypted_bytes, derived_key)
                if decrypted_file_bytes:
                    st.success("File decrypted successfully!")
                    st.download_button("Download Decrypted File", decrypted_file_bytes, f"decrypted_{encrypted_file.name.replace('encrypted_', '')}", "application/octet-stream", use_container_width=True)
                else:
                    st.error("❌ Decryption Failed. Check password or file integrity.")
            else:
                st.warning("⚠️ Please upload an encrypted file and its password.")
with tab_about:
    st.subheader("Understanding the Cryptography")
    st.markdown("""This application uses a robust, industry-standard combination of cryptographic techniques to keep your data secure. Here’s a breakdown: - **Streamlit**: Creates this interactive web interface. - **Hashlib (`SHA-256`)**: Used for **Key Derivation**. Your password is not used directly as the key. Instead, it's passed through the SHA-256 hashing algorithm to produce a secure, fixed-size 256-bit (32-byte) key. - **Cryptography (`Fernet`)**: The core engine for encryption. Fernet guarantees that a message encrypted using it cannot be manipulated or read without the correct key. It is a form of **Symmetric Authenticated Cryptography**. - **Lottie**: The beautiful animations are lightweight, scalable JSON files rendered in real-time.""")

# Footer
st.markdown("""<div class="footer"><p>Source Data Encryption Module by Taha | Built with ❤️ using Streamlit & Python</p></div>""", unsafe_allow_html=True)