import streamlit as st
import base64
import hashlib
from cryptography.fernet import Fernet
import secrets # New import for generating secure passwords
import string   # New import for password character set
from streamlit_extras.stylable_container import stylable_container # For better styling
from streamlit_extras.keyboard_url import keyboard_to_url # Just for fun!
from streamlit_extras.add_vertical_space import add_vertical_space

# --- 1. CORE ENCRYPTION & DECRYPTION FUNCTIONS ---

def derive_key(password: str) -> bytes:
    """Derives a 32-byte key from a password using SHA-256 for Fernet."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypts bytes using the derived Fernet key."""
    return Fernet(key).encrypt(data)

def decrypt(token: bytes, key: bytes) -> bytes | None:
    """Decrypts a Fernet token using the key. Returns None on failure."""
    try:
        return Fernet(key).decrypt(token)
    except Exception:
        return None

# --- NEW FEATURE: SECURE PASSWORD GENERATOR ---
def generate_secure_password(length: int = 16) -> str:
    """Generates a cryptographically secure random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(length))
    return password

# --- 2. STREAMLIT PAGE CONFIGURATION & STYLING ---

st.set_page_config(
    page_title="Source Data Encryption Module",
    page_icon="🔐",
    layout="wide", # Changed to wide for better layout
    initial_sidebar_state="auto"
)

# Custom CSS for a more polished look
st.markdown("""
<style>
    /* General body styling from config.toml is primary */
    .main {
        background-color: #09101d;
        color: #ffffff;
    }
    
    /* Hide the "Press Ctrk+Enter to apply" tooltip */
    [data-testid="stTextArea"] .st-helper {
        display: none;
    }
    
    /* Style for the tabs */
    .stTabs [data-baseweb="tab-list"] {
		gap: 24px;
	}
    .stTabs [data-baseweb="tab"] {
		height: 50px;
        white-space: pre-wrap;
		background-color: transparent;
		border-radius: 8px 8px 0px 0px;
		gap: 1px;
		padding: 10px 15px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1d2637;
        font-weight: bold;
    }

    /* Custom button styling */
    .stButton>button {
        background-color: #89f7fe;
        color: #09101d;
        border-radius: 25px;
        border: 2px solid #89f7fe;
        font-weight: bold;
        transition: all 0.3s ease-in-out;
        padding: 8px 20px;
    }
    .stButton>button:hover {
        background-color: transparent;
        color: #89f7fe;
        transform: scale(1.05);
    }
    .stButton>button:active {
        transform: scale(0.95);
    }
    
    /* Footer styling */
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: #09101d;
        color: #8892b0;
        text-align: center;
        padding: 10px;
        font-size: 14px;
        border-top: 1px solid #1d2637;
    }
</style>""", unsafe_allow_html=True)


# --- 3. STREAMLIT UI LAYOUT ---

st.title("🔐 Source Data Encryption Module")
st.write("A secure, modern, and user-friendly tool to encrypt and decrypt your sensitive data and files.")
add_vertical_space(1)

# Create tabs for different functionalities
tab_text, tab_file, tab_about = st.tabs(["🔒 Text Encryption/Decryption", "📁 File Encryption/Decryption", "💡 How It Works"])

# --- TEXT ENCRYPTION/DECRYPTION TAB ---
with tab_text:
    col1, col2 = st.columns(2, gap="large")

    with col1:
        st.subheader("Encrypt Your Text")
        with stylable_container(
            "encrypt_box",
            css_styles="""
            {
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                padding: 20px;
            }
            """
        ):
            plaintext = st.text_area("Enter text to encrypt:", height=150, key="plaintext_input", placeholder="Your secret message goes here...")
            password_encrypt = st.text_input("Enter a strong password:", type="password", key="password_encrypt")

            # NEW: Password Generator Button
            if st.button("Generate Secure Password", key="gen_pass_encrypt"):
                st.session_state.password_encrypt = generate_secure_password()
                st.rerun() # Rerun to update the text input value

            if st.button("Encrypt Text", key="encrypt_button", use_container_width=True):
                if plaintext and password_encrypt:
                    derived_key = derive_key(password_encrypt)
                    encrypted_text = encrypt(plaintext.encode(), derived_key)
                    st.session_state.encrypted_text = encrypted_text.decode()
                    st.success("✅ Encryption Successful!")
                else:
                    st.warning("⚠️ Please provide both text and a password.")
        
        if "encrypted_text" in st.session_state:
            st.text_area("Encrypted Text (copy this):", value=st.session_state.encrypted_text, height=150, key="encrypted_output")
            # NEW: Copy to Clipboard Button
            if st.button("📋 Copy to Clipboard", key="copy_encrypt"):
                st.toast("Copied to clipboard!", icon='✅')
                st.components.v1.html(f"<script>navigator.clipboard.writeText('{st.session_state.encrypted_text.replace(chr(10), ' ').replace(chr(13), ' ')}');</script>", height=0)


    with col2:
        st.subheader("Decrypt Your Text")
        with stylable_container(
            "decrypt_box",
            css_styles="""
            {
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                padding: 20px;
            }
            """
        ):
            ciphertext = st.text_area("Paste encrypted text here:", height=150, key="ciphertext_input")
            password_decrypt = st.text_input("Enter the decryption password:", type="password", key="password_decrypt")

            if st.button("Decrypt Text", key="decrypt_button", use_container_width=True):
                if ciphertext and password_decrypt:
                    try:
                        derived_key = derive_key(password_decrypt)
                        decrypted_bytes = decrypt(ciphertext.encode(), derived_key)
                        if decrypted_bytes:
                            st.session_state.decrypted_text = decrypted_bytes.decode()
                            st.success("✅ Decryption Successful!")
                        else:
                            st.error("❌ Decryption Failed. Check password or data.")
                            st.session_state.decrypted_text = ""
                    except Exception as e:
                        st.error(f"❌ Invalid data format. Error: {e}")
                        st.session_state.decrypted_text = ""
                else:
                    st.warning("⚠️ Please provide both encrypted text and a password.")
        
        if "decrypted_text" in st.session_state and st.session_state.decrypted_text:
            st.text_area("Decrypted Text:", value=st.session_state.decrypted_text, height=150, key="decrypted_output", disabled=True)

# --- NEW: FILE ENCRYPTION/DECRYPTION TAB ---
with tab_file:
    st.subheader("Encrypt or Decrypt Files")
    
    file_col1, file_col2 = st.columns(2, gap="large")
    
    with file_col1:
        with stylable_container(
            "encrypt_file_box",
            css_styles="""
            {
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                padding: 20px;
                background-color: #1d2637;
            }
            """
        ):
            st.markdown("#### Encrypt a File")
            uploaded_file = st.file_uploader("Choose a file to encrypt", key="file_uploader")
            file_password_encrypt = st.text_input("Enter a password for the file:", type="password", key="file_password_encrypt")

            if st.button("Encrypt File", key="encrypt_file_button", use_container_width=True):
                if uploaded_file and file_password_encrypt:
                    file_bytes = uploaded_file.getvalue()
                    derived_key = derive_key(file_password_encrypt)
                    encrypted_file_bytes = encrypt(file_bytes, derived_key)
                    
                    st.success("File encrypted successfully!")
                    
                    st.download_button(
                        label="Download Encrypted File",
                        data=encrypted_file_bytes,
                        file_name=f"encrypted_{uploaded_file.name}",
                        mime="application/octet-stream",
                        use_container_width=True
                    )
                else:
                    st.warning("⚠️ Please upload a file and enter a password.")

    with file_col2:
        with stylable_container(
            "decrypt_file_box",
            css_styles="""
            {
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                padding: 20px;
                background-color: #1d2637;
            }
            """
        ):
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
                        st.download_button(
                            label="Download Decrypted File",
                            data=decrypted_file_bytes,
                            file_name=f"decrypted_{encrypted_file.name.replace('encrypted_', '')}",
                            mime="application/octet-stream",
                            use_container_width=True
                        )
                    else:
                        st.error("❌ Decryption Failed. Check the password or file integrity.")
                else:
                    st.warning("⚠️ Please upload an encrypted file and enter its password.")

# --- HOW IT WORKS TAB ---
with tab_about:
    st.subheader("Understanding the Cryptography")
    st.markdown("""
    This application uses a robust, industry-standard combination of cryptographic techniques to keep your data secure. Here’s a breakdown of the libraries and the process:

    - **Streamlit & Streamlit-Extras:** Creates this interactive and user-friendly web interface with enhanced components.
    - **Hashlib (`SHA-256`):** This is used for **Key Derivation**. Your password is not used directly as the encryption key. Instead, it's passed through the SHA-256 hashing algorithm to produce a secure, fixed-size 256-bit (32-byte) key. This prevents issues with weak passwords and ensures the key is the correct length.
    - **Base64:** The derived key from `hashlib` is encoded into a URL-safe Base64 format, which is a requirement for the `cryptography` library's Fernet implementation.
    - **Cryptography (`Fernet`):** This is the core engine for encryption. Fernet guarantees that a message encrypted using it cannot be manipulated or read without the correct key. It is a form of **Symmetric Authenticated Cryptography**.
        - *Symmetric*: The same key is used to both encrypt and decrypt the data.
        - *Authenticated*: The encrypted message includes a signature (HMAC) that is verified during decryption. If the signature is invalid, it means the data has been tampered with, and decryption will fail.
    - **Secrets:** This Python module is used to generate cryptographically strong random numbers, which we use for the "Generate Secure Password" feature, ensuring high-quality, unpredictable passwords.
    """)

# --- NEW: FOOTER ---
st.markdown(
    """
    <div class="footer">
        <p>Source Data Encryption Module by Taha | Built with ❤️ using Streamlit & Python</p>
    </div>
    """, unsafe_allow_html=True
)