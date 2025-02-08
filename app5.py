import streamlit as st
import pandas as pd
import re
import json
import random
import os
import hashlib

# Local Database File
DB_FILE = "local_db.json"

def load_db():
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "r") as f:
            return json.load(f)
    return {"users": [], "transactions": []}

def save_db(db):
    with open(DB_FILE, "w") as f:
        json.dump(db, f, indent=4)

db = load_db()

st.set_page_config(page_title="Decentralized Fraud Detection System", layout="wide")

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'is_admin' not in st.session_state:
    st.session_state.is_admin = False
if 'aadhar_verified' not in st.session_state:
    st.session_state.aadhar_verified = False
if 'fraud_alerts' not in st.session_state:
    st.session_state.fraud_alerts = []
if 'pan_verified' not in st.session_state:
    st.session_state.pan_verified = False
if 'bank_verified' not in st.session_state:
    st.session_state.bank_verified = False
if 'credit_score' not in st.session_state:
    st.session_state.credit_score = random.randint(300, 900)
if 'otp_verified' not in st.session_state:
    st.session_state.otp_verified = False
if 'gst_verified' not in st.session_state:
    st.session_state.gst_verified = False

def hash_password(password):
    # Hash the password using SHA-256
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def check_password(stored_hash, password):
    # Check if the password matches the stored hash
    return stored_hash == hashlib.sha256(password.encode('utf-8')).hexdigest()

def register_user():
    st.subheader("📝 Register")
    username = st.text_input("Enter a username:")
    email = st.text_input("Enter your email:")
    password = st.text_input("Enter a password:", type="password")

    if st.button("Register"):
        if any(user['email'] == email for user in db['users']):
            st.error("Email already exists. Choose a different one.")
            return

        hashed_password = hash_password(password)
        user_data = {'id': str(len(db['users']) + 1), 'username': username, 'email': email, 'password_hash': hashed_password, 'role': 'user'}
        db['users'].append(user_data)
        save_db(db)
        st.success("✅ Registration successful! Please log in.")

def login_user():
    st.subheader("🔑 Login")
    email = st.text_input("Enter your email:")
    password = st.text_input("Enter your password:", type="password")

    if st.button("Login"):
        user = next((u for u in db['users'] if u['email'] == email), None)
        if user and check_password(user['password_hash'], password):
            st.session_state.logged_in = True
            st.session_state.username = user['username']
            st.session_state.user_id = user['id']
            st.session_state.is_admin = (user['role'] == 'admin')
            st.success("✅ Login successful!")
            st.rerun()
        else:
            st.error("❌ Invalid email or password.")

def logout_user():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.user_id = None
    st.session_state.is_admin = False
    st.rerun()

if not st.session_state.logged_in:
    st.sidebar.title("🔐 User Authentication")
    auth_option = st.sidebar.radio("Choose an option:", ["Login", "Register"])
    if auth_option == "Login":
        login_user()
    else:
        register_user()
    st.stop()

st.title(f"🚀 Welcome, {st.session_state.username}!")

st.sidebar.button("Logout", on_click=logout_user)

st.subheader("📄 PAN & GST Verification")

def verify_pan():
    pan_number = st.text_input("Enter PAN Number (Format: ABCDE1234F):")
    if st.button("Verify PAN"):
        if re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', pan_number):
            st.success("✅ PAN Verified Successfully!")
            st.session_state.pan_verified = True
        else:
            st.error("❌ Invalid PAN Number. Please enter a valid PAN.")

def verify_gst():
    gst_number = st.text_input("Enter GST Number (Format: 22AAAAA0000A1Z5):")
    if st.button("Verify GST"):
        if re.match(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9][Z][0-9]$', gst_number):
            st.success("✅ GST Verified Successfully!")
            st.session_state.gst_verified = True
        else:
            st.error("❌ Invalid GST Number. Please enter a valid GST.")

verify_pan()
verify_gst()

st.subheader("📋 Transaction Reports")

def load_transactions():
    return [t for t in db['transactions'] if t['user_id'] == st.session_state.user_id]

transactions = load_transactions()
if transactions:
    df = pd.DataFrame(transactions)
    df = df[['id', 'status', 'upi', 'amount', 'location']]
    df.rename(columns={'id': 'Transaction ID'}, inplace=True)
    st.dataframe(df, width=700)
    
    if st.session_state.is_admin:
        transaction_id = st.text_input("Enter Transaction ID to Approve:")
        if st.button("Approve Transaction"):
            for t in db['transactions']:
                if t['id'] == transaction_id:
                    t['status'] = 'Approved'
                    save_db(db)
                    st.success("Transaction Approved!")
                    st.rerun()
else:
    st.info("No transactions available.")

def add_transaction():
    upi_id = st.text_input("Enter UPI ID for transaction:")
    amount = st.number_input("Enter Amount:", min_value=1, step=1)
    location = st.text_input("Enter Transaction Location:")

    if st.button("Submit UPI"):
        if any(upi_id.endswith(handle) for handle in ["@sbi", "@icici", "@hdfcbank", "@okaxis", "@kotak", "@pnb","@rbl","@abfspay","@idbi","@bandhan","@indus"
    "@okicici","@paytm","@phonepe","@upi","@ptyes","@uco","	@yesg","@hsbc","@indianbank","@allbank","@inhdfc","@dlb","@freecharge","@citi","@citigold","@kbl"
    "@BARODAMPAY","@abfspay","@axisbank","@aubank","@sbi","@federal","@dbs"]):
            new_transaction = {'id': str(len(db['transactions']) + 1), 'user_id': st.session_state.user_id, 'status': 'Pending', 'upi': upi_id, 'amount': amount, 'location': location}
            db['transactions'].append(new_transaction)
            save_db(db)
            st.success("Transaction added successfully!")
            st.rerun()
        else:
            st.error("Invalid UPI ID. Please enter a valid UPI ID based in India.")

add_transaction()

st.sidebar.markdown("### 📥 Export Transactions")
if st.sidebar.button("Download CSV"):
    df.to_csv("transactions.csv", index=False)
    st.sidebar.success("Transactions exported as CSV!")
