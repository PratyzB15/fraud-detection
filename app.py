import streamlit as st
import pandas as pd
import re
import google.generativeai as genai
# import easyocr  # If needed
from PIL import Image
import io
import time
import random
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

# MongoDB connection (REPLACE with your connection string)
client = MongoClient("mongodb+srv://theabhik2020:hoAxx927XbF0Yp3c@cluster0.ko8v5.mongodb.net/pythonTest")
db = client["user_db"]
users = db["users"]

# Set Streamlit page config
st.set_page_config(page_title="Decentralized Fraud Detection System", layout="wide")

# Set up Gemini API key
genai.configure(api_key="AIzaSyDZfMZN51fqIhxjtSkkAM6eMDBvYdcCuvk")  # Replace with your actual key

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'user_id' not in st.session_state:  # Store user ID
    st.session_state.user_id = None  # Initialize to None
if 'users' not in st.session_state:
    st.session_state.users = {} # this line is not required

# User Registration
def register_user():
    st.subheader("📝 Register")
    username = st.text_input("Enter a username:")
    email = st.text_input("Enter your email:") # Add email input
    password = st.text_input("Enter a password:", type="password")

    if st.button("Register"):
        if users.find_one({'email': email}): # Check if email exists
            st.error("Email already exists. Choose a different one.")
            return

        hashed_password = generate_password_hash(password)
        user_data = {
            'username': username,
            'email': email,
            'password_hash': hashed_password
        }

        try:
            result = users.insert_one(user_data)
            st.success("✅ Registration successful! Please log in.")
        except Exception as e:
            st.error(f"An error occurred during registration: {e}")

# User Login
def login_user():
    st.subheader("🔑 Login")
    email = st.text_input("Enter your email:") # Login with email
    password = st.text_input("Enter your password:", type="password")

    if st.button("Login"):
        user = users.find_one({'email': email})
        if user and check_password_hash(user['password_hash'], password):
            st.session_state.logged_in = True
            st.session_state.username = user['username']
            st.session_state.user_id = str(user['_id']) # Store the user's ID
            st.success("✅ Login successful!")
            st.rerun()
        else:
            st.error("❌ Invalid email or password. Try again.")

# Logout
def logout_user():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.user_id = None # Clear user ID
    st.rerun()

# Show login/register page if not logged in
if not st.session_state.logged_in:
    st.sidebar.title("🔐 User Authentication")
    auth_option = st.sidebar.radio("Choose an option:", ["Login", "Register"])
    if auth_option == "Login":
        login_user()
    else:
        register_user()
    st.stop()

#... (rest of your Streamlit code: PAN/GST verification, transactions, etc.)

st.title(f"🚀 Welcome, {st.session_state.username}!")
st.sidebar.button("Logout", on_click=logout_user, key="logout_button")


# Initialize session state for various verifications and transactions
if 'transactions' not in st.session_state:
    st.session_state.transactions = []
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

# List of valid UPI handles in India
valid_upi_handles = {"@sbi", "@imobile", "@pockets", "@ezeepay", "@eazypay", "@icici", "@okicici",
    "@hdfcbank", "@payzapp", "@okhdfcbank", "@rajgovhdfcbank", "@mahb", "@kotak",
    "@kaypay", "@kmb", "@kmbl", "@yesbank", "@yesbankltd", "@ubi", "@united",
    "@utbi", "@idbi", "@idbibank", "@hsbc", "@pnb", "@centralbank", "@cbin",
    "@cboi", "@cnrb", "@barodampay","@okaxis"}

def is_valid_upi(upi_id):
    return any(upi_id.endswith(handle) for handle in valid_upi_handles)

# PAN Verification
def verify_pan():
    pan_number = st.text_input("Enter PAN Number (Format: ABCDE1234F):")
    if st.button("Verify PAN"):
        if re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', pan_number):
            st.success("✅ PAN Verified Successfully!")
            st.session_state.pan_verified = True
        else:
            st.error("❌ Invalid PAN Number. Please enter a valid PAN.")

# GST Verification
def verify_gst():
    gst_number = st.text_input("Enter GST Number (Format: 22AAAAA0000A1Z5):")
    if st.button("Verify GST"):
        if re.match(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9][Z][0-9]$', gst_number):
            st.success("✅ GST Verified Successfully!")
            st.session_state.gst_verified = True
        else:
            st.error("❌ Invalid GST Number. Please enter a valid GST.")

# st.title(f"🚀 Welcome, {st.session_state.username}!")
# st.sidebar.button("Logout", on_click=logout_user)

# PAN & GST Verification
st.subheader("📄 PAN & GST Verification")
verify_pan()
verify_gst()

# Display transactions as a table
st.subheader("📋 Transaction Reports")
if st.session_state.transactions:
    df = pd.DataFrame(st.session_state.transactions)
    st.dataframe(df, width=700)
    for i, row in df.iterrows():
        col1, col2, col3, col4, col5, col6 = st.columns([2, 2, 2, 2, 2, 2])
        col1.write(f"**{row['id']}**")
        col2.write(f"🚦 {row['status']}")
        col3.write(f"💰 {row['upi']}")
        col4.write(f"💲 {row['amount']}")
        col5.write(f"📍 {row['location']}")
        if col6.button("✅ Validate", key=f'btn_{i}'):
            st.session_state.transactions[i]['status'] = 'Validated'
            st.rerun()
else:
    st.info("No transactions available. Add a new transaction with a valid UPI ID.")

# Add sample data button
st.markdown("### 📌 Actions")
def add_sample_data():
    new_id = f'TXN{len(st.session_state.transactions) + 1}'
    upi_id = st.text_input("Enter UPI ID for transaction:", key=f'upi_input_{new_id}')
    amount = st.number_input("Enter Amount:", min_value=1, step=1, key=f'amount_{new_id}')
    location = st.text_input("Enter Transaction Location:", key=f'location_{new_id}')
    if st.button("Submit UPI", key=f'submit_{new_id}'):
        if is_valid_upi(upi_id):
            st.session_state.transactions.append({'id': new_id, 'status': 'Pending', 'upi': upi_id, 'amount': amount, 'location': location})
            st.rerun()
        else:
            st.error("Invalid UPI ID. Please enter a valid UPI ID based in India.")

add_sample_data()