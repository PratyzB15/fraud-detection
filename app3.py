import streamlit as st
import pandas as pd
import re
import google.generativeai as genai
from PIL import Image
import random
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from bson import ObjectId

# *DATABASE CONFIGURATION*
MONGO_URI = "mongodb+srv://theabhik2020:hoAxx927XbF0Yp3c@cluster0.ko8v5.mongodb.net/pythonTest"
DB_NAME = "fraud_detection_db"
USER_COLLECTION_NAME = "users"
TRANSACTION_COLLECTION_NAME = "transactions"

# MongoDB connection
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users = db[USER_COLLECTION_NAME]
transactions_db = db[TRANSACTION_COLLECTION_NAME]

# Set Streamlit page config
st.set_page_config(page_title="Decentralized Fraud Detection System", layout="wide")

# Set up Gemini API key
genai.configure(api_key="AIzaSyDZfMZN51fqIhxjtSkkAM6eMDBvYdcCuvk")

# Initialize session state
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'username' not in st.session_state:
    st.session_state.username = ""
if 'user_id' not in st.session_state:
    st.session_state.user_id = None

# User Registration
def register_user():
    st.subheader("📝 Register")
    username = st.text_input("Enter a username:")
    email = st.text_input("Enter your email:")
    password = st.text_input("Enter a password:", type="password")

    if st.button("Register"):
        if users.find_one({'email': email}):
            st.error("Email already exists. Choose a different one.")
            return

        hashed_password = generate_password_hash(password)
        user_data = {'username': username, 'email': email, 'password_hash': hashed_password}

        try:
            users.insert_one(user_data)
            st.success("✅ Registration successful! Please log in.")
        except Exception as e:
            st.error(f"An error occurred: {e}")

# User Login
def login_user():
    st.subheader("🔑 Login")
    email = st.text_input("Enter your email:")
    password = st.text_input("Enter your password:", type="password")

    if st.button("Login"):
        user = users.find_one({'email': email})
        if user and check_password_hash(user['password_hash'], password):
            st.session_state.logged_in = True
            st.session_state.username = user['username']
            st.session_state.user_id = str(user['_id'])
            st.success("✅ Login successful!")
            st.rerun()
        else:
            st.error("❌ Invalid email or password.")

# Logout
def logout_user():
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.user_id = None
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

st.title(f"🚀 Welcome, {st.session_state.username}!")
st.sidebar.button("Logout", on_click=logout_user)

# UPI validation
valid_upi_handles = {"@sbi", "@imobile", "@pockets", "@icici", "@hdfcbank", "@kotak", "@yesbank", "@idbi", "@pnb","@ptys","@okaxis"}

def is_valid_upi(upi_id):
    return any(upi_id.endswith(handle) for handle in valid_upi_handles)

# PAN Verification
def verify_pan():
    pan_number = st.text_input("Enter PAN Number (Format: ABCDE1234F):")
    if st.button("Verify PAN"):
        if re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', pan_number):
            st.success("✅ PAN Verified Successfully!")
        else:
            st.error("❌ Invalid PAN Number.")

# GST Verification
def verify_gst():
    gst_number = st.text_input("Enter GST Number (Format: 22AAAAA0000A1Z5):")
    if st.button("Verify GST"):
        if re.match(r'^[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9][Z][0-9]$', gst_number):
            st.success("✅ GST Verified Successfully!")
        else:
            st.error("❌ Invalid GST Number.")

st.subheader("📄 PAN & GST Verification")
verify_pan()
verify_gst()

# *Transaction Management*
def load_transactions():
    """Loads transactions from MongoDB."""
    all_transactions = list(transactions_db.find({'user_id': st.session_state.user_id}))

    for transaction in all_transactions:
        transaction['_id'] = str(transaction['_id'])
    return all_transactions

def update_transaction_status(transaction_id, new_status):
    """Updates a transaction's status in MongoDB."""
    try:
        transactions_db.update_one({'_id': ObjectId(transaction_id)}, {'$set': {'status': new_status}})
        st.success(f"Transaction {transaction_id} status updated to {new_status}")
        st.rerun()
    except Exception as e:
        st.error(f"Error updating transaction: {e}")

st.subheader("📋 Transaction Reports")
transactions = load_transactions()

if transactions:
    df = pd.DataFrame(transactions)
    df = df[['_id', 'status', 'upi', 'amount', 'location']]
    df.rename(columns={'_id': 'id'}, inplace=True)

    st.dataframe(df, width=700)

    for i, row in df.iterrows():
        col1, col2, col3, col4, col5, col6 = st.columns([2, 2, 2, 2, 2, 2])
        transaction_id = row['id']

        col1.write(f"{transaction_id}")
        col2.write(f"🚦 {row['status']}")
        col3.write(f"💰 {row['upi']}")
        col4.write(f"💲 {row['amount']}")
        col5.write(f"📍 {row['location']}")

        if col6.button("✅ Validate", key=f"validate_{transaction_id}"):
            update_transaction_status(transaction_id, "Validated")
else:
    st.info("No transactions available.")

st.markdown("### 📌 Add Transaction")

def add_sample_data():
    upi_id = st.text_input("Enter UPI ID for transaction:")
    amount = st.number_input("Enter Amount:", min_value=1, step=1)
    location = st.text_input("Enter Transaction Location:")

    if st.button("Submit UPI"):
        if not st.session_state.user_id:
            st.error("You must be logged in to add transactions.")
            return

        if is_valid_upi(upi_id):
            new_transaction = {
                'user_id': st.session_state.user_id,
                'status': 'Pending',
                'upi': upi_id,
                'amount': amount,
                'location': location
            }
            try:
                transactions_db.insert_one(new_transaction)
                st.success("Transaction added successfully!")
                st.rerun()
            except Exception as e:
                st.error(f"Error adding transaction: {e}")
        else:
            st.error("Invalid UPI ID. Please enter a valid UPI ID.")

add_sample_data()