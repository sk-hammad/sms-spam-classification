import streamlit as st
import bcrypt
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import pickle

# MySQL Database configuration
DATABASE_URL = "mysql+mysqlconnector://root:hammad@localhost/sms_db"

# Setting up the database
engine = create_engine(DATABASE_URL)
Base = declarative_base()
Session = sessionmaker(bind=engine)
session = Session()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(80), unique=True, nullable=False)
    password = Column(String(128), nullable=False)  # Increased size for hashed passwords

class Prediction(Base):
    __tablename__ = 'predictions'
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(80), nullable=False)
    message = Column(String, nullable=False)
    prediction = Column(Integer, nullable=False)  # 1 for Spam, 0 for Not Spam

Base.metadata.create_all(engine)

def register_user(username, password):
    if session.query(User).filter_by(username=username).first():
        return False  # User already exists
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    new_user = User(username=username, password=hashed_password.decode('utf-8'))
    session.add(new_user)
    session.commit()
    return True

def login_user(username, password):
    user = session.query(User).filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        return True
    return False

def save_prediction(username, message, prediction):
    print(f"Saving prediction with username: '{username}', message: '{message}', prediction: '{prediction}'")
    new_prediction = Prediction(username=username, message=message, prediction=int(prediction))
    session.add(new_prediction)
    session.commit()

def main():

    # Ensure session state variables are initialized
    if 'username' not in st.session_state:
        st.session_state.username = None

    # Sidebar for navigation
    st.sidebar.title("Navigation")
    if st.session_state.username is None:
        menu = ["Login", "Register"]
    else:
        menu = ["Spam Classifier", "Logout"]

    choice = st.sidebar.selectbox("Select a page", menu)

    if st.session_state.username is None:
        if choice == "Login":
            st.subheader("Login")

            username = st.text_input("Username")
            password = st.text_input("Password", type="password")

            if st.button("Login"):
                if login_user(username, password):
                    st.session_state.username = username
                    st.success(f"Welcome {username}!")
                else:
                    st.error("Invalid Username or Password")

        elif choice == "Register":
            st.subheader("Create New Account")
            new_username = st.text_input("Username")
            new_password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")

            if st.button("Register"):
                if not new_username or not new_password or not confirm_password:
                    st.error("Please fill in all fields.")
                elif new_password != confirm_password:
                    st.error("Passwords do not match.")
                else:
                    if register_user(new_username, new_password):
                        st.success("Registration Successful")
                        st.session_state.username = new_username
                    else:
                        st.warning("Username already exists. Please choose another.")

    else:
        if choice == "Spam Classifier":
            # Load the trained model and vectorizer
            cv = pickle.load(open('vectorizer.pkl', 'rb'))
            model = pickle.load(open('model.pkl', 'rb'))

            # Streamlit GUI for Spam Classification
            st.title("Email/SMS Spam Classifier")
            input_sms = st.text_area("Enter the message")

            if st.button('Predict'):
                # Vectorize the input message
                vector_input = cv.transform([input_sms]).toarray()

                # Predict using the trained model
                result = model.predict(vector_input)[0]

                # Convert numpy.int32 to native Python int
                result = int(result)

                # Save the prediction to the database
                save_prediction(st.session_state.username, input_sms, result)

                # Display the result
                if result == 1:
                    st.header("Spam")
                else:
                    st.header("Not Spam")

        elif choice == "Logout":
            st.session_state.username = None

if __name__ == '__main__':
    main()
