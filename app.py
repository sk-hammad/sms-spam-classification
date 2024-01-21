import streamlit as st
import pickle
from sklearn.feature_extraction.text import CountVectorizer

# Load the trained model and vectorizer
cv = pickle.load(open('vectorizer.pkl', 'rb'))
model = pickle.load(open('model.pkl', 'rb'))

# Streamlit GUI
st.title("Email/SMS Spam Classifier")
input_sms = st.text_area("Enter the message")

if st.button('Predict'):
    # Vectorize the input message
    vector_input = cv.transform([input_sms]).toarray()

    # Predict using the trained model
    result = model.predict(vector_input)[0]

    # Display the result
    if result == 1:
        st.header("Spam")
    else:
        st.header("Not Spam")