import streamlit as st
import sqlite3
from cryptography.fernet import Fernet
import base64

# Generate a key for encryption/decryption
def generate_key():
    key = Fernet.generate_key()
    return key

# Load the encryption key from a file or create one if not exists
def load_key():
    try:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
    except FileNotFoundError:
        key = generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    return key

key = load_key()
fernet = Fernet(key)

# Connect to SQLite database
conn = sqlite3.connect('notes.db')
c = conn.cursor()

# Create tables if not exist
c.execute('''CREATE TABLE IF NOT EXISTS notes
             (id INTEGER PRIMARY KEY, title TEXT, note TEXT)''')

c.execute('''CREATE TABLE IF NOT EXISTS password
             (id INTEGER PRIMARY KEY, password TEXT)''')
conn.commit()

# Function to check if a password is stored
def is_password_set():
    c.execute('SELECT * FROM password')
    return c.fetchone() is not None

# Function to get the stored password
def get_stored_password():
    c.execute('SELECT password FROM password')
    result = c.fetchone()
    return fernet.decrypt(result[0].encode()).decode() if result else None

# Password check
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

if not st.session_state.authenticated:
    st.markdown("<h1 style='text-align: center;'>🎵 Notes App 🎵</h1>", unsafe_allow_html=True)
    
    if is_password_set():
        # If password is set, prompt for password
        password = st.text_input('Enter password', type='password')
        if st.button('Login'):
            if password == get_stored_password():
                st.session_state.authenticated = True
                st.success('Password correct! Welcome to the Notes App.')
            else:
                st.error('Incorrect password. Please try again.')
    else:
        # If no password is set, allow setting a new password
        st.warning('No password set. Please set a new password.')
        new_password = st.text_input('Set new password', type='password')
        if st.button('Set Password'):
            if new_password:
                encrypted_password = fernet.encrypt(new_password.encode()).decode()
                c.execute('INSERT INTO password (password) VALUES (?)', (encrypted_password,))
                conn.commit()
                st.success('Password set successfully! You can now log in.')
else:
    # Initialize session state variables
    if 'notes' not in st.session_state:
        c.execute('SELECT title, note FROM notes')
        st.session_state.notes = [{'title': fernet.decrypt(row[0].encode()).decode(), 'note': fernet.decrypt(row[1].encode()).decode()} for row in c.fetchall()]

    # Title and notes emoji
    st.markdown("<h1 style='text-align: center;'>🎵 Notes App 🎵</h1>", unsafe_allow_html=True)

    # Note input form
    with st.form(key='note_form'):
        title = st.text_input('Enter note title')
        note = st.text_area('Enter your note')
        submit_button = st.form_submit_button(label='Add Note')

    if submit_button:
        encrypted_title = fernet.encrypt(title.encode()).decode()
        encrypted_note = fernet.encrypt(note.encode()).decode()
        c.execute('INSERT INTO notes (title, note) VALUES (?, ?)', (encrypted_title, encrypted_note))
        conn.commit()
        st.session_state.notes.append({'title': title, 'note': note})
        st.success('Note added!')

    # Clear all notes button
    if st.button('Clear All Notes'):
        c.execute('DELETE FROM notes')
        conn.commit()
        st.session_state.notes.clear()
        st.success('All notes cleared!')

    # Sidebar for navigating between notes
    st.sidebar.subheader('Navigation')
    options = ['Select a note'] + [f'Note {i+1}: {note["title"]}' for i, note in enumerate(st.session_state.notes)]
    selected_option = st.sidebar.selectbox('Select a note', options)

    if selected_option != 'Select a note':
        selected_note_index = options.index(selected_option) - 1
        selected_note = st.session_state.notes[selected_note_index]
        st.sidebar.markdown(f'**Title:** {selected_note["title"]}')
        st.sidebar.markdown(f'{selected_note["note"]}')

    # Close the database connection at the end of the script
    conn.close()
