import streamlit as st

from database.database import (
    create_user,
    authenticate_user
)


# ==================================================
# INITIALIZE AUTH SESSION
# ==================================================

def initialize_auth():

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "user" not in st.session_state:
        st.session_state.user = None


# ==================================================
# LOGIN / REGISTER PAGE
# ==================================================

def show_authentication():

    initialize_auth()

    st.title(
        "🛡️ AI Phishing Detection Platform"
    )

    st.subheader(
        "🔐 Account Authentication"
    )

    login_tab, register_tab = st.tabs(
        [
            "🔑 Login",
            "📝 Register"
        ]
    )

    # ==================================================
    # LOGIN
    # ==================================================

    with login_tab:

        st.write(
            "Login to access your security dashboard."
        )

        username = st.text_input(
            "Username",
            key="login_username"
        )

        password = st.text_input(
            "Password",
            type="password",
            key="login_password"
        )

        if st.button(
    "🔐 Login",
    type="primary",
    width="stretch",
    key="login_button"
):
            if not username or not password:

                st.warning(
                    "Please enter username and password."
                )

            else:

                user = authenticate_user(
                    username,
                    password
                )

                if user:

                    st.session_state.logged_in = True

                    st.session_state.user = user

                    st.success(
                        f"Welcome, {user['username']}!"
                    )

                    st.rerun()

                else:

                    st.error(
                        "❌ Invalid username or password."
                    )

    # ==================================================
    # REGISTER
    # ==================================================

    with register_tab:

        st.write(
            "Create a new account."
        )

        new_username = st.text_input(
            "Create Username",
            key="register_username"
        )

        new_password = st.text_input(
            "Create Password",
            type="password",
            key="register_password"
        )

        confirm_password = st.text_input(
            "Confirm Password",
            type="password",
            key="confirm_password"
        )

        if st.button(
    "📝 Create Account",
    width="stretch",
    key="register_button"
):

            if not new_username or not new_password:

                st.warning(
                    "Please fill in all fields."
                )

            elif new_password != confirm_password:

                st.error(
                    "❌ Passwords do not match."
                )

            elif len(new_password) < 6:

                st.warning(
                    "Password must contain at least 6 characters."
                )

            else:

                created = create_user(
                    new_username,
                    new_password
                )

                if created.get("success"):

                    st.success(
                        "✅ Account created successfully. "
                        "You can now login."
                    )

                else:

                    st.error(
                        f"❌ {created.get('error', 'Unable to create account.')}"
                    )


# ==================================================
# LOGOUT
# ==================================================

def logout():

    st.session_state.logged_in = False

    st.session_state.user = None

    st.session_state.email_history = []

    st.session_state.website_history = []

    st.rerun()