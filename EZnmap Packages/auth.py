import os
import ldap
from flask import (
    Blueprint, request, session, redirect, url_for,
    jsonify
)
from functools import wraps

auth_bp = Blueprint('auth', __name__)

# ----------------------------------
# Configuration Flags
# ----------------------------------
AUTH_REQUIRED = False  # Toggle to True/False as needed

# ----------------------------------
# AD / LDAP Settings
# ----------------------------------
AD_SERVER   = "ldap://192.168.1.26:389"  # Use "ldaps://..." for SSL
AD_DOMAIN   = "example.com"
BASE_DN     = "dc=example,dc=com"
IT_GROUP_DN = "CN=IT,CN=Users,DC=example,DC=com"

def bind_user(username, password):
    """
    Attempt a simple LDAP bind as the user themselves.
    Returns True if bind is successful, False otherwise.
    """
    try:
        conn = ldap.initialize(AD_SERVER)
        ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldap.set_option(ldap.OPT_REFERRALS, 0)

        user_upn = f"{username}@{AD_DOMAIN}"
        conn.simple_bind_s(user_upn, password)
        conn.unbind_s()
        return True
    except ldap.LDAPError as e:
        print(f"[bind_user] bind failed for {username} => {e}")
        return False


def is_user_in_group(username, password, group_dn):
    """
    Bind as the user, then search for userPrincipalName={username}@{AD_DOMAIN}.
    Retrieve 'memberOf' attribute, see if group_dn is in that list.
    """
    try:
        conn = ldap.initialize(AD_SERVER)
        ldap.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        ldap.set_option(ldap.OPT_REFERRALS, 0)

        user_upn = f"{username}@{AD_DOMAIN}"
        conn.simple_bind_s(user_upn, password)

        # Search for user’s own entry
        search_filter = f"(userPrincipalName={user_upn})"
        result = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, search_filter, ['memberOf'])
        conn.unbind_s()

        if result and len(result) > 0:
            user_attrs = result[0][1]
            member_of = user_attrs.get('memberOf', [])
            # Convert bytes to str if necessary
            group_list = [g.decode() if isinstance(g, bytes) else g for g in member_of]
            return group_dn in group_list

        return False
    except ldap.LDAPError as e:
        print(f"[is_user_in_group] Error: {e}")
        return False


def login_required(f):
    """
    Decorator that enforces login, if AUTH_REQUIRED is True.
    If a user is not authenticated or not in IT group, deny access.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if AUTH_REQUIRED:
            if not session.get('authenticated'):
                return redirect(url_for('auth.login'))
            if not session.get('in_it_group'):
                return jsonify({"error": "You do not have permission (not in IT group)"}), 403
        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route("/login", methods=['GET', 'POST'])
def login():
    if not AUTH_REQUIRED:
        # If authentication is not required, just skip
        return redirect(url_for('index'))

    if request.method == 'GET':
        return '''
        <h2>Login</h2>
        <form method="POST" action="/login">
            Username: <input type="text" name="username"><br/>
            Password: <input type="password" name="password"><br/>
            <input type="submit" value="Login"/>
        </form>
        '''

    username = request.form.get('username')
    password = request.form.get('password')

    # Validate credentials by binding to LDAP
    if not bind_user(username, password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Check if user is in IT group
    in_it_group = is_user_in_group(username, password, IT_GROUP_DN)

    # Store in session
    session['authenticated'] = True
    session['username'] = username
    session['in_it_group'] = in_it_group

    if not in_it_group:
        # If not in IT group, clear session
        session.clear()
        return jsonify({"error": "You do not have permission (not in IT group)"}), 403

    return redirect(url_for('index'))


@auth_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('auth.login'))

