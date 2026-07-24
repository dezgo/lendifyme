"""
Support routes.

The front door is an async support form (`GET/POST /support`): the user writes a
request, we store it and email the admin, who replies by email. No live agent is
promised, so the user never waits on a spinner.

The Socket.IO / WebRTC screen-share machinery below is retained for
*opportunistic* live support — the admin re-opening a session from a stored
request when the timing happens to work. It is no longer auto-triggered by the
user landing on the support page.
"""
from flask import (
    Blueprint,
    render_template,
    session,
    redirect,
    url_for,
    flash,
    request,
    request as flask_request,
)
from flask_socketio import emit, join_room, leave_room
from helpers.decorators import login_required, admin_required
from datetime import datetime

# Create blueprint
support_bp = Blueprint('support', __name__)

# In-memory storage for active support sessions
# Format: {user_id: {'room_id': str, 'status': 'waiting'|'connected', 'agent_sid': str, 'messages': []}}
active_sessions = {}

# ---------------------------------------------------------------------------
# Phase 2 — opportunistic live *chat* support
# ---------------------------------------------------------------------------
# Presence: which logged-in users currently have a socket open (a user can have
# several tabs, so we keep a set of sids). Used to decide whether "Start live
# session" shows an in-app banner (online) or emails a time-boxed link (offline).
# Format: {user_id: set(sid, ...)}
online_users = {}

# Open live chat sessions the admin has started, keyed by support_requests.id.
# Format: {request_id: {'user_id': int}}
live_sessions = {}


def _live_room(request_id) -> str:
    return f"live_{request_id}"


def is_user_online(user_id) -> bool:
    """True if the given user currently has at least one socket connected."""
    try:
        user_id = int(user_id)
    except (TypeError, ValueError):
        return False
    return bool(online_users.get(user_id))


def _session_is_admin() -> bool:
    """Role-based admin check usable inside HTTP and Socket.IO handlers."""
    from helpers.session_helpers import is_user_admin
    return is_user_admin()


def _live_participant_allowed(request_id) -> bool:
    """Admin may join any live room; a user may join only their own request's."""
    if _session_is_admin():
        return True
    from helpers.session_helpers import get_current_user_id
    from services.support_service import get_support_request
    uid = get_current_user_id()
    if not uid:
        return False
    req = get_support_request(request_id)
    return bool(req and req["user_id"] == uid)


def _display_name_for(user_id) -> str:
    """Best-effort human name for a user id (falls back to email, then #id)."""
    from helpers.db import get_db_connection
    try:
        conn = get_db_connection()
        row = conn.execute(
            "SELECT name, email FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        conn.close()
        if row:
            return row[0] or row[1] or f"User #{user_id}"
    except Exception:
        pass
    return f"User #{user_id}"


@support_bp.route("/support", methods=["GET", "POST"])
@login_required
def user_support():
    """Async support page: show the request form (GET) and handle it (POST)."""
    if request.method == "POST":
        return _handle_support_submit()

    return render_template("support.html")


def _handle_support_submit():
    """Validate, store, and email a written support request."""
    from flask import current_app
    import os

    from schemas.support import validate_support_input, ValidationError
    from services.support_service import submit_support_request

    ip_addr = (flask_request.headers.get("X-Forwarded-For") or flask_request.remote_addr or "").split(",")[0].strip()
    user_agent = flask_request.headers.get("User-Agent")

    try:
        data = validate_support_input(
            subject=flask_request.form.get("subject"),
            message=flask_request.form.get("message"),
            page_url=flask_request.form.get("page_url"),
            user_id=session.get("user_id"),
            user_email=session.get("user_email"),
            ip_addr=ip_addr,
            user_agent=user_agent,
        )
    except ValidationError as e:
        flash(str(e), "error")
        return redirect(url_for("support.user_support"))

    try:
        request_id, _ = submit_support_request(data)
    except ValidationError as e:
        flash(str(e), "error")
        return redirect(url_for("support.user_support"))

    # Notify the admin by email (best-effort — a delivery hiccup shouldn't lose
    # the request, which is already safely stored).
    try:
        admin_email = os.getenv("ADMIN_EMAIL")
        if admin_email:
            from services.email_sender import send_support_request_email
            app_url = os.getenv("APP_URL", "http://localhost:5000")
            success, message = send_support_request_email(
                admin_email=admin_email,
                user_email=data.user_email or "",
                user_id=data.user_id,
                app_url=app_url,
                subject=data.subject,
                message=data.message,
                request_id=request_id,
            )
            if not success:
                current_app.logger.warning(f"Failed to send support email: {message}")
        else:
            current_app.logger.warning("ADMIN_EMAIL not configured, cannot send support notification")
    except Exception:
        current_app.logger.exception("Failed to send support request email")

    flash(
        "Thanks — your request has been sent. Derek will get back to you by email, "
        "usually within a day.",
        "success",
    )
    return redirect(url_for("dashboard.index"))


@support_bp.route("/admin/support")
@admin_required
def admin_support():
    """Admin dashboard to view stored requests and join live sessions."""
    from services.support_service import list_support_requests

    # Legacy live (WebRTC) sessions — retained but no longer user-triggered.
    waiting_sessions = [
        {'user_id': uid, **data}
        for uid, data in active_sessions.items()
        if data['status'] == 'waiting'
    ]
    active_support = [
        {'user_id': uid, **data}
        for uid, data in active_sessions.items()
        if data['status'] == 'connected'
    ]

    # Phase 2 — stored written requests, annotated with live presence.
    stored_requests = []
    for row in list_support_requests():
        item = dict(row)
        item['user_online'] = is_user_online(item.get('user_id'))
        stored_requests.append(item)

    return render_template(
        "admin_support.html",
        waiting_sessions=waiting_sessions,
        active_sessions=active_support,
        stored_requests=stored_requests,
    )


@support_bp.route("/admin/support/<int:request_id>/start-live", methods=["POST"])
@admin_required
def admin_start_live(request_id):
    """
    Admin starts an opportunistic live chat for a stored request.

    If the user is currently online, push an in-app banner inviting them to join.
    Otherwise email a time-boxed join link. Returns JSON describing what happened
    so the admin dashboard can react without a page reload.
    """
    from flask import jsonify, current_app
    import os
    from services.support_service import get_support_request, issue_live_token
    from services.email_sender import send_live_support_invite_email

    req = get_support_request(request_id)
    if not req:
        return jsonify({"ok": False, "error": "Request not found."}), 404

    req = dict(req)
    user_id = req.get("user_id")
    user_email = req.get("user_email")

    # Mark a live session open so the invited user is allowed to join the room.
    live_sessions[request_id] = {"user_id": user_id}

    # Online → in-app banner via the user's presence room.
    if user_id and is_user_online(user_id):
        socketio = current_app.extensions.get("socketio")
        if socketio is not None:
            socketio.emit(
                "live_invite",
                {
                    "request_id": request_id,
                    "subject": req.get("subject") or "your support request",
                },
                room=f"user_{int(user_id)}",
            )
        return jsonify({"ok": True, "mode": "banner"})

    # Offline → time-boxed email link.
    if not user_email:
        return jsonify({
            "ok": False,
            "error": "User is offline and has no email on file.",
        }), 400

    from services.support_service import LIVE_TOKEN_TTL_MINUTES
    token, _ = issue_live_token(request_id, ttl_minutes=LIVE_TOKEN_TTL_MINUTES)
    app_url = os.getenv("APP_URL", "http://localhost:5000")
    join_link = f"{app_url}/support/live?token={token}"

    success, message = send_live_support_invite_email(
        to_email=user_email,
        to_name=None,
        join_link=join_link,
        expires_minutes=LIVE_TOKEN_TTL_MINUTES,
    )
    if not success:
        current_app.logger.warning(f"Failed to send live invite email: {message}")
        return jsonify({"ok": False, "error": "Couldn't send the invite email."}), 502

    return jsonify({"ok": True, "mode": "email", "email": user_email})


@support_bp.route("/support/live")
@login_required
def support_live():
    """
    User-facing live chat page. Reachable two ways:
      - ?token=<t>  from a time-boxed email invite (offline path)
      - ?r=<id>     from clicking the in-app banner (online path)
    In both cases the logged-in user must own the request.
    """
    from services.support_service import get_support_request, resolve_live_token

    token = request.args.get("token")
    req = None

    if token:
        req = resolve_live_token(token)
        if not req:
            flash("That live-chat link has expired. Please reply to your support email.", "error")
            return redirect(url_for("dashboard.index"))
    else:
        try:
            request_id = int(request.args.get("r", ""))
        except (TypeError, ValueError):
            flash("Invalid live-chat link.", "error")
            return redirect(url_for("dashboard.index"))
        req = get_support_request(request_id)

    req = dict(req) if req else None
    if not req:
        flash("Support request not found.", "error")
        return redirect(url_for("dashboard.index"))

    # Ownership: the live chat is for the user who filed the request.
    if req.get("user_id") != session.get("user_id"):
        flash("This live-chat link isn't for your account.", "error")
        return redirect(url_for("dashboard.index"))

    return render_template("support_live.html", request_id=req["id"], is_admin=False)


@support_bp.route("/admin/support/sessions")
@admin_required
def get_sessions():
    """API endpoint to get current sessions status (for polling)."""
    from flask import jsonify

    waiting_sessions = [
        {'user_id': uid, 'user_email': data.get('user_email', f'User #{uid}')}
        for uid, data in active_sessions.items()
        if data['status'] == 'waiting'
    ]

    active_support = [
        {'user_id': uid, 'user_email': data.get('user_email', f'User #{uid}')}
        for uid, data in active_sessions.items()
        if data['status'] == 'connected'
    ]

    return jsonify({
        'waiting': waiting_sessions,
        'active': active_support
    })


# ============================================================================
# Socket.IO Event Handlers
# ============================================================================

def register_socketio_handlers(socketio):
    """Register Socket.IO event handlers for WebRTC signaling."""
    from flask import request, current_app
    from helpers.db import get_db_connection
    import os

    # ------------------------------------------------------------------
    # Phase 2 — presence + opportunistic live *chat*
    # ------------------------------------------------------------------
    @socketio.on('connect')
    def handle_connect():
        """Track presence for any logged-in socket, and put them in a personal room."""
        user_id = session.get('user_id')
        if not user_id:
            return
        online_users.setdefault(int(user_id), set()).add(request.sid)
        join_room(f"user_{int(user_id)}")

    @socketio.on('live_join')
    def handle_live_join(data):
        """User or admin joins the live chat room for a support request."""
        try:
            request_id = int((data or {}).get('request_id'))
        except (TypeError, ValueError):
            emit('error', {'message': 'Invalid request.'})
            return

        if not _live_participant_allowed(request_id):
            emit('error', {'message': 'Not authorized for this session.'})
            return

        room = _live_room(request_id)
        join_room(room)
        is_admin = _session_is_admin()

        # Record who's present so a late joiner learns the other party is already
        # here (otherwise the first-joiner's presence ping is missed).
        sess = live_sessions.setdefault(request_id, {})
        sess['admin_present' if is_admin else 'user_present'] = True

        # Announce this party to everyone already in the room...
        socketio.emit('live_presence', {
            'request_id': request_id,
            'who': 'admin' if is_admin else 'user',
            'event': 'joined',
        }, room=room)

        # ...and catch the joiner up on the other party, if already present.
        other = 'user' if is_admin else 'admin'
        if sess.get(f'{other}_present'):
            emit('live_presence', {
                'request_id': request_id,
                'who': other,
                'event': 'joined',
            })

    @socketio.on('live_message')
    def handle_live_message(data):
        """Relay a chat message to everyone in the request's live room."""
        try:
            request_id = int((data or {}).get('request_id'))
        except (TypeError, ValueError):
            return
        text = ((data or {}).get('message') or '').strip()
        if not text:
            return
        if not _live_participant_allowed(request_id):
            emit('error', {'message': 'Not authorized for this session.'})
            return

        is_admin = _session_is_admin()
        sender = 'Derek (Support)' if is_admin else _display_name_for(session.get('user_id'))
        socketio.emit('live_message', {
            'request_id': request_id,
            'sender': sender,
            'text': text[:4000],
            'is_admin': is_admin,
            'timestamp': datetime.now().isoformat(),
        }, room=_live_room(request_id))

    @socketio.on('live_end')
    def handle_live_end(data):
        """End a live chat session (either party)."""
        try:
            request_id = int((data or {}).get('request_id'))
        except (TypeError, ValueError):
            return
        if not _live_participant_allowed(request_id):
            return
        socketio.emit('live_ended', {'request_id': request_id}, room=_live_room(request_id))
        live_sessions.pop(request_id, None)

    @socketio.on('request_support')
    def handle_request_support(data):
        """User requests support - create a waiting session."""
        user_id = session.get('user_id')
        if not user_id:
            emit('error', {'message': 'Not authenticated'})
            return

        # Create room for this support session
        room_id = f"support_{user_id}_{request.sid}"

        # Store session info
        active_sessions[user_id] = {
            'room_id': room_id,
            'status': 'waiting',
            'user_sid': request.sid,
            'agent_sid': None,
            'messages': []
        }

        # Join the room
        join_room(room_id)

        # Notify user
        emit('support_status', {
            'status': 'waiting',
            'message': 'Waiting for an agent to join...'
        })

        # Get user email and send notification to admin
        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute("SELECT email FROM users WHERE id = ?", (user_id,))
            user = c.fetchone()
            conn.close()

            user_email = user[0] if user else f"User #{user_id}"

            # Store user email in session data for display in admin dashboard
            active_sessions[user_id]['user_email'] = user_email

            # Send support request notification to admin
            import os
            admin_email = os.getenv('ADMIN_EMAIL')
            if admin_email:
                from services.email_sender import send_support_request_email
                app_url = os.getenv('APP_URL', 'http://localhost:5000')
                success, message = send_support_request_email(
                    admin_email=admin_email,
                    user_email=user_email,
                    user_id=user_id,
                    app_url=app_url,
                )
                if not success:
                    current_app.logger.warning(f"Failed to send support email: {message}")
            else:
                current_app.logger.warning("ADMIN_EMAIL not configured, cannot send support notification")
        except Exception:
            current_app.logger.exception("Failed to send support request email")

        # Notify all admins that a new request came in
        socketio.emit('new_support_request', {
            'user_id': user_id,
            'room_id': room_id,
            'user_email': user_email
        }, room='admin_room')


    @socketio.on('join_admin_room')
    def handle_join_admin_room():
        """Admin joins the admin notification room."""
        if session.get('user_id') != 1:  # Only user_id = 1 (admin)
            emit('error', {'message': 'Not authorized'})
            return

        join_room('admin_room')
        emit('admin_joined', {'message': 'Monitoring support requests'})


    @socketio.on('agent_join_session')
    def handle_agent_join(data):
        """Agent (admin) joins a user's support session."""
        if session.get('user_id') != 1:  # Only user_id = 1 (admin)
            emit('error', {'message': 'Not authorized'})
            return

        user_id = int(data.get('user_id'))  # Convert to int to match session keys
        session_info = active_sessions.get(user_id)

        if not session_info:
            emit('error', {'message': 'Session not found'})
            return

        room_id = session_info['room_id']

        # Update session status
        session_info['status'] = 'connected'
        session_info['agent_sid'] = request.sid

        # Agent joins the room
        join_room(room_id)

        # Notify user that agent joined
        socketio.emit('agent_joined', {
            'message': 'Agent has joined. You can now share your screen.'
        }, room=room_id)

        # Confirm to agent
        emit('joined_session', {
            'user_id': user_id,
            'room_id': room_id
        })


    @socketio.on('webrtc_offer')
    def handle_webrtc_offer(data):
        """Forward WebRTC offer from user to agent."""
        user_id = session.get('user_id')
        session_info = active_sessions.get(user_id)

        if not session_info:
            return

        room_id = session_info['room_id']

        # Forward offer to agent in the room
        emit('webrtc_offer', {
            'offer': data['offer'],
            'from': user_id
        }, room=room_id, skip_sid=request.sid)


    @socketio.on('webrtc_answer')
    def handle_webrtc_answer(data):
        """Forward WebRTC answer from agent to user."""
        if session.get('user_id') != 1:  # Only admin
            return

        user_id = int(data.get('user_id'))  # Convert to int to match session keys
        session_info = active_sessions.get(user_id)

        if not session_info:
            return

        room_id = session_info['room_id']

        # Forward answer to user
        emit('webrtc_answer', {
            'answer': data['answer']
        }, room=room_id, skip_sid=request.sid)


    @socketio.on('webrtc_ice_candidate')
    def handle_ice_candidate(data):
        """Forward ICE candidates between peers."""
        user_id = session.get('user_id')

        # Determine which session this belongs to
        if user_id == 1:  # Agent sending ICE candidate
            target_user_id = int(data.get('user_id'))  # Convert to int to match session keys
            session_info = active_sessions.get(target_user_id)
        else:  # User sending ICE candidate
            session_info = active_sessions.get(user_id)

        if not session_info:
            return

        room_id = session_info['room_id']

        # Forward ICE candidate to the other peer
        emit('webrtc_ice_candidate', {
            'candidate': data['candidate']
        }, room=room_id, skip_sid=request.sid)


    @socketio.on('end_support_session')
    def handle_end_session(data):
        """End a support session (can be called by user or agent)."""
        user_id = session.get('user_id')

        # Determine which session to end
        if user_id == 1:  # Agent ending session
            target_user_id = int(data.get('user_id'))  # Convert to int to match session keys
            session_info = active_sessions.get(target_user_id)
            cleanup_user_id = target_user_id
        else:  # User ending their own session
            session_info = active_sessions.get(user_id)
            cleanup_user_id = user_id

        if not session_info:
            return

        room_id = session_info['room_id']
        session_status = session_info.get('status', 'waiting')

        # Notify everyone in the room
        socketio.emit('session_ended', {
            'message': 'Support session has ended.',
            'user_id': cleanup_user_id
        }, room=room_id)

        # If the session was still waiting (user cancelled before agent joined),
        # notify admins to remove it from their waiting list
        if session_status == 'waiting':
            socketio.emit('session_cancelled', {
                'user_id': cleanup_user_id
            }, room='admin_room')
        # If it was active, notify admins to remove from active list
        else:
            socketio.emit('session_ended_by_user', {
                'user_id': cleanup_user_id
            }, room='admin_room')

        # Clean up
        if cleanup_user_id in active_sessions:
            del active_sessions[cleanup_user_id]

        # Leave room
        leave_room(room_id)


    @socketio.on('send_message')
    def handle_send_message(data):
        """Handle chat messages between user and agent."""
        user_id = session.get('user_id')
        if not user_id:
            return

        message_text = data.get('message', '').strip()
        if not message_text:
            return

        # Determine which session this belongs to
        if user_id == 1:  # Agent sending message
            target_user_id = int(data.get('user_id'))  # Convert to int to match session keys
            session_info = active_sessions.get(target_user_id)
            sender_name = "Support Agent"
            is_agent = True
        else:  # User sending message
            session_info = active_sessions.get(user_id)
            target_user_id = user_id
            # Get user name from database
            try:
                conn = get_db_connection()
                c = conn.cursor()
                c.execute("SELECT name, email FROM users WHERE id = ?", (user_id,))
                user_data = c.fetchone()
                conn.close()
                sender_name = user_data[0] if (user_data and user_data[0]) else (user_data[1] if user_data else f"User #{user_id}")
            except:
                sender_name = f"User #{user_id}"
            is_agent = False

        if not session_info:
            return

        room_id = session_info['room_id']

        # Store message in session
        message_obj = {
            'sender': sender_name,
            'text': message_text,
            'timestamp': datetime.now().isoformat(),
            'is_agent': is_agent
        }
        session_info['messages'].append(message_obj)

        # Broadcast message to everyone in the room
        socketio.emit('new_message', message_obj, room=room_id)


    @socketio.on('disconnect')
    def handle_disconnect():
        """Clean up when someone disconnects."""
        user_id = session.get('user_id')

        # Drop this socket from presence tracking (Phase 2 live support).
        if user_id:
            sids = online_users.get(int(user_id))
            if sids:
                sids.discard(request.sid)
                if not sids:
                    online_users.pop(int(user_id), None)

        # If this was a user with an active session, clean it up
        if user_id and user_id in active_sessions:
            session_info = active_sessions[user_id]
            room_id = session_info['room_id']

            # Notify the other party
            socketio.emit('peer_disconnected', {
                'message': 'The other party has disconnected.'
            }, room=room_id)

            # Clean up session
            del active_sessions[user_id]
