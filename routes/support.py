"""
Support routes - Remote screen sharing support for users and agents.
"""
from flask import Blueprint, render_template, session, redirect, url_for, flash, request as flask_request
from flask_socketio import emit, join_room, leave_room
from helpers.decorators import login_required, admin_required

# Create blueprint
support_bp = Blueprint('support', __name__)

# In-memory storage for active support sessions
# Format: {user_id: {'room_id': str, 'status': 'waiting'|'connected', 'agent_sid': str}}
active_sessions = {}


@support_bp.route("/support")
@login_required
def user_support():
    """User support page - request help and share screen."""
    user_id = session.get('user_id')

    # Check if user already has an active session
    existing_session = active_sessions.get(user_id)

    return render_template(
        "support.html",
        user_id=user_id,
        existing_session=existing_session
    )


@support_bp.route("/admin/support")
@admin_required
def admin_support():
    """Admin dashboard to view and join support requests."""
    # Get all waiting and active sessions
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

    return render_template(
        "admin_support.html",
        waiting_sessions=waiting_sessions,
        active_sessions=active_support
    )


# ============================================================================
# Socket.IO Event Handlers
# ============================================================================

def register_socketio_handlers(socketio):
    """Register Socket.IO event handlers for WebRTC signaling."""
    from flask import request

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
            'agent_sid': None
        }

        # Join the room
        join_room(room_id)

        # Notify user
        emit('support_status', {
            'status': 'waiting',
            'message': 'Waiting for an agent to join...'
        })

        # Notify all admins that a new request came in
        socketio.emit('new_support_request', {
            'user_id': user_id,
            'room_id': room_id
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

        user_id = data.get('user_id')
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

        user_id = data.get('user_id')
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
            target_user_id = data.get('user_id')
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
            target_user_id = data.get('user_id')
            session_info = active_sessions.get(target_user_id)
            cleanup_user_id = target_user_id
        else:  # User ending their own session
            session_info = active_sessions.get(user_id)
            cleanup_user_id = user_id

        if not session_info:
            return

        room_id = session_info['room_id']

        # Notify everyone in the room
        socketio.emit('session_ended', {
            'message': 'Support session has ended.'
        }, room=room_id)

        # Clean up
        if cleanup_user_id in active_sessions:
            del active_sessions[cleanup_user_id]

        # Leave room
        leave_room(room_id)


    @socketio.on('disconnect')
    def handle_disconnect():
        """Clean up when someone disconnects."""
        user_id = session.get('user_id')

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
