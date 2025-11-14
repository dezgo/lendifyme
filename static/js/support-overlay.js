/**
 * LendifyMe Global Support Overlay
 * Manages live support sessions with screen sharing and chat across all pages
 */

(function() {
    'use strict';

    // Only run for logged-in non-admin users
    const userId = window.LENDIFYME_USER_ID;
    const isAdmin = window.LENDIFYME_IS_ADMIN;

    if (!userId || isAdmin) {
        return; // Don't initialize for non-logged-in users or admins
    }

    // State management
    let socket = null;
    let peerConnection = null;
    let localStream = null;
    let isSharingScreen = false;

    // DOM elements (will be created dynamically)
    let liveIndicator, liveEndBtn, chatWidget, chatToggle, chatMessages, chatInput, chatSend, chatMinimize, shareModal;

    // Session storage keys
    const SESSION_KEY = 'support_session_active';
    const SESSION_DATA_KEY = 'support_session_data';

    // Initialize on page load
    document.addEventListener('DOMContentLoaded', function() {
        createSupportUI();
        attachEventListeners();

        // Check if there's an active session
        const hasActiveSession = sessionStorage.getItem(SESSION_KEY) === 'true';
        if (hasActiveSession) {
            const sessionData = JSON.parse(sessionStorage.getItem(SESSION_DATA_KEY) || '{}');
            restoreSession(sessionData);
        }
    });

    function createSupportUI() {
        // Create live indicator banner
        liveIndicator = createElement('div', 'support-live-indicator', `
            <div class="support-live-indicator-content">
                <div class="support-live-indicator-text">
                    <div class="support-live-pulse"></div>
                    <h2>🔴 LIVE - Agent is viewing your screen</h2>
                </div>
                <div class="support-live-indicator-actions">
                    <button class="support-btn-live-end" id="support-live-end-btn">End Session</button>
                </div>
            </div>
        `);

        // Create chat toggle button
        chatToggle = createElement('button', 'support-chat-toggle', '💬');
        chatToggle.setAttribute('aria-label', 'Open support chat');

        // Create chat widget
        chatWidget = createElement('div', 'support-chat-widget', `
            <div class="support-chat-header">
                <h3>💬 Chat with Support</h3>
                <button class="support-chat-minimize" id="support-chat-minimize">−</button>
            </div>
            <div class="support-chat-messages" id="support-chat-messages">
                <div class="support-chat-message agent">
                    <span class="support-chat-sender">Support Agent</span>
                    <div class="support-chat-bubble">
                        Hi! I'll be with you shortly. Feel free to describe your issue while you wait.
                    </div>
                </div>
            </div>
            <div class="support-chat-input-container">
                <input type="text" class="support-chat-input" id="support-chat-input" placeholder="Type a message...">
                <button class="support-chat-send" id="support-chat-send">→</button>
            </div>
        `);

        // Create screen share modal
        shareModal = createElement('div', 'support-modal-overlay', `
            <div class="support-modal-content">
                <h2>Ready to share your screen?</h2>
                <p>When you click <strong>"Start Sharing"</strong>, your browser will ask what to share.</p>
                <p><strong>Important:</strong> Select <strong>"Entire Screen"</strong> or <strong>"Window"</strong> (NOT "Tab") so the agent can see you navigate around the app.</p>
                <p style="font-size: 0.9rem; color: #666; margin-top: 1rem;">💡 Tip: If you share just a tab, the agent won't see you when you navigate to other pages.</p>
                <div class="support-modal-actions">
                    <button class="support-btn support-btn-secondary" id="support-modal-cancel">Cancel</button>
                    <button class="support-btn support-btn-primary" id="support-modal-confirm">Start Sharing</button>
                </div>
            </div>
        `);

        // Append to body
        document.body.appendChild(liveIndicator);
        document.body.appendChild(chatToggle);
        document.body.appendChild(chatWidget);
        document.body.appendChild(shareModal);

        // Get references to dynamically created elements
        liveEndBtn = document.getElementById('support-live-end-btn');
        chatMessages = document.getElementById('support-chat-messages');
        chatInput = document.getElementById('support-chat-input');
        chatSend = document.getElementById('support-chat-send');
        chatMinimize = document.getElementById('support-chat-minimize');
    }

    function createElement(tag, className, innerHTML) {
        const el = document.createElement(tag);
        el.className = className;
        if (innerHTML) el.innerHTML = innerHTML;
        return el;
    }

    function attachEventListeners() {
        // Live banner end button
        liveEndBtn.addEventListener('click', endSession);

        // Chat toggle
        chatToggle.addEventListener('click', function() {
            chatWidget.classList.add('active');
            chatToggle.classList.remove('show');
        });

        // Chat minimize
        chatMinimize.addEventListener('click', function() {
            chatWidget.classList.remove('active');
            chatToggle.classList.add('show');
        });

        // Chat send
        chatSend.addEventListener('click', sendChatMessage);
        chatInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') sendChatMessage();
        });

        // Modal buttons
        document.getElementById('support-modal-cancel').addEventListener('click', function() {
            shareModal.classList.remove('active');
        });

        document.getElementById('support-modal-confirm').addEventListener('click', startScreenShare);

        // Close modal on outside click
        shareModal.addEventListener('click', function(e) {
            if (e.target === shareModal) {
                shareModal.classList.remove('active');
            }
        });
    }

    // Public function to start a support request (called from /support page or nav link)
    window.LendifyMeSupport = {
        requestSupport: function() {
            if (!socket) initSocket();

            socket.emit('request_support', { user_id: userId });
            sessionStorage.setItem(SESSION_KEY, 'true');
            sessionStorage.setItem(SESSION_DATA_KEY, JSON.stringify({ status: 'waiting' }));

            // Show chat
            chatWidget.classList.add('active');
            chatToggle.classList.remove('show');
        },

        shareScreen: function() {
            shareModal.classList.add('active');
        }
    };

    function initSocket() {
        socket = io({
            transports: ['websocket', 'polling']
        });

        socket.on('connect', () => {
            console.log('[Support] Connected to server');
        });

        socket.on('support_status', (data) => {
            console.log('[Support] Status:', data.message);
        });

        socket.on('agent_joined', (data) => {
            console.log('[Support] Agent joined:', data.message);
            sessionStorage.setItem(SESSION_DATA_KEY, JSON.stringify({ status: 'connected' }));
        });

        socket.on('webrtc_answer', async (data) => {
            console.log('[Support] Received WebRTC answer');
            if (peerConnection) {
                await peerConnection.setRemoteDescription(new RTCSessionDescription(data.answer));
            }
        });

        socket.on('webrtc_ice_candidate', async (data) => {
            console.log('[Support] Received ICE candidate');
            if (data.candidate && peerConnection) {
                await peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
            }
        });

        socket.on('session_ended', (data) => {
            console.log('[Support] Session ended:', data.message);
            cleanup();
        });

        socket.on('peer_disconnected', (data) => {
            console.log('[Support] Peer disconnected:', data.message);
            cleanup();
        });

        socket.on('new_message', (data) => {
            addChatMessage(data.sender, data.text, data.is_agent);
        });
    }

    async function startScreenShare() {
        try {
            shareModal.classList.remove('active');

            console.log('[Support] Requesting screen share...');
            localStream = await navigator.mediaDevices.getDisplayMedia({
                video: { cursor: "always" },
                audio: false
            });

            console.log('[Support] Screen share granted');

            // Show live indicator
            liveIndicator.classList.add('active');
            document.body.classList.add('support-live-mode');
            isSharingScreen = true;

            sessionStorage.setItem(SESSION_DATA_KEY, JSON.stringify({ status: 'sharing' }));

            // Create peer connection
            peerConnection = new RTCPeerConnection({
                iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
            });

            // Add tracks
            localStream.getTracks().forEach(track => {
                console.log('[Support] Adding track:', track);
                peerConnection.addTrack(track, localStream);
            });

            // Handle ICE candidates
            peerConnection.onicecandidate = (event) => {
                if (event.candidate) {
                    console.log('[Support] Sending ICE candidate');
                    socket.emit('webrtc_ice_candidate', { candidate: event.candidate });
                }
            };

            // Handle track end
            localStream.getVideoTracks()[0].onended = () => {
                console.log('[Support] Screen sharing stopped');
                isSharingScreen = false;
                liveIndicator.classList.remove('active');
                document.body.classList.remove('support-live-mode');
            };

            // Create and send offer
            const offer = await peerConnection.createOffer();
            await peerConnection.setLocalDescription(offer);

            console.log('[Support] Sending offer to agent');
            socket.emit('webrtc_offer', { offer: offer });

        } catch (err) {
            console.error('[Support] Error sharing screen:', err);
            if (err.name === 'NotAllowedError') {
                alert('Screen sharing cancelled.');
            } else {
                alert('Failed to share screen. Please try again.');
            }
        }
    }

    function sendChatMessage() {
        const message = chatInput.value.trim();
        if (!message) return;

        socket.emit('send_message', { message: message });
        chatInput.value = '';
    }

    function addChatMessage(sender, text, isAgent) {
        const messageDiv = createElement('div', `support-chat-message ${isAgent ? 'agent' : 'user'}`, `
            <span class="support-chat-sender">${escapeHtml(sender)}</span>
            <div class="support-chat-bubble">${escapeHtml(text)}</div>
        `);

        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function endSession() {
        if (socket) {
            socket.emit('end_support_session', { user_id: userId });
        }
        cleanup();
    }

    function cleanup() {
        if (localStream) {
            localStream.getTracks().forEach(track => track.stop());
            localStream = null;
        }
        if (peerConnection) {
            peerConnection.close();
            peerConnection = null;
        }

        isSharingScreen = false;
        liveIndicator.classList.remove('active');
        document.body.classList.remove('support-live-mode');
        chatWidget.classList.remove('active');
        chatToggle.classList.remove('show');

        // Clear session storage
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem(SESSION_DATA_KEY);
    }

    function restoreSession(sessionData) {
        console.log('[Support] Restoring session:', sessionData);

        // Reinitialize socket connection
        initSocket();

        // Show chat if it was open
        if (sessionData.status === 'connected' || sessionData.status === 'sharing') {
            chatWidget.classList.add('active');
        }

        // Note: We can't automatically restore screen sharing
        // The user will need to reshare their screen after navigation
        if (sessionData.status === 'sharing') {
            // Show a message that they need to reshare
            addChatMessage('System', 'Page reloaded. Please click "Share Screen" again to continue sharing.', true);
        }
    }

})();
