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
    let shareType = null; // 'screen', 'window', or 'tab'

    // DOM elements (will be created dynamically)
    let liveIndicator, liveEndBtn, liveResumeBtn, chatWidget, chatToggle, chatMessages, chatInput, chatSend, chatMinimize, shareModal;

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
                    <button class="support-btn-live-resume" id="support-live-resume-btn" style="display: none;">Resume Sharing</button>
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

                <div style="background: #d4edda; border: 2px solid #28a745; border-radius: 6px; padding: 1rem; margin: 1rem 0;">
                    <p style="margin: 0 0 0.5rem 0; color: #155724; font-weight: 700;">✅ Best Option:</p>
                    <p style="margin: 0; color: #155724;">Select <strong>"Entire Screen"</strong> or <strong>"Window"</strong>. When you navigate to different pages, just click the yellow "Resume Sharing" button to reconnect (one click).</p>
                </div>

                <div style="background: #fff3cd; border: 2px solid #ffc107; border-radius: 6px; padding: 1rem; margin: 1rem 0;">
                    <p style="margin: 0 0 0.5rem 0; color: #856404; font-weight: 700;">⚠️ Not Recommended:</p>
                    <p style="margin: 0; color: #856404;">Avoid selecting <strong>"Tab"</strong> - you'll have to manually reshare every time you click a link!</p>
                </div>

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
        liveResumeBtn = document.getElementById('support-live-resume-btn');
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
        // Live banner buttons
        liveEndBtn.addEventListener('click', endSession);
        liveResumeBtn.addEventListener('click', resumeScreenShare);

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

            // Detect share type (this is a best-effort detection)
            const videoTrack = localStream.getVideoTracks()[0];
            const settings = videoTrack.getSettings();

            // Try to determine if it's screen, window, or tab based on displaySurface
            if (settings.displaySurface) {
                shareType = settings.displaySurface; // 'monitor', 'window', or 'browser'
                console.log('[Support] Share type detected:', shareType);

                // Warn if they shared a tab
                if (shareType === 'browser') {
                    addChatMessage('System', '⚠️ You shared a browser tab. This will disconnect when you navigate. For best results, reshare and select "Entire Screen" or "Window".', true);
                }
            }

            // Show live indicator
            liveIndicator.classList.add('active');
            liveResumeBtn.style.display = 'none'; // Hide resume button when actively sharing
            document.body.classList.add('support-live-mode');
            isSharingScreen = true;

            sessionStorage.setItem(SESSION_DATA_KEY, JSON.stringify({
                status: 'sharing',
                shareType: shareType
            }));

            // Setup the WebRTC peer connection
            await setupPeerConnection();

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

    async function resumeScreenShare() {
        console.log('[Support] Attempting to resume screen share...');
        await startScreenShare();
    }

    function restoreSession(sessionData) {
        console.log('[Support] Restoring session:', sessionData);

        // Reinitialize socket connection
        initSocket();

        // Show chat if it was open
        if (sessionData.status === 'connected' || sessionData.status === 'sharing') {
            chatWidget.classList.add('active');
        }

        // If they were sharing their screen, show resume button
        if (sessionData.status === 'sharing') {
            shareType = sessionData.shareType || null;

            // Show live banner with resume button (can't auto-reconnect - needs user interaction)
            liveIndicator.classList.add('active');
            liveResumeBtn.style.display = 'inline-block';
            document.body.classList.add('support-live-mode');

            // Add message based on share type
            if (shareType === 'browser') {
                addChatMessage('System', '⚠️ Tab sharing disconnected (happens when you navigate). Click "Resume Sharing" to continue.', true);
            } else {
                addChatMessage('System', 'Click "Resume Sharing" to continue sharing your screen.', true);
            }
        }
    }

    async function setupPeerConnection() {
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
            console.log('[Support] Screen sharing stopped by user');
            isSharingScreen = false;

            // Check if session is still active
            const hasActiveSession = sessionStorage.getItem(SESSION_KEY) === 'true';
            if (hasActiveSession) {
                // Show resume button
                liveResumeBtn.style.display = 'inline-block';
                addChatMessage('System', 'Screen sharing stopped. Click "Resume Sharing" to continue.', true);
            } else {
                liveIndicator.classList.remove('active');
                document.body.classList.remove('support-live-mode');
            }
        };

        // Create and send offer
        const offer = await peerConnection.createOffer();
        await peerConnection.setLocalDescription(offer);

        console.log('[Support] Sending offer to agent');
        socket.emit('webrtc_offer', { offer: offer });
    }

})();
