// Toast notification system
function showToast(message, type = 'success') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icons = {
        success: '✓',
        error: '✗',
        info: 'ℹ'
    };

    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.success}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="dismissToast(this)">×</button>
    `;

    container.appendChild(toast);

    // Auto-dismiss after 4 seconds
    setTimeout(() => {
        dismissToast(toast.querySelector('.toast-close'));
    }, 4000);
}

function dismissToast(button) {
    const toast = button.closest('.toast');
    toast.classList.add('hiding');
    setTimeout(() => toast.remove(), 300);
}

// Global utility: Convert server timestamps to local time
window.convertTimestamps = function() {
    const timeElements = document.querySelectorAll('[data-timestamp]');

    function getRelativeTime(date) {
        const now = new Date();
        const diffMs = now - date;
        const diffSec = Math.floor(diffMs / 1000);
        const diffMin = Math.floor(diffSec / 60);
        const diffHour = Math.floor(diffMin / 60);
        const diffDay = Math.floor(diffHour / 24);

        if (diffSec < 60) return 'just now';
        if (diffMin < 60) return `${diffMin}m ago`;
        if (diffHour < 24) return `${diffHour}h ago`;
        if (diffDay < 7) return `${diffDay}d ago`;

        // For older dates, show formatted date
        const options = {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        };
        return date.toLocaleString(undefined, options);
    }

    timeElements.forEach(function(element) {
        const serverTime = element.getAttribute('data-timestamp');
        if (!serverTime) return;

        // Parse the server timestamp (assuming format: "YYYY-MM-DD HH:MM:SS")
        // SQLite default timestamp format is UTC
        const date = new Date(serverTime + ' UTC');

        // Format to full local time for tooltip
        const fullOptions = {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        };
        const fullLocalTime = date.toLocaleString(undefined, fullOptions);

        // Get timezone
        const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;

        // Check if element wants relative time (default) or absolute time
        const useRelative = element.getAttribute('data-time-format') !== 'absolute';

        // Display time
        element.textContent = useRelative ? getRelativeTime(date) : fullLocalTime;
        element.title = `${fullLocalTime} (${timezone})`;
        element.style.cursor = 'help';
    });
};

// Auto-convert on page load
document.addEventListener('DOMContentLoaded', window.convertTimestamps);
