
// Robust parser for server timestamps
function parseServerTime(raw) {
  if (!raw) return null;
  const s = String(raw).trim();

  // 1) Pure numeric → epoch (sec or ms)
  if (/^\d+$/.test(s)) {
    const n = Number(s);
    return new Date(n < 1e12 ? n * 1000 : n);
  }

  // 2) Already ISO with timezone (Z or ±hh:mm) → pass through
  if (/[zZ]|[+\-]\d{2}:\d{2}$/.test(s)) {
    const d = new Date(s);
    return isNaN(d) ? null : d;
  }

  // 3) "YYYY-MM-DD" only → assume midnight UTC
  if (/^\d{4}-\d{2}-\d{2}$/.test(s)) {
    const d = new Date(`${s}T00:00:00Z`);
    return isNaN(d) ? null : d;
  }

  // 4) "YYYY-MM-DD HH:MM:SS(.ffffff)?" → normalize
  //    - replace space with T
  //    - trim fractional seconds to max 3 digits for Safari
  let norm = s.replace(' ', 'T');

  // fractional seconds handling
  norm = norm.replace(
    /(\.\d+)(?=$|[Zz]|[+\-]\d{2}:\d{2})/,
    (_, frac) => '.' + frac.slice(1, 4) // keep up to 3 digits
  );

  // append Z (assume UTC) only if no tz present
  if (!/[+\-]\d{2}:\d{2}$/.test(norm) && !/[zZ]$/.test(norm)) {
    norm += 'Z';
  }

  const d = new Date(norm);
  return isNaN(d) ? null : d;
}

function getRelativeTime(date) {
  const now = new Date();
  const diffMs = now - date;
  const sec = Math.floor(diffMs / 1000);
  const min = Math.floor(sec / 60);
  const hr  = Math.floor(min / 60);
  const day = Math.floor(hr / 24);

  if (sec < 60) return 'just now';
  if (min < 60) return `${min}m ago`;
  if (hr  < 24) return `${hr}h ago`;
  if (day < 7) return `${day}d ago`;

  return date.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
  });
}

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
  const els = document.querySelectorAll('[data-timestamp]');
  const tz  = Intl.DateTimeFormat().resolvedOptions().timeZone;

  els.forEach(el => {
    const raw = el.getAttribute('data-timestamp');
    const d = parseServerTime(raw);

    if (!d) {
      el.textContent = '—';
      el.title = `Unable to parse: ${raw ?? '(empty)'}`;
      el.style.cursor = 'help';
      // Optional inline debug without desktop console:
      if (new URLSearchParams(location.search).has('debug')) {
        showToast(`Invalid date: ${raw}`, 'error');
      }
      return;
    }

    const full = d.toLocaleString(undefined, {
      year:'numeric', month:'short', day:'numeric',
      hour:'2-digit', minute:'2-digit', second:'2-digit', hour12:false
    });

    const useRelative = el.getAttribute('data-time-format') !== 'absolute';
    el.textContent = useRelative ? getRelativeTime(d) : full;
    el.title = `${full} (${tz})`;
    el.style.cursor = 'help';
  });
};

document.addEventListener('DOMContentLoaded', window.convertTimestamps);
