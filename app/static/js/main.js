/* ===================================================================
   main.js — PQ Password Manager 2
   Dynamic interactions: particles, strength meter, biometric, AJAX
   =================================================================== */

// ── Particle Background ───────────────────────────────────────────
(function initParticles() {
    const canvas = document.getElementById('particles-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let particles = [];
    let W, H;

    function resize() {
        W = canvas.width = window.innerWidth;
        H = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    class Particle {
        constructor() { this.reset(); }
        reset() {
            this.x = Math.random() * W;
            this.y = Math.random() * H;
            this.vx = (Math.random() - 0.5) * 0.4;
            this.vy = (Math.random() - 0.5) * 0.4;
            this.r = Math.random() * 1.5 + 0.5;
            this.a = Math.random() * 0.5 + 0.1;
        }
        update() {
            this.x += this.vx; this.y += this.vy;
            if (this.x < 0 || this.x > W || this.y < 0 || this.y > H) this.reset();
        }
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(99,102,241,${this.a})`;
            ctx.fill();
        }
    }

    for (let i = 0; i < 120; i++) particles.push(new Particle());

    function connectParticles() {
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 120) {
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(99,102,241,${0.05 * (1 - dist / 120)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }
    }

    function animate() {
        ctx.clearRect(0, 0, W, H);
        particles.forEach(p => { p.update(); p.draw(); });
        connectParticles();
        requestAnimationFrame(animate);
    }
    animate();
})();


// ── Flash Messages Auto-dismiss ───────────────────────────────────
document.querySelectorAll('.alert').forEach(el => {
    setTimeout(() => el.remove(), 5000);
});


// ── Password Toggle (show/hide) ───────────────────────────────────
document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
        const input = btn.closest('.password-input-wrapper').querySelector('input');
        if (input.type === 'password') {
            input.type = 'text';
            btn.textContent = '🙈';
        } else {
            input.type = 'password';
            btn.textContent = '👁';
        }
    });
});


// ── Live Password Strength Meter ──────────────────────────────────
const strengthInput = document.getElementById('password-input');
const strengthBar = document.getElementById('strength-fill');
const strengthLabel = document.getElementById('strength-label');
const crackTime = document.getElementById('crack-time');

if (strengthInput) {
    let debounceTimer;
    strengthInput.addEventListener('input', () => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(async () => {
            const pwd = strengthInput.value;
            if (!pwd) {
                if (strengthBar) { strengthBar.className = 'strength-fill'; strengthBar.style.width = '0'; }
                if (strengthLabel) strengthLabel.textContent = '';
                if (crackTime) crackTime.textContent = '';
                return;
            }
            try {
                const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
                const res = await fetch('/api/strength', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest',
                        'X-CSRFToken': csrf
                    },
                    body: JSON.stringify({ password: pwd })
                });
                const data = await res.json();
                const labels = ['Very Weak', 'Weak', 'Fair', 'Strong', 'Very Strong'];
                if (strengthBar) {
                    strengthBar.className = `strength-fill strength-${data.score}`;
                }
                if (strengthLabel) {
                    strengthLabel.textContent = labels[data.score] || '';
                    strengthLabel.className = `strength-text-${data.score}`;
                }
                if (crackTime && data.crack_time) {
                    crackTime.textContent = `Crack time: ${data.crack_time}`;
                }
            } catch { }
        }, 300);
    });
}


// ── Generate Password Button ──────────────────────────────────────
const genBtn = document.getElementById('generate-btn');
if (genBtn) {
    genBtn.addEventListener('click', async () => {
        const length = document.getElementById('gen-length')?.value || 16;
        const symbols = document.getElementById('gen-symbols')?.checked ? 'true' : 'false';
        const res = await fetch(`/api/generate?length=${length}&symbols=${symbols}`);
        const data = await res.json();
        if (strengthInput) {
            strengthInput.value = data.password;
            strengthInput.dispatchEvent(new Event('input'));
        }
    });
}


// ── AJAX Vault Card Delete ────────────────────────────────────────
document.querySelectorAll('.delete-entry-btn').forEach(btn => {
    btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        if (!confirm('Delete this entry?')) return;
        const id = btn.dataset.id;
        const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
        const res = await fetch(`/delete/${id}`, {
            method: 'POST',
            headers: { 'X-Requested-With': 'XMLHttpRequest', 'X-CSRFToken': csrf }
        });
        if (res.ok) {
            const card = btn.closest('.vault-card');
            card.style.transform = 'scale(0.9)';
            card.style.opacity = '0';
            card.style.transition = 'all 0.3s ease';
            setTimeout(() => card.remove(), 300);
        }
    });
});


// ── Search Filter ─────────────────────────────────────────────────
const searchInput = document.getElementById('vault-search');
if (searchInput) {
    searchInput.addEventListener('input', () => {
        const q = searchInput.value.toLowerCase();
        document.querySelectorAll('.vault-card').forEach(card => {
            const txt = card.textContent.toLowerCase();
            card.style.display = txt.includes(q) ? '' : 'none';
        });
    });
}


// ── Biometric Login ───────────────────────────────────────────────
const bioLoginBtn = document.getElementById('biometric-login-btn');
if (bioLoginBtn) {
    bioLoginBtn.addEventListener('click', async () => {
        const username = document.getElementById('username')?.value?.trim();
        if (!username) { alert('Enter your username first.'); return; }

        try {
            bioLoginBtn.disabled = true;
            bioLoginBtn.innerHTML = '<span class="fingerprint-icon">⏳</span> Authenticating...';

            const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
            const beginRes = await fetch('/biometric/login/begin', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': csrf
                },
                body: JSON.stringify({ username })
            });
            if (!beginRes.ok) throw new Error('No biometric registered for this user.');
            const options = await beginRes.json();

            // Decode base64url fields
            options.challenge = base64urlToArrayBuffer(options.challenge);
            options.allowCredentials = (options.allowCredentials || []).map(c => ({
                ...c, id: base64urlToArrayBuffer(c.id)
            }));

            const credential = await navigator.credentials.get({ publicKey: options });
            const completeRes = await fetch('/biometric/login/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': csrf
                },
                body: JSON.stringify(credentialToJSON(credential))
            });
            const result = await completeRes.json();
            if (result.redirect) window.location.href = result.redirect;
        } catch (err) {
            alert('Biometric login failed: ' + err.message);
            bioLoginBtn.disabled = false;
            bioLoginBtn.innerHTML = '<span class="fingerprint-icon">🖐</span> Login with Fingerprint / Face';
        }
    });
}


// ── Biometric Register ────────────────────────────────────────────
const bioRegBtn = document.getElementById('biometric-register-btn');
if (bioRegBtn) {
    bioRegBtn.addEventListener('click', async () => {
        try {
            bioRegBtn.disabled = true;
            bioRegBtn.textContent = '⏳ Registering...';
            const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
            const beginRes = await fetch('/biometric/register/begin', {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': csrf
                }
            });
            const options = await beginRes.json();

            options.challenge = base64urlToArrayBuffer(options.challenge);
            options.user.id = base64urlToArrayBuffer(options.user.id);
            options.excludeCredentials = (options.excludeCredentials || []).map(c => ({
                ...c, id: base64urlToArrayBuffer(c.id)
            }));

            const credential = await navigator.credentials.create({ publicKey: options });
            const completeRes = await fetch('/biometric/register/complete', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'X-CSRFToken': csrf
                },
                body: JSON.stringify(credentialToJSON(credential))
            });
            const result = await completeRes.json();
            if (result.status === 'ok') {
                document.getElementById('bio-status').textContent = '✅ Biometric registered successfully!';
                document.getElementById('bio-status').style.color = '#10b981';
            }
        } catch (err) {
            alert('Registration failed: ' + err.message);
            bioRegBtn.disabled = false;
            bioRegBtn.textContent = '🖐 Register Fingerprint / Face';
        }
    });
}


// ── WebAuthn Helper Functions ─────────────────────────────────────
function base64urlToArrayBuffer(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const buf = new ArrayBuffer(bin.length);
    const view = new Uint8Array(buf);
    for (let i = 0; i < bin.length; i++) view[i] = bin.charCodeAt(i);
    return buf;
}

function arrayBufferToBase64url(buf) {
    const bytes = new Uint8Array(buf);
    let str = '';
    for (const b of bytes) str += String.fromCharCode(b);
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function credentialToJSON(credential) {
    const obj = {};
    if (credential.id) obj.id = credential.id;
    if (credential.type) obj.type = credential.type;
    if (credential.rawId) obj.rawId = arrayBufferToBase64url(credential.rawId);
    if (credential.response) {
        const r = credential.response;
        obj.response = {};
        for (const key of ['clientDataJSON', 'attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
            if (r[key]) obj.response[key] = arrayBufferToBase64url(r[key]);
        }
    }
    return obj;
}


// ── Copy to clipboard ─────────────────────────────────────────────
document.querySelectorAll('.copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const text = btn.dataset.copy;
        navigator.clipboard.writeText(text).then(() => {
            const orig = btn.textContent;
            btn.textContent = '✓ Copied!';
            btn.style.color = '#10b981';
            setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
        });
    });
});
