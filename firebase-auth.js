import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-app.js';
import {
    createUserWithEmailAndPassword,
    getAuth,
    onAuthStateChanged,
    sendPasswordResetEmail,
    signInWithEmailAndPassword,
    signOut,
    updateProfile
} from 'https://www.gstatic.com/firebasejs/11.10.0/firebase-auth.js';

const config = window.CYBERWIN_FIREBASE_CONFIG;
const validConfig = config
    && config.apiKey
    && !config.apiKey.startsWith('REPLACE_')
    && config.projectId
    && !config.projectId.startsWith('REPLACE_')
    && config.appId
    && !config.appId.startsWith('REPLACE_');

const userForm = document.getElementById('user-auth-form');
const adminForm = document.getElementById('admin-login-form');
const authMessage = document.getElementById('user-auth-message');
const adminMessage = document.getElementById('admin-auth-message');
let auth = null;
let presenceTimer = null;

function setMessage(element, message, isError = true) {
    if (!element) return;
    element.textContent = message;
    element.classList.toggle('text-red-400', isError);
    element.classList.toggle('text-emerald-400', !isError);
}

function getFirebaseErrorMessage(error) {
    const messages = {
        'auth/email-already-in-use': 'Ese correo ya tiene una cuenta. Inicia sesión.',
        'auth/invalid-email': 'El correo electrónico no tiene un formato válido.',
        'auth/invalid-credential': 'Correo o contraseña incorrectos.',
        'auth/weak-password': 'La contraseña debe tener al menos 8 caracteres.',
        'auth/too-many-requests': 'Hubo demasiados intentos. Espera un momento e inténtalo de nuevo.',
        'auth/network-request-failed': 'No se pudo conectar con Firebase. Revisa tu conexión.'
    };
    return messages[error.code] || 'No se pudo completar la autenticación. Verifica Firebase y vuelve a intentar.';
}

async function apiRequest(url, options = {}) {
    const user = auth.currentUser;
    if (!user) throw new Error('Inicia sesión para continuar.');
    const token = await user.getIdToken();
    const response = await fetch(url, {
        ...options,
        headers: {
            'Content-Type': 'application/json',
            ...options.headers,
            Authorization: `Bearer ${token}`
        }
    });
    if (!response.ok) {
        let message = `Error del servidor (${response.status}).`;
        try {
            const payload = await response.json();
            if (payload.error) message = payload.error;
        } catch {
            // Non-JSON error responses retain the explicit HTTP status.
        }
        throw new Error(message);
    }
    if (response.status === 204) return null;
    return response.json();
}

async function saveProfile(profile) {
    const result = await apiRequest('/api/me', {
        method: 'PUT',
        body: JSON.stringify(profile)
    });
    publishAuthState(auth.currentUser, result.profile);
    return result.profile;
}

function publishAuthState(user, profile = null, ready = true) {
    clearInterval(presenceTimer);
    presenceTimer = null;
    window.cyberWinAuthState = { ready, user, profile };
    if (!user) {
        localStorage.removeItem('liga_bs_usuario_activo');
    } else if (profile?.nickname && profile?.tag) {
        localStorage.setItem('liga_bs_usuario_activo', JSON.stringify({
            email: user.email,
            nickname: profile.nickname,
            tag: profile.tag,
            theme: profile.theme,
            accentColor: profile.accentColor,
            isCreator: profile.isCreator === true
        }));
    }
    window.dispatchEvent(new CustomEvent('cyberwin:auth-changed'));
    if (user && profile?.nickname && profile?.tag && window.cyberWinAuth) {
        const updatePresence = () => window.cyberWinAuth.request('/api/me/presence', { method: 'POST' })
            .catch(error => console.error('No se pudo actualizar la presencia:', error));
        updatePresence();
        presenceTimer = setInterval(updatePresence, 30_000);
    }
}

function profileFromForm(prefix = 'user') {
    const nicknameId = prefix === 'account' ? 'account-nickname' : 'user-nick';
    const tagId = prefix === 'account' ? 'account-tag' : 'user-tag';
    const profile = window.cyberWinAuthState?.profile;
    return {
        nickname: document.getElementById(nicknameId)?.value.trim(),
        tag: document.getElementById(tagId)?.value.trim(),
        theme: document.getElementById('account-theme')?.value || 'red',
        accentColor: document.getElementById('account-accent')?.value || '#dc2626',
        avatar: profile?.avatar || '',
        banner: profile?.banner || '',
        bannerColor: document.getElementById('account-banner-color')?.value || '#1c1917'
    };
}

function populateAccountForm(profile) {
    if (!profile) return;
    const nickname = document.getElementById('account-nickname');
    const tag = document.getElementById('account-tag');
    if (nickname) nickname.value = profile.nickname || '';
    if (tag) tag.value = profile.tag || '';
    const palette = {
        red: '#dc2626', ocean: '#0891b2', forest: '#16a34a', violet: '#9333ea',
        rose: '#e11d48', gold: '#d97706', cyber: '#06b6d4', arctic: '#38bdf8',
        sunset: '#f97316', mono: '#a1a1aa'
    };
    const accent = document.getElementById('account-accent');
    if (accent) accent.dataset.customized = String(profile.accentColor !== (palette[profile.theme] || palette.red));
    const bannerColor = document.getElementById('account-banner-color');
    if (bannerColor) bannerColor.value = profile.bannerColor || '#1c1917';
    if (typeof window.mostrarVistaPreviaPerfil === 'function') window.mostrarVistaPreviaPerfil(profile);
    const userNickname = document.getElementById('user-nick');
    const userTag = document.getElementById('user-tag');
    if (userNickname) userNickname.value = profile.nickname || '';
    if (userTag) userTag.value = profile.tag || '';
}

async function handleUserAuth(event) {
    event.preventDefault();
    const submitter = event.submitter || userForm.querySelector('button[type="submit"]');
    const mode = submitter?.dataset.authMode || 'login';
    const email = document.getElementById('user-email').value.trim().toLowerCase();
    const password = document.getElementById('user-password').value;
    const nickname = document.getElementById('user-nick').value.trim();
    const rawTag = document.getElementById('user-tag').value.trim().toUpperCase();
    const tag = rawTag && !rawTag.startsWith('#') ? `#${rawTag}` : rawTag;
    if (mode === 'register' && (nickname.length < 2 || nickname.length > 20 || !/^#?[0-9A-Z]{3,10}$/i.test(tag))) {
        setMessage(authMessage, 'Para crear una cuenta, indica un nickname (2-20 caracteres) y un Player Tag válido.');
        return;
    }
    if (mode === 'register' && password.length < 8) {
        setMessage(authMessage, 'La contraseña debe tener al menos 8 caracteres.');
        return;
    }
    submitter.disabled = true;
    setMessage(authMessage, 'Conectando con Firebase…', false);
    let accountCreated = false;
    try {
        const credential = mode === 'register'
            ? await createUserWithEmailAndPassword(auth, email, password)
            : await signInWithEmailAndPassword(auth, email, password);
        let profile;
        if (mode === 'register') {
            accountCreated = true;
            await updateProfile(credential.user, { displayName: nickname });
            profile = await saveProfile({
                ...profileFromForm(),
                nickname,
                tag
            });
        } else {
            const existing = (await apiRequest('/api/me')).profile;
            const savedNickname = existing.nickname || nickname;
            const savedTag = existing.tag || tag;
            if (!savedNickname || !savedTag) {
                throw new Error('Completa tu nickname y Player Tag para terminar de configurar tu perfil.');
            }
            profile = existing.nickname && existing.tag
                ? existing
                : await saveProfile({
                    nickname: savedNickname,
                    tag: savedTag,
                    theme: existing.theme || 'red',
                    accentColor: existing.accentColor || '#dc2626'
                });
        }
        document.getElementById('user-password').value = '';
        setMessage(authMessage, 'Sesión iniciada y perfil sincronizado.', false);
        publishAuthState(credential.user, profile);
    } catch (error) {
        const message = accountCreated && !error.code
            ? `La cuenta Firebase se creó, pero no se guardó el perfil: ${error.message} Inicia sesión con esa cuenta para completar el perfil.`
            : error.code ? getFirebaseErrorMessage(error) : error.message;
        setMessage(authMessage, message);
    } finally {
        submitter.disabled = false;
    }
}

async function handleAdminAuth(event) {
    event.preventDefault();
    const submitter = event.submitter || adminForm.querySelector('button[type="submit"]');
    submitter.disabled = true;
    setMessage(adminMessage, 'Verificando cuenta con Firebase…', false);
    try {
        const credential = await signInWithEmailAndPassword(
            auth,
            document.getElementById('admin-email').value.trim().toLowerCase(),
            document.getElementById('admin-password').value
        );
        const result = await apiRequest('/api/me');
        if (result.profile.role !== 'admin') {
            await signOut(auth);
            throw new Error('Esta cuenta no tiene rol administrador. Solicita al responsable que habilite el rol en PostgreSQL.');
        }
        publishAuthState(credential.user, result.profile);
        window.activarPanelAdminCompleto();
    } catch (error) {
        setMessage(adminMessage, error.code ? getFirebaseErrorMessage(error) : error.message);
    } finally {
        submitter.disabled = false;
    }
}

async function prepareImageFile(file, kind) {
    const isAvatar = kind === 'avatar';
    const maxBytes = isAvatar ? 300 * 1024 : 700 * 1024;
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(file.type)) {
        throw new Error('Usa una imagen JPEG, PNG o WebP.');
    }
    if (file.size > 12 * 1024 * 1024) throw new Error('La imagen original no puede superar 12 MB.');
    const bitmap = await createImageBitmap(file);
    if (bitmap.width * bitmap.height > 40_000_000) {
        bitmap.close();
        throw new Error('La imagen supera los 40 megapíxeles permitidos.');
    }
    const targetWidth = isAvatar ? 512 : 1600;
    const targetHeight = isAvatar ? 512 : 600;
    const canvas = document.createElement('canvas');
    canvas.width = isAvatar ? targetWidth : Math.max(1, Math.round(bitmap.width * Math.min(targetWidth / bitmap.width, targetHeight / bitmap.height, 1)));
    canvas.height = isAvatar ? targetHeight : Math.max(1, Math.round(bitmap.height * Math.min(targetWidth / bitmap.width, targetHeight / bitmap.height, 1)));
    const context = canvas.getContext('2d');
    if (!context) throw new Error('No se pudo preparar la imagen en este navegador.');
    if (isAvatar) {
        const side = Math.min(bitmap.width, bitmap.height);
        context.drawImage(bitmap, (bitmap.width - side) / 2, (bitmap.height - side) / 2, side, side, 0, 0, targetWidth, targetHeight);
    } else {
        context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    }
    bitmap.close();
    let blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', 0.88));
    for (let quality = 0.78; blob && blob.size > maxBytes && quality >= 0.48; quality -= 0.1) {
        blob = await new Promise(resolve => canvas.toBlob(resolve, 'image/jpeg', quality));
    }
    if (!blob || blob.size > maxBytes) {
        throw new Error(`No se pudo reducir la imagen al límite de ${Math.round(maxBytes / 1024)} KB. Prueba con otra imagen.`);
    }
    return await new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(new Error('No se pudo leer la imagen seleccionada.'));
        reader.readAsDataURL(blob);
    });
}

async function handleAccountUpdate(event) {
    event.preventDefault();
    const submitter = event.submitter || document.querySelector('#account-form button[type="submit"]');
    submitter.disabled = true;
    setMessage(document.getElementById('account-message'), 'Optimizando y guardando el perfil…', false);
    try {
        const update = profileFromForm('account');
        const avatarFile = document.getElementById('account-avatar-file').files[0];
        const bannerFile = document.getElementById('account-banner-file').files[0];
        if (avatarFile) update.avatar = await prepareImageFile(avatarFile, 'avatar');
        if (bannerFile) update.banner = await prepareImageFile(bannerFile, 'banner');
        const profile = await saveProfile(update);
        document.getElementById('account-avatar-file').value = '';
        document.getElementById('account-banner-file').value = '';
        applyTheme(profile.theme, profile.accentColor);
        setMessage(document.getElementById('account-message'), 'Perfil actualizado y sincronizado.', false);
    } catch (error) {
        setMessage(document.getElementById('account-message'), error.message);
    } finally {
        submitter.disabled = false;
    }
}

async function handlePasswordReset() {
    const email = document.getElementById('user-email').value.trim();
    if (!email) {
        setMessage(authMessage, 'Escribe tu correo para enviarte el enlace de recuperación.');
        return;
    }
    try {
        await sendPasswordResetEmail(auth, email);
        setMessage(authMessage, 'Si el correo corresponde a una cuenta, Firebase enviará el enlace de recuperación.', false);
    } catch (error) {
        setMessage(authMessage, getFirebaseErrorMessage(error));
    }
}

function applyTheme(theme = 'red', accentColor = '#dc2626') {
    const themes = ['red', 'ocean', 'forest', 'violet', 'rose', 'gold', 'cyber', 'arctic', 'sunset', 'mono'];
    const safeTheme = themes.includes(theme) ? theme : 'red';
    document.body.dataset.theme = safeTheme;
    document.body.style.setProperty('--custom-accent', /^#[0-9a-f]{6}$/i.test(accentColor) ? accentColor : '#dc2626');
    ['selector-tema-usuario', 'account-theme'].forEach(id => {
        const select = document.getElementById(id);
        if (select) select.value = safeTheme;
    });
    const color = document.getElementById('account-accent');
    if (color) color.value = accentColor;
}

if (!validConfig) {
    const message = 'Configura Firebase en firebase-config.js y habilita Email/Password en Firebase Console.';
    setMessage(authMessage, message);
    setMessage(adminMessage, message);
    userForm?.addEventListener('submit', event => {
        event.preventDefault();
        setMessage(authMessage, message);
    });
    adminForm?.addEventListener('submit', event => {
        event.preventDefault();
        setMessage(adminMessage, message);
    });
    window.cyberWinAuthState = { ready: true, user: null, profile: null };
    window.dispatchEvent(new CustomEvent('cyberwin:auth-changed'));
} else {
    const app = initializeApp(config);
    auth = getAuth(app);
    window.cyberWinAuth = { request: apiRequest, saveProfile, signOut: () => signOut(auth), applyTheme };
    userForm?.addEventListener('submit', handleUserAuth);
    adminForm?.addEventListener('submit', handleAdminAuth);
    document.getElementById('account-form')?.addEventListener('submit', handleAccountUpdate);
    document.getElementById('password-reset')?.addEventListener('click', handlePasswordReset);
    onAuthStateChanged(auth, async user => {
        if (!user) {
            publishAuthState(null);
            return;
        }
        try {
            const result = await apiRequest('/api/me');
            publishAuthState(user, result.profile);
            populateAccountForm(result.profile);
            applyTheme(result.profile.theme, result.profile.accentColor);
            if (adminForm && result.profile.role === 'admin') window.activarPanelAdminCompleto();
        } catch (error) {
            publishAuthState(user, null);
            setMessage(adminForm ? adminMessage : authMessage, error.message);
        }
    });
}
