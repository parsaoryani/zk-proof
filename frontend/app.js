/**
 * ZK-Mixer Frontend Utilities
 * Modern JavaScript utilities for enhanced UX
 */

// ============================================
// Toast Notification System
// ============================================
class ToastManager {
    constructor() {
        this.container = this.createContainer();
    }

    createContainer() {
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        return container;
    }

    show(message, type = 'info', duration = 3000) {
        const toast = document.createElement('div');
        toast.className = `toast ${type} fade-in`;
        
        const icons = {
            success: '✓',
            error: '✕',
            warning: '⚠',
            info: 'ℹ'
        };

        toast.innerHTML = `
            <div class="toast-icon">${icons[type] || icons.info}</div>
            <div class="toast-content">
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close" onclick="this.parentElement.remove()">×</button>
        `;

        this.container.appendChild(toast);

        if (duration > 0) {
            setTimeout(() => {
                toast.style.animation = 'fadeOut 0.3s ease';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        return toast;
    }

    success(message, duration) {
        return this.show(message, 'success', duration);
    }

    error(message, duration) {
        return this.show(message, 'error', duration);
    }

    warning(message, duration) {
        return this.show(message, 'warning', duration);
    }

    info(message, duration) {
        return this.show(message, 'info', duration);
    }
}

// Global toast instance
window.toast = new ToastManager();

// ============================================
// Theme Manager
// ============================================
class ThemeManager {
    constructor() {
        this.theme = localStorage.getItem('theme') || 'light';
        this.apply();
    }

    toggle() {
        this.theme = this.theme === 'light' ? 'dark' : 'light';
        this.apply();
        localStorage.setItem('theme', this.theme);
        return this.theme;
    }

    apply() {
        document.documentElement.setAttribute('data-theme', this.theme);
    }

    get current() {
        return this.theme;
    }
}

window.themeManager = new ThemeManager();

// ============================================
// Loading State Manager
// ============================================
class LoadingManager {
    constructor() {
        this.overlay = null;
        this.createOverlay();
    }

    createOverlay() {
        if (this.overlay) return;
        
        this.overlay = document.createElement('div');
        this.overlay.className = 'loading-overlay';
        this.overlay.innerHTML = `
            <div class="loading-spinner">
                <div class="spinner"></div>
                <p>Loading...</p>
            </div>
        `;
        this.overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: none;
            justify-content: center;
            align-items: center;
            z-index: 9999;
        `;
        
        const spinner = this.overlay.querySelector('.loading-spinner');
        spinner.style.cssText = `
            background: white;
            padding: 30px 50px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        `;
        
        const spinnerAnim = this.overlay.querySelector('.spinner');
        spinnerAnim.style.cssText = `
            width: 40px;
            height: 40px;
            border: 4px solid #e5e7eb;
            border-top-color: #667eea;
            border-radius: 50%;
            margin: 0 auto 15px;
            animation: spin 1s linear infinite;
        `;
        
        // Add keyframes
        if (!document.querySelector('#loading-keyframes')) {
            const style = document.createElement('style');
            style.id = 'loading-keyframes';
            style.textContent = `@keyframes spin { to { transform: rotate(360deg); } }`;
            document.head.appendChild(style);
        }
        
        document.body.appendChild(this.overlay);
    }

    show(message = 'Loading...') {
        this.createOverlay();
        const p = this.overlay.querySelector('p');
        if (p) p.textContent = message;
        this.overlay.style.display = 'flex';
    }

    hide() {
        if (this.overlay) {
            this.overlay.style.display = 'none';
        }
    }

    setLoading(element, isLoading) {
        if (typeof element === 'string') {
            element = document.querySelector(element);
        }
        
        if (!element) return;

        if (isLoading) {
            element.classList.add('loading');
            element.disabled = true;
        } else {
            element.classList.remove('loading');
            element.disabled = false;
        }
    }

    showSkeleton(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;

        container.innerHTML = `
            <div class="skeleton skeleton-title"></div>
            <div class="skeleton skeleton-text"></div>
            <div class="skeleton skeleton-text"></div>
            <div class="skeleton skeleton-text" style="width: 80%"></div>
        `;
    }

    showCardSkeleton(containerId, count = 3) {
        const container = document.getElementById(containerId);
        if (!container) return;

        container.innerHTML = Array(count).fill(0).map(() => 
            '<div class="card skeleton skeleton-card"></div>'
        ).join('');
    }
}

window.loadingManager = new LoadingManager();

// ============================================
// Form Validation
// ============================================
class FormValidator {
    static validate(formId, rules) {
        const form = document.getElementById(formId);
        if (!form) return false;

        let isValid = true;
        const errors = {};

        for (const [field, validators] of Object.entries(rules)) {
            const input = form.querySelector(`[name="${field}"]`);
            if (!input) continue;

            const value = input.value.trim();

            for (const validator of validators) {
                const result = validator(value);
                if (result !== true) {
                    isValid = false;
                    errors[field] = result;
                    this.showError(input, result);
                    break;
                } else {
                    this.clearError(input);
                }
            }
        }

        return isValid ? true : errors;
    }

    static showError(input, message) {
        this.clearError(input);
        
        input.classList.add('error');
        const errorDiv = document.createElement('div');
        errorDiv.className = 'field-error';
        errorDiv.style.color = '#ef4444';
        errorDiv.style.fontSize = '0.875rem';
        errorDiv.style.marginTop = '4px';
        errorDiv.textContent = message;
        
        input.parentElement.appendChild(errorDiv);
    }

    static clearError(input) {
        input.classList.remove('error');
        const errorDiv = input.parentElement.querySelector('.field-error');
        if (errorDiv) {
            errorDiv.remove();
        }
    }

    // Common validators
    static required(message = 'This field is required') {
        return (value) => value.length > 0 ? true : message;
    }

    static minLength(min, message) {
        return (value) => value.length >= min ? true : (message || `Minimum ${min} characters required`);
    }

    static maxLength(max, message) {
        return (value) => value.length <= max ? true : (message || `Maximum ${max} characters allowed`);
    }

    static email(message = 'Invalid email address') {
        return (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) ? true : message;
    }

    static numeric(message = 'Must be a number') {
        return (value) => !isNaN(value) && value !== '' ? true : message;
    }

    static positive(message = 'Must be a positive number') {
        return (value) => parseFloat(value) > 0 ? true : message;
    }
}

window.FormValidator = FormValidator;

// ============================================
// Clipboard Utilities
// ============================================
async function copyToClipboard(text, successMessage = 'Copied to clipboard!') {
    try {
        await navigator.clipboard.writeText(text);
        toast.success(successMessage);
        return true;
    } catch (err) {
        console.error('Failed to copy:', err);
        toast.error('Failed to copy to clipboard');
        return false;
    }
}

window.copyToClipboard = copyToClipboard;

// ============================================
// String Utilities
// ============================================
function truncateHash(hash, startLength = 8, endLength = 8) {
    if (!hash || hash.length <= startLength + endLength) return hash;
    return `${hash.substring(0, startLength)}...${hash.substring(hash.length - endLength)}`;
}

function formatCurrency(amount, decimals = 2) {
    return new Intl.NumberFormat('en-US', {
        minimumFractionDigits: decimals,
        maximumFractionDigits: decimals
    }).format(amount);
}

function formatDate(date) {
    return new Intl.DateTimeFormat('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }).format(new Date(date));
}

function formatRelativeTime(date) {
    const now = new Date();
    const then = new Date(date);
    const diffMs = now - then;
    const diffSecs = Math.floor(diffMs / 1000);
    const diffMins = Math.floor(diffSecs / 60);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);

    if (diffSecs < 60) return 'just now';
    if (diffMins < 60) return `${diffMins} min${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    return formatDate(date);
}

window.truncateHash = truncateHash;
window.formatCurrency = formatCurrency;
window.formatDate = formatDate;
window.formatRelativeTime = formatRelativeTime;

// ============================================
// Debounce & Throttle
// ============================================
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

window.debounce = debounce;
window.throttle = throttle;

// ============================================
// API Helper
// ============================================
class APIHelper {
    constructor(baseURL) {
        this.baseURL = baseURL;
        this.token = null;
    }

    setToken(token) {
        this.token = token;
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };

        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, {
                ...options,
                headers
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.detail || data.message || 'Request failed');
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    async get(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'GET' });
    }

    async post(endpoint, body, options = {}) {
        return this.request(endpoint, {
            ...options,
            method: 'POST',
            body: JSON.stringify(body)
        });
    }

    async put(endpoint, body, options = {}) {
        return this.request(endpoint, {
            ...options,
            method: 'PUT',
            body: JSON.stringify(body)
        });
    }

    async delete(endpoint, options = {}) {
        return this.request(endpoint, { ...options, method: 'DELETE' });
    }
}

window.APIHelper = APIHelper;

// ============================================
// Local Storage Helper
// ============================================
class StorageHelper {
    static set(key, value) {
        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch (e) {
            console.error('Storage error:', e);
            return false;
        }
    }

    static get(key, defaultValue = null) {
        try {
            const item = localStorage.getItem(key);
            return item ? JSON.parse(item) : defaultValue;
        } catch (e) {
            console.error('Storage error:', e);
            return defaultValue;
        }
    }

    static remove(key) {
        localStorage.removeItem(key);
    }

    static clear() {
        localStorage.clear();
    }
}

window.StorageHelper = StorageHelper;

// ============================================
// Modal Manager
// ============================================
class ModalManager {
    static show(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.add('show');
            document.body.style.overflow = 'hidden';
        }
    }

    static hide(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.classList.remove('show');
            document.body.style.overflow = '';
        }
    }

    static hideAll() {
        document.querySelectorAll('.modal.show').forEach(modal => {
            modal.classList.remove('show');
        });
        document.body.style.overflow = '';
    }
}

window.ModalManager = ModalManager;

// ============================================
// Confirmation Dialog
// ============================================
function confirm(message, title = 'Confirm') {
    return new Promise((resolve) => {
        const modal = document.createElement('div');
        modal.className = 'modal show';
        modal.innerHTML = `
            <div class="modal-content" style="max-width: 400px;">
                <div class="modal-header">
                    <h2>${title}</h2>
                </div>
                <div class="modal-body">
                    <p>${message}</p>
                </div>
                <div class="modal-footer" style="display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px;">
                    <button class="btn btn-secondary" onclick="this.closest('.modal').remove(); document.body.style.overflow = '';">Cancel</button>
                    <button class="btn btn-primary" id="confirmBtn">Confirm</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);
        document.body.style.overflow = 'hidden';

        modal.querySelector('#confirmBtn').addEventListener('click', () => {
            modal.remove();
            document.body.style.overflow = '';
            resolve(true);
        });

        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.remove();
                document.body.style.overflow = '';
                resolve(false);
            }
        });
    });
}

window.confirm = confirm;

// ============================================
// Progress Bar
// ============================================
class ProgressBar {
    constructor(containerId) {
        this.container = document.getElementById(containerId);
        if (!this.container) {
            console.error(`Container ${containerId} not found`);
            return;
        }
        
        this.bar = document.createElement('div');
        this.bar.className = 'progress-bar';
        this.bar.innerHTML = '<div class="progress-fill"></div>';
        this.container.appendChild(this.bar);
        this.fill = this.bar.querySelector('.progress-fill');
    }

    set(percent) {
        if (this.fill) {
            this.fill.style.width = `${Math.min(100, Math.max(0, percent))}%`;
        }
    }

    setIndeterminate() {
        if (this.fill) {
            this.fill.classList.add('progress-indeterminate');
        }
    }

    hide() {
        if (this.bar) {
            this.bar.style.display = 'none';
        }
    }

    show() {
        if (this.bar) {
            this.bar.style.display = 'block';
        }
    }
}

window.ProgressBar = ProgressBar;

// ============================================
// Initialize on DOM Load
// ============================================
document.addEventListener('DOMContentLoaded', () => {
    console.log('ZK-Mixer Enhanced UI loaded');
    
    // Add theme toggle button if not exists
    if (!document.querySelector('.theme-toggle')) {
        const themeToggle = document.createElement('button');
        themeToggle.className = 'theme-toggle';
        themeToggle.innerHTML = '🌙';
        themeToggle.title = 'Toggle dark mode';
        themeToggle.addEventListener('click', () => {
            const newTheme = themeManager.toggle();
            themeToggle.innerHTML = newTheme === 'dark' ? '☀️' : '🌙';
            toast.info(`${newTheme === 'dark' ? 'Dark' : 'Light'} mode enabled`);
        });
        document.body.appendChild(themeToggle);
    }

    // Close modals on Escape key
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            ModalManager.hideAll();
        }
    });
});

// ============================================
// Export for modules
// ============================================
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        toast,
        themeManager,
        loadingManager,
        FormValidator,
        APIHelper,
        StorageHelper,
        ModalManager,
        ProgressBar
    };
}
