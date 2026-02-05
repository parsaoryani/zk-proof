# ZK-Mixer Frontend Documentation

Modern, responsive frontend for the ZK-Mixer privacy-preserving transaction system.

## 📁 File Structure

```
frontend/
├── landing.html              # Modern landing page with hero section
├── index.html               # Main application (login/dashboard)
├── dashboard.html           # Enhanced dashboard with analytics
├── crypto-dashboard.html    # Interactive cryptography testing lab
├── crypto-flow.html         # Cryptographic flow visualization
├── app.css                  # Modern CSS framework with utilities
├── app.js                   # Enhanced JavaScript utilities
└── version.js              # Version control for cache busting
```

## 🚀 Features

### Landing Page (`landing.html`)
- **Hero Section**: Eye-catching gradient background with floating animations
- **Features Grid**: Showcase 6 core features with hover effects
- **How It Works**: Step-by-step process visualization
- **Statistics**: Animated counters showing platform metrics
- **Responsive Navigation**: Mobile-friendly menu
- **Call-to-Action**: Strategic CTAs throughout the page

### Main Application (`index.html`)
- **Authentication**: Secure login and registration
- **User Dashboard**: Transaction management interface
- **Real-time Updates**: Auto-refresh every 5 seconds
- **Transaction History**: Complete audit trail
- **Admin Panel**: Administrative controls for authorized users
- **Proof Verification**: ZK-proof generation and verification

### Enhanced Dashboard (`dashboard.html`)
- **Statistics Cards**: Real-time balance, deposits, withdrawals, active transactions
- **Quick Actions**: One-click access to common operations
- **Activity Feed**: Recent transaction history with timestamps
- **Health Monitoring**: System status indicator
- **User Profile**: Avatar and role display
- **Responsive Grid**: Adapts to all screen sizes

### Crypto Dashboard (`crypto-dashboard.html`)
- **Interactive Testing**: Test cryptographic primitives in real-time
- **Hash Functions**: Test SHA-256, Blake2, Keccak
- **Commitment Schemes**: Pedersen commitments with blinding factors
- **Merkle Trees**: Visualize tree construction and proof verification
- **ZK Proofs**: Generate and verify zero-knowledge proofs
- **Educational**: Learn cryptography through hands-on experimentation

### Crypto Flow (`crypto-flow.html`)
- **Visual Documentation**: Understand the complete cryptographic flow
- **Protocol Phases**: Deposit, withdrawal, and verification processes
- **Code Examples**: Real implementation snippets
- **Proof Components**: Public/private inputs visualization
- **Security Properties**: Understand anonymity guarantees

## 🎨 Design System

### CSS Framework (`app.css`)

#### Color Palette
```css
--primary-color: #667eea
--secondary-color: #764ba2
--success-color: #10b981
--error-color: #ef4444
--warning-color: #f59e0b
--info-color: #3b82f6
```

#### Components
- **Buttons**: Primary, secondary, success, danger, outline variants
- **Cards**: Shadow, hover effects, responsive
- **Forms**: Styled inputs with validation states
- **Badges**: Status indicators with color coding
- **Modals**: Centered overlays with backdrop
- **Toast Notifications**: Non-intrusive alerts
- **Skeletons**: Loading state placeholders
- **Progress Bars**: Determinate and indeterminate variants

#### Utilities
- **Spacing**: mt-1 to mt-4, mb-1 to mb-4, p-1 to p-4
- **Grid**: grid-cols-1 to grid-cols-4 (responsive)
- **Flexbox**: flex, flex-col, items-center, justify-between
- **Text Alignment**: text-center, text-left, text-right
- **Display**: hidden, opacity utilities

### JavaScript Utilities (`app.js`)

#### Toast Notifications
```javascript
toast.success('Operation completed!');
toast.error('Something went wrong');
toast.warning('Please review this');
toast.info('Helpful information');
```

#### Theme Management
```javascript
themeManager.toggle(); // Switch between light/dark
themeManager.current; // Get current theme
```

#### Loading States
```javascript
loadingManager.setLoading('#myButton', true);
loadingManager.showSkeleton('containerId');
loadingManager.showCardSkeleton('containerId', 3);
```

#### Form Validation
```javascript
FormValidator.validate('myForm', {
    email: [
        FormValidator.required(),
        FormValidator.email()
    ],
    amount: [
        FormValidator.required(),
        FormValidator.numeric(),
        FormValidator.positive()
    ]
});
```

#### Clipboard Operations
```javascript
await copyToClipboard('text to copy', 'Custom success message');
```

#### String Utilities
```javascript
truncateHash('0x1234567890abcdef', 8, 8); // "0x123456...abcdef"
formatCurrency(1234.56); // "1,234.56"
formatDate(new Date()); // "Feb 5, 2026, 10:30 AM"
formatRelativeTime(date); // "2 hours ago"
```

#### API Helper
```javascript
const api = new APIHelper('http://localhost:8000');
api.setToken(authToken);

const data = await api.get('/endpoint');
await api.post('/endpoint', { key: 'value' });
```

#### Storage Helper
```javascript
StorageHelper.set('key', { data: 'value' });
const data = StorageHelper.get('key', defaultValue);
StorageHelper.remove('key');
StorageHelper.clear();
```

#### Modal Manager
```javascript
ModalManager.show('modalId');
ModalManager.hide('modalId');
ModalManager.hideAll();
```

#### Progress Bar
```javascript
const progress = new ProgressBar('containerId');
progress.set(50); // 50%
progress.setIndeterminate();
progress.hide();
```

## 🎯 Usage Guide

### Getting Started

1. **Start the Backend Server**
   ```bash
   cd /path/to/zk-project
   ./run.sh
   ```

2. **Open the Frontend**
   - Landing page: Open `landing.html` in your browser
   - Main app: Open `index.html` in your browser
   - Dashboard: Open `dashboard.html` (requires authentication)
   - Crypto Lab: Open `crypto-dashboard.html`

3. **Create an Account**
   - Click "Sign Up" tab
   - Enter username, email, and password
   - Click "Create Account"

4. **Make a Deposit**
   - Click "Deposit" tab after login
   - Enter amount
   - Save the secret and nullifier (CRITICAL!)
   - Click "Deposit Funds"

5. **Withdraw Funds**
   - Click "Withdraw" tab
   - Enter your secret and nullifier
   - Enter recipient username
   - Enter withdrawal amount
   - Click "Withdraw Funds"

### Configuration

Edit the `API_BASE` constant in each HTML file to match your backend URL:

```javascript
const API_BASE = 'http://localhost:8000'; // Change this to your API URL
```

## 🎨 Customization

### Changing Colors

Edit `app.css` and modify the CSS variables:

```css
:root {
    --primary-color: #your-color;
    --bg-gradient: linear-gradient(135deg, #color1 0%, #color2 100%);
}
```

### Adding New Components

1. Create the HTML structure
2. Add styles in a `<style>` section or `app.css`
3. Add JavaScript logic using the utilities from `app.js`
4. Use existing components as templates

### Custom Toast Messages

```javascript
// Customize duration (default: 3000ms)
toast.success('Message', 5000); // Show for 5 seconds
toast.error('Message', 0); // Show indefinitely
```

## 📱 Responsive Design

All pages are fully responsive with breakpoints:
- **Desktop**: > 1024px
- **Tablet**: 640px - 1024px
- **Mobile**: < 640px

Mobile features:
- Collapsible navigation
- Stacked layouts
- Touch-friendly buttons
- Optimized spacing

## 🔒 Security Considerations

### Never Store Secrets
- **Secrets and nullifiers** must NEVER be stored in localStorage
- Users must copy and save them securely
- Warn users prominently about losing secrets

### Authentication
- Tokens stored in localStorage
- Auto-logout on invalid token
- Session validation on page load

### Input Validation
- Client-side validation using FormValidator
- Server-side validation is still required
- Sanitize all user inputs

### HTTPS Required
- Always use HTTPS in production
- Secure cookie flags should be set
- CSP headers recommended

## 🚀 Performance Optimizations

### Lazy Loading
```javascript
// Load images on scroll
const images = document.querySelectorAll('img[data-src]');
const imgObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            const img = entry.target;
            img.src = img.dataset.src;
            imgObserver.unobserve(img);
        }
    });
});
```

### Debouncing Search
```javascript
const searchInput = document.getElementById('search');
searchInput.addEventListener('input', debounce((e) => {
    performSearch(e.target.value);
}, 300));
```

### Caching Strategy
- Use version.js for cache busting
- Store frequently accessed data in localStorage
- Implement service workers for offline support

## 🧪 Testing Recommendations

### Manual Testing Checklist
- [ ] Registration flow works
- [ ] Login persists across refreshes
- [ ] Deposit creates valid commitments
- [ ] Withdrawal validates proofs correctly
- [ ] Admin features only visible to admins
- [ ] Toast notifications appear and dismiss
- [ ] Forms validate input correctly
- [ ] Responsive design works on mobile
- [ ] Theme toggle persists

### Browser Compatibility
- ✅ Chrome/Edge (latest)
- ✅ Firefox (latest)
- ✅ Safari (latest)
- ✅ Mobile browsers (iOS/Android)

## 📊 Analytics Integration

To add analytics (e.g., Google Analytics):

```javascript
// Add to <head>
<script async src="https://www.googletagmanager.com/gtag/js?id=GA_MEASUREMENT_ID"></script>
<script>
  window.dataLayer = window.dataLayer || [];
  function gtag(){dataLayer.push(arguments);}
  gtag('js', new Date());
  gtag('config', 'GA_MEASUREMENT_ID');
</script>
```

## 🐛 Troubleshooting

### "Failed to fetch" errors
- Check if backend is running
- Verify API_BASE URL is correct
- Check CORS settings on backend

### Tokens not persisting
- Check browser localStorage quota
- Verify no extensions blocking storage
- Clear browser cache and try again

### Styles not loading
- Hard refresh (Ctrl+Shift+R)
- Check browser console for CSS errors
- Verify file paths are correct

### Modal not showing
- Check if modal ID matches
- Ensure ModalManager.show() is called
- Verify no CSS conflicts

## 🔄 Auto-Refresh

The main app auto-refreshes data every 5 seconds:
```javascript
setInterval(() => {
    refreshStats();
    refreshUserBalance();
    refreshTransactions();
}, 5000);
```

To change the interval:
```javascript
setInterval(() => {
    // Your refresh functions
}, 10000); // 10 seconds
```

## 🎓 Learning Resources

- [MDN Web Docs](https://developer.mozilla.org/) - HTML/CSS/JS reference
- [Web.dev](https://web.dev/) - Best practices and performance
- [CSS Tricks](https://css-tricks.com/) - CSS tutorials and examples
- [JavaScript.info](https://javascript.info/) - Modern JavaScript tutorial

## 📝 License

Part of the ZK-Mixer project. See main project LICENSE file.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For issues or questions:
- Check the troubleshooting section
- Review the main project documentation
- Open an issue on GitHub

---

**Built with ❤️ for privacy and security**
