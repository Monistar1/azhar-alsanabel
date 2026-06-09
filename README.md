# Azhar Al-Sanabel - Premium Flower Shop

A secure, modern, and professional e-commerce web application for a luxury flower shop in Irbid, Jordan.

## Features

- **Modern 3D Interactive Background** - Canvas-based particle system with parallax effects
- **No Emojis** - Elegant SVG icons and smooth CSS animations throughout
- **Secure Authentication** - Password hashing, session management, rate limiting
- **Admin Dashboard** - Flask-Admin with role-based access control
- **Order Management** - Guest and user order tracking
- **Responsive Design** - Mobile-first, fully responsive on all devices
- **Bilingual** - English and Arabic support with RTL
- **SEO Ready** - Proper meta tags, semantic HTML, accessibility features

## Security Features

- CSRF Protection via Flask-Talisman
- Rate Limiting on auth endpoints (Flask-Limiter)
- XSS Prevention with Bleach sanitization
- SQL Injection Prevention via SQLAlchemy ORM
- Secure Headers (CSP, X-Frame-Options, etc.)
- Password Strength Validation
- Session Security (HttpOnly, Secure, SameSite)
- Input Validation & Sanitization

## Installation

```bash
# 1. Clone the repository
cd azhar_alsanabel

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy environment file
cp .env.example .env
# Edit .env with your settings

# 5. Run the application
python app.py
```

## Default Admin Credentials

- Email: `admin@azhar-alsanabel.com`
- Password: `AdminPass123!` (change immediately in production)

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| SECRET_KEY | Flask secret key | Auto-generated |
| DATABASE_URL | Database URI | sqlite:///azhar_alsanabel.db |
| ADMIN_EMAIL | Admin email | admin@azhar-alsanabel.com |
| ADMIN_PASSWORD | Admin password | AdminPass123! |
| SESSION_COOKIE_SECURE | Secure cookie flag | False |
| RATELIMIT_STORAGE_URI | Rate limit storage | memory:// |

## Production Deployment

```bash
# Using Gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

## Project Structure

```
azhar_alsanabel/
├── app.py                 # Main Flask application
├── requirements.txt       # Dependencies
├── .env.example          # Environment template
├── templates/
│   ├── index.html        # Main SPA template
│   ├── admin/
│   │   └── dashboard.html # Admin dashboard
│   └── errors/
│       ├── 404.html      # Not found page
│       ├── 500.html      # Server error page
│       └── 429.html      # Rate limit page
├── static/
│   ├── css/              # Stylesheets
│   ├── js/               # JavaScript files
│   ├── images/           # Image assets
│   └── fonts/            # Custom fonts
├── uploads/              # File uploads
└── logs/                 # Application logs
```

## License

All rights reserved. Azhar Al-Sanabel 2026.
