require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GitHubStrategy = require('passport-github2').Strategy;
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const http = require('http');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' ? 'https://<tu-sitio>.netlify.app' : 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Configuración de Express
app.use(express.static('public'));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 3600000,
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    sameSite: 'lax'
  }
}));
app.use(passport.initialize());
app.use(passport.session());

// Configuración de Passport para GitHub OAuth
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL
}, (accessToken, refreshToken, profile, done) => {
  console.log('Perfil de GitHub recibido:', {
    id: profile.id,
    username: profile.username,
    email: profile.emails ? profile.emails[0]?.value : 'No email'
  });
  return done(null, profile);
}));

passport.serializeUser((user, done) => {
  console.log('Serializando usuario:', user.id);
  done(null, user.id);
});
passport.deserializeUser((id, done) => {
  console.log('Deserializando usuario:', id);
  done(null, { id, username: 'unknown' });
});

// Middleware para verificar JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      console.log('Invalid token:', err.message);
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Rutas de autenticación
app.get('/auth/github', (req, res, next) => {
  console.log('Accediendo a /auth/github con sesión:', req.session);
  // Limpiar sesión existente para forzar nueva autenticación
  req.session.destroy((err) => {
    if (err) {
      console.error('Error al limpiar sesión:', err);
      return next(err);
    }
    res.clearCookie('connect.sid');
    console.log('Sesión limpiada, iniciando autenticación con GitHub');
    passport.authenticate('github', { 
      scope: ['user:email'],
      session: true
    })(req, res, next);
  });
});

app.get('/auth/github/callback', (req, res, next) => {
  console.log('Accediendo a /auth/github/callback con query:', req.query);
  passport.authenticate('github', { 
    failureRedirect: '/?error=auth_failed',
    failureMessage: true
  })(req, res, next);
}, (req, res) => {
  try {
    if (!req.user) {
      console.error('Error: No se recibió el perfil del usuario');
      return res.redirect('/?error=no_user');
    }
    console.log('Generando JWT para usuario:', req.user.id);
    const token = jwt.sign(
      { id: req.user.id, username: req.user.username || 'unknown' },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    console.log('JWT generado:', token);
    res.redirect(`/?token=${token}`);
  } catch (error) {
    console.error('Error en /auth/github/callback:', error);
    res.redirect('/?error=jwt_generation_failed');
  }
});

// Ruta de logout
app.get('/logout', (req, res) => {
  console.log('Cerrando sesión para usuario:', req.user?.id);
  req.logout((err) => {
    if (err) {
      console.error('Error al cerrar sesión:', err);
      return res.redirect('/?error=logout_failed');
    }
    req.session.destroy(() => {
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  });
});

// Ruta protegida
app.get('/api/profile', authenticateJWT, (req, res) => {
  console.log('Accediendo a /api/profile para usuario:', req.user.id);
  res.json({ id: req.user.id, username: req.user.username || 'unknown' });
});

// Socket.io para reacciones en tiempo real
const emojiCounts = { '😊': 0, '👍': 0, '❤️': 0 };

io.on('connection', (socket) => {
  console.log('Nuevo cliente conectado:', socket.id);
  socket.emit('emoji:updated', emojiCounts);

  socket.on('emoji:react', (emoji) => {
    if (emojiCounts[emoji] !== undefined) {
      emojiCounts[emoji]++;
      console.log('Reacción recibida:', emoji, 'Nuevos contadores:', emojiCounts);
      io.emit('emoji:updated', emojiCounts);
    }
  });

  socket.on('disconnect', () => {
    console.log('Cliente desconectado:', socket.id);
  });
});

// Ruta raíz
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));