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

// Store para usuarios conectados (en producción usar Redis o base de datos)
const connectedUsers = new Map();

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
    displayName: profile.displayName,
    email: profile.emails ? profile.emails[0]?.value : 'No email'
  });
  
  // Guardar información completa del usuario
  const userData = {
    id: profile.id,
    username: profile.username || profile.displayName || `user_${profile.id}`,
    displayName: profile.displayName,
    email: profile.emails ? profile.emails[0]?.value : null,
    avatar: profile.photos ? profile.photos[0]?.value : null
  };
  
  return done(null, userData);
}));

passport.serializeUser((user, done) => {
  console.log('Serializando usuario:', user.id);
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  console.log('Deserializando usuario:', id);
  // En lugar de retornar datos ficticios, buscar en nuestro store o usar los datos de la sesión
  const userData = connectedUsers.get(id) || { id, username: `user_${id}` };
  done(null, userData);
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

// Rutas de autenticación - SIN limpiar sesión
app.get('/auth/github', (req, res, next) => {
  console.log('Iniciando autenticación con GitHub para nueva sesión');
  passport.authenticate('github', { 
    scope: ['user:email'],
    session: true
  })(req, res, next);
});

app.get('/auth/github/callback', (req, res, next) => {
  console.log('Callback de GitHub recibido');
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
    
    console.log('Generando JWT para usuario:', req.user.id, req.user.username);
    
    // Guardar usuario en nuestro store
    connectedUsers.set(req.user.id, req.user);
    
    // Crear JWT con información completa
    const token = jwt.sign(
      { 
        id: req.user.id, 
        username: req.user.username,
        displayName: req.user.displayName
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    console.log('JWT generado exitosamente para usuario:', req.user.username);
    res.redirect(`/?token=${token}`);
  } catch (error) {
    console.error('Error en /auth/github/callback:', error);
    res.redirect('/?error=jwt_generation_failed');
  }
});

// Ruta de logout - solo afecta al usuario actual
app.get('/logout', (req, res) => {
  const userId = req.user?.id;
  console.log('Cerrando sesión para usuario:', userId);
  
  req.logout((err) => {
    if (err) {
      console.error('Error al cerrar sesión:', err);
      return res.redirect('/?error=logout_failed');
    }
    
    // Remover usuario del store si existe
    if (userId) {
      connectedUsers.delete(userId);
    }
    
    // Solo destruir la sesión actual, no todas las sesiones
    req.session.destroy((err) => {
      if (err) {
        console.error('Error al destruir sesión:', err);
      }
      res.clearCookie('connect.sid');
      res.redirect('/');
    });
  });
});

// Ruta protegida
app.get('/api/profile', authenticateJWT, (req, res) => {
  console.log('Accediendo a perfil para usuario:', req.user.id);
  res.json({ 
    id: req.user.id, 
    username: req.user.username || `user_${req.user.id}`,
    displayName: req.user.displayName
  });
});

// Socket.io para reacciones en tiempo real
const emojiCounts = { '😊': 0, '👍': 0, '❤️': 0 };
const userSockets = new Map(); // Mapear usuarios a sus sockets

io.on('connection', (socket) => {
  console.log('Nuevo cliente conectado:', socket.id);
  
  // Enviar contadores actuales al nuevo cliente
  socket.emit('emoji:updated', emojiCounts);
  
  // Manejar autenticación del socket (opcional)
  socket.on('authenticate', (token) => {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      socket.userId = decoded.id;
      socket.username = decoded.username;
      userSockets.set(decoded.id, socket.id);
      console.log(`Socket ${socket.id} autenticado para usuario: ${decoded.username}`);
    } catch (error) {
      console.error('Error autenticando socket:', error);
      socket.emit('auth_error', 'Token inválido');
    }
  });

  socket.on('emoji:react', (emoji) => {
    if (emojiCounts[emoji] !== undefined) {
      emojiCounts[emoji]++;
      console.log(`Reacción ${emoji} de socket ${socket.id} (usuario: ${socket.username || 'anónimo'})`);
      console.log('Contadores actualizados:', emojiCounts);
      
      // Emitir a todos los clientes conectados
      io.emit('emoji:updated', emojiCounts);
    }
  });

  socket.on('disconnect', () => {
    console.log(`Cliente desconectado: ${socket.id} (usuario: ${socket.username || 'anónimo'})`);
    
    // Remover del mapa si estaba autenticado
    if (socket.userId) {
      userSockets.delete(socket.userId);
    }
  });
});

// Ruta raíz
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Ruta para ver usuarios conectados (debug)
app.get('/api/debug/users', (req, res) => {
  const users = Array.from(connectedUsers.values()).map(user => ({
    id: user.id,
    username: user.username
  }));
  res.json({ 
    connectedUsers: users.length,
    users: users,
    emojiCounts: emojiCounts
  });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log('Múltiples usuarios pueden conectarse simultáneamente');
});
