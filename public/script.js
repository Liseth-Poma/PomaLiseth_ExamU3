const socket = io();
let token = null;

// Obtener token de la URL
const urlParams = new URLSearchParams(window.location.search);
token = urlParams.get('token');
const error = urlParams.get('error');

if (error) {
  console.error('Error en autenticación:', error);
  alert('Error al iniciar sesión: ' + error);
}

if (token) {
  // Limpiar URL sin recargar la página
  window.history.replaceState({}, document.title, window.location.pathname);
  
  showContent();
  fetchProfile();
  
  // Autenticar el socket con el token
  socket.emit('authenticate', token);
}

// Función para iniciar sesión
function login() {
  console.log('Iniciando sesión con GitHub');
  token = null;
  
  // Abrir GitHub OAuth en la misma ventana
  window.location.href = '/auth/github';
}

// Función para cerrar sesión
function logout() {
  console.log('Cerrando sesión');
  token = null;
  document.getElementById('username').textContent = '';
  document.getElementById('content').style.display = 'none';
  document.getElementById('auth').style.display = 'block';
  
  // Desconectar socket
  socket.disconnect();
  
  // Hacer logout en el servidor
  window.location.href = '/logout';
}

// Mostrar contenido después de autenticación
function showContent() {
  document.getElementById('auth').style.display = 'none';
  document.getElementById('content').style.display = 'block';
}

// Obtener perfil del usuario
async function fetchProfile() {
  try {
    console.log('Obteniendo perfil del usuario');
    const response = await fetch('/api/profile', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    console.log('Datos del perfil recibidos:', data);
    
    if (data.username) {
      document.getElementById('username').textContent = data.displayName || data.username;
    } else {
      console.error('No se recibió username:', data);
      alert('Error al cargar el perfil');
    }
  } catch (error) {
    console.error('Error fetching profile:', error);
    alert('Error al cargar el perfil: ' + error.message);
    // Redirigir al login si hay error de token
    if (error.message.includes('401') || error.message.includes('403')) {
      token = null;
      document.getElementById('content').style.display = 'none';
      document.getElementById('auth').style.display = 'block';
    }
  }
}

// Enviar reacción
function react(emoji) {
  if (!token) {
    alert('Debes iniciar sesión para reaccionar');
    return;
  }
  
  console.log('Enviando reacción:', emoji);
  socket.emit('emoji:react', emoji);
}

// Actualizar contadores de emojis
socket.on('emoji:updated', (counts) => {
  console.log('Contadores actualizados:', counts);
  Object.keys(counts).forEach(emoji => {
    const countElement = document.getElementById(`count-${emoji}`);
    if (countElement) {
      countElement.textContent = counts[emoji];
    }
  });
});

// Manejar errores de autenticación del socket
socket.on('auth_error', (message) => {
  console.error('Error de autenticación del socket:', message);
  alert('Error de autenticación: ' + message);
});

// Manejar desconexión
socket.on('disconnect', () => {
  console.log('Desconectado del servidor');
});

// Manejar reconexión
socket.on('connect', () => {
  console.log('Conectado al servidor');
  if (token) {
    socket.emit('authenticate', token);
  }
});

// Agregar botón de logout al HTML
document.addEventListener('DOMContentLoaded', () => {
  const contentDiv = document.getElementById('content');
  if (contentDiv) {
    const logoutButton = document.createElement('button');
    logoutButton.textContent = 'Cerrar Sesión';
    logoutButton.onclick = logout;
    logoutButton.style.marginTop = '20px';
    logoutButton.style.backgroundColor = '#e74c3c';
    contentDiv.appendChild(logoutButton);
  }
});
