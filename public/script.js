const socket = io(); // Cambia a 'https://<tu-sitio-railway>.up.railway.app' en producción
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
  showContent();
  fetchProfile();
}

// Función para iniciar sesión
function login() {
  console.log('Iniciando sesión con GitHub');
  token = null;
  localStorage.removeItem('token');
  sessionStorage.clear(); // Limpiar sessionStorage
  window.location.href = '/auth/github';
}

// Función para cerrar sesión
function logout() {
  console.log('Cerrando sesión');
  token = null;
  localStorage.removeItem('token');
  sessionStorage.clear();
  document.getElementById('username').textContent = '';
  document.getElementById('content').style.display = 'none';
  document.getElementById('auth').style.display = 'block';
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
    console.log('Obteniendo perfil con token:', token);
    const response = await fetch('/api/profile', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    const data = await response.json();
    if (data.username) {
      document.getElementById('username').textContent = data.username;
    } else {
      console.error('No se recibió username:', data);
      alert('Error al cargar el perfil');
    }
  } catch (error) {
    console.error('Error fetching profile:', error);
    alert('Error al cargar el perfil: ' + error.message);
  }
}

// Enviar reacción
function react(emoji) {
  console.log('Enviando reacción:', emoji);
  socket.emit('emoji:react', emoji);
}

// Actualizar contadores de emojis
socket.on('emoji:updated', (counts) => {
  console.log('Contadores actualizados:', counts);
  Object.keys(counts).forEach(emoji => {
    document.getElementById(`count-${emoji}`).textContent = counts[emoji];
  });
});