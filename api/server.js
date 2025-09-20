// VERSIÓN COMPLETA Y CORREGIDA DE api/server.js

// --- 1. Imports ---
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); 

// --- 2. Creación de la App ---
const app = express();

// --- 3. Middlewares ---
app.use(cors({
  origin: 'https://ulisesxxxi31.github.io'
}));
app.use(express.json());

// --- 4. Conexión a la Base de Datos ---
const uri = process.env.MONGODB_URI;
mongoose.connect(uri)
  .then(() => console.log('Conexión exitosa a MongoDB Atlas'))
  .catch(err => {
    console.error('Error de conexión a MongoDB Atlas:', err);
    process.exit(1); // Sale de la aplicación si la conexión falla
  });

// --- 5. Importación de Modelos ---
const User = require('../models/users');
const Progress = require('../models/progress');

// --- 6. Rutas de la API (Públicas) ---
app.get('/', (req, res) => {
  res.send('¡Hola, mundo desde el servidor!');
});

app.post('/api/users/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    const newUser = new User({ name, email, password: hashedPassword, role });
    await newUser.save();
    res.status(201).json({ message: 'Usuario registrado con éxito' });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(400).json({ message: 'El correo electrónico ya está registrado.' });
    }
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Credenciales inválidas' });
    }
    if (user.role !== 'profesor' && user.role !== 'alumno') {
      return res.status(403).json({ message: 'Acceso denegado. Rol no permitido.' });
    }
    
    // Generar y enviar el token
    const payload = { userId: user._id, role: user.role };
    const token = jwt.sign(payload, process.env.JWT_SECRET || 'your-secret-key', { expiresIn: '1h' });
    res.status(200).json({ 
      message: 'Inicio de sesión exitoso',
      user: { id: user._id, name: user.name, email: user.email, role: user.role },
      token: token
    });
  } catch (error) {
    res.status(500).json({ error: 'Error del servidor. Inténtalo de nuevo.' });
  }
});

// --- 7. Middleware de Autenticación ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- 8. Rutas de la API (Protegidas) ---
app.get('/api/users', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'profesor') {
      return res.status(403).json({ message: 'Acceso denegado. Solo profesores pueden ver esta lista.' });
    }
    
    const users = await User.find({ role: 'alumno' }).select('-password');
    if (!users) {
      return res.status(404).json({ message: 'No hay usuarios registrados.' });
    }
    res.status(200).json({ users: users });
  } catch (error) {
    console.error('Error al obtener los usuarios:', error);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

app.get('/api/progress/students', verifyToken, async (req, res) => {
  try {
    if (req.user.role !== 'profesor') {
      return res.status(403).json({ message: 'Acceso denegado. Solo profesores pueden ver el progreso.' });
    }
    
    const studentProgress = await Progress.find().populate('user', 'name email');
    const groupedProgress = studentProgress.reduce((acc, progress) => {
      const { user, ...rest } = progress._doc;
      if (!acc[user.name]) {
        acc[user.name] = {
          name: user.name,
          email: user.email,
          tasks: []
        };
      }
      acc[user.name].tasks.push(rest);
      return acc;
    }, {});
    res.status(200).json(Object.values(groupedProgress));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/progress/:userId', verifyToken, async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (req.user.role !== 'profesor' && req.user.userId !== userId) {
      return res.status(403).json({ message: 'Acceso denegado. No tienes permisos para ver este progreso.' });
    }

    const progressHistory = await Progress.find({ user: userId }).sort({ completedAt: 1 });
    if (!progressHistory || progressHistory.length === 0) {
      return res.status(404).json({ message: 'No se encontró historial de progreso para este usuario.' });
    }
    res.status(200).json({ progress: progressHistory });
  } catch (error) {
    console.error('Error al obtener el progreso del usuario:', error);
    res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// --- 9. Export de la App ---
module.exports = app;


