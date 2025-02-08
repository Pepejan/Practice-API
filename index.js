const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const app = express();

// Конфігурація
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(helmet());
app.use(cors());
app.use(compression());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 хвилин
    max: 100 // максимум 100 запитів від одного IP
});
app.use(limiter);

// База даних (для прикладу використовуємо масиви)
let users = [];
let students = [];
let nextUserId = 1;
let nextStudentId = 1;

// Middleware для логування
const logRequest = (req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
};
app.use(logRequest);

// Middleware для перевірки токена
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Необхідна авторизація' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Недійсний токен' });
        }
        req.user = user;
        next();
    });
};

// Middleware для перевірки ролі
const authorize = (roles = []) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Недостатньо прав' });
        }
        next();
    };
};

// Валідація даних користувача
const validateUser = (req, res, next) => {
    const { username, password } = req.body;

    if (!username || username.length < 3) {
        return res.status(400).json({ error: 'Ім\'я користувача повинно містити мінімум 3 символи' });
    }

    if (!password || password.length < 6) {
        return res.status(400).json({ error: 'Пароль повинен містити мінімум 6 символів' });
    }

    next();
};

// Публічні ендпоінти
app.post('/api/auth/register', validateUser, async (req, res) => {
    try {
        const { username, password } = req.body;

        // Перевірка на унікальність username
        if (users.find(u => u.username === username)) {
            return res.status(400).json({ error: 'Користувач з таким іменем вже існує' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = {
            id: nextUserId++,
            username,
            password: hashedPassword,
            role: 'User',
            createdAt: new Date(),
            updatedAt: new Date()
        };

        users.push(newUser);

        const { password: _, ...userWithoutPassword } = newUser;
        res.status(201).json(userWithoutPassword);
    } catch (error) {
        res.status(500).json({ error: 'Помилка при створенні користувача' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = users.find(u => u.username === username);

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Невірні облікові дані' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Помилка при вході в систему' });
    }
});

// Захищені ендпоінти для адміністраторів
app.get('/api/users', authenticateToken, authorize(['Admin']), (req, res) => {
    const usersWithoutPasswords = users.map(({ password, ...user }) => user);
    res.json(usersWithoutPasswords);
});

app.get('/api/users/:id', authenticateToken, authorize(['Admin']), (req, res) => {
    const user = users.find(u => u.id === parseInt(req.params.id));
    if (!user) {
        return res.status(404).json({ error: 'Користувача не знайдено' });
    }
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});

// Ендпоінти для роботи зі студентами
app.get('/api/students', authenticateToken, authorize(['Admin', 'User']), (req, res) => {
    res.json(students);
});

app.post('/api/students', authenticateToken, authorize(['Admin']), (req, res) => {
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Ім\'я є обов\'язковим' });
    }

    const newStudent = {
        id: nextStudentId++,
        name,
        createdAt: new Date(),
        updatedAt: new Date()
    };

    students.push(newStudent);
    res.status(201).json(newStudent);
});

app.patch('/api/students/:id', authenticateToken, authorize(['Admin']), (req, res) => {
    const { name } = req.body;
    const student = students.find(s => s.id === parseInt(req.params.id));

    if (!student) {
        return res.status(404).json({ error: 'Студента не знайдено' });
    }

    if (!name) {
        return res.status(400).json({ error: 'Ім\'я є обов\'язковим' });
    }

    student.name = name;
    student.updatedAt = new Date();

    res.json(student);
});

app.delete('/api/students/:id', authenticateToken, authorize(['Admin']), (req, res) => {
    const index = students.findIndex(s => s.id === parseInt(req.params.id));

    if (index === -1) {
        return res.status(404).json({ error: 'Студента не знайдено' });
    }

    const deletedStudent = students.splice(index, 1)[0];
    res.json(deletedStudent);
});

// Зміна пароля для користувача
app.post('/api/users/change-password', authenticateToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const user = users.find(u => u.id === req.user.userId);

        if (!user || !(await bcrypt.compare(currentPassword, user.password))) {
            return res.status(401).json({ error: 'Невірний поточний пароль' });
        }

        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Новий пароль повинен містити мінімум 6 символів' });
        }

        user.password = await bcrypt.hash(newPassword, 10);
        user.updatedAt = new Date();

        res.json({ message: 'Пароль успішно змінено' });
    } catch (error) {
        res.status(500).json({ error: 'Помилка при зміні пароля' });
    }
});

// Створення початкових користувачів
const createInitialUsers = async () => {
    if (users.length === 0) {
        const adminPassword = await bcrypt.hash('admin123', 10);
        const userPassword = await bcrypt.hash('user123', 10);

        users.push({
            id: nextUserId++,
            username: 'admin',
            password: adminPassword,
            role: 'Admin',
            createdAt: new Date(),
            updatedAt: new Date()
        });

        users.push({
            id: nextUserId++,
            username: 'user',
            password: userPassword,
            role: 'User',
            createdAt: new Date(),
            updatedAt: new Date()
        });

        console.log('Початкові користувачі створені');
    }
};

// Запуск сервера
app.listen(PORT, async () => {
    await createInitialUsers();
    console.log(`Сервер запущено на порту ${PORT}`);
});