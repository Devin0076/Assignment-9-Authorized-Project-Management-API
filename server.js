require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { db, User, Project, Task } = require('./database/setup');




const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());



function requireAuth(req, res, next) {
    try {
        // Look for token in Authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Missing or invalid Authorization header' });
        }

        // Extract the token
        const token = authHeader.split(' ')[1];

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Attach decoded user info to req
        req.user = decoded;

        next();

    } catch (error) {
        console.error('JWT auth error:', error);

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired. Please log in again.' });
        }

        return res.status(401).json({ error: 'Invalid or missing token' });
    }
}


function requireManager(req, res, next) {
    // Must be authenticated first
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required. Please log in.' });
    }

    // Allow managers and admins
    if (req.user.role === 'manager' || req.user.role === 'admin') {
        return next();
    }

    return res.status(403).json({ error: 'Access denied. Manager or admin role required.' });
}

function requireAdmin(req, res, next) {
    // Must be authenticated first
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required. Please log in.' });
    }

    // Allow only admins
    if (req.user.role === 'admin') {
        return next();
    }

    return res.status(403).json({ error: 'Access denied. Admin role required.' });
}



// Test database connection
async function testConnection() {
    try {
        await db.authenticate();
        console.log('Connection to database established successfully.');
    } catch (error) {
        console.error('Unable to connect to the database:', error);
    }
}

testConnection();

// AUTHENTICATION ROUTES

// POST /api/register - Register new user
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        
        // Check if user exists
        const existingUser = await User.findOne({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: 'User with this email already exists' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const newUser = await User.create({
            name,
            email,
            password: hashedPassword
            // TODO: Add role field
        });
        
        res.status(201).json({
            message: 'User registered successfully',
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email
            }
        });
        
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// POST /api/login - User login (JWT version)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = await User.findOne({ where: { email } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Validate password
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Create JWT payload
        const payload = {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        };

        // Generate token
        const token = jwt.sign(payload, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN
        });

        // Respond with token + user data
        res.json({
            message: 'Login successful',
            token,
            user: payload
        });

    } catch (error) {
        console.error('Error logging in user:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});


// POST /api/logout - JWT version (stateless)
app.post('/api/logout', (req, res) => {
    // Nothing to destroy — JWTs are stateless
    res.json({ message: 'Logout successful' });
});


// USER ROUTES

// GET /api/users/profile - Get current user profile
app.get('/api/users/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findByPk(req.user.id, {
            attributes: ['id', 'name', 'email'] // Don't return password
        });
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json(user);
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Failed to fetch user profile' });
    }
});

// GET /api/users - Get all users (TODO: Admin only)
app.get('/api/users', requireAuth, async (req, res) => {
    try {
        const users = await User.findAll({
            attributes: ['id', 'name', 'email'] // Don't return passwords
        });
        
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// PROJECT ROUTES

// GET /api/projects - Get projects
app.get('/api/projects', requireAuth, async (req, res) => {
    try {
        const projects = await Project.findAll({
            include: [
                {
                    model: User,
                    as: 'manager',
                    attributes: ['id', 'name', 'email']
                }
            ]
        });
        
        res.json(projects);
    } catch (error) {
        console.error('Error fetching projects:', error);
        res.status(500).json({ error: 'Failed to fetch projects' });
    }
});

// GET /api/projects/:id - Get single project
app.get('/api/projects/:id', requireAuth, async (req, res) => {
    try {
        const project = await Project.findByPk(req.params.id, {
            include: [
                {
                    model: User,
                    as: 'manager',
                    attributes: ['id', 'name', 'email']
                },
                {
                    model: Task,
                    include: [
                        {
                            model: User,
                            as: 'assignedUser',
                            attributes: ['id', 'name', 'email']
                        }
                    ]
                }
            ]
        });
        
        if (!project) {
            return res.status(404).json({ error: 'Project not found' });
        }
        
        res.json(project);
    } catch (error) {
        console.error('Error fetching project:', error);
        res.status(500).json({ error: 'Failed to fetch project' });
    }
});

// POST /api/projects - Create new project (TODO: Manager+ only)
app.post('/api/projects', requireAuth, async (req, res) => {
    try {
        const { name, description, status = 'active' } = req.body;
        
        const newProject = await Project.create({
            name,
            description,
            status,
            managerId: req.user.id
        });
        
        res.status(201).json(newProject);
    } catch (error) {
        console.error('Error creating project:', error);
        res.status(500).json({ error: 'Failed to create project' });
    }
});

// PUT /api/projects/:id - Update project (TODO: Manager+ only)
app.put('/api/projects/:id', requireAuth, async (req, res) => {
    try {
        const { name, description, status } = req.body;
        
        const [updatedRowsCount] = await Project.update(
            { name, description, status },
            { where: { id: req.params.id } }
        );
        
        if (updatedRowsCount === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }
        
        const updatedProject = await Project.findByPk(req.params.id);
        res.json(updatedProject);
    } catch (error) {
        console.error('Error updating project:', error);
        res.status(500).json({ error: 'Failed to update project' });
    }
});

// DELETE /api/projects/:id - Delete project (TODO: Admin only)
app.delete('/api/projects/:id', requireAuth, async (req, res) => {
    try {
        const deletedRowsCount = await Project.destroy({
            where: { id: req.params.id }
        });
        
        if (deletedRowsCount === 0) {
            return res.status(404).json({ error: 'Project not found' });
        }
        
        res.json({ message: 'Project deleted successfully' });
    } catch (error) {
        console.error('Error deleting project:', error);
        res.status(500).json({ error: 'Failed to delete project' });
    }
});

// TASK ROUTES

// GET /api/projects/:id/tasks - Get tasks for a project
app.get('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    try {
        const tasks = await Task.findAll({
            where: { projectId: req.params.id },
            include: [
                {
                    model: User,
                    as: 'assignedUser',
                    attributes: ['id', 'name', 'email']
                }
            ]
        });
        
        res.json(tasks);
    } catch (error) {
        console.error('Error fetching tasks:', error);
        res.status(500).json({ error: 'Failed to fetch tasks' });
    }
});

// POST /api/projects/:id/tasks - Create task (TODO: Manager+ only)
app.post('/api/projects/:id/tasks', requireAuth, async (req, res) => {
    try {
        const { title, description, assignedUserId, priority = 'medium' } = req.body;
        
        const newTask = await Task.create({
            title,
            description,
            projectId: req.params.id,
            assignedUserId,
            priority,
            status: 'pending'
        });
        
        res.status(201).json(newTask);
    } catch (error) {
        console.error('Error creating task:', error);
        res.status(500).json({ error: 'Failed to create task' });
    }
});

// PUT /api/tasks/:id - Update task
app.put('/api/tasks/:id', requireAuth, async (req, res) => {
    try {
        const { title, description, status, priority } = req.body;
        
        const [updatedRowsCount] = await Task.update(
            { title, description, status, priority },
            { where: { id: req.params.id } }
        );
        
        if (updatedRowsCount === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        const updatedTask = await Task.findByPk(req.params.id);
        res.json(updatedTask);
    } catch (error) {
        console.error('Error updating task:', error);
        res.status(500).json({ error: 'Failed to update task' });
    }
});

// DELETE /api/tasks/:id - Delete task (TODO: Manager+ only)
app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
    try {
        const deletedRowsCount = await Task.destroy({
            where: { id: req.params.id }
        });
        
        if (deletedRowsCount === 0) {
            return res.status(404).json({ error: 'Task not found' });
        }
        
        res.json({ message: 'Task deleted successfully' });
    } catch (error) {
        console.error('Error deleting task:', error);
        res.status(500).json({ error: 'Failed to delete task' });
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port http://localhost:${PORT}`);
});
