require("dotenv").config();
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());
app.get("/", (req, res) => {
    res.send("Authentication Server is Running Successfully!");
});
// Temporary users storage (No Database)
const users = [];

const JWT_SECRET = process.env.JWT_SECRET;

// --------------------------------
// 1. REGISTER API
// --------------------------------

app.post("/register", async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        // Check fields
        if (!name || !email || !password) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }

        // Check existing user
        const existingUser = users.find(
            user => user.email === email
        );

        if (existingUser) {
            return res.status(409).json({
                message: "User already exists"
            });
        }
        const allowedRoles = ["admin", "teacher", "student"];

        if (!allowedRoles.includes(role)) {
            return res.status(400).json({
                message: "Invalid role"
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const newUser = {
            id: users.length + 1,
            name,
            email,
            password: hashedPassword,
            role
        };

        users.push(newUser);

        res.status(201).json({
            message: "Registration successful",
            user: {
                id: newUser.id,
                name: newUser.name,
                email: newUser.email,
                role: newUser.role
            }
        });

    } catch (error) {
        res.status(500).json({
            message: "Server error"
        });
    }
});
app.get("/users", (req, res) => {

    res.json({
        message: "All users",
        users: users.map(user => ({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        }))
    });

});
app.get("/users/:id", (req, res) => {

    const id = Number(req.params.id);

    const user = users.find(user => user.id === id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    });

});
// --------------------------------
// 2. LOGIN API
// --------------------------------

app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find user
        const user = users.find(
            user => user.email === email
        );

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // Compare password
        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // Generate JWT
        const token = jwt.sign(
            { id: user.id,
              role: user.role
             },
            JWT_SECRET,
            { expiresIn: "1d" }
        );

        res.json({
            message: "Login successful",
            token
        });

    } catch (error) {
        res.status(500).json({
            message: "Server error"
        });
    }
});

// --------------------------------
// 3. AUTHENTICATION MIDDLEWARE
// --------------------------------

const authenticate = (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Token required"
            });
        }

        const token = authHeader.split(" ")[1];

        const decoded = jwt.verify(token, JWT_SECRET);

        req.user = decoded;

        next();

    } catch (error) {
        res.status(401).json({
            message: "Invalid or expired token"
        });
    }
};

// --------------------------------
// 4. PROTECTED PROFILE API
// --------------------------------

app.get("/profile", authenticate, (req, res) => {

    const user = users.find(
        user => user.id === req.user.id
    );

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    res.json({
        message: "Welcome to your profile",
        user: {
            id: user.id,
            name: user.name,
            email: user.email
        }
    });
});
app.get("/users", (req, res) => {

    res.json({
        message: "All users",
        users: users.map(user => ({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        }))
    });

});
app.get("/users/:id", (req, res) => {

    const id = Number(req.params.id);

    const user = users.find(user => user.id === id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
    });

});
app.patch("/users/:id", (req, res) => {

    const id = Number(req.params.id);

    const user = users.find(user => user.id === id);

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    const { name, email, role } = req.body;

    if (name !== undefined) user.name = name;
    if (email !== undefined) user.email = email;
    if (role !== undefined) {
        if (!["admin", "teacher", "student"].includes(role)) {
            return res.status(400).json({
                message: "Invalid role"
            });
        }
        user.role = role;
    }

    res.json({
        message: "User updated successfully",
        user: {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role
        }
    });

});
app.delete("/users/:id", (req, res) => {

    const id = Number(req.params.id);

    const userIndex = users.findIndex(
        user => user.id === id
    );

    if (userIndex === -1) {
        return res.status(404).json({
            message: "User not found"
        });
    }

    users.splice(userIndex, 1);

    res.json({
        message: "User deleted successfully"
    });

});

// --------------------------------
// 5. START SERVER
// --------------------------------

const PORT = 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
