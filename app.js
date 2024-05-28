import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

console.log(process.env.SERVER_PORT);

import {
  getUsers,
  getStudents,
  getModules,
  getLectures,
  getUser,
  getStudent,
  getModule,
  getLecture,
  addUser,
  deleteUser,
  deleteStudent,
  updateStudent,
} from './database.js';

const app = express();

app.use(express.json());

// AUTHENTICATION

app.post('/users/login', async (req, res) => {
  // users
  const users = await getUsers();
  const user = users.find((user) => user.username === req.body.user);
  if (user == null) {
    res.status(400).send("can't find user");
  }
  try {
    if (await bcrypt.compare(req.body.pass, user.password)) {
      // res.send('Login success');

      // Generate JWT for user

      const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
      res.json({ accessToken: accessToken });
    } else {
      res.send('Invalid credentials');
    }
  } catch {
    res.status(500).send();
  }
});

// AUTHENTICATE MIDLEWARE
function authToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (token === null) return res.sendStatus(403);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403).send('unauthorized');
    // req.user = user;
    next();
  });
  return;
}

// GET REQUESTS

// Get students
app.get('/students', authToken, async (req, res) => {
  const allStudents = await getStudents();
  res.send(allStudents);
});

// Get user
app.get('/users/:id', authToken, async (req, res) => {
  const id = req.params.id;
  const user = await getUser(id);
  res.send(user);
});

// Get student
app.get('/students/:id', authToken, async (req, res) => {
  const id = req.params.id;
  const student = await getStudent(id);
  res.send(student);
});
// ----------------------------------------------------------------------------

// POST REQUEST

// Add user
app.post('/users', async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.pass, 10);
  const { fname, lname, email, phone, user } = req.body;

  const addedUser = await addUser(
    fname,
    lname,
    email,
    phone,
    user,
    hashedPassword
  );
  res.status(200);
  res.send('User created');
});
// -----------------------------------------------------------------------------------

// DELETE REQUEST

// Delete user
app.delete('/users/:id', async (req, res) => {
  const id = req.params.id;
  const deletedUser = await deleteUser(id);
  res.send('User deleted');
});

// Delete student
app.delete('/students/:id', authToken, async (req, res) => {
  const id = req.params.id;
  const deletedStudent = await deleteStudent(id);
  res.send('Student deleted');
});
// ------------------------------------------------------------------------------------
// PUT REQUEST
// Update student
app.put('/students/:id', authToken, async (req, res) => {
  const id = req.params.id;
  const { fname, lname } = req.body;
  const updatedStudent = updateStudent(fname, lname, id);
  res.send('Student updated');
});

app.listen(process.env.SERVER_PORT, function () {
  console.log(`App listening on port ${process.env.SERVER_PORT}`);
});
