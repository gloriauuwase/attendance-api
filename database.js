import mysql from 'mysql2';
import dotenv from 'dotenv';

dotenv.config();

// const pool = mysql
//   .createPool({
//     host: 'localhost',
//     database: 'attendance',
//     user: 'root',
//     password: '',
//   })
//   .promise();

const pool = mysql
  .createPool({
    host: process.env.HOST,
    database: process.env.DB,
    user: process.env.USER,
    password: process.env.PASSWORD,
  })
  .promise();

// GET ALL FROM TABLE

// Get all users
export async function getUsers() {
  const [results] = await pool.query('SELECT * FROM users');
  return results;
}

// Get all Students
export async function getStudents() {
  const [results] = await pool.query('SELECT * FROM students');
  return results;
}

// Get all Modules
export async function getModules() {
  const [results] = await pool.query('SELECT * FROM modules');
  return results;
}

// Get all Lectures
export async function getLectures() {
  const [results] = await pool.query('SELECT * FROM lecture');
  return results;
}

const allUsers = await getUsers();
const allStudents = await getStudents();
const allModules = await getModules();
const allLectures = await getLectures();

// -----------------------------------------------------------------------------

// GET SINGLE RECORD

// Get single user
export async function getUser(id) {
  const [results] = await pool.query(
    `
  SELECT *
  FROM users
  WHERE id= ?
  `,
    [id]
  );
  return results;
}

// Get single student
export async function getStudent(id) {
  const [result] = await pool.query(
    `
  SELECT *
  FROM students
  WHERE id= ?
  `,
    [id]
  );
  return result;
}

// Get single module
export async function getModule(id) {
  const [result] = await pool.query(
    `
  SELECT *
  FROM modules
  WHERE id= ?
  `,
    [id]
  );
  return result;
}

// Get single lecture
export async function getLecture(id) {
  const [result] = await pool.query(
    `
  SELECT *
  FROM lecture
  WHERE id= ?
  `,
    [id]
  );
  return result;
}

const User = await getUser(1);
const Student = await getStudent(1);
const Module = await getModule(1);
const Lecture = await getLecture(3);

// ------------------------------------------------------------------------

// POST DATA INTO DB TABLES

// Post user
export async function addUser(fname, lname, email, phone, user, pass) {
  const [result] = await pool.query(
    `
      INSERT INTO users (role_id, firstname, lastname, email, phone, username, password)
      VALUES
      (?, ?, ?, ?, ?, ?, ?)
    `,
    [2, fname, lname, email, phone, user, pass]
  );
  return result;
}

const user = {
  fname: 'mwiza',
  lname: 'jane',
  email: 'jane@gmail.com',
  phone: '0789090877',
  user: 'user',
  pass: 'user',
};

// const addedUser = await addUser(
//   user.fname,
//   user.lname,
//   user.email,
//   user.phone,
//   user.user,
//   user.pass
// );

// ---------------------------------------------------------------------

// DELETE DB TABLED ATA

// Delete single user
export async function deleteUser(id) {
  const result = await pool.query(
    `
    DELETE
    FROM users
    WHERE id= ?
    `,
    [id]
  );
  return result;
}

// Delete single student
export async function deleteStudent(id) {
  const [result] = await pool.query(
    `
    DELETE 
    FROM students
    WHERE id= ?
    `,
    [id]
  );
  return result;
}

// const deletedUser = deleteUser(11);
// const deletedStudent = deleteStudent(5);

// ----------------------------------------------------------------------

// UPDATE DB TABLE DATA

//Update single user

export async function updateStudent(fname, lname, id) {
  const [result] = await pool.query(
    `
      UPDATE students 
      SET firstname = ?, lastname = ?
      WHERE id= ?
      `,
    [fname, lname, id]
  );
  return result;
}

const updatedStudent = updateStudent('manzi', 'kyle', 1);

console.log(updatedStudent);
