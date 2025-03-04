const express = require('express');
const app = express();
app.use(express.json());

let todos = [];
app.get('/todos', (req, res) => res.json(todos));
app.post('/todos', (req, res) => {
  todos.push(req.body.todo);
  res.json({ message: 'Todo added', todos });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));