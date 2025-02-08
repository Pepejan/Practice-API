const express = require("express");
const app = express();

app.use(express.json());

const port = 3000;

let students = [];
let nextId = 1; // Ідентифікатор студентів

// Отримати список студентів
app.get("/students", (req,
                      res) => {
    res.status(200).json({ students });
});

// Додати нового студента
app.post("/students", (req, res) => {
    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: "Ім'я є обов'язковим" });
    }

    const newStudent = { id: nextId++, name };
    students.push(newStudent);

    res.status(201).json({ message: "Студента додано", student: newStudent });
});

// Оновити ім’я студента
app.patch("/students/:id", (req, res) => {
    const { id } = req.params;
    const { newName } = req.body;
    const student = students.find((s) => s.id === parseInt(id));

    if (!student) {
        return res.status(404).json({ error: "Студент не знайдений" });
    }
    if (!newName) {
        return res.status(400).json({ error: "Нове ім'я є обов'язковим" });
    }

    student.name = newName;
    res.status(200).json({ message: "Ім'я змінено", student });
});

// Видалити студента
app.delete("/students/:id", (req, res) => {
    const { id } = req.params;
    const index = students.findIndex((s) => s.id === parseInt(id));

    if (index === -1) {
        return res.status(404).json({ error: "Студент не знайдений" });
    }

    const deletedStudent = students.splice(index, 1);
    res.status(200).json({ message: "Студента видалено", student: deletedStudent });
});

app.listen(port, () => {
    console.log(`Порт: ${port}!`);
});
