## https://documenter.getpostman.com/view/41951197/2sAYX9keu3
# API Управління Студентами 

Простий REST API сервер для управління списком студентів, створений з використанням Express.js. API дозволяє додавати, видаляти, оновлювати та переглядати інформацію про студентів.

## Вимоги

- Node.js (версія 12 або вище)
- npm (Node Package Manager)

## Встановлення

1. Клонуйте репозиторій:
```bash
git clone [https://github.com/BondarchukOlexander23-2/Practice-API]
```
2. Перейдіть у директорію проекту:
```bash
cd [practice]
```
3. Встановіть залежності:
```bash
npm install
```
## Запуск
Для запуску сервера виконайте:
```bash
npm start
```
Сервер запуститься на порту 3000: http://localhost:3000

## API Endpoints
### GET /students
- отримати список всіх студентів
- Відповідь: Масив студентів

### POST/students
- Додати нового студента
- Body: {"name": "Ім'я студента"}
- Відповідь: Оновлений студент

### DELETE /students/:id
- Видалити студента
- Відповідь: Видалений студент
### Приклад використання
```bash
# Додати нового студента
curl -X POST http://localhost:3000/students \
  -H "Content-Type: application/json" \
  -d '{"name": "Іван Петренко"}'

# Отримати список студентів
curl http://localhost:3000/students
```