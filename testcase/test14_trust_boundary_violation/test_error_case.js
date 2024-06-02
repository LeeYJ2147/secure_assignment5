const userInput = req.headers['x-user-input'];
executeQuery(`SELECT * FROM users WHERE name = '${userInput}'`);