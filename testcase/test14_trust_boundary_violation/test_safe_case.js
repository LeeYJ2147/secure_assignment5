const userInput = req.headers['x-user-input'];
if (validateInput(userInput)) {
    executeQuery(`SELECT * FROM users WHERE name = ?`, [userInput]);
} else {
    console.log("Invalid input detected");
}