{const userInput = "John'; DROP TABLE Users; --";
const query = "SELECT * FROM users WHERE name = '" + userInput + "'";
executeQuery(query);}