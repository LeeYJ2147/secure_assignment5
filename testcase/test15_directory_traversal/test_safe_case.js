{const fs = require('fs');
const path = require('path');
const userInput = "userInput.txt";
const safePath = path.resolve(__dirname, userInput);
fs.readFile(safePath, 'utf8', (err, data) => {
    if (err) {
        console.error(err);
        return;
    }
    console.log(data);
});}