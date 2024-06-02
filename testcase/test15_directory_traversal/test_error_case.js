{const fs = require('fs');
const userInput = "../etc/passwd";
fs.readFile(userInput, 'utf8', (err, data) => {
    if (err) {
        console.error(err);
        return;
    }
    console.log(data);
});}