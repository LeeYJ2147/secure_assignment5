const bcrypt = require('bcrypt');
const userPassword = "password123";
bcrypt.hash(userPassword, 10, (err, hash) => {
    if (err) {
        console.error(err);
        return;
    }
    console.log(hash);
});