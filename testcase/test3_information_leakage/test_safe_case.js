const userPassword = "password123";
const sanitizedPassword = userPassword.replace(/./g, '*');
console.log("User password is: " + sanitizedPassword);