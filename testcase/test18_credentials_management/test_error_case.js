{const userPassword = "password123";
const encodedPassword = Buffer.from(userPassword).toString('base64'); // base64 인코딩 사용
console.log(encodedPassword);}