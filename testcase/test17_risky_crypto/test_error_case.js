const crypto = require('crypto');
const hash = crypto.createHash('md5').update('password123').digest('hex');
console.log(hash);