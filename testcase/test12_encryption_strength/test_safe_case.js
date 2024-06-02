const crypto = require('crypto');
const hash = crypto.createHash('sha256').update('password123').digest('hex');
console.log(hash);