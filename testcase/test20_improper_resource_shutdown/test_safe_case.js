{const fs = require('fs');
const file = fs.openSync('example.txt', 'r');
fs.closeSync(file);} // 파일을 연 후, 닫음