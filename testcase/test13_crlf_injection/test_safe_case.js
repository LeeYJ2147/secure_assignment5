const userInput = "maliciousUser";
const sanitizedInput = userInput.replace(/[\r\n]/g, '');
const header = `X-User-Input: ${sanitizedInput}`;
console.log(header);