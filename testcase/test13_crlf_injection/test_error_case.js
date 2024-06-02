{const userInput = "maliciousUser\r\nSet-Cookie: sessionId=bad";
const header = `X-User-Input: ${userInput}`;
console.log(header);}