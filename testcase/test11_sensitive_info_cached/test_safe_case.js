const sensitiveInfo = "secretKey123";
const maskedInfo = sensitiveInfo.replace(/./g, '*');
localStorage.setItem("sensitiveInfo", maskedInfo);