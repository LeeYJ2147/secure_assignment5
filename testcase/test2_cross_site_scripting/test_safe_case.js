{const userInput = "<script>alert('XSS')</script>";
const sanitizedInput = userInput.replace(/</g, "&lt;").replace(/>/g, "&gt;");
document.write(sanitizedInput);}