{const userInput = "trustedPage";
const allowedPages = ["home", "profile", "trustedPage"];
if (allowedPages.includes(userInput)) {
    window.location.href = `https://trusted.com/${userInput}`;
} else {
    console.log("Invalid redirection attempt");
}}