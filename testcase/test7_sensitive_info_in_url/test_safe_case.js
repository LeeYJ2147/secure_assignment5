const userPassword = "password123";
fetch("https://example.com/api", {
    method: "POST",
    headers: {
        "Content-Type": "application/json"
    },
    body: JSON.stringify({ password: userPassword })
})
    .then(response => response.json())
    .then(data => console.log(data));