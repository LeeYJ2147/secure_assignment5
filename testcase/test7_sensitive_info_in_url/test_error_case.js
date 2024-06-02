{const userPassword = "password123";
fetch(`https://example.com/api?password=${userPassword}`)
    .then(response => response.json())
    .then(data => console.log(data));}