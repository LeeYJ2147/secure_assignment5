const session = require('express-session');
app.use(session({
    secret: 'mySecret',
    resave: false,
    saveUninitialized: true
    // missing session timeout
}));