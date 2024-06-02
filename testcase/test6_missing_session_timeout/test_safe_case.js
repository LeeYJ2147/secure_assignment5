{const session = require('express-session');
app.use(session({
    secret: 'mySecret',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 } // 1 minute timeout
}));}