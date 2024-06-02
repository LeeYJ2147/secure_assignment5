const session = require('express-session');
const app = require('express')();

app.use(session({
    secret: 'mySecret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
}));

app.get('/login', (req, res) => {
    req.session.userId = req.query.userId; // 세션 고정 공격 가능
    res.send('Logged in');
});

app.listen(3000, () => {
    console.log('Server is running on port 3000');
});