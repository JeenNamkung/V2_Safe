require('./utils');
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');

const saltRounds = 12;

const database = include('databaseConnection');
const db_utils = include('database/db_utils');
const db_users = include('database/users');
const success = db_utils.printMySQLVersion();

const port = process.env.PORT;

const app = express();

const expireTime = 60 * 60 * 1000;

const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

app.set('view engine', 'ejs');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.3baqgyv.mongodb.net/?retryWrites=true&w=majority`,
    crypto: {
        secret: mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.use(express.static(__dirname + "/public"));

function isValidSession(req) {
	if (req.session.authenticated) {
		return true;
	}
	return false;
}

function sessionValidation(req, res, next) {
	if (!isValidSession(req)) {
		req.session.destroy();
		res.redirect('/login');
		return;
	}
	else {
		next();
	}
}

app.use('/members', sessionValidation);

app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.render("index");
    } else {
        res.render("loggedinIndex", { username: req.session.username });
    }
});

app.get('/createTables', async (req,res) => {
    const create_tables = include('database/create_tables');

    var success = create_tables.createTables();
    if (success) {
        res.render("successMessage", {message: "Created tables."} );
    }
    else {
        res.render("errorMessage", {error: "Failed to create tables."} );
    }
});

app.get('/createUser', (req,res) => {
    var errorMessage = req.session.errorMessage;
    req.session.errorMessage = null;
    res.render("createUser", { error: errorMessage });
});

app.post('/submitUser', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

    if (!username || !password) {
        req.session.errorMessage = "Username and password are required";
        return res.redirect("/createUser");
    }

    var hashedPassword = bcrypt.hashSync(password, saltRounds);

    var success = await db_users.createUser({ user: username, hashedPassword: hashedPassword });

    if (success) {
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect("/members")
    }
    else {
        req.session.errorMessage = "Username already exists. Please choose another.";
        res.redirect("/createUser");
    }
});

app.get('/login', (req,res) => {
    if (isValidSession(req)) {
        res.redirect('/members');
        return;
    } else {
        var errorMessage = req.session.errorMessage;
        req.session.errorMessage = null;
        res.render("login", { error: errorMessage });
    }
});

app.post('/submitLogin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

    var results = await db_users.getUser({ user: username, hashedPassword: password });

    if (results) {
        if (results.length == 1) {
            if (bcrypt.compareSync(password, results[0].password)) {
                req.session.authenticated = true;
                req.session.username = username;
                req.session.cookie.maxAge = expireTime;
        
                res.redirect('/members');
                return;
            }
            else {
                req.session.errorMessage = "Username and password not found";
                return res.redirect("/login");
            }
        }
        else {
            req.session.errorMessage = "Username and password not found";
            return res.redirect("/login");         
        }
    }

    req.session.errorMessage = "Username and password not found";
    return res.redirect("/login");
});

app.get('/logout', (req, res) => {
	req.session.destroy();
	res.redirect('/');
});

app.get('/members', (req,res) => {
    const imagePaths = ['sky.jpg', 'tree.jpg', 'desert.jpg'];
    const randomIndex = Math.floor(Math.random() * imagePaths.length);
    const randomImagePath = imagePaths[randomIndex];
    res.render("members", { imagePath: randomImagePath, username: req.session.username});
});

app.get("*", (req, res) => {
	res.status(404);
	res.render("404");
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});