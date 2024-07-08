const express = require("express");
const bodyParser = require("body-parser");
const svgCaptcha = require("svg-captcha");
const session = require("express-session");
const { authenticator } = require("otplib");
const QRCode = require("qrcode");
const jwt = require("jsonwebtoken");
const mysql = require("mysql");

const app = express();

app.set("view engine", "ejs");

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({ secret: "123", resave: true, saveUninitialized: true }));

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "login_tes",
});

connection.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL database:", err);
    return;
  }
  console.log("Connected to MySQL database");
});

app.post("/register", (req, res) => {
  const { username, email, password } = req.body;
  connection.query("SELECT * FROM users WHERE username = ? OR email = ?", [username, email], (err, results) => {
    if (err) {
      console.error("Error querying user from MySQL database:", err);
      return res.status(500).send("Internal Server Error");
    }
    if (results.length > 0) {
      return res.json({ success: false, msg: "Username or email already exists" });
    } else {
      connection.query("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", [username, email, password], (err, result) => {
        if (err) {
          console.error("Error inserting user into MySQL database:", err);
          return res.status(500).send("Internal Server Error");
        }
        res.json({ success: true, msg: "User registered successfully" });
      });
    }
  });
});

app.post("/verify", (req, res) => {
  const { captcha } = req.body;
  const sessionCaptcha = req.session.captcha;
  if (!sessionCaptcha || captcha !== sessionCaptcha) {
    return res.json({ success: false, msg: "Failed captcha verification" });
  }
  res.json({ success: true, msg: "Captcha passed" });
});

app.post("/login", (req, res) => {
  const { username, password, captcha } = req.body;
  req.session.failedLoginAttempts = req.session.failedLoginAttempts || 0;
  if (req.session.failedLoginAttempts >= 3) {
    if (!captcha || captcha !== req.session.captcha) {
      return res.json({ success: false, msg: "Failed captcha verification" });
    }
  }
  connection.query("SELECT * FROM users WHERE username = ? AND password = ?", [username, password], (err, results) => {
    if (err) {
      console.error("Error querying user from MySQL database:", err);
      return res.status(500).send("Internal Server Error");
    }
    if (results.length > 0) {
      req.session.email = results[0].email;
      req.session.userId = results[0].id;
      if (results[0].is_2fa_registered) {
        return res.json({ success: true, msg: "Success", redirectUrl: "/login-2fa" });
      } else {
        return res.json({ success: true, msg: "Success", redirectUrl: "/activate-2fa" });
      }
    } else {
      req.session.failedLoginAttempts++;
      res.json({
        success: false,
        msg: "Invalid username or password",
        failedLoginAttempts: req.session.failedLoginAttempts,
      });
    }
  });
});

app.post("/activate-2fa", (req, res) => {
  const email = req.session.email;
  if (!email) {
    return res.status(400).send("Email not found in session");
  }
  const secret = authenticator.generateSecret();
  connection.query("UPDATE `users` SET `secret` = ?, `is_2fa_registered` = TRUE WHERE `email` = ?", [secret, email], (err, result) => {
    if (err) {
      throw err;
    }
    const qrCodeUrl = authenticator.keyuri(email, "2FA Node App", secret);
    QRCode.toDataURL(qrCodeUrl, (err, url) => {
      if (err) {
        throw err;
      }
      req.session.qr = url;
      res.redirect("/auth-2fa");
    });
  });
});

app.post("/auth-2fa", (req, res) => {
  if (!req.session.email) {
    return res.redirect("/");
  }
  const email = req.session.email;
  const code = req.body.code;
  return verifyLogin(email, code, req, res, "/auth-2fa");
});

app.post("/login-2fa", (req, res) => {
  if (!req.session.email) {
    return res.redirect("/");
  }
  const email = req.session.email;
  const code = req.body.code;
  return verifyLogin(email, code, req, res, "/views/login-2fa.html");
});

function verifyLogin(email, code, req, res, failUrl) {
  connection.query("SELECT secret, is_2fa_registered FROM users WHERE email = ?", [email], (err, result) => {
    if (err) {
      throw err;
    }

    const row = result[0];
    if (!row) {
      return res.redirect("/");
    }

    if (!authenticator.check(code, row.secret)) {
      return res.redirect(failUrl);
    }

    req.session.qr = null;
    req.session.email = null;
    req.session.token = jwt.sign(email, "supersecret");

    return res.redirect("/home");
  });
}

// GET endpoint
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/views/login.html");
});

app.get("/register", (req, res) => {
  res.sendFile(__dirname + "/views/register.html");
});

app.get("/captcha", (req, res) => {
  const captcha = svgCaptcha.create();
  req.session.captcha = captcha.text;
  res.setHeader("Content-Type", "image/svg+xml");
  res.send(captcha.data);
});

app.get("/login", (req, res) => {
  res.sendFile(__dirname + "/views/login.html");
});

app.get("/login-2fa", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }
  res.sendFile(__dirname + "/views/login-2fa.html");
});

app.get("/activate-2fa", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }
  res.sendFile(__dirname + "/views/activate-2fa.html");
});

app.get("/auth-2fa", (req, res) => {
  if (!req.session.qr) {
    return res.redirect("/");
  }
  return res.render("auth-2fa.ejs", { qr: req.session.qr });
});

app.get("/home", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }
  res.sendFile(__dirname + "/views/home.html");
});

app.get("/logout", (req, res) => {
  req.session.destroy();
  return res.redirect("/");
});

app.get("/users", (req, res) => {
  if (!req.session.userId) {
    return res.redirect("/");
  }

  connection.query("SELECT id, username, email FROM users WHERE id BETWEEN 1 AND 50", (err, results) => {
    if (err) {
      console.error("Error querying users from MySQL database:", err);
      return res.status(500).send("Internal Server Error");
    }

    res.render("user-list.ejs", { users: results });
  });
});

app.get("/vulnerable-users", (req, res) => {
  const userId = req.query.id;
  const query = `SELECT id, username, email FROM users WHERE id = ${userId}`;

  connection.query(query, (err, results) => {
    if (err) {
      console.error("Error querying users from MySQL database:", err);
      return res.status(500).send("Internal Server Error");
    }

    res.json(results);
  });
});

app.listen(3000, () => {
  console.log("Server started on http://localhost:3000");
});
