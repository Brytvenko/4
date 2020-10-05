var mysql = require("mysql");
var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  port: process.env.DATABASE_PORT,
  password: process.env.DATABASE_PASSWORD,
  database: process.env.DATABASE,
});

exports.register = (req, res) => {
  console.log(req.body);

  const { name, login, password, passwordConfirm } = req.body;

  db.query(
    "select login from user where login = ?",
    [login],
    async (error, results) => {
      if (error) {
        console.log(error);
      }

      if (results.length > 0) {
        return res.render("register", {
          message: " That login is already in use",
        });
      } else if (password !== passwordConfirm) {
        return res.render("register", {
          message: "Password do not match",
        });
      }

      let hashedPasword = await bcrypt.hash(password, 8);
      console.log(hashedPasword);

      db.query(
        "INSERT INTO user set ?",
        { name: name, login: login, password: hashedPasword },
        (error, results) => {
          if (error) {
            console.log(error);
          } else {
            console.log(results);
            return res.render("register", {
              message: "User registered..!",
            });
          }
          return getUsers;
        }
      );
    }
  );
};

exports.login = async (req, res) => {
  try {
    const { login, password } = req.body;

    if (!login || !password) {
      return res.status(400).render("login", {
        message: "Please provide an login and password",
      });
    }

    db.query(
      "select * from user where login = ?",
      [login],
      async (error, results) => {
        if (
          !results ||
          !(await bcrypt.compare(password, results[0].password))
        ) {
          res.status(401).render("login", {
            message: "login or password is incorrect",
          });
        } else {
          var id = results[0].id;
          var token = jwt.sign({ id }, process.env.JWT_SECRET, {
            expiresIn: process.env.JWT_EXPIRES_IN,
          });

          console.log("The Token is : " + token);
          var cookieOptions = {
            expires: new Date(
              Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000
            ),
            httpOnly: true,
          };

          res.cookie("jwt", token, cookieOptions);
          res.status(200).redirect("/");
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
};

exports.getUsers = async (req, res) => {
  try {
    const token = req.cookies["jwt"];
    console.log(token);
    if (token === null) return res.sendStatus(401); // if there isn't any token
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      console.log(err);
      if (err) {
        return res.sendStatus(403);
      }
      req.user = user;
      db.query("select * from user", async (error, results) => {
        res.setHeader("Content-Type", "application/json");
        if (error) {
          res.end({});
        } else {
          const result = results.map((r) => {
            return { name: r.name, login: r.login };
          });
          res.end(JSON.stringify(result));
        }
      });
    });
  } catch (error) {
    console.log(error);
    res.status(500).end({
      message: "Internal error",
    });
  }
};
