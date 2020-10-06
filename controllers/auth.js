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
  if (!login || !password) {
    return res.status(400).render("register", {
      message: "Поля незаполнены!",
    });
  }
  db.query(
    "select login from user where login = ?",
    [login],
    async (error, results) => {
      if (error) {
        console.log(error);
      }

      if (results.length > 0) {
        return res.render("register", {
          message: " Данный пользователь уже зарегистрирован!",
        });
      } else if (password !== passwordConfirm) {
        return res.render("register", {
          message: "Пароли не совпадают!",
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
            return (
              res.render("register",
              {
                message: "User registered..!",
                }),
              res.status(200).redirect("/users")
            );
          }
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
        message: "Поля незаполнены!",
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
            message: "Логин или пароль введены не правильно!",
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
          res.status(200).redirect("/users");
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
};

exports.users = async (req, res) => {
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
        if (error) {
          res.end({});
        } else {
          const result = results.map((r) => {
            return { name: r.name, login: r.login };
          });
          res.render("users", {
            users: result,
          });
        }
      });
    });
  } catch (error) {
    console.log(error);
    res.status(500).end({
      message: "Внутренняя ошибка",
    });
  }
};
