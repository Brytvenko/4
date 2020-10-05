var express = require("express");
var authController = require("../controllers/auth");

var router = express.Router();

router.get("/", (req, res) => {
  res.render("index");
});
router.get("/register", (req, res) => {
  res.render("register");
});
router.get("/login", (req, res) => {
  res.render("login");
});

router.get("/getUsers", authController.getUsers);

module.exports = router;
