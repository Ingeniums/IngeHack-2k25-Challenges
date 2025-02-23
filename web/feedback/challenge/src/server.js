const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");
const logger = require("./middlewares/logger");

require("dotenv").config();

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));

app.use(logger);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.get("/", (req, res) => {
  const success = req.query.success === "true";
  res.render("index", { success });
});

app.post("/submit", (req, res) => {
  res.redirect("/?success=true");
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
