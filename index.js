const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
var app = express();
app.set("view engine","ejs");
app.use(express.urlencoded({extended:true}));
app.use(express.static('public'));
require("dotenv").config();
const secret = process.env.SECRET;
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
app.use(cookieParser());

const mongoose = require("mongoose");
mongoose.connect("mongodb://localhost:27017/secrets",
    { useNewUrlParser: true, useUnifiedTopology: true }
);
const trySchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const encrypt = require("mongoose-encryption");
trySchema.plugin(encrypt,{secret:secret,encryptedFields:["password"]});

const User = mongoose.model("persons",trySchema);

app.get("/", function(req,res){
    res.render("home");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register",async function(req,res){
     try {
        const newUser = new User({
            name: req.body.name,
            email: req.body.username,
            password: req.body.password
        });
        await newUser.save(); 
        res.redirect("login");
    } catch (err) {
        res.send("Error registering user.");
    }
   
});

app.get("/login", function(req, res) {
    res.render("login");
});

 app.get("/submit",async function(req, res) {
  res.render("submit"); 
});

app.post("/submit", async function(req, res) {
    const submittedSecret = req.body.secret;
    console.log("Secret submitted:", submittedSecret);
    res.send("✅ Secret received!");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ email: username });
  if (user && user.password === password) {
    const token = jwt.sign({ id: user._id }, secret, { expiresIn: "1h" });
    res.cookie("token", token, { httpOnly: true });
    res.redirect("/secrets");
  } else {
    res.send("Invalid login.");
  }
});
function authenticateJWT(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");

  jwt.verify(token, secret, (err, decoded) => {
    if (err) return res.send("Token invalid.");
    req.userId = decoded.id;
    next();
  });
}
app.get("/secrets", authenticateJWT, async (req, res) => {
  const user = await User.findById(req.userId);
  res.render("secrets");
});
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/login");
});

app.listen(5500,function(){
    console.log("server started on 5000");
});