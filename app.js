//jshint esversion:6
require('dotenv').config()
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
//Level 2
//const encrypt=require("mongoose-encryption");

//Level 3 security using the md5 Hashing Algorithm
//const md5 = require("md5");

//Level 4 Security using npm-bcrypt
// const bcrypt=require("bcrypt");
// const saltRounds = 10;

//Level 5  using passport.js
const session = require('express-session');
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');


const  GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate=require('mongoose-findorcreate');

const app=express();

app.set("view engine","ejs");

app.use(express.static("public"));
app.use(bodyParser.urlencoded({
    extended:true
}));

// The below code should be used before the mongoose.connect line.
app.use(session({
    secret: 'This is my secret',
    resave: false,
    saveUninitialized: false
  }));

  app.use(passport.initialize());
  app.use(passport.session());  



mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true ,useUnifiedTopology: true});
mongoose.set("useCreateIndex",true);

const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    secret:String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User=mongoose.model("User",userSchema);


passport.use(User.createStrategy());


//Came from passport-local-mongoose

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// Came from passport npm package works for all authentications
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });




passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",(req,res)=>{
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

// This request is made by the google
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login",(req,res)=>{
    res.render("login");
});

app.get("/register",(req,res)=>{
 
    res.render("register"); 
});

app.get("/secrets",(req,res)=>{
    // if(req.isAuthenticated()) {   //i.e logged in
    //  res.render("secrets");
    // }   else{
    //     res.redirect("/login");
    // }
   
   User.find({ secret: { $ne: null } },(err,foundUsers)=>{
       if(err){
         console.log(err);
       }else{
        if(foundUsers){ 
        res.render("secrets",{usersWithSecrets:foundUsers})
        } 
      }

   });


});

app.get("/submit",(req,res)=>{
     if(req.isAuthenticated()){
     res.render("submit");
     }else{
       res.redirect("/login");
     }
});

app.post("/submit",(req,res)=>{

   loggedSecret=(req.body.secret); 
   User.findById(req.user.id,(err,foundUser)=>{
      if(err){
        console.log(err);
      }else{
        if(foundUser){
        foundUser.secret=(loggedSecret);
        foundUser.save(()=>{
          res.redirect("/secrets");
        }) ;  
      }
      }
   })
});


// app.post("/submit", function(req, res){
//   const submittedSecret = req.body.secret;

// //Once the user is authenticated and their session gets saved, their user details are saved to req.user.
//   // console.log(req.user.id);

//   User.findById(req.user.id, function(err, foundUser){
//     if (err) {
//       console.log(err);
//     } else {
//       if (foundUser) {
//         foundUser.secret = submittedSecret;
//         foundUser.save(function(){
//           res.redirect("/secrets");
//         });
//       }
//     }
//   });
// });



//Level 2 Security using mongoose-encryption package

// Use encryption code before compiling the collection of the database i.e. before the below
//line mentioned.


//Level 2 code  
//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"]  });
//>>>>>>>>>>>>>>>>
//Level 4




app.post("/register",(req,res)=>{
     

// Here we need to put the values entered by the user in the respective fields. 
    User.register({username:req.body.username}, req.body.password, function(err, user) {
        if (err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            //Authenticate our user using Passport.
            // The callback will trigger only when the user is authenticated. We managed to 
            // save the current cookie and their session details.
            passport.authenticate("local")(req,res,function(){
        // So here we're redirecting the user to the user's page and now in get request of the
        // secrets page if the user is already authenticated i.e logged in then he can access 
        // his secret page until he does not close the browser as closing browser will expire 
        // the cookie and the session i.e. created using the passport authenticate method.
                    res.redirect("/secrets");
                });
            }
});

});


// LEVEL-3 SECURITY using the md5 algorithm of hasing i.e passing the plaintexpassword to 
// the md5 hash function using the md5 npm package and then in login template matching the
//  


// app.post("/register",(req,res)=>{
//    const newUser=new User({
//        email:req.body.username,
//        password:md5(req.body.password)
//    });
//   // Insert in DB
//     newUser.save((err)=>{
//         if(err){
//             console.log(err);
//         }
//         res.render("secrets");
//     });


// });


// app.post("/login",(req,res)=>{

//   const Useremail=req.body.username;
//   const Userpass=md5(req.body.password);
  
//     User.findOne({email:Useremail},(err,foundUser)=>{
//         if(err){
//             console.log(err);
//         } else{
//          //Level 1 Security 

//         if(foundUser){
//         if(foundUser.password===Userpass){
//             console.log(foundUser.password);
//             res.render("secrets");
//         }else{
//             res.send("Email and password don't match");
//         }
//       }
       
//     }
//     });

// });


// Level 4 Security (bcrypt)

// app.post("/register",(req,res)=>{
//     bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
//         // Store hash in your password DB.

//         if(err){
//             console.log(err);
//         }else{
//         const newUser=new User({
//             email:req.body.username,
//             password:hash
//         });
//         // Insert in DB
//      newUser.save((err)=>{
//         if(err){
//             console.log(err);
//         }
//         res.render("secrets");
//     });
//    }
//     });
   
   
 
 
//  });
 
app.get("/logout",(req,res)=>{
    req.logout();
    res.redirect('/');
});
 
 app.post("/login",(req,res)=>{
 
   const Useremail=req.body.username;
   const Userpass=req.body.password;

    const user=new User({
       username:Useremail,
       password:Userpass
    });

    //new user that's data is saved above.
   req.login(user, function(err) {
    if (err) { return res.send("ERROR"); }
    else{
        passport.authenticate("local")(req,res,function(){   
            res.redirect("/secrets");

        });
    }
  });
    
 
 });
 






app.listen(3000,(req,res)=>{
    console.log("Server started at port 3000");
})