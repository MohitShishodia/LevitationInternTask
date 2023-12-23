const express = require('express')
const bcrypt=require('bcrypt')
const app = express()
const dotenv = require("dotenv");
const PORT = process.env.PORT || 3000;
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const database=require("./config/database");
const User =require("./models/User");
const BlogPost=require("./models/BlogPost");
dotenv.config();
database.connect();
const mongoSanitize = require('express-mongo-sanitize');


// Sanitize user input
app.use(mongoSanitize());

app.use(express.json());

//Helps in Express for Secure Web Applications by setting various HTTP Headers
app.use(helmet());


//Use Rate-Limit to control the number of requests of a User can make to a Server within a Specified timeframe.
const limiter = rateLimit(
  {
    windowMs: 15 * 60 * 1000, // TimeFrame
    max: 50, // Limit
  });

app.use(limiter);

//Hash Password Using Bcrypt.
const hashingPassword = async (req, res, next) => {
    if (req.body.password) {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      req.body.password = hashedPassword;
    }
    next();
  };

// Middleware to Authenticate User By Token
const authenticateUser =async (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) {
      return res.status(401).json({ 
        message: 'Unauthorized User'
      });
    }

    try {
      const decoded = await jwt.verify(token, process.env.JWT_SECRET );
      req.user = decoded;
      next();
    } 
    catch (err) {
      res.status(401).json({ 
        message: 'Something Went Wrong Please Check Your Details'
      });
    }
  };

//User-Registeration
app.post('/api/V1/register', hashingPassword, async (req, res) => {
    try {
      const { username, password } = req.body;
      const newUser = new User({ username,password});
      await newUser.save();//Save the User in DB
      res.status(200).json({ message: 'User registered Successfully' });
    } 
    catch (error) {
      res.status(500).json({ message: 'Try After Sometime Internal Server Error' });
    }
  });

// Login  for authenticating users
app.post('/api/V1/login', async (req, res) => {
    try {
      const {username,password } = req.body;
      const user=await User.findOne({username});
  
      if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({ message: 'Invalid Username or Password' });
      }
  
      const token = jwt.sign({userId:user._id,username:user.username },process.env.JWT_SECRET, {
        expiresIn: '2h', //token Expiring
      });
      res.json({token});
    } 
    catch (error) {
      res.status(500).json({ 
        message: 'Login Failure Please Try Again' 
      });
    }
  });

//For Non-Authenticate User They can read Blog-Posts
app.get('/api/V1/blog-posts', async (req, res) => {
    try {
      const posts = await BlogPost.find();
      res.json(posts);
    } 
    catch (error) {
      res.status(500).json({ message: 'Something Went Wrong'});
    }
  });
  

// For Authenticated users can create a New Blog Post
app.post('/api/V1/blog-posts', authenticateUser,async(req, res)=>{
    try {
      const { title, content } = req.body;
      const newPost = new BlogPost({ title, content, author: req.user.userId });
      await newPost.save();
      res.status(201).json(newPost);
    }
    catch(error){
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });


//For Authenticated Users can Read their Own Blog posts
app.get('/api/V1/blog-posts', authenticateUser, async (req, res) => {
    try {
      const posts = await BlogPost.find({ author: req.user.userId });
      res.json(posts);
    } 
    catch (error){
      res.status(500).json({ message: 'Internal Server Error' });
    }
  });
  

//For Authenticated users can update their Content or Title for their own blogPost
app.put('/api/V1/blog-posts/:id', authenticateUser, async (req, res) => {
    try {
      const postId = req.params.id;
      const { title, content } = req.body;
      const updatedPost = await BlogPost.findOneAndUpdate(
        { _id: postId, author: req.user.userId },
        { title, content },
        { new: true }
      );
  
      if (!updatedPost) {
        return res.status(404).json({ message: 'Blog post not found' });
      }
  
      res.json(updatedPost);
    } 
    catch (error){
      res.status(500).json({ message: 'Something Bad Happen' });
    }
  });

//For Authenticated users can delete their own blogPost
app.delete('/api/V1/blog-posts/:id', authenticateUser, async (req, res) => {
    try{
      const postId = req.params.id;
      const deletedPost = await BlogPost.findOneAndDelete({ _id: postId, author: req.user.userId });
      if (!deletedPost) {
        return res.status(404).json({ message: 'Blog post not found' });
      }
      res.json(deletedPost);
    } 
    catch(error){
      res.status(500).json({ message:'Something Went Wrong'});
    }
  });

app.get('/',(req,res)=>{
  res.send("Welcome to Blog Website");
})

app.listen(PORT, () => {
  console.log(` app listening on port ${PORT}`)
})