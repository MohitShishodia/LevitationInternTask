const mongoose=require("mongoose")

const blogPostSchema = new mongoose.Schema({
    title: String,
    content: String,
    author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  });
  
module.exports = mongoose.model('BlogPost', blogPostSchema);