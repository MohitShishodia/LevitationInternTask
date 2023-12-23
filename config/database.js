const mongoose = require("mongoose");
require("dotenv").config();
const { MONGODB_URL } = process.env;

// mongoose.connect(MONGODB_URL);

// // Check for successful connection
// const db = mongoose.connection;
// db.on('error', console.error.bind(console, 'MongoDB connection error:'));
// db.once('open', () => {
//     console.log('Connected to MongoDB');
// });

exports.connect = () => {
	mongoose
		.connect(MONGODB_URL)
		.then(console.log(`DB Connection Success`))
		.catch((err) => {
			console.log(`DB Connection Failed`);
			console.log(err);
			process.exit(1);
		});
};
