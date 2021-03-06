const express = require("express");
const mongoose = require("mongoose");
const userRouter = require("./routes/userRouter");
const cors = require("cors");
require("dotenv").config();

// set up express
const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => console.log(`the server has started on port: ${PORT}`));

// set up mongoose
mongoose.connect(
  process.env.MONGODB_CONNECTION_STRING,
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
  },
  (err) => {
    if (err) throw err;
    console.log("Mongoose connection established");
  }
);

// set User routes
app.use("/users", userRouter);
