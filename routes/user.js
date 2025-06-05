const { Router } = require("express");
const { userModel, purchaseModel, courseModel } = require("../db");
const jwt = require("jsonwebtoken");
const  { JWT_USER_PASSWORD } = require("../config");
const { userMiddleware } = require("../middleware/userAuth");
const userRouter = Router();
const { z } = require("zod");
const bcrypt = require("bcrypt");

const requiredBody = z.object({
    email : z.string().min(3).max(100).email(),
    password : z.string().min(3).max(30)
  .regex(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9])/,
    "Password must include uppercase, lowercase, number, and special character"
  ),
  firstName : z.string().min(3).max(30),
  lastName : z.string().min(3).max(30) 
})

userRouter.post("/signup", async function(req, res) {
    try{
    const { email, password, firstName, lastName } = requiredBody.parse(req.body); 
    // TODO: adding zod validation
    // DONE!! TODO: hash the password so plaintext pw is not stored in the DB
    const hashedPassword = await bcrypt.hash(password,5);
    console.log("password hashed successfully!");

    // this step is done for handling the error correctly 
    const existingUser = await userModel.findOne({ email });
            if (existingUser) {
              return res.status(409).json({ message: "User with this email already exists." });
            }

    // DONE!! TODO: Put inside a try catch block done!!
    await userModel.create({
        email: email,
        password: hashedPassword,
        firstName: firstName, 
        lastName: lastName
    })

    res.status(201).json({
        message: "Signup succeeded"
    })
}catch(error){
        if (error instanceof z.ZodError) {
            return res.status(400).json({
            message: "Validation failed",
            errors: error.issues.map(issue => ({
            field: issue.path.join('.'),
            message: issue.message
            }))
    });
    }else {
              console.error("Error during signup:", error);
              res.status(500).json({ message: "Error during signup." });
            }
        }
});

//try-catch 
userRouter.post("/signin", async function(req, res) {
    try{
    const { email, password } = requiredBody.parse(req.body);

    // TODO: ideally password should be hashed, and hence you cant compare the user provided password and the database password
    const user = await userModel.findOne({ email });

    if(!user) return res.status(403).json({ message: "Incorrect credentials"}); 

    const passwordMatch = await bcrypt.compare(password,user.password);
    
    if(!passwordMatch) return res.status(403).json({message: "password not matched"})

    if (user && passwordMatch) {
        const token = jwt.sign({id: user._id},JWT_USER_PASSWORD,{expiresIn: "1w"});


        // Do cookie logic/ fetch

        // ✅ Set token in the response header
        res.set("Authorization", `Bearer ${token}`);

        res.json({
            token: token
        })
    }
 } catch(error) {
        if (error instanceof z.ZodError) {
      return res.status(400).json({ message: "Invalid input", errors: error.issues });
    }
    console.error("Signin error:", error);
    return res.status(500).json({ message: "Server error during signin" });
  }
})

userRouter.get("/purchases", userMiddleware, async function(req, res) {
    const userId = req.userId;

    const purchases = await purchaseModel.find({
        userId,
    });

    let purchasedCourseIds = [];

    for (let i = 0; i<purchases.length;i++){ 
        purchasedCourseIds.push(purchases[i].courseId)
    }

    const coursesData = await courseModel.find({
        _id: { $in: purchasedCourseIds }
    })

    res.json({
        purchases,
        coursesData
    })
})

module.exports = {
    userRouter: userRouter
}