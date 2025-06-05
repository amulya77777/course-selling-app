const { Router } = require("express");
const adminRouter = Router();
const { adminModel, courseModel } = require("../db");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { z } = require("zod");
// brcypt, zod, jsonwebtoken
const  { JWT_ADMIN_PASSWORD } = require("../config");
const { adminMiddleware } = require("../middleware/adminAuth");

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

adminRouter.post("/signup", async function(req, res) {
    try{
    const { email, password, firstName, lastName } = requiredBody.parse(req.body); // TODO: adding zod validation
    // DONE!! TODO: hash the password so plaintext pw is not stored in the DB
    const hashedPassword = await bcrypt.hash(password,5);
    console.log("password hashed successfully!");

    // this step is done for handling the error correctly 
    const existingUser = await adminModel.findOne({ email });
            if (existingUser) {
              return res.status(409).json({ message: "User with this email already exists." });
            }

    // DONE!! TODO: Put inside a try catch block done!!
    await adminModel.create({
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
adminRouter.post("/signin", async function(req, res) {
    try{
    const { email, password } = requiredBody.parse(req.body);

    // TODO: ideally password should be hashed, and hence you cant compare the user provided password and the database password
    const admin = await adminModel.findOne({ email });

    if(!admin) return res.status(403).json({ message: "Incorrect credentials"}); 

    const passwordMatch = await bcrypt.compare(password,admin.password);
    
    if(!passwordMatch) return res.status(403).json({message: "password not matched"})

    if (admin && passwordMatch) {
        const token = jwt.sign({id: admin._id},JWT_ADMIN_PASSWORD,{expiresIn: "1w"});


        // Do cookie logic


        // ✅ Set token in the response header
        res.set("Authorization" , `bearer ${token}`);
        
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

adminRouter.post("/course", adminMiddleware, async function(req, res) {
    const adminId = req.userId;

    const { title, description, imageUrl, price } = req.body;

    // creating a web3 saas in 6 hours
    const course = await courseModel.create({
        title: title, 
        description: description, 
        imageUrl: imageUrl, 
        price: price, 
        creatorId: adminId
    })

    res.json({
        message: "Course created",
        courseId: course._id
    })
})

adminRouter.put("/course", adminMiddleware, async function(req, res) {
    const adminId = req.userId;

    const { title, description, imageUrl, price, courseId } = req.body;

    // creating a web3 saas in 6 hours
    const course = await courseModel.updateOne({
        _id: courseId, 
        creatorId: adminId 
    }, {
        title: title, 
        description: description, 
        imageUrl: imageUrl, 
        price: price
    })

    res.json({
        message: "Course updated",
        courseId: course._id
    })
})

adminRouter.get("/course/bulk", adminMiddleware,async function(req, res) {
    const adminId = req.userId;

    const courses = await courseModel.find({
        creatorId: adminId 
    });

    res.json({
        message: "Course updated",
        courses
    })
})

module.exports = {
    adminRouter: adminRouter
}