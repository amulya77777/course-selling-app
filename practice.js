adminRouter.post("/signin", async function (req, res) {
  try {
    const { email, password } = requiredBody.parse(req.body);

    const admin = await adminModel.findOne({ email });

    if (!admin) {
      return res.status(403).json({ message: "Incorrect credentials" });
    }

    const passwordMatch = await bcrypt.compare(password, admin.password);

    if (!passwordMatch) {
      return res.status(403).json({ message: "Incorrect credentials" });
    }

    const token = jwt.sign({ id: admin._id }, JWT_ADMIN_PASSWORD, {
      expiresIn: "1d", // optional: expires in 1 day
    });

    // Optional: set token in a cookie
    // res.cookie("token", token, { httpOnly: true });

    return res.json({ token });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return res.status(400).json({ message: "Invalid input", errors: error.issues });
    }

    console.error("Signin error:", error);
    return res.status(500).json({ message: "Server error during signin" });
  }
});
