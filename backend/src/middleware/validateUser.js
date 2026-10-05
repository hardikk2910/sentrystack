const validateUser = (req, res, next) => {
    const { username, email, password   } = req.body;
    const errors = [];

    if (!username || username.trim() === "") {
        errors.push("Username is required");
    }
    if (!email || email.trim() === "") {
        errors.push("Email is required");
    }
    else {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            errors.push("Email format is invalid");
        }
    }
    if (!password || password.trim() === "") {
        errors.push("Password is required");
    }
    else if (password.length < 6) {
        errors.push("Password must be at least 6 characters long");
    }

    if (errors.length > 0) {
        return res.status(400).json({ errors });
    }

    next();
};

module.exports = validateUser;
    