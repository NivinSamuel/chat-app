import User from "../models/UserModel.js";
import jwt from "jsonwebtoken"; // Import jwt
const { sign } = jwt; // Destructure sign from jwt

const maxAge = 3 * 24 * 60 * 60 * 1000;

const createToken = (email, userId) => {
    return sign({ email, userId }, process.env.JWT_KEY, { expiresIn: maxAge });
};

export const signup = async (request, response, next) => {
    try {
        const { email, password } = request.body;
        if (!email || !password) {
            return response.status(400).send("Email and Password are required.");
        }
        
        // Check if the user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return response.status(400).send("User already exists.");
        }
        
        // Create a new user
        const user = await User.create({ email, password });
        
        // Set JWT cookie
        response.cookie("jwt", createToken(email, user._id), {
            maxAge,
            secure: process.env.NODE_ENV === 'production', // Use `secure` only in production
            sameSite: "None",
        });
        
        return response.status(201).json({
            user: {
                id: user._id,
                email: user.email,
                profileSetup: user.profileSetup,
            },
        });
    } catch (error) {
        console.log({ error });
        return response.status(500).send("Internal Server Error");
    }
};
