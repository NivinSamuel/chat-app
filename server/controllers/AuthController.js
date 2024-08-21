import User from "../models/UserModel.js";
import jwt from "jsonwebtoken";
import { compare } from "bcrypt";

const { sign } = jwt;
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
        response.cookie("jwt", createToken(email, user.id), {
            maxAge,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Ensure the cookie is only sent over HTTPS in production
            sameSite: "None", // Allow cross-site requests
        });

        return response.status(201).json({
            user: {
                id: user.id,
                email: user.email,
                profileSetup: user.profileSetup,
            },
        });
    } catch (error) {
        console.log({ error });
        return response.status(500).send("Internal Server Error");
    }
};

export const login = async (request, response, next) => {
    try {
        const { email, password } = request.body;
        if (!email || !password) {
            return response.status(400).send("Email and Password are required.");
        }

        // Check if the user already exists
        const user = await User.findOne({ email });
        if (!user) {
            return response.status(404).send("User with the given email not found.");
        }

        const auth = await compare(password, user.password);
        if (!auth) {
            return response.status(401).send("Password is incorrect.");
        }

        // Set JWT cookie
        response.cookie("jwt", createToken(email, user.id), {
            maxAge,
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production', // Ensure the cookie is only sent over HTTPS in production
            sameSite: "None", // Allow cross-site requests
        });

        return response.status(200).json({
            user: {
                id: user.id,
                email: user.email,
                profileSetup: user.profileSetup,
                firstName: user.firstName,
                lastName: user.lastName,
                image: user.image,
                color: user.color,
            },
        });
    } catch (error) {
        console.log({ error });
        return response.status(500).send("Internal Server Error");
    }
};

// Ensure CORS middleware is properly set up in your Express app
import cors from 'cors';
app.use(cors({
    origin: 'http://localhost:3000', // Replace with your frontend's URL
    credentials: true, // Allow credentials (cookies, authorization headers, etc.) to be sent with requests
}));
