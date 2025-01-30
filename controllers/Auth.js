import jwt from 'jsonwebtoken'
import UserModal from '../models/User.js';
import bcrypt from 'bcryptjs'

const Register = async (req, res) => {
    try {
        const {FullName, email, password, role} = req.body
        const imagePath = req.file.filename;
        console.log(imagePath)
        
        const existUser = await UserModal.findOne({email})
        if (existUser) {
            return res.status(301).json({success:false, message:"User Already Exist Please Login"})
        }
        const hasePassword = await bcrypt.hashSync(password,10)
        const newUser = new UserModal({
            FullName: FullName,
            email: email,
            password: hasePassword,
            profile: imagePath,
            role: role || 'user' 
        });

        await newUser.save();

        res.status(201).json({success:true, message: 'User registered successfully', user:newUser});
    } catch (error) {
        console.error('Error during registration', error);
        res.status(500).json({ error: 'Error during registration' });
    }
}

const Login = async (req, res) => {
    try {
        const { email, password } = req.body;
        console.log(email, password);
        if (!email || !password) {
            return res.status(400).json({ success: false, message: "All fields are required" });
        }
        const FindUser = await UserModal.findOne({ email });
        if (!FindUser) {
            return res.status(404).json({ success: false, message: "Account not found. Please register." });
        }
        const comparePassword = await bcrypt.compare(password, FindUser.password);
        if (!comparePassword) {
            return res.status(401).json({ success: false, message: "Invalid password" });
        }

        const token = jwt.sign({ userId: FindUser._id }, process.env.JWT_SECRET);
        
        // Set the token in a cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        return res.status(200).json({ success: true, message: "Login successfully", user: FindUser, token });
    } catch (error) {
        console.error('Error during login', error);
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

const Logout = async(req,res) => {
    try {
        // Clear the token cookie
        res.clearCookie('token');
        res.status(200).json({ success: true, message: "Logout successful" });
    } catch (error) {
        console.error("Error logging out:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
}

const updateProfile = async (req, res) => {
    try {
        const userId = req.params.id;
        const { FullName, oldpassword, newpassword } = req.body;

        const ExistUser = await UserModal.findById(userId);
        if (!ExistUser) {
            return res.status(404).json({ success: false, message: "Account not found." });
        }

        if (oldpassword) {
            const comparePassword = await bcrypt.compare(oldpassword, ExistUser.password);
            if (!comparePassword) {
                return res.status(401).json({ success: false, message: "Old password is incorrect." });
            }
        }

        if (FullName) {
            ExistUser.FullName = FullName;
        }

        if (oldpassword && newpassword) {
            const hashedPassword = await bcrypt.hash(newpassword, 10);
            ExistUser.password = hashedPassword;
        } else if (oldpassword && !newpassword) {
            return res.status(400).json({ success: false, message: "New password is required when old password is provided." });
        }

        await ExistUser.save();

        res.status(200).json({ success: true, message: "Profile updated successfully.", user: ExistUser });

    } catch (error) {
        console.error("Error updating profile:", error);
        res.status(500).json({ success: false, message: "Internal Server Error" });
    }
};

export {Register,Login,Logout,updateProfile}
