import User from "../models/User.js";
import bcrypt from "bcrypt";
import { createError } from "../utils/error.js";
import jwt from "jsonwebtoken";

/* Creates a new user. 
Uses bcrypt to encrypt password. */

export const register = async (req, res, next) => {
    try {

        const salt = bcrypt.genSaltSync(10);
        const hash = bcrypt.hashSync(req.body.password, salt)
        const newUser = new User ({
            username:req.body.username, 
            email:req.body.email,
            password:hash,
        })
        await newUser.save()
        res.status(201).send("User registration complete")
    } catch (err) {
        next(err)
    }
}

export const login = async (req, res, next) => {
    try {
        const user = await User.findOne(({username:req.body.username}))
        if (!user) return next (createError(404, "user not found")) // may need to get rid of the next here.


        const isPasswordCorrect = await bcrypt.compare(
            req.body.password,
            user.password);
        
        if (!isPasswordCorrect) 
        return next (createError(400, "Wrong username or password"));

        const token = jwt.sign({id: user._id, isAdmin: user.isAdmin}, process.env.SECRET) //hide in .env later
        
        const { password, isAdmin, ...otherDetails} = user._doc;
        

        res
        .cookie("access_token", token, {
            httpOnly:true,
            
        })
        .status(200).json({ details:{...otherDetails}, isAdmin});
    } catch (err) {
        next(err)
    }
}















    //     try {
//         const salt = bcrypt.genSaltSync(10);
//         const hash = bcrypt.hashSync(req.body.password, salt);


//         const newUser = new User({
//             ...req.body,
//             password: hash,
//         });

//         await newUser.save();
//         res.status(200).send("User has been created");
//     } catch (err) {
//         next(err);
//     }
// };

// /* User login autheticates username and password. 
// If password is correct a jwt is generated. */

// export const login = async (req, res, next) => {

//     try {
//         const user = await User.findOne({ username: req.body.username });
//         if(!user) return next(createError(404, "User not found" ));

//         const isPasswordCorrect = await bcrypt.compare(req.body.password, user.password)
//         if(!isPasswordCorrect) return next(createError(400, "Wrong username or password" ))

//         const token = jwt.sign(
//             { id: user._id, isAdmin: user.isAdmin }, 
//             process.env.JWT);

//         const { password, isAdmin, ...otherDetails} = user._doc;

        
//         res.status(200).json({ token: token, details: { ...otherDetails }, isAdmin });

//             res.cookie("access_token", token, {
//             httpOnly: true,
//          })
//         .status(200)
//         .json({ details: { ...otherDetails }, isAdmin });
//   } catch (err) {
//     next(err);
//   }
// };


